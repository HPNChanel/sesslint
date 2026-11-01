"""Atomic copy-only write operations guaranteeing no torn files or in-place mutations."""

from __future__ import annotations

import errno
import hashlib
import os
from collections.abc import Callable, Collection
from pathlib import Path

from sesslint.errors import AtomicWriteError

StrPath = str | os.PathLike[str]

# B23(b): when ``os.link`` is unavailable (FAT/exFAT, some SMB/NFS mounts) the
# no-clobber publish falls back to a rename that never replaces an existing
# entry. Windows ``os.rename`` (MoveFileExW without MOVEFILE_REPLACE_EXISTING)
# already refuses an existing destination; POSIX ``rename(2)`` clobbers, so
# there the name is first reserved with O_CREAT|O_EXCL|O_NOFOLLOW.
_RENAME_IS_NO_CLOBBER: bool = os.name == "nt"

_TEMP_NAME_ATTEMPTS = 100


def _sync_dir(path: Path) -> None:
    """Best-effort parent directory fsync across platforms (guarded for Windows)."""
    if os.name == "nt":
        return
    try:
        dir_fd = os.open(str(path), os.O_RDONLY)
    except (OSError, PermissionError):
        return
    try:
        os.fsync(dir_fd)
    except (OSError, PermissionError):
        pass
    finally:
        try:
            os.close(dir_fd)
        except OSError:
            pass


def _same_existing_file(dest: Path, prohibited: StrPath) -> bool:
    """True when both paths exist and name one file (hard link, case alias)."""
    try:
        return os.path.samefile(dest, prohibited)
    except OSError:
        return False


def _create_flags() -> int:
    """Exclusive-create flags that never follow a planted symlink."""
    return (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )


def _open_temp(parent: Path, prefix: str, perm: int) -> tuple[int, Path]:
    """Exclusively create a fresh temp file in ``parent`` (B23(b)).

    ``perm`` is passed to ``open(2)`` so the process umask applies exactly as
    it would to any ordinary file creation; the name carries no content.
    """
    for _ in range(_TEMP_NAME_ATTEMPTS):
        candidate = parent / f"{prefix}{os.urandom(8).hex()}"
        try:
            return os.open(candidate, _create_flags(), perm), candidate
        except FileExistsError:
            continue
    raise FileExistsError(errno.EEXIST, "No unused temporary file name available", str(parent))


def _publish_reserved_replace(temp: Path, dest: Path) -> None:
    """POSIX fallback: reserve ``dest`` exclusively, then rename over the reservation.

    The placeholder is removed again on failure only while it is still the
    entry this call created (same device/inode), so a concurrent writer's file
    is never deleted.
    """
    fd = os.open(dest, _create_flags(), 0o600)
    try:
        reserved = os.fstat(fd)
    finally:
        os.close(fd)
    try:
        os.replace(temp, dest)
    except BaseException:
        try:
            current = os.lstat(dest)
            if (current.st_dev, current.st_ino) == (reserved.st_dev, reserved.st_ino):
                os.unlink(dest)
        except OSError:
            pass
        raise


def _publish_no_clobber(temp: Path, dest: Path) -> None:
    """Publish ``temp`` at ``dest`` without ever replacing an existing entry (B23(a,b)).

    Primary path is ``os.link`` (atomic, fails with EEXIST for any existing
    entry, dangling symlinks included). When the filesystem cannot hard-link
    (FAT/exFAT, SMB, some NFS), a no-clobber rename is used instead. Raises
    ``FileExistsError`` when ``dest`` already exists in any form.
    """
    try:
        os.link(temp, dest)
    except FileExistsError:
        raise
    except OSError:
        if _RENAME_IS_NO_CLOBBER:
            os.rename(temp, dest)
        else:
            _publish_reserved_replace(temp, dest)
        return
    try:
        os.unlink(temp)
    except OSError:
        pass


def atomic_write_bytes(
    dest: StrPath,
    data: bytes,
    *,
    mode: int | None = None,
    fsync: bool = True,
    refuse_paths: Collection[StrPath] = (),
    prefix: str = ".sesslint_tmp_",
    pre_write_hook: Callable[[], None] | None = None,
    pre_rename_hook: Callable[[Path], None] | None = None,
    sync_dir: bool = False,
    exclusive: bool = False,
) -> str:
    """Write bytes to dest atomically using a temporary file in dest's parent directory.

    Guarantees:
    1. Zero in-place mutation: writes to a hidden temporary file and atomically renames.
    2. Zero partial-visibility: dest is absent or completely intact until atomic rename.
    3. Failure cleanup: temporary file is immediately unlinked if write or rename fails.
    4. Refuse list: strictly refuses to write to any path in refuse_paths (realpath).
    5. Integrity: returns the SHA-256 hex digest of the written bytes.
    6. Permissions (B23(b)): without ``mode`` the published file gets ordinary
       umask semantics (it is created ``0o666 & ~umask``, never a stray 0600);
       with ``mode`` the temp file is created 0600 and set to exactly ``mode``
       before publication.
    7. No-clobber (B23(a)): with ``exclusive=True`` an existing ``dest`` in any
       form (file, directory, dangling symlink) is refused before and at
       publication time; the check and the publish cannot race into a clobber.

    Args:
        dest: Destination path where the file will be placed.
        data: Raw bytes to write.
        mode: Optional permissions mode (e.g. 0o600) to apply before atomic rename.
        fsync: Whether to flush and fsync before rename (defaults to True).
        refuse_paths: Prohibited paths that must never be overwritten.
        prefix: Prefix for the temporary file name.
        pre_write_hook: Optional hook called after temp file creation before write.
        pre_rename_hook: Optional hook called with temp Path before atomic rename.
        sync_dir: Whether to fsync parent directory after rename.
        exclusive: Refuse (never replace) an existing destination entry.

    Returns:
        64-character lowercase SHA-256 hexadecimal digest of the written bytes.

    Raises:
        AtomicWriteError: If refuse_paths check fails, parent directory does not exist,
            ``exclusive`` and dest exists (``__cause__`` is ``FileExistsError``),
            or write/rename encounters any I/O or permissions error.
    """
    dest_path = Path(dest)
    dest_real = os.path.realpath(dest_path)

    # 1. Prohibited path preflight check (before creating any temporary artifact)
    for prohibited in refuse_paths:
        prohibited_real = os.path.realpath(prohibited)
        if dest_real == prohibited_real or _same_existing_file(dest_path, prohibited):
            raise AtomicWriteError(
                f"Refusing to write to protected path: {dest} "
                f"(matches prohibited path {prohibited})"
            )

    parent_dir = dest_path.parent
    if not parent_dir.exists():
        raise AtomicWriteError(f"Destination directory does not exist: {parent_dir}")
    if not parent_dir.is_dir():
        raise AtomicWriteError(f"Destination parent path is not a directory: {parent_dir}")
    if exclusive and os.path.lexists(dest_path):
        exists_err = FileExistsError(errno.EEXIST, "Destination already exists", str(dest))
        raise AtomicWriteError(
            f"Atomic write to '{dest}' failed: destination already exists"
        ) from exists_err

    temp_path: Path | None = None
    try:
        # Create temp file in the same directory/filesystem to guarantee atomic publication
        fd, temp_path = _open_temp(parent_dir, prefix, 0o666 if mode is None else 0o600)
        with os.fdopen(fd, "wb") as tmp_file:
            if pre_write_hook is not None:
                pre_write_hook()
            tmp_file.write(data)
            if fsync:
                tmp_file.flush()
                os.fsync(tmp_file.fileno())

        if mode is not None:
            os.chmod(temp_path, mode)

        if pre_rename_hook is not None:
            pre_rename_hook(temp_path)

        if exclusive:
            _publish_no_clobber(temp_path, dest_path)
        else:
            os.replace(temp_path, dest_path)
        temp_path = None  # Successfully published, no cleanup needed

        if sync_dir:
            _sync_dir(parent_dir)
    except BaseException as err:
        if temp_path is not None and os.path.lexists(temp_path):
            try:
                temp_path.unlink()
            except OSError:
                pass
        if isinstance(err, Exception):
            raise AtomicWriteError(f"Atomic write to '{dest}' failed: {err}") from err
        raise

    return hashlib.sha256(data).hexdigest()


def atomic_write_text(
    dest: StrPath,
    text: str,
    *,
    encoding: str = "utf-8",
    mode: int | None = None,
    fsync: bool = True,
    refuse_paths: Collection[StrPath] = (),
    prefix: str = ".sesslint_tmp_",
    pre_write_hook: Callable[[], None] | None = None,
    pre_rename_hook: Callable[[Path], None] | None = None,
    sync_dir: bool = False,
    exclusive: bool = False,
) -> str:
    """Convenience helper to write text to dest atomically using strict encoding.

    Args:
        dest: Destination path where the file will be placed.
        text: Text string to write.
        encoding: Character encoding (defaults to 'utf-8').
        mode: Optional permissions mode to apply before rename.
        fsync: Whether to flush and fsync before rename (defaults to True).
        refuse_paths: Prohibited paths that must never be overwritten.
        prefix: Prefix for the temporary file name.
        pre_write_hook: Optional hook called after temp file creation before write.
        pre_rename_hook: Optional hook called with temp Path before atomic rename.
        sync_dir: Whether to fsync parent directory after rename.
        exclusive: Refuse (never replace) an existing destination entry (B23(a)).

    Returns:
        64-character lowercase SHA-256 hexadecimal digest of the written bytes.

    Raises:
        AtomicWriteError: On refuse check failure or I/O failure.
    """
    try:
        data = text.encode(encoding, errors="strict")
    except Exception as err:
        raise AtomicWriteError(f"Failed to encode text with encoding '{encoding}': {err}") from err

    return atomic_write_bytes(
        dest,
        data,
        mode=mode,
        fsync=fsync,
        refuse_paths=refuse_paths,
        prefix=prefix,
        pre_write_hook=pre_write_hook,
        pre_rename_hook=pre_rename_hook,
        sync_dir=sync_dir,
        exclusive=exclusive,
    )
