"""Atomic copy-only write operations guaranteeing no torn files or in-place mutations."""

from __future__ import annotations

import hashlib
import os
import tempfile
from collections.abc import Callable, Collection
from pathlib import Path

from sesslint.errors import AtomicWriteError

StrPath = str | os.PathLike[str]


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
) -> str:
    """Write bytes to dest atomically using a temporary file in dest's parent directory.

    Guarantees:
    1. Zero in-place mutation: writes to a hidden temporary file and atomically renames.
    2. Zero partial-visibility: dest is absent or completely intact until atomic rename.
    3. Failure cleanup: temporary file is immediately unlinked if write or rename fails.
    4. Refuse list: strictly refuses to write to any path in refuse_paths (realpath).
    5. Integrity: returns the SHA-256 hex digest of the written bytes.

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

    Returns:
        64-character lowercase SHA-256 hexadecimal digest of the written bytes.

    Raises:
        AtomicWriteError: If refuse_paths check fails, parent directory does not exist,
            or write/rename encounters any I/O or permissions error.
    """
    dest_path = Path(dest)
    dest_real = os.path.realpath(dest_path)

    # 1. Prohibited path preflight check (before creating any temporary artifact)
    for prohibited in refuse_paths:
        prohibited_real = os.path.realpath(prohibited)
        if dest_real == prohibited_real:
            raise AtomicWriteError(
                f"Refusing to write to protected path: {dest} "
                f"(matches prohibited path {prohibited})"
            )

    parent_dir = dest_path.parent
    if not parent_dir.exists():
        raise AtomicWriteError(f"Destination directory does not exist: {parent_dir}")
    if not parent_dir.is_dir():
        raise AtomicWriteError(f"Destination parent path is not a directory: {parent_dir}")

    temp_path: Path | None = None
    try:
        # Create temp file in the same directory/filesystem to guarantee atomic os.replace
        with tempfile.NamedTemporaryFile(
            delete=False,
            dir=parent_dir,
            prefix=prefix,
        ) as tmp_file:
            temp_path = Path(tmp_file.name)
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

        os.replace(temp_path, dest_path)
        temp_path = None  # Successfully replaced, no cleanup needed

        if sync_dir:
            _sync_dir(parent_dir)
    except BaseException as err:
        if temp_path is not None and temp_path.exists():
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
    )
