"""Source fingerprinting, immutability guarding, and concurrent-modification detection."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from sesslint.errors import SourceChangedError
from sesslint.io import ReaderLimits, iter_events

if TYPE_CHECKING:
    from sesslint.canonical import SessionEvent
    from sesslint.finding import Finding

StrPath = str | os.PathLike[str]


def fingerprint_file(path: StrPath, *, chunk_size: int = 65536) -> str:
    """Compute the SHA-256 hex digest of a file's raw bytes in streaming chunks.

    Args:
        path: Path to the target file.
        chunk_size: Byte size of chunks to read into memory (defaults to 64 KiB).

    Returns:
        64-character lowercase SHA-256 hexadecimal digest.

    Raises:
        ValueError: If chunk_size is not positive.
        IsADirectoryError: If path points to a directory.
        FileNotFoundError: If path does not exist.
        OSError: If reading the file fails.
    """
    if chunk_size <= 0:
        raise ValueError(f"chunk_size must be positive, got {chunk_size}")

    path_obj = Path(path)
    if path_obj.is_dir():
        raise IsADirectoryError(f"Expected file, got directory: {path}")

    hasher = hashlib.sha256()
    with open(path_obj, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


@dataclass(frozen=True, slots=True)
class SourceGuard:
    """Snapshot of a source file's identity and state for concurrent-mutation detection."""

    path: Path
    sha256: str
    size: int
    mtime_ns: int


def guard(path: StrPath) -> SourceGuard:
    """Create a guard snapshot of a source file before processing.

    Follows symlinks and records the canonical realpath, initial size, mtime, and SHA-256.

    Args:
        path: Path to the source file to guard.

    Returns:
        Frozen SourceGuard snapshot.

    Raises:
        IsADirectoryError: If path points to a directory.
        FileNotFoundError: If path does not exist.
        OSError: On filesystem access errors.
    """
    real_path = Path(os.path.realpath(path))
    if real_path.is_dir():
        raise IsADirectoryError(f"Expected file, got directory: {path}")

    st = real_path.stat()
    digest = fingerprint_file(real_path)
    return SourceGuard(
        path=real_path,
        sha256=digest,
        size=st.st_size,
        mtime_ns=st.st_mtime_ns,
    )


def verify(g: SourceGuard) -> None:
    """Verify that a guarded source file has remained untouched since guard creation.

    Performs a fast-path check on file size and mtime_ns, followed by a full SHA-256
    hash comparison.

    Args:
        g: The SourceGuard created before processing started.

    Raises:
        SourceChangedError: If the file was deleted, truncated, appended, or rewritten.
    """
    try:
        st = g.path.stat()
    except OSError as err:
        raise SourceChangedError(
            f"Source file inaccessible or removed during processing: {g.path} ({err})"
        ) from err

    if st.st_size != g.size or st.st_mtime_ns != g.mtime_ns:
        raise SourceChangedError(
            f"Source file metadata changed concurrently: {g.path} "
            f"(expected size {g.size}B mtime {g.mtime_ns}ns, "
            f"got size {st.st_size}B mtime {st.st_mtime_ns}ns)"
        )

    current_digest = fingerprint_file(g.path)
    if current_digest != g.sha256:
        raise SourceChangedError(
            f"Source file content SHA-256 modified concurrently: {g.path} "
            f"(expected {g.sha256}, got {current_digest})"
        )


def guarded_iter_events(
    path: StrPath,
    *,
    limits: ReaderLimits | None = None,
) -> Iterator[SessionEvent | Finding]:
    """Stream session events and findings from path, verifying file immutability upon exhaustion.

    A SourceGuard snapshot is captured before reading begins. On normal completion of
    the stream, the file is re-verified to confirm zero concurrent mutations occurred.

    Args:
        path: Path to the session file.
        limits: Optional reader limits for bounded streaming.

    Yields:
        SessionEvent instances or Finding diagnostics emitted during streaming.

    Raises:
        SourceChangedError: If the file was modified concurrently while being iterated.
    """
    effective_limits = ReaderLimits() if limits is None else limits
    g = guard(path)
    yield from iter_events(path, limits=effective_limits)
    verify(g)


@contextmanager
def guarded(path: StrPath) -> Iterator[SourceGuard]:
    """Context manager wrapping manual loops or inspections with pre/post immutability checks.

    Args:
        path: Path to the source file to guard.

    Yields:
        Active SourceGuard instance.

    Raises:
        SourceChangedError: If the source file was modified before the context exited.
    """
    g = guard(path)
    yield g
    verify(g)
