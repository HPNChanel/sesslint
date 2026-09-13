"""Unit tests for atomic write helper and copy-only repair safety contracts."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from sesslint.atomic import atomic_write_bytes, atomic_write_text
from sesslint.errors import AtomicWriteError


def test_atomic_write_bytes_basic(tmp_path: Path) -> None:
    """atomic_write_bytes writes exact bytes and returns correct SHA-256 digest."""
    dest = tmp_path / "out.jsonl"
    data = b'{"hello": "world"}\n'
    expected_hash = hashlib.sha256(data).hexdigest()

    returned_hash = atomic_write_bytes(dest, data)
    assert returned_hash == expected_hash
    assert dest.exists()
    assert dest.read_bytes() == data


def test_atomic_write_text_basic(tmp_path: Path) -> None:
    """atomic_write_text writes UTF-8 text and returns SHA-256 digest."""
    dest = tmp_path / "out_text.jsonl"
    text = '{"message": "h\u00e9llo \u2728"}\n'
    expected_data = text.encode("utf-8")
    expected_hash = hashlib.sha256(expected_data).hexdigest()

    returned_hash = atomic_write_text(dest, text)
    assert returned_hash == expected_hash
    assert dest.read_bytes() == expected_data


def test_atomic_write_refuses_protected_source_path(tmp_path: Path) -> None:
    """atomic_write_bytes raises AtomicWriteError before creating temp when dest in refuse_paths."""
    source_file = tmp_path / "original_source.jsonl"
    source_file.write_bytes(b"initial source")

    # Destination is identical to source
    with pytest.raises(AtomicWriteError, match="Refusing to write to protected path"):
        atomic_write_bytes(source_file, b"corrupted rewrite", refuse_paths=[source_file])

    # Assert source file was completely untouched
    assert source_file.read_bytes() == b"initial source"

    # Assert zero temporary files were created in parent directory
    temp_files = list(tmp_path.glob(".sesslint_tmp_*"))
    assert len(temp_files) == 0


def test_atomic_write_refuses_equivalent_resolved_path(tmp_path: Path) -> None:
    """atomic_write_bytes detects path equivalence via realpath."""
    source_file = tmp_path / "source.jsonl"
    source_file.write_bytes(b"data")

    # Reference the same file via relative navigation (./source.jsonl or sub/../source.jsonl)
    dest_path = tmp_path / "subdir" / ".." / "source.jsonl"

    with pytest.raises(AtomicWriteError, match="Refusing to write to protected path"):
        atomic_write_bytes(dest_path, b"new", refuse_paths=[source_file])


def test_atomic_write_nonexistent_parent_raises(tmp_path: Path) -> None:
    """atomic_write_bytes raises AtomicWriteError if parent directory does not exist."""
    nonexistent_dir = tmp_path / "missing_dir" / "out.jsonl"
    with pytest.raises(AtomicWriteError, match="Destination directory does not exist"):
        atomic_write_bytes(nonexistent_dir, b"data")


def test_atomic_write_parent_is_not_dir_raises(tmp_path: Path) -> None:
    """atomic_write_bytes raises AtomicWriteError if parent path is a regular file."""
    regular_file = tmp_path / "file.txt"
    regular_file.write_text("not a directory", encoding="utf-8")
    bad_dest = regular_file / "out.jsonl"

    with pytest.raises(AtomicWriteError):
        atomic_write_bytes(bad_dest, b"data")


def test_atomic_write_failure_cleans_temp_file(tmp_path: Path) -> None:
    """If write or replace fails, temp file is unlinked and dest is untouched."""
    dest = tmp_path / "output.jsonl"
    dest.write_bytes(b"pre-existing untouched")

    # Simulate an I/O failure during os.replace
    with patch("os.replace", side_effect=OSError("Disk write error")):
        with pytest.raises(AtomicWriteError, match="Atomic write to .* failed"):
            atomic_write_bytes(dest, b"bad new data")

    # Original destination remains untouched
    assert dest.read_bytes() == b"pre-existing untouched"

    # Temporary file was cleaned up and does not linger
    temp_files = list(tmp_path.glob(".sesslint_tmp_*"))
    assert len(temp_files) == 0


def test_atomic_write_overwrites_existing_unprotected_dest(tmp_path: Path) -> None:
    """atomic_write_bytes cleanly and atomically overwrites non-protected target."""
    dest = tmp_path / "previous_repair.jsonl"
    dest.write_bytes(b"old version")

    new_data = b"new version"
    atomic_write_bytes(dest, new_data)
    assert dest.read_bytes() == new_data


def test_atomic_write_mode_applied(tmp_path: Path) -> None:
    """atomic_write_bytes applies requested permissions mode when provided."""
    dest = tmp_path / "private.jsonl"
    data = b"confidential"
    atomic_write_bytes(dest, data, mode=0o600)

    assert dest.exists()
    assert dest.read_bytes() == data
    # On POSIX systems, verify mode bits
    if os.name != "nt":
        stat_mode = dest.stat().st_mode & 0o777
        assert stat_mode == 0o600


def test_atomic_write_custom_prefix(tmp_path: Path) -> None:
    """atomic_write_bytes respects custom temporary file prefix during write."""
    dest = tmp_path / "custom_prefix_target.jsonl"
    created_prefix: list[str] = []

    def inspect_temp_prefix(temp_path: Path) -> None:
        created_prefix.append(temp_path.name)

    atomic_write_bytes(
        dest,
        b"data",
        prefix=".custom_sesslint_prefix_",
        pre_rename_hook=inspect_temp_prefix,
    )
    assert len(created_prefix) == 1
    assert created_prefix[0].startswith(".custom_sesslint_prefix_")
    assert dest.read_bytes() == b"data"


def test_atomic_write_hooks_lifecycle(tmp_path: Path) -> None:
    """pre_write_hook and pre_rename_hook fire in correct order and clean up on failure."""
    dest = tmp_path / "hook_target.jsonl"
    lifecycle: list[str] = []

    def on_pre_write() -> None:
        lifecycle.append("pre_write")

    def on_pre_rename(temp_p: Path) -> None:
        lifecycle.append("pre_rename")
        assert temp_p.exists()
        assert temp_p.read_bytes() == b"payload"

    atomic_write_bytes(
        dest,
        b"payload",
        pre_write_hook=on_pre_write,
        pre_rename_hook=on_pre_rename,
        sync_dir=True,
    )
    assert lifecycle == ["pre_write", "pre_rename"]
    assert dest.read_bytes() == b"payload"

    # Verify failure in pre_rename_hook cleans up temporary file
    failing_dest = tmp_path / "fail_target.jsonl"

    def failing_rename_hook(temp_p: Path) -> None:
        raise RuntimeError("Fault injection before rename")

    with pytest.raises(AtomicWriteError, match="Fault injection before rename"):
        atomic_write_bytes(failing_dest, b"fail", pre_rename_hook=failing_rename_hook)

    assert not failing_dest.exists()
    assert list(tmp_path.glob(".sesslint_tmp_*")) == []


def test_atomic_write_text_passthrough_options(tmp_path: Path) -> None:
    """atomic_write_text correctly forwards prefix, hooks, and sync_dir."""
    dest = tmp_path / "text_target.jsonl"
    hook_fired = False

    def on_rename(temp_p: Path) -> None:
        nonlocal hook_fired
        hook_fired = True
        assert temp_p.name.startswith(".text_prefix_")

    atomic_write_text(
        dest,
        "text data",
        prefix=".text_prefix_",
        pre_rename_hook=on_rename,
        sync_dir=True,
    )
    assert hook_fired is True
    assert dest.read_text(encoding="utf-8") == "text data"
