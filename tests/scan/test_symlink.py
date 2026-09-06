"""Tests for symlink handling and loop detection during recursive scan (TASK-024)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from sesslint.api import check_dir
from sesslint.scan import ScanReport


def test_symlink_dir_skipped_by_default(tmp_path: Path) -> None:
    """Directory symlinks are skipped by default when follow_symlinks=False."""
    sub_dir = tmp_path / "target_dir"
    sub_dir.mkdir()
    session_file = sub_dir / "valid.jsonl"
    session_file.write_text(
        '{"id":"1","type":"user_message","message":"hi","timestamp":"2025-01-01T12:00:00Z"}\n'
        '{"id":"2","parentId":"1","type":"assistant_message","message":"ok","timestamp":"2025-01-01T12:00:01Z"}\n',
        encoding="utf-8",
    )

    link_dir = tmp_path / "link_to_dir"
    try:
        os.symlink(sub_dir, link_dir, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"Symlinks not supported in environment: {exc}")

    # Scan with follow_symlinks=False (default)
    report: ScanReport = check_dir(tmp_path, recursive=True, follow_symlinks=False)
    skipped_items = [f for f in report.files if f.verdict == "skipped"]
    assert any("symlink-directory-skipped" in (f.skipped_reason or "") for f in skipped_items)


def test_symlink_cycle_guarded_with_follow_symlinks(tmp_path: Path) -> None:
    """Symlink cycles are detected and aborted cleanly without infinite recursion."""
    dir_a = tmp_path / "dir_a"
    dir_a.mkdir()
    link_back = dir_a / "cycle_link"

    try:
        os.symlink(tmp_path, link_back, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"Symlinks not supported in environment: {exc}")

    # Scan with follow_symlinks=True -> should terminate safely and flag symlink-loop-detected
    report: ScanReport = check_dir(tmp_path, recursive=True, follow_symlinks=True)
    loop_items = [f for f in report.files if (f.skipped_reason or "") == "symlink-loop-detected"]
    assert len(loop_items) >= 1
