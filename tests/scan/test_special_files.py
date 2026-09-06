"""Tests for special file handling (FIFO, sockets, devices) during scan (TASK-024)."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

from sesslint.api import check_dir
from sesslint.scan import scan_path


def test_fifo_skipped_if_supported(tmp_path: Path) -> None:
    """FIFO files are skipped without blocking."""
    if not hasattr(os, "mkfifo"):
        pytest.skip("os.mkfifo is not supported on this platform")

    fifo_path = tmp_path / "test_pipe.fifo"
    try:
        os.mkfifo(fifo_path)
    except OSError as exc:
        pytest.skip(f"mkfifo failed: {exc}")

    report = check_dir(tmp_path, recursive=True)
    fifo_results = [f for f in report.files if (f.skipped_reason or "").startswith("fifo")]
    assert len(fifo_results) == 1
    assert fifo_results[0].verdict == "skipped"


def test_special_file_skipped_via_stat_inspection(tmp_path: Path) -> None:
    """Special file modes (FIFO, socket, device) are skipped via stat inspection."""
    dummy_file = tmp_path / "mock_device.node"
    dummy_file.write_text("placeholder", encoding="utf-8")

    # Simulate S_IFCHR (character device)
    orig_lstat = Path.lstat

    def mock_lstat(self: Path) -> os.stat_result:
        real_st = orig_lstat(self)
        if self.name == "mock_device.node":
            # Override st_mode with character device
            new_mode = (real_st.st_mode & ~0o170000) | stat.S_IFCHR
            return os.stat_result(
                (
                    new_mode,
                    real_st.st_ino,
                    real_st.st_dev,
                    real_st.st_nlink,
                    real_st.st_uid,
                    real_st.st_gid,
                    real_st.st_size,
                    real_st.st_atime,
                    real_st.st_mtime,
                    real_st.st_ctime,
                )
            )
        return real_st

    with patch.object(Path, "lstat", mock_lstat):
        report = scan_path(dummy_file, recursive=False)
        assert len(report.files) == 1
        assert report.files[0].verdict == "skipped"
        assert report.files[0].skipped_reason == "device-special-file-skipped"
        assert report.totals.skipped == 1
