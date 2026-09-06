"""Tests for I/O and binary read error separation into unreadable bucket (TASK-024)."""

from __future__ import annotations

from pathlib import Path

from sesslint.api import check_dir, check_file
from sesslint.scan import ScanReport


def test_binary_file_classified_as_unreadable(tmp_path: Path) -> None:
    """Binary files containing NUL bytes are classified as unreadable, never healthy."""
    bin_file = tmp_path / "corrupt.bin"
    bin_file.write_bytes(b"\x00\x01\x02\x03\xff\xfe\x00")

    report: ScanReport = check_dir(tmp_path, recursive=True)
    assert len(report.files) == 1
    assert report.files[0].verdict == "unreadable"
    assert report.totals.unreadable == 1
    assert report.totals.healthy == 0


def test_invalid_utf8_classified_as_unreadable(tmp_path: Path) -> None:
    """Files with non-UTF8 encoding errors are classified as unreadable."""
    bad_utf8 = tmp_path / "bad_utf8.jsonl"
    bad_utf8.write_bytes(b"\xff\xfe non utf8 string")

    report: ScanReport = check_dir(tmp_path, recursive=True)
    assert len(report.files) == 1
    assert report.files[0].verdict == "unreadable"
    assert report.totals.unreadable == 1
    assert report.totals.healthy == 0


def test_check_file_nonexistent_raises_filenotfound(tmp_path: Path) -> None:
    """Non-existent file passed to check_file raises FileNotFoundError."""
    import pytest

    with pytest.raises(FileNotFoundError):
        check_file(tmp_path / "missing.jsonl")
