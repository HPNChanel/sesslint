"""Tests for hardlink and repeat path deduplication during scan (TASK-024)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from sesslint.api import check_dir
from sesslint.scan import ScanReport


def test_hardlink_deduplication(tmp_path: Path) -> None:
    """Hardlink duplicate is marked skipped with duplicate-hardlink reason."""
    file_a = tmp_path / "file_a.jsonl"
    file_a.write_text(
        '{"id":"1","type":"user_message","message":"hello","timestamp":"2025-01-01T12:00:00Z"}\n'
        '{"id":"2","parentId":"1","type":"assistant_message","message":"hi","timestamp":"2025-01-01T12:00:01Z"}\n',
        encoding="utf-8",
    )

    file_b = tmp_path / "file_b.jsonl"
    try:
        os.link(file_a, file_b)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"Hard links not supported: {exc}")

    report: ScanReport = check_dir(tmp_path, recursive=True)

    # Exactly 2 files discovered
    assert len(report.files) == 2
    verdicts = [f.verdict for f in report.files]
    assert "healthy" in verdicts
    assert "skipped" in verdicts

    dup = [f for f in report.files if f.verdict == "skipped"][0]
    assert dup.skipped_reason == "duplicate-hardlink"
    assert report.totals.healthy == 1
    assert report.totals.skipped == 1
