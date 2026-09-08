"""Tests for I/O and binary read error separation into unreadable bucket (TASK-024)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

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


def test_scan_fault_isolation_on_unhandled_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RVW-022: Crashing single file during checking does not abort directory scan."""
    f1 = tmp_path / "normal.jsonl"
    f1.write_text(
        '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"s1"}\n'
        '{"actor":"user","id":"m1","kind":"message","parent_id":null,"payload":{"text":"hi"},"seq":0,"ts":"2026-09-05T12:00:00Z"}\n',
        encoding="utf-8",
    )
    f2 = tmp_path / "crashing.jsonl"
    f2.write_text(
        '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"s2"}\n'
        '{"actor":"user","id":"m2","kind":"message","parent_id":null,"payload":{"text":"boom"},"seq":0,"ts":"2026-09-05T12:00:00Z"}\n',
        encoding="utf-8",
    )

    from sesslint.repair import executor

    original_run_all_checks = executor.run_all_checks

    def crashing_checks(events: Any, profile: str = "neutral", source_path: str = "") -> list[Any]:
        if "crashing" in str(source_path):
            raise RuntimeError("Simulated unexpected crash during checks")
        return list(original_run_all_checks(events, profile=profile, source_path=source_path))

    monkeypatch.setattr(executor, "run_all_checks", crashing_checks)

    report: ScanReport = check_dir(tmp_path, recursive=True)
    assert report.totals.healthy == 1
    assert report.totals.invalid == 1
    crashing_res = next(r for r in report.files if "crashing" in r.path)
    assert crashing_res.verdict == "invalid"
    assert "Failed to process file" in crashing_res.findings[0].message


def test_scan_fault_isolation_on_file_too_large(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RVW-022: FileTooLargeError maps to unreadable without aborting sweep."""
    from sesslint.errors import FileTooLargeError
    from sesslint.repair import executor

    f1 = tmp_path / "normal.jsonl"
    f1.write_text(
        '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"s1"}\n'
        '{"actor":"user","id":"m1","kind":"message","parent_id":null,"payload":{"text":"hi"},"seq":0,"ts":"2026-09-05T12:00:00Z"}\n',
        encoding="utf-8",
    )
    f2 = tmp_path / "huge.jsonl"
    f2.write_text(
        '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"s2"}\n'
        '{"actor":"user","id":"m2","kind":"message","parent_id":null,"payload":{"text":"huge"},"seq":0,"ts":"2026-09-05T12:00:00Z"}\n',
        encoding="utf-8",
    )

    original_run_all_checks = executor.run_all_checks

    def too_large_checks(events: Any, profile: str = "neutral", source_path: str = "") -> list[Any]:
        if "huge" in str(source_path):
            raise FileTooLargeError("File exceeds byte limit")
        return list(original_run_all_checks(events, profile=profile, source_path=source_path))

    monkeypatch.setattr(executor, "run_all_checks", too_large_checks)

    report: ScanReport = check_dir(tmp_path, recursive=True)
    assert report.totals.healthy == 1
    assert report.totals.unreadable == 1
    huge_res = next(r for r in report.files if "huge" in r.path)
    assert huge_res.verdict == "unreadable"
    assert "Unreadable file" in huge_res.findings[0].message
