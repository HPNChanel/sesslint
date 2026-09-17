"""Tests for the --progress-json flag (DW-T-13): NDJSON progress on stderr,
stdout remains the result channel (FR-091)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "cli"
DETECT_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "detect"


def test_check_progress_json_emits_ndjson_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    fixture = FIXTURES_DIR / "check_basic" / "healthy.jsonl"
    code = main(["check", str(fixture), "--json", "--progress-json"])
    assert code == 0
    captured = capsys.readouterr()
    lines = [line for line in captured.err.strip().splitlines() if line.strip()]
    assert len(lines) == 4
    events = [json.loads(line) for line in lines]
    assert [e["phase"] for e in events] == [
        "check:detect",
        "check:load",
        "check:analyze",
        "check:report",
    ]
    # stdout is still the result channel
    report = json.loads(captured.out)
    assert report["schema_version"].startswith("sesslint.report/")


def test_check_without_progress_flag_has_empty_stderr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture = FIXTURES_DIR / "check_basic" / "healthy.jsonl"
    code = main(["check", str(fixture), "--json"])
    assert code == 0
    captured = capsys.readouterr()
    assert captured.err == ""


def test_scan_progress_json_emits_per_file(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["scan", str(DETECT_DIR), "--recursive", "--json", "--progress-json"])
    captured = capsys.readouterr()
    assert code in (0, 1)
    lines = [line for line in captured.err.strip().splitlines() if line.strip()]
    assert len(lines) > 0
    events = [json.loads(line) for line in lines]
    assert all(e["phase"] == "scan" for e in events)
    assert [e["completed"] for e in events] == list(range(1, len(events) + 1))
    # stdout still carries the scan report
    report = json.loads(captured.out)
    assert report["schema_version"].startswith("sesslint.scan-report/")


def test_progress_events_contain_no_full_paths(capsys: pytest.CaptureFixture[str]) -> None:
    fixture = FIXTURES_DIR / "check_basic" / "healthy.jsonl"
    code = main(["check", str(fixture), "--progress-json"])
    assert code == 0
    captured = capsys.readouterr()
    for line in captured.err.strip().splitlines():
        event = json.loads(line)
        item = event.get("item")
        if item is not None:
            assert "/" not in item
            assert "\\" not in item
