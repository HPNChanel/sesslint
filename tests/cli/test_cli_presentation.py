"""Tests for CLI human presentation and ANSI table alignment (P2-03 / TASK-023)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from sesslint.cli import format_scan_report_human, main
from sesslint.scan import FileResult, ScanReport, ScanTotals

ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "scan" / "mixed"


def _make_dummy_scan_report() -> ScanReport:
    """Construct a synthetic ScanReport containing every verdict type."""
    files = (
        FileResult(path="sessions/turn_01.jsonl", verdict="healthy"),
        FileResult(
            path="sessions/turn_02.jsonl",
            verdict="invalid",
            error_count=2,
            warning_count=1,
        ),
        FileResult(path="sessions/turn_03.jsonl", verdict="unsupported"),
        FileResult(path="sessions/turn_04.jsonl", verdict="unreadable"),
        FileResult(
            path="sessions/turn_05.jsonl",
            verdict="skipped",
            skipped_reason="max-depth-exceeded",
        ),
    )
    totals = ScanTotals(healthy=1, invalid=1, unsupported=1, unreadable=1, skipped=1)
    return ScanReport(
        root_path="/test/sessions",
        totals=totals,
        files=files,
    )


def test_ansi_table_width_alignment() -> None:
    """Verify that colored and uncolored scan table tags align at identical visual column widths."""
    report = _make_dummy_scan_report()

    colored_output = format_scan_report_human(report, color=True)
    uncolored_output = format_scan_report_human(report, color=False)

    # 1. Byte-level equality after stripping ANSI escapes
    stripped_output = ANSI_ESCAPE.sub("", colored_output)
    assert stripped_output == uncolored_output

    # 2. Assert that in every file line, the path starts at column 23 (0-indexed)
    file_lines_colored = [
        line
        for line in colored_output.splitlines()
        if line.startswith("  [") or line.startswith("  \033[")
    ]
    file_lines_uncolored = [
        line for line in uncolored_output.splitlines() if line.startswith("  [")
    ]

    assert len(file_lines_colored) == 5
    assert len(file_lines_uncolored) == 5

    for colored_line, uncolored_line in zip(file_lines_colored, file_lines_uncolored, strict=True):
        # Stripped visual line
        stripped_line = ANSI_ESCAPE.sub("", colored_line)
        assert stripped_line == uncolored_line

        # Path starts at column 23: "  " (2) + "[TAG]     " (20) + " " (1) = 23
        idx = stripped_line.find("sessions/")
        assert idx == 23, f"Misaligned path start at column {idx}: {stripped_line}"


def test_cli_scan_command_color_alignment(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify CLI scan output has strictly aligned paths with --color always vs --color never."""
    monkeypatch.delenv("NO_COLOR", raising=False)

    # Run with color always
    main(["scan", str(FIXTURES_DIR), "--color", "always"])
    always_out = capsys.readouterr().out

    # Run with color never
    main(["scan", str(FIXTURES_DIR), "--color", "never"])
    never_out = capsys.readouterr().out

    assert "\033[" in always_out
    assert "\033[" not in never_out

    stripped_always = ANSI_ESCAPE.sub("", always_out)
    assert stripped_always == never_out

    # Check table alignment across all file entries: the status tag occupies
    # columns 2-21 (padded to 20 chars), so every displayed path starts at column 23.
    file_lines = [line for line in never_out.splitlines() if line.startswith("  [")]
    assert len(file_lines) > 0
    for line in file_lines:
        assert len(line) > 23, f"Missing path column: {line}"
        assert line[22] == " " and line[23] != " ", f"Misaligned path start: {line}"


def test_skipped_reasons_aggregate_line() -> None:
    """Skipped-reason aggregates surface cap exhaustion; hint only for cap reasons."""
    files = (
        FileResult(path="a.jsonl", verdict="healthy"),
        FileResult(path="b.jsonl", verdict="skipped", skipped_reason="max-bytes-cap-exceeded"),
        FileResult(path="c.jsonl", verdict="skipped", skipped_reason="max-bytes-cap-exceeded"),
    )
    report = ScanReport(
        root_path="/x",
        totals=ScanTotals(healthy=1, skipped=2),
        files=files,
    )
    out = format_scan_report_human(report, color=False)
    assert "Skipped reasons: max-bytes-cap-exceeded=2" in out
    assert "Hint: resource budget exhausted" in out


def test_skipped_reasons_line_no_hint_for_non_cap() -> None:
    """Non-capability skips get the aggregate line but no budget hint."""
    report = _make_dummy_scan_report()
    out = format_scan_report_human(report, color=False)
    assert "Skipped reasons: max-depth-exceeded=1" in out
    assert "Hint:" not in out


def test_skipped_reasons_line_absent_without_skips() -> None:
    files = (FileResult(path="a.jsonl", verdict="healthy"),)
    report = ScanReport(root_path="/x", totals=ScanTotals(healthy=1), files=files)
    out = format_scan_report_human(report, color=False)
    assert "Skipped reasons:" not in out
