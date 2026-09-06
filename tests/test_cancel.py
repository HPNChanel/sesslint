"""Tests for safe cancellation and interrupt handling (TASK-027, FR-096, AC-013).

Guarantees:
- KeyboardInterrupt / SIGINT cleanly cancels check, scan, or repair.
- Exits with 130 (or 1).
- Stdout never carries valid healthy JSON on interrupted run.
- Stderr carries clear cancellation message.
- Temporary files are purged and target output is never published.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from sesslint.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "determinism" / "repeat"
VALID_SESSION = FIXTURES_DIR / "repeat_session.json"


def test_cancel_check_human_mode(capsys: pytest.CaptureFixture[str]) -> None:
    """KeyboardInterrupt during check in human mode exits 130 with clean message."""
    with patch("sesslint.repair.executor.run_all_checks", side_effect=KeyboardInterrupt):
        exit_code = main(["check", str(VALID_SESSION)])

    captured = capsys.readouterr()
    assert exit_code == 130
    assert "Operation cancelled by user" in captured.err
    assert captured.out.strip() == ""


def test_cancel_check_json_mode(capsys: pytest.CaptureFixture[str]) -> None:
    """KeyboardInterrupt during check in --json mode exits 130 and stdout is never valid JSON."""
    with patch("sesslint.repair.executor.run_all_checks", side_effect=KeyboardInterrupt):
        exit_code = main(["check", str(VALID_SESSION), "--json"])

    captured = capsys.readouterr()
    assert exit_code == 130
    assert "Operation cancelled by user" in captured.err

    # Stdout must not be a valid healthy report
    if captured.out.strip():
        try:
            data = json.loads(captured.out)
            assert data.get("assurance") != "A0" or data.get("verdict") != "healthy"
        except json.JSONDecodeError:
            pass  # Truncated or empty is expected and safe


def test_cancel_repair_cleans_up_and_leaves_no_target(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """KeyboardInterrupt during repair cleans up temp files and leaves target untouched."""
    out_file = tmp_path / "cancelled_output.json"
    assert not out_file.exists()

    with patch("sesslint.repair.planner.plan", side_effect=KeyboardInterrupt):
        exit_code = main(["repair", str(VALID_SESSION), "--output", str(out_file)])

    captured = capsys.readouterr()
    assert exit_code == 130
    assert "Operation cancelled by user" in captured.err

    # Target output must not exist
    assert not out_file.exists()
    assert not (tmp_path / f"{out_file.name}.manifest.json").exists()

    # No leftover temporary files
    leftover_tmps = list(tmp_path.glob(".*.tmp*"))
    assert not leftover_tmps
