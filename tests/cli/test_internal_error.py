"""Tests for internal error envelope and non-leak operational failure (TASK-027, FR-097).

Guarantees:
- Unexpected internal errors return diagnostic ID matching ^ERR-[0-9a-f]{8}$.
- In JSON mode, envelope with verdict='error' and code='INTERNAL_ERROR' is emitted.
- In human mode, actionable error information is printed to stderr.
- Never labels the session healthy (verdict != "healthy").
- Exits with return code 1.
- Never prints unhandled python tracebacks to stdout.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from unittest.mock import patch

import pytest

from sesslint.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "determinism" / "repeat"
VALID_SESSION = FIXTURES_DIR / "repeat_session.json"
ERR_ID_PATTERN = re.compile(r"^ERR-[0-9a-fA-F]{8}$")


def test_internal_error_json_mode(capsys: pytest.CaptureFixture[str]) -> None:
    """Internal error in --json mode emits operational error envelope to stdout and exits 1."""
    with patch(
        "sesslint.repair.executor.run_all_checks",
        side_effect=RuntimeError("Simulated engine crash"),
    ):
        exit_code = main(["check", str(VALID_SESSION), "--json"])

    captured = capsys.readouterr()
    assert exit_code == 1

    # Stdout must parse as valid JSON envelope
    envelope = json.loads(captured.out)
    assert envelope["verdict"] == "error"
    assert envelope["code"] == "INTERNAL_ERROR"
    assert ERR_ID_PATTERN.match(envelope["error_id"])
    assert "Simulated engine crash" in envelope["message"]

    # Stdout must never contain Python tracebacks
    assert "Traceback (most recent call last):" not in captured.out


def test_internal_error_human_mode(capsys: pytest.CaptureFixture[str]) -> None:
    """Internal error in human mode emits operational error to stderr and exits 1."""
    with patch(
        "sesslint.repair.executor.run_all_checks",
        side_effect=RuntimeError("Simulated engine crash"),
    ):
        exit_code = main(["check", str(VALID_SESSION)])

    captured = capsys.readouterr()
    assert exit_code == 1

    # Stderr must contain operational error with ERR- ID
    assert "Operational error [ERR-" in captured.err
    assert "Simulated engine crash" in captured.err

    # Stdout must never contain Python tracebacks
    assert "Traceback (most recent call last):" not in captured.out
    assert captured.out.strip() == ""


def test_internal_error_repair_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Internal error during repair command emits operational error and exits 1."""
    out_file = tmp_path / "out.json"
    with patch("sesslint.repair.planner.plan", side_effect=RuntimeError("Simulated planner crash")):
        exit_code = main(["repair", str(VALID_SESSION), "--output", str(out_file), "--json"])

    captured = capsys.readouterr()
    assert exit_code == 1

    envelope = json.loads(captured.out)
    assert envelope["verdict"] == "error"
    assert envelope["code"] == "INTERNAL_ERROR"
    assert ERR_ID_PATTERN.match(envelope["error_id"])
    assert "Simulated planner crash" in envelope["message"]
    assert not out_file.exists()
