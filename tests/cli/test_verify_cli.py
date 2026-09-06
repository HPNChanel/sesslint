"""Tests for sesslint verify CLI command wiring (TASK-024)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "verify"


def test_verify_cli_ok_set(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify CLI exits 0 on valid, untampered repair artifacts."""
    d = FIXTURES_DIR / "ok"
    code = main(
        [
            "verify",
            "--source",
            str(d / "source.jsonl"),
            "--plan",
            str(d / "plan.json"),
            "--output",
            str(d / "output.jsonl"),
            "--manifest",
            str(d / "manifest.json"),
        ]
    )
    assert code == 0

    captured = capsys.readouterr()
    verdict = json.loads(captured.out)
    assert verdict["ok"] is True
    assert "checks" in verdict
    assert "assurance" in verdict


def test_verify_cli_tampered_output(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify CLI exits 1 on tampered output artifact."""
    d = FIXTURES_DIR / "tampered_output"
    code = main(
        [
            "verify",
            "--source",
            str(d / "source.jsonl"),
            "--plan",
            str(d / "plan.json"),
            "--output",
            str(d / "output.jsonl"),
            "--manifest",
            str(d / "manifest.json"),
        ]
    )
    assert code == 1

    captured = capsys.readouterr()
    verdict = json.loads(captured.out)
    assert verdict["ok"] is False


def test_verify_cli_missing_flag_exits_2() -> None:
    """Verify CLI exits 2 when required flag is missing."""
    with pytest.raises(SystemExit) as exc_info:
        main(["verify", "--source", "fake.jsonl"])
    assert exc_info.value.code == 2
