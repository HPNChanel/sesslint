"""Tests for --profile override behavior in CLI (TASK-023)."""

from __future__ import annotations

from pathlib import Path

import pytest

from sesslint.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "cli"


def test_profile_override_valid(capsys: pytest.CaptureFixture[str]) -> None:
    """Valid profile override is accepted and executes check."""
    fixture = FIXTURES_DIR / "check_basic" / "healthy.jsonl"
    code = main(["check", str(fixture), "--profile", "claude-strict"])
    assert code == 0
    captured = capsys.readouterr()
    assert "healthy" in captured.out.lower()


def test_profile_override_invalid(capsys: pytest.CaptureFixture[str]) -> None:
    """Invalid profile causes parser error with exit 2."""
    fixture = FIXTURES_DIR / "check_basic" / "healthy.jsonl"
    with pytest.raises(SystemExit) as exc_info:
        main(["check", str(fixture), "--profile", "unknown_profile_xyz"])
    assert exc_info.value.code == 2
    captured = capsys.readouterr()
    assert "unknown profile" in captured.err.lower() or "error" in captured.err.lower()
