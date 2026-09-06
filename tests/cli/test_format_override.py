"""Tests for --format override behavior in CLI (TASK-023)."""

from __future__ import annotations

from pathlib import Path

import pytest

from sesslint.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "cli"


def test_format_override_valid(capsys: pytest.CaptureFixture[str]) -> None:
    """Valid --format override resolves the specified adapter explicitly."""
    fixture = FIXTURES_DIR / "check_ambiguity" / "polyglot.json"
    code = main(["check", str(fixture), "--format", "openai-agents"])
    assert code == 0
    captured = capsys.readouterr()
    assert "Valid OpenAI Agents session" in captured.out


def test_format_override_invalid_value(capsys: pytest.CaptureFixture[str]) -> None:
    """Invalid --format value causes exit 2 with usage error."""
    fixture = FIXTURES_DIR / "check_basic" / "healthy.jsonl"
    with pytest.raises(SystemExit) as exc_info:
        main(["check", str(fixture), "--format", "bogus-adapter"])
    assert exc_info.value.code == 2
    captured = capsys.readouterr()
    assert "invalid choice" in captured.err.lower() or "unsupported format" in captured.err.lower()


def test_format_disallowed_by_profile(capsys: pytest.CaptureFixture[str]) -> None:
    """Format disallowed by profile allowlist exits 2."""
    fixture = FIXTURES_DIR / "check_basic" / "healthy.jsonl"
    # claude-strict profile allows only claude and canonical; specifying openai-agents must fail
    code = main(["check", str(fixture), "--format", "openai-agents", "--profile", "claude-strict"])
    assert code == 2
    captured = capsys.readouterr()
    assert "not permitted by profile" in captured.err
