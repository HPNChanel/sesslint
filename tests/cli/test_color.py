"""Tests for ANSI color and TTY awareness in CLI (TASK-023)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from sesslint.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "cli"
ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def test_color_never_no_ansi(capsys: pytest.CaptureFixture[str]) -> None:
    """--color never emits no ANSI escape sequences."""
    fixture = FIXTURES_DIR / "check_basic" / "healthy.jsonl"
    code = main(["check", str(fixture), "--color", "never"])
    assert code == 0
    captured = capsys.readouterr()
    assert "\033[" not in captured.out


def test_color_always_has_ansi(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """--color always emits ANSI escapes in human mode when NO_COLOR is not set."""
    monkeypatch.delenv("NO_COLOR", raising=False)
    fixture = FIXTURES_DIR / "check_basic" / "healthy.jsonl"
    code = main(["check", str(fixture), "--color", "always"])
    assert code == 0
    captured = capsys.readouterr()
    assert "\033[" in captured.out


def test_color_no_color_env_overrides_always(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """NO_COLOR environment variable forces color off even with --color always."""
    monkeypatch.setenv("NO_COLOR", "1")
    fixture = FIXTURES_DIR / "check_basic" / "healthy.jsonl"
    code = main(["check", str(fixture), "--color", "always"])
    assert code == 0
    captured = capsys.readouterr()
    assert "\033[" not in captured.out


def test_color_json_never_colors(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """JSON output mode never includes ANSI escapes, even with --color always."""
    monkeypatch.delenv("NO_COLOR", raising=False)
    fixture = FIXTURES_DIR / "check_basic" / "healthy.jsonl"
    code = main(["check", str(fixture), "--json", "--color", "always"])
    assert code == 0
    captured = capsys.readouterr()
    assert "\033[" not in captured.out


def test_color_semantic_neutrality(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Stripping ANSI codes from --color always output yields identical text to --color never."""
    monkeypatch.delenv("NO_COLOR", raising=False)
    fixture = FIXTURES_DIR / "check_basic" / "healthy.jsonl"

    main(["check", str(fixture), "--color", "never"])
    never_out = capsys.readouterr().out

    main(["check", str(fixture), "--color", "always"])
    always_out = capsys.readouterr().out

    stripped = ANSI_ESCAPE.sub("", always_out)
    assert stripped == never_out
