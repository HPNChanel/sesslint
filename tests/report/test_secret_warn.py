"""Tests for --include-content warning banner and JSON markers (TASK-025)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "report" / "secret_seed"
WARNING_MESSAGE = "WARNING: --include-content embeds raw transcript content; do not share output"


def test_secret_warning_emitted_to_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify that --include-content emits the exact warning banner to stderr."""
    fixture = FIXTURES_DIR / "claude_secret.jsonl"
    code = main(["check", str(fixture), "--format", "claude-code-jsonl", "--include-content"])
    assert code == 0
    captured = capsys.readouterr()
    assert WARNING_MESSAGE in captured.err


def test_secret_warning_absent_in_default_mode(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify that running without --include-content produces zero warning in stderr."""
    fixture = FIXTURES_DIR / "claude_secret.jsonl"
    code = main(["check", str(fixture), "--format", "claude-code-jsonl"])
    assert code == 0
    captured = capsys.readouterr()
    assert WARNING_MESSAGE not in captured.err
    assert captured.err == ""


def test_json_warning_keys_present_only_with_flag(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify JSON output includes content_warning and included_content only with flag."""
    fixture = FIXTURES_DIR / "claude_secret.jsonl"

    # With flag
    code_flag = main(
        [
            "check",
            str(fixture),
            "--format",
            "claude-code-jsonl",
            "--json",
            "--include-content",
        ]
    )
    assert code_flag == 0
    captured_flag = capsys.readouterr()
    data_flag = json.loads(captured_flag.out)
    assert data_flag["content_warning"] is True
    assert data_flag["included_content"] is True

    # Without flag
    code_no_flag = main(
        [
            "check",
            str(fixture),
            "--format",
            "claude-code-jsonl",
            "--json",
        ]
    )
    assert code_no_flag == 0
    captured_no_flag = capsys.readouterr()
    data_no_flag = json.loads(captured_no_flag.out)
    assert "content_warning" not in data_no_flag
    assert "included_content" not in data_no_flag
