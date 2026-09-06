"""Tests for stdout and stderr stream separation (TASK-023)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "cli"


def test_streams_check_json_success(capsys: pytest.CaptureFixture[str]) -> None:
    """In --json mode on clean session, stdout is single JSON document and stderr is empty."""
    fixture = FIXTURES_DIR / "check_basic" / "healthy.jsonl"
    code = main(["check", str(fixture), "--json"])
    assert code == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    # stdout parses cleanly as valid JSON with no extraneous text
    data = json.loads(captured.out)
    assert data["schema_version"] == "sesslint.report/v1"


def test_streams_formats_json_success(capsys: pytest.CaptureFixture[str]) -> None:
    """formats --json emits JSON array to stdout only, stderr empty."""
    code = main(["formats", "--json"])
    assert code == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    data = json.loads(captured.out)
    assert isinstance(data, list)


def test_streams_version_json_success(capsys: pytest.CaptureFixture[str]) -> None:
    """version --json emits JSON object to stdout only, stderr empty."""
    code = main(["version", "--json"])
    assert code == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    data = json.loads(captured.out)
    assert isinstance(data, dict)


def test_streams_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    """Usage error outputs to stderr only; stdout remains empty."""
    with pytest.raises(SystemExit) as exc_info:
        main(["check"])
    assert exc_info.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "usage:" in captured.err.lower() or "error:" in captured.err.lower()


def test_streams_ambiguity_warning_on_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    """Ambiguity warning / hint goes to stderr, JSON report goes to stdout."""
    fixture = FIXTURES_DIR / "check_ambiguity" / "polyglot.json"
    code = main(["check", str(fixture), "--json"])
    assert code == 1
    captured = capsys.readouterr()
    assert "specify --format" in captured.err
    data = json.loads(captured.out)
    assert data["schema_version"] == "sesslint.report/v1"
