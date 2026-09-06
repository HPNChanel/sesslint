"""Tests for CLI exit code matrix 0 / 1 / 2 (TASK-023)."""

from __future__ import annotations

from pathlib import Path

import pytest

from sesslint.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "cli"


def test_exit_code_0_matrix(tmp_path: Path) -> None:
    """Exit code 0 is returned on healthy check, formats, and version."""
    fixture = FIXTURES_DIR / "check_basic" / "healthy.jsonl"
    assert main(["check", str(fixture)]) == 0
    assert main(["check", str(fixture), "--json"]) == 0
    assert main(["formats"]) == 0
    assert main(["formats", "--json"]) == 0
    assert main(["version"]) == 0
    assert main(["version", "--json"]) == 0


def test_exit_code_1_matrix(tmp_path: Path) -> None:
    """Exit code 1 is returned when findings (error/fatal) or ambiguity exist."""
    ambig_fixture = FIXTURES_DIR / "check_ambiguity" / "polyglot.json"
    assert main(["check", str(ambig_fixture)]) == 1

    corrupt = tmp_path / "corrupt.jsonl"
    corrupt.write_text('{"id":"1","type":"unknown_bogus"}\n', encoding="utf-8")
    assert main(["check", str(corrupt), "--format", "claude-code-jsonl"]) == 1


def _run_cli(argv: list[str]) -> int:
    try:
        return main(argv)
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 0


def test_exit_code_2_matrix(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Exit code 2 is returned on usage errors, unreadable arguments, or missing paths."""
    # 1. Missing path arg
    assert _run_cli(["check"]) == 2

    # 2. Invalid format option
    fixture = FIXTURES_DIR / "check_basic" / "healthy.jsonl"
    assert _run_cli(["check", str(fixture), "--format", "non_existent_fmt"]) == 2

    # 3. Invalid profile option
    assert _run_cli(["check", str(fixture), "--profile", "non_existent_prof"]) == 2

    # 4. Directory input without recursive flag
    assert _run_cli(["check", str(tmp_path)]) == 2

    # 5. Nonexistent file
    missing = tmp_path / "missing.jsonl"
    assert _run_cli(["check", str(missing)]) == 2
