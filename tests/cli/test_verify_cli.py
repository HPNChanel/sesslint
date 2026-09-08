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


def test_verify_cli_positional_syntax(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify CLI accepts positional syntax without --plan and renders human mode."""
    d = FIXTURES_DIR / "ok"
    code = main(
        [
            "verify",
            str(d / "source.jsonl"),
            str(d / "output.jsonl"),
            "--manifest",
            str(d / "manifest.json"),
        ]
    )
    assert code == 0
    captured = capsys.readouterr()
    assert "Verification: PASSED" in captured.out
    assert "Checks:" in captured.out
    assert "source_hash: matched" in captured.out


def test_verify_cli_positional_with_json_flag(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify CLI accepts --json flag alongside positional arguments."""
    d = FIXTURES_DIR / "ok"
    code = main(
        [
            "verify",
            str(d / "source.jsonl"),
            str(d / "output.jsonl"),
            "--manifest",
            str(d / "manifest.json"),
            "--json",
        ]
    )
    assert code == 0
    captured = capsys.readouterr()
    verdict = json.loads(captured.out)
    assert verdict["ok"] is True


def test_verify_cli_positional_tampered_human_mode(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify CLI prints human failure format on tampered output without --json."""
    d = FIXTURES_DIR / "tampered_output"
    code = main(
        [
            "verify",
            str(d / "source.jsonl"),
            str(d / "output.jsonl"),
            "--manifest",
            str(d / "manifest.json"),
        ]
    )
    assert code == 1
    captured = capsys.readouterr()
    assert "Verification: FAILED" in captured.out
    assert "Checks:" in captured.out
    assert "output_hash" in captured.out


def test_verify_cli_positional_missing_repaired_exits_2() -> None:
    """Verify CLI exits 2 when repaired positional argument is omitted."""
    d = FIXTURES_DIR / "ok"
    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                "verify",
                str(d / "source.jsonl"),
                "--manifest",
                str(d / "manifest.json"),
            ]
        )
    assert exc_info.value.code == 2
