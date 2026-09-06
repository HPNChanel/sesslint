"""Tests for sesslint check command (TASK-023)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.cli import main
from sesslint.report import parse_report

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "cli"


def test_check_healthy_human(capsys: pytest.CaptureFixture[str]) -> None:
    """Healthy session exits 0, contains '[read-only]' and 'healthy', stderr is empty."""
    fixture = FIXTURES_DIR / "check_basic" / "healthy.jsonl"
    code = main(["check", str(fixture)])
    assert code == 0
    captured = capsys.readouterr()
    assert "[read-only]" in captured.out
    assert "healthy" in captured.out.lower()
    assert captured.err == ""


def test_check_healthy_json(capsys: pytest.CaptureFixture[str]) -> None:
    """Healthy session with --json outputs valid Report schema with total==0 and exits 0."""
    fixture = FIXTURES_DIR / "check_basic" / "healthy.jsonl"
    code = main(["check", str(fixture), "--json"])
    assert code == 0
    captured = capsys.readouterr()
    assert captured.err == ""

    data = json.loads(captured.out)
    assert data["schema_version"] == "sesslint.report/v1"
    assert data["counts"]["total"] == 0
    assert data["counts"]["by_severity"]["error"] == 0
    # Must parse cleanly with parse_report validator
    rep = parse_report(data)
    assert rep.counts.total == 0


def test_check_finding_exit1(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Session with structural flaw exits 1 and lists finding in human and JSON modes."""
    # Orphan tool_result without tool_use
    bad_session = tmp_path / "broken.jsonl"
    bad_session.write_text(
        '{"id":"msg_01","type":"user_message","message":"hi"}\n'
        '{"id":"msg_02","parentId":"msg_01","type":"tool_result","toolUseId":"call_missing","content":"res"}\n',
        encoding="utf-8",
    )

    # Human mode
    code = main(["check", str(bad_session), "--format", "claude-code-jsonl"])
    assert code == 1
    captured = capsys.readouterr()
    assert "Integrity check failed" in captured.out
    assert "SL101" in captured.out

    # JSON mode
    code_json = main(["check", str(bad_session), "--format", "claude-code-jsonl", "--json"])
    assert code_json == 1
    captured_json = capsys.readouterr()
    data = json.loads(captured_json.out)
    assert data["counts"]["total"] >= 1
    assert any(f["code"] == "SL101" for f in data["findings"])


def test_check_ambiguity_fail_closed(capsys: pytest.CaptureFixture[str]) -> None:
    """Ambiguous format fails closed with exit 1 and stderr actionable hint."""
    fixture = FIXTURES_DIR / "check_ambiguity" / "polyglot.json"
    code = main(["check", str(fixture)])
    assert code == 1
    captured = capsys.readouterr()
    assert "Format detection ambiguous" in captured.err
    assert "specify --format" in captured.err

    # With --json
    code_json = main(["check", str(fixture), "--json"])
    assert code_json == 1
    captured_json = capsys.readouterr()
    data = json.loads(captured_json.out)
    assert any(f["code"] == "SL302" for f in data["findings"])


def test_check_directory_rejected(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Directory passed to check without recursive exits 2 with error."""
    code = main(["check", str(tmp_path)])
    assert code == 2
    captured = capsys.readouterr()
    assert "directory" in captured.err.lower()
    assert "--recursive" in captured.err


def test_check_nonexistent_file(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Non-existent file exits 2 with error."""
    non_file = tmp_path / "does_not_exist.jsonl"
    code = main(["check", str(non_file)])
    assert code == 2
    captured = capsys.readouterr()
    assert "not found" in captured.err.lower()


def test_check_binary_non_utf8_file(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Binary non-UTF8 file fails closed with exit 1 or 2, never raises unhandled exception."""
    bin_file = tmp_path / "corrupt.dat"
    bin_file.write_bytes(b"\x00\xff\xfe\x00\xaa\xbb\xcc\xdd" * 100)
    code = main(["check", str(bin_file), "--json"])
    assert code in (1, 2)
    captured = capsys.readouterr()
    # In JSON mode with exit 1, output should still be valid JSON
    if code == 1 and captured.out.strip():
        data = json.loads(captured.out)
        assert data["schema_version"] == "sesslint.report/v1"
