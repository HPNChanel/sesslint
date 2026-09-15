"""Tests for vendor-to-canonical export (T-12)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint import api
from sesslint.adapters.canonical import load_canonical
from sesslint.cli import main
from sesslint.exporter import ExportRefused, export_to_canonical

FIXTURES = Path(__file__).resolve().parent.parent.parent / "fixtures"
CANONICAL_MINIMAL = FIXTURES / "canonical" / "minimal.json"
CLAUDE_BASIC = FIXTURES / "claude_code" / "basic.jsonl"
OPENAI_PARALLEL = FIXTURES / "conformance" / "openai_agents" / "parallel_tool.json"
SECRET_SEED = FIXTURES / "conformance" / "secret_seed" / "canonical_secret.jsonl"


def test_export_canonical_roundtrip(tmp_path: Path) -> None:
    out = tmp_path / "out.jsonl"
    summary = export_to_canonical(CANONICAL_MINIMAL, out)
    assert summary.input_format == "canonical"
    assert summary.event_count > 0
    events, _ = load_canonical(out)
    assert len(events) == summary.event_count


def test_export_deterministic(tmp_path: Path) -> None:
    out1 = tmp_path / "a.jsonl"
    out2 = tmp_path / "b.jsonl"
    export_to_canonical(CLAUDE_BASIC, out1)
    export_to_canonical(CLAUDE_BASIC, out2)
    assert out1.read_bytes() == out2.read_bytes()


def test_export_claude_and_openai(tmp_path: Path) -> None:
    claude_out = tmp_path / "claude.jsonl"
    openai_out = tmp_path / "openai.jsonl"
    claude_summary = export_to_canonical(CLAUDE_BASIC, claude_out)
    openai_summary = export_to_canonical(OPENAI_PARALLEL, openai_out)
    assert claude_summary.input_format == "claude-code-jsonl"
    assert openai_summary.input_format == "openai-agents"
    claude_events, _ = load_canonical(claude_out)
    openai_events, _ = load_canonical(openai_out)
    assert len(claude_events) == claude_summary.event_count
    assert len(openai_events) == openai_summary.event_count


def test_export_then_repair_accepts(tmp_path: Path) -> None:
    exported = tmp_path / "exported.jsonl"
    export_to_canonical(CLAUDE_BASIC, exported)
    plan, manifest = api.repair(exported, None, dry_run=True)
    assert manifest is None
    assert plan.fingerprint


def test_export_summary_content_free(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "secret.jsonl"
    summary = export_to_canonical(SECRET_SEED, out)
    rendered = json.dumps(summary.to_dict(), sort_keys=True)
    assert "CANARY-SESS-9F31" not in rendered
    assert "sk-test-FAILED-IF-VISIBLE-12345" not in rendered
    assert "AKIA-FAILED-IF-VISIBLE-EXAMPLE" not in rendered

    out2 = tmp_path / "secret2.jsonl"
    code = main(["export", str(SECRET_SEED), "--output", str(out2)])
    assert code == 0
    captured = capsys.readouterr()
    assert "CANARY-SESS-9F31" not in captured.out
    assert "sk-test-FAILED-IF-VISIBLE-12345" not in captured.out


def test_export_refuses_self_and_existing(tmp_path: Path) -> None:
    with pytest.raises(ExportRefused):
        export_to_canonical(CANONICAL_MINIMAL, CANONICAL_MINIMAL)
    out = tmp_path / "exists.jsonl"
    out.write_text("sentinel", encoding="utf-8")
    with pytest.raises(ExportRefused):
        export_to_canonical(CANONICAL_MINIMAL, out)
    assert out.read_text(encoding="utf-8") == "sentinel"


def test_export_cli_json_and_refusal(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "cli.jsonl"
    code = main(["export", str(CANONICAL_MINIMAL), "--output", str(out), "--json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["input_format"] == "canonical"
    assert payload["event_count"] > 0

    code = main(["export", str(CANONICAL_MINIMAL), "--output", str(out)])
    assert code == 1
    assert "refused" in capsys.readouterr().err.lower()


def test_export_refuses_malformed_syntax_errors(tmp_path: Path) -> None:
    malformed_fixture = FIXTURES / "hostile" / "malformed_nonterminal.jsonl"
    out = tmp_path / "malformed_out.jsonl"
    with pytest.raises(ExportRefused, match="fatal or error findings"):
        export_to_canonical(malformed_fixture, out)
    assert not out.exists()


def test_export_refuses_empty_session(tmp_path: Path) -> None:
    empty_fixture = FIXTURES / "hostile" / "empty.jsonl"
    out = tmp_path / "empty_out.jsonl"
    with pytest.raises(ExportRefused):
        export_to_canonical(empty_fixture, out, format="canonical")
    assert not out.exists()


def test_export_refuses_torn_final(tmp_path: Path) -> None:
    torn_fixture = FIXTURES / "hostile" / "torn_final.jsonl"
    out = tmp_path / "torn_out.jsonl"
    with pytest.raises(ExportRefused, match="fatal or error findings"):
        export_to_canonical(torn_fixture, out, format="canonical")
    assert not out.exists()


def test_export_cli_refuses_corrupted_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    malformed_fixture = FIXTURES / "hostile" / "malformed_nonterminal.jsonl"
    out = tmp_path / "cli_malformed_out.jsonl"
    code = main(["export", str(malformed_fixture), "--output", str(out)])
    assert code == 1
    captured = capsys.readouterr()
    assert "refused" in captured.err.lower()
    assert not out.exists()
