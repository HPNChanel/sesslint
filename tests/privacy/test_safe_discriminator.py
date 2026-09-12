"""Tests for bounded SL302 discriminator echo and privacy hardening (DEV-008, FR-081, FR-082).

Verifies:
1. Allowlist boundaries for safe_discriminator (length 64 vs 65, charset, symbols, non-strings).
2. Hostile 5KB prose and secret-seeded types are absent verbatim from default reports.
3. Shape descriptor and type_truncated=True are emitted for hostile types.
4. Benign unknown types continue to echo verbatim without type_truncated marker.
5. Zero regressions across Claude Code, OpenAI Agents, and Canonical adapters.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sesslint.adapters.canonical import load_canonical
from sesslint.adapters.claude_code import load_claude_code
from sesslint.adapters.openai_agents import load_openai_agents
from sesslint.adapters.safe_value import safe_discriminator, safe_type_value
from sesslint.api import check_file
from sesslint.cli import main
from sesslint.codes import SL302
from sesslint.finding import CANONICAL_EVIDENCE_KEYS, SourceRef, compute_finding_fingerprint

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"


# ---------------------------------------------------------------------------
# Unit tests: safe_type_value and safe_discriminator
# ---------------------------------------------------------------------------


class TestSafeDiscriminatorUnit:
    """Unit tests for safe_discriminator allowlist and safe_type_value fallback."""

    def test_safe_type_value_shapes(self) -> None:
        """safe_type_value returns type and size descriptors for sized types, else type."""
        assert safe_type_value("hello") == "<str:len=5>"
        assert safe_type_value(b"bytes") == "<bytes:len=5>"
        assert safe_type_value([1, 2, 3]) == "<list:len=3>"
        assert safe_type_value({"a": 1}) == "<dict:len=1>"
        assert safe_type_value({1, 2}) == "<set:len=2>"
        assert safe_type_value((1,)) == "<tuple:len=1>"
        assert safe_type_value(None) == "<NoneType>"
        assert safe_type_value(42) == "<int>"
        assert safe_type_value(3.14) == "<float>"
        assert safe_type_value(True) == "<bool>"

    def test_allowlist_exact_boundaries(self) -> None:
        """Allowlist accepts lengths 1 through 64 and rejects 0 or 65+."""
        # 1 character
        val_1 = "a"
        res, truncated = safe_discriminator(val_1)
        assert res == "a"
        assert truncated is False

        # 64 characters (maximum allowed)
        val_64 = "a" * 64
        res, truncated = safe_discriminator(val_64)
        assert res == val_64
        assert truncated is False

        # 65 characters (one over limit -> truncated)
        val_65 = "a" * 65
        res, truncated = safe_discriminator(val_65)
        assert res == "<str:len=65>"
        assert truncated is True

        # Empty string (0 characters -> truncated)
        res, truncated = safe_discriminator("")
        assert res == "<str:len=0>"
        assert truncated is True

    def test_allowlist_allowed_characters(self) -> None:
        """Allowlist accepts alphanumeric, dot, hyphen, underscore."""
        valid_samples = [
            "message",
            "futureWidget",
            "custom_type",
            "event-v2",
            "dotted.name",
            "mixed.type_name-123",
            "UPPER_LOWER-123.test",
        ]
        for s in valid_samples:
            res, truncated = safe_discriminator(s)
            assert res == s
            assert truncated is False

    @pytest.mark.parametrize(
        "invalid_sample",
        [
            "type with spaces",
            "type:with:colons",
            "type/with/slashes",
            "type\\with\\backslashes",
            "custom<xml>tag",
            "custom;sql-inject",
            "type@domain.com",
            "type#anchor",
            "type$var",
            "type%percent",
            "type!exclamation",
            "type=assignment",
            "type\nnewline",
            "type\ttab",
        ],
    )
    def test_allowlist_rejects_symbols_and_control_chars(self, invalid_sample: str) -> None:
        """Symbols, whitespaces, and punctuation not in allowlist fallback to shape."""
        res, truncated = safe_discriminator(invalid_sample)
        assert res == f"<str:len={len(invalid_sample)}>"
        assert truncated is True

    @pytest.mark.parametrize(
        "non_string_val,expected_shape",
        [
            (None, "<NoneType>"),
            (12345, "<int>"),
            (99.9, "<float>"),
            (True, "<bool>"),
            ([1, 2], "<list:len=2>"),
            ({"key": "val"}, "<dict:len=1>"),
            (b"data", "<bytes:len=4>"),
        ],
    )
    def test_non_string_discriminators_fallback_to_shape(
        self, non_string_val: Any, expected_shape: str
    ) -> None:
        """Non-string inputs are converted to shape descriptors with truncated=True."""
        res, truncated = safe_discriminator(non_string_val)
        assert res == expected_shape
        assert truncated is True

    @pytest.mark.parametrize(
        "secret_sample",
        [
            "sk-proj-testkey12345678901234567890",
            "sk_live_12345678901234567890",
            "rk_live_12345678901234567890",
            "ghp_1234567890abcdefghijklmnopqrstuvwx",
            "gho_abcdefghijklmnopqrstuvwxyz123456",
            "ghu_1234567890abcdefghijklmnopqrstuvwx",
            "ghs_1234567890abcdefghijklmnopqrstuvwx",
            "ghr_1234567890abcdefghijklmnopqrstuvwx",
            "glpat-12345678901234567890",
            "AKIAIOSFODNN7EXAMPLE",
            "ASIAIOSFODNN7EXAMPLE",
            "prefix-AKIAIOSFODNN7EXAMPLE",
            "AIzaSyDummySecretKey123456789012345",
            "xoxb-1234567890-1234567890-abcdef",
            "slack_token_1234567890abcdef",
            "bearer-token-12345",
            "bearer_token_12345",
        ],
    )
    def test_secret_patterns_fallback_to_shape(self, secret_sample: str) -> None:
        """Credential patterns are rejected from verbatim echo even if under 64 chars."""
        res, truncated = safe_discriminator(secret_sample)
        assert res == f"<str:len={len(secret_sample)}>"
        assert truncated is True


# ---------------------------------------------------------------------------
# Static fixture tests: fixtures/privacy/hostile_type_value.jsonl
# ---------------------------------------------------------------------------


class TestHostileFixtureStatic:
    """Verify loading and scanning of static hostile fixture."""

    def test_hostile_static_fixture_loaded_via_claude_adapter(self) -> None:
        """Verify loading of static hostile fixture and bounding of hostile types."""
        fixture_path = FIXTURES_DIR / "privacy" / "hostile_type_value.jsonl"
        assert fixture_path.is_file(), f"Missing fixture: {fixture_path}"

        events, findings = load_claude_code(fixture_path)
        assert len(events) >= 1

        sl302_findings = [f for f in findings if f.code == SL302]
        assert len(sl302_findings) >= 3

        for f in sl302_findings:
            assert f.evidence is not None
            assert "type_value" in f.evidence
            tv = f.evidence["type_value"]
            # All hostile types must be bounded shapes
            assert tv.startswith("<str:len=") and tv.endswith(">")
            # Truncated marker must be set
            assert f.evidence.get("type_truncated") is True
            # Verbatim hostile text must not appear in type_value
            assert "HostileInternalProse" not in tv
            assert "<custom>" not in tv
            assert "AAAA" not in tv

        # CLI execution on static fixture
        exit_code = main(["check", str(fixture_path), "--format", "claude-code-jsonl", "--json"])
        assert exit_code == 1

        # API check_file execution on static fixture
        report = check_file(fixture_path)
        report_json = json.dumps(report.to_dict())
        assert "HostileInternalProse" not in report_json
        assert "<custom>" not in report_json
        assert "AAAAAAAAAAAAAAAA" not in report_json
        assert len([f for f in report.findings if f.code == "SL302"]) >= 3


# ---------------------------------------------------------------------------
# Privacy regression tests: Claude Code adapter
# ---------------------------------------------------------------------------


class TestClaudeCodePrivacyHardening:
    """Verify Claude Code adapter never leaks hostile or secret discriminators."""

    def test_secret_seeded_type_not_echoed_verbatim(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Secret token in type discriminator is bounded to shape; zero leak in JSON report."""
        secret_token = "sk-ant-api03-SECRET-CANARY-TOKEN-XYZ123"
        fpath = tmp_path / "claude_secret_type.jsonl"
        records = [
            {"id": "msg_01", "type": "user_message", "message": "hello"},
            {"id": "msg_02", "parentId": "msg_01", "type": secret_token},
        ]
        fpath.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")

        events, findings = load_claude_code(fpath)
        sl302 = [f for f in findings if f.code == SL302]
        assert len(sl302) == 1
        ev = sl302[0].evidence or {}
        assert ev.get("type_value") == f"<str:len={len(secret_token)}>"
        assert ev.get("type_truncated") is True
        assert secret_token not in ev.get("type_value", "")

        # CLI check --json execution
        exit_code = main(["check", str(fpath), "--format", "claude-code-jsonl", "--json"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert secret_token not in captured.out
        assert secret_token not in captured.err

        data = json.loads(captured.out)
        f_list = [f for f in data.get("findings", []) if f.get("code") == "SL302"]
        assert len(f_list) == 1
        evidence = f_list[0].get("evidence", {})
        assert evidence.get("type_value") == f"<str:len={len(secret_token)}>"
        assert evidence.get("type_truncated") is True

        # API check_file execution (DEV-008 parity)
        report = check_file(fpath, format="claude-code-jsonl")
        report_json = json.dumps(report.to_dict())
        assert secret_token not in report_json
        sl302_api = [f for f in report.findings if f.code == "SL302"]
        assert len(sl302_api) == 1
        assert sl302_api[0].evidence.get("type_value") == f"<str:len={len(secret_token)}>"
        assert sl302_api[0].evidence.get("type_truncated") is True

    def test_5kb_prose_type_bounded_to_shape(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """5KB prose type discriminator is bounded to shape descriptor in report."""
        prose_payload = (
            "Proprietary confidential diagnostic conversation history that contains "
            "private system instructions and trade secrets. "
        ) * 50
        assert len(prose_payload) > 5000

        fpath = tmp_path / "claude_5kb_prose.jsonl"
        records = [
            {"id": "msg_01", "type": "user_message", "message": "hello"},
            {"id": "msg_02", "parentId": "msg_01", "type": prose_payload},
        ]
        fpath.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")

        events, findings = load_claude_code(fpath)
        sl302 = [f for f in findings if f.code == SL302]
        assert len(sl302) == 1
        ev = sl302[0].evidence or {}
        assert ev.get("type_value") == f"<str:len={len(prose_payload)}>"
        assert ev.get("type_truncated") is True

        # CLI check --json
        exit_code = main(["check", str(fpath), "--format", "claude-code-jsonl", "--json"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert prose_payload not in captured.out
        assert prose_payload not in captured.err

        data = json.loads(captured.out)
        f_list = [f for f in data.get("findings", []) if f.get("code") == "SL302"]
        assert len(f_list) == 1
        evidence = f_list[0].get("evidence", {})
        assert evidence.get("type_value") == f"<str:len={len(prose_payload)}>"
        assert evidence.get("type_truncated") is True

        # API check_file execution (DEV-008 parity)
        report = check_file(fpath, format="claude-code-jsonl")
        report_json = json.dumps(report.to_dict())
        assert prose_payload not in report_json
        sl302_api = [f for f in report.findings if f.code == "SL302"]
        assert len(sl302_api) == 1
        assert sl302_api[0].evidence.get("type_value") == f"<str:len={len(prose_payload)}>"
        assert sl302_api[0].evidence.get("type_truncated") is True


# ---------------------------------------------------------------------------
# Privacy regression tests: OpenAI Agents adapter
# ---------------------------------------------------------------------------


class TestOpenAIAgentsPrivacyHardening:
    """Verify OpenAI Agents adapter never leaks hostile or secret discriminators."""

    def test_secret_seeded_type_not_echoed_verbatim(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Secret token in OpenAI item type is bounded to shape; zero leak in JSON report."""
        secret_token = "ghp_1234567890abcdefghijklmnopqrstuvwx"
        fpath = tmp_path / "openai_secret_type.json"
        doc = {
            "export_version": "1.0.0",
            "items": [
                {"id": "item_01", "type": "message", "role": "user", "content": "hi"},
                {"id": "item_02", "type": secret_token},
            ],
        }
        fpath.write_text(json.dumps(doc), encoding="utf-8")

        events, findings = load_openai_agents(fpath)
        sl302 = [f for f in findings if f.code == SL302]
        assert len(sl302) == 1
        ev = sl302[0].evidence or {}
        assert ev.get("type_value") == f"<str:len={len(secret_token)}>"
        assert ev.get("type_truncated") is True
        assert secret_token not in ev.get("type_value", "")

        # CLI check --json
        exit_code = main(["check", str(fpath), "--format", "openai-agents", "--json"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert secret_token not in captured.out
        assert secret_token not in captured.err

        # API check_file execution (DEV-008 parity)
        report = check_file(fpath, format="openai-agents")
        report_json = json.dumps(report.to_dict())
        assert secret_token not in report_json
        sl302_api = [f for f in report.findings if f.code == "SL302"]
        assert len(sl302_api) == 1
        assert sl302_api[0].evidence.get("type_value") == f"<str:len={len(secret_token)}>"
        assert sl302_api[0].evidence.get("type_truncated") is True

    def test_5kb_prose_type_bounded_to_shape(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """5KB prose type discriminator in OpenAI item is bounded to shape."""
        prose = "ConfidentialAgentExportPayloadProseThatMustNeverBeEchoedRawIntoEvidence " * 75
        assert len(prose) > 5000

        fpath = tmp_path / "openai_5kb_prose.json"
        doc = {
            "export_version": "1.0.0",
            "items": [
                {"id": "item_01", "type": "message", "role": "user", "content": "hi"},
                {"id": "item_02", "type": prose},
            ],
        }
        fpath.write_text(json.dumps(doc), encoding="utf-8")

        events, findings = load_openai_agents(fpath)
        sl302 = [f for f in findings if f.code == SL302]
        assert len(sl302) == 1
        ev = sl302[0].evidence or {}
        assert ev.get("type_value") == f"<str:len={len(prose)}>"
        assert ev.get("type_truncated") is True

        exit_code = main(["check", str(fpath), "--format", "openai-agents", "--json"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert prose not in captured.out

        # API check_file execution (DEV-008 parity)
        report = check_file(fpath, format="openai-agents")
        report_json = json.dumps(report.to_dict())
        assert prose not in report_json
        sl302_api = [f for f in report.findings if f.code == "SL302"]
        assert len(sl302_api) == 1
        assert sl302_api[0].evidence.get("type_value") == f"<str:len={len(prose)}>"
        assert sl302_api[0].evidence.get("type_truncated") is True


# ---------------------------------------------------------------------------
# Privacy regression tests: Canonical adapter
# ---------------------------------------------------------------------------


class TestCanonicalPrivacyHardening:
    """Verify Canonical adapter bounds unknown critical type discriminator."""

    def test_canonical_event_with_hostile_type_discriminator(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Canonical event with unknown critical 'type' field containing secret is bounded."""
        secret_token = "sk-ant-api03-SECRET-CANARY-TOKEN-XYZ123"
        fpath = tmp_path / "canonical_secret_type.jsonl"
        lines = [
            json.dumps({"schema_version": "sesslint.session/v1", "session_id": "sess_01"}),
            json.dumps(
                {
                    "id": "evt_01",
                    "actor": "user",
                    "kind": "message",
                    "payload": {"role": "user", "content": "hello"},
                    "ts": "2026-09-12T12:00:00Z",
                    "type": secret_token,
                }
            ),
        ]
        fpath.write_text("\n".join(lines) + "\n", encoding="utf-8")

        events, findings = load_canonical(fpath)
        sl302 = [f for f in findings if f.code == SL302]
        assert len(sl302) == 1
        ev = sl302[0].evidence or {}
        assert ev.get("field_path") == "type"
        assert ev.get("type_value") == f"<str:len={len(secret_token)}>"
        assert ev.get("type_truncated") is True
        assert secret_token not in ev.get("type_value", "")

        exit_code = main(["check", str(fpath), "--format", "canonical", "--json"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert secret_token not in captured.out

        # API check_file execution (DEV-008 parity)
        report = check_file(fpath, format="canonical")
        report_json = json.dumps(report.to_dict())
        assert secret_token not in report_json
        sl302_api = [f for f in report.findings if f.code == "SL302"]
        assert len(sl302_api) == 1
        assert sl302_api[0].evidence.get("type_value") == f"<str:len={len(secret_token)}>"
        assert sl302_api[0].evidence.get("type_truncated") is True


# ---------------------------------------------------------------------------
# No-regression on benign unknown types
# ---------------------------------------------------------------------------


class TestBenignDiscriminatorNoRegression:
    """Verify benign unknown types continue to echo verbatim without truncation."""

    def test_claude_unknown_type_fixture_echoes_verbatim(self) -> None:
        """fixtures/claude_code/unknown_type.jsonl echoes 'futureWidget' verbatim."""
        fixture_path = FIXTURES_DIR / "claude_code" / "unknown_type.jsonl"
        events, findings = load_claude_code(fixture_path)
        sl302 = [f for f in findings if f.code == SL302]
        assert len(sl302) >= 1
        f = sl302[0]
        assert f.evidence is not None
        assert f.evidence["field_path"] == "type"
        assert f.evidence["type_value"] == "futureWidget"
        assert "type_truncated" not in f.evidence

    def test_openai_unknown_type_echoes_verbatim(self, tmp_path: Path) -> None:
        """OpenAI unknown type 'futureTool' echoes verbatim."""
        fpath = tmp_path / "openai_benign_unknown.json"
        doc = {
            "export_version": "1.0.0",
            "items": [
                {"id": "item_01", "type": "message", "role": "user", "content": "hello"},
                {"id": "item_02", "type": "futureTool"},
            ],
        }
        fpath.write_text(json.dumps(doc), encoding="utf-8")

        events, findings = load_openai_agents(fpath)
        sl302 = [f for f in findings if f.code == SL302]
        assert len(sl302) == 1
        f = sl302[0]
        assert f.evidence is not None
        assert f.evidence["field_path"] == "type"
        assert f.evidence["type_value"] == "futureTool"
        assert "type_truncated" not in f.evidence

    def test_canonical_unknown_type_echoes_verbatim(self, tmp_path: Path) -> None:
        """Canonical unknown critical 'type' field echoes benign identifier verbatim."""
        fpath = tmp_path / "canonical_benign_unknown.jsonl"
        lines = [
            json.dumps({"schema_version": "sesslint.session/v1", "session_id": "sess_01"}),
            json.dumps(
                {
                    "id": "evt_01",
                    "actor": "user",
                    "kind": "message",
                    "payload": {"role": "user", "content": "hello"},
                    "ts": "2026-09-12T12:00:00Z",
                    "type": "futureCanonicalRecord",
                }
            ),
        ]
        fpath.write_text("\n".join(lines) + "\n", encoding="utf-8")

        events, findings = load_canonical(fpath)
        sl302 = [f for f in findings if f.code == SL302]
        assert len(sl302) == 1
        f = sl302[0]
        assert f.evidence is not None
        assert f.evidence["field_path"] == "type"
        assert f.evidence["type_value"] == "futureCanonicalRecord"
        assert "type_truncated" not in f.evidence

    def test_canonical_evidence_keys_includes_type_truncated(self) -> None:
        """CANONICAL_EVIDENCE_KEYS contains type_truncated for fingerprint inclusion."""
        assert "type_truncated" in CANONICAL_EVIDENCE_KEYS

        # Fingerprint computation incorporates type_truncated
        src = SourceRef(path="test.json", line=1, record_id="r1")
        fp_truncated = compute_finding_fingerprint(
            code="SL302",
            source=src,
            evidence={"type_truncated": True},
        )
        fp_non_truncated = compute_finding_fingerprint(
            code="SL302",
            source=src,
            evidence={},
        )
        assert fp_truncated != fp_non_truncated
