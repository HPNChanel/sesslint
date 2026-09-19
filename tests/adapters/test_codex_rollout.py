"""Unit, boundary, and hostile-input tests for the Codex rollout adapter (DW-T-12).

Validates:
- Envelope records ({type,timestamp,ordinal,payload}) canonicalize into
  sesslint.session/v1 events with preserved source coordinates.
- response_item payload types map to canonical kinds: message (role
  disambiguated), agent_message, reasoning (opaque), function_call /
  custom_tool_call (tool_call), function_call_output /
  custom_tool_call_output (tool_result).
- Non-conversational envelopes (session_meta, event_msg, turn_context,
  world_state, inter_agent_communication_metadata) map to system/opaque;
  compacted maps to compaction_boundary.
- call_id pairing preserved via correlation_id for SL101/SL102 detection.
- Linear parentage derived from envelope ordinal continuity; dropped records
  break the chain honestly (SL006/SL007).
- SL301 on explicit unsupported format-version markers; SL302 on unknown
  envelope types, unknown payload types, and unknown critical fields.
- SL001/SL002 terminal-torn distinction, strict JSON, NUL, UTF-8, limits.
- Synthetic IDs under sesslint:synthetic:codex_rollout namespace with
  collision guard.
- Determinism, source immutability, SQLite refusal, profile interplay.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from sesslint.adapters.codex_rollout import (
    SQLITE_MAGIC,
    SUPPORTED_CODEX_ROLLOUT_VERSIONS,
    detect_codex_rollout,
    load_codex_rollout,
    load_codex_rollout_session,
)
from sesslint.adapters.synthetic import is_synthetic_id
from sesslint.api import check_file
from sesslint.canonical import Session
from sesslint.codes import (
    SL001,
    SL002,
    SL006,
    SL007,
    SL101,
    SL102,
    SL107,
    SL301,
    SL302,
    Severity,
)
from sesslint.io import ReaderLimits

FIXTURES = Path(__file__).resolve().parent.parent.parent / "fixtures" / "adapters" / "codex"
CONF = Path(__file__).resolve().parent.parent.parent / "fixtures" / "conformance" / "codex_rollout"


def _env(ordinal: int, type_: str, payload: dict, ts: str | None = None) -> dict:
    return {
        "ordinal": ordinal,
        "payload": payload,
        "timestamp": ts or f"2026-09-17T10:{ordinal:02d}:00Z",
        "type": type_,
    }


def _item(ordinal: int, itype: str, iid: str | None, **kw: object) -> dict:
    p: dict[str, object] = {"type": itype}
    if iid is not None:
        p["id"] = iid
    p.update(kw)
    return _env(ordinal, "response_item", p)


def _jsonl(*records: dict) -> bytes:
    return ("\n".join(json.dumps(r, sort_keys=True) for r in records) + "\n").encode()


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


class TestDetection:
    def test_detect_rollout_envelope(self) -> None:
        data = _jsonl(
            _env(0, "session_meta", {"cli_version": "0.42.0"}),
            _item(1, "message", "m1", role="user"),
        )
        assert detect_codex_rollout(data, "rollout-2026-09-17T10-00-00-abc.jsonl") == 1.0

    def test_detect_without_rollout_filename(self) -> None:
        data = _jsonl(
            _env(0, "session_meta", {}),
            _item(1, "message", "m1", role="user"),
        )
        assert detect_codex_rollout(data, "session.jsonl") == 1.0

    def test_detect_rejects_non_jsonl_extension(self) -> None:
        data = _jsonl(_env(0, "session_meta", {}))
        assert detect_codex_rollout(data, "session.txt") == 0.0
        assert detect_codex_rollout(data, "rollout-abc.sqlite") == 0.0

    def test_detect_empty_and_sqlite(self) -> None:
        assert detect_codex_rollout(b"", "rollout-x.jsonl") == 0.0
        assert detect_codex_rollout(SQLITE_MAGIC + b"\x00" * 32, "rollout-x.jsonl") == 0.0

    def test_detect_weak_signal_partial(self) -> None:
        # Ordinal+payload but no envelope type vocabulary -> weak score.
        data = b'{"ordinal": 0, "payload": {"a": 1}}\n'
        score = detect_codex_rollout(data, "x.jsonl")
        assert 0.0 < score < 1.0


# ---------------------------------------------------------------------------
# Envelope -> canonical mapping
# ---------------------------------------------------------------------------


class TestEnvelopeMapping:
    def test_healthy_min_events(self) -> None:
        events, findings = load_codex_rollout(FIXTURES / "healthy_min.jsonl")
        assert len(findings) == 0
        assert len(events) == 3
        assert events[0].kind == "opaque" and events[0].actor == "system"
        assert events[1].kind == "message" and events[1].actor == "user"
        assert events[2].kind == "message" and events[2].actor == "assistant"

    def test_linear_parentage(self) -> None:
        events, _ = load_codex_rollout(FIXTURES / "healthy_min.jsonl")
        assert events[0].parent_id is None
        assert events[1].parent_id == events[0].id
        assert events[2].parent_id == events[1].id

    def test_source_coords_preserved(self) -> None:
        events, _ = load_codex_rollout(FIXTURES / "healthy_min.jsonl")
        for ev in events:
            assert ev.source_line is not None and ev.source_line >= 1
            assert ev.source_record_hash is not None
            assert ev.source_record_hash.startswith("sha256:")
            assert ev.source_adapter == "codex-rollout"

    def test_message_roles(self) -> None:
        events, _ = load_codex_rollout(
            _jsonl(
                _env(0, "session_meta", {}),
                _item(1, "message", "m1", role="user", content=[]),
                _item(2, "message", "m2", role="assistant", content=[]),
                _item(3, "message", "m3", role="developer", content=[]),
                _item(4, "agent_message", "am1", author="a", recipient="b", content="hi"),
            )
        )
        assert events[1].actor == "user"
        assert events[2].actor == "assistant"
        assert events[3].actor == "system"  # developer -> system
        assert events[4].actor == "assistant" and events[4].kind == "message"

    def test_reasoning_is_opaque(self) -> None:
        events, _ = load_codex_rollout(
            _jsonl(
                _env(0, "session_meta", {}),
                _item(1, "reasoning", "rs1", summary=[], encrypted_content="x"),
            )
        )
        assert events[1].kind == "opaque"
        assert events[1].actor == "assistant"
        # Encrypted reasoning content must not be projected into payload.
        assert "encrypted_content" not in events[1].payload

    def test_opaque_envelopes(self) -> None:
        events, _ = load_codex_rollout(
            _jsonl(
                _env(0, "session_meta", {"session_id": "s1"}),
                _env(1, "turn_context", {"turn_id": "t1", "model": "m"}),
                _env(2, "event_msg", {"type": "task_complete", "turn_id": "t1"}),
                _env(3, "world_state", {"state": {}}),
                _env(4, "inter_agent_communication_metadata", {"turn_id": "t1"}),
            )
        )
        assert [e.kind for e in events] == ["opaque"] * 5
        assert all(e.actor == "system" for e in events)
        # Identifiers kept, nothing else projected.
        assert events[0].payload.get("session_id") == "s1"
        assert events[1].payload.get("turn_id") == "t1"

    def test_compacted_maps_compaction_boundary(self) -> None:
        events, _ = load_codex_rollout(
            _jsonl(
                _env(0, "session_meta", {}),
                _env(
                    1,
                    "compacted",
                    {
                        "first_window_id": "w0",
                        "message": "window compacted",
                        "previous_window_id": None,
                        "replacement_history": [],
                        "window_id": "w0",
                        "window_number": 0,
                    },
                ),
            )
        )
        assert events[1].kind == "compaction_boundary"
        assert events[1].actor == "system"

    def test_session_meta_source_metadata(self) -> None:
        events, _ = load_codex_rollout(
            _jsonl(
                _env(
                    0,
                    "session_meta",
                    {
                        "cli_version": "0.42.0",
                        "cwd": "C:/should/not/leak",
                        "model_provider": "openai",
                        "originator": "codex_cli",
                        "session_id": "sess-x",
                    },
                ),
            )
        )
        meta = events.source.session_meta  # type: ignore[attr-defined]
        assert meta is not None
        assert meta.get("cli_version") == "0.42.0"
        assert meta.get("session_id") == "sess-x"
        # cwd / instructions are content-adjacent and must be minimized away.
        assert "cwd" not in meta

    def test_timestamp_normalization(self) -> None:
        events, _ = load_codex_rollout(
            _jsonl(
                _env(0, "session_meta", {}, ts="2026-09-17T10:00:00Z"),
                _item(1, "message", "m1", role="user"),
            )
        )
        assert events[0].ts == "2026-09-17T10:00:00Z"
        # Missing/garbage ts normalizes deterministically.
        rec = _env(1, "turn_context", {})
        del rec["timestamp"]
        events2, _ = load_codex_rollout(_jsonl(_env(0, "session_meta", {}), rec))
        assert events2[1].ts == "1970-01-01T00:00:00Z"


# ---------------------------------------------------------------------------
# Tool pairing
# ---------------------------------------------------------------------------


class TestToolPairing:
    def test_function_call_pairs_via_call_id(self) -> None:
        events, _ = load_codex_rollout(CONF / "parallel_tool.jsonl")
        calls = {e.correlation_id for e in events if e.kind == "tool_call"}
        results = {e.correlation_id for e in events if e.kind == "tool_result"}
        assert calls == results == {"call_syn_20", "call_syn_21"}
        for ev in events:
            if ev.kind == "tool_call":
                assert ev.actor == "assistant"
            if ev.kind == "tool_result":
                assert ev.actor == "tool"
                assert ev.execution_state == "success"
                assert ev.side_effects == "none"

    def test_custom_tool_call_pairs(self) -> None:
        events, _ = load_codex_rollout(CONF / "healthy.jsonl")
        call = next(e for e in events if e.id == "ctc_syn_01")
        result = next(e for e in events if e.id == "ctc_syn_02")
        assert call.kind == "tool_call" and call.correlation_id == "call_syn_02"
        assert result.kind == "tool_result" and result.correlation_id == "call_syn_02"

    def test_tool_call_arguments_parsed(self) -> None:
        events, _ = load_codex_rollout(CONF / "healthy.jsonl")
        fc = next(e for e in events if e.id == "fc_syn_01")
        assert fc.payload["input"] == {"command": "ls"}
        assert fc.payload["name"] == "exec"
        assert fc.payload["tool_use_id"] == "call_syn_01"

    def test_orphan_output_detected(self) -> None:
        report = check_file(FIXTURES / "orphan_output.jsonl", format="codex-rollout")
        assert any(f.code == SL101 for f in report.findings)

    def test_dangling_call_detected(self) -> None:
        report = check_file(FIXTURES / "dangling_call.jsonl", format="codex-rollout")
        assert any(f.code == SL102 for f in report.findings)

    def test_tail_loss_dangling_detected(self) -> None:
        """Unlinked-inode-shaped tail loss: stream ends after a pending call."""
        report = check_file(FIXTURES / "tail_loss.jsonl", format="codex-rollout")
        assert any(f.code == SL102 for f in report.findings)

    def test_duplicate_ordinal_breaks_chain(self) -> None:
        """Duplicate envelope ordinal breaks parentage honestly -> new root."""
        report = check_file(FIXTURES / "duplicate_ordinal.jsonl", format="codex-rollout")
        codes = {f.code for f in report.findings}
        assert SL006 in codes or SL007 in codes

    def test_async_pairing_profile_interplay(self) -> None:
        """openai-strict covers rollout semantics: async pairs flag SL107 at
        ERROR under strict, WARNING under neutral — designed strictness."""
        neutral = check_file(FIXTURES / "async_pairing.jsonl", format="codex-rollout")
        sl107 = [f for f in neutral.findings if f.code == SL107]
        assert sl107, "expected SL107 warning for non-adjacent async pair"
        assert all(f.severity == Severity.WARNING for f in sl107)

        strict = check_file(
            FIXTURES / "async_pairing.jsonl",
            format="codex-rollout",
            profile="openai-strict",
        )
        sl107_strict = [f for f in strict.findings if f.code == SL107]
        assert sl107_strict
        assert all(f.severity == Severity.ERROR for f in sl107_strict)


# ---------------------------------------------------------------------------
# Version negotiation + unknown records
# ---------------------------------------------------------------------------


class TestVersionAndUnknowns:
    def test_unknown_version_sl301(self) -> None:
        _, findings = load_codex_rollout(FIXTURES / "unknown_version.jsonl")
        sl301 = [f for f in findings if f.code == SL301]
        assert sl301
        assert sl301[0].evidence["version_raw"] == "99.0.0"
        assert set(sl301[0].evidence["supported_set"]) == set(SUPPORTED_CODEX_ROLLOUT_VERSIONS)

    def test_supported_version_marker_no_finding(self) -> None:
        events, findings = load_codex_rollout(
            _jsonl(
                _env(0, "session_meta", {"rollout_version": "1.0.0"}),
                _item(1, "message", "m1", role="user"),
            )
        )
        assert not any(f.code == SL301 for f in findings)

    def test_invalid_version_type_sl301(self) -> None:
        _, findings = load_codex_rollout(
            _jsonl(_env(0, "session_meta", {"rollout_version": {"bad": "type"}}))
        )
        assert any(f.code == SL301 for f in findings)

    def test_unknown_envelope_type_sl302(self) -> None:
        _, findings = load_codex_rollout(FIXTURES / "unknown_type.jsonl")
        sl302 = [f for f in findings if f.code == SL302]
        assert sl302
        assert sl302[0].evidence["field_path"] == "type"
        assert sl302[0].evidence["type_value"] == "mystery_envelope"

    def test_unknown_payload_type_sl302(self) -> None:
        _, findings = load_codex_rollout(FIXTURES / "unknown_payload_type.jsonl")
        sl302 = [f for f in findings if f.code == SL302]
        assert sl302
        assert sl302[0].evidence["type_value"] == "weird_item"

    def test_non_mapping_payload_sl302(self) -> None:
        _, findings = load_codex_rollout(
            _jsonl(_env(0, "response_item", "not-a-dict"))  # type: ignore[dict-item]
        )
        assert any(f.code == SL302 for f in findings)

    def test_unknown_critical_field_sl302(self) -> None:
        _, findings = load_codex_rollout(
            _jsonl(
                _env(0, "session_meta", {}),
                _item(1, "message", "m1", role="user", unknown_critical_field="x"),
            )
        )
        assert any(
            f.code == SL302 and f.evidence.get("field_path") == "unknown_critical_field"
            for f in findings
        )

    def test_cli_version_not_version_gated(self) -> None:
        """session_meta.cli_version is an app version, never SL301-gated."""
        _, findings = load_codex_rollout(
            _jsonl(_env(0, "session_meta", {"cli_version": "999.0.0-beta"}))
        )
        assert not any(f.code == SL301 for f in findings)


# ---------------------------------------------------------------------------
# Hostile input / corruption families
# ---------------------------------------------------------------------------


class TestHostileInput:
    def test_torn_tail_sl002(self) -> None:
        _, findings = load_codex_rollout(FIXTURES / "torn_tail.jsonl")
        assert any(f.code == SL002 for f in findings)
        assert not any(f.code == SL001 for f in findings)

    def test_malformed_escaped_mid_line_sl001(self) -> None:
        events, findings = load_codex_rollout(FIXTURES / "malformed_escaped.jsonl")
        sl001 = [f for f in findings if f.code == SL001]
        assert sl001
        assert sl001[0].source.line == 2
        # The record after the torn line is a new root (honest break).
        assert events[-1].parent_id is None

    def test_nul_byte_rejected(self) -> None:
        data = _jsonl(_env(0, "session_meta", {})) + b'{"ordinal":1,"payload":\x00}\n'
        _, findings = load_codex_rollout(data)
        assert any(f.code == SL002 and "NUL" in f.message for f in findings)

    def test_invalid_utf8(self) -> None:
        data = _jsonl(_env(0, "session_meta", {})) + b"\xff\xfe\n"
        _, findings = load_codex_rollout(data)
        assert any("UTF-8" in f.message for f in findings)

    def test_oversize_line(self) -> None:
        limits = ReaderLimits(max_line_bytes=256)
        big = _jsonl(_env(0, "session_meta", {"pad": "x" * 500}))
        _, findings = load_codex_rollout(big, limits=limits)
        assert any("line byte limit" in f.message for f in findings)

    def test_oversize_file(self) -> None:
        limits = ReaderLimits(max_file_bytes=64)
        big = _jsonl(_env(0, "session_meta", {"pad": "x" * 500}))
        _, findings = load_codex_rollout(big, limits=limits)
        assert any("File size exceeds" in f.message for f in findings)

    def test_max_records(self) -> None:
        limits = ReaderLimits(max_records=1)
        data = _jsonl(
            _env(0, "session_meta", {}),
            _item(1, "message", "m1", role="user"),
        )
        from sesslint.errors import MaxRecordsExceededError

        with pytest.raises(MaxRecordsExceededError):
            load_codex_rollout(data, limits=limits)

    def test_deep_nesting(self) -> None:
        deep = _env(0, "session_meta", {"state": {"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}}})
        _, findings = load_codex_rollout(_jsonl(deep), limits=ReaderLimits(max_depth=3))
        assert any("depth" in f.message for f in findings)

    def test_strict_json_constants_rejected(self) -> None:
        data = b'{"ordinal":0,"payload":{"x":NaN},"timestamp":"t","type":"session_meta"}\n'
        _, findings = load_codex_rollout(data)
        assert findings, "NaN must be rejected by strict decoder"

    def test_non_dict_record_malformed(self) -> None:
        _, findings = load_codex_rollout(b'["not","a","dict"]\n')
        assert any(f.code in (SL001, SL002) for f in findings)

    def test_sqlite_refusal(self) -> None:
        _, findings = load_codex_rollout(SQLITE_MAGIC + b"\x00" * 100)
        assert findings[0].code == SL001
        assert findings[0].severity == Severity.FATAL
        assert findings[0].evidence["reason"] == "refused_live_db"

    def test_empty_stream(self) -> None:
        events, findings = load_codex_rollout(b"")
        assert len(events) == 0
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Synthetic IDs, determinism, session wrap, immutability
# ---------------------------------------------------------------------------


class TestIdsDeterminismAndWrap:
    def test_synthetic_ids_for_missing_payload_id(self) -> None:
        events, _ = load_codex_rollout(CONF / "synthetic_ids.jsonl")
        assert len(events) == 3
        for ev in events:
            assert is_synthetic_id(ev.id)
            assert ev.id.startswith("sesslint:synthetic:codex_rollout:")
            assert ev.original_id is None

    def test_native_ids_preserved(self) -> None:
        events, _ = load_codex_rollout(CONF / "healthy.jsonl")
        assert events[1].id == "msg_syn_01"
        assert events[1].original_id == "msg_syn_01"

    def test_determinism(self) -> None:
        data = (CONF / "healthy.jsonl").read_bytes()
        e1, f1 = load_codex_rollout(data)
        e2, f2 = load_codex_rollout(data)
        assert [e.id for e in e1] == [e.id for e in e2]
        assert [e.content_hash for e in e1] == [e.content_hash for e in e2]
        assert [(f.code, f.message) for f in f1] == [(f.code, f.message) for f in f2]

    def test_session_wrap(self) -> None:
        session, findings = load_codex_rollout_session(CONF / "healthy.jsonl")
        assert isinstance(session, Session)
        assert session.header.schema_version == "sesslint.session/v1"
        assert session.header.session_id == "sess-syn-001"
        assert len(session.events) == 11
        assert len(findings) == 0

    def test_source_immutability(self, tmp_path: Path) -> None:
        src = CONF / "healthy.jsonl"
        target = tmp_path / "rollout-test.jsonl"
        data = src.read_bytes()
        target.write_bytes(data)
        load_codex_rollout(target)
        check_file(target)
        assert target.read_bytes() == data

    def test_stream_input(self) -> None:
        data = (CONF / "healthy.jsonl").read_bytes()
        events, findings = load_codex_rollout(io.BytesIO(data))
        assert len(events) == 11
        assert len(findings) == 0

    def test_no_content_in_findings(self) -> None:
        """Finding evidence must never carry message/tool content (FR-081)."""
        _, findings = load_codex_rollout(FIXTURES / "unknown_payload_type.jsonl")
        blob = json.dumps([f.evidence for f in findings], sort_keys=True)
        assert "weird_item" in blob  # discriminator is allowlisted evidence
        for f in findings:
            assert "content" not in json.dumps(f.evidence)
            assert "arguments" not in json.dumps(f.evidence)


class TestRepairEmit:
    """Codex input repairs write back vendor bytes under 'auto'; an explicit
    canonical emit produces a canonical session stream."""

    def test_repair_auto_emits_vendor_writeback(self, tmp_path: Path) -> None:
        from sesslint import api

        out = tmp_path / "repaired.jsonl"
        plan, manifest = api.repair(FIXTURES / "torn_tail.jsonl", out)
        assert manifest is not None
        assert manifest.adapter_id == "codex-rollout"
        # Output is a codex rollout stream, not a canonical session stream
        first = json.loads(out.read_text(encoding="utf-8").splitlines()[0])
        assert first.get("type") == "session_meta"
        assert [s.recipe for s in plan.steps] == ["torn-terminal-record-discard"]

    def test_repair_vendor_emit_accepted(self, tmp_path: Path) -> None:
        from sesslint import api

        out = tmp_path / "v.jsonl"
        _, manifest = api.repair(FIXTURES / "torn_tail.jsonl", out, emit="vendor")
        assert manifest is not None
        assert manifest.adapter_id == "codex-rollout"
        assert out.exists()

    def test_repair_canonical_emit(self, tmp_path: Path) -> None:
        from sesslint import api

        out = tmp_path / "c.jsonl"
        _, manifest = api.repair(FIXTURES / "torn_tail.jsonl", out, emit="canonical")
        assert manifest is not None
        assert manifest.adapter_id == "canonical"
        first = json.loads(out.read_text(encoding="utf-8").splitlines()[0])
        assert first["schema_version"] == "sesslint.session/v1"

    def test_repair_dry_run_no_writes(self, tmp_path: Path) -> None:
        from sesslint import api

        plan, manifest = api.repair(FIXTURES / "torn_tail.jsonl", None, dry_run=True)
        assert manifest is None
        assert len(plan.steps) == 1
        assert list(tmp_path.iterdir()) == []
