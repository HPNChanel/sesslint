"""W1-1/W1-2: bookkeeping stays outside pairing; unknown linkage fails closed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint import api
from sesslint.adapters.claude_code import SESSION_METADATA_TYPES, load_claude_code
from sesslint.adapters.codex_rollout import load_codex_rollout
from sesslint.adapters.detect import detect_format
from sesslint.adapters.metadata import UnknownMetadataTracker

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures/adapters/metadata"


@pytest.mark.parametrize("key", ["sessionId", "session_id"])
def test_session_identifier_alone_cannot_select_a_vendor(tmp_path: Path, key: str) -> None:
    source = tmp_path / "foreign.jsonl"
    source.write_bytes(json.dumps({key: "synthetic", "type": "foreign_session"}).encode() + b"\n")
    assert detect_format(source).format is None
    report = api.check_file(source)
    assert report.limitation.startswith("Unsupported:")
    assert report.findings == ()


def test_known_claude_metadata_can_identify_a_session(tmp_path: Path) -> None:
    source = tmp_path / "session.jsonl"
    source.write_bytes(b'{"type":"custom-title","sessionId":"synthetic"}\n')
    assert detect_format(source).format == "claude-code-jsonl"


@pytest.mark.parametrize("record_type", sorted(SESSION_METADATA_TYPES))
def test_known_claude_metadata_is_not_a_graph_node(tmp_path: Path, record_type: str) -> None:
    src = tmp_path / "session.jsonl"
    src.write_bytes(
        b'{"type":"user","uuid":"u1","message":{"role":"user","content":"synthetic"}}\n'
        + (
            json.dumps({"type": record_type, "id": "decorative-id", "sessionId": "s"}) + "\n"
        ).encode()
    )
    events, findings = load_claude_code(src)
    assert [e.id for e in events] == ["u1"]
    assert not findings


def test_known_metadata_with_uuid_preserves_chain_node(tmp_path: Path) -> None:
    src = tmp_path / "session.jsonl"
    src.write_bytes(b'{"type":"queue-operation","uuid":"linked-metadata"}\n')
    events, findings = load_claude_code(src)
    assert [(e.id, e.kind) for e in events] == [("linked-metadata", "opaque")]
    assert not findings


def test_claude_compaction_uses_logical_parent_and_opaque_attachment() -> None:
    events, findings = load_claude_code(FIXTURES / "claude_modern.jsonl")
    assert not any(f.code == "SL302" for f in findings)
    assert [(e.kind, e.parent_id) for e in events[-2:]] == [
        ("compaction_boundary", "synthetic-a1"),
        ("opaque", "synthetic-c1"),
    ]
    report = api.check_file(FIXTURES / "claude_modern.jsonl", format="claude-code-jsonl")
    assert not any(f.code in {"SL004", "SL006", "SL007", "SL302"} for f in report.findings)


def test_claude_native_compaction_allows_fully_paired_continuation(tmp_path: Path) -> None:
    source = tmp_path / "synthetic.jsonl"
    rows = [
        {"type": "user", "uuid": "u1", "parentUuid": None},
        {"type": "system", "subtype": "compact_boundary", "uuid": "b1", "logicalParentUuid": "u1"},
        {
            "type": "tool_use",
            "id": "call",
            "parentUuid": "b1",
            "toolUseId": "c1",
            "name": "Read",
            "input": {},
        },
        {
            "type": "tool_result",
            "id": "result",
            "parentUuid": "call",
            "toolUseId": "c1",
            "output": "synthetic",
        },
    ]
    source.write_bytes(b"".join(json.dumps(row).encode() + b"\n" for row in rows))
    report = api.check_file(source, format="claude-code-jsonl")
    assert not any(f.code in {"SL102", "SL203"} for f in report.findings)
    assert any(
        s.check == "SL203" and s.reason == "adapter-not-applicable" for s in report.coverage.skipped
    )
    complete = source.read_bytes()
    source.write_bytes(complete + b'{"uuid":"torn"')
    repaired = tmp_path / "repaired.jsonl"
    _, manifest = api.repair(source, output_path=repaired, format="claude-code-jsonl")
    assert manifest is not None
    assert repaired.read_bytes() == complete
    source.write_bytes(b"".join(json.dumps(row).encode() + b"\n" for row in rows[:-1]))
    assert any(
        f.code == "SL102" for f in api.check_file(source, format="claude-code-jsonl").findings
    )


@pytest.mark.parametrize("subtype", ["stop_hook_summary", "local_command"])
def test_system_metadata_is_transparent_to_tool_pairing(tmp_path: Path, subtype: str) -> None:
    src = tmp_path / "session.jsonl"
    records = [
        {"type": "tool_use", "id": "call", "name": "Read", "input": {}, "toolUseId": "c1"},
        {"type": "system", "subtype": subtype, "uuid": "sys", "parentUuid": "call"},
        {
            "type": "tool_result",
            "id": "result",
            "parentUuid": "sys",
            "toolUseId": "c1",
            "output": "synthetic",
        },
    ]
    src.write_bytes("".join(json.dumps(r) + "\n" for r in records).encode())
    findings = api.check_file(src, format="claude-code-jsonl", profile="claude-strict").findings
    assert not any(f.code in {"SL107", "SL302"} for f in findings)


@pytest.mark.parametrize("vendor", ["claude", "codex"])
def test_unknown_metadata_is_bounded_info(vendor: str) -> None:
    fmt = "claude-code-jsonl" if vendor == "claude" else "codex-rollout"
    report = api.check_file(FIXTURES / f"{vendor}_unknown.jsonl", format=fmt)
    advisory = [f for f in report.findings if f.code == "SL306"]
    assert len(advisory) == 1
    assert advisory[0].severity == "info"
    assert advisory[0].evidence["count"] == (2 if vendor == "claude" else 1)
    assert not any(f.code == "SL302" for f in report.findings)
    assert "synthetic" not in json.dumps(advisory[0].evidence)


@pytest.mark.parametrize("vendor", ["claude", "codex"])
@pytest.mark.parametrize("field", ["id", "parentUuid", "call_id", "content", "critical_state"])
def test_unknown_record_with_nested_semantics_stays_critical(
    tmp_path: Path, vendor: str, field: str
) -> None:
    src = tmp_path / "session.jsonl"
    record = {"type": "future_type", "payload": {"nested": {field: "synthetic"}}}
    src.write_bytes((json.dumps(record) + "\n").encode())
    loader = load_claude_code if vendor == "claude" else load_codex_rollout
    _events, findings = loader(src)
    assert any(f.code == "SL302" for f in findings)
    assert not any(f.code == "SL306" for f in findings)


def test_retained_context_is_opaque_non_durable_and_does_not_pair() -> None:
    events, findings = load_codex_rollout(FIXTURES / "codex_retained.jsonl")
    retained = events[2]
    assert retained.kind == "opaque"
    assert retained.actor == "system"
    assert retained.correlation_id is None
    assert retained.extra_fields["codex"]["durable"] is False
    assert "questions" not in retained.payload
    assert not any(f.code == "SL302" for f in findings)
    report = api.check_file(
        FIXTURES / "codex_retained.jsonl", format="codex-rollout", profile="openai-strict"
    )
    assert not any(f.code in {"SL101", "SL102", "SL107", "SL302"} for f in report.findings)


def test_unknown_type_groups_have_a_fixed_memory_bound() -> None:
    tracker = UnknownMetadataTracker()
    for i in range(200):
        tracker.note(f"future_{i}", line=i + 1)
    findings = tracker.findings("synthetic.jsonl")
    assert len(findings) == 33
    assert sum(int(f.evidence["count"]) for f in findings) == 200
