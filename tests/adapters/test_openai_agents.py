"""Unit, conformance, and golden snapshot tests for OpenAI Agents SDK adapter (TASK-009).

Validates canonicalization, call_id correlation, checkpoint preservation,
version evidence extraction (SL301), unknown critical item handling (SL302),
live SQLite refusal safety gate (no mutation, zero sqlite3 imports),
format-parity between JSON and JSONL, and DoS-resistant limit enforcement.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from sesslint.adapters.openai_agents import (
    MAX_PROJECTED_CHECKPOINTS,
    MAX_PROJECTED_RUN_STATE_KEYS,
    SQLITE_MAGIC,
    SUPPORTED_OPENAI_AGENTS_VERSIONS,
    detect_openai_agents,
    load_openai_agents,
    load_openai_agents_session,
    normalize_version,
    project_run_state,
)
from sesslint.canonical import canonical_bytes, to_canonical_json
from sesslint.codes import SL001, SL002, SL301, SL302, Repairability, Severity
from sesslint.errors import MaxRecordsExceededError
from sesslint.io import ReaderLimits

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "openai_agents"
SNAPSHOTS_DIR = Path(__file__).resolve().parent / "snapshots"


def test_items_basic() -> None:
    """Verify 5 items produce canonical chain, tool_call<->tool_result share correlation_id,

    0 findings, and match golden snapshot byte-for-byte.
    """
    fixture_path = FIXTURES_DIR / "items_basic.json"
    events, findings = load_openai_agents(fixture_path)

    # Invariants: 5 events, 0 findings
    assert len(findings) == 0
    assert len(events) == 5

    # Verify event 0: user message
    assert events[0].id == "msg_01"
    assert events[0].actor == "user"
    assert events[0].kind == "message"
    assert events[0].parent_id is None
    assert events[0].seq == 0
    assert events[0].payload.get("role") == "user"

    # Verify event 1: assistant message
    assert events[1].id == "msg_02"
    assert events[1].actor == "assistant"
    assert events[1].kind == "message"
    assert events[1].parent_id == "msg_01"
    assert events[1].seq == 1
    assert events[1].payload.get("role") == "assistant"

    # Verify event 2: tool_call
    assert events[2].id == "msg_03"
    assert events[2].actor == "assistant"
    assert events[2].kind == "tool_call"
    assert events[2].parent_id == "msg_02"
    assert events[2].seq == 2
    assert events[2].correlation_id == "call_01"
    assert events[2].payload.get("tool_name") == "read_file"
    assert events[2].payload.get("call_id") == "call_01"

    # Verify event 3: tool_result
    assert events[3].id == "msg_04"
    assert events[3].actor == "tool"
    assert events[3].kind == "tool_result"
    assert events[3].parent_id == "msg_03"
    assert events[3].seq == 3
    assert events[3].correlation_id == "call_01"
    assert events[3].execution_state == "success"
    assert events[3].payload.get("call_id") == "call_01"

    # Verify correlation_id linkage between call and result
    assert events[2].correlation_id == events[3].correlation_id == "call_01"

    # Verify event 4: assistant message
    assert events[4].id == "msg_05"
    assert events[4].actor == "assistant"
    assert events[4].kind == "message"
    assert events[4].parent_id == "msg_04"
    assert events[4].seq == 4

    # Golden snapshot byte-equality comparison
    golden_path = SNAPSHOTS_DIR / "openai_basic.canonical.json"
    assert golden_path.is_file(), f"Golden snapshot missing at {golden_path}"
    golden_bytes = golden_path.read_bytes()
    actual_bytes = to_canonical_json(events).encode("utf-8")
    assert actual_bytes == golden_bytes


def test_run_state_checkpoints_preserved() -> None:
    """Verify run-state and checkpoints wrapper preserves checkpoint metadata verbatim-hash."""
    fixture_path = FIXTURES_DIR / "run_state_checkpoint.json"
    events, findings = load_openai_agents(fixture_path)

    assert len(findings) == 0
    assert len(events) == 3

    # Verify handoff event
    handoff_ev = events[1]
    assert handoff_ev.id == "item_02"
    assert handoff_ev.kind == "handoff"
    assert handoff_ev.payload.get("target") == "specialist_agent"

    # Verify checkpoints preserved with length 2 and intact attributes
    checkpoints = events.source.checkpoints
    assert len(checkpoints) == 2
    assert checkpoints[0]["id"] == "chk_01"
    assert checkpoints[0]["seq"] == 1
    assert (
        checkpoints[0]["hash"]
        == "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    )
    assert checkpoints[1]["id"] == "chk_02"
    assert checkpoints[1]["seq"] == 2
    assert (
        checkpoints[1]["hash"]
        == "sha256:2222222222222222222222222222222222222222222222222222222222222222"
    )

    # In SessionHeader wrapper
    session, session_findings = load_openai_agents_session(fixture_path)
    assert len(session_findings) == 0
    assert isinstance(session.header.source, dict)
    assert len(session.header.source["checkpoints"]) == 2
    assert session.header.source["run_state"]["thread_id"] == "thread_abc123"


def test_unknown_item_SL302() -> None:
    """Verify unknown item type with call_id linkage emits SL302 with kind='unknown'."""
    fixture_path = FIXTURES_DIR / "unknown_item.json"
    events, findings = load_openai_agents(fixture_path)

    assert len(events) == 2
    assert len(findings) >= 1

    # Record 1 has kind="unknown"
    assert events[1].kind == "unknown"
    assert events[1].actor == "system"

    # SL302 finding with field evidence
    sl302_findings = [f for f in findings if f.code == SL302]
    assert len(sl302_findings) == 1
    f = sl302_findings[0]
    assert f.severity == Severity.ERROR
    assert f.repairability == Repairability.MANUAL
    assert f.source.record_id == "item_02"
    assert f.evidence is not None
    assert f.evidence["field_path"] == "type"
    assert f.evidence["type_value"] == "futureTool"


def test_old_sdk_version_SL301(tmp_path: Path) -> None:
    """Verify obsolete export_version emits SL301 with structured evidence."""
    f = tmp_path / "old_version.json"
    doc = {
        "export_version": "0.0.1",
        "items": [
            {
                "id": "item_01",
                "type": "message",
                "role": "user",
                "content": "hello",
            }
        ],
    }
    f.write_text(json.dumps(doc), encoding="utf-8")

    events, findings = load_openai_agents(f)
    assert len(events) == 1
    assert len(findings) == 1

    finding = findings[0]
    assert finding.code == SL301
    assert finding.severity == Severity.ERROR
    assert finding.repairability == Repairability.UNSUPPORTED
    assert finding.evidence is not None
    assert finding.evidence["version_raw"] == "0.0.1"
    assert set(finding.evidence["supported_set"]) == set(SUPPORTED_OPENAI_AGENTS_VERSIONS)


def test_live_db_refused() -> None:
    """Verify live SQLite file is refused with fatal SL001, without mutation and zero

    sqlite3 import.
    """
    fixture_path = FIXTURES_DIR / "live_db_fake.sqlite"

    # Record digest before call
    initial_bytes = fixture_path.read_bytes()
    initial_sha = hashlib.sha256(initial_bytes).hexdigest()
    initial_mtime = fixture_path.stat().st_mtime_ns

    # Clean sqlite3 from sys.modules if present
    sys.modules.pop("sqlite3", None)

    events, findings = load_openai_agents(fixture_path)

    # 1. Returned results
    assert len(events) == 0
    assert len(findings) == 1

    f = findings[0]
    assert f.code == SL001
    assert f.severity == Severity.FATAL
    assert f.repairability == Repairability.UNSUPPORTED
    assert f.evidence == {"reason": "refused_live_db"}
    assert "refused_live_db" in f.message

    # 2. Assert sqlite3 was NEVER imported
    assert "sqlite3" not in sys.modules

    # 3. Assert file was NOT modified
    after_bytes = fixture_path.read_bytes()
    after_sha = hashlib.sha256(after_bytes).hexdigest()
    after_mtime = fixture_path.stat().st_mtime_ns

    assert initial_sha == after_sha
    assert initial_mtime == after_mtime


def test_jsonl_stream(tmp_path: Path) -> None:
    """Verify identical items in JSONL format produce byte-identical canonical JSON to JSON form."""
    json_path = FIXTURES_DIR / "items_basic.json"
    events_json, findings_json = load_openai_agents(json_path)
    assert len(findings_json) == 0

    # Convert items to JSONL
    doc = json.loads(json_path.read_text(encoding="utf-8"))
    jsonl_lines = [json.dumps(it) for it in doc["items"]]
    jsonl_text = "\n".join(jsonl_lines) + "\n"

    jsonl_file = tmp_path / "items_stream.jsonl"
    jsonl_file.write_text(jsonl_text, encoding="utf-8")

    events_jsonl, findings_jsonl = load_openai_agents(jsonl_file)
    assert len(findings_jsonl) == 0

    # Format parity check: Canonical bytes must be 100% byte-equal
    bytes_from_json = canonical_bytes(events_json)
    bytes_from_jsonl = canonical_bytes(events_jsonl)
    assert bytes_from_json == bytes_from_jsonl


def test_determinism() -> None:
    """Verify identical input produces byte-identical canonical JSON and findings across runs."""
    fixture_path = FIXTURES_DIR / "items_basic.json"
    events_1, findings_1 = load_openai_agents(fixture_path)
    events_2, findings_2 = load_openai_agents(fixture_path)

    assert to_canonical_json(events_1) == to_canonical_json(events_2)

    findings_json_1 = json.dumps([f.to_dict() for f in findings_1], sort_keys=True)
    findings_json_2 = json.dumps([f.to_dict() for f in findings_2], sort_keys=True)
    assert findings_json_1 == findings_json_2


def test_limit_gate(tmp_path: Path) -> None:
    """Verify oversize document produces an SL001 limit finding without unhandled exceptions."""
    f = tmp_path / "oversize.json"
    f.write_text('{"items": [{"id": "1", "type": "message", "content": "hi"}]}', encoding="utf-8")

    # Limit smaller than file
    limits = ReaderLimits(max_file_bytes=10)
    events, findings = load_openai_agents(f, limits=limits)

    assert len(events) == 0
    assert len(findings) == 1
    assert findings[0].code == SL001
    assert "LIMIT" in findings[0].message
    assert findings[0].evidence is not None
    assert findings[0].evidence["reason"] == "size_limit_exceeded"


def test_detect_openai_agents() -> None:
    """Verify heuristic detector correctly classifies OpenAI Agents SDK artifacts."""
    # 1. Valid JSON export
    sample_json = b'{"items": [{"id": "1", "call_id": "c1", "type": "tool_call"}]}'
    assert detect_openai_agents(sample_json, "export.json") >= 0.8

    # 2. Valid run_state export
    sample_wrapper = b'{"run_state": {}, "checkpoints": []}'
    assert detect_openai_agents(sample_wrapper, "state.json") >= 0.8

    # 3. Live SQLite file
    assert detect_openai_agents(SQLITE_MAGIC, "session.sqlite") == 1.0
    assert detect_openai_agents(SQLITE_MAGIC, "session.json") == 0.5

    # 4. Irrelevant files
    assert detect_openai_agents(b'{"random": 123}', "other.txt") == 0.0
    assert detect_openai_agents(b"", "empty.json") == 0.0


def test_normalize_version() -> None:
    """Verify version normalization handles 'v' prefix, whitespace, and case."""
    assert normalize_version("1.0.0") == "1.0.0"
    assert normalize_version("v1.0.0") == "1.0.0"
    assert normalize_version("  V0.2.0  ") == "0.2.0"
    assert normalize_version("openai-agents-v1") == "openai-agents-v1"


def test_load_openai_agents_session() -> None:
    """Verify load_openai_agents_session creates valid Session envelope."""
    fixture_path = FIXTURES_DIR / "items_basic.json"
    session, findings = load_openai_agents_session(fixture_path)

    assert len(findings) == 0
    assert session.header.schema_version == "sesslint.session/v1"
    assert session.header.session_id == "openai-agents-session"
    assert len(session.events) == 5


def test_adversarial_sqlite_magic_renamed_to_json(tmp_path: Path) -> None:
    """Verify SQLite magic renamed to .json is still refused (magic wins over extension)."""
    fake_db = tmp_path / "sneaky.json"
    fake_db.write_bytes(SQLITE_MAGIC + b"\x00" * 32)

    events, findings = load_openai_agents(fake_db)
    assert len(events) == 0
    assert len(findings) == 1
    assert findings[0].code == SL001
    assert findings[0].severity == Severity.FATAL
    assert findings[0].evidence == {"reason": "refused_live_db"}


def test_adversarial_items_as_dict(tmp_path: Path) -> None:
    """Verify items supplied as dict instead of list is preserved as single item without raising."""
    f = tmp_path / "dict_items.json"
    f.write_text(
        '{"items": {"id": "single", "type": "message", "role": "user", "content": "hi"}}',
        encoding="utf-8",
    )

    events, findings = load_openai_agents(f)
    assert len(findings) == 0
    assert len(events) == 1
    assert events[0].id == "single"


def test_adversarial_handoff_missing_target(tmp_path: Path) -> None:
    """Verify handoff item with missing target preserves None without inventing values."""
    f = tmp_path / "handoff_no_target.json"
    f.write_text('{"items": [{"id": "h1", "type": "handoff"}]}', encoding="utf-8")

    events, findings = load_openai_agents(f)
    assert len(findings) == 0
    assert len(events) == 1
    assert events[0].kind == "handoff"
    assert events[0].payload.get("target") is None


def test_adversarial_nul_byte(tmp_path: Path) -> None:
    """Verify NUL byte triggers SL001 finding rather than escaping into payload."""
    f = tmp_path / "nul_doc.json"
    f.write_bytes(b'{"items": [{"id": "m1", \x00 "type": "message"}]}')

    events, findings = load_openai_agents(f)
    assert len(events) == 0
    assert len(findings) == 1
    assert findings[0].code == SL001
    assert "NUL byte" in findings[0].message


def test_adversarial_invalid_utf8(tmp_path: Path) -> None:
    """Verify invalid UTF-8 triggers SL001 without unhandled traceback leak."""
    f = tmp_path / "invalid_utf8.json"
    f.write_bytes(b'{"items": [{"id": "m1", "val": \xff\xfe}]}')

    events, findings = load_openai_agents(f)
    assert len(events) == 0
    assert len(findings) == 1
    assert findings[0].code == SL001
    assert "ENCODING" in findings[0].message


def test_adversarial_version_type_confusion(tmp_path: Path) -> None:
    """Verify version supplied as dict or list triggers SL301 without crashing."""
    f = tmp_path / "version_confusion.json"
    f.write_text(
        '{"sdk_version": {"major": 1}, "items": [{"id": "m1", "type": "message"}]}',
        encoding="utf-8",
    )

    events, findings = load_openai_agents(f)
    assert len(events) == 1
    assert len(findings) == 1
    assert findings[0].code == SL301
    assert findings[0].evidence is not None
    assert findings[0].evidence["version_raw"] == "<invalid_version_type>"


def test_deep_nesting_limit(tmp_path: Path) -> None:
    """Verify nesting depth exceeding max_depth triggers SL001 limit finding."""
    deep_val: dict[str, Any] = {"leaf": 1}
    for _ in range(15):
        deep_val = {"nest": deep_val}

    f = tmp_path / "deep.json"
    f.write_text(
        json.dumps({"items": [{"id": "m1", "type": "message", "data": deep_val}]}),
        encoding="utf-8",
    )

    limits = ReaderLimits(max_depth=5)
    events, findings = load_openai_agents(f, limits=limits)
    assert len(events) == 0
    assert len(findings) == 1
    assert findings[0].code == SL001
    assert "detail: LIMIT" in findings[0].message


def test_file_not_found() -> None:
    """Verify missing file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        load_openai_agents(Path("nonexistent_session.json"))


def test_directory_path(tmp_path: Path) -> None:
    """Verify passing a directory path raises IsADirectoryError."""
    with pytest.raises(IsADirectoryError):
        load_openai_agents(tmp_path)


def test_max_records_exceeded(tmp_path: Path) -> None:
    """Verify record count exceeding max_records raises MaxRecordsExceededError."""
    f = tmp_path / "records.json"
    doc = {
        "items": [
            {"id": "m1", "type": "message"},
            {"id": "m2", "type": "message"},
            {"id": "m3", "type": "message"},
        ]
    }
    f.write_text(json.dumps(doc), encoding="utf-8")

    limits = ReaderLimits(max_records=2)
    with pytest.raises(MaxRecordsExceededError):
        load_openai_agents(f, limits=limits)


def test_jsonl_torn_tail_delegates_SL002(tmp_path: Path) -> None:
    """Verify terminal incomplete line in JSONL mode delegates to SL002."""
    f = tmp_path / "torn.jsonl"
    line1 = '{"id":"m1","type":"message","content":"hello"}\n'
    line2 = '{"id":"m2","type":"message","content":"inc'
    f.write_text(line1 + line2, encoding="utf-8")

    events, findings = load_openai_agents(f)
    assert len(events) == 1
    assert len(findings) == 1
    assert findings[0].code == SL002
    assert findings[0].source.line == 2


def test_jsonl_malformed_midstream_delegates_SL001(tmp_path: Path) -> None:
    """Verify nonterminal broken line in JSONL mode delegates to SL001."""
    f = tmp_path / "broken_mid.jsonl"
    line1 = '{"id":"m1","type":"message","content":"hello"}\n'
    line2 = '{"id":"broken" corrupt line\n'
    line3 = '{"id":"m2","type":"message","content":"world"}\n'
    f.write_text(line1 + line2 + line3, encoding="utf-8")

    events, findings = load_openai_agents(f)
    assert len(events) == 2
    assert len(findings) == 1
    assert findings[0].code == SL001
    assert findings[0].source.line == 2


def test_bytes_direct_input() -> None:
    """Verify load_openai_agents directly accepts raw bytes."""
    data = b'{"items": [{"id": "m1", "type": "message", "content": "from_bytes"}]}'
    events, findings = load_openai_agents(data)
    assert len(events) == 1
    assert len(findings) == 0
    assert events[0].id == "m1"


def test_source_metadata_attribute_error() -> None:
    """Verify accessing nonexistent attribute on SourceMetadata raises AttributeError."""
    events, _ = load_openai_agents(b'{"items": []}')
    with pytest.raises(AttributeError, match="has no attribute 'nonexistent'"):
        _ = events.source.nonexistent


def test_detect_openai_agents_extended_signals() -> None:
    """Verify detector matches function_call, function_call_output, and handoff tokens."""
    data = b'{"type": "function_call", "name": "do_task", "handoff": true}'
    assert detect_openai_agents(data, "session.json") >= 0.8


def test_tool_call_json_string_input() -> None:
    """Verify tool_call with JSON string arguments decodes arguments to mapping."""
    doc = {
        "items": [
            {
                "id": "tc1",
                "type": "tool_call",
                "name": "lookup",
                "args": '{"query": "antigravity"}',
            }
        ]
    }
    events, findings = load_openai_agents(json.dumps(doc).encode("utf-8"))
    assert len(findings) == 0
    assert len(events) == 1
    assert events[0].payload["input"] == {"query": "antigravity"}


def test_checkpoint_and_compaction_items() -> None:
    """Verify checkpoint and compaction_boundary items parse all fields."""
    doc = {
        "items": [
            {
                "id": "chk_item",
                "type": "checkpoint",
                "seq": 42,
                "hash": "sha256:abc",
                "state": {"cursor": 10},
            },
            {
                "id": "cmp_item",
                "type": "compaction_boundary",
                "summary": "Pruned 50 messages",
            },
        ]
    }
    events, findings = load_openai_agents(json.dumps(doc).encode("utf-8"))
    assert len(findings) == 0
    assert len(events) == 2
    assert events[0].kind == "checkpoint"
    assert events[0].payload["seq"] == 42
    assert events[0].payload["hash"] == "sha256:abc"
    assert events[0].payload["state"] == {"cursor": 10}

    assert events[1].kind == "compaction_boundary"
    assert events[1].payload["summary"] == "Pruned 50 messages"


def test_json_doc_top_level_list_and_non_dict_items() -> None:
    """Verify top-level JSON list parses and non-dict items emit SL001."""
    data = b'[{"id": "m1", "type": "message", "role": "user"}, "invalid_item"]'
    events, findings = load_openai_agents(data)
    assert len(events) == 1
    assert len(findings) == 1
    assert findings[0].code == SL001
    assert findings[0].evidence == {"reason": "item_not_dict"}


def test_role_dispatches_and_missing_type() -> None:
    """Verify role='system' and role='tool' dispatch correctly with or without type."""
    doc = {
        "items": [
            {"id": "s1", "type": "message", "role": "system", "content": "system prompt"},
            {"id": "t1", "type": "message", "role": "tool", "content": "tool output"},
            {"id": "s2", "role": "system", "content": "system 2"},
            {"id": "t2", "role": "tool", "content": "tool 2"},
            {"id": "u1", "role": "user", "content": "user 2"},
            {"id": "a1", "role": "assistant", "content": "assistant 2"},
            {"id": "x1", "role": "unknown_role", "content": "unknown 2"},
        ]
    }
    events, findings = load_openai_agents(json.dumps(doc).encode("utf-8"))
    assert len(findings) == 0
    assert len(events) == 7
    assert events[0].actor == "system"
    assert events[0].kind == "message"
    assert events[1].actor == "tool"
    assert events[1].kind == "tool_result"
    assert events[2].actor == "system"
    assert events[2].kind == "message"
    assert events[3].actor == "tool"
    assert events[3].kind == "tool_result"
    assert events[4].actor == "user"
    assert events[5].actor == "assistant"
    assert events[6].kind == "unknown"


def test_critical_field_sl302() -> None:
    """Verify critical_ field prefix triggers SL302."""
    doc = {
        "items": [
            {
                "id": "m1",
                "type": "message",
                "role": "user",
                "critical_flag": "unsafe",
            }
        ]
    }
    events, findings = load_openai_agents(json.dumps(doc).encode("utf-8"))
    assert len(events) == 1
    assert len(findings) == 1
    assert findings[0].code == SL302
    assert findings[0].evidence is not None
    assert findings[0].evidence["field_path"] == "critical_flag"


def test_tool_result_failure_state() -> None:
    """Verify tool_result with is_error=True receives execution_state='failure'."""
    doc = {
        "items": [
            {
                "id": "tr1",
                "type": "tool_result",
                "call_id": "c1",
                "is_error": True,
                "content": "command not found",
            }
        ]
    }
    events, findings = load_openai_agents(json.dumps(doc).encode("utf-8"))
    assert len(findings) == 0
    assert len(events) == 1
    assert events[0].execution_state == "failure"


def test_jsonl_hostile_limits_matrix(tmp_path: Path) -> None:
    """Verify JSONL hostile limits: NUL byte, invalid UTF-8, line too long, and depth."""
    # 1. NUL byte in JSONL
    f_nul = tmp_path / "nul.jsonl"
    f_nul.write_bytes(b'{"id":"m1","content":"hello\x00world"}\n{"id":"m2","content":"ok"}\n')
    _, findings_nul = load_openai_agents(f_nul)
    assert any("NUL byte" in f.message for f in findings_nul)

    # 2. Invalid UTF-8 in JSONL
    f_utf8 = tmp_path / "bad_utf8.jsonl"
    f_utf8.write_bytes(b'{"id":"m1","content":\xff\xfe}\n{"id":"m2","content":"ok"}\n')
    _, findings_utf8 = load_openai_agents(f_utf8)
    assert any("ENCODING" in f.message for f in findings_utf8)

    # 3. Line too long in JSONL
    f_long = tmp_path / "long.jsonl"
    f_long.write_text('{"id":"m1","content":"' + ("x" * 200) + '"}\n', encoding="utf-8")
    limits = ReaderLimits(max_line_bytes=50)
    _, findings_long = load_openai_agents(f_long, limits=limits)
    assert any("LIMIT" in f.message for f in findings_long)

    # 4. Deep nesting in JSONL
    f_deep = tmp_path / "deep.jsonl"
    deep_val: dict[str, Any] = {"leaf": 1}
    for _ in range(10):
        deep_val = {"nest": deep_val}
    f_deep.write_text(json.dumps({"id": "m1", "data": deep_val}) + "\n", encoding="utf-8")
    limits_depth = ReaderLimits(max_depth=5)
    _, findings_deep = load_openai_agents(f_deep, limits=limits_depth)
    assert any("LIMIT" in f.message for f in findings_deep)


def test_project_run_state_empty_and_absent() -> None:
    """Verify project_run_state handles None, empty dict, or non-matching dict gracefully."""
    empty_expected = {
        "checkpoints": [],
        "keys": [],
        "shapes": {},
        "truncated": False,
    }

    assert project_run_state(None) == empty_expected
    assert project_run_state({}) == empty_expected
    assert project_run_state({"irrelevant_field": 123}) == empty_expected


def test_project_run_state_bounding_and_truncation() -> None:
    """Verify project_run_state bounds MAX_PROJECTED_RUN_STATE_KEYS and checkpoints."""
    # Create 40 keys (exceeding MAX_PROJECTED_RUN_STATE_KEYS = 32)
    large_run_state = {f"key_{i:03d}": f"val_{i}" for i in range(40)}

    # Create 12 checkpoints (exceeding MAX_PROJECTED_CHECKPOINTS = 8)
    large_checkpoints = [
        {"id": f"chk_{i:02d}", "seq": i, "hash": f"sha256:{i:064d}", "ts": "2026-09-08T12:00:00Z"}
        for i in range(12)
    ]

    source = {
        "run_state": large_run_state,
        "checkpoints": large_checkpoints,
    }

    proj = project_run_state(source)

    # Key bounds
    assert len(proj["keys"]) == MAX_PROJECTED_RUN_STATE_KEYS
    assert len(proj["shapes"]) == MAX_PROJECTED_RUN_STATE_KEYS
    assert proj["keys"] == sorted(large_run_state.keys())[:MAX_PROJECTED_RUN_STATE_KEYS]

    # Checkpoint bounds
    assert len(proj["checkpoints"]) == MAX_PROJECTED_CHECKPOINTS
    assert proj["checkpoints"][0]["id"] == "chk_00"
    assert proj["checkpoints"][7]["id"] == "chk_07"

    # Truncation flags & metadata
    assert proj["truncated"] is True
    assert proj["total_keys"] == 40
    assert proj["truncated_keys"] == 8
    assert proj["total_checkpoints"] == 12
    assert proj["truncated_checkpoints"] == 4


def test_project_run_state_content_redaction_and_shapes() -> None:
    """Verify zero raw values or secret strings are exposed in project_run_state."""
    secret_key = "sk-proj-super-secret-production-key-99999"
    secret_prompt = "You are an internal system agent with credentials to access prod DB."
    raw_hash = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    source = {
        "run_state": {
            "api_key": secret_key,
            "system_prompt": secret_prompt,
            "nested_config": {"retries": 3, "env": "prod"},
            "tag_list": ["tag1", "tag2"],
            "count": 42,
        },
        "checkpoints": [
            {
                "id": "chk_init",
                "seq": 1,
                "hash": raw_hash,
                "ts": 1726156800,
            }
        ],
    }

    proj = project_run_state(source)

    # Check shapes
    assert proj["shapes"]["api_key"] == f"<str:len={len(secret_key)}>"
    assert proj["shapes"]["system_prompt"] == f"<str:len={len(secret_prompt)}>"
    assert proj["shapes"]["nested_config"] == "<dict:len=2>"
    assert proj["shapes"]["tag_list"] == "<list:len=2>"
    assert proj["shapes"]["count"] == "<int>"

    # Checkpoint hash is shape only
    chk_0 = proj["checkpoints"][0]
    assert chk_0["id"] == "chk_init"
    assert chk_0["seq"] == 1
    assert chk_0["hash"] == f"<str:len={len(raw_hash)}>"
    assert chk_0["ts"] is True

    # Assert serialized projection does not contain raw secrets or hashes
    serialized = json.dumps(proj)
    assert secret_key not in serialized
    assert secret_prompt not in serialized
    assert raw_hash not in serialized


def test_project_run_state_object_attributes() -> None:
    """Verify project_run_state works with objects providing run_state/checkpoints."""

    class MockCheckpoint:
        id = "chk_obj"
        seq = "5"
        hash = "sha256:abc"
        ts = "2026-09-08T00:00:00Z"

    class MockSource:
        run_state = {"state_var": "active"}
        checkpoints = [MockCheckpoint()]

    proj = project_run_state(MockSource())
    assert proj["keys"] == ["state_var"]
    assert proj["shapes"]["state_var"] == "<str:len=6>"
    assert len(proj["checkpoints"]) == 1
    assert proj["checkpoints"][0]["id"] == "chk_obj"
    assert proj["checkpoints"][0]["seq"] == 5
    assert proj["checkpoints"][0]["hash"] == "<str:len=10>"
    assert proj["checkpoints"][0]["ts"] is True
    assert proj["truncated"] is False


def test_project_run_state_non_string_keys_and_collisions() -> None:
    """Verify project_run_state handles non-string keys and collision deduplication."""
    source = {
        "run_state": {
            1: "int_key_val",
            2: "another_int_key",
            "bad key with spaces 1": "val1",
            "bad key with spaces 2": "val2",
        },
        "checkpoints": [
            {"id": "c1", "seq": "42"},
            {"id": "sk-secret-token", "seq": 43},
        ],
    }

    proj = project_run_state(source)
    assert len(proj["keys"]) == 4
    assert len(proj["shapes"]) == 4
    for k in proj["keys"]:
        assert k in proj["shapes"]

    # Redacted ID check
    assert proj["checkpoints"][0]["id"] == "c1"
    assert proj["checkpoints"][0]["seq"] == 42
    assert proj["checkpoints"][1]["id"] == "<redacted>"
    assert proj["checkpoints"][1]["seq"] == 43


def test_project_run_state_idempotence() -> None:
    """Verify passing an already projected dictionary or source returns a matching projection."""
    existing_proj = {
        "checkpoints": [{"hash": "<str:len=10>", "id": "c1", "seq": 1, "ts": True}],
        "keys": ["k1"],
        "shapes": {"k1": "<int>"},
        "truncated": False,
    }

    res1 = project_run_state(existing_proj)
    assert res1 == existing_proj

    class MockWithProj:
        run_state_projection = existing_proj

    res2 = project_run_state(MockWithProj())
    assert res2 == existing_proj
