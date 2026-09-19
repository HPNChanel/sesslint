"""Unit, conformance, and golden snapshot tests for Claude Code JSONL adapter (TASK-008).

Validates canonicalization, version evidence extraction (SL301), unknown record
handling (SL302), streaming limits, malformed record delegation (SL001/SL002),
and determinism guarantees.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from sesslint.adapters.claude_code import (
    SUPPORTED_CLAUDE_VERSIONS,
    detect_claude_code,
    load_claude_code,
    load_claude_code_session,
    normalize_version,
)
from sesslint.canonical import to_canonical_json
from sesslint.codes import SL001, SL002, SL301, SL302, Repairability, Severity
from sesslint.errors import FileTooLargeError, MaxRecordsExceededError
from sesslint.io import ReaderLimits

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "claude_code"
SNAPSHOTS_DIR = Path(__file__).resolve().parent / "snapshots"


def test_basic_chain() -> None:
    """Verify 5-record basic chain produces 5 canonical events and matches golden snapshot."""
    fixture_path = FIXTURES_DIR / "basic.jsonl"
    events, findings = load_claude_code(fixture_path)

    # Invariants: 5 events, 0 findings
    assert len(findings) == 0
    assert len(events) == 5

    # Verify event fields and kinds
    assert events[0].id == "msg_01"
    assert events[0].actor == "user"
    assert events[0].kind == "message"
    assert events[0].parent_id is None
    assert events[0].seq == 0

    assert events[1].id == "msg_02"
    assert events[1].actor == "assistant"
    assert events[1].kind == "message"
    assert events[1].parent_id == "msg_01"
    assert events[1].seq == 1

    assert events[2].id == "msg_03"
    assert events[2].actor == "assistant"
    assert events[2].kind == "tool_call"
    assert events[2].parent_id == "msg_02"
    assert events[2].seq == 2
    assert events[2].payload.get("tool_name") == "read_file"

    assert events[3].id == "msg_04"
    assert events[3].actor == "tool"
    assert events[3].kind == "tool_result"
    assert events[3].parent_id == "msg_03"
    assert events[3].seq == 3
    assert events[3].execution_state == "success"

    assert events[4].id == "msg_05"
    assert events[4].actor == "assistant"
    assert events[4].kind == "message"
    assert events[4].parent_id == "msg_04"
    assert events[4].seq == 4

    # Golden snapshot byte-equality comparison
    golden_path = SNAPSHOTS_DIR / "claude_basic.canonical.json"
    assert golden_path.is_file(), f"Golden snapshot missing at {golden_path}"
    golden_bytes = golden_path.read_bytes()
    actual_bytes = to_canonical_json(events).encode("utf-8")
    assert actual_bytes == golden_bytes


def test_version_old_emits_SL301() -> None:
    """Verify obsolete version field emits exactly 1 SL301 with structured evidence."""
    fixture_path = FIXTURES_DIR / "version_old.jsonl"
    events, findings = load_claude_code(fixture_path)

    assert len(events) == 2
    assert len(findings) == 1

    f = findings[0]
    assert f.code == SL301
    assert f.severity == Severity.ERROR
    assert f.repairability == Repairability.UNSUPPORTED
    assert f.source.line == 1
    assert f.source.record_id == "msg_01"

    # Evidence checks
    assert f.evidence is not None
    assert f.evidence["version_raw"] == "0.0.1"
    assert set(f.evidence["supported_set"]) == set(SUPPORTED_CLAUDE_VERSIONS)


def test_unknown_type_emits_SL302() -> None:
    """Verify unknown record type emits SL302, sets kind=unknown, and includes field evidence."""
    fixture_path = FIXTURES_DIR / "unknown_type.jsonl"
    events, findings = load_claude_code(fixture_path)

    assert len(events) == 2
    assert len(findings) >= 1

    # Record 2 has kind=="unknown"
    assert events[1].kind == "unknown"
    assert events[1].actor == "system"

    # At least one SL302 finding with field_path/type_value
    sl302_findings = [f for f in findings if f.code == SL302]
    assert len(sl302_findings) >= 1
    f = sl302_findings[0]
    assert f.severity == Severity.ERROR
    assert f.repairability == Repairability.MANUAL
    assert f.source.record_id == "msg_02"
    assert f.evidence is not None
    assert "field_path" in f.evidence
    assert "type_value" in f.evidence
    assert f.evidence["type_value"] == "futureWidget"


def test_unknown_noncritical_no_finding() -> None:
    """Verify decorative unknown fields (theme, extra_debug) are ignored without findings."""
    fixture_path = FIXTURES_DIR / "mixed_unknown_noncritical.jsonl"
    events, findings = load_claude_code(fixture_path)

    # 0 findings emitted
    assert len(findings) == 0
    assert len(events) == 2
    assert events[0].actor == "user"
    assert events[0].kind == "message"
    assert events[1].actor == "assistant"
    assert events[1].kind == "message"


def test_malformed_delegates_SL001(tmp_path: Path) -> None:
    """Verify nonterminal malformed JSON lines delegate to SL001 and continue streaming."""
    bad_file = tmp_path / "broken_mid.jsonl"
    line1 = '{"id":"msg_01","type":"user_message","message":"Valid 1"}\n'
    line2 = '{"id":"broken", this is malformed json\n'
    line3 = '{"id":"msg_02","parentId":"msg_01","type":"assistant_message","message":"Valid 2"}\n'
    bad_file.write_text(line1 + line2 + line3, encoding="utf-8")

    events, findings = load_claude_code(bad_file)

    # Should recover valid records and report SL001 on line 2
    assert len(events) == 2
    assert len(findings) == 1
    f = findings[0]
    assert f.code == SL001
    assert f.source.line == 2
    assert f.severity == Severity.ERROR
    assert f.repairability == Repairability.MANUAL


def test_torn_tail_SL002(tmp_path: Path) -> None:
    """Verify terminal incomplete line delegates to SL002 (torn terminal record)."""
    torn_file = tmp_path / "torn_tail.jsonl"
    line1 = '{"id":"msg_01","type":"user_message","message":"Valid 1"}\n'
    line2 = '{"id":"msg_02","type":"assistant_message","message":"Inc'
    torn_file.write_text(line1 + line2, encoding="utf-8")

    events, findings = load_claude_code(torn_file)

    assert len(events) == 1
    assert len(findings) == 1
    f = findings[0]
    assert f.code == SL002
    assert f.source.line == 2
    assert f.severity == Severity.ERROR
    assert f.repairability == Repairability.DETERMINISTIC


def test_determinism() -> None:
    """Verify identical input bytes produce byte-identical canonical JSON output across runs."""
    fixture_path = FIXTURES_DIR / "basic.jsonl"
    events_1, findings_1 = load_claude_code(fixture_path)
    events_2, findings_2 = load_claude_code(fixture_path)

    json_1 = to_canonical_json([e for e in events_1])
    json_2 = to_canonical_json([e for e in events_2])
    assert json_1 == json_2

    findings_json_1 = json.dumps([f.to_dict() for f in findings_1], sort_keys=True)
    findings_json_2 = json.dumps([f.to_dict() for f in findings_2], sort_keys=True)
    assert findings_json_1 == findings_json_2


def test_streaming_budget(tmp_path: Path) -> None:
    """Verify streaming reader operates in bounded memory across 5,000 records."""
    large_file = tmp_path / "large_5k.jsonl"
    with open(large_file, "w", encoding="utf-8") as f:
        for i in range(5000):
            parent = f"rec_{i - 1}" if i > 0 else None
            rec = {
                "id": f"rec_{i}",
                "parentId": parent,
                "type": "user_message" if i % 2 == 0 else "assistant_message",
                "message": f"Turn {i}",
                "timestamp": "2025-01-01T00:00:00Z",
            }
            f.write(json.dumps(rec) + "\n")

    limits = ReaderLimits(max_line_bytes=100_000, max_records=10_000)
    events, findings = load_claude_code(large_file, limits=limits)

    assert len(findings) == 0
    assert len(events) == 5000
    assert events[4999].parent_id == "rec_4998"


def test_detect_claude_code() -> None:
    """Verify heuristic detector returns high confidence for Claude Code files and 0 for others."""
    # 1. Valid Claude Code JSONL file content
    claude_bytes = (
        b'{"id":"msg_01","type":"user_message","message":"Hello","timestamp":"2025-01-01T00:00:00Z"}\n'
        b'{"id":"msg_02","parentId":"msg_01","type":"assistant_message","message":"Hi","timestamp":"2025-01-01T00:00:01Z"}\n'
    )
    conf = detect_claude_code(claude_bytes, "session.jsonl")
    assert conf >= 0.8

    # 2. Non-JSONL filename
    assert detect_claude_code(claude_bytes, "session.txt") == 0.0
    assert detect_claude_code(claude_bytes, "session.csv") == 0.0

    # 3. Empty bytes
    assert detect_claude_code(b"", "session.jsonl") == 0.0

    # 4. Irrelevant JSONL
    other_bytes = b'{"number": 1, "value": "test"}\n'
    assert detect_claude_code(other_bytes, "test.jsonl") <= 0.2


def test_normalize_version() -> None:
    """Verify version normalization handles whitespace, 'v' prefix, and case."""
    assert normalize_version("1.0.0") == "1.0.0"
    assert normalize_version("v1.0.0") == "1.0.0"
    assert normalize_version("  V0.1.0  ") == "0.1.0"
    assert normalize_version("claude-code-v1") == "claude-code-v1"


def test_load_claude_code_session() -> None:
    """Verify load_claude_code_session returns a valid Session envelope."""
    fixture_path = FIXTURES_DIR / "basic.jsonl"
    session, findings = load_claude_code_session(fixture_path)

    assert len(findings) == 0
    assert session.header.schema_version == "sesslint.session/v1"
    assert session.header.source == {"format": "claude-code-jsonl"}
    assert len(session.events) == 5


def test_adversarial_max_line_bytes(tmp_path: Path) -> None:
    """Verify a giant line exceeding max_line_bytes triggers SL001 without unbounded buffering."""
    huge_file = tmp_path / "huge_line.jsonl"
    normal_line = '{"id":"msg_01","type":"user_message","message":"hi"}\n'
    huge_payload = "x" * 1000
    huge_line = f'{{"id":"msg_02","type":"assistant_message","message":"{huge_payload}"}}\n'
    tail_line = '{"id":"msg_03","type":"assistant_message","message":"bye"}\n'

    huge_file.write_text(normal_line + huge_line + tail_line, encoding="utf-8")

    limits = ReaderLimits(max_line_bytes=200)
    events, findings = load_claude_code(huge_file, limits=limits)

    assert any(f.code == SL001 and "LIMIT" in f.message for f in findings)


def test_adversarial_nul_byte(tmp_path: Path) -> None:
    """Verify NUL byte triggers finding rather than escaping into payload."""
    nul_file = tmp_path / "nul_byte.jsonl"
    part1 = b'{"id":"msg_01","type":"user_message","message":"hello \x00 world"}\n'
    part2 = b'{"id":"msg_02","type":"assistant_message","message":"ok"}\n'
    nul_file.write_bytes(part1 + part2)

    events, findings = load_claude_code(nul_file)
    assert len(findings) >= 1
    assert any("NUL byte" in f.message for f in findings)


def test_adversarial_version_type_confusion(tmp_path: Path) -> None:
    """Verify version supplied as dict or list triggers SL301 without crashing."""
    confused_file = tmp_path / "version_dict.jsonl"
    confused_content = (
        '{"id":"msg_01","type":"user_message","version":{"major": 1},"message":"hi"}\n'
    )
    confused_file.write_text(confused_content, encoding="utf-8")

    events, findings = load_claude_code(confused_file)
    assert len(events) == 1
    assert len(findings) == 1
    assert findings[0].code == SL301
    assert findings[0].evidence is not None
    assert findings[0].evidence["version_raw"] == "<invalid_version_type>"


def test_file_not_found() -> None:
    """Verify missing file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        load_claude_code(Path("nonexistent_session.jsonl"))


def test_directory_path(tmp_path: Path) -> None:
    """Verify passing a directory path raises IsADirectoryError."""
    with pytest.raises(IsADirectoryError):
        load_claude_code(tmp_path)


def test_file_too_large(tmp_path: Path) -> None:
    """Verify file exceeding max_file_bytes raises FileTooLargeError."""
    f = tmp_path / "large.jsonl"
    f.write_text('{"id":"m1","type":"user_message","message":"hi"}\n', encoding="utf-8")
    limits = ReaderLimits(max_file_bytes=10)
    with pytest.raises(FileTooLargeError):
        load_claude_code(f, limits=limits)


def test_max_records_exceeded(tmp_path: Path) -> None:
    """Verify record count exceeding max_records raises MaxRecordsExceededError."""
    f = tmp_path / "three_records.jsonl"
    content = (
        '{"id":"m1","type":"user_message","message":"1"}\n'
        '{"id":"m2","type":"assistant_message","message":"2"}\n'
        '{"id":"m3","type":"user_message","message":"3"}\n'
    )
    f.write_text(content, encoding="utf-8")
    limits = ReaderLimits(max_records=2)
    with pytest.raises(MaxRecordsExceededError):
        load_claude_code(f, limits=limits)


def test_binary_stream_input() -> None:
    """Verify load_claude_code directly accepts BinaryIO stream."""
    stream = io.BytesIO(b'{"id":"m1","type":"user_message","message":"stream"}\n')
    events, findings = load_claude_code(stream)
    assert len(events) == 1
    assert len(findings) == 0
    assert events[0].id == "m1"


def test_compaction_boundary_record(tmp_path: Path) -> None:
    """Verify compaction boundary record creates canonical compaction event."""
    f = tmp_path / "compact.jsonl"
    f.write_text(
        '{"id":"c1","type":"compaction","summary":"Context pruned"}\n',
        encoding="utf-8",
    )
    events, findings = load_claude_code(f)
    assert len(findings) == 0
    assert len(events) == 1
    assert events[0].kind == "compaction_boundary"
    assert events[0].payload.get("summary") == "Context pruned"


def test_non_dict_record(tmp_path: Path) -> None:
    """Verify non-dict JSON records (e.g. array or string) trigger SL001 / SL002."""
    f = tmp_path / "not_dict.jsonl"
    f.write_text('["not", "a", "dict"]\n', encoding="utf-8")
    events, findings = load_claude_code(f)
    assert len(events) == 0
    assert len(findings) == 1
    assert findings[0].code == SL002


def test_critical_field_sl302(tmp_path: Path) -> None:
    """Verify critical_ field prefix triggers SL302."""
    f = tmp_path / "crit.jsonl"
    f.write_text(
        '{"id":"m1","type":"user_message","critical_action":"do_stuff"}\n',
        encoding="utf-8",
    )
    events, findings = load_claude_code(f)
    assert len(events) == 1
    assert len(findings) == 1
    assert findings[0].code == SL302
    assert findings[0].evidence is not None
    assert findings[0].evidence["field_path"] == "critical_action"


def test_deep_nesting_limit(tmp_path: Path) -> None:
    """Verify payload nesting depth exceeding limit triggers finding."""
    f = tmp_path / "deep.jsonl"
    deep_val: dict[str, Any] = {"leaf": 1}
    for _ in range(15):
        deep_val = {"nest": deep_val}
    f.write_text(
        json.dumps({"id": "m1", "type": "user_message", "input": deep_val}) + "\n",
        encoding="utf-8",
    )
    limits = ReaderLimits(max_depth=5)
    events, findings = load_claude_code(f, limits=limits)
    assert len(events) == 0
    assert len(findings) == 1
    assert "detail: LIMIT" in findings[0].message


def test_real_claude_code_shape_with_parent_uuid_and_tool_blocks(tmp_path: Path) -> None:
    """Verify real Claude Code JSONL shape with parentUuid, nested tool blocks, and sessionId."""
    session_file = tmp_path / "real_claude.jsonl"
    lines = [
        json.dumps(
            {
                "uuid": "u1",
                "parentUuid": None,
                "type": "user",
                "sessionId": "sess_real_123",
                "message": {
                    "role": "user",
                    "content": [{"type": "text", "text": "Check git status"}],
                },
            }
        ),
        json.dumps(
            {
                "uuid": "u2",
                "parentUuid": "u1",
                "type": "assistant",
                "sessionId": "sess_real_123",
                "agentId": "subagent-1",
                "branchId": "branch-main",
                "message": {
                    "role": "assistant",
                    "content": [
                        {"type": "text", "text": "Running git status now."},
                        {
                            "type": "tool_use",
                            "id": "toolu_git_1",
                            "name": "bash",
                            "input": {"command": "git status"},
                        },
                    ],
                },
            }
        ),
        json.dumps(
            {
                "uuid": "u3",
                "parentUuid": "u2",
                "type": "user",
                "sessionId": "sess_real_123",
                "agentId": "subagent-1",
                "branchId": "branch-main",
                "message": {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_git_1",
                            "content": "nothing to commit, working tree clean",
                        },
                    ],
                },
            }
        ),
        json.dumps(
            {
                "uuid": "u4",
                "parentUuid": "u3",
                "type": "assistant",
                "sessionId": "sess_real_123",
                "message": {
                    "role": "assistant",
                    "content": [{"type": "text", "text": "All clean!"}],
                },
            }
        ),
    ]
    session_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    session, findings = load_claude_code_session(session_file)
    assert len(findings) == 0
    assert session.header.session_id == "sess_real_123"

    events = session.events
    assert len(events) == 5  # u1, u2_text, u2 (tool_call), u3 (tool_result), u4

    # u1: user message
    assert events[0].id == "u1"
    assert events[0].actor == "user"
    assert events[0].kind == "message"
    assert events[0].parent_id is None

    # u2_text: assistant preamble
    assert events[1].id == "u2_text"
    assert events[1].actor == "assistant"
    assert events[1].kind == "message"
    assert events[1].parent_id == "u1"

    # u2: assistant tool call
    assert events[2].id == "u2"
    assert events[2].actor == "assistant"
    assert events[2].kind == "tool_call"
    assert events[2].parent_id == "u2_text"
    assert events[2].correlation_id == "toolu_git_1"
    assert events[2].payload.get("tool_name") == "bash"
    assert events[2].agent_id == "subagent-1"
    assert events[2].branch_id == "branch-main"

    # u3: tool result
    assert events[3].id == "u3"
    assert events[3].actor == "tool"
    assert events[3].kind == "tool_result"
    assert events[3].parent_id == "u2"
    assert events[3].correlation_id == "toolu_git_1"
    assert events[3].execution_state == "success"
    assert events[3].agent_id == "subagent-1"
    assert events[3].branch_id == "branch-main"

    # u4: assistant message
    assert events[4].id == "u4"
    assert events[4].actor == "assistant"
    assert events[4].kind == "message"
    assert events[4].parent_id == "u3"

    # Verify run_all_checks passes with 0 error findings on real-shaped session
    from sesslint.repair.executor import run_all_checks

    check_findings = run_all_checks(events)
    error_findings = [f for f in check_findings if f.severity == Severity.ERROR]
    assert len(error_findings) == 0


def test_regression_top_level_tool_use_variants(tmp_path: Path) -> None:
    """Verify top-level tool_use records handle input shapes and side_effects."""
    f = tmp_path / "top_level_tool_use.jsonl"
    lines = [
        # 1. Read-only tool with tool_name, args mapping, tool_use_id
        json.dumps(
            {
                "id": "c1",
                "type": "tool_use",
                "tool_name": "read_file",
                "tool_use_id": "tu_read_1",
                "args": {"path": "/etc/hosts"},
            }
        ),
        # 2. Mutating tool with name, arguments mapping, toolUseId
        json.dumps(
            {
                "id": "c2",
                "parentId": "c1",
                "type": "tool_use",
                "name": "write_file",
                "toolUseId": "tu_write_2",
                "arguments": {"path": "/tmp/out.txt", "content": "data"},
            }
        ),
        # 3. Unknown tool with scalar input wrapped into {'value': ...}, missing toolUseId
        json.dumps(
            {
                "id": "c3",
                "parentId": "c2",
                "type": "tool_use",
                "name": "custom_diagnostic_tool",
                "input": "probe-system",
            }
        ),
    ]
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")

    events, findings = load_claude_code(f)
    assert len(findings) == 0
    assert len(events) == 3

    # Event 1: read_file -> side_effects="none"
    assert events[0].id == "c1"
    assert events[0].kind == "tool_call"
    assert events[0].actor == "assistant"
    assert events[0].correlation_id == "tu_read_1"
    assert events[0].side_effects == "none"
    assert events[0].payload["tool_name"] == "read_file"
    assert events[0].payload["input"] == {"path": "/etc/hosts"}

    # Event 2: write_file -> side_effects="possible"
    assert events[1].id == "c2"
    assert events[1].kind == "tool_call"
    assert events[1].correlation_id == "tu_write_2"
    assert events[1].side_effects == "possible"
    assert events[1].payload["tool_name"] == "write_file"
    assert events[1].payload["input"] == {"path": "/tmp/out.txt", "content": "data"}

    # Event 3: custom tool -> side_effects="unknown", scalar input wrapped
    assert events[2].id == "c3"
    assert events[2].kind == "tool_call"
    assert events[2].correlation_id == "c3"  # falls back to rec_id
    assert events[2].side_effects == "unknown"
    assert events[2].payload["tool_name"] == "custom_diagnostic_tool"
    assert events[2].payload["input"] == {"value": "probe-system"}


def test_regression_top_level_tool_result_variants(tmp_path: Path) -> None:
    """Verify top-level tool_result records handle output, error, and status states."""
    f = tmp_path / "top_level_tool_result.jsonl"
    lines = [
        # 1. Success result with output and tool_use_id
        json.dumps(
            {
                "id": "r1",
                "type": "tool_result",
                "tool_use_id": "tu_read_1",
                "output": "127.0.0.1 localhost",
                "is_error": False,
            }
        ),
        # 2. Failure result with result and error=True
        json.dumps(
            {
                "id": "r2",
                "parentId": "r1",
                "type": "tool_result",
                "toolUseId": "tu_write_2",
                "result": "Permission denied: /tmp/out.txt",
                "error": True,
            }
        ),
    ]
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")

    events, findings = load_claude_code(f)
    assert len(findings) == 0
    assert len(events) == 2

    # Result 1: success
    assert events[0].id == "r1"
    assert events[0].kind == "tool_result"
    assert events[0].actor == "tool"
    assert events[0].correlation_id == "tu_read_1"
    assert events[0].execution_state == "success"
    assert events[0].side_effects == "none"
    assert events[0].payload["content"] == "127.0.0.1 localhost"
    assert events[0].payload["is_error"] is False

    # Result 2: failure
    assert events[1].id == "r2"
    assert events[1].kind == "tool_result"
    assert events[1].actor == "tool"
    assert events[1].correlation_id == "tu_write_2"
    assert events[1].execution_state == "failure"
    assert events[1].side_effects == "none"
    assert events[1].payload["content"] == "Permission denied: /tmp/out.txt"
    assert events[1].payload["is_error"] is True


def test_regression_content_blocks_multiple_tool_calls_and_preamble(tmp_path: Path) -> None:
    """Verify assistant message with preamble text and multiple tool_use forms parent chain."""
    f = tmp_path / "multi_tool_use_chain.jsonl"
    record = {
        "uuid": "turn_assistant_1",
        "parentUuid": "turn_user_0",
        "type": "assistant",
        "content": [
            {"type": "text", "text": "I will examine the workspace and list directory contents."},
            {
                "type": "tool_use",
                "id": "tu_first",
                "name": "read_file",
                "input": {"path": "README.md"},
            },
            {"type": "tool_use", "id": "tu_second", "name": "list_dir", "input": {"path": "."}},
        ],
    }
    f.write_text(json.dumps(record) + "\n", encoding="utf-8")

    events, findings = load_claude_code(f)
    assert len(findings) == 0
    assert len(events) == 3

    # 1. Preamble text event: turn_assistant_1_text, parent=turn_user_0
    assert events[0].id == "turn_assistant_1_text"
    assert events[0].kind == "message"
    assert events[0].parent_id == "turn_user_0"
    assert events[0].original_id is None
    assert (
        events[0].payload["content"] == "I will examine the workspace and list directory contents."
    )

    # 2. First tool call: tu_first, parent=turn_assistant_1_text
    assert events[1].id == "tu_first"
    assert events[1].kind == "tool_call"
    assert events[1].parent_id == "turn_assistant_1_text"
    assert events[1].correlation_id == "tu_first"
    assert events[1].original_id == "tu_first"
    assert events[1].payload["tool_name"] == "read_file"

    # 3. Second tool call: turn_assistant_1 (last tool call takes record ID), parent=tu_first
    assert events[2].id == "turn_assistant_1"
    assert events[2].kind == "tool_call"
    assert events[2].parent_id == "tu_first"
    assert events[2].correlation_id == "tu_second"
    assert events[2].original_id == "turn_assistant_1"
    assert events[2].payload["tool_name"] == "list_dir"


def test_regression_content_blocks_multiple_tool_results(tmp_path: Path) -> None:
    """Verify user message with multiple tool_result blocks generates individual events."""
    f = tmp_path / "multi_tool_result.jsonl"
    record = {
        "uuid": "turn_results",
        "parentUuid": "turn_assistant_1",
        "type": "user",
        "content": [
            {
                "type": "tool_result",
                "id": "tr_custom_1",
                "tool_use_id": "tu_first",
                "content": "File content",
            },
            {
                "type": "tool_result",
                "tool_use_id": "tu_second",
                "content": "dir listing",
                "is_error": False,
            },
        ],
    }
    f.write_text(json.dumps(record) + "\n", encoding="utf-8")

    events, findings = load_claude_code(f)
    assert len(findings) == 0
    assert len(events) == 2

    # First result carries block id tr_custom_1
    assert events[0].id == "tr_custom_1"
    assert events[0].kind == "tool_result"
    assert events[0].correlation_id == "tu_first"
    assert events[0].payload["content"] == "File content"

    # Second result carries turn_results_res_1
    assert events[1].id == "turn_results_res_1"
    assert events[1].kind == "tool_result"
    assert events[1].correlation_id == "tu_second"
    assert events[1].payload["content"] == "dir listing"


def test_regression_fallback_modes(tmp_path: Path) -> None:
    """Verify fallback mechanisms for records without type or with alternative type signatures."""
    f = tmp_path / "fallbacks.jsonl"
    lines = [
        # 1. No type, top-level role='user'
        json.dumps({"id": "m1", "role": "user", "content": "Hello from user"}),
        # 2. No type, message object with role='assistant'
        json.dumps(
            {"id": "m2", "parentId": "m1", "message": {"role": "assistant", "content": "Hi there"}}
        ),
        # 3. type='message' with role='user'
        json.dumps(
            {"id": "m3", "parentId": "m2", "type": "message", "role": "user", "text": "Question"}
        ),
        # 4. type='summary'
        json.dumps(
            {"id": "m4", "parentId": "m3", "type": "summary", "content": "Summary checkpoint"}
        ),
        # 5. type='compaction_boundary'
        json.dumps(
            {
                "id": "m5",
                "parentId": "m4",
                "type": "compaction_boundary",
                "summary": "Pruned 20 turns",
            }
        ),
    ]
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")

    events, findings = load_claude_code(f)
    assert len(findings) == 0
    assert len(events) == 5

    assert events[0].actor == "user" and events[0].kind == "message"
    assert events[1].actor == "assistant" and events[1].kind == "message"
    assert events[2].actor == "user" and events[2].kind == "message"
    assert events[3].actor == "system" and events[3].kind == "compaction_boundary"
    assert events[4].actor == "system" and events[4].kind == "compaction_boundary"


def test_regression_scope_metadata_and_sidechain(tmp_path: Path) -> None:
    """Verify agent_id, branch_id, sidechain flag, and interaction_id are captured."""
    f = tmp_path / "scope_metadata.jsonl"
    lines = [
        json.dumps(
            {
                "id": "m1",
                "type": "user_message",
                "message": "Start subagent branch",
                "agentId": "subagent-alpha",
                "branchId": "branch-feature",
                "interactionId": "interaction-99",
            }
        ),
        json.dumps(
            {
                "id": "m2",
                "parentId": "m1",
                "type": "assistant_message",
                "message": "In sidechain",
                "agent_id": "subagent-alpha",
                "isSidechain": True,
            }
        ),
    ]
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")

    events, findings = load_claude_code(f)
    assert len(findings) == 0
    assert len(events) == 2

    assert events[0].agent_id == "subagent-alpha"
    assert events[0].branch_id == "branch-feature"
    assert events[0].interaction_id == "interaction-99"

    assert events[1].agent_id == "subagent-alpha"
    assert events[1].branch_id == "sidechain"  # isSidechain -> "sidechain"


def test_regression_decorative_keys_ignored(tmp_path: Path) -> None:
    """Verify recognized decorative metadata fields are silently ignored without raising SL302."""
    f = tmp_path / "decorative_metadata.jsonl"
    record = {
        "id": "m1",
        "type": "assistant_message",
        "message": "Thinking completed",
        "thinking": "analyzing file structure...",
        "tokens": 450,
        "model": "claude-3-5-sonnet",
        "prompt_tokens": 300,
        "completion_tokens": 150,
        "cost": 0.0045,
        "costUSD": 0.0045,
        "durationMs": 1200,
        "duration_ms": 1200,
        "cwd": "/workspace/sesslint",
        "git_branch": "feature-branch",
        "slug": "sess-alpha",
        "leafUuid": "leaf-1234",
        "user": "developer",
    }
    f.write_text(json.dumps(record) + "\n", encoding="utf-8")

    events, findings = load_claude_code(f)
    assert len(findings) == 0
    assert len(events) == 1
    assert events[0].id == "m1"


def test_regression_synthetic_ids_and_original_id(tmp_path: Path) -> None:
    """Verify records missing id/uuid obtain deterministic synthetic IDs with original_id=None."""
    f = tmp_path / "missing_ids.jsonl"
    lines = [
        json.dumps({"type": "user_message", "message": "First event without ID"}),
        json.dumps({"type": "assistant_message", "message": "Second event without ID"}),
    ]
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")

    events, findings = load_claude_code(f)
    assert len(findings) == 0
    assert len(events) == 2

    assert events[0].id.startswith("sesslint:synthetic:claude_code:0:")
    assert events[0].original_id is None

    assert events[1].id.startswith("sesslint:synthetic:claude_code:1:")
    assert events[1].original_id is None


def test_regression_collision_guard_rejection(tmp_path: Path) -> None:
    """Verify collision guard rejects hostile input that squats on an active synthetic ID."""
    from sesslint.adapters.synthetic import synthetic_event_id
    from sesslint.errors import AdapterError

    f = tmp_path / "hostile_collision.jsonl"
    path_str = str(f).replace("\\", "/")

    line1_dict = {"type": "user_message", "message": "First event without ID"}
    line1_bytes = json.dumps(line1_dict).encode("utf-8") + b"\n"
    predicted_synth_id = synthetic_event_id(
        "claude_code",
        0,
        source_hint=path_str,
        payload_len=len(line1_bytes),
    )

    line2_dict = {
        "id": predicted_synth_id,
        "type": "assistant_message",
        "message": "Squatter colliding with line 1",
    }
    line2_bytes = json.dumps(line2_dict).encode("utf-8") + b"\n"
    f.write_bytes(line1_bytes + line2_bytes)

    with pytest.raises(AdapterError, match="Synthetic ID collision"):
        load_claude_code(f)


def test_regression_encoding_sl001_mid_and_sl002_tail(tmp_path: Path) -> None:
    """Verify invalid UTF-8 emits SL001 mid-file and SL002 at terminal EOF with byte coordinates."""
    # Mid-file invalid UTF-8 byte
    bad_mid = tmp_path / "bad_mid.jsonl"
    part1 = b'{"id":"m1","type":"user_message","message":"good 1"}\n'
    part2 = b'{"id":"m2",\xff,"type":"assistant_message"}\n'
    part3 = b'{"id":"m3","type":"user_message","message":"good 3"}\n'
    bad_mid.write_bytes(part1 + part2 + part3)

    events_mid, findings_mid = load_claude_code(bad_mid)
    assert len(events_mid) == 2
    sl001_f = [f for f in findings_mid if f.code == SL001]
    assert len(sl001_f) == 1
    assert "ENCODING" in sl001_f[0].message
    assert sl001_f[0].evidence is not None
    assert "byte_offset" in sl001_f[0].evidence
    assert "byte_end" in sl001_f[0].evidence

    # Terminal invalid UTF-8 byte
    bad_tail = tmp_path / "bad_tail.jsonl"
    bad_tail.write_bytes(part1 + part2.rstrip(b"\n"))

    events_tail, findings_tail = load_claude_code(bad_tail)
    assert len(events_tail) == 1
    sl002_f = [f for f in findings_tail if f.code == SL002]
    assert len(sl002_f) == 1
    assert "ENCODING" in sl002_f[0].message
    assert sl002_f[0].evidence is not None
    assert "byte_offset" in sl002_f[0].evidence


def test_regression_unsupported_version_single_finding(tmp_path: Path) -> None:
    """Verify obsolete version is reported once per session even if repeated on every record."""
    f = tmp_path / "multi_version_old.jsonl"
    lines = [
        json.dumps({"id": "m1", "type": "user_message", "version": "0.0.1", "message": "One"}),
        json.dumps(
            {
                "id": "m2",
                "parentId": "m1",
                "type": "assistant_message",
                "version": "0.0.1",
                "message": "Two",
            }
        ),
        json.dumps(
            {
                "id": "m3",
                "parentId": "m2",
                "type": "user_message",
                "version": "0.0.1",
                "message": "Three",
            }
        ),
    ]
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")

    events, findings = load_claude_code(f)
    assert len(events) == 3
    sl301_f = [f for f in findings if f.code == SL301]
    assert len(sl301_f) == 1  # Exactly 1 finding emitted for whole session
    assert sl301_f[0].source.line == 1


def test_regression_sl302_long_type_truncated(tmp_path: Path) -> None:
    """Verify long unknown type discriminator is capped to prevent unbounded echo (DEV-008)."""
    f = tmp_path / "long_unknown_type.jsonl"
    long_type = "unsupportedType" + "X" * 300
    record = {"id": "m1", "type": long_type, "message": "Test payload"}
    f.write_text(json.dumps(record) + "\n", encoding="utf-8")

    events, findings = load_claude_code(f)
    assert len(events) == 1
    assert events[0].kind == "unknown"

    sl302_f = [f for f in findings if f.code == SL302]
    assert len(sl302_f) == 1
    evidence = sl302_f[0].evidence
    assert evidence is not None
    assert evidence.get("type_truncated") is True
    assert len(str(evidence.get("type_value"))) <= 100
