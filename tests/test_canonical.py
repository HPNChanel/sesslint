"""Unit and edge-case tests for canonical session model and deterministic serialization."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any, cast

import pytest

from sesslint.canonical import (
    MAX_NON_STREAMING_BYTES,
    MAX_PAYLOAD_DEPTH,
    SCHEMA_VERSION,
    VALID_ACTORS,
    VALID_KINDS,
    Session,
    SessionEvent,
    SessionHeader,
    canonical_bytes,
    compute_content_hash,
    dump_session,
    dump_session_file,
    get_session_schema_path,
    load_session_file,
    load_session_schema,
    parse_session,
    parse_session_event,
    parse_session_header,
    parse_session_lines,
    to_canonical_json,
)
from sesslint.errors import SchemaError, UnknownFieldError


def create_sample_header(*, session_id: str = "sess_001") -> SessionHeader:
    """Helper to create a valid sample header."""
    return SessionHeader(
        schema_version=SCHEMA_VERSION,
        session_id=session_id,
        created_at="2026-09-05T12:00:00Z",
    )


def create_sample_event(
    *,
    event_id: str = "evt_001",
    parent_id: str | None = None,
    seq: int = 0,
    actor: str = "user",
    kind: str = "message",
    payload: dict[str, Any] | None = None,
) -> SessionEvent:
    """Helper to create a valid sample session event."""
    return SessionEvent(
        id=event_id,
        parent_id=parent_id,
        seq=seq,
        ts="2026-09-05T12:00:00Z",
        actor=actor,  # type: ignore[arg-type]
        kind=kind,  # type: ignore[arg-type]
        payload=payload if payload is not None else {"text": "hello"},
    )


def test_frozen_dataclasses() -> None:
    """Verify that Session, SessionHeader, and SessionEvent are strictly immutable."""
    header = create_sample_header()
    event = create_sample_event()
    session = Session(header=header, events=(event,))

    with pytest.raises(FrozenInstanceError):
        header.session_id = "mutated"  # type: ignore[misc]

    with pytest.raises(FrozenInstanceError):
        event.seq = 999  # type: ignore[misc]

    with pytest.raises(FrozenInstanceError):
        session.header = create_sample_header(session_id="mutated_session")  # type: ignore[misc]


def test_canonical_json_determinism() -> None:
    """Verify deterministic serialization ignoring dictionary key insertion order."""
    dict_a = {
        "z": 1,
        "a": 2,
        "m": {"nested_z": 10, "nested_a": 20},
    }
    dict_b = {
        "a": 2,
        "m": {"nested_a": 20, "nested_z": 10},
        "z": 1,
    }

    json_a = to_canonical_json(dict_a)
    json_b = to_canonical_json(dict_b)

    assert json_a == json_b
    assert json_a == '{"a":2,"m":{"nested_a":20,"nested_z":10},"z":1}'
    assert canonical_bytes(dict_a) == json_a.encode("utf-8")


def test_canonical_json_unicode_preservation() -> None:
    """Verify non-ASCII unicode characters are preserved directly rather than escaped."""
    obj = {"vietnamese": "Tiến hành kiểm tra", "emoji": "🔍🚀"}
    canonical = to_canonical_json(obj)
    assert "\\u" not in canonical
    assert "Tiến hành kiểm tra" in canonical
    assert "🔍🚀" in canonical


def test_event_round_trip() -> None:
    """Verify round-trip parse -> dump -> parse equality for events."""
    event = create_sample_event(
        event_id="evt_tool_1",
        parent_id="evt_user_1",
        seq=1,
        actor="assistant",
        kind="tool_call",
        payload={"query": "pytest"},
    )
    serialized = to_canonical_json(event)
    data = json.loads(serialized)
    parsed = parse_session_event(data)

    assert parsed == event
    assert to_canonical_json(parsed) == serialized


def test_session_round_trip() -> None:
    """Verify full session round-trip equality via lines and files."""
    header = create_sample_header()
    ev1 = create_sample_event(event_id="e1", seq=0, actor="user", kind="message")
    ev2 = create_sample_event(
        event_id="e2", parent_id="e1", seq=1, actor="assistant", kind="tool_call"
    )
    ev3 = create_sample_event(
        event_id="e3", parent_id="e2", seq=2, actor="tool", kind="tool_result"
    )
    session = Session(header=header, events=(ev1, ev2, ev3))

    dumped = dump_session(session)
    reloaded = parse_session_lines(dumped.splitlines())

    assert reloaded == session
    assert dump_session(reloaded) == dumped


def test_rfc3339_utc_rejection() -> None:
    """Verify non-RFC3339 or non-UTC timestamps are rejected."""
    bad_timestamps = [
        "not-a-date",
        "2026-09-05",
        "2026/09/05 12:00:00",
        "2026-09-05T12:00:00+07:00",  # Non-UTC timezone offset
        "2026-09-05T12:00:00-05:00",  # Non-UTC timezone offset
        "2026-09-05 12:00:00Z",  # Space instead of T
        "",
    ]
    for bad_ts in bad_timestamps:
        with pytest.raises(SchemaError, match="RFC3339 UTC timestamp"):
            parse_session_header(
                {
                    "schema_version": SCHEMA_VERSION,
                    "session_id": "s1",
                    "created_at": bad_ts,
                }
            )

        with pytest.raises(SchemaError, match="RFC3339 UTC timestamp"):
            parse_session_event(
                {
                    "id": "e1",
                    "parent_id": None,
                    "seq": 0,
                    "ts": bad_ts,
                    "actor": "user",
                    "kind": "message",
                    "payload": {},
                }
            )


def test_actor_and_kind_validation() -> None:
    """Verify actor and kind are strictly constrained to valid vocabularies."""
    valid_event_dict: dict[str, Any] = {
        "id": "e1",
        "parent_id": None,
        "seq": 0,
        "ts": "2026-09-05T12:00:00Z",
        "actor": "user",
        "kind": "message",
        "payload": {},
    }

    # Invalid actor
    bad_actor = dict(valid_event_dict, actor="bogus_actor")
    with pytest.raises(SchemaError, match="Invalid actor 'bogus_actor'"):
        parse_session_event(bad_actor)

    # Invalid kind
    bad_kind = dict(valid_event_dict, kind="bogus_kind")
    with pytest.raises(SchemaError, match="Invalid kind 'bogus_kind'"):
        parse_session_event(bad_kind)

    # Verify all valid actors and kinds are accepted
    for actor in VALID_ACTORS:
        evt = parse_session_event(dict(valid_event_dict, actor=actor))
        assert evt.actor == actor

    for kind in VALID_KINDS:
        evt = parse_session_event(dict(valid_event_dict, kind=kind))
        assert evt.kind == kind


def test_seq_type_validation() -> None:
    """Verify seq must be a non-negative integer and cannot be boolean or negative."""
    valid_dict: dict[str, Any] = {
        "id": "e1",
        "parent_id": None,
        "seq": 0,
        "ts": "2026-09-05T12:00:00Z",
        "actor": "user",
        "kind": "message",
        "payload": {},
    }

    with pytest.raises(SchemaError, match="Field 'seq' must be a non-negative integer"):
        parse_session_event(dict(valid_dict, seq=-1))

    with pytest.raises(SchemaError, match="Field 'seq' must be a non-negative integer"):
        parse_session_event(dict(valid_dict, seq=True))

    with pytest.raises(SchemaError, match="Field 'seq' must be a non-negative integer"):
        parse_session_event(dict(valid_dict, seq=cast(Any, "0")))


def test_parent_id_self_reference_rejected() -> None:
    """Verify self-referencing parent_id is rejected."""
    event_dict = {
        "id": "evt_self",
        "parent_id": "evt_self",
        "seq": 0,
        "ts": "2026-09-05T12:00:00Z",
        "actor": "user",
        "kind": "message",
        "payload": {},
    }
    with pytest.raises(SchemaError, match="self-referencing parent_id"):
        parse_session_event(event_dict)


def test_missing_parent_allowed_in_canonical_parser() -> None:
    """Verify missing parent (parent_id pointing to non-existent ID) is allowed at schema level."""
    event_dict = {
        "id": "evt_orphan",
        "parent_id": "evt_does_not_exist",
        "seq": 0,
        "ts": "2026-09-05T12:00:00Z",
        "actor": "user",
        "kind": "message",
        "payload": {},
    }
    event = parse_session_event(event_dict)
    assert event.parent_id == "evt_does_not_exist"


def test_duplicate_event_id_rejected() -> None:
    """Verify duplicate event IDs in a session raise SchemaError."""
    lines = [
        to_canonical_json(create_sample_header()),
        to_canonical_json(create_sample_event(event_id="duplicate_id", seq=0)),
        to_canonical_json(create_sample_event(event_id="duplicate_id", seq=1)),
    ]
    with pytest.raises(SchemaError, match="Duplicate event ID detected: 'duplicate_id'"):
        parse_session_lines(lines)


def test_experimental_fields_allowed_and_roundtripped() -> None:
    """Verify fields starting with experimental_ are permitted and preserved."""
    event_dict: dict[str, Any] = {
        "id": "evt_exp",
        "parent_id": None,
        "seq": 0,
        "ts": "2026-09-05T12:00:00Z",
        "actor": "user",
        "kind": "message",
        "payload": {},
        "experimental_custom_trace": "xyz-123",
    }
    event = parse_session_event(event_dict)
    assert event.extra_fields.get("experimental_custom_trace") == "xyz-123"

    dumped = to_canonical_json(event)
    assert '"experimental_custom_trace":"xyz-123"' in dumped

    reparsed = parse_session_event(json.loads(dumped))
    assert reparsed == event


def test_empty_events_session_allowed() -> None:
    """Verify degenerate session with only header and zero events parses cleanly."""
    header = create_sample_header()
    session = Session(header=header, events=())
    dumped = dump_session(session)

    reloaded = parse_session_lines(dumped.splitlines())
    assert reloaded == session
    assert len(reloaded.events) == 0


def test_bom_crlf_and_trailing_whitespace(tmp_path: Path) -> None:
    """Verify UTF-8 BOM, CRLF line endings, and trailing whitespace are normalized."""
    file_path = tmp_path / "crlf_bom_session.jsonl"
    bom = "\ufeff"
    header_line = to_canonical_json(create_sample_header())
    event_line = to_canonical_json(create_sample_event())
    content = f"{bom}{header_line}\r\n{event_line}  \r\n\r\n"

    file_path.write_bytes(content.encode("utf-8"))

    session = load_session_file(file_path)
    assert session.header.session_id == "sess_001"
    assert len(session.events) == 1


def test_deeply_nested_payload_rejection() -> None:
    """Verify payloads exceeding max depth cap raise SchemaError without crashing."""
    nested: dict[str, Any] = {"leaf": True}
    for _ in range(MAX_PAYLOAD_DEPTH + 10):
        nested = {"child": nested}

    event_dict = {
        "id": "e_deep",
        "parent_id": None,
        "seq": 0,
        "ts": "2026-09-05T12:00:00Z",
        "actor": "user",
        "kind": "message",
        "payload": nested,
    }

    with pytest.raises(SchemaError, match="Payload nesting depth"):
        parse_session_event(event_dict)


def test_size_limit_rejection(tmp_path: Path) -> None:
    """Verify files larger than 100MB are rejected directing to streaming reader."""
    oversized_file = tmp_path / "oversized.jsonl"
    # Create a sparse file or truncated file with size > 100MB
    target_size = MAX_NON_STREAMING_BYTES + 1024
    with open(oversized_file, "wb") as f:
        f.seek(target_size - 1)
        f.write(b"\n")

    with pytest.raises(SchemaError, match="exceeds maximum non-streaming limit"):
        load_session_file(oversized_file)


def test_adversarial_keys_handled_safely() -> None:
    """Verify keys like __proto__ and constructor do not pollute object prototype or dictionary."""
    event_dict = {
        "id": "evt_proto",
        "parent_id": None,
        "seq": 0,
        "ts": "2026-09-05T12:00:00Z",
        "actor": "user",
        "kind": "message",
        "payload": {"__proto__": {"injected": "dangerous"}, "constructor": "Object"},
    }
    event = parse_session_event(event_dict)
    assert event.payload["__proto__"] == {"injected": "dangerous"}
    assert event.payload["constructor"] == "Object"


def test_file_persistence_helper(tmp_path: Path) -> None:
    """Verify dump_session_file writes valid canonical bytes loadable by load_session_file."""
    session = Session(
        header=create_sample_header(),
        events=(create_sample_event(event_id="evt_save"),),
    )
    dest_path = tmp_path / "saved_session.jsonl"
    dump_session_file(session, dest_path)

    loaded = load_session_file(dest_path)
    assert loaded == session


def test_parse_session_framed_and_flat() -> None:
    """Verify parse_session supports both framed and flat dictionary formats."""
    flat_dict = {
        "schema_version": SCHEMA_VERSION,
        "session_id": "sess_flat",
        "created_at": "2026-09-05T12:00:00Z",
        "events": [
            {
                "id": "e1",
                "parent_id": None,
                "seq": 0,
                "ts": "2026-09-05T12:00:00Z",
                "actor": "user",
                "kind": "message",
                "payload": {},
            }
        ],
    }
    s_flat = parse_session(flat_dict)
    assert s_flat.header.session_id == "sess_flat"
    assert len(s_flat.events) == 1

    framed_dict = {
        "header": {
            "schema_version": SCHEMA_VERSION,
            "session_id": "sess_framed",
            "created_at": "2026-09-05T12:00:00Z",
        },
        "events": [
            {
                "id": "e1",
                "parent_id": None,
                "seq": 0,
                "ts": "2026-09-05T12:00:00Z",
                "actor": "user",
                "kind": "message",
                "payload": {},
            }
        ],
    }
    s_framed = parse_session(framed_dict)
    assert s_framed.header.session_id == "sess_framed"
    assert len(s_framed.events) == 1


def test_header_validation_errors() -> None:
    """Verify detailed validation errors for session header."""
    with pytest.raises(SchemaError, match="must be a mapping"):
        parse_session_header("not_a_mapping")  # type: ignore[arg-type]

    with pytest.raises(SchemaError, match="Missing required field 'schema_version'"):
        parse_session_header({"session_id": "s1", "created_at": "2026-09-05T12:00:00Z"})

    with pytest.raises(SchemaError, match="must be a string"):
        parse_session_header(
            {"schema_version": 123, "session_id": "s1", "created_at": "2026-09-05T12:00:00Z"}
        )

    with pytest.raises(SchemaError, match="Missing required header field 'created_at'"):
        parse_session_header({"schema_version": SCHEMA_VERSION, "session_id": "s1"})

    with pytest.raises(SchemaError, match="Field 'session_id' must be a non-empty string"):
        parse_session_header(
            {
                "schema_version": SCHEMA_VERSION,
                "session_id": "   ",
                "created_at": "2026-09-05T12:00:00Z",
            }
        )

    with pytest.raises(SchemaError, match="Field 'title' must be a string or None"):
        parse_session_header(
            {
                "schema_version": SCHEMA_VERSION,
                "session_id": "s1",
                "created_at": "2026-09-05T12:00:00Z",
                "title": 123,
            }
        )

    with pytest.raises(SchemaError, match="Field 'metadata' must be a mapping"):
        parse_session_header(
            {
                "schema_version": SCHEMA_VERSION,
                "session_id": "s1",
                "created_at": "2026-09-05T12:00:00Z",
                "metadata": "not_a_map",
            }
        )


def test_event_optional_fields_type_checks() -> None:
    """Verify validation for optional fields on canonical events."""
    base: dict[str, Any] = {
        "id": "e1",
        "parent_id": None,
        "seq": 0,
        "ts": "2026-09-05T12:00:00Z",
        "actor": "user",
        "kind": "message",
        "payload": {},
    }

    # All valid optional fields populated
    full = dict(
        base,
        content_hash="sha256:abc",
        correlation_id="call_123",
        branch_id="main",
        interaction_id="turn_1",
        agent_id="agent_alpha",
        execution_state="success",
        source_line=42,
        source_record_hash="sha256:def",
        original_id="raw_99",
    )
    ev = parse_session_event(full)
    assert ev.content_hash == "sha256:abc"
    assert ev.correlation_id == "call_123"
    assert ev.source_line == 42
    assert ev.execution_state == "success"

    # Type error cases
    with pytest.raises(SchemaError, match="Field 'content_hash' must be a string"):
        parse_session_event(dict(base, content_hash=123))

    with pytest.raises(SchemaError, match="Field 'correlation_id' must be a string"):
        parse_session_event(dict(base, correlation_id=123))

    with pytest.raises(SchemaError, match="Field 'branch_id' must be a string"):
        parse_session_event(dict(base, branch_id=123))

    with pytest.raises(SchemaError, match="Field 'interaction_id' must be a string"):
        parse_session_event(dict(base, interaction_id=123))

    with pytest.raises(SchemaError, match="Field 'agent_id' must be a string"):
        parse_session_event(dict(base, agent_id=123))

    with pytest.raises(SchemaError, match="Invalid execution_state 'invalid_state'"):
        parse_session_event(dict(base, execution_state="invalid_state"))

    with pytest.raises(SchemaError, match="Field 'source_line' must be a positive integer"):
        parse_session_event(dict(base, source_line=0))

    with pytest.raises(SchemaError, match="Field 'source_record_hash' must be a string"):
        parse_session_event(dict(base, source_record_hash=123))

    with pytest.raises(SchemaError, match="Field 'original_id' must be a string"):
        parse_session_event(dict(base, original_id=123))


def test_to_canonical_json_type_error() -> None:
    """Verify to_canonical_json raises TypeError on non-serializable objects."""
    with pytest.raises(TypeError, match="is not JSON serializable"):
        to_canonical_json({"func": lambda x: x})


def test_load_session_file_edge_cases(tmp_path: Path) -> None:
    """Verify load_session_file errors for missing file, empty file, and invalid UTF-8."""
    missing = tmp_path / "does_not_exist.jsonl"
    with pytest.raises(FileNotFoundError):
        load_session_file(missing)

    empty_f = tmp_path / "empty.jsonl"
    empty_f.write_text("   \n\n", encoding="utf-8")
    with pytest.raises(SchemaError, match="Session file is empty"):
        load_session_file(empty_f)

    bad_encoding = tmp_path / "bad_encoding.jsonl"
    bad_encoding.write_bytes(b"\x80\x81\x82")
    with pytest.raises(SchemaError, match="not valid UTF-8"):
        load_session_file(bad_encoding)


def test_load_session_file_single_json_document(tmp_path: Path) -> None:
    """Verify load_session_file correctly handles a single full JSON object file."""
    doc = {
        "schema_version": SCHEMA_VERSION,
        "session_id": "sess_doc",
        "created_at": "2026-09-05T12:00:00Z",
        "events": [
            {
                "id": "e1",
                "parent_id": None,
                "seq": 0,
                "ts": "2026-09-05T12:00:00Z",
                "actor": "user",
                "kind": "message",
                "payload": {"text": "hi"},
            }
        ],
    }
    json_path = tmp_path / "session.json"
    json_path.write_text(json.dumps(doc), encoding="utf-8")

    session = load_session_file(json_path)
    assert session.header.session_id == "sess_doc"
    assert len(session.events) == 1


def test_parse_session_lines_malformed_json() -> None:
    """Verify parse_session_lines raises SchemaError on malformed JSON lines."""
    with pytest.raises(SchemaError, match="Malformed JSON on header line"):
        parse_session_lines(["{broken_header"])

    valid_header = to_canonical_json(create_sample_header())
    with pytest.raises(SchemaError, match="Malformed JSON on event line 2"):
        parse_session_lines([valid_header, "{broken_event"])


def test_compute_content_hash_deterministic() -> None:
    """Verify compute_content_hash produces deterministic sha256 across key orders."""
    payload_a = {"z": 10, "a": 20, "nested": {"k": "v"}}
    payload_b = {"a": 20, "nested": {"k": "v"}, "z": 10}
    hash_a = compute_content_hash(payload_a)
    hash_b = compute_content_hash(payload_b)

    assert hash_a.startswith("sha256:")
    assert len(hash_a) == 7 + 64
    assert hash_a == hash_b


def test_calendar_date_validation() -> None:
    """Verify invalid calendar dates (Feb 30, Feb 31, Apr 31) are rejected."""
    invalid_dates = [
        "2026-02-30T12:00:00Z",
        "2026-02-31T12:00:00Z",
        "2026-04-31T12:00:00Z",
        "2026-02-29T12:00:00Z",  # 2026 is not a leap year
    ]
    for bad_date in invalid_dates:
        with pytest.raises(SchemaError, match="invalid calendar date/time"):
            parse_session_header(
                {
                    "schema_version": SCHEMA_VERSION,
                    "session_id": "s_bad_date",
                    "created_at": bad_date,
                }
            )


def test_canonical_json_nan_inf_rejected() -> None:
    """Verify NaN and Infinity floats are strictly rejected per RFC 8785."""
    with pytest.raises(SchemaError, match="Float value"):
        to_canonical_json({"nan": float("nan")})

    with pytest.raises(SchemaError, match="Float value"):
        to_canonical_json({"inf": float("inf")})

    with pytest.raises(SchemaError, match="Float value"):
        to_canonical_json({"neginf": float("-inf")})


def test_cycle_detection_in_payload_and_canonical_json() -> None:
    """Verify in-memory cyclic structures are caught immediately without recursion overflow."""
    cyclic_dict: dict[str, Any] = {"foo": "bar"}
    cyclic_dict["self"] = cyclic_dict

    with pytest.raises(SchemaError, match="Cyclic reference detected"):
        parse_session_event(
            {
                "id": "e_cyclic",
                "parent_id": None,
                "seq": 0,
                "ts": "2026-09-05T12:00:00Z",
                "actor": "user",
                "kind": "message",
                "payload": cyclic_dict,
            }
        )

    with pytest.raises(SchemaError, match="Cyclic reference detected"):
        to_canonical_json(cyclic_dict)

    cyclic_list: list[Any] = [1, 2]
    cyclic_list.append(cyclic_list)
    with pytest.raises(SchemaError, match="Cyclic reference detected"):
        to_canonical_json({"arr": cyclic_list})


def test_provenance_and_source_fields_roundtrip() -> None:
    """Verify source_adapter, source_location, source, and version fields parse and round-trip."""
    header = SessionHeader(
        schema_version=SCHEMA_VERSION,
        session_id="sess_prov",
        created_at="2026-09-05T12:00:00Z",
        source={"adapter": "claude_jsonl", "version": "1.0"},
        version=1,
    )
    event = SessionEvent(
        id="evt_prov_1",
        parent_id=None,
        seq=0,
        ts="2026-09-05T12:00:00Z",
        actor="user",
        kind="message",
        payload={"text": "hello"},
        source_adapter="claude_jsonl",
        source_location="line:1,offset:0",
    )
    session = Session(header=header, events=(event,))

    dumped = dump_session(session)
    reloaded = parse_session_lines(dumped.splitlines())

    assert reloaded.header.source == {"adapter": "claude_jsonl", "version": "1.0"}
    assert reloaded.header.version == 1
    assert reloaded.events[0].source_adapter == "claude_jsonl"
    assert reloaded.events[0].source_location == "line:1,offset:0"
    assert reloaded == session


def test_framed_session_unknown_field_rejected() -> None:
    """Verify framed session dictionary rejects unknown top-level fields."""
    framed_bad = {
        "header": {
            "schema_version": SCHEMA_VERSION,
            "session_id": "s_framed_bad",
            "created_at": "2026-09-05T12:00:00Z",
        },
        "events": [],
        "evil": 666,
    }
    with pytest.raises(UnknownFieldError, match="Unknown top-level field in session: 'evil'"):
        parse_session(framed_bad)

    # But experimental_* fields are permitted
    framed_exp = {
        "header": {
            "schema_version": SCHEMA_VERSION,
            "session_id": "s_framed_exp",
            "created_at": "2026-09-05T12:00:00Z",
        },
        "events": [],
        "experimental_batch": "batch_999",
    }
    session = parse_session(framed_exp)
    assert session.extra_fields.get("experimental_batch") == "batch_999"


def test_parse_session_missing_events_field_rejected() -> None:
    """Verify session dictionary without required 'events' key raises SchemaError."""
    bad_doc = {
        "schema_version": SCHEMA_VERSION,
        "session_id": "sess_no_events",
        "created_at": "2026-09-05T12:00:00Z",
    }
    with pytest.raises(SchemaError, match="Missing required field 'events' in session"):
        parse_session(bad_doc)


def test_parse_session_lines_line_number_accuracy() -> None:
    """Verify line numbers in errors accurately reflect 1-indexed lines even with blanks."""
    lines = [
        "",  # Line 1: blank
        to_canonical_json(create_sample_header()),  # Line 2: header
        "",  # Line 3: blank
        "{bad_event_json",  # Line 4: broken JSON
    ]
    with pytest.raises(SchemaError, match="Malformed JSON on event line 4"):
        parse_session_lines(lines)


def test_schema_loader_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify get_session_schema_path and load_session_schema return valid schema dict."""
    path = get_session_schema_path()
    assert path.is_file()
    assert path.name == "sesslint.session.v1.json"

    schema = load_session_schema()
    assert schema.get("$id") == "https://sesslint.dev/schemas/sesslint.session/v1"
    assert "$defs" in schema

    # Test FileNotFoundError when schema file is missing
    monkeypatch.setattr(
        "sesslint.canonical.get_session_schema_path",
        lambda: Path("/non/existent/schema.json"),
    )
    with pytest.raises(FileNotFoundError, match="Canonical session schema not found"):
        load_session_schema()


def test_canonical_json_valid_float() -> None:
    """Verify valid non-nan non-inf float serializes properly."""
    res = to_canonical_json({"ratio": 3.14})
    assert res == '{"ratio":3.14}'


def test_session_header_experimental_fields_and_validations() -> None:
    """Verify experimental fields in header and validation of source and version."""
    header = parse_session_header(
        {
            "schema_version": SCHEMA_VERSION,
            "session_id": "s_exp_header",
            "created_at": "2026-09-05T12:00:00Z",
            "experimental_flag": True,
            "source": "manual_test",
            "version": 1,
        }
    )
    assert header.extra_fields.get("experimental_flag") is True
    assert header.source == "manual_test"
    assert header.version == 1

    # Invalid source type
    with pytest.raises(SchemaError, match="Field 'source' must be a mapping or string"):
        parse_session_header(
            {
                "schema_version": SCHEMA_VERSION,
                "session_id": "s1",
                "created_at": "2026-09-05T12:00:00Z",
                "source": 12345,
            }
        )

    # Invalid version type
    with pytest.raises(SchemaError, match="Field 'version' must be an integer"):
        parse_session_header(
            {
                "schema_version": SCHEMA_VERSION,
                "session_id": "s1",
                "created_at": "2026-09-05T12:00:00Z",
                "version": True,  # boolean not allowed as integer
            }
        )
    with pytest.raises(SchemaError, match="Field 'version' must be an integer"):
        parse_session_header(
            {
                "schema_version": SCHEMA_VERSION,
                "session_id": "s1",
                "created_at": "2026-09-05T12:00:00Z",
                "version": "1",
            }
        )


def test_session_event_source_adapter_and_location_validation() -> None:
    """Verify source_adapter and source_location type validation."""
    base: dict[str, Any] = {
        "id": "e1",
        "parent_id": None,
        "seq": 0,
        "ts": "2026-09-05T12:00:00Z",
        "actor": "user",
        "kind": "message",
        "payload": {},
    }
    with pytest.raises(SchemaError, match="Field 'source_adapter' must be a string"):
        parse_session_event(dict(base, source_adapter=123))

    with pytest.raises(SchemaError, match="Field 'source_location' must be a string"):
        parse_session_event(dict(base, source_location=123))


def test_parse_session_type_validations() -> None:
    """Verify parse_session handles non-mapping obj, non-list events, non-map framed header."""
    with pytest.raises(SchemaError, match="Session object must be a mapping"):
        parse_session("not_a_mapping")  # type: ignore[arg-type]

    with pytest.raises(SchemaError, match="Field 'events' must be a list or tuple"):
        parse_session(
            {
                "schema_version": SCHEMA_VERSION,
                "session_id": "s1",
                "created_at": "2026-09-05T12:00:00Z",
                "events": "not_a_list",
            }
        )

    with pytest.raises(SchemaError, match="Field 'header' must be a mapping"):
        parse_session({"header": "not_a_header", "events": []})


def test_parse_session_lines_all_blank() -> None:
    """Verify parse_session_lines on stream with only whitespace/empty lines raises SchemaError."""
    with pytest.raises(SchemaError, match="Session stream contains no records"):
        parse_session_lines(["  ", "\n", "\t  \r\n"])
