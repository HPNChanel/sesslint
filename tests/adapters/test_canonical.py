"""Unit, conformance, round-trip, and golden tests for Canonical Session Format v1 (TASK-010).

Validates:
- dump_canonical byte-determinism and golden snapshot matching.
- Exact round-trip (load(dump(x)) == x and dump(load(b)) == b) for minimal, empty, and checkpoints.
- Detection heuristics (detect_canonical) on canonical, partial, and negative samples.
- Unsupported version handling (SL301 error/unsupported) with best-effort event recovery.
- Unknown critical fields routing to SL302, with decorative unknown fields silently permitted.
- Malformed inputs, missing keys, and schema violations producing SL001 without exception escape.
- Adversarial edge cases: trailing garbage, type confusion, duplicate IDs, non-UTF-8, limits.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sesslint.adapters.canonical import (
    detect_canonical,
    dump_canonical,
    load_canonical,
    load_canonical_session,
)
from sesslint.codes import SL001, SL301, SL302, Repairability, Severity
from sesslint.errors import MaxRecordsExceededError
from sesslint.io import ReaderLimits

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "canonical"
SNAPSHOTS_DIR = Path(__file__).resolve().parent / "snapshots"


def test_write_minimal_golden() -> None:
    """Dump 2-event chain and verify byte-identical match to committed snapshot."""
    minimal_path = FIXTURES_DIR / "minimal.json"
    assert minimal_path.is_file(), f"Fixture missing: {minimal_path}"

    events, findings = load_canonical(minimal_path)
    assert len(findings) == 0
    assert len(events) == 2

    dumped_bytes = dump_canonical(events, source=events.source)
    snapshot_path = SNAPSHOTS_DIR / "canonical_minimal.json"
    assert snapshot_path.is_file(), f"Snapshot missing: {snapshot_path}"

    expected_bytes = snapshot_path.read_bytes()
    assert dumped_bytes == expected_bytes, (
        f"Dumped bytes mismatch:\nActual: {dumped_bytes!r}\nExpected: {expected_bytes!r}"
    )


def test_round_trip_minimal() -> None:
    """Verify load(dump(x)) == x and dump(load(bytes)) == bytes for minimal fixture."""
    minimal_path = FIXTURES_DIR / "minimal.json"
    events1, findings1 = load_canonical(minimal_path)
    assert len(findings1) == 0
    assert len(events1) == 2

    # dump(events) -> bytes
    dumped1 = dump_canonical(events1, source=events1.source)

    # load(dumped) -> events
    events2, findings2 = load_canonical(dumped1)
    assert len(findings2) == 0
    assert len(events2) == 2

    # Events equality
    assert events1 == events2

    # dump(events2) -> bytes matches dumped1
    dumped2 = dump_canonical(events2, source=events2.source)
    assert dumped1 == dumped2


def test_round_trip_empty() -> None:
    """Verify round-trip for legal empty fixture (0 events, legal headers)."""
    empty_path = FIXTURES_DIR / "empty.json"
    events1, findings1 = load_canonical(empty_path)
    assert len(findings1) == 0
    assert len(events1) == 0

    dumped1 = dump_canonical(events1, source=events1.source)
    events2, findings2 = load_canonical(dumped1)
    assert len(findings2) == 0
    assert len(events2) == 0

    dumped2 = dump_canonical(events2, source=events2.source)
    assert dumped1 == dumped2


def test_round_trip_checkpoint() -> None:
    """Verify round-trip preserves checkpoint entries in source metadata."""
    chk_path = FIXTURES_DIR / "with_checkpoint.json"
    events1, findings1 = load_canonical(chk_path)
    assert len(findings1) == 0
    assert len(events1) == 2

    # Check that source checkpoints are loaded
    assert hasattr(events1, "source")
    assert "checkpoints" in events1.source
    checkpoints = events1.source["checkpoints"]
    assert len(checkpoints) == 1
    assert checkpoints[0]["id"] == "chk_001"
    assert checkpoints[0]["seq"] == 1

    # Dump and reload
    dumped1 = dump_canonical(events1, source=events1.source)
    events2, findings2 = load_canonical(dumped1)
    assert len(findings2) == 0
    assert len(events2) == 2
    assert events2.source["checkpoints"] == checkpoints

    dumped2 = dump_canonical(events2, source=events2.source)
    assert dumped1 == dumped2


def test_version_999_SL301() -> None:
    """Verify version:999 fixture produces SL301 finding, with events still parsed best-effort."""
    v999_path = FIXTURES_DIR / "v999.json"
    events, findings = load_canonical(v999_path)

    # Invariants: 1 event recovered, exactly 1 finding
    assert len(events) == 1
    assert events[0].id == "evt_001"
    assert len(findings) == 1

    sl301 = findings[0]
    assert sl301.code == SL301
    assert sl301.severity == Severity.ERROR
    assert sl301.repairability == Repairability.UNSUPPORTED
    assert sl301.evidence.get("version_raw") == "999"
    assert "1" in sl301.evidence.get("supported_set", ())


def test_unknown_critical_SL302() -> None:
    """Verify unknown critical top-level and item keys produce SL302 findings."""
    unk_path = FIXTURES_DIR / "unknown_critical.json"
    events, findings = load_canonical(unk_path)

    assert len(events) == 1
    assert len(findings) >= 1

    sl302_codes = [f for f in findings if f.code == SL302]
    assert len(sl302_codes) >= 1
    for f in sl302_codes:
        assert f.severity == Severity.ERROR
        assert f.repairability == Repairability.MANUAL
        assert f.evidence.get("field_path") in (
            "unknown_critical",
            "unknown_critical_field",
        )


def test_decorative_unknown_key_no_finding() -> None:
    """Verify decorative / non-critical unknown fields are permitted without findings."""
    doc = {
        "schema": "sesslint.session/v1",
        "version": 1,
        "source": {"format": "canonical"},
        "decorative_doc_note": "harmless annotation",
        "events": [
            {
                "actor": "user",
                "id": "evt_001",
                "kind": "message",
                "parent_id": None,
                "payload": {"text": "hello"},
                "seq": 0,
                "ts": "2026-09-05T12:00:00Z",
                "decorative_color": "blue",
            }
        ],
    }
    raw_bytes = json.dumps(doc).encode("utf-8")
    events, findings = load_canonical(raw_bytes)

    assert len(findings) == 0
    assert len(events) == 1
    assert events[0].extra_fields.get("decorative_color") == "blue"


def test_bad_schema_SL001() -> None:
    """Verify wrong schema string produces SL001 finding, not SL301, and does not raise."""
    doc = {
        "schema": "wrong.schema/v1",
        "version": 1,
        "source": {"format": "canonical"},
        "events": [],
    }
    raw_bytes = json.dumps(doc).encode("utf-8")
    events, findings = load_canonical(raw_bytes)

    assert len(events) == 0
    assert len(findings) == 1
    assert findings[0].code == SL001
    assert findings[0].severity == Severity.ERROR
    assert findings[0].evidence.get("reason") == "invalid_schema"
    assert findings[0].evidence.get("schema") == "wrong.schema/v1"


def test_missing_required_top_level_keys_SL001() -> None:
    """Verify missing schema, version, or events top-level keys produce SL001 findings."""
    # Missing schema
    doc_no_schema = {"version": 1, "events": []}
    events, findings = load_canonical(json.dumps(doc_no_schema).encode("utf-8"))
    assert len(events) == 0
    assert any(f.code == SL001 and f.evidence.get("field") == "schema" for f in findings)

    # Missing version
    doc_no_ver = {"schema": "sesslint.session/v1", "events": []}
    events, findings = load_canonical(json.dumps(doc_no_ver).encode("utf-8"))
    assert len(events) == 0
    assert any(f.code == SL001 and f.evidence.get("field") == "version" for f in findings)

    # Missing events
    doc_no_events = {"schema": "sesslint.session/v1", "version": 1}
    events, findings = load_canonical(json.dumps(doc_no_events).encode("utf-8"))
    assert len(events) == 0
    assert any(f.code == SL001 and f.evidence.get("field") == "events" for f in findings)


def test_detect_confidences() -> None:
    """Verify detect_canonical returns 1.0 for canonical, 0.6 for substring, 0.0 for empty."""
    # Empty
    assert detect_canonical(b"", "session.json") == 0.0

    # Canonical exact header match
    canonical_sample = b'{"schema":"sesslint.session/v1","version":1}'
    assert detect_canonical(canonical_sample, "session.json") == 1.0

    # Canonical schema_version match
    schema_ver_sample = b'{"schema_version": "sesslint.session/v1", "events": []}'
    assert detect_canonical(schema_ver_sample, "session.json") == 1.0

    # Partial substring match (different schema version)
    partial_sample = b'{"schema": "sesslint.session/v2", "version": 2}'
    assert detect_canonical(partial_sample, "session.json") == 0.6

    # Unrelated JSON
    unrelated_sample = b'{"items": [{"id": "1", "role": "user"}]}'
    assert detect_canonical(unrelated_sample, "session.json") == 0.0


def test_empty_legal() -> None:
    """Verify empty fixture loads with 0 events and 0 findings."""
    empty_path = FIXTURES_DIR / "empty.json"
    events, findings = load_canonical(empty_path)
    assert len(events) == 0
    assert len(findings) == 0


def test_trailing_garbage_SL001() -> None:
    """Verify trailing garbage after canonical JSON (}{) produces SL001 finding."""
    corrupt_bytes = (
        b'{"schema":"sesslint.session/v1","version":1,"events":[]}{"trailing":"garbage"}'
    )
    events, findings = load_canonical(corrupt_bytes)
    assert len(events) == 0
    assert len(findings) == 1
    assert findings[0].code == SL001
    assert findings[0].evidence.get("reason") == "malformed_json"


def test_events_type_confusion_SL001() -> None:
    """Verify events: null or events: {} produces SL001 finding without exception."""
    doc_null = {"schema": "sesslint.session/v1", "version": 1, "events": None}
    events, findings = load_canonical(json.dumps(doc_null).encode("utf-8"))
    assert len(events) == 0
    assert len(findings) == 1
    assert findings[0].code == SL001
    assert findings[0].evidence.get("reason") == "invalid_events_type"

    doc_dict = {"schema": "sesslint.session/v1", "version": 1, "events": {"not": "a list"}}
    events, findings = load_canonical(json.dumps(doc_dict).encode("utf-8"))
    assert len(events) == 0
    assert len(findings) == 1
    assert findings[0].code == SL001
    assert findings[0].evidence.get("reason") == "invalid_events_type"


def test_duplicate_ids_preserved() -> None:
    """Verify duplicate event IDs are preserved verbatim (detector SL003 judges later)."""
    doc = {
        "schema": "sesslint.session/v1",
        "version": 1,
        "source": {"format": "canonical"},
        "events": [
            {
                "actor": "user",
                "id": "dup_001",
                "kind": "message",
                "parent_id": None,
                "payload": {"text": "first"},
                "seq": 0,
                "ts": "2026-09-05T12:00:00Z",
            },
            {
                "actor": "assistant",
                "id": "dup_001",
                "kind": "message",
                "parent_id": "dup_001",
                "payload": {"text": "second"},
                "seq": 1,
                "ts": "2026-09-05T12:00:01Z",
            },
        ],
    }
    events, findings = load_canonical(json.dumps(doc).encode("utf-8"))
    assert len(findings) == 0
    assert len(events) == 2
    assert events[0].id == "dup_001"
    assert events[1].id == "dup_001"


def test_non_utf8_bytes_SL001() -> None:
    """Verify non-UTF-8 bytes produce SL001 decode finding without traceback."""
    bad_bytes = b"\xff\xfe\x00\x00 invalid utf-8"
    events, findings = load_canonical(bad_bytes)
    assert len(events) == 0
    assert len(findings) == 1
    assert findings[0].code == SL001
    assert findings[0].evidence.get("reason") in ("invalid_utf8", "forbidden_nul_byte")


def test_nul_bytes_SL001() -> None:
    """Verify forbidden NUL bytes produce SL001 finding."""
    nul_bytes = b'{"schema":"sesslint.session/v1",\x00"version":1,"events":[]}'
    events, findings = load_canonical(nul_bytes)
    assert len(events) == 0
    assert len(findings) == 1
    assert findings[0].code == SL001
    assert findings[0].evidence.get("reason") == "forbidden_nul_byte"


def test_empty_file_refused() -> None:
    """Verify 0-byte input produces SL001 finding."""
    events, findings = load_canonical(b"")
    assert len(events) == 0
    assert len(findings) == 1
    assert findings[0].code == SL001
    assert findings[0].evidence.get("reason") == "empty_input"


def test_max_file_bytes_limit(tmp_path: Path) -> None:
    """Verify file exceeding max_file_bytes produces SL001 size limit finding."""
    large_file = tmp_path / "large_session.json"
    content = json.dumps({"schema": "sesslint.session/v1", "version": 1, "events": []})
    large_file.write_text(content, encoding="utf-8")

    limits = ReaderLimits(max_file_bytes=10)
    events, findings = load_canonical(large_file, limits=limits)
    assert len(events) == 0
    assert len(findings) == 1
    assert findings[0].code == SL001
    assert findings[0].evidence.get("reason") == "size_limit_exceeded"


def test_max_records_limit() -> None:
    """Verify exceeding max_records raises MaxRecordsExceededError."""
    doc = {
        "schema": "sesslint.session/v1",
        "version": 1,
        "events": [
            {
                "actor": "user",
                "id": f"evt_{i}",
                "kind": "message",
                "parent_id": None,
                "payload": {},
                "seq": i,
                "ts": "2026-09-05T12:00:00Z",
            }
            for i in range(10)
        ],
    }
    limits = ReaderLimits(max_records=5)
    with pytest.raises(MaxRecordsExceededError) as exc_info:
        load_canonical(json.dumps(doc).encode("utf-8"), limits=limits)
    assert "exceeds limit of 5" in str(exc_info.value)


def test_per_event_missing_required_keys_SL001() -> None:
    """Verify per-event missing required keys (id, parent_id, kind, ts) produce SL001."""
    doc = {
        "schema": "sesslint.session/v1",
        "version": 1,
        "events": [
            {
                # Missing id, parent_id, kind, ts
                "actor": "user",
                "payload": {"text": "bad event"},
            }
        ],
    }
    events, findings = load_canonical(json.dumps(doc).encode("utf-8"))
    assert len(events) == 1  # event parsed best-effort
    assert len(findings) == 4  # 4 missing required keys
    fields_flagged = {f.evidence.get("field") for f in findings}
    assert fields_flagged == {"id", "parent_id", "kind", "ts"}


def test_sha256_stability() -> None:
    """Verify dump_canonical is strictly deterministic (dump twice -> identical sha256)."""
    minimal_path = FIXTURES_DIR / "minimal.json"
    events, _ = load_canonical(minimal_path)

    bytes1 = dump_canonical(events, source=events.source)
    bytes2 = dump_canonical(events, source=events.source)
    assert bytes1 == bytes2
    assert hashlib.sha256(bytes1).hexdigest() == hashlib.sha256(bytes2).hexdigest()


def test_load_canonical_session() -> None:
    """Verify load_canonical_session returns Session object with valid SessionHeader."""
    minimal_path = FIXTURES_DIR / "minimal.json"
    session, findings = load_canonical_session(minimal_path)

    assert len(findings) == 0
    assert session.header.schema_version == "sesslint.session/v1"
    assert session.header.session_id == "canonical-session"
    assert session.header.version == 1
    assert len(session.events) == 2
    assert session.events[0].id == "evt_001"
    assert session.events[1].id == "evt_002"


def test_dump_canonical_accepts_session() -> None:
    """Verify dump_canonical accepts a Session dataclass directly and produces exact bytes."""
    minimal_path = FIXTURES_DIR / "minimal.json"
    session, findings = load_canonical_session(minimal_path)
    assert len(findings) == 0

    dumped_from_session = dump_canonical(session)
    dumped_from_events = dump_canonical(session.events, source=session.header.source)
    assert dumped_from_session == dumped_from_events

    snapshot_path = SNAPSHOTS_DIR / "canonical_minimal.json"
    assert dumped_from_session == snapshot_path.read_bytes()


def test_null_or_empty_id_rejected_SL001() -> None:
    """Verify null, empty, or whitespace event id produces SL001 finding without inventing id."""
    # id: None (null in JSON)
    doc_null = {
        "schema": "sesslint.session/v1",
        "version": 1,
        "events": [
            {
                "id": None,
                "parent_id": None,
                "kind": "message",
                "ts": "2026-09-05T12:00:00Z",
            }
        ],
    }
    events, findings = load_canonical(json.dumps(doc_null).encode("utf-8"))
    assert len(findings) == 1
    assert findings[0].code == SL001
    assert findings[0].evidence.get("reason") == "invalid_id"

    # id: "" (empty string)
    doc_empty = {
        "schema": "sesslint.session/v1",
        "version": 1,
        "events": [
            {
                "id": "   ",
                "parent_id": None,
                "kind": "message",
                "ts": "2026-09-05T12:00:00Z",
            }
        ],
    }
    events, findings = load_canonical(json.dumps(doc_empty).encode("utf-8"))
    assert len(findings) == 1
    assert findings[0].code == SL001
    assert findings[0].evidence.get("reason") == "invalid_id"


def test_non_string_id_rejected_SL001() -> None:
    """Verify non-string id (e.g. integer) produces SL001 finding."""
    doc_int = {
        "schema": "sesslint.session/v1",
        "version": 1,
        "events": [
            {
                "id": 12345,
                "parent_id": None,
                "kind": "message",
                "ts": "2026-09-05T12:00:00Z",
            }
        ],
    }
    events, findings = load_canonical(json.dumps(doc_int).encode("utf-8"))
    assert len(findings) == 1
    assert findings[0].code == SL001
    assert findings[0].evidence.get("reason") == "invalid_id"


def test_invalid_parent_id_SL001() -> None:
    """Verify empty string or non-string parent_id produces SL001 finding."""
    doc = {
        "schema": "sesslint.session/v1",
        "version": 1,
        "events": [
            {
                "id": "evt_001",
                "parent_id": "",
                "kind": "message",
                "ts": "2026-09-05T12:00:00Z",
            },
            {
                "id": "evt_002",
                "parent_id": 123,
                "kind": "message",
                "ts": "2026-09-05T12:00:01Z",
            },
        ],
    }
    events, findings = load_canonical(json.dumps(doc).encode("utf-8"))
    parent_id_findings = [f for f in findings if f.evidence.get("reason") == "invalid_parent_id"]
    assert len(parent_id_findings) == 2


def test_invalid_payload_type_SL001() -> None:
    """Verify non-mapping payload produces SL001 finding."""
    doc = {
        "schema": "sesslint.session/v1",
        "version": 1,
        "events": [
            {
                "id": "evt_001",
                "parent_id": None,
                "kind": "message",
                "ts": "2026-09-05T12:00:00Z",
                "payload": "not_a_mapping",
            }
        ],
    }
    events, findings = load_canonical(json.dumps(doc).encode("utf-8"))
    assert any(
        f.code == SL001 and f.evidence.get("reason") == "invalid_payload_type" for f in findings
    )


def test_invalid_source_type_SL001() -> None:
    """Verify non-mapping/non-string source produces SL001 finding."""
    doc = {
        "schema": "sesslint.session/v1",
        "version": 1,
        "source": 12345,
        "events": [],
    }
    events, findings = load_canonical(json.dumps(doc).encode("utf-8"))
    assert any(
        f.code == SL001 and f.evidence.get("reason") == "invalid_source_type" for f in findings
    )


def test_stream_read_size_limit_bounded() -> None:
    """Verify open stream exceeding max_file_bytes is bounded without unbounded read."""
    import io

    large_stream = io.BytesIO(b"x" * 200)
    limits = ReaderLimits(max_file_bytes=100)
    events, findings = load_canonical(large_stream, limits=limits)
    assert len(events) == 0
    assert len(findings) == 1
    assert findings[0].code == SL001
    assert findings[0].evidence.get("reason") == "size_limit_exceeded"


def test_load_canonical_session_preserves_document_metadata() -> None:
    """Verify document session_id, created_at, title, and metadata are preserved in header."""
    doc = {
        "schema": "sesslint.session/v1",
        "version": 1,
        "session_id": "custom-sess-42",
        "created_at": "2026-09-05T10:30:00Z",
        "title": "Custom Investigation Session",
        "metadata": {"investigator": "Tom", "tags": ["audit"]},
        "source": {"format": "canonical"},
        "events": [
            {
                "id": "evt_001",
                "parent_id": None,
                "kind": "message",
                "ts": "2026-09-05T10:30:01Z",
                "actor": "user",
                "payload": {"text": "inspect"},
                "seq": 0,
            }
        ],
    }
    session, findings = load_canonical_session(json.dumps(doc).encode("utf-8"))
    assert len(findings) == 0
    assert session.header.session_id == "custom-sess-42"
    assert session.header.created_at == "2026-09-05T10:30:00Z"
    assert session.header.title == "Custom Investigation Session"
    assert session.header.metadata.get("investigator") == "Tom"


def test_10k_events_size_limit() -> None:
    """Verify 10k-event document over size limit produces size-gate finding before load."""
    doc = {
        "schema": "sesslint.session/v1",
        "version": 1,
        "source": {"format": "canonical"},
        "events": [
            {
                "actor": "user",
                "id": f"evt_{i:06d}",
                "kind": "message",
                "parent_id": f"evt_{i - 1:06d}" if i > 0 else None,
                "payload": {"counter": i, "padding": "a" * 100},
                "seq": i,
                "ts": "2026-09-05T12:00:00Z",
            }
            for i in range(10000)
        ],
    }
    raw_bytes = json.dumps(doc).encode("utf-8")
    assert len(raw_bytes) > 1_000_000  # Over 1MB

    # Tight limit (50KB) triggers size-gate refusal
    limits = ReaderLimits(max_file_bytes=50_000)
    events, findings = load_canonical(raw_bytes, limits=limits)
    assert len(events) == 0
    assert len(findings) == 1
    assert findings[0].code == SL001
    assert findings[0].evidence.get("reason") == "size_limit_exceeded"


def test_unicode_utf8_roundtrip() -> None:
    """Verify non-ASCII unicode (Vietnamese, diacritics, emoji) round-trips cleanly."""
    doc = {
        "schema": "sesslint.session/v1",
        "version": 1,
        "source": {"format": "canonical"},
        "events": [
            {
                "actor": "user",
                "id": "evt_vn_01",
                "kind": "message",
                "parent_id": None,
                "payload": {"text": "Kiểm tra tính toàn vẹn phiên làm việc 🚀"},
                "seq": 0,
                "ts": "2026-09-05T12:00:00Z",
            }
        ],
    }
    bytes1 = dump_canonical(load_canonical(json.dumps(doc).encode("utf-8"))[0])
    events2, findings2 = load_canonical(bytes1)
    assert len(findings2) == 0
    assert events2[0].payload.get("text") == "Kiểm tra tính toàn vẹn phiên làm việc 🚀"
    bytes2 = dump_canonical(events2)
    assert bytes1 == bytes2
