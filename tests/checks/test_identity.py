"""Unit and regression tests for SL003 identity detector.

Covers TASK-012 requirements:
- Identical duplicates -> single warning/deterministic finding per ID.
- Conflicting duplicates -> single error/manual finding per ID with field names only.
- Content-free evidence: no raw values leaked.
- Null/missing IDs ignored without error.
- Clean canonical sessions produce 0 findings.
- Deterministic ordering and stable fingerprints under input permutations.
- Cap at MAX_IDENTITY_FINDINGS + deterministic overflow summary.
- Immutability of inputs.
- Zero vendor leakage (no Claude/OpenAI/toolUse/call_id references).
- Adversarial scale: 100k events, 50-variant diffs, non-string IDs, Unicode codepoint sort.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any, cast

from sesslint.adapters.canonical import load_canonical
from sesslint.canonical import (
    CanonicalEvent,
    SessionEvent,
    canonical_bytes,
    to_canonical_dict,
)
from sesslint.checks.identity import (
    MAX_IDENTITY_FINDINGS,
    MAX_RECORD_INDEXES_IN_EVIDENCE,
    cap_findings,
    check_identities,
    compute_identity_fingerprint,
    diff_field_names,
)
from sesslint.codes import SL003, Repairability, Severity
from sesslint.finding import Finding, SourceRef, parse_finding_dict

FIXTURES_CHECKS_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "checks"
FIXTURES_CANONICAL_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "canonical"
IDENTITY_SRC_FILE = (
    Path(__file__).resolve().parent.parent.parent / "src" / "sesslint" / "checks" / "identity.py"
)


def _load_raw_fixture_events(path: Path) -> list[SessionEvent]:
    """Load fixture events preserving null IDs without schema interception."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    events: list[SessionEvent] = []
    for ev in doc["events"]:
        events.append(
            SessionEvent(
                id=ev["id"],
                parent_id=ev.get("parent_id"),
                seq=ev.get("seq", 0),
                ts=ev.get("ts", "2026-09-05T12:00:00Z"),
                actor=ev.get("actor", "user"),
                kind=ev.get("kind", "message"),
                payload=ev.get("payload", {}),
            )
        )
    return events


def test_identical_collapse_candidate() -> None:
    """Identical fixture produces exactly 1 warning/deterministic finding with indexes."""
    fixture_path = FIXTURES_CHECKS_DIR / "sl003_identical.json"
    event_list, load_findings = load_canonical(fixture_path)
    assert not load_findings

    findings = check_identities(event_list)
    assert len(findings) == 1

    finding = findings[0]
    assert finding.code == SL003
    assert finding.variant == "identical-duplicate"
    assert finding.severity == Severity.WARNING
    assert finding.repairability == Repairability.DETERMINISTIC
    assert finding.source.record_id == "evt-1"

    evidence = cast(dict[str, Any], finding.evidence)
    assert evidence["id"] == "evt-1"
    assert evidence["count"] == 3
    assert evidence["first_index"] == 0
    assert evidence["record_indexes"] == [0, 1, 2]
    assert evidence["variant"] == "identical-duplicate"


def test_conflicting_error_manual() -> None:
    """Conflicting fixture produces 1 error/manual finding with differing field names only."""
    fixture_path = FIXTURES_CHECKS_DIR / "sl003_conflicting.json"
    event_list, load_findings = load_canonical(fixture_path)
    assert not load_findings

    findings = check_identities(event_list)
    assert len(findings) == 1

    finding = findings[0]
    assert finding.code == SL003
    assert finding.variant == "conflicting-duplicate"
    assert finding.severity == Severity.ERROR
    assert finding.repairability == Repairability.MANUAL
    assert finding.source.record_id == "evt-1"

    evidence = cast(dict[str, Any], finding.evidence)
    assert evidence["id"] == "evt-1"
    assert evidence["count"] == 2
    assert evidence["first_index"] == 0
    assert evidence["record_indexes"] == [0, 1]
    assert "parent_id" in evidence["differing_fields"]
    assert evidence["variant"] == "conflicting-duplicate"

    # Strict content-free assertion: raw differing parent string must not leak
    assert "evt-divergent-parent-unique" not in str(evidence)
    assert "evt-divergent-parent-unique" not in finding.message


def test_mixed_and_null_ignored() -> None:
    """Mixed fixture produces 2 findings (1 identical, 1 conflicting); null IDs ignored."""
    fixture_path = FIXTURES_CHECKS_DIR / "sl003_mixed.json"
    events = _load_raw_fixture_events(fixture_path)
    assert len(events) == 6

    # Verify fixture has null-ID events
    null_id_count = sum(1 for e in events if e.id is None)
    assert null_id_count == 2

    findings = check_identities(events)
    assert len(findings) == 2

    findings_by_id = {f.source.record_id: f for f in findings}
    assert "evt-ident" in findings_by_id
    assert "evt-conflict" in findings_by_id

    ident_finding = findings_by_id["evt-ident"]
    assert ident_finding.variant == "identical-duplicate"
    assert ident_finding.severity == Severity.WARNING
    assert ident_finding.repairability == Repairability.DETERMINISTIC
    assert ident_finding.evidence is not None
    assert ident_finding.evidence["count"] == 2
    assert ident_finding.evidence["record_indexes"] == [0, 1]

    conflict_finding = findings_by_id["evt-conflict"]
    assert conflict_finding.variant == "conflicting-duplicate"
    assert conflict_finding.severity == Severity.ERROR
    assert conflict_finding.repairability == Repairability.MANUAL
    assert conflict_finding.evidence is not None
    assert conflict_finding.evidence["count"] == 2
    assert conflict_finding.evidence["record_indexes"] == [2, 3]
    assert "payload" in conflict_finding.evidence["differing_fields"]

    # Ensure zero findings were produced for null-ID events
    assert not any(f.source.record_id is None for f in findings)
    assert not any(f.source.record_id == "<none>" for f in findings)


def test_singletons_clean() -> None:
    """Minimal canonical session with unique IDs produces 0 findings."""
    fixture_path = FIXTURES_CANONICAL_DIR / "minimal.json"
    event_list, load_findings = load_canonical(fixture_path)
    assert not load_findings

    findings = check_identities(event_list)
    assert findings == []


def test_determinism() -> None:
    """Shuffling input order preserves stable fingerprints and deterministic output."""
    events = [
        SessionEvent(
            id="evt-dup-b",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={"text": "b1"},
        ),
        SessionEvent(
            id="evt-dup-a",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={"text": "a1"},
        ),
        SessionEvent(
            id="evt-dup-b",
            parent_id="other",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="message",
            payload={"text": "b2"},
        ),
        SessionEvent(
            id="evt-dup-a",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={"text": "a1"},
        ),
    ]

    findings_forward = check_identities(events)
    events_reversed = list(reversed(events))
    findings_reversed = check_identities(events_reversed)

    assert len(findings_forward) == 2
    assert len(findings_reversed) == 2

    # Findings must be in sorted (code, id) order in both runs
    assert [f.source.record_id for f in findings_forward] == ["evt-dup-a", "evt-dup-b"]
    assert [f.source.record_id for f in findings_reversed] == ["evt-dup-a", "evt-dup-b"]

    # Fingerprints must match exactly across permutations (stable fingerprints)
    assert [f.fingerprint for f in findings_forward] == [f.fingerprint for f in findings_reversed]
    assert [f.code for f in findings_forward] == [f.code for f in findings_reversed]
    assert [f.severity for f in findings_forward] == [f.severity for f in findings_reversed]
    rep_forward = [f.repairability for f in findings_forward]
    rep_reversed = [f.repairability for f in findings_reversed]
    assert rep_forward == rep_reversed

    # Running twice on the same input produces byte-identical output
    raw_1 = json.dumps([f.to_dict() for f in check_identities(events)], sort_keys=True)
    raw_2 = json.dumps([f.to_dict() for f in check_identities(events)], sort_keys=True)
    assert raw_1 == raw_2


def test_cap() -> None:
    """Synthesizing 1500 conflicting IDs produces <= MAX+1 findings with overflow marker."""
    events: list[SessionEvent] = []
    # Generate 1500 distinct IDs, each having 2 conflicting occurrences
    for i in range(1500):
        id_str = f"id_{i:04d}"
        events.append(
            SessionEvent(
                id=id_str,
                parent_id=None,
                seq=0,
                ts="2026-09-05T12:00:00Z",
                actor="user",
                kind="message",
                payload={"variant": 1},
            )
        )
        events.append(
            SessionEvent(
                id=id_str,
                parent_id=None,
                seq=0,
                ts="2026-09-05T12:00:00Z",
                actor="user",
                kind="message",
                payload={"variant": 2},
            )
        )

    findings = check_identities(events, max_findings=MAX_IDENTITY_FINDINGS)
    assert len(findings) == MAX_IDENTITY_FINDINGS + 1

    # First 1000 findings must correspond to first 1000 sorted IDs
    first_1000_ids = [f.source.record_id for f in findings[:MAX_IDENTITY_FINDINGS]]
    expected_first_1000 = [f"id_{i:04d}" for i in range(1000)]
    assert first_1000_ids == expected_first_1000

    # The 1001st finding is the overflow marker
    overflow = findings[MAX_IDENTITY_FINDINGS]
    assert overflow.code == SL003
    assert overflow.variant == "overflow-summary"
    assert overflow.severity == Severity.WARNING
    assert overflow.repairability == Repairability.MANUAL
    assert overflow.evidence is not None
    assert overflow.evidence["overflow"] is True
    assert overflow.evidence["cap"] == 1000
    assert overflow.evidence["total_duplicate_ids"] == 1500
    assert overflow.evidence["truncated_count"] == 500


def test_vendor_free() -> None:
    """Source file must be strictly vendor-free (no Claude/OpenAI/toolUse/call_id)."""
    assert IDENTITY_SRC_FILE.is_file(), f"Missing source file: {IDENTITY_SRC_FILE}"
    source_content = IDENTITY_SRC_FILE.read_text(encoding="utf-8")

    forbidden_patterns = [
        re.compile(r"\bclaude\b", re.IGNORECASE),
        re.compile(r"\bopenai\b", re.IGNORECASE),
        re.compile(r"\btoolUse\b"),
        re.compile(r"\bcall_id\b"),
    ]

    for pattern in forbidden_patterns:
        match = pattern.search(source_content)
        assert match is None, (
            f"Forbidden vendor keyword '{match.group(0)}' found in {IDENTITY_SRC_FILE}"
        )


def test_immutability() -> None:
    """Input sequence must remain deeply equal and unmutated after execution."""
    events = [
        SessionEvent(
            id="evt-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={"deep": [1, 2, {"k": "v"}]},
        ),
        SessionEvent(
            id="evt-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={"deep": [1, 2, {"k": "v"}]},
        ),
    ]

    snapshot = copy.deepcopy(events)
    check_identities(events)

    assert events == snapshot


# Adversarial and boundary test cases


def test_scale_100k_identical_ids() -> None:
    """100,000 occurrences of the same identical ID produce exactly 1 finding, not 100,000."""
    template_event = SessionEvent(
        id="evt-scale",
        parent_id=None,
        seq=0,
        ts="2026-09-05T12:00:00Z",
        actor="user",
        kind="message",
        payload={"ping": "pong"},
    )
    # Repeated reference in list without blowing up memory
    events = [template_event] * 100_000

    findings = check_identities(events)
    assert len(findings) == 1

    finding = findings[0]
    assert finding.variant == "identical-duplicate"
    evidence = cast(dict[str, Any], finding.evidence)
    assert evidence["count"] == 100_000
    assert evidence["first_index"] == 0
    assert len(evidence["record_indexes"]) == MAX_RECORD_INDEXES_IN_EVIDENCE
    assert evidence["truncated"] is True


def test_fifty_variant_diffs_bounded_evidence() -> None:
    """50 variants of same ID differing in 1 field each produce 1 finding with capped indexes."""
    events: list[SessionEvent] = []
    for i in range(50):
        events.append(
            SessionEvent(
                id="evt-diverge",
                parent_id=f"parent_{i:02d}",
                seq=i,
                ts="2026-09-05T12:00:00Z",
                actor="user",
                kind="message",
                payload={"index": i},
            )
        )

    findings = check_identities(events)
    assert len(findings) == 1

    finding = findings[0]
    assert finding.variant == "conflicting-duplicate"
    evidence = cast(dict[str, Any], finding.evidence)
    assert evidence["count"] == 50
    assert evidence["truncated"] is True
    assert len(evidence["record_indexes"]) == 32
    assert "parent_id" in evidence["differing_fields"]
    assert "payload" in evidence["differing_fields"]
    assert "seq" in evidence["differing_fields"]


def test_non_string_id_coercion() -> None:
    """Non-string IDs (int 1 vs '1') are defensively coerced with coerced:true in evidence."""
    events = [
        SessionEvent(
            id=cast(str, 1),
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id="1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        ),
    ]

    findings = check_identities(events)
    assert len(findings) == 1
    assert findings[0].evidence is not None
    assert findings[0].evidence["coerced"] is True
    assert findings[0].source.record_id == "1"


def test_empty_events_list() -> None:
    """Empty events list yields empty findings without error."""
    assert check_identities([]) == []


def test_unicode_ids_codepoint_sorting() -> None:
    """Unicode IDs sort by codepoint across platforms deterministically."""
    events = [
        SessionEvent(
            id="β_id",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id="α_id",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id="β_id",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id="α_id",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        ),
    ]

    findings = check_identities(events)
    assert len(findings) == 2
    # 'α' (U+03B1) precedes 'β' (U+03B2)
    assert [f.source.record_id for f in findings] == ["α_id", "β_id"]


def test_credential_in_id_suppressed_safely() -> None:
    """Credential-like string in duplicate ID is suppressed in message and coordinates."""
    bad_id = "sk-ant-api03-1234567890abcdefghijklmnopqrstuvwxyz"
    events = [
        SessionEvent(
            id=bad_id,
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id=bad_id,
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        ),
    ]

    findings = check_identities(events)
    assert len(findings) == 1
    finding = findings[0]
    # Sensitive credential suppressed from source.record_id and message
    assert finding.source.record_id is None
    assert bad_id not in finding.message
    assert finding.evidence is not None
    assert bad_id not in str(finding.evidence)


def test_diff_field_names_direct() -> None:
    """diff_field_names returns field names only without leaking values."""
    ev1 = SessionEvent(
        id="e1",
        parent_id="p1",
        seq=1,
        ts="2026-09-05T12:00:00Z",
        actor="user",
        kind="message",
        payload={"a": 1},
        branch_id="b1",
    )
    ev2 = SessionEvent(
        id="e1",
        parent_id="p2",
        seq=2,
        ts="2026-09-05T12:00:00Z",
        actor="user",
        kind="message",
        payload={"a": 2},
        branch_id=None,
    )

    diffs = diff_field_names([ev1, ev2])
    assert diffs == ["branch_id", "parent_id", "payload", "seq"]


def test_canonical_event_alias_and_methods() -> None:
    """CanonicalEvent is SessionEvent alias with proper canonical methods."""
    assert CanonicalEvent is SessionEvent
    ev = SessionEvent(
        id="e1",
        parent_id=None,
        seq=0,
        ts="2026-09-05T12:00:00Z",
        actor="user",
        kind="message",
        payload={"key": "val"},
    )
    assert isinstance(ev.to_canonical_bytes(), bytes)
    assert isinstance(ev.to_canonical_dict(), dict)
    assert isinstance(canonical_bytes(ev), bytes)
    assert isinstance(to_canonical_dict(ev), dict)
    assert len(ev.canonical_hash()) == 64
    assert ev.payload_hash().startswith("sha256:")


def test_compute_identity_fingerprint_direct() -> None:
    """Fingerprint is deterministic and ordering-independent for payload hashes."""
    fp1 = compute_identity_fingerprint("id1", ["h1", "h2"])
    fp2 = compute_identity_fingerprint("id1", ["h2", "h1"])
    assert fp1 == fp2
    assert len(fp1) == 16


def test_cap_findings_direct() -> None:
    """cap_findings does not add overflow marker when below cap."""
    f = Finding(
        code=SL003,
        severity=Severity.WARNING,
        repairability=Repairability.DETERMINISTIC,
        message="msg",
        source=SourceRef(path="path", line=1, record_id="r1"),
        related_ids=(),
        fingerprint="0123456789abcdef",
    )
    res = cap_findings([f], max_findings=10)
    assert len(res) == 1
    assert res[0].source.record_id == "r1"


def test_diff_field_names_none_vs_missing() -> None:
    """diff_field_names correctly detects field present with None vs key missing."""
    ev1 = SessionEvent(
        id="e1",
        parent_id=None,
        seq=0,
        ts="2026-09-05T12:00:00Z",
        actor="user",
        kind="message",
        payload={},
        extra_fields={"experimental_foo": None},
    )
    ev2 = SessionEvent(
        id="e1",
        parent_id=None,
        seq=0,
        ts="2026-09-05T12:00:00Z",
        actor="user",
        kind="message",
        payload={},
        extra_fields={},
    )

    diffs = diff_field_names([ev1, ev2])
    assert "experimental_foo" in diffs

    findings = check_identities([ev1, ev2])
    assert len(findings) == 1
    assert findings[0].variant == "conflicting-duplicate"
    assert findings[0].evidence is not None
    assert "experimental_foo" in findings[0].evidence["differing_fields"]


def test_empty_and_whitespace_id_ignored() -> None:
    """Empty string and whitespace-only IDs are treated as missing and ignored."""
    events = [
        SessionEvent(
            id="",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id="",
            parent_id=None,
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id="   ",
            parent_id=None,
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="user",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id="   ",
            parent_id=None,
            seq=3,
            ts="2026-09-05T12:00:03Z",
            actor="user",
            kind="message",
            payload={},
        ),
    ]
    findings = check_identities(events)
    assert findings == []


def test_mapping_event_duck_typing() -> None:
    """check_identities and diff_field_names work on dict mappings via duck typing."""
    events = [
        {
            "id": "evt-map",
            "parent_id": None,
            "seq": 0,
            "ts": "2026-09-05T12:00:00Z",
            "actor": "user",
            "kind": "message",
            "payload": {"text": "hello"},
        },
        {
            "id": "evt-map",
            "parent_id": None,
            "seq": 0,
            "ts": "2026-09-05T12:00:00Z",
            "actor": "user",
            "kind": "message",
            "payload": {"text": "hello"},
        },
    ]
    findings = check_identities(cast(Any, events))
    assert len(findings) == 1
    assert findings[0].variant == "identical-duplicate"
    assert findings[0].source.record_id == "evt-map"


def test_windows_backslash_path_normalization() -> None:
    """Windows backslashes in source_path are normalized to forward slashes."""
    events = [
        SessionEvent(
            id="e1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id="e1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        ),
    ]
    findings = check_identities(events, source_path="folder\\subfolder\\session.jsonl")
    assert len(findings) == 1
    assert findings[0].source.path == "folder/subfolder/session.jsonl"


def test_source_line_zero_or_negative_guarded() -> None:
    """source_line values <= 0 are normalized to None, preventing FindingError."""
    events = [
        SessionEvent(
            id="e1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
            source_line=0,
        ),
        SessionEvent(
            id="e1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
            source_line=0,
        ),
    ]
    findings = check_identities(events)
    assert len(findings) == 1
    assert findings[0].source.line is None


def test_cap_findings_overflow_schema_valid() -> None:
    """Overflow finding produced by cap_findings roundtrips through parse_finding_dict."""
    events: list[SessionEvent] = []
    for i in range(5):
        events.append(
            SessionEvent(
                id=f"id_{i}",
                parent_id=None,
                seq=0,
                ts="2026-09-05T12:00:00Z",
                actor="user",
                kind="message",
                payload={},
            )
        )
        events.append(
            SessionEvent(
                id=f"id_{i}",
                parent_id=None,
                seq=0,
                ts="2026-09-05T12:00:00Z",
                actor="user",
                kind="message",
                payload={},
            )
        )

    findings = check_identities(events, max_findings=2)
    assert len(findings) == 3
    overflow = findings[2]
    assert overflow.variant == "overflow-summary"

    d = overflow.to_dict()
    reparsed = parse_finding_dict(d)
    assert reparsed == overflow
