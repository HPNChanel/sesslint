"""Unit and regression tests for tool-pairing detector part 1 (SL101-SL104).

Covers TASK-014 requirements:
- SL101: Orphan tool result produces error/manual finding per orphan result event.
- SL102: Dangling tool call produces error/manual finding per dangling call event.
- SL103: Reused tool-call ID produces error/manual finding per correlation identifier.
- SL104: Multiple tool results produces error/manual finding per correlation identifier.
- Pinned interaction: 2 calls + 1 result -> SL103 only.
- Pinned interaction: 2 calls + 2 results -> BOTH SL103 and SL104 fire independently.
- Pinned null correlation: null-corr tool call -> SL102; null-corr tool result -> SL101.
- Pinned empty string: empty/whitespace correlation is treated as a real key, not null.
- Zero vendor leakage (no Claude/OpenAI/toolUse/call_id references in source).
- Pure function / immutability.
- Deterministic ordering and stable fingerprints.
- Cap and overflow handling.
- Adversarial scale (10k results sharing one correlation identifier).
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any, cast

from sesslint.adapters.canonical import load_canonical
from sesslint.canonical import SessionEvent
from sesslint.checks.tool_pairing_1 import (
    MAX_PAIRING_SAMPLE_SIZE,
    check_multiple_results,
    check_orphan_results,
    check_sl101,
    check_sl102,
    check_sl103,
    check_sl104,
    check_tool_pairing_1,
)
from sesslint.codes import (
    SL101,
    SL102,
    SL103,
    SL104,
    Repairability,
    Severity,
)
from sesslint.finding import Finding

FIXTURES_CHECKS_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "checks"
TOOL_PAIRING_1_SRC_FILE = (
    Path(__file__).resolve().parent.parent.parent
    / "src"
    / "sesslint"
    / "checks"
    / "tool_pairing_1.py"
)


def _evidence(f: Finding) -> dict[str, Any]:
    """Helper to extract and cast non-null evidence mapping for type checkers."""
    assert f.evidence is not None
    return cast(dict[str, Any], f.evidence)


def test_healthy_clean() -> None:
    """Healthy fixture with 2 complete pairs produces 0 findings."""
    fixture_path = FIXTURES_CHECKS_DIR / "pairing_healthy.json"
    events, load_findings = load_canonical(fixture_path)
    assert not load_findings

    findings = check_tool_pairing_1(events)
    assert not findings


def test_sl101_orphan_fixture() -> None:
    """Orphan fixture produces exactly 1 SL101 finding with healthy pair untouched."""
    fixture_path = FIXTURES_CHECKS_DIR / "sl101_orphan.json"
    events, load_findings = load_canonical(fixture_path)
    assert not load_findings

    findings = check_tool_pairing_1(events)
    assert len(findings) == 1

    finding = findings[0]
    assert finding.code == SL101
    assert finding.severity == Severity.ERROR
    assert finding.repairability == Repairability.MANUAL
    assert finding.source.record_id == "evt-orphan"

    evidence = cast(dict[str, Any], finding.evidence)
    assert evidence["correlation_id"] == "call-orphan"
    assert evidence["result_id"] == "evt-orphan"
    assert evidence["index"] == 3


def test_sl102_dangling_fixture() -> None:
    """Dangling fixture produces exactly 1 SL102 finding with healthy pair untouched."""
    fixture_path = FIXTURES_CHECKS_DIR / "sl102_dangling.json"
    events, load_findings = load_canonical(fixture_path)
    assert not load_findings

    findings = check_tool_pairing_1(events)
    assert len(findings) == 1

    finding = findings[0]
    assert finding.code == SL102
    assert finding.severity == Severity.ERROR
    assert finding.repairability == Repairability.MANUAL
    assert finding.source.record_id == "evt-dangling"

    evidence = cast(dict[str, Any], finding.evidence)
    assert evidence["correlation_id"] == "call-dangling"
    assert evidence["event_id"] == "evt-dangling"
    assert evidence["index"] == 3


def test_sl102_torn_tail_not_downgraded() -> None:
    """Dangling call adjacent to torn tail is not auto-downgraded; reported as SL102."""
    events = [
        SessionEvent(
            id="evt-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="call-tail",
            payload={"name": "test_cmd"},
        )
    ]
    findings = check_tool_pairing_1(events)
    assert len(findings) == 1
    assert findings[0].code == SL102
    assert findings[0].severity == Severity.ERROR
    assert findings[0].repairability == Repairability.MANUAL


def test_sl103_reused_fixture() -> None:
    """Reused fixture (2 calls + 1 result) produces exactly 1 SL103 finding and no SL104."""
    fixture_path = FIXTURES_CHECKS_DIR / "sl103_reused.json"
    events, load_findings = load_canonical(fixture_path)
    assert not load_findings

    findings = check_tool_pairing_1(events)
    assert len(findings) == 1

    finding = findings[0]
    assert finding.code == SL103
    assert finding.severity == Severity.ERROR
    assert finding.repairability == Repairability.MANUAL
    assert finding.source.record_id == "evt-call-1"

    evidence = cast(dict[str, Any], finding.evidence)
    assert evidence["correlation_id"] == "call-A"
    assert evidence["count"] == 2
    assert evidence["call_indexes"] == [1, 2]
    assert evidence["event_ids"] == ["evt-call-1", "evt-call-2"]
    assert evidence["truncated"] is False


def test_sl104_multi_result_fixture() -> None:
    """Multi-result fixture (1 call + 2 results) produces exactly 1 SL104 finding and no SL103."""
    fixture_path = FIXTURES_CHECKS_DIR / "sl104_multi_result.json"
    events, load_findings = load_canonical(fixture_path)
    assert not load_findings

    findings = check_tool_pairing_1(events)
    assert len(findings) == 1

    finding = findings[0]
    assert finding.code == SL104
    assert finding.severity == Severity.ERROR
    assert finding.repairability == Repairability.MANUAL
    assert finding.source.record_id == "evt-res-1"

    evidence = cast(dict[str, Any], finding.evidence)
    assert evidence["correlation_id"] == "call-B"
    assert evidence["count"] == 2
    assert evidence["result_indexes"] == [2, 3]
    assert evidence["event_ids"] == ["evt-res-1", "evt-res-2"]
    assert evidence["truncated"] is False


def test_sl103_plus_sl104_interaction() -> None:
    """Synthetic 2 calls + 2 results same correlation identifier fires BOTH SL103 and SL104."""
    events = [
        SessionEvent(
            id="call-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="shared-corr",
        ),
        SessionEvent(
            id="call-2",
            parent_id="call-1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="shared-corr",
        ),
        SessionEvent(
            id="res-1",
            parent_id="call-2",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="tool",
            kind="tool_result",
            correlation_id="shared-corr",
        ),
        SessionEvent(
            id="res-2",
            parent_id="res-1",
            seq=3,
            ts="2026-09-05T12:00:03Z",
            actor="tool",
            kind="tool_result",
            correlation_id="shared-corr",
        ),
    ]

    findings = check_tool_pairing_1(events)
    codes = [f.code for f in findings]
    assert sorted(codes) == [SL103, SL104]
    assert all(f.severity == Severity.ERROR for f in findings)
    assert all(f.repairability == Repairability.MANUAL for f in findings)


def test_null_correlation() -> None:
    """Null-correlation tool call produces SL102; null-correlation tool result produces SL101."""
    events = [
        SessionEvent(
            id="call-null",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id=None,
        ),
        SessionEvent(
            id="res-null",
            parent_id="call-null",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="tool",
            kind="tool_result",
            correlation_id=None,
        ),
    ]

    findings = check_tool_pairing_1(events)
    assert len(findings) == 2

    findings_by_code = {f.code: f for f in findings}
    assert SL101 in findings_by_code
    assert SL102 in findings_by_code

    f101 = findings_by_code[SL101]
    assert f101.source.record_id == "res-null"
    assert _evidence(f101)["correlation_id"] is None
    assert _evidence(f101)["index"] == 1

    f102 = findings_by_code[SL102]
    assert f102.source.record_id == "call-null"
    assert _evidence(f102)["correlation_id"] is None
    assert _evidence(f102)["index"] == 0


def test_empty_string_correlation() -> None:
    """Empty or whitespace correlation string is treated as a real key, firing SL103/SL104."""
    events = [
        SessionEvent(
            id="c1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="",
        ),
        SessionEvent(
            id="c2",
            parent_id="c1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="",
        ),
        SessionEvent(
            id="r1",
            parent_id="c2",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="tool",
            kind="tool_result",
            correlation_id="",
        ),
    ]

    findings = check_tool_pairing_1(events)
    assert len(findings) == 1
    assert findings[0].code == SL103
    assert _evidence(findings[0])["correlation_id"] == ""
    assert _evidence(findings[0])["count"] == 2


def test_whitespace_correlation() -> None:
    """Whitespace correlation string is treated as a real key."""
    events = [
        SessionEvent(
            id="c1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="   ",
        ),
        SessionEvent(
            id="r1",
            parent_id="c1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="tool",
            kind="tool_result",
            correlation_id="   ",
        ),
        SessionEvent(
            id="r2",
            parent_id="r1",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="tool",
            kind="tool_result",
            correlation_id="   ",
        ),
    ]

    findings = check_tool_pairing_1(events)
    assert len(findings) == 1
    assert findings[0].code == SL104
    assert _evidence(findings[0])["correlation_id"] == "   "
    assert _evidence(findings[0])["count"] == 2


def test_multi_orphan_same_corr() -> None:
    """Multi-orphans sharing one correlation_id each get own finding with shared corr."""
    events = [
        SessionEvent(
            id="res-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="tool",
            kind="tool_result",
            correlation_id="unseen-call",
        ),
        SessionEvent(
            id="res-2",
            parent_id="res-1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="tool",
            kind="tool_result",
            correlation_id="unseen-call",
        ),
    ]

    findings = check_orphan_results(events)
    # Per-result granularity: each orphan result event gets its own finding
    assert len(findings) == 2
    assert findings[0].code == SL101
    assert findings[0].source.record_id == "res-1"
    assert _evidence(findings[0])["correlation_id"] == "unseen-call"
    assert findings[1].code == SL101
    assert findings[1].source.record_id == "res-2"
    assert _evidence(findings[1])["correlation_id"] == "unseen-call"


def test_determinism_and_stable_fingerprints() -> None:
    """Input sequence order and repeated runs produce stable findings and fingerprints."""
    events = [
        SessionEvent(
            id="call-b",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="corr-b",
        ),
        SessionEvent(
            id="call-a",
            parent_id=None,
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="corr-a",
        ),
    ]

    findings_1 = check_tool_pairing_1(events)
    findings_2 = check_tool_pairing_1(events)

    raw_1 = json.dumps([f.to_dict() for f in findings_1], sort_keys=True)
    raw_2 = json.dumps([f.to_dict() for f in findings_2], sort_keys=True)
    assert raw_1 == raw_2

    # Deterministic sorting: both findings are SL102, sorted by record_id
    assert [f.source.record_id for f in findings_1] == ["call-a", "call-b"]


def test_caps_and_overflow() -> None:
    """Cap truncation appends deterministic overflow finding with summary counts."""
    events: list[SessionEvent] = []
    # Create 20 orphan results
    for i in range(20):
        events.append(
            SessionEvent(
                id=f"res-{i:03d}",
                parent_id=None,
                seq=i,
                ts="2026-09-05T12:00:00Z",
                actor="tool",
                kind="tool_result",
                correlation_id=f"orphan-{i:03d}",
            )
        )

    # Set cap to 5
    findings = check_orphan_results(events, max_findings=5)
    assert len(findings) == 6  # 5 kept + 1 overflow
    regular = findings[:5]
    overflow = findings[5]

    assert all(f.code == SL101 for f in regular)
    assert overflow.code == SL101
    assert overflow.severity == Severity.WARNING
    assert overflow.repairability == Repairability.MANUAL
    assert _evidence(overflow)["overflow"] is True
    assert _evidence(overflow)["total_count"] == 20
    assert _evidence(overflow)["truncated_count"] == 15
    assert _evidence(overflow)["cap"] == 5


def test_immutability() -> None:
    """check_tool_pairing_1 does not mutate input event objects or sequence."""
    events = [
        SessionEvent(
            id="c1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="corr-x",
        ),
        SessionEvent(
            id="r1",
            parent_id="c1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="tool",
            kind="tool_result",
            correlation_id="corr-x",
        ),
    ]

    events_copy = copy.deepcopy(events)
    _ = check_tool_pairing_1(events)
    assert events == events_copy


def test_vendor_free() -> None:
    """Source file must be strictly vendor-free (no Claude/OpenAI/toolUse/call_id)."""
    assert TOOL_PAIRING_1_SRC_FILE.is_file(), f"Missing source file: {TOOL_PAIRING_1_SRC_FILE}"
    source_content = TOOL_PAIRING_1_SRC_FILE.read_text(encoding="utf-8")

    forbidden_patterns = [
        re.compile(r"\bclaude\b", re.IGNORECASE),
        re.compile(r"\bopenai\b", re.IGNORECASE),
        re.compile(r"\banthropic\b", re.IGNORECASE),
        re.compile(r"\bchatgpt\b", re.IGNORECASE),
        re.compile(r"\btoolUse\b"),
        re.compile(r"\bcall_id\b"),
    ]

    for pattern in forbidden_patterns:
        match = pattern.search(source_content)
        assert match is None, (
            f"Forbidden vendor keyword '{match.group(0)}' found in {TOOL_PAIRING_1_SRC_FILE}"
        )


def test_adversarial_10k_multi_result() -> None:
    """Adversarial scale: 10k results sharing one correlation_id -> 1 SL104 with capped sample."""
    events: list[SessionEvent] = [
        SessionEvent(
            id="call-init",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="bulk-corr",
        )
    ]

    for i in range(1, 10001):
        events.append(
            SessionEvent(
                id=f"res-{i}",
                parent_id="call-init",
                seq=i,
                ts="2026-09-05T12:00:01Z",
                actor="tool",
                kind="tool_result",
                correlation_id="bulk-corr",
            )
        )

    findings = check_multiple_results(events)
    assert len(findings) == 1

    f = findings[0]
    assert f.code == SL104
    assert _evidence(f)["count"] == 10000
    assert len(_evidence(f)["result_indexes"]) == MAX_PAIRING_SAMPLE_SIZE
    assert len(_evidence(f)["event_ids"]) == MAX_PAIRING_SAMPLE_SIZE
    assert _evidence(f)["truncated"] is True


def test_corr_event_id_collision() -> None:
    """Correlation ID colliding with event ID namespace causes no cross-talk."""
    events = [
        SessionEvent(
            id="shared-name",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
        ),
        SessionEvent(
            id="call-1",
            parent_id="shared-name",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="shared-name",
        ),
        SessionEvent(
            id="res-1",
            parent_id="call-1",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="tool",
            kind="tool_result",
            correlation_id="shared-name",
        ),
    ]

    findings = check_tool_pairing_1(events)
    assert not findings


def test_unicode_corr_ids() -> None:
    """Unicode correlation identifiers sort by codepoint deterministically."""
    events = [
        SessionEvent(
            id="call-z",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="β-beta",
        ),
        SessionEvent(
            id="call-a",
            parent_id=None,
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="α-alpha",
        ),
    ]

    findings = check_tool_pairing_1(events)
    assert len(findings) == 2
    # Sorted by record_id
    assert [f.source.record_id for f in findings] == ["call-a", "call-z"]


def test_non_tool_events_ignored() -> None:
    """Non-tool events carrying correlation_id are ignored by pairing detector."""
    events = [
        SessionEvent(
            id="msg-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            correlation_id="ignored-corr",
        ),
        SessionEvent(
            id="msg-2",
            parent_id="msg-1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="message",
            correlation_id="ignored-corr",
        ),
    ]

    findings = check_tool_pairing_1(events)
    assert not findings


def test_per_code_helpers() -> None:
    """Direct invocations of check_sl101, check_sl102, check_sl103, check_sl104 work."""
    call_event = SessionEvent(
        id="c1",
        parent_id=None,
        seq=0,
        ts="2026-09-05T12:00:00Z",
        actor="assistant",
        kind="tool_call",
        correlation_id="c-lone",
    )
    res_event = SessionEvent(
        id="r1",
        parent_id=None,
        seq=1,
        ts="2026-09-05T12:00:01Z",
        actor="tool",
        kind="tool_result",
        correlation_id="r-lone",
    )

    f101 = check_sl101([res_event])
    assert len(f101) == 1 and f101[0].code == SL101

    f102 = check_sl102([call_event])
    assert len(f102) == 1 and f102[0].code == SL102

    f103 = check_sl103([call_event])
    assert not f103

    f104 = check_sl104([res_event])
    assert not f104


def test_content_free_evidence() -> None:
    """Evidence contains only structural IDs, indexes, counts — no raw payloads."""
    events = [
        SessionEvent(
            id="c1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="corr-secret",
            payload={"secret_key": "sk-123456789012345678"},
        )
    ]

    findings = check_tool_pairing_1(events)
    assert len(findings) == 1
    evidence_str = str(findings[0].evidence)
    assert "sk-123456789012345678" not in evidence_str
    assert "secret_key" not in evidence_str


def test_severity_and_repairability() -> None:
    """All 4 rules produce error severity and manual repairability."""
    events = [
        SessionEvent(
            id="c1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="reused",
        ),
        SessionEvent(
            id="c2",
            parent_id="c1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="reused",
        ),
        SessionEvent(
            id="r1",
            parent_id="c2",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="tool",
            kind="tool_result",
            correlation_id="reused",
        ),
        SessionEvent(
            id="r2",
            parent_id="r1",
            seq=3,
            ts="2026-09-05T12:00:03Z",
            actor="tool",
            kind="tool_result",
            correlation_id="reused",
        ),
        SessionEvent(
            id="c_dangling",
            parent_id="r2",
            seq=4,
            ts="2026-09-05T12:00:04Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="dangling",
        ),
        SessionEvent(
            id="r_orphan",
            parent_id="c_dangling",
            seq=5,
            ts="2026-09-05T12:00:05Z",
            actor="tool",
            kind="tool_result",
            correlation_id="orphan",
        ),
    ]

    findings = check_tool_pairing_1(events)
    found_codes = {f.code for f in findings}
    assert found_codes == {SL101, SL102, SL103, SL104}

    for f in findings:
        assert f.severity == Severity.ERROR
        assert f.repairability == Repairability.MANUAL


def test_mapping_input_support() -> None:
    """check_tool_pairing_1 supports dict-like event objects as input."""
    raw_events: list[dict[str, Any]] = [
        {
            "id": "c1",
            "kind": "tool_call",
            "correlation_id": "test-dict",
            "source_location": "test.jsonl:1",
            "source_line": 1,
        }
    ]

    findings = check_tool_pairing_1(cast(list[SessionEvent], raw_events))
    assert len(findings) == 1
    assert findings[0].code == SL102
    assert findings[0].source.path == "test.jsonl:1"
    assert findings[0].source.line == 1
