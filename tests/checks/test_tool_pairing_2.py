"""Unit and regression tests for tool-pairing detector part 2 (SL105-SL108).

Covers TASK-015 requirements:
- SL105: Reversed tool pairing produces error/manual finding per correlation identifier.
- SL106: Cross-branch tool pairing produces error/manual finding per correlation identifier.
- SL107: Non-adjacent tool pairing produces warning/manual finding with parallel-exemption.
- SL108: Split compaction boundary produces warning/manual finding.
- Cardinality precedence: SL103/SL104 corrs skipped by part 2 detectors.
- Parallel-exemption: Valid concurrent fan-out does not fire SL107.
- Index-only ordering: Wall-clock timestamp skew is ignored.
- Strict boundary between: Boundary at endpoints does not fire SL108.
- Zero vendor leakage (no Claude/OpenAI/toolUse/call_id references in source).
- Deterministic ordering and stable fingerprints.
- Cap and overflow handling.
- Immutability of input sequence.
- Cross-task non-regression with TASK-014.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any, cast

from sesslint.adapters.canonical import load_canonical
from sesslint.canonical import SessionEvent
from sesslint.checks.tool_pairing_1 import check_tool_pairing_1
from sesslint.checks.tool_pairing_2 import (
    check_adjacency,
    check_cross_branch,
    check_reversed_order,
    check_sl105,
    check_sl106,
    check_sl107,
    check_sl108,
    check_tool_pairing_2,
)
from sesslint.codes import (
    SL105,
    SL106,
    SL107,
    SL108,
    Repairability,
    Severity,
)
from sesslint.finding import Finding

FIXTURES_CHECKS_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "checks"
TOOL_PAIRING_2_SRC_FILE = (
    Path(__file__).resolve().parent.parent.parent
    / "src"
    / "sesslint"
    / "checks"
    / "tool_pairing_2.py"
)


def _evidence(f: Finding) -> dict[str, Any]:
    """Helper to extract and cast non-null evidence mapping for type checkers."""
    assert f.evidence is not None
    return cast(dict[str, Any], f.evidence)


def test_parallel_valid_clean() -> None:
    """Valid-parallel non-regression: interleaved fan-out produces 0 findings across part 1 & 2."""
    fixture_path = FIXTURES_CHECKS_DIR / "parallel_valid.json"
    events, load_findings = load_canonical(fixture_path)
    assert not load_findings

    # Part 2 checks: 0 findings (SL107 is parallel-exempted, no SL105, SL106, SL108)
    findings_part2 = check_tool_pairing_2(events)
    assert not findings_part2

    # Part 1 checks: 0 findings (clean pairing)
    findings_part1 = check_tool_pairing_1(events)
    assert not findings_part1


def test_sl105_reversed_fixture() -> None:
    """SL105 reversed fixture: result before call produces error/manual finding."""
    fixture_path = FIXTURES_CHECKS_DIR / "sl105_reversed.json"
    events, load_findings = load_canonical(fixture_path)
    assert not load_findings

    findings = check_tool_pairing_2(events)
    assert len(findings) == 1

    f = findings[0]
    assert f.code == SL105
    assert f.severity == Severity.ERROR
    assert f.repairability == Repairability.MANUAL
    assert f.source.record_id == "evt-call"

    ev = _evidence(f)
    assert ev["correlation_id"] == "call-rev"
    assert ev["result_index"] == 1
    assert ev["use_index"] == 2


def test_sl106_cross_branch_fixture() -> None:
    """SL106 cross-branch fixture: call and result in different branches produces error/manual."""
    fixture_path = FIXTURES_CHECKS_DIR / "sl106_cross_branch.json"
    events, load_findings = load_canonical(fixture_path)
    assert not load_findings

    findings = check_tool_pairing_2(events)
    assert len(findings) == 1

    f = findings[0]
    assert f.code == SL106
    assert f.severity == Severity.ERROR
    assert f.repairability == Repairability.MANUAL
    assert f.source.record_id == "evt-call-branch1"

    ev = _evidence(f)
    assert ev["correlation_id"] == "call-cross"
    assert ev["use_id"] == "evt-call-branch1"
    assert ev["result_id"] == "evt-res-branch2"
    assert ev["use_index"] == 2
    assert ev["result_index"] == 3


def test_sl107_gap_fixture() -> None:
    """SL107 gap fixture: user message intervening between call and result fires warning/manual."""
    fixture_path = FIXTURES_CHECKS_DIR / "sl107_gap.json"
    events, load_findings = load_canonical(fixture_path)
    assert not load_findings

    findings = check_tool_pairing_2(events)
    assert len(findings) == 1

    f = findings[0]
    assert f.code == SL107
    assert f.severity == Severity.WARNING
    assert f.repairability == Repairability.MANUAL
    assert f.source.record_id == "evt-2"

    ev = _evidence(f)
    assert ev["correlation_id"] == "call-gap"
    assert ev["intervening_count"] == 1
    assert ev["intervening_kinds"] == ["message"]
    assert ev["use_index"] == 1
    assert ev["result_index"] == 3


def test_sl108_compaction_fixture() -> None:
    """SL108 compaction fixture: compaction_boundary between call and result fires SL108 & SL107."""
    fixture_path = FIXTURES_CHECKS_DIR / "sl108_compaction.json"
    events, load_findings = load_canonical(fixture_path)
    assert not load_findings

    findings = check_tool_pairing_2(events)
    # SL108 fires for compaction boundary; SL107 also fires since compaction_boundary is non-tool
    codes = {f.code for f in findings}
    assert codes == {SL107, SL108}

    f108 = next(f for f in findings if f.code == SL108)
    assert f108.severity == Severity.WARNING
    assert f108.repairability == Repairability.DETERMINISTIC
    assert f108.source.record_id == "evt-call"

    ev = _evidence(f108)
    assert ev["correlation_id"] == "call-compact"
    assert ev["boundary_index"] == 2
    assert ev["use_index"] == 1
    assert ev["result_index"] == 3


def test_reversed_plus_boundary() -> None:
    """Result preceding call with intervening compaction_boundary fires BOTH SL105 and SL108."""
    events = [
        SessionEvent(
            id="res-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="tool",
            kind="tool_result",
            correlation_id="corr-rev-split",
        ),
        SessionEvent(
            id="bound-1",
            parent_id="res-1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="system",
            kind="compaction_boundary",
        ),
        SessionEvent(
            id="call-1",
            parent_id="bound-1",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="corr-rev-split",
        ),
    ]

    findings = check_tool_pairing_2(events)
    codes = {f.code for f in findings}
    assert SL105 in codes
    assert SL108 in codes


def test_cardinality_precedence() -> None:
    """SL103/SL104 correlation IDs are skipped by part 2 placement detectors."""
    # 2 calls + 1 result: cardinality fault (SL103), part 2 must produce 0 findings
    events_reused = [
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
    ]
    assert not check_tool_pairing_2(events_reused)

    # 1 call + 2 results: cardinality fault (SL104), part 2 must produce 0 findings
    events_multi = [
        SessionEvent(
            id="c1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="multi",
        ),
        SessionEvent(
            id="r1",
            parent_id="c1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="tool",
            kind="tool_result",
            correlation_id="multi",
        ),
        SessionEvent(
            id="r2",
            parent_id="r1",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="tool",
            kind="tool_result",
            correlation_id="multi",
        ),
    ]
    assert not check_tool_pairing_2(events_multi)


def test_ts_ignored() -> None:
    """Wall-clock timestamp skew never overrides canonical sequence index order."""
    events = [
        SessionEvent(
            id="c1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:10Z",  # Skewed later timestamp
            actor="assistant",
            kind="tool_call",
            correlation_id="corr-clean",
        ),
        SessionEvent(
            id="r1",
            parent_id="c1",
            seq=1,
            ts="2026-09-05T12:00:00Z",  # Skewed earlier timestamp
            actor="tool",
            kind="tool_result",
            correlation_id="corr-clean",
        ),
    ]

    # Index order is c1 (0) then r1 (1), which is correct -> 0 findings
    findings = check_tool_pairing_2(events)
    assert not findings


def test_nested_fanout_exemption_scaling() -> None:
    """50 concurrent pairs interleaved produces 0 SL107 findings (parallel-exemption scales)."""
    events: list[SessionEvent] = []
    parent_id: str | None = None

    # Emit 50 calls
    for i in range(50):
        ev_id = f"call-{i}"
        events.append(
            SessionEvent(
                id=ev_id,
                parent_id=parent_id,
                seq=len(events),
                ts="2026-09-05T12:00:00Z",
                actor="assistant",
                kind="tool_call",
                correlation_id=f"pair-{i}",
            )
        )
        parent_id = ev_id

    # Emit 50 results
    for i in range(50):
        ev_id = f"res-{i}"
        events.append(
            SessionEvent(
                id=ev_id,
                parent_id=parent_id,
                seq=len(events),
                ts="2026-09-05T12:00:01Z",
                actor="tool",
                kind="tool_result",
                correlation_id=f"pair-{i}",
            )
        )
        parent_id = ev_id

    findings = check_tool_pairing_2(events)
    assert not findings


def test_boundary_at_endpoint_no_sl108() -> None:
    """Compaction boundary located outside strict (min_idx, max_idx) does not trigger SL108."""
    events = [
        SessionEvent(
            id="bound-0",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="system",
            kind="compaction_boundary",
        ),
        SessionEvent(
            id="call-1",
            parent_id="bound-0",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="corr-1",
        ),
        SessionEvent(
            id="res-1",
            parent_id="call-1",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="tool",
            kind="tool_result",
            correlation_id="corr-1",
        ),
        SessionEvent(
            id="bound-3",
            parent_id="res-1",
            seq=3,
            ts="2026-09-05T12:00:03Z",
            actor="system",
            kind="compaction_boundary",
        ),
    ]

    findings = check_tool_pairing_2(events)
    assert not findings


def test_roots_cross_branch() -> None:
    """Pairing where call and result are both roots (parent=None) triggers SL106."""
    events = [
        SessionEvent(
            id="call-root",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="corr-roots",
        ),
        SessionEvent(
            id="res-root",
            parent_id=None,
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="tool",
            kind="tool_result",
            correlation_id="corr-roots",
        ),
    ]

    findings = check_cross_branch(events)
    assert len(findings) == 1
    assert findings[0].code == SL106


def test_determinism_and_stable_fingerprints() -> None:
    """Repeated runs produce byte-identical sorted outputs and stable fingerprints."""
    events = [
        SessionEvent(
            id="r1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="tool",
            kind="tool_result",
            correlation_id="b-rev",
        ),
        SessionEvent(
            id="c1",
            parent_id="r1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="b-rev",
        ),
        SessionEvent(
            id="r2",
            parent_id="c1",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="tool",
            kind="tool_result",
            correlation_id="a-rev",
        ),
        SessionEvent(
            id="c2",
            parent_id="r2",
            seq=3,
            ts="2026-09-05T12:00:03Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="a-rev",
        ),
    ]

    findings_1 = check_tool_pairing_2(events)
    findings_2 = check_tool_pairing_2(events)

    raw_1 = json.dumps([f.to_dict() for f in findings_1], sort_keys=True)
    raw_2 = json.dumps([f.to_dict() for f in findings_2], sort_keys=True)
    assert raw_1 == raw_2
    assert [f.source.record_id for f in findings_1] == ["c2", "c1"]


def test_caps_and_overflow() -> None:
    """Cap truncation appends deterministic overflow finding with summary counts."""
    events: list[SessionEvent] = []
    # Create 20 reversed pairs
    for i in range(20):
        events.append(
            SessionEvent(
                id=f"r-{i:03d}",
                parent_id=None,
                seq=len(events),
                ts="2026-09-05T12:00:00Z",
                actor="tool",
                kind="tool_result",
                correlation_id=f"rev-{i:03d}",
            )
        )
        events.append(
            SessionEvent(
                id=f"c-{i:03d}",
                parent_id=None,
                seq=len(events),
                ts="2026-09-05T12:00:01Z",
                actor="assistant",
                kind="tool_call",
                correlation_id=f"rev-{i:03d}",
            )
        )

    findings = check_reversed_order(events, max_findings=5)
    assert len(findings) == 6  # 5 kept + 1 overflow
    regular = findings[:5]
    overflow = findings[5]

    assert all(f.code == SL105 for f in regular)
    assert overflow.code == SL105
    assert overflow.severity == Severity.WARNING
    assert overflow.repairability == Repairability.MANUAL
    assert _evidence(overflow)["overflow"] is True
    assert _evidence(overflow)["total_count"] == 20
    assert _evidence(overflow)["truncated_count"] == 15


def test_immutability() -> None:
    """check_tool_pairing_2 does not mutate input event objects or sequence."""
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
    _ = check_tool_pairing_2(events)
    assert events == events_copy


def test_vendor_free() -> None:
    """Source file must be strictly vendor-free (no Claude/OpenAI/toolUse/call_id)."""
    assert TOOL_PAIRING_2_SRC_FILE.is_file(), f"Missing source file: {TOOL_PAIRING_2_SRC_FILE}"
    source_content = TOOL_PAIRING_2_SRC_FILE.read_text(encoding="utf-8")

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
            f"Forbidden vendor keyword '{match.group(0)}' found in {TOOL_PAIRING_2_SRC_FILE}"
        )


def test_per_code_helpers() -> None:
    """Direct invocations of check_sl105, check_sl106, check_sl107, check_sl108 work."""
    rev_events = [
        SessionEvent(
            id="r1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="tool",
            kind="tool_result",
            correlation_id="rev",
        ),
        SessionEvent(
            id="c1",
            parent_id="r1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="rev",
        ),
    ]

    f105 = check_sl105(rev_events)
    assert len(f105) == 1 and f105[0].code == SL105

    f106 = check_sl106(rev_events)
    assert not f106

    f107 = check_sl107(rev_events)
    assert not f107

    f108 = check_sl108(rev_events)
    assert not f108


def test_mapping_input_support() -> None:
    """check_tool_pairing_2 supports dict-like event objects as input."""
    raw_events: list[dict[str, Any]] = [
        {
            "id": "r1",
            "kind": "tool_result",
            "correlation_id": "test-dict",
            "source_location": "test.jsonl:1",
            "source_line": 1,
        },
        {
            "id": "c1",
            "parent_id": "r1",
            "kind": "tool_call",
            "correlation_id": "test-dict",
            "source_location": "test.jsonl:2",
            "source_line": 2,
        },
    ]

    findings = check_tool_pairing_2(cast(list[SessionEvent], raw_events))
    assert len(findings) == 1
    assert findings[0].code == SL105
    assert findings[0].source.path == "test.jsonl:1"
    assert findings[0].source.line == 1


def test_sl106_scope_mismatch_interleaved_agent() -> None:
    """Interleaved main/sub-agent cross-pair fires SL106 even within same parent tree (RVW-018)."""
    events = [
        SessionEvent(
            id="root",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
        ),
        SessionEvent(
            id="call-1",
            parent_id="root",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="corr-1",
            agent_id="main-agent",
        ),
        SessionEvent(
            id="res-1",
            parent_id="call-1",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="tool",
            kind="tool_result",
            correlation_id="corr-1",
            agent_id="sub-agent-a",
        ),
    ]

    findings = check_cross_branch(events)
    assert len(findings) == 1
    assert findings[0].code == SL106
    assert findings[0].evidence is not None
    assert findings[0].evidence["scope_mismatch"] is True
    assert findings[0].evidence["call_agent_id"] == "main-agent"
    assert findings[0].evidence["result_agent_id"] == "sub-agent-a"


def test_sl106_same_scope_disconnected_does_not_fire() -> None:
    """Same-scope disconnected pair does not fire SL106 (belongs to graph checks) (RVW-018)."""
    events = [
        SessionEvent(
            id="call-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="corr-1",
            agent_id="main-agent",
        ),
        SessionEvent(
            id="res-1",
            parent_id=None,
            seq=1,
            ts="2026-09-05T12:00:02Z",
            actor="tool",
            kind="tool_result",
            correlation_id="corr-1",
            agent_id="main-agent",
        ),
    ]

    findings = check_cross_branch(events)
    assert len(findings) == 0


def test_sl106_empty_id_deterministic() -> None:
    """Empty IDs produce deterministic behavior without id() addresses (RVW-034)."""
    events = [
        SessionEvent(
            id="",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="corr-1",
        ),
        SessionEvent(
            id="",
            parent_id=None,
            seq=1,
            ts="2026-09-05T12:00:02Z",
            actor="tool",
            kind="tool_result",
            correlation_id="corr-1",
        ),
    ]
    findings1 = check_cross_branch(events)
    findings2 = check_cross_branch(events)
    assert findings1 == findings2
    assert len(findings1) == 0


def test_profile_severity_modulation_sl107_sl108() -> None:
    """SL107 and SL108 are warning under neutral and error under strict (RVW-012)."""
    from sesslint.profiles import CLAUDE_STRICT_PROFILE, NEUTRAL_PROFILE

    # SL107 fixture (interleaved non-tool message)
    events_sl107 = [
        SessionEvent(
            id="c1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="corr-gap",
        ),
        SessionEvent(
            id="m1",
            parent_id="c1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="user",
            kind="message",
        ),
        SessionEvent(
            id="r1",
            parent_id="m1",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="tool",
            kind="tool_result",
            correlation_id="corr-gap",
        ),
    ]

    f_neutral = check_adjacency(events_sl107, profile=NEUTRAL_PROFILE)
    assert len(f_neutral) == 1
    assert f_neutral[0].severity == Severity.WARNING

    f_strict = check_adjacency(events_sl107, profile=CLAUDE_STRICT_PROFILE)
    assert len(f_strict) == 1
    assert f_strict[0].severity == Severity.ERROR
