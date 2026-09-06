"""Unit, regression, and adversarial tests for generic parent-graph checks (SL004–SL007).

Covers TASK-013 requirements:
- SL004: Missing parent (error, manual) with {id, parent_id, index} evidence.
- SL005: Parent cycle (fatal, unsupported) with deterministic smallest-first closed cycle_path.
- SL006: Disconnected components (warning, manual) over present edges with root-min tie-breaking.
- SL007: Ambiguous heads (warning, manual) for multiple tips; suppressed on empty/all-cycle.
- First-occurrence policy for duplicate IDs.
- Capping at MAX_GRAPH_FINDINGS (500) per family + deterministic overflow marker.
- Vendor-free verification.
- Immutability of inputs.
- Hostile adversarial scaling (100k-node linear chain without recursion).
"""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any, cast

from sesslint.adapters.canonical import load_canonical
from sesslint.canonical import SessionEvent
from sesslint.checks.graph import (
    check_components,
    check_cycles,
    check_graph,
    check_heads,
    check_missing_parent,
)
from sesslint.codes import (
    SL004,
    SL005,
    SL006,
    SL007,
    Repairability,
    Severity,
)

FIXTURES_CHECKS_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "checks"
GRAPH_SRC_FILE = (
    Path(__file__).resolve().parent.parent.parent / "src" / "sesslint" / "checks" / "graph.py"
)


def test_healthy_clean() -> None:
    """Healthy linear chain produces 0 findings across all four checks and check_graph."""
    fixture_path = FIXTURES_CHECKS_DIR / "graph_healthy.json"
    event_list, load_findings = load_canonical(fixture_path)
    assert not load_findings

    assert check_missing_parent(event_list) == []
    assert check_cycles(event_list) == []
    assert check_components(event_list) == []
    assert check_heads(event_list) == []
    assert check_graph(event_list) == []


def test_sl004_missing_parent() -> None:
    """SL004 fixture detects missing parent 'ghost' on evt-orphan."""
    fixture_path = FIXTURES_CHECKS_DIR / "sl004_missing.json"
    event_list, load_findings = load_canonical(fixture_path)
    assert not load_findings

    findings = check_missing_parent(event_list)
    assert len(findings) == 1

    f = findings[0]
    assert f.code == SL004
    assert f.severity == Severity.ERROR
    assert f.repairability == Repairability.MANUAL
    assert f.source.record_id == "evt-orphan"

    evidence = cast(dict[str, Any], f.evidence)
    assert evidence["id"] == "evt-orphan"
    assert evidence["parent_id"] == "ghost"
    assert evidence["index"] == 3

    # On check_graph: SL004 fires for evt-orphan, and SL006 fires for the
    # isolated singleton component {evt-orphan} formed by the missing parent link.
    all_findings = check_graph(event_list)
    codes = [x.code for x in all_findings]
    assert SL004 in codes
    assert SL006 in codes


def test_sl005_cycle_path() -> None:
    """SL005 fixture detects 3-cycle with deterministic smallest-first closed path."""
    fixture_path = FIXTURES_CHECKS_DIR / "sl005_cycle.json"
    event_list, load_findings = load_canonical(fixture_path)
    assert not load_findings

    findings = check_cycles(event_list)
    assert len(findings) == 1

    f = findings[0]
    assert f.code == SL005
    assert f.severity == Severity.FATAL
    assert f.repairability == Repairability.UNSUPPORTED
    assert f.source.record_id == "a"

    evidence = cast(dict[str, Any], f.evidence)
    assert evidence["cycle_path"] == ["a", "b", "c", "a"]
    assert evidence["entry_index"] == 0

    # Determinism: running twice produces identical cycle_path and fingerprint
    findings_second = check_cycles(event_list)
    assert f.fingerprint == findings_second[0].fingerprint
    assert cast(dict[str, Any], findings_second[0].evidence)["cycle_path"] == ["a", "b", "c", "a"]

    # Rotated-input variant: reverse the event order and verify identical cycle_path
    reversed_events = list(reversed(event_list))
    findings_rev = check_cycles(reversed_events)
    assert len(findings_rev) == 1
    assert cast(dict[str, Any], findings_rev[0].evidence)["cycle_path"] == ["a", "b", "c", "a"]


def test_sl006_disconnected() -> None:
    """SL006 fixture detects smaller disconnected branch naming its root."""
    fixture_path = FIXTURES_CHECKS_DIR / "sl006_disconnected.json"
    event_list, load_findings = load_canonical(fixture_path)
    assert not load_findings

    findings = check_components(event_list)
    assert len(findings) == 1

    f = findings[0]
    assert f.code == SL006
    assert f.severity == Severity.WARNING
    assert f.repairability == Repairability.MANUAL
    assert f.source.record_id == "c2-1"

    evidence = cast(dict[str, Any], f.evidence)
    assert evidence["root_id"] == "c2-1"
    assert evidence["size"] == 2
    assert evidence["member_sample"] == ["c2-1", "c2-2"]


def test_sl007_two_heads() -> None:
    """SL007 fixture with two leaf tips produces exactly one warning/manual finding."""
    fixture_path = FIXTURES_CHECKS_DIR / "sl007_two_heads.json"
    event_list, load_findings = load_canonical(fixture_path)
    assert not load_findings

    # Check heads in isolation
    heads_findings = check_heads(event_list)
    assert len(heads_findings) == 1
    f = heads_findings[0]
    assert f.code == SL007
    assert f.severity == Severity.WARNING
    assert f.repairability == Repairability.MANUAL
    assert f.source.record_id == "tip-a"

    evidence = cast(dict[str, Any], f.evidence)
    assert evidence["heads"] == ["tip-a", "tip-b"]
    assert evidence["count"] == 2

    # Check that in check_graph, SL004, SL005, and SL006 do not fire
    all_findings = check_graph(event_list)
    assert len(all_findings) == 1
    assert all_findings[0].code == SL007


def test_sl007_all_cycle_suppressed() -> None:
    """Pure cycle session has 0 heads; SL005 is present and SL007 is absent."""
    events = [
        SessionEvent(
            id="a",
            parent_id="b",
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id="b",
            parent_id="c",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id="c",
            parent_id="a",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="user",
            kind="message",
            payload={},
        ),
    ]
    heads_findings = check_heads(events)
    assert heads_findings == []

    all_findings = check_graph(events)
    codes = [f.code for f in all_findings]
    assert SL005 in codes
    assert SL007 not in codes


def test_empty_clean() -> None:
    """Empty events list produces 0 findings across all checks without crashing."""
    assert check_missing_parent([]) == []
    assert check_cycles([]) == []
    assert check_components([]) == []
    assert check_heads([]) == []
    assert check_graph([]) == []


def test_conflicting_dup_policy() -> None:
    """Conflicting duplicate IDs follow the first-occurrence policy deterministically."""
    events = [
        SessionEvent(
            id="evt-dup",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={"version": 1},
        ),
        SessionEvent(
            id="evt-dup",
            parent_id="ghost-parent",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="message",
            payload={"version": 2},
        ),
        SessionEvent(
            id="evt-child",
            parent_id="evt-dup",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="user",
            kind="message",
            payload={},
        ),
    ]
    # First occurrence of evt-dup has parent_id: None.
    # Second occurrence has parent_id: "ghost-parent", but is ignored by occurrence policy.
    findings = check_missing_parent(events)
    assert findings == []


def test_caps() -> None:
    """Synthetic dataset exceeding max_findings caps results and appends overflow finding."""
    # Synthesize 600 disjoint cycles of length 1 (self-loops)
    events: list[SessionEvent] = []
    for i in range(600):
        id_str = f"cycle_{i:04d}"
        events.append(
            SessionEvent(
                id=id_str,
                parent_id=id_str,
                seq=i,
                ts="2026-09-05T12:00:00Z",
                actor="user",
                kind="message",
                payload={},
            )
        )

    findings = check_cycles(events, max_findings=500)
    assert len(findings) == 501

    kept = findings[:500]
    assert all(f.code == SL005 for f in kept)
    assert all(f.severity == Severity.FATAL for f in kept)

    overflow = findings[500]
    assert overflow.code == SL005
    assert overflow.severity == Severity.WARNING
    assert overflow.repairability == Repairability.MANUAL
    assert overflow.evidence is not None
    assert overflow.evidence["overflow"] is True
    assert overflow.evidence["total_count"] == 600
    assert overflow.evidence["truncated_count"] == 100
    assert overflow.evidence["cap"] == 500


def test_vendor_free() -> None:
    """Verify that graph.py contains zero vendor tokens."""
    content = GRAPH_SRC_FILE.read_text(encoding="utf-8")
    forbidden_tokens = [
        "claude",
        "openai",
        "toolUse",
        "tool_call_id",
        "call_id",
        "chatgpt",
        "anthropic",
    ]
    for token in forbidden_tokens:
        matches = re.findall(rf"\b{re.escape(token)}\b", content, re.IGNORECASE)
        assert not matches, f"Forbidden vendor token {token!r} found in graph.py"


def test_immutability() -> None:
    """Verify that check_graph does not mutate input event objects or sequence."""
    events = [
        SessionEvent(
            id="evt-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={"deep": [1, 2, 3]},
        ),
        SessionEvent(
            id="evt-2",
            parent_id="ghost",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="message",
            payload={"text": "hello"},
        ),
    ]
    events_clone = copy.deepcopy(events)
    _ = check_graph(events)
    assert events == events_clone


def test_adversarial_100k_chain() -> None:
    """100,000-event linear chain verifies iterative non-recursive traversal."""
    events: list[SessionEvent] = []
    events.append(
        SessionEvent(
            id="node_000000",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        )
    )
    for i in range(1, 100_000):
        events.append(
            SessionEvent(
                id=f"node_{i:06d}",
                parent_id=f"node_{i - 1:06d}",
                seq=i,
                ts="2026-09-05T12:00:00Z",
                actor="assistant" if i % 2 == 1 else "user",
                kind="message",
                payload={},
            )
        )

    # Must complete without RecursionError and find 0 errors/cycles
    assert check_missing_parent(events) == []
    assert check_cycles(events) == []
    assert check_components(events) == []
    heads = check_heads(events)
    assert heads == []
    all_f = check_graph(events)
    assert all_f == []


def test_adversarial_self_loop() -> None:
    """Self-loop (parent_id == id) fires SL005 as a 1-node cycle ['x', 'x'], not SL004."""
    events = [
        SessionEvent(
            id="self_node",
            parent_id="self_node",
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        )
    ]
    missing = check_missing_parent(events)
    assert missing == []

    cycles = check_cycles(events)
    assert len(cycles) == 1
    assert cast(dict[str, Any], cycles[0].evidence)["cycle_path"] == ["self_node", "self_node"]


def test_adversarial_forward_reference() -> None:
    """Parent referencing a later-defined ID is legal and does not trigger SL004."""
    events = [
        SessionEvent(
            id="child",
            parent_id="future_parent",
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id="future_parent",
            parent_id=None,
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="message",
            payload={},
        ),
    ]
    findings = check_missing_parent(events)
    assert findings == []


def test_adversarial_empty_string_parent() -> None:
    """Empty string parent_id is treated as missing parent (only None is root)."""
    events = [
        SessionEvent(
            id="evt-with-empty-parent",
            parent_id="",
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        )
    ]
    findings = check_missing_parent(events)
    assert len(findings) == 1
    assert findings[0].code == SL004
    assert cast(dict[str, Any], findings[0].evidence)["parent_id"] == ""


def test_adversarial_two_identical_cycles_dup_ids() -> None:
    """Duplicate IDs in a cycle are deduplicated by the first-occurrence policy."""
    events = [
        SessionEvent(
            id="c1",
            parent_id="c2",
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id="c2",
            parent_id="c1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="user",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id="c1",
            parent_id="c2",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="user",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id="c2",
            parent_id="c1",
            seq=3,
            ts="2026-09-05T12:00:03Z",
            actor="user",
            kind="message",
            payload={},
        ),
    ]
    findings = check_cycles(events)
    assert len(findings) == 1
    assert cast(dict[str, Any], findings[0].evidence)["cycle_path"] == ["c1", "c2", "c1"]


def test_adversarial_component_tie_breaking() -> None:
    """Components of equal size break ties by lexicographically smallest root ID."""
    # Component A: root 'alpha', child 'alpha_child' (size 2)
    # Component B: root 'beta', child 'beta_child' (size 2)
    events = [
        SessionEvent(
            id="beta",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id="beta_child",
            parent_id="beta",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id="alpha",
            parent_id=None,
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="user",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id="alpha_child",
            parent_id="alpha",
            seq=3,
            ts="2026-09-05T12:00:03Z",
            actor="assistant",
            kind="message",
            payload={},
        ),
    ]
    # Both size 2. 'alpha' < 'beta', so Component A is primary.
    # Component B ('beta') is the extra component.
    findings = check_components(events)
    assert len(findings) == 1
    assert findings[0].source.record_id == "beta"
    assert cast(dict[str, Any], findings[0].evidence)["root_id"] == "beta"


def test_adversarial_member_sample_cap() -> None:
    """SL006 member_sample caps at 8 members in evidence."""
    events = [
        SessionEvent(
            id="main_root",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        ),
    ]
    # Add a huge main chain
    for i in range(1, 20):
        events.append(
            SessionEvent(
                id=f"main_{i:02d}",
                parent_id="main_root" if i == 1 else f"main_{i - 1:02d}",
                seq=i,
                ts="2026-09-05T12:00:00Z",
                actor="assistant",
                kind="message",
                payload={},
            )
        )
    # Add a disconnected component with 15 members
    events.append(
        SessionEvent(
            id="sub_root",
            parent_id=None,
            seq=20,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        )
    )
    for i in range(1, 15):
        events.append(
            SessionEvent(
                id=f"sub_{i:02d}",
                parent_id="sub_root" if i == 1 else f"sub_{i - 1:02d}",
                seq=20 + i,
                ts="2026-09-05T12:00:00Z",
                actor="assistant",
                kind="message",
                payload={},
            )
        )

    findings = check_components(events)
    assert len(findings) == 1
    evidence = cast(dict[str, Any], findings[0].evidence)
    assert evidence["size"] == 15
    assert len(evidence["member_sample"]) == 8


def test_adversarial_non_string_ids_ignored() -> None:
    """Non-string or null IDs are ignored for graph linkage without crashing."""
    raw_dict_events = [
        {
            "id": None,
            "parent_id": None,
            "seq": 0,
            "ts": "2026-09-05T12:00:00Z",
            "actor": "user",
            "kind": "message",
            "payload": {},
        },
        {
            "id": "valid_1",
            "parent_id": None,
            "seq": 1,
            "ts": "2026-09-05T12:00:01Z",
            "actor": "assistant",
            "kind": "message",
            "payload": {},
        },
        {
            "id": 12345,
            "parent_id": "valid_1",
            "seq": 2,
            "ts": "2026-09-05T12:00:02Z",
            "actor": "user",
            "kind": "message",
            "payload": {},
        },
    ]
    findings = check_graph(cast(list[SessionEvent], raw_dict_events))
    assert findings == []


def test_source_coords_resolution() -> None:
    """Ensure source_location and source_line from event propagate into SourceRef."""
    events = [
        SessionEvent(
            id="evt-1",
            parent_id="ghost",
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
            source_line=42,
            source_location="src/custom/path.json",
        )
    ]
    findings = check_missing_parent(events)
    assert len(findings) == 1
    assert findings[0].source.line == 42
    assert findings[0].source.path == "src/custom/path.json"


def test_custom_source_path() -> None:
    """Ensure explicit source_path overrides default <canonical>."""
    events = [
        SessionEvent(
            id="evt-1",
            parent_id="ghost",
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        )
    ]
    findings = check_missing_parent(events, source_path="C:\\test\\session.jsonl")
    assert findings[0].source.path == "C:/test/session.jsonl"


def test_caps_missing_parent_and_components() -> None:
    """Test capping behavior on SL004 and SL006."""
    events: list[SessionEvent] = []
    # 20 distinct missing parents capped at 10
    for i in range(20):
        events.append(
            SessionEvent(
                id=f"node_{i:02d}",
                parent_id=f"missing_{i:02d}",
                seq=i,
                ts="2026-09-05T12:00:00Z",
                actor="user",
                kind="message",
                payload={},
            )
        )
    sl004_capped = check_missing_parent(events, max_findings=10)
    assert len(sl004_capped) == 11
    assert sl004_capped[-1].code == SL004
    assert cast(dict[str, Any], sl004_capped[-1].evidence)["overflow"] is True

    # 20 disjoint singletons capped at 10 for SL006
    sl006_capped = check_components(events, max_findings=10)
    assert len(sl006_capped) == 11
    assert sl006_capped[-1].code == SL006
    assert cast(dict[str, Any], sl006_capped[-1].evidence)["overflow"] is True


def test_redacted_pii_in_ids() -> None:
    """IDs containing PII or control chars are safely sanitized/redacted across all checks."""
    # SL004 missing parent with PII
    events_missing = [
        SessionEvent(
            id="user@example.com",
            parent_id="ghost@example.com",
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        )
    ]
    f_missing = check_missing_parent(events_missing)
    assert len(f_missing) == 1
    ev_m = cast(dict[str, Any], f_missing[0].evidence)
    assert ev_m["id"] == "<redacted>"
    assert ev_m["parent_id"] == "<redacted>"

    # SL005 cycle with PII
    events_cycle = [
        SessionEvent(
            id="pii_a@example.com",
            parent_id="pii_b@example.com",
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id="pii_b@example.com",
            parent_id="pii_a@example.com",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="message",
            payload={},
        ),
    ]
    f_cycle = check_cycles(events_cycle)
    assert len(f_cycle) == 1
    ev_c = cast(dict[str, Any], f_cycle[0].evidence)
    assert ev_c["cycle_path"] == ["<redacted>", "<redacted>", "<redacted>"]
    assert f_cycle[0].source.record_id == "<redacted>"

    # SL006 disconnected components with PII
    events_comp = [
        SessionEvent(
            id="c1@example.com",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id="c2@example.com",
            parent_id=None,
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="message",
            payload={},
        ),
    ]
    f_comp = check_components(events_comp)
    assert len(f_comp) == 1
    ev_comp = cast(dict[str, Any], f_comp[0].evidence)
    assert ev_comp["root_id"] == "<redacted>"
    assert ev_comp["member_sample"] == ["<redacted>"]

    # SL007 heads with PII
    f_heads = check_heads(events_comp)
    assert len(f_heads) == 1
    ev_h = cast(dict[str, Any], f_heads[0].evidence)
    assert ev_h["count"] == 2
    assert ev_h["heads"] == ["<redacted>", "<redacted>"]

    # check_graph executes without raising FindingError
    all_f = check_graph(events_cycle + events_comp)
    assert len(all_f) >= 1


def test_non_string_parent_id() -> None:
    """Coerced non-string parent_id (e.g. integer) is treated as missing parent."""
    events = [
        SessionEvent(
            id="evt-1",
            parent_id=cast(Any, 99999),
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        )
    ]
    findings = check_missing_parent(events)
    assert len(findings) == 1
    assert cast(dict[str, Any], findings[0].evidence)["parent_id"] == "99999"


def test_whitespace_in_matching_ids_no_false_positive() -> None:
    """Non-empty IDs with leading/trailing spaces preserve identity and match parent_id."""
    events = [
        SessionEvent(
            id="node 1 ",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id="node 2",
            parent_id="node 1 ",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="message",
            payload={},
        ),
    ]
    # 'node 1 ' exists in g.id_set; parent_id matches verbatim, so SL004 must not fire
    findings = check_missing_parent(events)
    assert findings == []


def test_check_graph_overflow_order() -> None:
    """In check_graph, overflow findings sort after all regular findings for a code."""
    # Synthesize 30 self-loops to trigger capping with max_findings=10 for both SL005 and SL006
    events = [
        SessionEvent(
            id=f"cycle_{i:04d}",
            parent_id=f"cycle_{i:04d}",
            seq=i,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        )
        for i in range(30)
    ]
    results = check_graph(events, max_findings_per_family=10)

    # 11 findings for SL005, 11 findings for SL006
    sl005_results = [f for f in results if f.code == SL005]
    assert len(sl005_results) == 11
    for f in sl005_results[:10]:
        assert f.severity == Severity.FATAL
        assert f.evidence is not None
        assert f.evidence.get("overflow") is not True
    assert sl005_results[-1].severity == Severity.WARNING
    assert sl005_results[-1].evidence is not None
    assert sl005_results[-1].evidence.get("overflow") is True

    sl006_results = [f for f in results if f.code == SL006]
    assert len(sl006_results) == 11
    for f in sl006_results[:10]:
        assert f.severity == Severity.WARNING
        assert f.evidence is not None
        assert f.evidence.get("overflow") is not True
    assert sl006_results[-1].evidence is not None
    assert sl006_results[-1].evidence.get("overflow") is True


def test_converging_branches_into_cycle() -> None:
    """Branches converging into a cycle detect the cycle and produce deterministic entry_index."""
    # Graph:
    # 0_lead_a -> cycle_1
    # 0_lead_b -> cycle_1
    # cycle_1 -> cycle_2 -> cycle_1
    events = [
        SessionEvent(
            id="0_lead_a",
            parent_id="cycle_1",
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id="0_lead_b",
            parent_id="cycle_1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="user",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id="cycle_1",
            parent_id="cycle_2",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="assistant",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id="cycle_2",
            parent_id="cycle_1",
            seq=3,
            ts="2026-09-05T12:00:03Z",
            actor="assistant",
            kind="message",
            payload={},
        ),
    ]
    findings = check_cycles(events)
    assert len(findings) == 1
    ev = cast(dict[str, Any], findings[0].evidence)
    assert ev["cycle_path"] == ["cycle_1", "cycle_2", "cycle_1"]
    assert ev["entry_index"] == 2

    # Reversed order produces identical cycle_path
    findings_rev = check_cycles(list(reversed(events)))
    assert len(findings_rev) == 1
    ev_rev = cast(dict[str, Any], findings_rev[0].evidence)
    assert ev_rev["cycle_path"] == ["cycle_1", "cycle_2", "cycle_1"]


def test_multiple_cycles_disjoint() -> None:
    """Multiple disjoint cycles are all detected and sorted deterministically."""
    events = [
        SessionEvent(
            id="loop_z1",
            parent_id="loop_z2",
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id="loop_z2",
            parent_id="loop_z1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id="loop_a1",
            parent_id="loop_a2",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="user",
            kind="message",
            payload={},
        ),
        SessionEvent(
            id="loop_a2",
            parent_id="loop_a1",
            seq=3,
            ts="2026-09-05T12:00:03Z",
            actor="assistant",
            kind="message",
            payload={},
        ),
    ]
    findings = check_cycles(events)
    assert len(findings) == 2
    # Sorted by primary_id (cycle_path[0])
    assert cast(dict[str, Any], findings[0].evidence)["cycle_path"] == [
        "loop_a1",
        "loop_a2",
        "loop_a1",
    ]
    assert cast(dict[str, Any], findings[1].evidence)["cycle_path"] == [
        "loop_z1",
        "loop_z2",
        "loop_z1",
    ]


def test_whitespace_only_id_ignored() -> None:
    """Whitespace-only ID is ignored for linkage."""
    events = [
        SessionEvent(
            id="   ",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={},
        )
    ]
    assert check_graph(events) == []


def test_dict_event_source_coords() -> None:
    """Mapping event source_location and source_line resolve into finding."""
    dict_events = [
        {
            "id": "evt-orphan",
            "parent_id": "ghost",
            "seq": 0,
            "ts": "2026-09-05T12:00:00Z",
            "actor": "user",
            "kind": "message",
            "payload": {},
            "source_location": "custom/path.jsonl",
            "source_line": 99,
        }
    ]
    findings = check_missing_parent(cast(list[SessionEvent], dict_events))
    assert len(findings) == 1
    assert findings[0].source.path == "custom/path.jsonl"
    assert findings[0].source.line == 99
