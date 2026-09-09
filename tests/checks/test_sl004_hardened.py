"""Comprehensive unit, adversarial decoy, and positive lifecycle tests for hardened SL004.

Invariants verified:
1. same_compaction_segment helper across zero, single, endpoint, and multiple boundaries.
2. Elimination of prefix matching (c.id.startswith) across detector, precondition, and apply.
3. 4 adversarial decoy scenarios fail-closed (MANUAL finding, 0 plan steps, PreconditionFailed):
   a. Prefix-collision decoy (shares prefix but not exact equality).
   b. Cross-branch decoy (exact equality match but conflicting branch_id).
   c. Cross-segment decoy (exact match, same branch, separated by compaction_boundary).
   d. Duplicate-candidate decoy (multiple matching candidates).
4. Positive exact-match full repair cycle: detection -> plan -> execute -> verify manifest.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from sesslint.adapters.canonical import load_canonical
from sesslint.canonical import SessionEvent
from sesslint.checks.graph import (
    check_missing_parent,
    find_qualifying_parent_candidates,
    is_qualifying_parent_candidate,
    same_compaction_segment,
)
from sesslint.codes import SL004, Repairability, Severity
from sesslint.finding import SourceRef, make_finding
from sesslint.repair.executor import execute
from sesslint.repair.planner import PlanStep, plan
from sesslint.repair.preconditions import PreconditionContext, unique_parent_candidate
from sesslint.repair.recipes_conservative import (
    PreconditionFailed,
    apply_proven_unique_parent_restore,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"


# ---------------------------------------------------------------------------
# 1. Compaction Segment Confinement Helper Tests
# ---------------------------------------------------------------------------


def test_same_compaction_segment_zero_boundaries() -> None:
    """Zero compaction boundaries in session means all event pairs are in the same segment."""
    events = [
        SessionEvent(
            id="e0", parent_id=None, seq=0, ts="2026-09-05T12:00:00Z", actor="user", kind="message"
        ),
        SessionEvent(
            id="e1",
            parent_id="e0",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="message",
        ),
        SessionEvent(
            id="e2", parent_id="e1", seq=2, ts="2026-09-05T12:00:02Z", actor="user", kind="message"
        ),
    ]
    assert same_compaction_segment(events, events[0], events[2]) is True
    assert same_compaction_segment(events, 0, 2) is True


def test_same_compaction_segment_strictly_between() -> None:
    """A compaction_boundary strictly between sequence numbers breaks segment confinement."""
    events = [
        SessionEvent(
            id="e0", parent_id=None, seq=0, ts="2026-09-05T12:00:00Z", actor="user", kind="message"
        ),
        SessionEvent(
            id="b1",
            parent_id="e0",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="system",
            kind="compaction_boundary",
        ),
        SessionEvent(
            id="e2",
            parent_id="b1",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="assistant",
            kind="message",
        ),
    ]
    # Spanning across boundary at seq=1
    assert same_compaction_segment(events, events[0], events[2]) is False
    assert same_compaction_segment(events, 0, 2) is False

    # Adjacent pair e0 and b1 does not have any boundary strictly between
    assert same_compaction_segment(events, events[0], events[1]) is True
    # Adjacent pair b1 and e2 does not have any boundary strictly between
    assert same_compaction_segment(events, events[1], events[2]) is True


def test_same_compaction_segment_boundary_at_endpoints() -> None:
    """Boundary at an endpoint does not violate strictly-between confinement."""
    events = [
        SessionEvent(
            id="b0",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="system",
            kind="compaction_boundary",
        ),
        SessionEvent(
            id="e1", parent_id="b0", seq=1, ts="2026-09-05T12:00:01Z", actor="user", kind="message"
        ),
        SessionEvent(
            id="b2",
            parent_id="e1",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="system",
            kind="compaction_boundary",
        ),
    ]
    # Endpoint at seq 0 or seq 2 is not strictly between
    assert same_compaction_segment(events, events[0], events[1]) is True
    assert same_compaction_segment(events, events[1], events[2]) is True


def test_same_compaction_segment_dict_events_and_indices() -> None:
    """Dictionary inputs and missing seq fields fall back to index-based intervals."""
    events = [
        {"id": "d0", "kind": "message"},
        {"id": "d1", "kind": "compaction_boundary"},
        {"id": "d2", "kind": "message"},
    ]
    assert same_compaction_segment(events, 0, 2) is False
    assert same_compaction_segment(events, 0, 1) is True
    assert same_compaction_segment(events, 1, 2) is True


# ---------------------------------------------------------------------------
# 2. Candidate Qualification Predicate Unit Tests
# ---------------------------------------------------------------------------


def test_is_qualifying_parent_candidate_rules() -> None:
    """Test individual confinement rules in candidate qualification."""
    events = [
        {"id": "p-exact", "parent_id": None, "seq": 0, "branch_id": "main"},
        {"id": "child", "parent_id": "p-exact", "seq": 1, "branch_id": "main"},
    ]
    cand = events[0]
    child = events[1]

    # 1. Exact equality passes
    qualifies, reason = is_qualifying_parent_candidate(cand, child, events, "p-exact")
    assert qualifies is True
    assert reason == "ok"

    # 2. Self candidate rejected
    qualifies, reason = is_qualifying_parent_candidate(child, child, events, "child")
    assert qualifies is False
    assert reason == "self_candidate"

    # 3. No full match rejected (prefix not enough)
    qualifies, reason = is_qualifying_parent_candidate(cand, child, events, "p-")
    assert qualifies is False
    assert reason == "no_full_match"

    # 4. Cross branch rejected
    cand_other_branch = {"id": "p-exact", "parent_id": None, "seq": 0, "branch_id": "other"}
    qualifies, reason = is_qualifying_parent_candidate(cand_other_branch, child, events, "p-exact")
    assert qualifies is False
    assert reason == "cross_branch"

    # 5. Cross segment rejected
    events_seg = [
        {"id": "p-exact", "parent_id": None, "seq": 0, "branch_id": "main"},
        {"id": "b", "kind": "compaction_boundary", "seq": 1, "branch_id": "main"},
        {"id": "child", "parent_id": "p-exact", "seq": 2, "branch_id": "main"},
    ]
    qualifies, reason = is_qualifying_parent_candidate(
        events_seg[0], events_seg[2], events_seg, "p-exact"
    )
    assert qualifies is False
    assert reason == "cross_segment"


# ---------------------------------------------------------------------------
# 3. Adversarial Decoy Scenario A: Prefix-Collision Decoy
# ---------------------------------------------------------------------------


def test_adversarial_decoy_prefix_collision() -> None:
    """Prefix collision decoy: shares prefix but not exact ID -> MANUAL, 0 plan steps."""
    fixture_path = FIXTURES_DIR / "checks" / "sl004_prefix_collision.json"
    event_list, load_findings = load_canonical(fixture_path)
    assert not load_findings

    # 1. Detector layer
    findings = check_missing_parent(event_list)
    assert len(findings) == 1
    f = findings[0]
    assert f.code == SL004
    assert f.severity == Severity.ERROR
    assert f.repairability == Repairability.MANUAL

    ev = cast(dict[str, Any], f.evidence)
    assert ev["match_rule"] == "full-equality"
    assert ev["candidate_count"] == 0
    assert ev["reason"] == "no_full_match"
    assert len(ev["rejected_decoys"]) == 1
    assert ev["rejected_decoys"][0]["reason"] == "no_full_match"

    # 2. Planner layer
    p = plan([f], event_list)
    assert len(p.steps) == 0
    assert len(p.blocked) == 1
    assert p.blocked[0].code == "SL004"
    assert p.blocked[0].reason == "repairability-manual"

    # 3. Precondition layer
    ctx = PreconditionContext(
        findings=[f],
        events=event_list,
        profile="neutral",
        source_hash="",
        finding=f,
    )
    assert unique_parent_candidate(ctx) is False

    # 4. Apply layer direct invocation fails closed
    step = PlanStep(
        seq=0,
        recipe="proven-unique-parent-restore",
        target_finding_fp=f.fingerprint,
        target_index=ev["index"],
        params={"parent_id": ev["parent_id"]},
    )
    with pytest.raises(PreconditionFailed, match="zero candidates"):
        apply_proven_unique_parent_restore(event_list, step)


# ---------------------------------------------------------------------------
# 4. Adversarial Decoy Scenario B: Cross-Branch Decoy
# ---------------------------------------------------------------------------


def test_adversarial_decoy_cross_branch() -> None:
    """Cross-branch decoy: exact ID match on different branch -> MANUAL, 0 plan steps."""
    fixture_path = FIXTURES_DIR / "repair" / "recipe_parent_restore_cross_branch.json"
    with open(fixture_path, encoding="utf-8") as fh:
        data = json.load(fh)

    scenario = data["refusal_cross_branch"]
    events = scenario["input_events"]
    step = PlanStep(
        seq=scenario["step"]["seq"],
        recipe=scenario["step"]["recipe"],
        target_finding_fp=scenario["step"]["target_finding_fp"],
        target_index=scenario["step"]["target_index"],
        params=scenario["step"]["params"],
    )

    # 1. Direct apply re-verifies and refuses
    with pytest.raises(PreconditionFailed, match="cross_branch"):
        apply_proven_unique_parent_restore(events, step)

    # 2. Precondition layer returns False
    f = make_finding(
        code=SL004,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Missing parent reference for record {record_id}",
        source=SourceRef(path="<canonical>", line=None, record_id="node-child-fork"),
        evidence={
            "id": "node-child-fork",
            "index": 1,
            "parent_id": "node-target",
            "match_rule": "full-equality",
            "confinement": {"branch": False, "segment": True},
            "candidate_count": 0,
            "reason": "cross_branch",
        },
    )
    ctx = PreconditionContext(
        findings=[f],
        events=events,
        profile="neutral",
        source_hash="",
        finding=f,
    )
    assert unique_parent_candidate(ctx) is False

    # 3. Planner blocks manual finding with 0 steps
    p = plan([f], events)
    assert len(p.steps) == 0
    assert p.blocked[0].reason == "repairability-manual"


# ---------------------------------------------------------------------------
# 5. Adversarial Decoy Scenario C: Cross-Segment Decoy
# ---------------------------------------------------------------------------


def test_adversarial_decoy_cross_segment() -> None:
    """Cross-segment decoy: intervening compaction boundary -> MANUAL, 0 plan steps."""
    fixture_path = FIXTURES_DIR / "checks" / "sl004_cross_segment_decoy.json"
    event_list, load_findings = load_canonical(fixture_path)
    assert not load_findings

    # 1. Detector layer
    findings = check_missing_parent(event_list)
    assert len(findings) == 1
    f = findings[0]
    assert f.code == SL004
    assert f.repairability == Repairability.MANUAL

    # 2. Shared candidate qualification helper rejects across boundary
    qualifying, rejected, conf, reason = find_qualifying_parent_candidates(
        events=event_list,
        child=event_list[2],
        target_idx=2,
        missing_parent_id="msg-seg-parent",
    )
    assert len(qualifying) == 0
    assert conf["segment"] is False
    assert reason == "cross_segment"

    # 3. Apply layer raises PreconditionFailed
    step = PlanStep(
        seq=0,
        recipe="proven-unique-parent-restore",
        target_finding_fp=f.fingerprint,
        target_index=2,
        params={"parent_id": "msg-seg-parent"},
    )
    with pytest.raises(PreconditionFailed, match="cross_segment"):
        apply_proven_unique_parent_restore(event_list, step)


# ---------------------------------------------------------------------------
# 6. Adversarial Decoy Scenario D: Duplicate-Candidate Ambiguity
# ---------------------------------------------------------------------------


def test_adversarial_decoy_duplicate_candidates() -> None:
    """Duplicate candidate decoy: multiple candidates with exact match -> MANUAL, 0 plan steps."""
    fixture_path = FIXTURES_DIR / "repair" / "recipe_parent_restore.json"
    with open(fixture_path, encoding="utf-8") as fh:
        data = json.load(fh)

    scenario = data["refusal_ambiguous"]
    events = scenario["input_events"]
    step = PlanStep(
        seq=scenario["step"]["seq"],
        recipe=scenario["step"]["recipe"],
        target_finding_fp=scenario["step"]["target_finding_fp"],
        target_index=scenario["step"]["target_index"],
        params=scenario["step"]["params"],
    )

    # 1. Shared helper evaluates candidate_count = 2
    qualifying, rejected, conf, reason = find_qualifying_parent_candidates(
        events=events,
        child=events[2],
        target_idx=2,
        missing_parent_id="msg-parent-ambig",
    )
    assert len(qualifying) == 2
    assert reason == "ambiguous"

    # 2. Apply layer raises PreconditionFailed naming ambiguity
    with pytest.raises(PreconditionFailed, match="ambiguous candidates"):
        apply_proven_unique_parent_restore(events, step)

    # 3. Precondition layer returns False
    f = make_finding(
        code=SL004,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Missing parent reference for record {record_id}",
        source=SourceRef(path="<canonical>", line=None, record_id="msg-child-3"),
        evidence={
            "id": "msg-child-3",
            "index": 2,
            "parent_id": "msg-parent-ambig",
            "match_rule": "full-equality",
            "candidate_count": 2,
            "reason": "ambiguous",
        },
    )
    ctx = PreconditionContext(
        findings=[f],
        events=events,
        profile="neutral",
        source_hash="",
        finding=f,
    )
    assert unique_parent_candidate(ctx) is False


# ---------------------------------------------------------------------------
# 7. Positive Exact-Match Test (Lifecycle: Plan -> Execute -> Verify)
# ---------------------------------------------------------------------------


def test_positive_exact_match_full_lifecycle(tmp_path: Path) -> None:
    """Positive exact match: single candidate passes confinement -> plan -> execute -> manifest."""
    events = [
        {
            "actor": "user",
            "branch_id": "main",
            "id": "msg-parent-exact",
            "kind": "message",
            "parent_id": None,
            "payload": {"text": "Original prompt"},
            "seq": 0,
            "ts": "2026-09-05T12:00:00Z",
        },
        {
            "actor": "assistant",
            "branch_id": "main",
            "id": "msg-child-exact",
            "kind": "message",
            "parent_id": "msg-parent-broken",
            "payload": {"text": "Response needing parent reattach"},
            "seq": 1,
            "ts": "2026-09-05T12:00:01Z",
        },
    ]

    # 1. Evaluate shared qualification predicate
    qualifying, rejected, conf, reason = find_qualifying_parent_candidates(
        events=events,
        child=events[1],
        target_idx=1,
        missing_parent_id="msg-parent-exact",
    )
    assert len(qualifying) == 1
    assert qualifying[0] == 0
    assert conf["branch"] is True
    assert conf["segment"] is True
    assert reason == "ok"

    # 2. Form deterministic finding
    f = make_finding(
        code=SL004,
        severity=Severity.ERROR,
        repairability=Repairability.DETERMINISTIC,
        message_template="Missing parent reference for record {record_id}",
        source=SourceRef(path="<canonical>", line=None, record_id="msg-child-exact"),
        evidence={
            "id": "msg-child-exact",
            "index": 1,
            "parent_id": "msg-parent-exact",
            "match_rule": "full-equality",
            "confinement": conf,
            "candidate_count": 1,
            "reason": "ok",
        },
    )

    # 3. Plan repair
    repair_plan = plan([f], events)
    assert len(repair_plan.steps) == 1
    step = repair_plan.steps[0]
    assert step.recipe == "proven-unique-parent-restore"
    assert step.target_index == 1
    assert step.params.get("parent_id") == "msg-parent-exact"

    # 4. Write session file for execute
    source_file = tmp_path / "session.jsonl"
    with open(source_file, "w", encoding="utf-8") as fh:
        header = {
            "schema_version": "sesslint.session/v1",
            "session_id": "sess-exact-test",
            "created_at": "2026-09-05T12:00:00Z",
        }
        fh.write(json.dumps(header) + "\n")
        for ev in events:
            fh.write(json.dumps(ev) + "\n")

    output_file = tmp_path / "repaired.jsonl"
    manifest_file = tmp_path / "repaired.jsonl.manifest.json"

    # 5. Execute repair plan
    manifest = execute(
        source_path=source_file,
        plan=repair_plan,
        output_path=output_file,
        policy="conservative",
    )

    # 6. Verify manifest and atomic output
    assert output_file.is_file()
    assert manifest_file.is_file()
    assert len(manifest.actions) == 1
    assert manifest.actions[0].kind == "proven-unique-parent-restore"
    assert manifest.policy == "conservative"
    assert "proven-unique-parent-restore" in manifest.recipe_versions

    # 7. Verify repaired content has parent_id bound to exact parent
    repaired_lines = [
        json.loads(line) for line in output_file.read_text(encoding="utf-8").strip().split("\n")
    ]
    assert len(repaired_lines) == 3  # header + 2 events
    repaired_child = repaired_lines[2]
    assert repaired_child["id"] == "msg-child-exact"
    assert repaired_child["parent_id"] == "msg-parent-exact"
