# Challenger stress tests for DEV-002: Harden proven-unique-parent-restore

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sesslint.codes import SL004, Repairability, Severity
from sesslint.finding import SourceRef, make_finding
from sesslint.repair.errors import OutputInvalid, PlanSourceMismatch, PlanTampered
from sesslint.repair.executor import execute
from sesslint.repair.fingerprint import compute_plan_fingerprint
from sesslint.repair.planner import PlanStep, plan
from sesslint.repair.recipes_conservative import (
    PreconditionFailed,
    apply_proven_unique_parent_restore,
)

# ===========================================================================
# SUITE 1: Defense-in-depth against malicious/forged plan steps
# ===========================================================================


def test_forged_step_nonexistent_parent() -> None:
    events = [
        {"id": "e0", "parent_id": None, "seq": 0, "branch_id": "main", "kind": "message"},
        {"id": "e1", "parent_id": "missing-p", "seq": 1, "branch_id": "main", "kind": "message"},
    ]
    step = PlanStep(
        seq=0,
        recipe="proven-unique-parent-restore",
        target_finding_fp="fp-forged",
        target_index=1,
        params={"parent_id": "forged-nonexistent-id"},
    )
    with pytest.raises(PreconditionFailed, match="zero candidates matching"):
        apply_proven_unique_parent_restore(events, step)


def test_forged_step_prefix_collision() -> None:
    events = [
        {
            "id": "e0-prefix-extra",
            "parent_id": None,
            "seq": 0,
            "branch_id": "main",
            "kind": "message",
        },
        {"id": "e1", "parent_id": "e0", "seq": 1, "branch_id": "main", "kind": "message"},
    ]
    step = PlanStep(
        seq=0,
        recipe="proven-unique-parent-restore",
        target_finding_fp="fp-forged",
        target_index=1,
        params={"parent_id": "e0"},
    )
    with pytest.raises(PreconditionFailed, match="zero candidates matching"):
        apply_proven_unique_parent_restore(events, step)


def test_forged_step_cross_branch_candidate() -> None:
    events = [
        {
            "id": "parent-candidate",
            "parent_id": None,
            "seq": 0,
            "branch_id": "feature-a",
            "kind": "message",
        },
        {
            "id": "child-orphan",
            "parent_id": "broken",
            "seq": 1,
            "branch_id": "feature-b",
            "kind": "message",
        },
    ]
    step = PlanStep(
        seq=0,
        recipe="proven-unique-parent-restore",
        target_finding_fp="fp-forged",
        target_index=1,
        params={"parent_id": "parent-candidate"},
    )
    with pytest.raises(PreconditionFailed, match="cross_branch"):
        apply_proven_unique_parent_restore(events, step)


def test_forged_step_cross_segment_candidate() -> None:
    events = [
        {
            "id": "parent-candidate",
            "parent_id": None,
            "seq": 0,
            "branch_id": "main",
            "kind": "message",
        },
        {
            "id": "boundary-1",
            "parent_id": "parent-candidate",
            "seq": 1,
            "branch_id": "main",
            "kind": "compaction_boundary",
        },
        {
            "id": "child-orphan",
            "parent_id": "broken",
            "seq": 2,
            "branch_id": "main",
            "kind": "message",
        },
    ]
    step = PlanStep(
        seq=0,
        recipe="proven-unique-parent-restore",
        target_finding_fp="fp-forged",
        target_index=2,
        params={"parent_id": "parent-candidate"},
    )
    with pytest.raises(PreconditionFailed, match="cross_segment"):
        apply_proven_unique_parent_restore(events, step)


def test_forged_step_duplicate_candidate() -> None:
    events = [
        {"id": "ambig-parent", "parent_id": None, "seq": 0, "branch_id": "main", "kind": "message"},
        {"id": "ambig-parent", "parent_id": None, "seq": 1, "branch_id": "main", "kind": "message"},
        {
            "id": "child-orphan",
            "parent_id": "broken",
            "seq": 2,
            "branch_id": "main",
            "kind": "message",
        },
    ]
    step = PlanStep(
        seq=0,
        recipe="proven-unique-parent-restore",
        target_finding_fp="fp-forged",
        target_index=2,
        params={"parent_id": "ambig-parent"},
    )
    with pytest.raises(PreconditionFailed, match="ambiguous candidates"):
        apply_proven_unique_parent_restore(events, step)


def test_forged_step_self_reference() -> None:
    events = [
        {
            "id": "child-orphan",
            "parent_id": "broken",
            "seq": 0,
            "branch_id": "main",
            "kind": "message",
        },
    ]
    step = PlanStep(
        seq=0,
        recipe="proven-unique-parent-restore",
        target_finding_fp="fp-forged",
        target_index=0,
        params={"parent_id": "child-orphan"},
    )
    with pytest.raises(PreconditionFailed, match="zero candidates matching"):
        apply_proven_unique_parent_restore(events, step)


def test_forged_step_post_child_candidate_causal_inversion() -> None:
    events = [
        {
            "id": "child-orphan",
            "parent_id": "broken",
            "seq": 0,
            "branch_id": "main",
            "kind": "message",
        },
        {
            "id": "future-candidate",
            "parent_id": None,
            "seq": 1,
            "branch_id": "main",
            "kind": "message",
        },
    ]
    step = PlanStep(
        seq=0,
        recipe="proven-unique-parent-restore",
        target_finding_fp="fp-forged",
        target_index=0,
        params={"parent_id": "future-candidate"},
    )
    with pytest.raises(PreconditionFailed, match="zero candidates matching"):
        apply_proven_unique_parent_restore(events, step)


def test_forged_step_invalid_target_index() -> None:
    events = [
        {"id": "e0", "parent_id": None, "seq": 0, "branch_id": "main", "kind": "message"},
    ]
    for bad_idx in [-1, 999, "bad", True, False]:
        step = PlanStep(
            seq=0,
            recipe="proven-unique-parent-restore",
            target_finding_fp="fp-forged",
            target_index=bad_idx,  # type: ignore[arg-type]
            params={"parent_id": "e0"},
        )
        with pytest.raises(PreconditionFailed, match="missing or invalid target_index"):
            apply_proven_unique_parent_restore(events, step)


def test_forged_step_through_executor_lifecycle(tmp_path: Path) -> None:
    events = [
        {
            "actor": "user",
            "branch_id": "main",
            "id": "p0",
            "kind": "message",
            "parent_id": None,
            "payload": {},
            "seq": 0,
            "ts": "2026-09-05T12:00:00Z",
        },
        {
            "actor": "assistant",
            "branch_id": "feature-diff",
            "id": "c1",
            "kind": "message",
            "parent_id": "broken",
            "payload": {},
            "seq": 1,
            "ts": "2026-09-05T12:00:01Z",
        },
    ]
    src = tmp_path / "sess.jsonl"
    with open(src, "w", encoding="utf-8") as fh:
        fh.write(
            json.dumps(
                {
                    "schema_version": "sesslint.session/v1",
                    "session_id": "s1",
                    "created_at": "2026-09-05T12:00:00Z",
                }
            )
            + "\n"
        )
        for e in events:
            fh.write(json.dumps(e) + "\n")

    step = PlanStep(
        seq=0,
        recipe="proven-unique-parent-restore",
        target_finding_fp="fp0",
        target_index=1,
        params={"parent_id": "p0"},  # Cross branch!
    )
    src_bytes = src.read_bytes()
    import hashlib

    src_sha = hashlib.sha256(src_bytes).hexdigest()
    f_dummy = make_finding(
        code=SL004,
        severity=Severity.ERROR,
        repairability=Repairability.DETERMINISTIC,
        message_template="dummy",
        source=SourceRef(path="<canonical>", line=None, record_id="c1"),
        evidence={"id": "c1", "index": 1, "parent_id": "p0", "candidate_count": 1, "reason": "ok"},
    )
    base_plan = plan([f_dummy], events)
    object.__setattr__(base_plan, "steps", (step,))
    object.__setattr__(base_plan, "source_hash", src_sha)
    object.__setattr__(base_plan, "fingerprint", compute_plan_fingerprint(base_plan.to_dict()))
    plan_obj = base_plan

    out_file = tmp_path / "repaired.jsonl"
    with pytest.raises(OutputInvalid, match="cross_branch"):
        execute(
            source_path=src,
            plan=plan_obj,
            output_path=out_file,
            policy="conservative",
        )
    assert not out_file.exists()


# ===========================================================================
# SUITE 2: Event mutation between planning and application
# ===========================================================================


def test_events_mutated_in_memory_before_apply() -> None:
    _events = [
        {"id": "good-parent", "parent_id": None, "seq": 0, "branch_id": "main", "kind": "message"},
        {"id": "child", "parent_id": "broken", "seq": 1, "branch_id": "main", "kind": "message"},
    ]
    step = PlanStep(
        seq=0,
        recipe="proven-unique-parent-restore",
        target_finding_fp="fp-test",
        target_index=1,
        params={"parent_id": "good-parent"},
    )

    # Mutation A: candidate ID renamed
    mutated_events_a = [
        {
            "id": "tampered-parent",
            "parent_id": None,
            "seq": 0,
            "branch_id": "main",
            "kind": "message",
        },
        {"id": "child", "parent_id": "broken", "seq": 1, "branch_id": "main", "kind": "message"},
    ]
    with pytest.raises(PreconditionFailed, match="no_full_match"):
        apply_proven_unique_parent_restore(mutated_events_a, step)

    # Mutation B: compaction boundary inserted
    mutated_events_b = [
        {"id": "good-parent", "parent_id": None, "seq": 0, "branch_id": "main", "kind": "message"},
        {
            "id": "cb",
            "parent_id": "good-parent",
            "seq": 1,
            "branch_id": "main",
            "kind": "compaction_boundary",
        },
        {"id": "child", "parent_id": "broken", "seq": 2, "branch_id": "main", "kind": "message"},
    ]
    step_b = PlanStep(
        seq=0,
        recipe="proven-unique-parent-restore",
        target_finding_fp="fp-test",
        target_index=2,
        params={"parent_id": "good-parent"},
    )
    with pytest.raises(PreconditionFailed, match="cross_segment"):
        apply_proven_unique_parent_restore(mutated_events_b, step_b)

    # Mutation C: branch ID mutated
    mutated_events_c = [
        {
            "id": "good-parent",
            "parent_id": None,
            "seq": 0,
            "branch_id": "branch-x",
            "kind": "message",
        },
        {"id": "child", "parent_id": "broken", "seq": 1, "branch_id": "main", "kind": "message"},
    ]
    with pytest.raises(PreconditionFailed, match="cross_branch"):
        apply_proven_unique_parent_restore(mutated_events_c, step)


def test_disk_file_mutated_between_planning_and_execute(tmp_path: Path) -> None:
    events = [
        {
            "actor": "user",
            "branch_id": "main",
            "id": "p0",
            "kind": "message",
            "parent_id": None,
            "payload": {},
            "seq": 0,
            "ts": "2026-09-05T12:00:00Z",
        },
        {
            "actor": "assistant",
            "branch_id": "main",
            "id": "c1",
            "kind": "message",
            "parent_id": "broken",
            "payload": {},
            "seq": 1,
            "ts": "2026-09-05T12:00:01Z",
        },
    ]
    src = tmp_path / "sess.jsonl"
    with open(src, "w", encoding="utf-8") as fh:
        fh.write(
            json.dumps(
                {
                    "schema_version": "sesslint.session/v1",
                    "session_id": "s1",
                    "created_at": "2026-09-05T12:00:00Z",
                }
            )
            + "\n"
        )
        for e in events:
            fh.write(json.dumps(e) + "\n")

    f = make_finding(
        code=SL004,
        severity=Severity.ERROR,
        repairability=Repairability.DETERMINISTIC,
        message_template="Missing parent",
        source=SourceRef(path="<canonical>", line=None, record_id="c1"),
        evidence={"id": "c1", "index": 1, "parent_id": "p0", "candidate_count": 1, "reason": "ok"},
    )
    repair_plan = plan([f], events)

    # TOCTOU: Modify session file on disk!
    with open(src, "a", encoding="utf-8") as fh:
        fh.write(
            json.dumps(
                {
                    "actor": "user",
                    "branch_id": "main",
                    "id": "c2",
                    "kind": "message",
                    "parent_id": "c1",
                    "payload": {},
                    "seq": 2,
                    "ts": "2026-09-05T12:00:02Z",
                }
            )
            + "\n"
        )

    out_file = tmp_path / "repaired.jsonl"
    with pytest.raises(PlanSourceMismatch):
        execute(
            source_path=src,
            plan=repair_plan,
            output_path=out_file,
            policy="conservative",
        )
    assert not out_file.exists()


def test_plan_tampered_detected(tmp_path: Path) -> None:
    events = [
        {
            "actor": "user",
            "branch_id": "main",
            "id": "p0",
            "kind": "message",
            "parent_id": None,
            "payload": {},
            "seq": 0,
            "ts": "2026-09-05T12:00:00Z",
        },
        {
            "actor": "assistant",
            "branch_id": "main",
            "id": "c1",
            "kind": "message",
            "parent_id": "broken",
            "payload": {},
            "seq": 1,
            "ts": "2026-09-05T12:00:01Z",
        },
    ]
    src = tmp_path / "sess.jsonl"
    with open(src, "w", encoding="utf-8") as fh:
        fh.write(
            json.dumps(
                {
                    "schema_version": "sesslint.session/v1",
                    "session_id": "s1",
                    "created_at": "2026-09-05T12:00:00Z",
                }
            )
            + "\n"
        )
        for e in events:
            fh.write(json.dumps(e) + "\n")

    f = make_finding(
        code=SL004,
        severity=Severity.ERROR,
        repairability=Repairability.DETERMINISTIC,
        message_template="Missing parent",
        source=SourceRef(path="<canonical>", line=None, record_id="c1"),
        evidence={"id": "c1", "index": 1, "parent_id": "p0", "candidate_count": 1, "reason": "ok"},
    )
    repair_plan = plan([f], events)

    # Tamper with the plan step without updating fingerprint!
    tampered_steps = [
        PlanStep(
            seq=0,
            recipe="proven-unique-parent-restore",
            target_finding_fp=repair_plan.steps[0].target_finding_fp,
            target_index=1,
            params={"parent_id": "forged_p"},
        )
    ]
    object.__setattr__(repair_plan, "steps", tampered_steps)

    out_file = tmp_path / "repaired.jsonl"
    with pytest.raises(PlanTampered):
        execute(
            source_path=src,
            plan=repair_plan,
            output_path=out_file,
            policy="conservative",
        )


# ===========================================================================
# SUITE 3: Multiple SL004 findings in a session
# ===========================================================================


def test_multiple_independent_sl004_findings(tmp_path: Path) -> None:
    events = [
        {
            "actor": "user",
            "branch_id": "main",
            "id": "p0",
            "kind": "message",
            "parent_id": None,
            "payload": {},
            "seq": 0,
            "ts": "2026-09-05T12:00:00Z",
        },
        {
            "actor": "assistant",
            "branch_id": "main",
            "id": "c1",
            "kind": "message",
            "parent_id": "broken1",
            "payload": {},
            "seq": 1,
            "ts": "2026-09-05T12:00:01Z",
        },
        {
            "actor": "user",
            "branch_id": "main",
            "id": "p2",
            "kind": "message",
            "parent_id": "c1",
            "payload": {},
            "seq": 2,
            "ts": "2026-09-05T12:00:02Z",
        },
        {
            "actor": "assistant",
            "branch_id": "main",
            "id": "c3",
            "kind": "message",
            "parent_id": "broken2",
            "payload": {},
            "seq": 3,
            "ts": "2026-09-05T12:00:03Z",
        },
    ]
    f1 = make_finding(
        code=SL004,
        severity=Severity.ERROR,
        repairability=Repairability.DETERMINISTIC,
        message_template="Missing parent",
        source=SourceRef(path="<canonical>", line=None, record_id="c1"),
        evidence={"id": "c1", "index": 1, "parent_id": "p0", "candidate_count": 1, "reason": "ok"},
    )
    f2 = make_finding(
        code=SL004,
        severity=Severity.ERROR,
        repairability=Repairability.DETERMINISTIC,
        message_template="Missing parent",
        source=SourceRef(path="<canonical>", line=None, record_id="c3"),
        evidence={"id": "c3", "index": 3, "parent_id": "p2", "candidate_count": 1, "reason": "ok"},
    )

    repair_plan = plan([f1, f2], events)
    assert len(repair_plan.steps) == 2
    assert repair_plan.steps[0].target_index == 1
    assert repair_plan.steps[0].params.get("parent_id") == "p0"
    assert repair_plan.steps[1].target_index == 3
    assert repair_plan.steps[1].params.get("parent_id") == "p2"

    src = tmp_path / "sess_multi.jsonl"
    with open(src, "w", encoding="utf-8") as fh:
        fh.write(
            json.dumps(
                {
                    "schema_version": "sesslint.session/v1",
                    "session_id": "s_multi",
                    "created_at": "2026-09-05T12:00:00Z",
                }
            )
            + "\n"
        )
        for e in events:
            fh.write(json.dumps(e) + "\n")

    out_file = tmp_path / "repaired_multi.jsonl"
    manifest = execute(
        source_path=src,
        plan=repair_plan,
        output_path=out_file,
        policy="conservative",
    )
    assert len(manifest.actions) == 2
    repaired_lines = [
        json.loads(line) for line in out_file.read_text(encoding="utf-8").strip().split("\n")
    ]
    assert repaired_lines[2]["parent_id"] == "p0"
    assert repaired_lines[4]["parent_id"] == "p2"


def test_mixed_deterministic_and_manual_sl004_no_crosstalk() -> None:
    events = [
        {"id": "p0", "parent_id": None, "seq": 0, "branch_id": "main", "kind": "message"},
        {"id": "c1", "parent_id": "broken1", "seq": 1, "branch_id": "main", "kind": "message"},
        {
            "id": "p2_cb",
            "parent_id": "c1",
            "seq": 2,
            "branch_id": "other_branch",
            "kind": "message",
        },
        {"id": "c3", "parent_id": "broken2", "seq": 3, "branch_id": "main", "kind": "message"},
    ]
    f_det = make_finding(
        code=SL004,
        severity=Severity.ERROR,
        repairability=Repairability.DETERMINISTIC,
        message_template="Missing parent",
        source=SourceRef(path="<canonical>", line=None, record_id="c1"),
        evidence={"id": "c1", "index": 1, "parent_id": "p0", "candidate_count": 1, "reason": "ok"},
    )
    f_manual = make_finding(
        code=SL004,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Missing parent",
        source=SourceRef(path="<canonical>", line=None, record_id="c3"),
        evidence={
            "id": "c3",
            "index": 3,
            "parent_id": "p2_cb",
            "candidate_count": 0,
            "reason": "cross_branch",
        },
    )

    repair_plan = plan([f_det, f_manual], events)
    assert len(repair_plan.steps) == 1
    assert repair_plan.steps[0].target_index == 1
    assert len(repair_plan.blocked) == 1
    assert repair_plan.blocked[0].reason == "repairability-manual"
    assert repair_plan.blocked[0].finding_fp == f_manual.fingerprint


def test_multiple_children_sharing_same_parent() -> None:
    events = [
        {
            "id": "shared-parent",
            "parent_id": None,
            "seq": 0,
            "branch_id": "main",
            "kind": "message",
        },
        {"id": "child1", "parent_id": "broken", "seq": 1, "branch_id": "main", "kind": "message"},
        {"id": "child2", "parent_id": "broken", "seq": 2, "branch_id": "main", "kind": "message"},
    ]
    f1 = make_finding(
        code=SL004,
        severity=Severity.ERROR,
        repairability=Repairability.DETERMINISTIC,
        message_template="Missing parent",
        source=SourceRef(path="<canonical>", line=None, record_id="child1"),
        evidence={
            "id": "child1",
            "index": 1,
            "parent_id": "shared-parent",
            "candidate_count": 1,
            "reason": "ok",
        },
    )
    f2 = make_finding(
        code=SL004,
        severity=Severity.ERROR,
        repairability=Repairability.DETERMINISTIC,
        message_template="Missing parent",
        source=SourceRef(path="<canonical>", line=None, record_id="child2"),
        evidence={
            "id": "child2",
            "index": 2,
            "parent_id": "shared-parent",
            "candidate_count": 1,
            "reason": "ok",
        },
    )
    repair_plan = plan([f1, f2], events)
    assert len(repair_plan.steps) == 2

    applied = events
    for st in repair_plan.steps:
        applied = apply_proven_unique_parent_restore(applied, st)

    assert applied[1]["parent_id"] == "shared-parent"
    assert applied[2]["parent_id"] == "shared-parent"


# ===========================================================================
# SUITE 4: Advanced edge cases, parameter corruption & chained parents
# ===========================================================================


def test_chained_missing_parents_handling() -> None:
    # Event 0 is Root.
    # Event 1 is Child 1 whose parent is Root.
    # Event 2 is Child 2 whose parent is Child 1.
    events = [
        {"id": "root", "parent_id": None, "seq": 0, "branch_id": "main", "kind": "message"},
        {
            "id": "child1",
            "parent_id": "missing_root",
            "seq": 1,
            "branch_id": "main",
            "kind": "message",
        },
        {
            "id": "child2",
            "parent_id": "missing_child1",
            "seq": 2,
            "branch_id": "main",
            "kind": "message",
        },
    ]

    f1 = make_finding(
        code=SL004,
        severity=Severity.ERROR,
        repairability=Repairability.DETERMINISTIC,
        message_template="Missing parent",
        source=SourceRef(path="<canonical>", line=None, record_id="child1"),
        evidence={
            "id": "child1",
            "index": 1,
            "parent_id": "root",
            "candidate_count": 1,
            "reason": "ok",
        },
    )
    f2 = make_finding(
        code=SL004,
        severity=Severity.ERROR,
        repairability=Repairability.DETERMINISTIC,
        message_template="Missing parent",
        source=SourceRef(path="<canonical>", line=None, record_id="child2"),
        evidence={
            "id": "child2",
            "index": 2,
            "parent_id": "child1",
            "candidate_count": 1,
            "reason": "ok",
        },
    )

    repair_plan = plan([f1, f2], events)
    assert len(repair_plan.steps) == 2

    # Step 0 repairs child1 -> root
    # Step 1 repairs child2 -> child1
    applied = events
    for step in repair_plan.steps:
        applied = apply_proven_unique_parent_restore(applied, step)

    assert applied[1]["parent_id"] == "root"
    assert applied[2]["parent_id"] == "child1"


def test_corrupted_params_variations() -> None:
    events = [
        {"id": "p0", "parent_id": None, "seq": 0, "branch_id": "main", "kind": "message"},
        {"id": "c1", "parent_id": None, "seq": 1, "branch_id": "main", "kind": "message"},
    ]

    # Empty parent_id in params and in child
    step_empty = PlanStep(
        seq=0,
        recipe="proven-unique-parent-restore",
        target_finding_fp="fp",
        target_index=1,
        params={"parent_id": ""},
    )
    with pytest.raises(PreconditionFailed, match="missing parent_id"):
        apply_proven_unique_parent_restore(events, step_empty)

    # Missing params / None
    step_none = PlanStep(
        seq=0,
        recipe="proven-unique-parent-restore",
        target_finding_fp="fp",
        target_index=1,
        params={},
    )
    with pytest.raises(PreconditionFailed, match="missing parent_id"):
        apply_proven_unique_parent_restore(events, step_none)


def test_multi_finding_scale_and_order_preservation(tmp_path: Path) -> None:
    # 20 pairs of (parent, child) in a single session
    events: list[dict[str, Any]] = []
    findings = []
    for i in range(20):
        p_idx = 2 * i
        c_idx = 2 * i + 1
        p_id = f"parent_{i}"
        c_id = f"child_{i}"
        events.append(
            {
                "actor": "user",
                "branch_id": "main",
                "id": p_id,
                "kind": "message",
                "parent_id": None if i == 0 else f"child_{i - 1}",
                "payload": {},
                "seq": p_idx,
                "ts": f"2026-09-05T12:{i:02d}:00Z",
            }
        )
        events.append(
            {
                "actor": "assistant",
                "branch_id": "main",
                "id": c_id,
                "kind": "message",
                "parent_id": "unlinked",
                "payload": {},
                "seq": c_idx,
                "ts": f"2026-09-05T12:{i:02d}:01Z",
            }
        )

        f = make_finding(
            code=SL004,
            severity=Severity.ERROR,
            repairability=Repairability.DETERMINISTIC,
            message_template="Missing parent",
            source=SourceRef(path="<canonical>", line=None, record_id=c_id),
            evidence={
                "id": c_id,
                "index": c_idx,
                "parent_id": p_id,
                "candidate_count": 1,
                "reason": "ok",
            },
        )
        findings.append(f)

    repair_plan = plan(findings, events)
    assert len(repair_plan.steps) == 20

    src = tmp_path / "scale_sess.jsonl"
    with open(src, "w", encoding="utf-8") as fh:
        fh.write(
            json.dumps(
                {
                    "schema_version": "sesslint.session/v1",
                    "session_id": "scale_sess",
                    "created_at": "2026-09-05T12:00:00Z",
                }
            )
            + "\n"
        )
        for e in events:
            fh.write(json.dumps(e) + "\n")

    out_file = tmp_path / "repaired_scale.jsonl"
    manifest = execute(
        source_path=src,
        plan=repair_plan,
        output_path=out_file,
        policy="conservative",
    )
    assert len(manifest.actions) == 20
    repaired_lines = [
        json.loads(line) for line in out_file.read_text(encoding="utf-8").strip().split("\n")
    ]
    for i in range(20):
        c_line = repaired_lines[1 + 2 * i + 1]
        assert c_line["id"] == f"child_{i}"
        assert c_line["parent_id"] == f"parent_{i}"
