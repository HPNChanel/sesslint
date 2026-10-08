"""B20: validate untrusted repair plans against current source-derived findings."""

from __future__ import annotations

import json
from collections.abc import Sequence

from sesslint.canonical import SessionEvent
from sesslint.finding import Finding
from sesslint.repair.planner import PlanStep, RepairPlan
from sesslint.repair.planner import plan as planner_plan


def _plan_step_identity(step: PlanStep) -> str:
    """Everything a step does, minus its position (``seq``), as canonical JSON."""
    body = {k: v for k, v in step.to_dict().items() if k != "seq"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def vet_plan(
    supplied: RepairPlan,
    *,
    findings: Sequence[Finding],
    events: Sequence[SessionEvent],
    source_hash: str,
    acknowledge_side_effects: bool,
    input_format: str,
) -> None:
    """Refuse a supplied plan unless each step is one the planner derives now (B20).

    Exported plans are untrusted even when their fingerprint verifies (it is a
    plain digest anyone can recompute). Every step must target a finding the
    current source still has, through the recipe, params, and loss the planner
    itself derives for it, in the planner's order; a plan may apply a subset.
    Finding fingerprints include the source file name, so a plan applies only
    to the file (name and bytes) it was exported from.
    """
    from sesslint.repair.errors import PlanSourceMismatch, RepairRefused
    from sesslint.repair.planner import compute_events_source_hash

    if supplied.source_hash not in (source_hash, compute_events_source_hash(events)):
        raise PlanSourceMismatch(
            f"Plan source_hash mismatch: plan '{supplied.source_hash}' matches neither "
            f"source file SHA-256 ('{source_hash}') nor the source events hash"
        )
    expected = planner_plan(
        findings=findings,
        events=events,
        profile=supplied.profile,
        policy=supplied.policy,
        source_hash=supplied.source_hash,
        acknowledge_side_effects=acknowledge_side_effects,
        input_format=input_format,
    )
    positions: dict[str, list[int]] = {}
    for idx, step in enumerate(expected.steps):
        positions.setdefault(_plan_step_identity(step), []).append(idx)
    previous = -1
    for step in sorted(supplied.steps, key=lambda s: s.seq):
        later = [i for i in positions.get(_plan_step_identity(step), ()) if i > previous]
        if not later:
            raise RepairRefused(
                f"Plan step {step.seq} (recipe '{step.recipe}') is not a repair sesslint "
                "derives for this source now; export the plan from this exact file (same "
                "name and bytes) with this sesslint version"
            )
        previous = later[0]
