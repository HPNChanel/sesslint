"""Salvage repair recipe pack (TASK-020).

This module implements the four lossy salvage repair recipes as pure event-list
transforms under explicit opt-in policy:
1. unresolvable-branch-amputate: drop a weakly-connected parent component that contains
   an SL006 disconnected branch or SL005 fatal cycle with no checkpoints.
2. torn-compaction-project: project across a compaction boundary splitting tool pairs
   by dropping the boundary plus the minority side's orphaned halves.
3. side-effect-unknown-truncate: truncate session at the first tool event having
   side_effects != 'none' when acknowledged by the operator.
4. orphan-result-drop: drop a single SL101 orphan tool_result record when the
   operator explicitly accepts that the record may be the sole evidence of a
   completed external action.

Guarantees:
- Zero I/O, zero disk access, zero network calls.
- Pure functions: inputs are deep-copied and never mutated.
- Strict gating on explicit 'salvage' policy opt-in.
- PreconditionFailed raised on invalid direct application.
- No-synthetic-success: never fabricates tool results or success states.
- Vendor-free: operates strictly on canonical event dictionaries.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Final

from sesslint._events import (
    _copy_events_as_dicts,
    _event_corr_id,
    _event_id,
    _event_kind,
    _event_parent_id,
    _to_event_dict,
)
from sesslint.codes import SL005, SL006, SL101, SL102, SL108
from sesslint.policy.abstention import AffectedRegion
from sesslint.repair.planner import PlanStep
from sesslint.repair.preconditions import (
    PreconditionContext,
    _find_component_indices,
    _find_torn_compaction_dropped_indices,
    register_precondition,
)
from sesslint.repair.recipes_conservative import PreconditionFailed
from sesslint.repair.registry import Recipe, get_recipe, register_recipe

_TOOL_KINDS: Final[frozenset[str]] = frozenset({"tool_call", "tool_use", "tool_result"})
MAX_COMPONENT_SIZE: Final[int] = 10_000


# ---------------------------------------------------------------------------
# 1. Unresolvable Branch Amputate
# ---------------------------------------------------------------------------


def apply_unresolvable_branch_amputate_with_loss(
    events: Sequence[Any],
    step: PlanStep,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Drop weakly-connected parent component containing fork or fatal cycle.

    Raises:
        PreconditionFailed: If target index is missing/invalid, component contains
            checkpoints, component exceeds 10k events, or amputation drops entire session.
    """
    if not events:
        raise PreconditionFailed("Cannot amputate an empty session")

    seed_idx = step.target_index
    if seed_idx is None and step.params:
        root_id = step.params.get("root_id") or step.params.get("record_id")
        if root_id is not None:
            root_id_str = str(root_id)
            for i, ev in enumerate(events):
                if _event_id(ev) == root_id_str:
                    seed_idx = i
                    break

    if seed_idx is None or seed_idx < 0 or seed_idx >= len(events):
        raise PreconditionFailed(f"Invalid target_index {seed_idx!r} for amputation")

    component_indices = _find_component_indices(events, seed_idx)

    if len(component_indices) > MAX_COMPONENT_SIZE:
        raise PreconditionFailed(
            f"Component size ({len(component_indices)}) exceeds limit of {MAX_COMPONENT_SIZE}"
        )

    for idx in component_indices:
        if _event_kind(events[idx]) == "checkpoint":
            raise PreconditionFailed("Branch contains a checkpoint; cannot amputate")

    if len(component_indices) >= len(events):
        raise PreconditionFailed("Amputating entire session is forbidden")

    out: list[dict[str, Any]] = []
    for idx, ev in enumerate(events):
        if idx not in component_indices:
            out.append(_to_event_dict(ev))

    dropped_count = len(component_indices)
    loss_delta = {"amputated-branch": dropped_count}
    return out, loss_delta


def apply_unresolvable_branch_amputate(
    events: Sequence[Any],
    step: PlanStep,
) -> list[dict[str, Any]]:
    """Drop weakly-connected parent component (019-compatible signature returning list)."""
    transformed, _ = apply_unresolvable_branch_amputate_with_loss(events, step)
    return transformed


# ---------------------------------------------------------------------------
# 2. Torn Compaction Project
# ---------------------------------------------------------------------------


def apply_torn_compaction_project_with_loss(
    events: Sequence[Any],
    step: PlanStep,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Project across compaction boundary by dropping boundary and minority orphaned halves.

    Raises:
        PreconditionFailed: If target is not a compaction_boundary or boundary splits no pairs.
    """
    if not events:
        raise PreconditionFailed("Cannot project across compaction in empty session")

    boundary_idx = step.target_index
    if boundary_idx is None and step.params:
        boundary_idx = step.params.get("boundary_index")

    if boundary_idx is None or boundary_idx < 0 or boundary_idx >= len(events):
        # Fallback: search for unique compaction_boundary in events
        boundaries = [i for i, e in enumerate(events) if _event_kind(e) == "compaction_boundary"]
        if len(boundaries) == 1:
            boundary_idx = boundaries[0]
        else:
            raise PreconditionFailed(f"Invalid compaction boundary index {boundary_idx!r}")

    if _event_kind(events[boundary_idx]) != "compaction_boundary":
        raise PreconditionFailed(f"Event at index {boundary_idx} is not a compaction_boundary")

    try:
        dropped_indices = _find_torn_compaction_dropped_indices(events, boundary_idx)
    except ValueError as err:
        raise PreconditionFailed(str(err)) from err

    out: list[dict[str, Any]] = []
    for idx, ev in enumerate(events):
        if idx not in dropped_indices:
            out.append(_to_event_dict(ev))

    loss_delta = {"projected-orphans": len(dropped_indices)}
    return out, loss_delta


def apply_torn_compaction_project(
    events: Sequence[Any],
    step: PlanStep,
) -> list[dict[str, Any]]:
    """Project across compaction boundary (019-compatible signature returning list)."""
    transformed, _ = apply_torn_compaction_project_with_loss(events, step)
    return transformed


# ---------------------------------------------------------------------------
# 3. Side Effect Unknown Truncate
# ---------------------------------------------------------------------------


def apply_side_effect_unknown_truncate_with_loss(
    events: Sequence[Any],
    step: PlanStep,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Truncate session at the first unsafe tool event.

    Raises:
        PreconditionFailed: If cut index <= 0 or out of bounds.
    """
    if not events:
        raise PreconditionFailed("Cannot truncate an empty session")

    cut = step.target_index
    if cut is None and step.params:
        cut = step.params.get("first_unsafe_index") or step.params.get("cut_index")

    if cut is None:
        raise PreconditionFailed("Truncate recipe requires a valid target_index")

    if cut <= 0:
        raise PreconditionFailed(
            f"Cannot truncate at index {cut}: would empty or violate session root"
        )

    if cut >= len(events):
        raise PreconditionFailed(
            f"Cut index {cut} is out of bounds for session of length {len(events)}"
        )

    out = _copy_events_as_dicts(events[:cut])
    dropped_count = len(events) - cut
    loss_delta = {"truncated-side-effects": dropped_count}
    return out, loss_delta


def apply_side_effect_unknown_truncate(
    events: Sequence[Any],
    step: PlanStep,
) -> list[dict[str, Any]]:
    """Truncate session at unsafe tool event (019-compatible signature returning list)."""
    transformed, _ = apply_side_effect_unknown_truncate_with_loss(events, step)
    return transformed


# ---------------------------------------------------------------------------
# 4. Orphan Result Drop
# ---------------------------------------------------------------------------

_CALL_KINDS: Final[frozenset[str]] = frozenset({"tool_call", "tool_use"})


def _resolve_orphan_target_index(events: Sequence[Any], step: PlanStep) -> int | None:
    """Resolve the orphan tool_result index for a plan step.

    Resolution is identity-first so that sequential deletion of earlier records
    (which shifts indices) cannot silently retarget the drop: explicit record
    identifiers from the finding evidence, then a unique correlation-id match,
    then the plan-time target_index hint, then a single unambiguous orphan.
    Returns None when no unambiguous target can be resolved.
    """
    params = step.params if isinstance(step.params, Mapping) else {}

    for key in ("result_id", "event_id", "record_id"):
        rid = params.get(key)
        if rid is not None:
            rid_str = str(rid)
            for i, ev in enumerate(events):
                if _event_id(ev) == rid_str:
                    return i

    corr = params.get("correlation_id")
    if corr is not None:
        corr_str = str(corr)
        matches = [
            i
            for i, ev in enumerate(events)
            if _event_kind(ev) == "tool_result" and _event_corr_id(ev) == corr_str
        ]
        if len(matches) == 1:
            return matches[0]

    # An explicit target_index is authoritative: out-of-bounds or non-orphan
    # targets are refused by the validation layer rather than silently retargeted.
    idx = step.target_index
    if idx is not None:
        if not isinstance(idx, int) or isinstance(idx, bool):
            return None
        return idx

    orphans = _find_orphan_result_indices(events)
    if len(orphans) == 1:
        return orphans[0]
    return None


def _find_orphan_result_indices(events: Sequence[Any]) -> list[int]:
    """Return indices of tool_result events whose correlation has no tool call."""
    call_corrs = {
        c
        for c in (_event_corr_id(e) for e in events if _event_kind(e) in _CALL_KINDS)
        if c is not None
    }
    orphans: list[int] = []
    for i, ev in enumerate(events):
        if _event_kind(ev) != "tool_result":
            continue
        corr = _event_corr_id(ev)
        if corr is None or corr not in call_corrs:
            orphans.append(i)
    return orphans


def _validate_orphan_target(events: Sequence[Any], idx: int, step: PlanStep) -> None:
    """Fail-closed validation that events[idx] is a droppable orphan result.

    Raises:
        PreconditionFailed: If the target is out of bounds, not a tool_result,
            has a matching call, has dependent children, or mismatches params.
    """
    if idx < 0 or idx >= len(events):
        raise PreconditionFailed(f"orphan-result-drop: invalid target index {idx!r}")

    target = events[idx]
    if _event_kind(target) != "tool_result":
        raise PreconditionFailed(f"orphan-result-drop: event at index {idx} is not a tool_result")

    corr = _event_corr_id(target)
    if step.params:
        p_corr = step.params.get("correlation_id")
        if p_corr is not None and corr is not None and str(p_corr) != corr:
            raise PreconditionFailed(
                "orphan-result-drop: target correlation does not match finding evidence"
            )

    if corr is not None:
        for ev in events:
            if _event_kind(ev) in _CALL_KINDS and _event_corr_id(ev) == corr:
                raise PreconditionFailed(
                    f"orphan-result-drop: result at index {idx} is not an orphan "
                    "(a matching tool call exists)"
                )

    target_id = _event_id(target)
    if target_id:
        for ev in events:
            if _event_parent_id(ev) == target_id:
                raise PreconditionFailed(
                    "orphan-result-drop: result has dependent child events; "
                    "dropping it would create missing parents"
                )


def apply_orphan_result_drop_with_loss(
    events: Sequence[Any],
    step: PlanStep,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Drop a single SL101 orphan tool_result record (lossy, salvage-only).

    Never synthesizes calls, results, or execution state. Drops exactly the one
    validated orphan record; all other events are preserved verbatim.

    Raises:
        PreconditionFailed: If no unambiguous orphan target can be resolved or
            the resolved target fails orphan/drop validation.
    """
    if not events:
        raise PreconditionFailed("orphan-result-drop: cannot apply to an empty session")

    idx = _resolve_orphan_target_index(events, step)
    if idx is None:
        raise PreconditionFailed(
            "orphan-result-drop: no unambiguous orphan result target could be resolved"
        )

    _validate_orphan_target(events, idx, step)

    out: list[dict[str, Any]] = []
    for i, ev in enumerate(events):
        if i != idx:
            out.append(_to_event_dict(ev))

    return out, {"orphan-result": 1}


def apply_orphan_result_drop(
    events: Sequence[Any],
    step: PlanStep,
) -> list[dict[str, Any]]:
    """Drop a single orphan tool_result (019-compatible signature returning list)."""
    transformed, _ = apply_orphan_result_drop_with_loss(events, step)
    return transformed


def affected_region_orphan_result_drop(
    step: Any,
    events: Sequence[Any],
) -> AffectedRegion:
    """Declare affected region for orphan-result-drop (DEV-013).

    Region is exactly the dropped orphan record plus any events parented to it
    (the recipe refuses such cases, but the region remains honest). Returns
    unproven when no unambiguous target resolves.
    """
    try:
        if not events:
            return AffectedRegion(unproven=True)
        idx = _resolve_orphan_target_index(events, step)
        if idx is None or idx < 0 or idx >= len(events):
            return AffectedRegion(unproven=True)
        target = events[idx]
        indices: set[int] = {idx}
        ids: set[str] = set()
        t_id = _event_id(target)
        if t_id:
            ids.add(t_id)
            for j, ev in enumerate(events):
                if _event_parent_id(ev) == t_id:
                    indices.add(j)
                    c_id = _event_id(ev)
                    if c_id:
                        ids.add(c_id)
        return AffectedRegion(indices=frozenset(indices), ids=frozenset(ids))
    except Exception:
        return AffectedRegion(unproven=True)


def sl101_orphan_present(ctx: PreconditionContext) -> bool:
    """Precondition: finding is SL101 and resolves to a droppable orphan result."""
    if ctx.finding is not None and ctx.finding.code != SL101:
        return False
    if not any(f.code == SL101 for f in ctx.findings):
        return False
    if ctx.finding is None:
        return True
    ev = ctx.finding.evidence
    idx: int | None = None
    if isinstance(ev, Mapping):
        for k in ("index", "at_index"):
            v = ev.get(k)
            if isinstance(v, int) and not isinstance(v, bool) and 0 <= v < len(ctx.events):
                idx = v
                break
    if idx is None and ctx.finding.source and ctx.finding.source.record_id:
        rec_id = ctx.finding.source.record_id
        for i, e in enumerate(ctx.events):
            if _event_id(e) == rec_id:
                idx = i
                break
    if idx is None:
        orphans = _find_orphan_result_indices(ctx.events)
        if len(orphans) == 1:
            idx = orphans[0]
    if idx is None:
        return False
    try:
        _validate_orphan_target(ctx.events, idx, _EMPTY_STEP)
    except PreconditionFailed:
        return False
    return True


# Placeholder step used only for precondition-time target validation; the real
# step is supplied by the planner at apply time.
_EMPTY_STEP: Final[PlanStep] = PlanStep(
    seq=0, recipe="orphan-result-drop", target_finding_fp="", target_index=None
)


# ---------------------------------------------------------------------------
# Recipe Registry Definitions
# ---------------------------------------------------------------------------

RECIPE_UNRESOLVABLE_BRANCH_AMPUTATE: Final[Recipe] = Recipe(
    name="unresolvable-branch-amputate",
    handles=(SL005, SL006),
    preconditions=("salvage_policy", "branch_has_no_checkpoint"),
    lossy=True,
    salvage_only=True,
    apply=apply_unresolvable_branch_amputate,
)

RECIPE_TORN_COMPACTION_PROJECT: Final[Recipe] = Recipe(
    name="torn-compaction-project",
    handles=(SL108,),
    preconditions=("salvage_policy", "sl108_present"),
    lossy=True,
    salvage_only=True,
    apply=apply_torn_compaction_project,
)

RECIPE_SIDE_EFFECT_UNKNOWN_TRUNCATE: Final[Recipe] = Recipe(
    name="side-effect-unknown-truncate",
    handles=(SL102,),
    preconditions=("salvage_policy", "acknowledge_side_effects"),
    lossy=True,
    salvage_only=True,
    apply=apply_side_effect_unknown_truncate,
)

RECIPE_ORPHAN_RESULT_DROP: Final[Recipe] = Recipe(
    name="orphan-result-drop",
    handles=(SL101,),
    preconditions=("salvage_policy", "acknowledge_side_effects", "sl101_orphan_present"),
    lossy=True,
    salvage_only=True,
    apply=apply_orphan_result_drop,
    affected_region=affected_region_orphan_result_drop,
)

RECIPES: Final[tuple[Recipe, ...]] = (
    RECIPE_UNRESOLVABLE_BRANCH_AMPUTATE,
    RECIPE_TORN_COMPACTION_PROJECT,
    RECIPE_SIDE_EFFECT_UNKNOWN_TRUNCATE,
    RECIPE_ORPHAN_RESULT_DROP,
)
SALVAGE_RECIPES: Final[tuple[Recipe, ...]] = RECIPES

# The recipe's finding-level precondition lives in this module but registers
# through the public precondition extension point so the planner can gate on it.
register_precondition("sl101_orphan_present", sl101_orphan_present)


def register_all() -> None:
    """Register all four salvage recipes into the repair registry."""
    register_precondition("sl101_orphan_present", sl101_orphan_present)
    for r in RECIPES:
        if get_recipe(r.name) is None:
            register_recipe(r)


__all__ = [
    "MAX_COMPONENT_SIZE",
    "RECIPES",
    "RECIPE_ORPHAN_RESULT_DROP",
    "RECIPE_SIDE_EFFECT_UNKNOWN_TRUNCATE",
    "RECIPE_TORN_COMPACTION_PROJECT",
    "RECIPE_UNRESOLVABLE_BRANCH_AMPUTATE",
    "SALVAGE_RECIPES",
    "affected_region_orphan_result_drop",
    "apply_orphan_result_drop",
    "apply_orphan_result_drop_with_loss",
    "apply_side_effect_unknown_truncate",
    "apply_side_effect_unknown_truncate_with_loss",
    "apply_torn_compaction_project",
    "apply_torn_compaction_project_with_loss",
    "apply_unresolvable_branch_amputate",
    "apply_unresolvable_branch_amputate_with_loss",
    "register_all",
    "sl101_orphan_present",
]
