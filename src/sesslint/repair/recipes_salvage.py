"""Salvage repair recipe pack (TASK-020).

This module implements the three lossy salvage repair recipes as pure event-list
transforms under explicit opt-in policy:
1. unresolvable-branch-amputate: drop a weakly-connected parent component that contains
   an SL006 disconnected branch or SL005 fatal cycle with no checkpoints.
2. torn-compaction-project: project across a compaction boundary splitting tool pairs
   by dropping the boundary plus the minority side's orphaned halves.
3. side-effect-unknown-truncate: truncate session at the first tool event having
   side_effects != 'none' when acknowledged by the operator.

Guarantees:
- Zero I/O, zero disk access, zero network calls.
- Pure functions: inputs are deep-copied and never mutated.
- Strict gating on explicit 'salvage' policy opt-in.
- PreconditionFailed raised on invalid direct application.
- No-synthetic-success: never fabricates tool results or success states.
- Vendor-free: operates strictly on canonical event dictionaries.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from typing import Any, Final

from sesslint.canonical import to_canonical_dict
from sesslint.codes import SL005, SL006, SL102, SL108
from sesslint.repair.planner import PlanStep
from sesslint.repair.preconditions import (
    _find_component_indices,
    _find_torn_compaction_dropped_indices,
)
from sesslint.repair.recipes_conservative import PreconditionFailed
from sesslint.repair.registry import Recipe, get_recipe, register_recipe

_TOOL_KINDS: Final[frozenset[str]] = frozenset({"tool_call", "tool_use", "tool_result"})
MAX_COMPONENT_SIZE: Final[int] = 10_000


def _event_kind(ev: Any) -> str | None:
    k = getattr(ev, "kind", None)
    if k is None and isinstance(ev, Mapping):
        k = ev.get("kind")
    return str(k) if k is not None else None


def _event_id(ev: Any) -> str | None:
    i = getattr(ev, "id", None)
    if i is None and isinstance(ev, Mapping):
        i = ev.get("id")
    return str(i) if i is not None else None


def _event_parent_id(ev: Any) -> str | None:
    p = getattr(ev, "parent_id", None)
    if p is None and isinstance(ev, Mapping):
        p = ev.get("parent_id")
    return str(p) if p is not None else None


def _event_corr_id(ev: Any) -> str | None:
    c = getattr(ev, "correlation_id", None)
    if c is None and isinstance(ev, Mapping):
        c = ev.get("correlation_id")
    return str(c) if c is not None else None


def _to_event_dict(ev: Any) -> dict[str, Any]:
    if hasattr(ev, "to_canonical_dict"):
        return copy.deepcopy(ev.to_canonical_dict())
    if isinstance(ev, Mapping):
        return copy.deepcopy(dict(ev))
    try:
        return copy.deepcopy(to_canonical_dict(ev))
    except Exception:
        return copy.deepcopy(dict(ev))


def _copy_events_as_dicts(events: Sequence[Any]) -> list[dict[str, Any]]:
    return [_to_event_dict(e) for e in events]


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

RECIPES: Final[tuple[Recipe, ...]] = (
    RECIPE_UNRESOLVABLE_BRANCH_AMPUTATE,
    RECIPE_TORN_COMPACTION_PROJECT,
    RECIPE_SIDE_EFFECT_UNKNOWN_TRUNCATE,
)
SALVAGE_RECIPES: Final[tuple[Recipe, ...]] = RECIPES


def register_all() -> None:
    """Register all three salvage recipes into the repair registry."""
    for r in RECIPES:
        if get_recipe(r.name) is None:
            register_recipe(r)


__all__ = [
    "MAX_COMPONENT_SIZE",
    "RECIPES",
    "RECIPE_SIDE_EFFECT_UNKNOWN_TRUNCATE",
    "RECIPE_TORN_COMPACTION_PROJECT",
    "RECIPE_UNRESOLVABLE_BRANCH_AMPUTATE",
    "SALVAGE_RECIPES",
    "apply_side_effect_unknown_truncate",
    "apply_side_effect_unknown_truncate_with_loss",
    "apply_torn_compaction_project",
    "apply_torn_compaction_project_with_loss",
    "apply_unresolvable_branch_amputate",
    "apply_unresolvable_branch_amputate_with_loss",
    "register_all",
]
