"""SL002 Torn Terminal Record repair recipe (RVW-002, TASK-2.1).

This module implements the conservative repair recipe for SL002:
discarding an incomplete or malformed terminal record suffix.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any, Final

from sesslint.canonical import to_canonical_dict
from sesslint.codes import SL002
from sesslint.policy.abstention import AffectedRegion
from sesslint.repair.registry import Recipe, get_recipe, register_recipe

if TYPE_CHECKING:
    from sesslint.repair.planner import PlanStep


def _event_id(ev: Any) -> str | None:
    i = getattr(ev, "id", None)
    if i is None and isinstance(ev, Mapping):
        i = ev.get("id")
    return str(i) if i is not None else None


def _copy_events_as_dicts(events: Sequence[Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for ev in events:
        if hasattr(ev, "to_canonical_dict"):
            result.append(copy.deepcopy(ev.to_canonical_dict()))
        elif isinstance(ev, Mapping):
            result.append(copy.deepcopy(dict(ev)))
        else:
            try:
                result.append(copy.deepcopy(to_canonical_dict(ev)))
            except Exception:
                result.append(copy.deepcopy(dict(ev)))
    return result


def apply_torn_terminal_record_discard(
    events: Sequence[Any],
    step: PlanStep,
) -> list[dict[str, Any]]:
    """Discard incomplete or torn terminal record suffix safely.

    Guarantees:
    - If the malformed terminal line was dropped during ingestion, ensures
      preceding events are valid and preserved.
    - If target_index points to the terminal event in events, discards that terminal event.
    - Preserves all valid preceding events.
    """
    out = _copy_events_as_dicts(events)
    if step.target_index is not None and 0 <= step.target_index < len(out):
        if step.target_index == len(out) - 1:
            out.pop()
    return out


def affected_region_torn_terminal_record_discard(
    step: Any,
    events: Sequence[Any],
) -> AffectedRegion:
    """Declare affected region for torn-terminal-record-discard.

    Guarantees:
    - Pure function, deterministic, zero I/O.
    - Total function: handles empty inputs, invalid indices, or malformed steps safely.
    - Region includes the truncated suffix AND the new terminal record boundary (DEV-013).
    """
    try:
        num_events = len(events)
        if num_events == 0:
            return AffectedRegion(unproven=True)

        cut = getattr(step, "target_index", None)
        params = getattr(step, "params", None)
        if cut is None and isinstance(params, Mapping):
            p_cut = params.get("cut_index")
            if p_cut is None:
                p_cut = params.get("first_unsafe_index")
            if p_cut is None:
                p_cut = params.get("target_index")
            if isinstance(p_cut, int) and not isinstance(p_cut, bool):
                cut = p_cut

        if cut is not None:
            if not isinstance(cut, int) or isinstance(cut, bool):
                return AffectedRegion(unproven=True)
            if cut < 0 or cut >= num_events:
                return AffectedRegion(unproven=True)

            affected_indices: set[int] = set(range(cut, num_events))
            if cut > 0:
                affected_indices.add(cut - 1)

            start_ord = max(0, cut - 1)
            end_ord = num_events - 1
            ranges = ((start_ord, end_ord),)
            affected_ids = {
                eid for i in affected_indices if (eid := _event_id(events[i])) is not None
            }

            return AffectedRegion(
                indices=frozenset(affected_indices),
                ids=frozenset(affected_ids),
                ranges=ranges,
            )

        # Ingestion-dropped line: the terminal record in events is the new boundary
        boundary_idx = num_events - 1
        boundary_id = _event_id(events[boundary_idx])
        ids = frozenset({boundary_id}) if boundary_id is not None else frozenset()
        return AffectedRegion(
            indices=frozenset({boundary_idx}),
            ids=ids,
            ranges=((boundary_idx, boundary_idx),),
        )
    except Exception:
        return AffectedRegion(unproven=True)


RECIPE_TORN_TERMINAL_RECORD_DISCARD: Final[Recipe] = Recipe(
    name="torn-terminal-record-discard",
    handles=(SL002,),
    preconditions=("no_sl203", "torn_terminal_record"),
    lossy=False,
    salvage_only=False,
    min_policy="conservative",
    version="1.0.0",
    apply=apply_torn_terminal_record_discard,
    affected_region=affected_region_torn_terminal_record_discard,
)


def register_all() -> None:
    """Register SL002 recipe into repair registry."""
    if get_recipe(RECIPE_TORN_TERMINAL_RECORD_DISCARD.name) is None:
        register_recipe(RECIPE_TORN_TERMINAL_RECORD_DISCARD)


__all__ = [
    "RECIPE_TORN_TERMINAL_RECORD_DISCARD",
    "affected_region_torn_terminal_record_discard",
    "apply_torn_terminal_record_discard",
    "register_all",
]
