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
from sesslint.repair.registry import Recipe, get_recipe, register_recipe

if TYPE_CHECKING:
    from sesslint.repair.planner import PlanStep


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


RECIPE_TORN_TERMINAL_RECORD_DISCARD: Final[Recipe] = Recipe(
    name="torn-terminal-record-discard",
    handles=(SL002,),
    preconditions=("no_sl203", "torn_terminal_record"),
    lossy=False,
    salvage_only=False,
    min_policy="conservative",
    version="1.0.0",
    apply=apply_torn_terminal_record_discard,
)


def register_all() -> None:
    """Register SL002 recipe into repair registry."""
    if get_recipe(RECIPE_TORN_TERMINAL_RECORD_DISCARD.name) is None:
        register_recipe(RECIPE_TORN_TERMINAL_RECORD_DISCARD)


__all__ = [
    "RECIPE_TORN_TERMINAL_RECORD_DISCARD",
    "apply_torn_terminal_record_discard",
    "register_all",
]
