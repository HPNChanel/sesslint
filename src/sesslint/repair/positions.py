"""B21: re-address plan steps from source positions to current positions.

Plan steps address events by their position in the source as loaded, but each
drop step shifts every later event. While recipes run, each working event
carries its source position under a private key (recipes deep-copy events, so
the key travels with the event); it is stripped before output validation, and
the canonical schema admits no such field. The executor and the independent
verifier replay steps through these same helpers, so both address the same
events.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping, MutableMapping, Sequence
from typing import Any, Final

from sesslint.repair.errors import OutputInvalid
from sesslint.repair.planner import PlanStep

ORIGIN_KEY: Final[str] = "\x00sesslint.origin"
STEP_INDEX_PARAMS: Final[tuple[str, ...]] = (
    "at_index",
    "boundary_index",
    "cut_index",
    "entry_index",
    "first_index",
    "first_unsafe_index",
    "index",
    "use_index",
)
STEP_INDEX_LIST_PARAMS: Final[tuple[str, ...]] = ("record_indexes", "result_indexes")


def tag_origins(events: Sequence[MutableMapping[str, Any]]) -> None:
    """Record each event's source position under ``ORIGIN_KEY``, failing closed on a clash."""
    if any(ORIGIN_KEY in ev for ev in events):
        raise OutputInvalid("Source event carries a field reserved for repair bookkeeping")
    for origin, ev_dict in enumerate(events):
        ev_dict[ORIGIN_KEY] = origin


def strip_origins(events: Sequence[MutableMapping[str, Any]]) -> None:
    """Remove the bookkeeping key from every event."""
    for ev_dict in events:
        ev_dict.pop(ORIGIN_KEY, None)


def source_positions(events: Sequence[Mapping[str, Any]]) -> dict[int, int]:
    """Map each surviving source position to its current position."""
    positions: dict[int, int] = {}
    for current, ev in enumerate(events):
        origin = ev.get(ORIGIN_KEY)
        if isinstance(origin, int):
            if origin in positions:
                raise OutputInvalid(f"Repair duplicated source event {origin}")
            positions[origin] = current
    return positions


def relocate_step(step: PlanStep, positions: Mapping[int, int], source_len: int) -> PlanStep:
    """Re-address ``step`` from source positions to current positions.

    A position that an earlier step removed fails closed instead of letting
    the step act on whichever event now sits there. Values that are not
    source positions pass through for the recipe's own guards to judge.
    """

    def relocate(value: Any) -> Any:
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < source_len:
            return value
        current = positions.get(value)
        if current is None:
            raise OutputInvalid(
                f"Step {step.seq} (recipe '{step.recipe}') targets source event {value}, "
                "which an earlier step removed"
            )
        return current

    params = dict(step.params)
    for key in STEP_INDEX_PARAMS:
        if key in params:
            params[key] = relocate(params[key])
    for key in STEP_INDEX_LIST_PARAMS:
        values = params.get(key)
        if isinstance(values, (list, tuple)):
            params[key] = [relocate(value) for value in values]
    return dataclasses.replace(step, target_index=relocate(step.target_index), params=params)
