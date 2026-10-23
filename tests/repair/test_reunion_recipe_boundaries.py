"""Exact-behaviour pins for ``compaction-projection-reunion`` (CL-08 mutation triage).

Pins refusal messages, correlation lookup order and the exact relocated
output of ``apply_compaction_projection_reunion``.
"""

from __future__ import annotations

from typing import Any

import pytest

from sesslint.repair.planner import PlanStep
from sesslint.repair.recipes_conservative import (
    PreconditionFailed,
    apply_compaction_projection_reunion,
)

_P = "compaction-projection-reunion: "


def _ev(kind: str, ident: str, corr: str | None = None) -> dict[str, Any]:
    e: dict[str, Any] = {"kind": kind, "id": ident}
    if corr is not None:
        e["correlation_id"] = corr
    return e


def _step(target: int | None = None, **params: Any) -> PlanStep:
    return PlanStep(
        seq=0,
        recipe="compaction-projection-reunion",
        target_finding_fp="f" * 16,
        target_index=target,
        params=params,
    )


def _ids(events: list[dict[str, Any]]) -> list[str]:
    return [e["id"] for e in events]


def _pair_with_boundary(call_kind: str = "tool_call") -> list[dict[str, Any]]:
    return [
        _ev("message", "m0"),
        _ev(call_kind, "c", "k1"),
        _ev("compaction_boundary", "b"),
        _ev("tool_result", "r", "k1"),
        _ev("message", "m4"),
    ]


def test_relocates_boundary_after_result() -> None:
    events = _pair_with_boundary()
    out = apply_compaction_projection_reunion(events, _step(correlation_id="k1"))
    assert _ids(out) == ["m0", "c", "r", "b", "m4"]
    assert _ids(events) == ["m0", "c", "b", "r", "m4"]  # input untouched


def test_tool_use_call_kind_accepted() -> None:
    out = apply_compaction_projection_reunion(
        _pair_with_boundary("tool_use"), _step(correlation_id="k1")
    )
    assert _ids(out) == ["m0", "c", "r", "b", "m4"]


def test_reversed_pair_relocates_after_later_endpoint() -> None:
    events = [
        _ev("tool_result", "r", "k1"),
        _ev("compaction_boundary", "b"),
        _ev("tool_call", "c", "k1"),
        _ev("message", "m3"),
    ]
    out = apply_compaction_projection_reunion(events, _step(correlation_id="k1"))
    assert _ids(out) == ["r", "c", "b", "m3"]


def test_boundary_adjacent_to_pair_end_keeps_following_events_after_it() -> None:
    events = [
        _ev("tool_call", "c", "k1"),
        _ev("message", "x"),
        _ev("compaction_boundary", "b"),
        _ev("tool_result", "r", "k1"),
    ]
    out = apply_compaction_projection_reunion(events, _step(correlation_id="k1"))
    assert _ids(out) == ["c", "x", "r", "b"]


def test_correlation_taken_from_target_event_when_param_missing() -> None:
    events = _pair_with_boundary()
    out = apply_compaction_projection_reunion(events, _step(target=1))
    assert _ids(out) == ["m0", "c", "r", "b", "m4"]
    out = apply_compaction_projection_reunion(events, _step(target=3))
    assert _ids(out) == ["m0", "c", "r", "b", "m4"]


def test_param_correlation_wins_over_target_event() -> None:
    events = _pair_with_boundary() + [
        _ev("tool_call", "c2", "k2"),
        _ev("tool_result", "r2", "k2"),
    ]
    # target points at the k2 call, but the explicit parameter selects k1.
    out = apply_compaction_projection_reunion(events, _step(target=5, correlation_id="k1"))
    assert _ids(out)[:5] == ["m0", "c", "r", "b", "m4"]


@pytest.mark.parametrize("target", [None, -1, 99, 0])
def test_missing_correlation_refused(target: int | None) -> None:
    events = _pair_with_boundary()  # events[0] has no correlation_id
    with pytest.raises(PreconditionFailed) as exc:
        apply_compaction_projection_reunion(events, _step(target=target))
    assert str(exc.value) == _P + "missing correlation_id"


def test_target_index_zero_is_valid_lower_bound() -> None:
    events = [
        _ev("tool_call", "c", "k1"),
        _ev("compaction_boundary", "b"),
        _ev("tool_result", "r", "k1"),
    ]
    out = apply_compaction_projection_reunion(events, _step(target=0))
    assert _ids(out) == ["c", "r", "b"]


def test_target_index_equal_to_len_is_out_of_range() -> None:
    events = _pair_with_boundary()
    with pytest.raises(PreconditionFailed) as exc:
        apply_compaction_projection_reunion(events, _step(target=len(events)))
    assert str(exc.value) == _P + "missing correlation_id"


@pytest.mark.parametrize(
    "events",
    [
        [_ev("tool_call", "c", "k1"), _ev("compaction_boundary", "b")],
        [_ev("compaction_boundary", "b"), _ev("tool_result", "r", "k1")],
        [
            _ev("tool_call", "c", "k1"),
            _ev("tool_call", "c2", "k1"),
            _ev("compaction_boundary", "b"),
            _ev("tool_result", "r", "k1"),
        ],
        [
            _ev("tool_call", "c", "k1"),
            _ev("compaction_boundary", "b"),
            _ev("tool_result", "r", "k1"),
            _ev("tool_result", "r2", "k1"),
        ],
    ],
)
def test_pair_cardinality_refused(events: list[dict[str, Any]]) -> None:
    with pytest.raises(PreconditionFailed) as exc:
        apply_compaction_projection_reunion(events, _step(correlation_id="k1"))
    assert str(exc.value) == (
        _P + "pair for correlation 'k1' must have exactly 1 call and 1 result"
    )


def test_other_correlation_ids_do_not_count() -> None:
    events = _pair_with_boundary() + [_ev("tool_call", "c9", "k9"), _ev("tool_result", "r9", "k9")]
    out = apply_compaction_projection_reunion(events, _step(correlation_id="k1"))
    assert _ids(out) == ["m0", "c", "r", "b", "m4", "c9", "r9"]


_ENDPOINT = _P + "boundary sits at pair endpoint (not strictly between)"


@pytest.mark.parametrize("hint", [1, 3])
def test_boundary_index_hint_at_endpoint_refused(hint: int) -> None:
    with pytest.raises(PreconditionFailed) as exc:
        apply_compaction_projection_reunion(
            _pair_with_boundary(), _step(correlation_id="k1", boundary_index=hint)
        )
    assert str(exc.value) == _ENDPOINT


def test_boundary_index_hint_strictly_between_accepted() -> None:
    out = apply_compaction_projection_reunion(
        _pair_with_boundary(), _step(correlation_id="k1", boundary_index=2)
    )
    assert _ids(out) == ["m0", "c", "r", "b", "m4"]


def test_target_boundary_at_endpoint_refused() -> None:
    events = [
        _ev("compaction_boundary", "b0", "k1"),
        _ev("compaction_boundary", "b1"),
        _ev("tool_call", "c", "k1"),
        _ev("tool_result", "r", "k1"),
    ]
    # target (index 0) is a boundary, but the call/result pair is (2, 3): hint 0 is not an endpoint.
    with pytest.raises(PreconditionFailed) as exc:
        apply_compaction_projection_reunion(events, _step(target=0, correlation_id="k1"))
    assert str(exc.value).startswith(_P + "expected exactly 1 boundary strictly between pair")


def test_target_boundary_hint_is_used_when_it_sits_on_endpoint() -> None:
    events = [
        _ev("tool_call", "c", "k1"),
        _ev("compaction_boundary", "b"),
        _ev("tool_result", "r", "k1"),
    ]
    # target index 1 is the boundary between the pair -> fine.
    out = apply_compaction_projection_reunion(events, _step(target=1, correlation_id="k1"))
    assert _ids(out) == ["c", "r", "b"]


@pytest.mark.parametrize("n_between", [0, 2])
def test_boundary_count_between_pair_must_be_exactly_one(n_between: int) -> None:
    events = [_ev("tool_call", "c", "k1")]
    events += [_ev("compaction_boundary", f"b{i}") for i in range(n_between)]
    events += [_ev("tool_result", "r", "k1")]
    with pytest.raises(PreconditionFailed) as exc:
        apply_compaction_projection_reunion(events, _step(correlation_id="k1"))
    assert str(exc.value) == (
        _P + f"expected exactly 1 boundary strictly between pair, found {n_between}"
    )


def test_boundary_outside_pair_does_not_count() -> None:
    events = [
        _ev("compaction_boundary", "b_out"),
        _ev("tool_call", "c", "k1"),
        _ev("tool_result", "r", "k1"),
        _ev("compaction_boundary", "b_out2"),
    ]
    with pytest.raises(PreconditionFailed) as exc:
        apply_compaction_projection_reunion(events, _step(correlation_id="k1"))
    assert str(exc.value).endswith("found 0")


def test_boundary_on_endpoint_event_refused() -> None:
    events = [
        {"kind": "compaction_boundary", "id": "c", "correlation_id": "k1"},
        {"kind": "tool_result", "id": "r", "correlation_id": "k1"},
    ]
    # the "call" slot is not a call kind so the pair is incomplete.
    with pytest.raises(PreconditionFailed):
        apply_compaction_projection_reunion(events, _step(correlation_id="k1"))
