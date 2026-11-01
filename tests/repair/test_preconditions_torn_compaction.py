"""Behaviour pins for SL108 torn-compaction preconditions (mutation survivors)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from sesslint.repair.preconditions import (
    PreconditionContext,
    _find_torn_compaction_dropped_indices,
    sl108_present,
)


def _ev(kind: str, corr: str | None = None) -> dict[str, Any]:
    ev: dict[str, Any] = {"kind": kind}
    if corr is not None:
        ev["correlation_id"] = corr
    return ev


BOUNDARY = _ev("compaction_boundary")


def _ctx(events: list[Any], codes: tuple[str, ...] = ("SL108",)) -> PreconditionContext:
    return PreconditionContext(
        findings=[SimpleNamespace(code=c) for c in codes],  # type: ignore[misc]
        events=events,
        profile="generic",
        source_hash="h",
    )


class TestFindTornCompactionDroppedIndices:
    def test_empty_session_refused(self) -> None:
        with pytest.raises(ValueError) as exc:
            _find_torn_compaction_dropped_indices([], 0)
        assert str(exc.value) == "Cannot project across compaction in empty session"

    @pytest.mark.parametrize("idx", [-1, 2])
    def test_out_of_range_boundary_refused(self, idx: int) -> None:
        with pytest.raises(ValueError) as exc:
            _find_torn_compaction_dropped_indices([BOUNDARY, _ev("message")], idx)
        assert str(exc.value) == f"Invalid compaction boundary index {idx!r}"

    def test_last_index_is_valid(self) -> None:
        events = [_ev("tool_call", "c1"), BOUNDARY]
        assert _find_torn_compaction_dropped_indices(events, 1) == {1}

    def test_non_boundary_refused(self) -> None:
        with pytest.raises(ValueError) as exc:
            _find_torn_compaction_dropped_indices([_ev("message"), BOUNDARY], 0)
        assert str(exc.value) == "Event at index 0 is not a compaction_boundary"

    def test_split_pair_tie_prefers_trailing_side(self) -> None:
        events = [_ev("tool_call", "c1"), BOUNDARY, _ev("tool_result", "c1")]
        assert _find_torn_compaction_dropped_indices(events, 1) == {1, 2}

    def test_tool_use_kind_counts_as_call(self) -> None:
        events = [_ev("tool_use", "c1"), BOUNDARY, _ev("tool_result", "c1")]
        assert _find_torn_compaction_dropped_indices(events, 1) == {1, 2}

    def test_leading_minority_is_dropped(self) -> None:
        events = [
            _ev("tool_call", "c1"),
            BOUNDARY,
            _ev("tool_result", "c1"),
            _ev("tool_result", "c1"),
        ]
        assert _find_torn_compaction_dropped_indices(events, 1) == {0, 1}

    def test_trailing_minority_is_dropped(self) -> None:
        events = [
            _ev("tool_call", "c1"),
            _ev("tool_call", "c1"),
            BOUNDARY,
            _ev("tool_result", "c1"),
        ]
        assert _find_torn_compaction_dropped_indices(events, 2) == {2, 3}

    def test_result_before_call_after_pair(self) -> None:
        events = [_ev("tool_result", "c1"), BOUNDARY, _ev("tool_call", "c1")]
        assert _find_torn_compaction_dropped_indices(events, 1) == {1, 2}

    def test_result_before_two_calls_after_drops_leading_result(self) -> None:
        events = [
            _ev("tool_result", "c1"),
            BOUNDARY,
            _ev("tool_call", "c1"),
            _ev("tool_use", "c1"),
        ]
        assert _find_torn_compaction_dropped_indices(events, 1) == {0, 1}

    def test_orphaned_call_before_boundary_drops_only_boundary(self) -> None:
        events = [_ev("tool_call", "c1"), BOUNDARY]
        assert _find_torn_compaction_dropped_indices(events, 1) == {1}

    def test_orphaned_result_after_boundary_drops_only_boundary(self) -> None:
        events = [BOUNDARY, _ev("tool_result", "c1")]
        assert _find_torn_compaction_dropped_indices(events, 0) == {0}

    def test_independent_correlations_accumulate(self) -> None:
        events = [
            _ev("tool_call", "a"),
            _ev("tool_call", "b"),
            BOUNDARY,
            _ev("tool_result", "a"),
            _ev("tool_result", "b"),
            _ev("tool_result", "b"),
        ]
        # A={0,1}, B={3,4,5} -> leading side is the minority
        assert _find_torn_compaction_dropped_indices(events, 2) == {0, 1, 2}

    @pytest.mark.parametrize(
        "events, boundary",
        [
            ([_ev("tool_call", "c1"), _ev("tool_result", "c1"), BOUNDARY], 2),
            ([BOUNDARY, _ev("tool_call", "c1"), _ev("tool_result", "c1")], 0),
            ([_ev("tool_result", "c1"), BOUNDARY], 1),
            ([_ev("tool_result", "c1"), BOUNDARY, _ev("tool_result", "c1")], 1),
            ([_ev("tool_call", "c1"), BOUNDARY, _ev("tool_call", "c1")], 1),
            ([_ev("message", "c1"), BOUNDARY, _ev("message", "c1")], 1),
            ([_ev("tool_call"), BOUNDARY, _ev("tool_result")], 1),
        ],
    )
    def test_no_split_refused(self, events: list[Any], boundary: int) -> None:
        with pytest.raises(ValueError) as exc:
            _find_torn_compaction_dropped_indices(events, boundary)
        assert str(exc.value) == (
            f"Compaction boundary at index {boundary} has no split pairs or orphaned halves"
        )


class TestSl108Present:
    def test_requires_sl108_finding(self) -> None:
        events = [_ev("tool_call", "c1"), BOUNDARY, _ev("tool_result", "c1")]
        assert sl108_present(_ctx(events, codes=("SL107",))) is False
        assert sl108_present(_ctx(events, codes=())) is False

    def test_requires_boundary(self) -> None:
        events = [_ev("tool_call", "c1"), _ev("tool_result", "c1")]
        assert sl108_present(_ctx(events)) is False

    def test_boundary_without_split_is_false(self) -> None:
        events = [_ev("message"), BOUNDARY, _ev("message")]
        assert sl108_present(_ctx(events)) is False

    def test_split_pair_is_true(self) -> None:
        events = [_ev("tool_call", "c1"), BOUNDARY, _ev("tool_result", "c1")]
        assert sl108_present(_ctx(events)) is True

    def test_later_boundary_with_split_is_found(self) -> None:
        events = [BOUNDARY, _ev("tool_call", "c1"), BOUNDARY, _ev("tool_result", "c1")]
        # first boundary: c1 call+result both after -> no split; second splits
        assert sl108_present(_ctx(events)) is True

    def test_sl108_among_other_findings(self) -> None:
        events = [_ev("tool_call", "c1"), BOUNDARY, _ev("tool_result", "c1")]
        assert sl108_present(_ctx(events, codes=("SL001", "SL108"))) is True
