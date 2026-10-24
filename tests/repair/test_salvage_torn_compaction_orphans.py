"""Behaviour pins for torn-compaction projection and orphan-result lookup (mutation survivors)."""

from __future__ import annotations

from typing import Any

import pytest

from sesslint.repair.planner import PlanStep
from sesslint.repair.recipes_conservative import PreconditionFailed
from sesslint.repair.recipes_salvage import (
    _find_orphan_result_indices,
    apply_torn_compaction_project_with_loss,
)


def _ev(eid: str, kind: str, corr: str | None = None) -> dict[str, Any]:
    ev: dict[str, Any] = {"id": eid, "kind": kind}
    if corr is not None:
        ev["correlation_id"] = corr
    return ev


def _step(target: int | None, params: dict[str, Any] | None = None) -> PlanStep:
    return PlanStep(
        seq=0,
        recipe="torn-compaction-project",
        target_finding_fp="fp",
        target_index=target,
        params=params or {},
        lossy=True,
    )


def _split() -> list[dict[str, Any]]:
    return [
        _ev("a", "message"),
        _ev("b", "tool_call", "c1"),
        _ev("x", "compaction_boundary"),
        _ev("d", "tool_result", "c1"),
        _ev("e", "message"),
    ]


class TestTornCompactionProject:
    def test_empty_refused(self) -> None:
        with pytest.raises(PreconditionFailed) as exc:
            apply_torn_compaction_project_with_loss([], _step(0))
        assert str(exc.value) == "Cannot project across compaction in empty session"

    def test_projects_boundary_and_tied_trailing_half(self) -> None:
        out, loss = apply_torn_compaction_project_with_loss(_split(), _step(2))
        assert [e["id"] for e in out] == ["a", "b", "e"]
        assert loss == {"projected-orphans": 2}

    def test_boundary_index_from_params(self) -> None:
        out, loss = apply_torn_compaction_project_with_loss(
            _split(), _step(None, {"boundary_index": 2})
        )
        assert [e["id"] for e in out] == ["a", "b", "e"]
        assert loss == {"projected-orphans": 2}

    def test_target_zero_is_not_treated_as_missing(self) -> None:
        events = [_ev("x", "compaction_boundary"), _ev("r", "tool_result", "c1")]
        out, loss = apply_torn_compaction_project_with_loss(events, _step(0))
        assert [e["id"] for e in out] == ["r"]
        assert loss["projected-orphans"] == len(events) - len(out)

    def test_params_boundary_index_selects_among_several_boundaries(self) -> None:
        events = [*_split(), _ev("y", "compaction_boundary")]
        out, _ = apply_torn_compaction_project_with_loss(events, _step(None, {"boundary_index": 2}))
        assert [e["id"] for e in out] == ["a", "b", "e", "y"]

    def test_explicit_target_wins_over_params(self) -> None:
        events = [*_split(), _ev("y", "compaction_boundary")]
        out, _ = apply_torn_compaction_project_with_loss(events, _step(2, {"boundary_index": 5}))
        assert [e["id"] for e in out] == ["a", "b", "e", "y"]

    @pytest.mark.parametrize("target", [None, -1, 5, 99])
    def test_invalid_index_falls_back_to_unique_boundary(self, target: int | None) -> None:
        out, loss = apply_torn_compaction_project_with_loss(_split(), _step(target))
        assert [e["id"] for e in out] == ["a", "b", "e"]
        assert loss == {"projected-orphans": 2}

    def test_last_index_is_in_range(self) -> None:
        events = [_ev("t", "tool_call", "c1"), _ev("x", "compaction_boundary")]
        out, loss = apply_torn_compaction_project_with_loss(events, _step(1))
        assert [e["id"] for e in out] == ["t"]
        assert loss == {"projected-orphans": 1}

    @pytest.mark.parametrize("target", [-1, 9])
    def test_invalid_index_with_ambiguous_boundaries_refused(self, target: int) -> None:
        events = _split() + [_ev("y", "compaction_boundary")]
        with pytest.raises(PreconditionFailed) as exc:
            apply_torn_compaction_project_with_loss(events, _step(target))
        assert str(exc.value) == f"Invalid compaction boundary index {target!r}"

    def test_missing_index_without_boundary_refused(self) -> None:
        with pytest.raises(PreconditionFailed) as exc:
            apply_torn_compaction_project_with_loss([_ev("a", "message")], _step(None))
        assert str(exc.value) == "Invalid compaction boundary index None"

    def test_non_boundary_target_refused(self) -> None:
        with pytest.raises(PreconditionFailed) as exc:
            apply_torn_compaction_project_with_loss(_split(), _step(1))
        assert str(exc.value) == "Event at index 1 is not a compaction_boundary"

    def test_boundary_without_split_refused_with_core_message(self) -> None:
        events = [_ev("a", "message"), _ev("x", "compaction_boundary")]
        with pytest.raises(PreconditionFailed) as exc:
            apply_torn_compaction_project_with_loss(events, _step(1))
        assert str(exc.value) == (
            "Compaction boundary at index 1 has no split pairs or orphaned halves"
        )


class TestFindOrphanResultIndices:
    def test_orphans_listed_in_order(self) -> None:
        events = [
            _ev("1", "tool_result", "gone"),
            _ev("2", "tool_call", "c1"),
            _ev("3", "tool_result", "c1"),
            _ev("4", "tool_result"),
        ]
        assert _find_orphan_result_indices(events) == [0, 3]

    def test_tool_use_counts_as_call(self) -> None:
        events = [_ev("1", "tool_use", "c1"), _ev("2", "tool_result", "c1")]
        assert _find_orphan_result_indices(events) == []

    def test_only_tool_results_are_orphan_candidates(self) -> None:
        events = [_ev("1", "message", "c1"), _ev("2", "tool_call", "c2")]
        assert _find_orphan_result_indices(events) == []

    def test_call_without_correlation_does_not_cover_results(self) -> None:
        events = [_ev("1", "tool_call"), _ev("2", "tool_result")]
        assert _find_orphan_result_indices(events) == [1]

    def test_non_call_kinds_do_not_cover_results(self) -> None:
        events = [_ev("1", "message", "c1"), _ev("2", "tool_result", "c1")]
        assert _find_orphan_result_indices(events) == [1]

    def test_empty(self) -> None:
        assert _find_orphan_result_indices([]) == []
