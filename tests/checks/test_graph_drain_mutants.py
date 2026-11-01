"""Mutation-driven tests for checks/graph.py and accounting window start (CL-17)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from sesslint.canonical import SessionEvent
from sesslint.checks import accounting as acc
from sesslint.checks import graph as g
from sesslint.context import CheckContext


def _se(
    eid: Any,
    parent: Any = None,
    *,
    seq: int = 0,
    kind: str = "message",
    line: int | None = None,
    extra: Any = None,
    branch: Any = None,
) -> SessionEvent:
    return SessionEvent(
        id=eid,
        parent_id=parent,
        seq=seq,
        ts="",
        actor="assistant",
        kind=kind,
        source_line=line,
        source_adapter="x",
        source_location="f.jsonl",
        extra_fields=extra if extra is not None else {},
        branch_id=branch,
    )


def _ctx() -> CheckContext:
    return CheckContext(adapter_id="ad", adapter_version="1", profile_id="pr", profile_version="2")


def test_cycles_uses_supplied_occurrence_graph() -> None:
    events = [_se("a", "b"), _se("b", "a")]
    graph = g._OccurrenceGraph(events, "f.jsonl")
    (f,) = g.check_cycles([], occurrence_graph=graph, source_path="f.jsonl")
    assert f.evidence is not None
    assert f.evidence["cycle_path"] == ["a", "b", "a"]


def test_cycles_related_ids_and_context_are_propagated() -> None:
    events = [_se("c", "a"), _se("a", "b"), _se("b", "c"), _se("tail", "c")]
    (f,) = g.check_cycles(events, context=_ctx())
    assert list(f.related_ids) == ["a", "b", "c"]
    base = g.check_cycles(events)[0].fingerprint
    assert f.fingerprint != base
    other = CheckContext(adapter_id="zz", adapter_version="1", profile_id="pr", profile_version="2")
    assert g.check_cycles(events, context=other)[0].fingerprint != f.fingerprint


def test_same_segment_skips_seqless_items_without_stopping() -> None:
    # An item without a usable seq precedes the boundary; the scan must go on.
    events: list[Any] = [
        SimpleNamespace(id="x", kind="message"),
        _se("b", seq=2, kind="compaction_boundary"),
    ]
    assert g.same_compaction_segment(events, 1, 4) is False


def test_components_continue_after_redundant_union() -> None:
    # a<->b is a cycle: the second union is redundant and must not end the pass.
    events = [_se("a", "b"), _se("b", "a"), _se("c"), _se("d", "c")]
    (f,) = g.check_components(events)
    assert f.evidence is not None
    assert f.evidence["size"] == 2


def test_components_tie_breaks_on_root_id_not_member_order() -> None:
    # Both components have size 2. Root "a" must win the tie (primary), so the
    # reported disconnected component is the one rooted at "b".
    events = [_se("b"), _se("c", "b"), _se("z", "a"), _se("a")]
    (f,) = g.check_components(events)
    assert f.evidence is not None
    assert f.evidence["root_id"] == "b"


def test_components_finding_points_at_root_event_line() -> None:
    events = [_se("a", line=1), _se("b", line=2), _se("c", "b", line=3)]
    (f,) = g.check_components(events)
    assert f.source.record_id == "a"
    assert f.source.line == 1


def test_accounting_window_start_after_first_marker_following_boundary() -> None:
    def usage(contrib: dict[str, int] | None, cum: dict[str, int] | None) -> dict[str, Any]:
        u: dict[str, Any] = {}
        if contrib is not None:
            u["contribution"] = contrib
        if cum is not None:
            u["cumulative"] = cum
        return {"usage": u}

    events = [
        _se("b0", kind="compaction_boundary", line=1),
        _se("m1", extra=usage({"in": 1}, {"in": 10}), line=2),
        _se("m2", extra=usage({"in": 2}, {"in": 99}), line=3),
    ]
    (f,) = acc.check_accounting(events)
    assert f.evidence is not None
    assert f.evidence["window_start_index"] == 2
    assert f.evidence["window_end_index"] == 2


def test_components_root_is_member_whose_parent_is_absent() -> None:
    # "b" points at a parent that is not in the file; "c" hangs below it.
    events = [_se("a"), _se("x", "a"), _se("y", "x"), _se("b", "gone"), _se("c", "b")]
    (f,) = g.check_components(events)
    assert f.evidence is not None
    assert f.evidence["root_id"] == "b"


def test_components_skip_does_not_stop_later_components() -> None:
    events = [
        _se("a"),
        _se("b", "a"),
        _se("c", "b"),
        _se("v1", branch="br", seq=1),
        _se("v2", "v1", branch="br", seq=2),
        _se("k1", kind="compaction_boundary", seq=3),
        _se("k2", "k1", kind="compaction_boundary", seq=4),
        _se("z", seq=5),
    ]
    (f,) = g.check_components(events)
    assert f.evidence is not None
    assert f.evidence["root_id"] == "z"


def test_graph_duplicate_ids_do_not_hide_later_events() -> None:
    events = [_se("a"), _se("a"), _se("b", "c"), _se("c", "b")]
    (f,) = g.check_cycles(events)
    assert f.evidence is not None
    assert f.evidence["cycle_path"] == ["b", "c", "b"]


def test_graph_reads_parent_from_plain_objects() -> None:
    events = [
        SimpleNamespace(id="a", parent_id="b", kind="message"),
        SimpleNamespace(id="b", parent_id="a", kind="message"),
    ]
    (f,) = g.check_cycles(events)  # type: ignore[arg-type]
    assert f.evidence is not None
    assert f.evidence["cycle_path"] == ["a", "b", "a"]


def test_accounting_evidence_carries_record_id() -> None:
    events = [_se("m1", extra={"usage": {"cumulative": {"in": 3}}}, line=1)]
    (f,) = acc.check_accounting(events)
    assert f.evidence is not None
    assert f.evidence["record_id"] == "m1"
