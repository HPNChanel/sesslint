"""Mutation-driven tests for checks/graph.py (CL-15)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from sesslint.canonical import SessionEvent
from sesslint.checks import graph as g
from sesslint.codes import Repairability, Severity
from sesslint.context import CheckContext
from sesslint.finding import SourceRef, make_finding


def _se(
    eid: Any,
    parent: Any = None,
    *,
    seq: int = 0,
    kind: str = "message",
    branch: Any = None,
    line: int | None = None,
    loc: str = "dir\\f.jsonl",
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
        source_location=loc,
        extra_fields={},
        branch_id=branch,
    )


def _ns(
    eid: Any, parent: Any = None, *, kind: str = "message", branch: Any = None, **kw: Any
) -> Any:
    return SimpleNamespace(id=eid, parent_id=parent, kind=kind, branch_id=branch, **kw)


# ------------------------------------------------------------ small helpers


def test_event_accessors_on_all_shapes() -> None:
    assert g._event_get({"kind": "k"}, "kind") == "k"
    assert g._event_get(SimpleNamespace(kind="k"), "kind") == "k"
    assert g._event_get(SimpleNamespace(kind=None), "kind") is None
    assert g._event_get({}, "kind") is None
    assert g._event_get(object(), "kind") is None
    assert g._event_id_safe({"id": 5}) == "5"
    assert g._event_id_safe({}) is None
    assert g._event_parent_id_safe({"parent_id": 7}) == "7"
    assert g._event_branch_safe({"branch_id": "b"}) == "b"
    assert g._event_seq_safe({"seq": 4}) == 4
    assert g._event_seq_safe({"seq": True}, default_idx=9) == 9
    assert g._event_seq_safe({"seq": "4"}) is None
    assert g._event_seq_safe(_se("a", seq=6)) == 6
    assert g._event_seq_safe(SimpleNamespace(seq=3)) == 3


def test_cap_sort_key_uses_evidence_id_when_no_record_id() -> None:
    f = make_finding(
        code="SL004",
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Missing parent for record {record_id}",
        template_args={"record_id": "zzz"},
        source=SourceRef(path="p"),
        evidence={"id": "fromevidence"},
    )
    assert g._cap_finding_sort_key(f) == ("SL004", 0, "fromevidence", f.fingerprint)
    g2 = make_finding(
        code="SL004",
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Missing parent for record {record_id}",
        source=SourceRef(path="p", record_id="rid"),
        evidence={"id": "ignored", "overflow": True},
    )
    assert g._cap_finding_sort_key(g2)[1:3] == (1, "rid")


# ------------------------------------------------------ same_compaction_segment


def _seq_events() -> list[Any]:
    return [
        _ns("a", seq=0),
        _ns("b", seq=1),
        _ns("c", seq=2, kind="compaction_boundary"),
        _ns("d", seq=3),
        _ns("e", seq=4),
    ]


def test_same_segment_integers_and_boundaries() -> None:
    ev = _seq_events()
    assert g.same_compaction_segment(ev, 0, 1) is True
    assert g.same_compaction_segment(ev, 0, 3) is False
    assert g.same_compaction_segment(ev, 3, 0) is False
    assert g.same_compaction_segment(ev, 3, 4) is True
    assert g.same_compaction_segment(ev, 2, 4) is True  # boundary at endpoint
    assert g.same_compaction_segment(ev, 0, 2) is True
    assert g.same_compaction_segment(ev, 0, 4) is False
    assert g.same_compaction_segment(ev, 0, 0) is True


def test_same_segment_objects_without_seq_use_list_index() -> None:
    ev = [
        SimpleNamespace(id="a", kind="message"),
        SimpleNamespace(id="b", kind="message"),
        SimpleNamespace(id="c", kind="compaction_boundary"),
        SimpleNamespace(id="d", kind="message"),
    ]
    assert g.same_compaction_segment(ev, ev[0], ev[1]) is True
    assert g.same_compaction_segment(ev, ev[0], ev[3]) is False
    assert g.same_compaction_segment(ev, ev[1], ev[3]) is False
    assert g.same_compaction_segment(ev, ev[3], ev[0]) is False


def test_same_segment_unlocatable_endpoint_is_false() -> None:
    ev = [SimpleNamespace(id="a", kind="message")]
    stranger = SimpleNamespace(id="x", kind="message")
    assert g.same_compaction_segment(ev, stranger, ev[0]) is False
    assert g.same_compaction_segment(ev, ev[0], stranger) is False
    assert g.same_compaction_segment(ev, 0, stranger) is False


def test_same_segment_bool_endpoints_are_not_sequence_numbers() -> None:
    ev = [_ns("a", seq=5), _ns("b", seq=6)]
    # True is not treated as an int sequence number; falls back to the event's seq
    assert g.same_compaction_segment(ev, True, ev[1]) is False


# ------------------------------------------- qualifying parent candidates


def _chain_events() -> list[Any]:
    return [
        _ns("p", None, seq=0),
        _ns("x", None, seq=1, branch="other"),
        _ns("child", "p", seq=2),
    ]


def test_is_qualifying_reason_codes() -> None:
    ev = _chain_events()
    child = ev[2]
    assert g.is_qualifying_parent_candidate(ev[0], child, ev) == (True, "ok")
    assert g.is_qualifying_parent_candidate(child, child, ev) == (False, "self_candidate")
    assert g.is_qualifying_parent_candidate(_ns(""), child, ev) == (False, "empty_candidate_id")
    assert g.is_qualifying_parent_candidate(_ns(None), child, ev) == (False, "empty_candidate_id")
    assert g.is_qualifying_parent_candidate(ev[1], child, ev) == (False, "no_full_match")
    cross = _ns("p", None, seq=0, branch="side")
    assert g.is_qualifying_parent_candidate(cross, child, ev) == (False, "cross_branch")


def test_is_qualifying_explicit_missing_parent_overrides_child_parent() -> None:
    ev = _chain_events()
    child = ev[2]
    assert g.is_qualifying_parent_candidate(ev[1], child, ev, missing_parent_id="x")[1] == (
        "cross_branch"
    )
    # explicit empty-string target is honoured, not replaced by the child's parent
    assert g.is_qualifying_parent_candidate(ev[0], child, ev, missing_parent_id="zz") == (
        False,
        "no_full_match",
    )


def test_is_qualifying_child_without_parent_matches_nothing() -> None:
    ev = [_ns("a", seq=0), _ns("rootchild", None, seq=1)]
    assert g.is_qualifying_parent_candidate(ev[0], ev[1], ev) == (False, "no_full_match")
    # child with an unreadable parent still compares against ""
    assert g.is_qualifying_parent_candidate(_ns("q"), ev[1], ev) == (False, "no_full_match")


def test_is_qualifying_cross_segment() -> None:
    ev = [
        _ns("p", seq=0),
        _ns("b", seq=1, kind="compaction_boundary"),
        _ns("child", "p", seq=2),
    ]
    # adjacent seq (0,2) has a boundary strictly between -> cross_segment
    assert g.is_qualifying_parent_candidate(ev[0], ev[2], ev) == (False, "cross_segment")


def test_find_candidates_ok_and_evidence_shape() -> None:
    ev = _chain_events()
    q, rej, conf, reason = g.find_qualifying_parent_candidates(ev, ev[2], 2)
    assert q == [0]
    assert rej == [{"id": "x", "index": 1, "reason": "no_full_match"}]
    assert conf == {"branch": True, "segment": True}
    assert reason == "ok"


def test_find_candidates_no_id_match_has_false_confinement() -> None:
    ev = [_ns("a", seq=0), _ns("child", "ghost", seq=1)]
    q, rej, conf, reason = g.find_qualifying_parent_candidates(ev, ev[1], 1)
    assert q == []
    assert rej == [{"id": "a", "index": 0, "reason": "no_full_match"}]
    assert conf == {"branch": False, "segment": False}
    assert reason == "no_full_match"


def test_find_candidates_explicit_missing_parent_and_unnamed_candidate() -> None:
    ev = [_ns(None, seq=0), _ns("p", seq=1), _ns("child", None, seq=2)]
    q, rej, _conf, reason = g.find_qualifying_parent_candidates(ev, ev[2], 2, missing_parent_id="p")
    assert q == [1]
    assert rej == [{"id": "", "index": 0, "reason": "empty_candidate_id"}]
    assert reason == "ok"


def test_find_candidates_reasons() -> None:
    cross_branch = [_ns("p", seq=0, branch="s"), _ns("c", "p", seq=1)]
    assert (
        g.find_qualifying_parent_candidates(cross_branch, cross_branch[1], 1)[3] == "cross_branch"
    )
    assert g.find_qualifying_parent_candidates(cross_branch, cross_branch[1], 1)[2] == {
        "branch": False,
        "segment": True,
    }
    seg = [
        _ns("p", seq=0),
        _ns("b", seq=1, kind="compaction_boundary"),
        _ns("c", "p", seq=2),
    ]
    q, _r, conf, reason = g.find_qualifying_parent_candidates(seg, seg[2], 2)
    assert (q, reason) == ([], "cross_segment")
    assert conf == {"branch": True, "segment": False}
    dup = [_ns("p", seq=0), _ns("p", seq=1), _ns("c", "p", seq=2)]
    q, _r, _c, reason = g.find_qualifying_parent_candidates(dup, dup[2], 2)
    assert q == [0, 1]
    assert reason == "ambiguous"
    one = [_ns("p", seq=0), _ns("c", "p", seq=1)]
    assert g.find_qualifying_parent_candidates(one, one[1], 1)[3] == "ok"
    both = [
        _ns("p", seq=0, branch="s"),
        _ns("b", seq=1, kind="compaction_boundary"),
        _ns("c", "p", seq=2),
    ]
    assert g.find_qualifying_parent_candidates(both, both[2], 2)[3] == "cross_branch"


# --------------------------------------------------------- check_missing_parent


def test_missing_parent_finding_exact() -> None:
    ctx = CheckContext(adapter_id="ad", adapter_version="1", profile_id="pr", profile_version="2")
    evs = [_se("a", None, line=1), _se("b", "ghost", line=2)]
    (f,) = g.check_missing_parent(evs, context=ctx)
    assert f.source.path == "dir/f.jsonl"
    assert f.source.line == 2
    assert f.source.record_id == "b"
    assert f.related_ids == ("b", "ghost")
    assert dict(f.evidence or {}) == {
        "id": "b",
        "index": 1,
        "parent_id": "ghost",
        "match_rule": "full-equality",
        "confinement": {"branch": False, "segment": False},
        "candidate_count": 0,
        "rejected_decoys": [],
        "reason": "no_full_match",
    }


def test_missing_parent_uses_supplied_occurrence_graph() -> None:
    other = [_se("z", "nowhere")]
    graph = g._OccurrenceGraph(other, "<canonical>")
    (f,) = g.check_missing_parent([_se("a", None)], occurrence_graph=graph)
    assert f.source.record_id == "z"


def test_missing_parent_cap_overflow_carries_path_and_context() -> None:
    evs = [_se(f"n{i:02d}", "ghost", line=i + 1) for i in range(4)]
    a = g.check_missing_parent(
        evs, source_path="a\\b.jsonl", max_findings=2, context=CheckContext(adapter_id="one")
    )
    b = g.check_missing_parent(
        evs, source_path="a\\b.jsonl", max_findings=2, context=CheckContext(adapter_id="two")
    )
    assert a[-1].source.path == "a/b.jsonl"
    assert a[-1].fingerprint != b[-1].fingerprint


# ------------------------------------------------------------------ cycles


def test_cycle_finding_location_and_path() -> None:
    evs = [_se("b", "a", line=3), _se("a", "b", line=7)]
    (f,) = g.check_cycles(evs)
    assert f.source.record_id == "a"
    assert f.source.line == 7
    assert f.source.path == "dir/f.jsonl"
    assert dict(f.evidence or {}) == {"cycle_path": ["a", "b", "a"], "entry_index": 1}
    assert f.related_ids == ("a", "b")


def test_cycle_walk_through_explored_node_returns_list() -> None:
    # z (root) is explored first; x -> y -> z reaches an already-black node.
    evs = [_se("z", None), _se("x", "y"), _se("y", "z")]
    assert g.check_cycles(evs) == []


def test_cycle_downstream_of_cycle_reported_once() -> None:
    evs = [_se("a", "b"), _se("b", "a"), _se("t", "a"), _se("u", "t")]
    out = g.check_cycles(evs)
    assert len(out) == 1
    assert dict(out[0].evidence or {})["cycle_path"] == ["a", "b", "a"]


def test_cycle_self_loop() -> None:
    (f,) = g.check_cycles([_se("a", "a", line=2)])
    assert dict(f.evidence or {})["cycle_path"] == ["a", "a"]
    assert f.source.line == 2


# -------------------------------------------------------------- components


def test_component_with_single_named_branch_is_not_disconnected() -> None:
    evs = [
        _se("r", None),
        _se("r2", "r"),
        _se("s1", "gone", branch="side"),
        _se("s2", "s1", branch="side"),
    ]
    assert g.check_components(evs) == []


def test_component_with_two_named_branches_is_reported() -> None:
    evs = [
        _se("r", None),
        _se("r2", "r"),
        _se("s1", None, branch="b1"),
        _se("s2", "s1", branch="b2"),
    ]
    (f,) = g.check_components(evs)
    assert f.source.record_id == "s1"
    assert dict(f.evidence or {}) == {"member_sample": ["s1", "s2"], "root_id": "s1", "size": 2}


def test_component_with_mixed_branch_and_none_is_reported() -> None:
    evs = [_se("r", None), _se("r2", "r"), _se("s1", None, branch="b1"), _se("s2", "s1")]
    assert len(g.check_components(evs)) == 1


def test_skipped_non_conversational_component_does_not_hide_later_ones() -> None:
    evs = [
        _se("m1", None),
        _se("m2", "m1"),
        _se("m3", "m2"),
        _se("n1", None, kind="opaque"),
        _se("n2", "n1", kind="compaction_boundary"),
        _se("lone", None),
    ]
    (f,) = g.check_components(evs)
    assert f.source.record_id == "lone"
    assert dict(f.evidence or {})["size"] == 1


def test_component_related_ids_and_sample_cap() -> None:
    def chain(prefix: str, n: int) -> list[SessionEvent]:
        out = [_se(f"{prefix}00", None)]
        out += [_se(f"{prefix}{i:02d}", f"{prefix}{i - 1:02d}") for i in range(1, n)]
        return out

    (f,) = g.check_components(chain("a", 12) + chain("b", 11))
    ev = dict(f.evidence or {})
    assert ev["size"] == 11
    assert ev["root_id"] == "b00"
    assert ev["member_sample"] == [f"b{i:02d}" for i in range(g.MAX_MEMBER_SAMPLE_SIZE)]
    assert f.related_ids == tuple(f"b{i:02d}" for i in range(11))
