"""Mutation-driven behaviour tests for SL208 (CL-15)."""

from __future__ import annotations

from typing import Any

import pytest

from sesslint.canonical import SessionEvent
from sesslint.checks.compaction_snapshot import check_compaction_snapshot
from sesslint.codes import Repairability, Severity
from sesslint.context import CheckContext

MSG_TYPE = (
    "Compaction snapshot item type disagrees with the durable stream on line {l} for record {r}"
)
MSG_CORR = (
    "Compaction snapshot correlator disagrees with the durable stream on line {l} for record {r}"
)
MSG_FUTURE = (
    "Compaction snapshot cites an item not yet written to the stream on line {l} for record {r}"
)


def _ev(
    eid: Any,
    line: int,
    *,
    kind: str = "message",
    codex: Any = None,
    extra: Any = "auto",
    loc: str = "d\\t.jsonl",
) -> SessionEvent:
    if extra == "auto":
        extra = {"codex": codex} if codex is not None else {}
    return SessionEvent(
        id=eid,
        parent_id=None,
        seq=line,
        ts="",
        actor="assistant",
        kind=kind,
        source_line=line,
        source_adapter="codex-rollout",
        source_location=loc,
        extra_fields=extra,
    )


def _item(eid: str, line: int, typ: str = "message", call_id: str | None = None) -> SessionEvent:
    cx: dict[str, Any] = {"item_type": typ}
    if call_id is not None:
        cx["call_id"] = call_id
    return _ev(eid, line, codex=cx)


def _bound(eid: str, line: int, items: Any) -> SessionEvent:
    return _ev(eid, line, kind="compaction_boundary", codex={"guardian_items": items})


def _by_div(findings: list[Any]) -> dict[str, Any]:
    return {f.evidence["divergence"]: f for f in findings}


def test_no_boundaries_silent() -> None:
    assert check_compaction_snapshot([_item("a", 1)]) == []


def test_type_mismatch_exact() -> None:
    ctx = CheckContext(adapter_id="ad", adapter_version="1", profile_id="pr", profile_version="2")
    evs = [_item("a", 1, "message"), _bound("c", 5, [{"id": "a", "type": "function_call"}])]
    (f,) = check_compaction_snapshot(evs, context=ctx)
    assert f.code == "SL208"
    assert f.severity is Severity.WARNING
    assert f.repairability is Repairability.MANUAL
    assert f.message == MSG_TYPE.format(l=5, r="c")
    assert f.source.path == "d/t.jsonl"
    assert f.source.line == 5
    assert f.source.record_id == "c"
    assert dict(f.evidence or {}) == {
        "divergence": "type-mismatch",
        "item_id": "a",
        "occurrences": 1,
        "boundary_index": 1,
        "item_index": 0,
        "snapshot_item_type": "function_call",
        "stream_item_type": "message",
    }


def test_correlation_mismatch_exact() -> None:
    evs = [
        _item("a", 1, "function_call", "call_1"),
        _bound("c", 5, [{"id": "a", "type": "function_call", "call_id": "call_2"}]),
    ]
    (f,) = check_compaction_snapshot(evs, source_path="given.jsonl")
    assert f.message == MSG_CORR.format(l=5, r="c")
    assert f.source.path == "given.jsonl"
    assert dict(f.evidence or {}) == {
        "divergence": "correlation-mismatch",
        "item_id": "a",
        "occurrences": 1,
        "boundary_index": 1,
        "item_index": 0,
        "snapshot_correlator": "call_2",
        "stream_correlator": "call_1",
    }


def test_correlation_none_vs_value_and_reverse() -> None:
    evs = [_item("a", 1, "x", "k"), _bound("c", 5, [{"id": "a"}])]
    (f,) = check_compaction_snapshot(evs)
    ev = dict(f.evidence or {})
    assert ev["snapshot_correlator"] is None
    assert ev["stream_correlator"] == "k"
    evs = [_item("a", 1, "x"), _bound("c", 5, [{"id": "a", "call_id": "k"}])]
    (f,) = check_compaction_snapshot(evs)
    ev = dict(f.evidence or {})
    assert ev["snapshot_correlator"] == "k"
    assert ev["stream_correlator"] is None


def test_non_string_correlators_normalise_to_none() -> None:
    evs = [
        _ev("a", 1, codex={"item_type": "x", "call_id": 5}),
        _bound("c", 5, [{"id": "a", "call_id": 7}]),
    ]
    assert check_compaction_snapshot(evs) == []


def test_future_item_exact() -> None:
    evs = [_bound("c", 2, [{"id": "a"}]), _item("a", 9)]
    (f,) = check_compaction_snapshot(evs)
    assert f.message == MSG_FUTURE.format(l=2, r="c")
    assert dict(f.evidence or {}) == {
        "divergence": "future-item",
        "item_id": "a",
        "occurrences": 1,
        "boundary_index": 0,
        "item_index": 1,
    }


def test_item_at_same_index_as_boundary_not_future() -> None:
    # boundary that is itself a stream item citing its own id
    b = _ev(
        "c",
        2,
        kind="compaction_boundary",
        codex={"item_type": "compaction", "guardian_items": [{"id": "c"}]},
    )
    assert check_compaction_snapshot([b]) == []


def test_healthy_snapshot_silent() -> None:
    evs = [_item("a", 1, "m", "k"), _bound("c", 3, [{"id": "a", "type": "m", "call_id": "k"}])]
    assert check_compaction_snapshot(evs) == []


def test_snapshot_only_and_unkeyed_items_silent() -> None:
    evs = [
        _item("a", 1),
        _bound("c", 3, [{"id": "zzz", "type": "q"}, {"type": "q"}, {"id": 5}, "str", 7, None]),
    ]
    assert check_compaction_snapshot(evs) == []


def test_untyped_snapshot_item_not_type_mismatch() -> None:
    evs = [_item("a", 1, "m"), _bound("c", 3, [{"id": "a"}, {"id": "a", "type": 4}])]
    assert check_compaction_snapshot(evs) == []


def test_occurrences_count_and_first_anchor_wins() -> None:
    evs = [
        _item("a", 1, "m"),
        _item("b", 2, "m"),
        _bound("c1", 3, [{"id": "a", "type": "x"}, {"id": "b", "type": "y"}]),
        _bound("c2", 4, [{"id": "a", "type": "z"}]),
    ]
    (f,) = check_compaction_snapshot(evs)
    ev = dict(f.evidence or {})
    assert ev["occurrences"] == 3
    assert ev["item_id"] == "a"
    assert ev["snapshot_item_type"] == "x"
    assert ev["boundary_index"] == 2
    assert f.source.record_id == "c1"
    assert f.source.line == 3


def test_first_stream_occurrence_wins_on_id_reuse() -> None:
    evs = [
        _item("a", 1, "m", "k1"),
        _item("a", 2, "other", "k2"),
        _bound("c", 5, [{"id": "a", "type": "m", "call_id": "k1"}]),
    ]
    assert check_compaction_snapshot(evs) == []


def test_all_three_findings_emitted_in_fixed_order() -> None:
    evs = [
        _item("a", 1, "m", "k"),
        _bound("c", 2, [{"id": "a", "type": "x", "call_id": "j"}, {"id": "f"}]),
        _item("f", 3),
    ]
    out = check_compaction_snapshot(evs)
    assert [f.evidence["divergence"] for f in out] == [
        "type-mismatch",
        "correlation-mismatch",
        "future-item",
    ]
    assert all(f.evidence["occurrences"] == 1 for f in out)


def test_independent_anchor_per_kind() -> None:
    evs = [
        _item("a", 1, "m", "k"),
        _bound("c1", 2, [{"id": "a", "type": "m", "call_id": "k"}]),
        _bound("c2", 3, [{"id": "a", "type": "x", "call_id": "k"}]),
        _bound("c3", 4, [{"id": "a", "type": "m", "call_id": "j"}]),
    ]
    got = _by_div(check_compaction_snapshot(evs))
    assert got["type-mismatch"].source.record_id == "c2"
    assert got["correlation-mismatch"].source.record_id == "c3"


def test_boundary_requires_kind_and_list_items() -> None:
    plain = _ev("c", 2, codex={"guardian_items": [{"id": "a", "type": "x"}]})
    assert check_compaction_snapshot([_item("a", 1, "m"), plain]) == []
    bad = _ev("c", 2, kind="compaction_boundary", codex={"guardian_items": {"id": "a"}})
    assert check_compaction_snapshot([_item("a", 1, "m"), bad]) == []
    tup = _ev("c", 2, kind="compaction_boundary", codex={"guardian_items": ({"id": "a"},)})
    assert check_compaction_snapshot([_item("a", 1, "m"), tup]) == []


def test_empty_guardian_list_silent() -> None:
    assert check_compaction_snapshot([_item("a", 1), _bound("c", 2, [])]) == []


@pytest.mark.parametrize("extra", [None, "s", [], {"codex": None}, {"codex": "s"}, {"codex": []}])
def test_malformed_extra_ignored(extra: Any) -> None:
    evs = [_item("a", 1, "m"), _ev("b", 2, extra=extra), _bound("c", 3, [{"id": "a", "type": "m"}])]
    assert check_compaction_snapshot(evs) == []


def test_non_string_id_or_type_not_indexed() -> None:
    evs = [
        _ev(None, 1, codex={"item_type": "m"}),
        _ev("a", 2, codex={"item_type": 5}),
        _ev("b", 3, codex={}),
        _bound("c", 4, [{"id": "a", "type": "x"}, {"id": "b", "type": "x"}]),
    ]
    assert check_compaction_snapshot(evs) == []


def test_long_values_are_truncated() -> None:
    long_id = "i" * 300
    evs = [
        _ev(long_id, 1, codex={"item_type": "t" * 100, "call_id": "c" * 300}),
        _bound("c", 2, [{"id": long_id, "type": "u" * 100, "call_id": "d" * 300}]),
    ]
    got = _by_div(check_compaction_snapshot(evs))
    t = dict(got["type-mismatch"].evidence or {})
    assert t["item_id"] == "i" * 256
    assert t["snapshot_item_type"] == "u" * 64
    assert t["stream_item_type"] == "t" * 64
    c = dict(got["correlation-mismatch"].evidence or {})
    assert c["snapshot_correlator"] == "d" * 256
    assert c["stream_correlator"] == "c" * 256
    assert c["item_id"] == "i" * 256


def test_blank_boundary_id_no_record_id() -> None:
    for eid in (None, "", "  "):
        b = _ev(
            eid, 2, kind="compaction_boundary", codex={"guardian_items": [{"id": "a", "type": "x"}]}
        )
        (f,) = check_compaction_snapshot([_item("a", 1, "m"), b])
        assert f.source.record_id is None


def test_boundary_id_stripped() -> None:
    b = _ev(
        " cc ", 2, kind="compaction_boundary", codex={"guardian_items": [{"id": "a", "type": "x"}]}
    )
    (f,) = check_compaction_snapshot([_item("a", 1, "m"), b])
    assert f.source.record_id == "cc"
