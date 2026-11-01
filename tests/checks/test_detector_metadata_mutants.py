"""Mutation-driven tests (CL-15): adapter/profile metadata reaches the
finding fingerprint for the codex-scoped and writer/size detectors, and
per-loop ``continue`` semantics hold when malformed records precede valid
ones.
"""

from __future__ import annotations

from typing import Any

import pytest

from sesslint.canonical import SessionEvent
from sesslint.checks.compaction_snapshot import check_compaction_snapshot
from sesslint.checks.context_pressure import check_context_pressure
from sesslint.checks.durable_prefix import check_durable_prefix
from sesslint.checks.foreign_shape import check_foreign_shape
from sesslint.checks.size import check_size_anomaly
from sesslint.checks.writers import check_writers
from sesslint.context import CheckContext


def _ev(eid: Any, line: int, extra: Any, kind: str = "message") -> SessionEvent:
    return SessionEvent(
        id=eid,
        parent_id=None,
        seq=line,
        ts="",
        actor="assistant",
        kind=kind,
        source_line=line,
        source_adapter="x",
        source_location="t.jsonl",
        extra_fields=extra,
    )


def _cx(**kw: Any) -> dict[str, Any]:
    return {"codex": kw}


def _events_for(name: str) -> list[SessionEvent]:
    if name == "context_pressure":
        return [_ev("e", 1, _cx(context_pressure={"occupancy": 99, "window": 100}))]
    if name == "foreign_shape":
        return [_ev("e", 1, _cx(item_type="reasoning", reasoning_content_shape="array"))]
    if name == "durable_prefix":
        return [
            _ev("a", 1, _cx(ordinal=0, durable=True)),
            _ev("b", 2, _cx(ordinal=4, durable=True)),
        ]
    if name == "compaction_snapshot":
        return [
            _ev("a", 1, _cx(item_type="m")),
            _ev("c", 2, _cx(guardian_items=[{"id": "a", "type": "x"}]), "compaction_boundary"),
        ]
    if name == "writers":
        return [_ev(f"e{i}", i, {"writer": {"version": v}}) for i, v in enumerate("ABA", 1)]
    raise AssertionError(name)


_CHECKS = {
    "context_pressure": check_context_pressure,
    "foreign_shape": check_foreign_shape,
    "durable_prefix": check_durable_prefix,
    "compaction_snapshot": check_compaction_snapshot,
    "writers": check_writers,
}

_BASE = {
    "adapter_id": "ad",
    "adapter_version": "1",
    "profile_id": "pr",
    "profile_version": "2",
}


@pytest.mark.parametrize("name", sorted(_CHECKS))
@pytest.mark.parametrize("field", sorted(_BASE))
def test_context_metadata_changes_fingerprint(name: str, field: str) -> None:
    run = _CHECKS[name]
    evs = _events_for(name)
    base = run(evs, context=CheckContext(**_BASE))
    changed = run(evs, context=CheckContext(**{**_BASE, field: "other"}))
    assert base and changed
    assert base[0].fingerprint != changed[0].fingerprint
    # and the default (no context) differs from an explicit one
    assert run(evs)[0].fingerprint != base[0].fingerprint


def test_size_ratio_rounded_to_three_places() -> None:
    sizes = [3] * 8 + [262144 + 1]
    (f,) = check_size_anomaly(
        [], source_path="p", context=CheckContext(source_metadata={"record_sizes": sizes})
    )
    ratio = dict(f.evidence or {})["ratio"]
    assert ratio == round(262145 / 3, 3)
    assert ratio != round(262145 / 3, 4)


def test_writers_out_of_order_duplicate_line_marker_deduped() -> None:
    evs = [
        _ev("e1", 1, {"writer": {"version": "A"}}),
        _ev("e2", 2, {"writer": {"version": "B"}}),
        _ev("e3", 1, {"writer": {"version": "A"}}),
    ]
    assert check_writers(evs) == []


# --- leading malformed records must not stop the scan ----------------------

_BAD_EXTRAS: list[Any] = [None, {}, {"codex": "x"}]


@pytest.mark.parametrize("bad", _BAD_EXTRAS)
def test_context_pressure_scan_continues_past_malformed(bad: Any) -> None:
    evs = [
        _ev("bad", 1, bad),
        _ev("good", 2, _cx(context_pressure={"occupancy": 99, "window": 100})),
    ]
    (f,) = check_context_pressure(evs)
    assert f.source.record_id == "good"


def test_context_pressure_scan_continues_past_missing_pressure() -> None:
    evs = [
        _ev("bad", 1, _cx(other=1)),
        _ev("good", 2, _cx(context_pressure={"occupancy": 99, "window": 100})),
    ]
    assert len(check_context_pressure(evs)) == 1


@pytest.mark.parametrize("bad", _BAD_EXTRAS)
def test_foreign_shape_scan_continues_past_malformed(bad: Any) -> None:
    evs = [
        _ev("bad", 1, bad),
        _ev("good", 2, _cx(item_type="reasoning", reasoning_content_shape="array")),
    ]
    (f,) = check_foreign_shape(evs)
    assert f.source.record_id == "good"


def test_foreign_shape_scan_continues_past_non_str_item_type_and_unknown_family() -> None:
    evs = [
        _ev("b1", 1, _cx(item_type=5, reasoning_content_shape="array")),
        _ev("b2", 2, _cx(item_type="message", reasoning_content_shape="array")),
        _ev("good", 3, _cx(item_type="reasoning", reasoning_content_shape="array")),
    ]
    (f,) = check_foreign_shape(evs)
    assert f.source.record_id == "good"
    assert dict(f.evidence or {})["item_count"] == 1


def test_compaction_snapshot_scan_continues_past_unmarked_event() -> None:
    evs = [
        _ev("plain", 1, {}),
        _ev("a", 2, _cx(item_type="m")),
        _ev("c", 3, _cx(guardian_items=[{"id": "a", "type": "x"}]), "compaction_boundary"),
    ]
    assert len(check_compaction_snapshot(evs)) == 1


def test_compaction_snapshot_inner_scan_continues_past_unprovable_items() -> None:
    evs = [
        _ev("a", 1, _cx(item_type="m")),
        _ev(
            "c",
            2,
            _cx(guardian_items=["junk", {"id": "unknown", "type": "q"}, {"id": "a", "type": "x"}]),
            "compaction_boundary",
        ),
    ]
    (f,) = check_compaction_snapshot(evs)
    assert dict(f.evidence or {})["item_id"] == "a"


def test_compaction_snapshot_counts_accumulate_for_future_and_correlation() -> None:
    evs = [
        _ev("c", 1, _cx(guardian_items=[{"id": "f1"}, {"id": "f2"}]), "compaction_boundary"),
        _ev("f1", 2, _cx(item_type="m")),
        _ev("f2", 3, _cx(item_type="m")),
        _ev("a", 4, _cx(item_type="m", call_id="k")),
        _ev(
            "c2",
            5,
            _cx(guardian_items=[{"id": "a", "call_id": "x"}, {"id": "a", "call_id": "y"}]),
            "compaction_boundary",
        ),
    ]
    got = {f.evidence["divergence"]: f for f in check_compaction_snapshot(evs)}
    assert got["future-item"].evidence["occurrences"] == 2
    assert got["correlation-mismatch"].evidence["occurrences"] == 2


def test_compaction_snapshot_future_item_id_truncated_to_256() -> None:
    long_id = "q" * 300
    evs = [
        _ev("c", 1, _cx(guardian_items=[{"id": long_id}]), "compaction_boundary"),
        _ev(long_id, 2, _cx(item_type="m")),
    ]
    (f,) = check_compaction_snapshot(evs)
    assert dict(f.evidence or {})["item_id"] == "q" * 256


# --- durable_prefix ----------------------------------------------------------


def test_durable_trailing_anchor_scan_continues_past_non_int_ordinal() -> None:
    evs = [
        _ev("x", 1, _cx(ordinal="1", durable=True)),
        _ev("a", 2, _cx(ordinal=0, durable=True, subagent_history_start_ordinal=3)),
        _ev("claim", 3, _cx(ordinal=3, durable=False)),
    ]
    (f,) = check_durable_prefix(evs)
    assert f.source.record_id == "claim"


def test_durable_trailing_falls_back_to_last_marked_record() -> None:
    # Only a negative durable ordinal exists, claim points past it and
    # matches no record: the anchor is the last marked record.
    evs = [
        _ev("first", 1, _cx(ordinal=-2, durable=True, subagent_history_start_ordinal=-1)),
        _ev("last", 2, _cx(note="no ordinal")),
    ]
    (f,) = check_durable_prefix(evs)
    assert f.source.record_id == "last"
    assert "tail_ordinal" not in dict(f.evidence or {})


def test_durable_present_count_accumulates() -> None:
    evs = [
        _ev("p1", 1, _cx(item_type="reasoning", has_encrypted_content=True)),
        _ev("p2", 2, _cx(item_type="reasoning", has_encrypted_content=True)),
        _ev("p3", 3, _cx(item_type="reasoning", has_encrypted_content=True)),
        _ev("m", 4, _cx(item_type="reasoning", has_encrypted_content=False)),
    ]
    (f,) = check_durable_prefix(evs)
    assert dict(f.evidence or {})["present_count"] == 3
