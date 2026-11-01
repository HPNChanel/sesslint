"""Mutation-driven tests for checks/checkpoint.py event paths and the cap (CL-15)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from sesslint.checks import checkpoint as cp
from sesslint.checks.checkpoint import check_checkpoint_gap
from sesslint.codes import SL201, Repairability, Severity
from sesslint.context import CheckContext

CTX = CheckContext(adapter_id="ad", adapter_version="1", profile_id="pr", profile_version="2")


def _e(kind: str, eid: str | None, line: int | None, **payload: Any) -> Any:
    return SimpleNamespace(
        kind=kind,
        id=eid,
        source_location="dir\\f.jsonl",
        source_line=line,
        payload=payload or None,
    )


def test_run_start_without_checkpoint_source_fields() -> None:
    (f,) = check_checkpoint_gap([_e("run_start", "r1", 4)], context=CTX)
    assert f.code == "SL201"
    assert f.severity is Severity.ERROR
    assert f.repairability is Repairability.MANUAL
    assert f.source.path == "dir/f.jsonl"
    assert f.source.line == 4
    assert f.source.record_id == "r1"
    assert dict(f.evidence or {}) == {"at_index": 0, "expected_seq": 0, "found_seq": None}


def test_missing_event_id_uses_positional_placeholder() -> None:
    (f,) = check_checkpoint_gap([_e("run_start", None, 4)], context=CTX)
    assert f.source.record_id == "<event:0>"
    (f,) = check_checkpoint_gap([_e("x", "a", 1), _e("continuation", None, 2)], context=CTX)
    assert f.source.record_id == "<event:1>"


def test_checkpoint_without_hash_source_fields() -> None:
    ev = _e("checkpoint", "c1", 7, checkpoint_id="k", seq=0)
    (f,) = check_checkpoint_gap([ev], context=CTX)
    assert f.source.path == "dir/f.jsonl"
    assert f.source.line == 7
    assert f.source.record_id == "c1"
    assert dict(f.evidence or {}) == {"at_index": 0, "expected_seq": 0, "found_seq": 0}


def test_checkpoint_seq_jump_source_fields() -> None:
    evs = [
        _e("checkpoint", "c1", 1, checkpoint_id="a", seq=0, state_hash="h"),
        _e("checkpoint", "c2", 9, checkpoint_id="b", seq=3, state_hash="h2"),
    ]
    (f,) = check_checkpoint_gap(evs, context=CTX)
    assert f.source.line == 9
    assert f.source.record_id == "c2"
    assert dict(f.evidence or {}) == {"at_index": 1, "expected_seq": 1, "found_seq": 3}


def test_high_sensitivity_missing_seq_source_fields() -> None:
    evs = [
        _e("checkpoint", "c1", 1, checkpoint_id="a", seq=4, state_hash="h"),
        _e("checkpoint", "c2", 6, checkpoint_id="b", state_hash="h2"),
    ]
    assert check_checkpoint_gap(evs, context=CTX) == []
    (f,) = check_checkpoint_gap(evs, context=CTX, checkpoint_sensitivity="high")
    assert f.source.line == 6
    assert f.source.record_id == "c2"
    assert dict(f.evidence or {}) == {
        "at_index": 1,
        "expected_seq": 5,
        "found_seq": None,
        "sensitivity": "high",
    }


def test_cap_overflow_summary_exact() -> None:
    evs = [_e("run_start", f"r{i:02d}", i + 1) for i in range(5)]
    out = check_checkpoint_gap(evs, source_path="a\\b.jsonl", max_findings=2, context=CTX)
    assert len(out) == 3
    *kept, overflow = out
    assert [k.source.record_id for k in kept] == ["r00", "r01"]
    assert overflow.code == SL201
    assert overflow.severity is Severity.WARNING
    assert overflow.repairability is Repairability.MANUAL
    assert overflow.source.path == "a/b.jsonl"
    assert overflow.source.line is None
    assert overflow.source.record_id is None
    assert dict(overflow.evidence or {}) == {
        "cap": 2,
        "overflow": True,
        "total_count": 5,
        "truncated_count": 3,
        "variant": "overflow-summary",
    }


def test_cap_overflow_carries_context_metadata() -> None:
    evs = [_e("run_start", f"r{i}", i + 1) for i in range(3)]
    a = check_checkpoint_gap(evs, max_findings=1, context=CTX)[-1]
    b = check_checkpoint_gap(
        evs,
        max_findings=1,
        context=CheckContext(
            adapter_id="other", adapter_version="1", profile_id="pr", profile_version="2"
        ),
    )[-1]
    assert a.fingerprint != b.fingerprint


def test_cap_at_exact_limit_has_no_overflow() -> None:
    evs = [_e("run_start", f"r{i}", i + 1) for i in range(3)]
    assert len(check_checkpoint_gap(evs, max_findings=3, context=CTX)) == 3
    assert len(check_checkpoint_gap(evs, max_findings=2, context=CTX)) == 3


def test_cap_helper_default_source_path_and_context() -> None:
    f = [
        cp.make_finding(
            code=SL201,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message_template="Checkpoint gap detected for record {record_id}",
            source=cp.SourceRef(path="p", line=None, record_id=f"r{i}"),
        )
        for i in range(3)
    ]
    out = cp.cap_checkpoint_findings(f, code="SL201", max_findings=1)
    assert out[-1].source.path == "<canonical>"


def test_run_state_object_item_without_optional_attributes() -> None:
    ctx = SimpleNamespace(
        source_metadata={
            "checkpoints": [
                SimpleNamespace(),
                SimpleNamespace(id="x"),
                SimpleNamespace(checkpoint_id="y"),
            ]
        }
    )
    out = cp._extract_run_state_checkpoints(context=ctx)  # type: ignore[arg-type]
    assert [(o["id"], o["seq"], o["hash"]) for o in out] == [
        ("chk-runstate-0", None, None),
        ("x", None, None),
        ("y", None, None),
    ]


def test_run_state_hash_sentinel_strings_become_none() -> None:
    ctx = SimpleNamespace(
        source_metadata={
            "checkpoints": [
                {"id": "a", "hash": "<NoneType>"},
                {"id": "b", "hash": "<null>"},
                {"id": "c", "hash": "<nonetype>"},
                {"id": "d", "hash": "NULL"},
            ]
        }
    )
    out = cp._extract_run_state_checkpoints(context=ctx)  # type: ignore[arg-type]
    assert [o["hash"] for o in out] == [None, None, "<nonetype>", "NULL"]


def test_event_baseline_follows_run_state_last_seq() -> None:
    meta = CheckContext(
        source_metadata={
            "checkpoints": [
                {"id": "a", "seq": 0, "hash": "h0"},
                {"id": "b", "seq": 1, "hash": "h1"},
            ]
        }
    )
    ev = _e("checkpoint", "c", 3, checkpoint_id="k")
    (f,) = check_checkpoint_gap([ev], context=meta)
    assert dict(f.evidence or {})["expected_seq"] == 2


def test_divergence_on_mapping_events_and_ids() -> None:
    evs = [
        {"kind": "checkpoint", "id": "a", "payload": {"seq": 1, "state_hash": "h1"}},
        {"kind": "checkpoint", "id": "b", "payload": {"seq": 1, "state_hash": "h2"}},
    ]
    (f,) = cp.check_checkpoint_divergence(evs, context=CTX)
    assert f.code == "SL202"
    assert f.source.record_id == "b"
    assert dict(f.evidence or {}) == {"hash_a": "h1", "hash_b": "h2", "seq": 1}


def _chain(parent_of_leaf: str | None) -> list[Any]:
    leaf = SimpleNamespace(
        kind="message", id="leaf", parent_id=parent_of_leaf, source_location="f", source_line=1
    )
    boundary = SimpleNamespace(
        kind="compaction_boundary",
        id="bnd",
        parent_id=None,
        source_location="f",
        source_line=2,
        extra_fields={"coverage": {"covered_through_id": "leaf"}},
    )
    return [leaf, boundary]


def test_coverage_ancestor_equal_to_boundary_is_non_contiguous() -> None:
    (f,) = cp.check_compaction_coverage(_chain("bnd"), context=CTX)
    assert f.code == "SL205"
    assert dict(f.evidence or {})["non_contiguous"] is True
    assert cp.check_compaction_coverage(_chain(None), context=CTX) == []


def test_coverage_default_source_path_is_canonical_placeholder() -> None:
    boundary = SimpleNamespace(
        kind="compaction_boundary",
        id="bnd",
        parent_id=None,
        extra_fields={"coverage": {"covered_through_id": "nope"}},
    )
    (f,) = cp.check_compaction_coverage([boundary], context=CTX)
    assert f.source.path == "<canonical>"
    assert dict(f.evidence or {})["missing"] is True


def test_check_checkpoint_orders_by_code_before_location() -> None:
    boundary = SimpleNamespace(
        kind="compaction_boundary",
        id="bnd",
        parent_id=None,
        source_location="f",
        source_line=1,
        extra_fields={"coverage": {"covered_through_id": "nope"}},
    )
    start = SimpleNamespace(
        kind="run_start", id="rs", parent_id=None, source_location="f", source_line=9
    )
    out = cp.check_checkpoint([boundary, start], context=CTX)
    assert [f.code for f in out] == ["SL201", "SL205"]
    assert [f.source.line for f in out] == [9, 1]


def test_gap_fingerprint_depends_on_every_context_field() -> None:
    base = {"adapter_id": "ad", "adapter_version": "1", "profile_id": "pr", "profile_version": "2"}
    runstate = {
        "checkpoints": [
            {"id": "a", "seq": 0, "hash": "h"},
            {"id": "b", "seq": 3, "hash": None},
            {"id": "c"},
        ]
    }
    events = [
        _e("run_start", "r", 1),
        _e("checkpoint", "c1", 2, checkpoint_id="x", seq=0),
        _e("checkpoint", "c2", 3, checkpoint_id="y", seq=5, state_hash="h"),
        _e("checkpoint", "c3", 4, checkpoint_id="z", state_hash="h"),
    ]

    def run(ctx_fields: dict[str, str], meta: Any) -> list[str]:
        ctx = CheckContext(**ctx_fields, source_metadata=meta)
        return [
            f.fingerprint
            for f in check_checkpoint_gap(events, context=ctx, checkpoint_sensitivity="high")
        ]

    for meta in (None, runstate):
        ref = run(base, meta)
        assert len(ref) >= 3
        for field in base:
            other = run({**base, field: "zz"}, meta)
            assert len(other) == len(ref)
            assert all(a != b for a, b in zip(ref, other, strict=True)), field
