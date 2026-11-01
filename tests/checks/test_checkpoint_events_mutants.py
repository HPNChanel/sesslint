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
