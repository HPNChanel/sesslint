"""Tests for the torn-record-excision salvage recipe (SL001).

Validates:
- ``sl001_excisable`` accepts only real per-line malformed records — never
  stream-level ``size_limit_exceeded`` refusals, missing coordinates, or
  records with provable dependents in the parsed event stream.
- Conservative policy and missing acknowledgement block planning with the
  pinned reasons (``needs-salvage-policy`` / ``needs-acknowledgement``).
- Plan steps carry source-coordinate anchors and declare loss class
  ``torn-record``; ``total_kept`` counts parsed events only (the torn record
  never produced an event).
- Apply-time validation re-checks anchors and dependents (crafted-plan
  fail-closed); parsed events are preserved verbatim.
- End-to-end canonical repair emits a fully parseable stream with the torn
  line removed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sesslint.canonical import SessionEvent
from sesslint.codes import SL001, SL006
from sesslint.finding import Repairability, Severity, SourceRef, make_finding
from sesslint.repair.planner import (
    PlanStep,
    plan,
)
from sesslint.repair.preconditions import PreconditionContext
from sesslint.repair.recipes_conservative import (
    PreconditionFailed,
)
from sesslint.repair.recipes_conservative import (
    register_all as register_conservative,
)
from sesslint.repair.recipes_salvage import (
    apply_torn_record_excision,
    apply_torn_record_excision_with_loss,
    sl001_excisable,
)
from sesslint.repair.recipes_salvage import (
    register_all as register_salvage,
)
from sesslint.repair.registry import clear_registry


@pytest.fixture(autouse=True)
def setup_recipe_registry() -> None:
    """Ensure both recipe packs are registered before each test."""
    clear_registry()
    register_conservative()
    register_salvage()


_TORN_EVIDENCE: dict[str, Any] = {
    "byte_offset": 120,
    "byte_end": 210,
    "record_ordinal": 2,
}


def _ev(i: int, parent: str | None = None) -> SessionEvent:
    return SessionEvent(
        id=f"msg-{i}",
        parent_id=parent,
        seq=i,
        ts=f"2026-09-05T12:00:0{i}Z",
        actor="user" if i % 2 == 0 else "assistant",
        kind="message",
        payload={"text": f"m{i}"},
    )


def _sl001_finding(
    *,
    line: int | None = 3,
    record_id: str | None = "msg-torn",
    evidence: dict[str, Any] | None = None,
) -> Any:
    return make_finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Malformed nonterminal record on line {line} for record {record_id}",
        source=SourceRef(path="sess.jsonl", line=line, record_id=record_id),
        evidence=dict(_TORN_EVIDENCE if evidence is None else evidence),
    )


def _ctx(
    finding: Any,
    events: list[SessionEvent],
    *,
    policy: str = "salvage",
    ack: bool = True,
) -> PreconditionContext:
    return PreconditionContext(
        findings=[finding],
        events=events,
        profile="neutral",
        source_hash="0" * 64,
        finding=finding,
        policy=policy,
        acknowledge_side_effects=ack,
    )


def test_sl001_excisable_precondition() -> None:
    """sl001_excisable passes only for real per-line torn records."""
    events = [_ev(0), _ev(2)]
    f = _sl001_finding()
    assert sl001_excisable(_ctx(f, events)) is True

    # size-limit refusals carry no droppable line
    f_size = _sl001_finding(evidence={"reason": "size_limit_exceeded", "limit": 10})
    assert sl001_excisable(_ctx(f_size, events)) is False

    # No physical line -> nothing to excise
    assert sl001_excisable(_ctx(_sl001_finding(line=None), events)) is False

    # Missing/degenerate stream coordinates -> not a real torn record
    for bad_ev in (
        {"byte_end": 10, "record_ordinal": 1},
        {"byte_offset": 5, "record_ordinal": 1},
        {"byte_offset": 0, "byte_end": 9, "record_ordinal": 0},
        {"byte_offset": 9, "byte_end": 9, "record_ordinal": 1},
        {"byte_offset": "x", "byte_end": 9, "record_ordinal": 1},
    ):
        assert sl001_excisable(_ctx(_sl001_finding(evidence=bad_ev), events)) is False

    # Provable dependents: a parsed event parents to the extracted record id
    dependent = _ev(3, parent="msg-torn")
    assert sl001_excisable(_ctx(f, events + [dependent])) is False

    # Non-SL001 finding never matches
    f_other = make_finding(
        code=SL006,
        severity=Severity.WARNING,
        repairability=Repairability.MANUAL,
        message_template="Disconnected branch at line {line}",
        source=SourceRef(path="sess.jsonl", line=3),
        evidence=dict(_TORN_EVIDENCE),
    )
    assert sl001_excisable(_ctx(f_other, events)) is False


def test_plan_sl001_salvage_emits_excision_step() -> None:
    """Under salvage+ack the plan carries one excision step with declared loss."""
    events = [_ev(0), _ev(2)]
    f = _sl001_finding()
    p = plan([f], events, policy="salvage", acknowledge_side_effects=True)
    assert len(p.steps) == 1
    step = p.steps[0]
    assert step.recipe == "torn-record-excision"
    assert step.lossy is True
    assert step.min_policy == "salvage"
    assert step.loss == {"torn-record": 1}
    # Anchors injected for apply-time validation and manifest honesty
    assert step.params["line"] == 3
    assert step.params["record_id"] == "msg-torn"
    assert step.params["byte_offset"] == 120
    assert step.params["record_ordinal"] == 2
    # The torn record never produced an event: kept stays len(events)
    assert p.total_lost == 1
    assert p.total_kept == 2
    assert p.blocked == ()


def test_plan_sl001_conservative_and_noack_blocked() -> None:
    """Conservative policy and missing acknowledgement both block the recipe."""
    events = [_ev(0), _ev(2)]
    f = _sl001_finding()

    p_cons = plan([f], events, policy="conservative")
    assert len(p_cons.steps) == 0
    assert [b.reason for b in p_cons.blocked] == ["needs-salvage-policy"]

    p_noack = plan([f], events, policy="salvage", acknowledge_side_effects=False)
    assert len(p_noack.steps) == 0
    assert [b.reason for b in p_noack.blocked] == ["needs-acknowledgement"]


def test_plan_sl001_dependents_and_size_limit_blocked() -> None:
    """Provable dependents and stream-level refusals are never excised."""
    events = [_ev(0), _ev(3, parent="msg-torn")]
    f = _sl001_finding()
    p_dep = plan([f], events, policy="salvage", acknowledge_side_effects=True)
    assert len(p_dep.steps) == 0
    assert [b.reason for b in p_dep.blocked] == ["precondition-failed:sl001_excisable"]

    f_size = _sl001_finding(evidence={"reason": "size_limit_exceeded", "limit": 10})
    p_size = plan([f_size], [_ev(0)], policy="salvage", acknowledge_side_effects=True)
    assert len(p_size.steps) == 0
    assert [b.reason for b in p_size.blocked] == ["precondition-failed:sl001_excisable"]


def test_plan_sl001_multiple_torn_lines() -> None:
    """Each torn record gets its own excision step; loss sums honestly."""
    events = [_ev(0), _ev(2)]
    f_a = _sl001_finding(line=3)
    f_b = _sl001_finding(line=5, record_id="msg-torn2")
    p = plan([f_a, f_b], events, policy="salvage", acknowledge_side_effects=True)
    assert len(p.steps) == 2
    assert all(s.recipe == "torn-record-excision" for s in p.steps)
    assert p.total_lost == 2
    assert p.total_kept == 2


def test_apply_torn_record_excision_validation() -> None:
    """Apply re-validates anchors and dependents; events are preserved verbatim."""
    events = [_ev(0), _ev(2)]
    step = PlanStep(
        seq=0,
        recipe="torn-record-excision",
        target_finding_fp="fp",
        target_index=None,
        params={
            "line": 3,
            "record_ordinal": 2,
            "byte_offset": 120,
            "byte_end": 210,
            "record_id": "msg-torn",
        },
        lossy=True,
        loss={"torn-record": 1},
        min_policy="salvage",
    )

    out, loss = apply_torn_record_excision_with_loss(events, step)
    assert loss == {"torn-record": 1}
    assert [e["id"] for e in out] == ["msg-0", "msg-2"]
    assert apply_torn_record_excision(events, step) == out

    with pytest.raises(PreconditionFailed, match="empty session"):
        apply_torn_record_excision([], step)

    for bad in (
        {"record_ordinal": 2, "byte_offset": 1, "byte_end": 5},
        {"line": 0, "record_ordinal": 2, "byte_offset": 1, "byte_end": 5},
        {"line": 3, "record_ordinal": 0, "byte_offset": 1, "byte_end": 5},
        {"line": 3, "record_ordinal": 2, "byte_offset": 5, "byte_end": 5},
        {"line": "3", "record_ordinal": 2, "byte_offset": 1, "byte_end": 5},
    ):
        bad_step = PlanStep(
            seq=0,
            recipe="torn-record-excision",
            target_finding_fp="fp",
            target_index=None,
            params=bad,
            lossy=True,
            loss={"torn-record": 1},
            min_policy="salvage",
        )
        with pytest.raises(PreconditionFailed):
            apply_torn_record_excision(events, bad_step)

    dependent = _ev(3, parent="msg-torn")
    with pytest.raises(PreconditionFailed, match="dependent"):
        apply_torn_record_excision(events + [dependent], step)


def test_repair_torn_record_end_to_end(tmp_path: Path) -> None:
    """E2E: canonical file with a torn mid-record repairs to a clean stream."""
    from sesslint import api

    src = tmp_path / "torn.jsonl"
    lines = [
        json.dumps(
            {
                "created_at": "2026-09-05T12:00:00Z",
                "schema_version": "sesslint.session/v1",
                "session_id": "sess-torn-e2e",
            }
        ),
        json.dumps(
            {
                "actor": "user",
                "id": "msg-0",
                "kind": "message",
                "parent_id": None,
                "payload": {"text": "hello"},
                "seq": 0,
                "ts": "2026-09-05T12:00:00Z",
            }
        ),
        '{"actor":"assistant","id":"msg-torn","kind":"message", CORRUPT ////',
        json.dumps(
            {
                "actor": "user",
                "id": "msg-2",
                "kind": "message",
                "parent_id": "msg-0",
                "payload": {"text": "proceed"},
                "seq": 2,
                "ts": "2026-09-05T12:00:02Z",
            }
        ),
    ]
    src.write_text("\n".join(lines) + "\n", encoding="utf-8")
    out = tmp_path / "out.jsonl"

    plan_obj, manifest = api.repair(
        source_path=str(src),
        output_path=str(out),
        policy="salvage",
        format="canonical",
        acknowledge_side_effects=True,
    )
    assert [s.recipe for s in plan_obj.steps] == ["torn-record-excision"]
    assert plan_obj.loss_accounting.total_lost == 1
    assert plan_obj.loss_accounting.total_kept == 2

    out_lines = out.read_text(encoding="utf-8").splitlines()
    assert len(out_lines) == 3
    for line in out_lines:
        json.loads(line)  # every emitted line parses
    assert all("CORRUPT" not in line for line in out_lines)
    assert manifest is not None

    # The repaired artifact re-checks clean under the same profile.
    from sesslint.repair.executor import load_session_source_with_findings

    _hdr, out_events, out_stream_findings = load_session_source_with_findings(out)
    assert len(out_events) == 2
    assert [f for f in out_stream_findings if f.code == SL001] == []
