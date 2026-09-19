"""Tests for repair-engine T-04: identical-duplicate-drop + seq-renumber."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from sesslint import api
from sesslint.repair.planner import SYNTHETIC_STEP_FP
from sesslint.repair.planner import plan as planner_plan

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"
VENDOR_TORN = FIXTURES_DIR / "adapters" / "codex" / "torn_tail.jsonl"

_HDR = {
    "created_at": "2026-01-01T00:00:00Z",
    "schema_version": "sesslint.session/v1",
    "session_id": "t04",
    "source": {"format": "canonical"},
    "version": 1,
}


def _ev(i: str, pid: str | None, seq: int, ts: str, actor: str, content: str) -> dict:
    return {
        "actor": actor,
        "id": i,
        "kind": "message",
        "parent_id": pid,
        "payload": {"content": content},
        "seq": seq,
        "ts": ts,
    }


def _write(tmp_path: Path, events: list[dict], name: str = "s.jsonl") -> Path:
    src = tmp_path / name
    lines = [json.dumps(_HDR), *(json.dumps(e) for e in events)]
    src.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return src


def _dup_events(*, adjacent: bool) -> list[dict]:
    """Identical-duplicate of e2 — same id/parent/ts/content, only seq differs."""
    if adjacent:
        return [
            _ev("e1", None, 0, "2026-01-01T00:00:01Z", "user", "a"),
            _ev("e2", "e1", 1, "2026-01-01T00:00:02Z", "assistant", "A"),
            _ev("e2", "e1", 2, "2026-01-01T00:00:02Z", "assistant", "A"),
            _ev("e3", "e2", 3, "2026-01-01T00:00:03Z", "user", "b"),
        ]
    return [
        _ev("e1", None, 0, "2026-01-01T00:00:01Z", "user", "a"),
        _ev("e2", "e1", 1, "2026-01-01T00:00:02Z", "assistant", "A"),
        _ev("e3", "e2", 2, "2026-01-01T00:00:03Z", "user", "b"),
        _ev("e2", "e1", 3, "2026-01-01T00:00:02Z", "assistant", "A"),
    ]


def test_nonadjacent_dup_plans_drop_plus_renumber(tmp_path: Path) -> None:
    """Non-adjacent identical dup → identical-duplicate-drop + seq-renumber."""
    src = _write(tmp_path, _dup_events(adjacent=False))
    plan = api.plan(src)
    recipes = [s.recipe for s in plan.steps]
    assert "identical-duplicate-drop" in recipes
    assert recipes[-1] == "seq-renumber"
    ren = plan.steps[-1]
    assert ren.target_finding_fp == SYNTHETIC_STEP_FP
    assert ren.target_index is None
    assert not ren.lossy
    assert plan.blocked == ()


def test_adjacent_dup_still_collapses(tmp_path: Path) -> None:
    """Adjacent identical pair keeps identical-duplicate-collapse semantics."""
    src = _write(tmp_path, _dup_events(adjacent=True))
    plan = api.plan(src)
    recipes = [s.recipe for s in plan.steps]
    assert "identical-duplicate-collapse" in recipes
    assert "identical-duplicate-drop" not in recipes
    assert recipes[-1] == "seq-renumber"


def test_conflicting_dup_blocked_manual(tmp_path: Path) -> None:
    """Conflicting-duplicate class never reaches a drop recipe."""
    evs = [
        _ev("e1", None, 0, "2026-01-01T00:00:01Z", "user", "a"),
        _ev("e2", "e1", 1, "2026-01-01T00:00:02Z", "assistant", "A"),
        _ev("e2", "e1", 2, "2026-01-01T00:00:09Z", "assistant", "DIFFERENT"),
        _ev("e3", "e2", 3, "2026-01-01T00:00:03Z", "user", "b"),
    ]
    src = _write(tmp_path, evs)
    from sesslint.repair.errors import RepairRefused

    with pytest.raises(RepairRefused):
        api.plan(src)


def test_drop_removes_only_later_identicals(tmp_path: Path) -> None:
    """End-to-end: later identical removed, legit middle event kept."""
    src = _write(tmp_path, _dup_events(adjacent=False))
    out = tmp_path / "out.jsonl"
    api.repair(src, output_path=out)
    evs = [
        json.loads(line) for line in out.read_text().splitlines() if line.strip() and "seq" in line
    ]
    assert [e["id"] for e in evs] == ["e1", "e2", "e3"]


def test_renumbered_seq_contiguous(tmp_path: Path) -> None:
    """seq-renumber emits contiguous 0..n-1 ordinals after drops."""
    src = _write(tmp_path, _dup_events(adjacent=False))
    out = tmp_path / "out.jsonl"
    api.repair(src, output_path=out)
    evs = [
        json.loads(line) for line in out.read_text().splitlines() if line.strip() and "seq" in line
    ]
    assert [e["seq"] for e in evs] == list(range(len(evs)))


def test_no_renumber_without_drops(tmp_path: Path) -> None:
    """Clean canonical input plans no synthetic steps."""
    evs = [
        _ev("e1", None, 0, "2026-01-01T00:00:01Z", "user", "a"),
        _ev("e2", "e1", 1, "2026-01-01T00:00:02Z", "assistant", "A"),
    ]
    src = _write(tmp_path, evs)
    plan = api.plan(src)
    assert all(s.recipe != "seq-renumber" for s in plan.steps)


def test_no_renumber_on_vendor_input(tmp_path: Path) -> None:
    """Vendor input skips seq-renumber (write-back keeps vendor lines)."""
    src = tmp_path / "v.jsonl"
    shutil.copyfile(VENDOR_TORN, src)
    plan = api.plan(src)
    assert len(plan.steps) >= 1
    assert all(s.recipe != "seq-renumber" for s in plan.steps)


def test_repair_output_idempotent(tmp_path: Path) -> None:
    """Repaired output is a fixed point: no findings, no further steps."""
    src = _write(tmp_path, _dup_events(adjacent=False))
    out = tmp_path / "out.jsonl"
    api.repair(src, output_path=out)
    plan2 = api.plan(out)
    assert plan2.steps == ()
    assert plan2.blocked == ()


def test_seq_renumber_step_idempotent() -> None:
    """Applying seq-renumber twice converges to the same event list."""
    from sesslint.repair.planner import PlanStep
    from sesslint.repair.recipes_conservative import apply_seq_renumber

    step = PlanStep(seq=0, recipe="seq-renumber", target_finding_fp="-", target_index=None)
    evs = [{"id": "a", "seq": 5, "kind": "message"}, {"id": "b", "seq": 9, "kind": "message"}]
    once = apply_seq_renumber(evs, step)
    twice = apply_seq_renumber(once, step)
    assert once == twice
    assert [e["seq"] for e in once] == [0, 1]


def test_drop_fails_closed_on_conflicting_variant() -> None:
    """Crafted plan with conflicting variant is refused inside the recipe."""
    from sesslint.repair.planner import PlanStep
    from sesslint.repair.recipes_conservative import (
        PreconditionFailed,
        apply_identical_duplicate_drop,
    )

    step = PlanStep(
        seq=0,
        recipe="identical-duplicate-drop",
        target_finding_fp="fp",
        target_index=1,
        params={"variant": "conflicting-duplicate", "record_indexes": [1, 2]},
    )
    with pytest.raises(PreconditionFailed):
        apply_identical_duplicate_drop([{"id": "x"}] * 4, step)


def test_drop_fails_closed_on_content_drift() -> None:
    """Recipe refuses when a listed occurrence no longer matches content."""
    from sesslint.repair.planner import PlanStep
    from sesslint.repair.recipes_conservative import (
        PreconditionFailed,
        apply_identical_duplicate_drop,
    )

    evs = [
        {"id": "e", "kind": "message", "payload": {"content": "A"}},
        {"id": "e", "kind": "message", "payload": {"content": "A"}},
        {"id": "e", "kind": "message", "payload": {"content": "DRIFTED"}},
    ]
    step = PlanStep(
        seq=0,
        recipe="identical-duplicate-drop",
        target_finding_fp="fp",
        target_index=0,
        params={"variant": "identical-duplicate", "record_indexes": [0, 1, 2]},
    )
    with pytest.raises(PreconditionFailed):
        apply_identical_duplicate_drop(evs, step)


def test_plan_determinism_with_synthetic_step(tmp_path: Path) -> None:
    """Identical input yields identical plan bytes including renumber."""
    src = _write(tmp_path, _dup_events(adjacent=False))
    a = api.plan(src).to_dict()
    b = api.plan(src).to_dict()
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_seq_renumber_absent_when_no_steps(tmp_path: Path) -> None:
    """Pure relink-only plans carry no normalizing tail step."""
    evs = [_ev("e1", None, 0, "2026-01-01T00:00:01Z", "user", "a")]
    src = _write(tmp_path, evs)
    plan = api.plan(src)
    assert all(s.recipe != "seq-renumber" for s in plan.steps)


def test_planner_input_format_default_off(tmp_path: Path) -> None:
    """planner.plan() without input_format never appends seq-renumber."""
    out_plan = planner_plan(findings=[], events=[])
    assert all(s.recipe != "seq-renumber" for s in out_plan.steps)
