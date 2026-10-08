"""B21: plan steps address source positions, whatever earlier steps removed.

The planner derives every step's indexes from the source as loaded, but each
drop step shifts the events after it. The executor re-addresses each step to
the current events and fails closed when an earlier step already removed its
target. An SL003 group is collapsed only when it is exactly one adjacent pair;
a larger group drops every later copy in one step.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sesslint import api
from sesslint.codes import SL003
from sesslint.repair.errors import OutputInvalid, RepairRefused
from sesslint.repair.executor import execute
from sesslint.repair.fingerprint import compute_plan_fingerprint
from sesslint.repair.planner import RepairPlan

HEADER = (
    '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1",'
    '"session_id":"coords"}\n'
)


def _line(event: dict[str, Any]) -> str:
    return json.dumps(event, separators=(",", ":"), sort_keys=True) + "\n"


def _msg(i: int, parent: str | None, text: str) -> dict[str, Any]:
    return {
        "actor": "user" if i % 2 == 0 else "assistant",
        "id": f"msg-{i}",
        "kind": "message",
        "parent_id": parent,
        "payload": {"text": text},
        "seq": i,
        "ts": f"2026-09-05T12:00:0{i}Z",
    }


M0, M1, M2, M3 = (
    _line(_msg(0, None, "a")),
    _line(_msg(1, "msg-0", "b")),
    _line(_msg(2, "msg-1", "c")),
    _line(_msg(3, "msg-2", "d")),
)
INTERLEAVED = HEADER + M0 + M1 + M2 + M1 + M2 + M3


def _stage(tmp_path: Path, text: str) -> Path:
    src = tmp_path / "session.jsonl"
    src.write_bytes(text.encode("utf-8"))
    return src


def _ids(path: Path) -> list[str]:
    return [json.loads(line)["id"] for line in path.read_text(encoding="utf-8").splitlines()[1:]]


@pytest.mark.parametrize(
    "text",
    [
        HEADER + M0 + M1 + M1 + M2 + M2 + M3,
        INTERLEAVED,
        HEADER + M0 + M1 + M1 + M1 + M2 + M3,
        HEADER + M0 + M1 + M2 + M1 + M3 + M1,
    ],
    ids=["two-adjacent-pairs", "interleaved", "triple", "spread-triple"],
)
def test_every_duplicate_group_is_repaired_in_one_pass(tmp_path: Path, text: str) -> None:
    src = _stage(tmp_path, text)
    out = tmp_path / "out.jsonl"
    _plan, manifest = api.repair(src, out)
    assert manifest is not None
    assert _ids(out) == ["msg-0", "msg-1", "msg-2", "msg-3"]
    assert not [f for f in api.check_file(out).findings if f.code == SL003]


def test_group_of_three_is_dropped_not_collapsed(tmp_path: Path) -> None:
    """Collapsing one pair of a triple used to leave a copy behind and still pass."""
    src = _stage(tmp_path, HEADER + M0 + M1 + M1 + M1 + M2)
    assert [s.recipe for s in api.plan_repair(src).steps] == [
        "identical-duplicate-drop",
        "seq-renumber",
    ]


def test_truncated_duplicate_group_is_refused(tmp_path: Path) -> None:
    """Evidence lists at most 32 copies: dropping only those would leave the rest."""
    src = _stage(tmp_path, HEADER + M0 + M1 * 40 + M2)
    plan = api.plan_repair(src)
    assert plan.steps == ()
    assert [(b.code, b.reason) for b in plan.blocked] == [
        (SL003, "precondition-failed:sl003_identical_duplicate")
    ]


def test_salvage_drop_before_duplicate_group(tmp_path: Path) -> None:
    orphan = {
        "actor": "tool",
        "correlation_id": "call-gone",
        "id": "res-x",
        "kind": "tool_result",
        "parent_id": "msg-0",
        "payload": {"text": "r"},
        "seq": 1,
        "ts": "2026-09-05T12:00:01Z",
    }
    src = _stage(tmp_path, HEADER + M0 + _line(orphan) + M1 + M2 + M1 + M3)
    plan = api.plan_repair(src, policy="salvage", acknowledge_side_effects=True)
    assert [s.recipe for s in plan.steps] == [
        "orphan-result-drop",
        "identical-duplicate-drop",
        "seq-renumber",
    ]
    out = tmp_path / "out.jsonl"
    api.repair(src, out, policy="salvage", acknowledge_side_effects=True)
    assert _ids(out) == ["msg-0", "msg-1", "msg-2", "msg-3"]


def test_step_whose_target_an_earlier_step_removed_fails_closed(tmp_path: Path) -> None:
    src = _stage(tmp_path, INTERLEAVED)
    doc = api.plan_repair(src).to_dict()
    first = doc["steps"][0]
    assert first["params"]["record_indexes"] == [1, 3]
    doc["steps"] = [first, dict(first, seq=1)]
    doc.pop("fingerprint")
    doc["fingerprint"] = compute_plan_fingerprint(doc)
    out = tmp_path / "out.jsonl"
    with pytest.raises(RepairRefused, match="derives for this source now"):
        execute(source_path=src, plan=RepairPlan.from_dict(doc), output_path=out)
    assert not out.exists()


def test_relocation_refuses_an_already_removed_source_coordinate(tmp_path: Path) -> None:
    from sesslint.repair.executor import _relocate_step

    src = _stage(tmp_path, INTERLEAVED)
    step = api.plan_repair(src).steps[0]
    with pytest.raises(OutputInvalid, match="which an earlier step removed"):
        _relocate_step(step, {0: 0, 1: 1, 2: 2, 4: 3}, 5)
