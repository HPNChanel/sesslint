"""B20: an exported plan is untrusted — every step must be one sesslint derives now.

The plan fingerprint is a plain digest anyone can recompute, so a hand-edited
plan still "verifies". Apply re-checks the source and refuses any step that is
not the planner's own step for a current finding (same recipe, params and
declared loss, in planner order); a subset of the derived steps is allowed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sesslint import api
from sesslint.cli import main
from sesslint.repair.errors import PlanSourceMismatch, RepairRefused
from sesslint.repair.fingerprint import compute_plan_fingerprint

HEADER = (
    '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1",'
    '"session_id":"vet"}\n'
)
MSG0 = (
    '{"actor":"user","id":"msg-0","kind":"message","parent_id":null,'
    '"payload":{"text":"hello"},"seq":0,"ts":"2026-09-05T12:00:00Z"}\n'
)
MSG1 = (
    '{"actor":"assistant","id":"msg-1","kind":"message","parent_id":"msg-0",'
    '"payload":{"text":"ok"},"seq":1,"ts":"2026-09-05T12:00:01Z"}\n'
)
MSG2 = (
    '{"actor":"user","id":"msg-2","kind":"message","parent_id":"msg-1",'
    '"payload":{"text":"go"},"seq":2,"ts":"2026-09-05T12:00:02Z"}\n'
)
DUPLICATE = HEADER + MSG0 + MSG1 + MSG1 + MSG2
TORN_MIDDLE = HEADER + MSG0 + MSG1 + '{"actor":"assistant","id":"msg-x", "payl\n' + MSG2
REFUSAL = "derives for this source now"


def _stage(tmp_path: Path, text: str, name: str = "session.jsonl") -> Path:
    src = tmp_path / name
    src.write_bytes(text.encode("utf-8"))
    return src


def _reseal(doc: dict[str, Any]) -> dict[str, Any]:
    """Recompute the fingerprint, as anyone holding an edited plan can."""
    doc = {k: v for k, v in doc.items() if k != "fingerprint"}
    doc["fingerprint"] = compute_plan_fingerprint(doc)
    return doc


def _forge(plan: dict[str, Any], **step_changes: Any) -> dict[str, Any]:
    doc = json.loads(json.dumps(plan))
    doc["steps"][0].update(step_changes)
    return _reseal(doc)


def test_exported_plan_applies(tmp_path: Path) -> None:
    src = _stage(tmp_path, DUPLICATE)
    exported = api.plan_repair(src).to_dict()
    _plan, manifest = api.apply_plan(src, exported, output_path=tmp_path / "out.jsonl")
    assert manifest is not None
    assert [a.kind for a in manifest.actions] == [s["recipe"] for s in exported["steps"]]


def test_subset_of_derived_steps_applies(tmp_path: Path) -> None:
    src = _stage(tmp_path, DUPLICATE)
    exported = api.plan_repair(src).to_dict()
    assert [s["recipe"] for s in exported["steps"]] == [
        "identical-duplicate-collapse",
        "seq-renumber",
    ]
    subset = _reseal(dict(exported, steps=exported["steps"][:1]))
    _plan, manifest = api.apply_plan(src, subset, output_path=tmp_path / "out.jsonl")
    assert manifest is not None
    assert [a.kind for a in manifest.actions] == ["identical-duplicate-collapse"]


@pytest.mark.parametrize(
    "changes",
    [
        {"target_finding_fp": "0123456789abcdef"},
        {"target_index": 3},
        {"params": {"first_index": 1, "record_indexes": [1, 3], "variant": "identical-duplicate"}},
        {"recipe": "identical-duplicate-drop"},
    ],
    ids=["finding", "index", "params", "recipe"],
)
def test_forged_step_is_refused(tmp_path: Path, changes: dict[str, Any]) -> None:
    src = _stage(tmp_path, DUPLICATE)
    before = src.read_bytes()
    forged = _forge(api.plan_repair(src).to_dict(), **changes)
    out = tmp_path / "out.jsonl"
    with pytest.raises(RepairRefused, match=REFUSAL):
        api.apply_plan(src, forged, output_path=out)
    assert not out.exists()
    assert src.read_bytes() == before


@pytest.mark.parametrize(
    "changes",
    [{"lossy": False, "loss": {}}, {"loss": {"torn-record": 0}}, {"loss": {"torn-record": 7}}],
    ids=["hidden", "zero", "inflated"],
)
def test_misdeclared_loss_is_refused(tmp_path: Path, changes: dict[str, Any]) -> None:
    src = _stage(tmp_path, TORN_MIDDLE)
    exported = api.plan_repair(src, policy="salvage", acknowledge_side_effects=True).to_dict()
    assert exported["steps"][0]["loss"] == {"torn-record": 1}
    out = tmp_path / "out.jsonl"
    with pytest.raises(RepairRefused, match=REFUSAL):
        api.apply_plan(
            src, _forge(exported, **changes), output_path=out, acknowledge_side_effects=True
        )
    assert not out.exists()


def test_declared_loss_is_the_planner_derivation(tmp_path: Path) -> None:
    src = _stage(tmp_path, TORN_MIDDLE)
    exported = api.plan_repair(src, policy="salvage", acknowledge_side_effects=True).to_dict()
    _plan, manifest = api.apply_plan(
        src, exported, output_path=tmp_path / "out.jsonl", acknowledge_side_effects=True
    )
    assert manifest is not None
    assert manifest.declared_loss == ("torn-record:1",)


def test_reordered_steps_are_refused(tmp_path: Path) -> None:
    src = _stage(tmp_path, DUPLICATE)
    doc = api.plan_repair(src).to_dict()
    first, second = doc["steps"]
    swapped = _reseal(dict(doc, steps=[dict(second, seq=0), dict(first, seq=1)]))
    with pytest.raises(RepairRefused, match=REFUSAL):
        api.apply_plan(src, swapped, output_path=tmp_path / "out.jsonl")


def test_plan_for_changed_source_is_stale(tmp_path: Path) -> None:
    src = _stage(tmp_path, DUPLICATE)
    exported = api.plan_repair(src).to_dict()
    src.write_bytes((DUPLICATE + MSG2.replace("msg-2", "msg-3")).encode("utf-8"))
    with pytest.raises(PlanSourceMismatch):
        api.apply_plan(src, exported, output_path=tmp_path / "out.jsonl")


def test_plan_for_another_file_name_is_refused(tmp_path: Path) -> None:
    """Finding fingerprints bind the file name, so a renamed copy needs its own plan."""
    exported = api.plan_repair(_stage(tmp_path, DUPLICATE)).to_dict()
    copy = _stage(tmp_path, DUPLICATE, name="copy.jsonl")
    with pytest.raises(RepairRefused, match="same name and bytes"):
        api.apply_plan(copy, exported, output_path=tmp_path / "out.jsonl")


def test_cli_refuses_forged_plan(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    src = _stage(tmp_path, DUPLICATE)
    forged = tmp_path / "plan.json"
    forged.write_text(
        json.dumps(_forge(api.plan_repair(src).to_dict(), target_finding_fp="0123456789abcdef")),
        encoding="utf-8",
    )
    out = tmp_path / "out.jsonl"
    code = main(["repair", str(src), "--plan", str(forged), "--output", str(out)])
    assert code == 1
    assert "REPAIR_REFUSED" in capsys.readouterr().err
    assert not out.exists()
