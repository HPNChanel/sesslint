"""B22: canonical emission must account for every undecoded source record."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sesslint import api
from sesslint.errors import SesslintError
from sesslint.repair.executor import execute, load_source_for_format, run_all_checks
from sesslint.repair.fingerprint import compute_plan_fingerprint
from sesslint.repair.planner import RepairPlan
from sesslint.repair.planner import plan as derive_plan

HEADER = {
    "created_at": "2026-10-08T00:00:00Z",
    "schema_version": "sesslint.session/v1",
    "session_id": "synthetic-undecoded",
}
EVENT = {
    "actor": "user",
    "id": "e0",
    "kind": "message",
    "parent_id": None,
    "payload": {"text": "synthetic"},
    "seq": 0,
    "ts": "2026-10-08T00:00:00Z",
}


def _source(tmp_path: Path, *, vendor: bool = False) -> Path:
    src = tmp_path / "source.jsonl"
    if vendor:
        first = dict(EVENT, type="user", uuid="e0", message={"role": "user", "content": "x"})
        lines = [json.dumps(first), "GARBAGE", json.dumps(first)]
    else:
        lines = [json.dumps(HEADER), json.dumps(EVENT), "GARBAGE", json.dumps(EVENT)]
    src.write_bytes(("\n".join(lines) + "\n").encode())
    return src


def _plan(src: Path, fmt: str = "canonical", policy: str = "conservative") -> RepairPlan:
    data = src.read_bytes()
    _header, events, findings = load_source_for_format(src, fmt, data=data)
    return derive_plan(
        findings=findings + list(run_all_checks(events, source_path=src.name, adapter=fmt)),
        events=events,
        input_format=fmt,
        policy=policy,
        source_hash=hashlib.sha256(data).hexdigest(),
        acknowledge_side_effects=True,
    )


@pytest.mark.parametrize("vendor", [False, True], ids=["canonical", "vendor-to-canonical"])
@pytest.mark.parametrize("supplied", [False, True], ids=["automatic", "exported-plan"])
def test_unrepaired_bad_line_refuses_canonical_emission(
    tmp_path: Path, vendor: bool, supplied: bool
) -> None:
    src = _source(tmp_path, vendor=vendor)
    before = src.read_bytes()
    fmt = "claude-code-jsonl" if vendor else "canonical"
    plan = _plan(src, fmt)
    assert plan.steps  # A safe duplicate repair does not authorize discarding GARBAGE.
    assert any(b.code == "SL001" for b in plan.blocked)
    out = tmp_path / "repaired.jsonl"
    with pytest.raises(SesslintError, match="undecoded"):
        api.repair(src, out, format=fmt, emit="canonical", plan=plan if supplied else None)
    assert src.read_bytes() == before
    assert not out.exists()
    assert not Path(f"{out}.manifest.json").exists()


def test_direct_executor_also_refuses_unrepaired_bad_line(tmp_path: Path) -> None:
    src = _source(tmp_path)
    with pytest.raises(SesslintError, match="undecoded"):
        execute(source_path=src, plan=_plan(src), output_path=tmp_path / "out.jsonl")


def test_salvage_excision_accounts_for_bad_line(tmp_path: Path) -> None:
    src = _source(tmp_path)
    out = tmp_path / "out.jsonl"
    _plan, manifest = api.repair(src, out, policy="salvage", acknowledge_side_effects=True)
    assert manifest is not None
    assert manifest.declared_loss == ("torn-record:1",)
    assert [json.loads(line)["id"] for line in out.read_bytes().split(b"\n")[1:-1]] == ["e0"]


def test_salvage_subset_cannot_omit_excision(tmp_path: Path) -> None:
    src = _source(tmp_path)
    plan = _plan(src, policy="salvage").to_dict()
    plan["steps"] = [s for s in plan["steps"] if s["recipe"] != "torn-record-excision"]
    for i, step in enumerate(plan["steps"]):
        step["seq"] = i
    plan.pop("fingerprint")
    plan["fingerprint"] = compute_plan_fingerprint(plan)
    with pytest.raises(SesslintError, match="undecoded"):
        api.apply_plan(src, plan, output_path=tmp_path / "out.jsonl", acknowledge_side_effects=True)
