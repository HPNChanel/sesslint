"""Tests for repair plan export/apply split (repair-engine T-01).

Covers ``--plan-out`` (export a ``sesslint.plan/v1`` document) and
``--apply-plan``/``--plan`` (plan-authoritative execution) plus the
``api.plan_repair``/``api.apply_plan`` entry points.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from sesslint import api
from sesslint.cli import main
from sesslint.repair import RepairPlan, load_plan
from sesslint.repair.errors import PlanSourceMismatch, PlanTampered

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "repair_cli"
BASIC_SRC = FIXTURES_DIR / "basic" / "source.jsonl"


def _stage(tmp_path: Path) -> Path:
    src = tmp_path / "src.jsonl"
    shutil.copyfile(BASIC_SRC, src)
    return src


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _one_shot(tmp_path: Path) -> tuple[Path, Path]:
    """Baseline one-shot repair; returns (output, manifest) paths."""
    src = _stage(tmp_path / "oneshot")
    (tmp_path / "oneshot").mkdir(exist_ok=True)
    out = tmp_path / "oneshot" / "out.jsonl"
    code = main(["repair", str(src), "--output", str(out)])
    assert code == 0
    return out, tmp_path / "oneshot" / "out.jsonl.manifest.json"


def test_plan_out_export_only(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """--plan-out without --output exports the plan and writes nothing else."""
    src = _stage(tmp_path)
    plan_path = tmp_path / "plan.json"

    code = main(["repair", str(src), "--plan-out", str(plan_path)])
    assert code == 0
    assert plan_path.is_file()
    doc = json.loads(plan_path.read_text(encoding="utf-8"))
    for key in (
        "version",
        "source_hash",
        "profile",
        "fingerprint",
        "steps",
        "blocked",
        "loss_accounting",
    ):
        assert key in doc
    assert doc["version"] == "sesslint.plan/v1"
    # No output or manifest was produced.
    assert list(tmp_path.glob("*.manifest.json")) == []
    out = capsys.readouterr().out
    assert "Plan written to" in out
    assert "Plan fingerprint:" in out


def test_plan_out_deterministic_bytes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Two exports of the same source produce byte-identical plan documents."""
    src = _stage(tmp_path)
    p1, p2 = tmp_path / "a.json", tmp_path / "b.json"
    assert main(["repair", str(src), "--plan-out", str(p1), "--dry-run"]) == 0
    assert main(["repair", str(src), "--plan-out", str(p2), "--dry-run"]) == 0
    assert p1.read_bytes() == p2.read_bytes()


def test_apply_plan_byte_identical_to_one_shot(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """--apply-plan on an unchanged source yields one-shot output+manifest bytes."""
    src = _stage(tmp_path)
    plan_path = tmp_path / "plan.json"
    assert main(["repair", str(src), "--plan-out", str(plan_path)]) == 0

    out = tmp_path / "applied.jsonl"
    code = main(["repair", str(src), "--apply-plan", str(plan_path), "--output", str(out)])
    assert code == 0

    ref_out = tmp_path / "ref.jsonl"
    assert main(["repair", str(src), "--output", str(ref_out)]) == 0
    assert _sha(out) == _sha(ref_out)
    assert _sha(tmp_path / "applied.jsonl.manifest.json") == _sha(
        tmp_path / "ref.jsonl.manifest.json"
    )


def test_plan_out_then_apply_same_run(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """--plan-out + --output exports and applies in one run, matching one-shot."""
    src = _stage(tmp_path)
    plan_path = tmp_path / "plan.json"
    out = tmp_path / "out.jsonl"
    code = main(["repair", str(src), "--plan-out", str(plan_path), "--output", str(out)])
    assert code == 0
    assert plan_path.is_file()

    ref_out = tmp_path / "ref.jsonl"
    assert main(["repair", str(src), "--output", str(ref_out)]) == 0
    assert _sha(out) == _sha(ref_out)
    assert _sha(tmp_path / "out.jsonl.manifest.json") == _sha(tmp_path / "ref.jsonl.manifest.json")


def test_legacy_plan_flag_still_applies(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """The pre-existing --plan spelling remains an apply alias."""
    src = _stage(tmp_path)
    plan_path = tmp_path / "plan.json"
    assert main(["repair", str(src), "--plan-out", str(plan_path)]) == 0
    out = tmp_path / "out.jsonl"
    code = main(["repair", str(src), "--plan", str(plan_path), "--output", str(out)])
    assert code == 0
    assert out.is_file()


def test_apply_plan_stale_source_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A one-byte source drift after export refuses with plan-stale mismatch."""
    src = _stage(tmp_path)
    plan_path = tmp_path / "plan.json"
    assert main(["repair", str(src), "--plan-out", str(plan_path)]) == 0
    src.write_bytes(src.read_bytes() + b"\n")

    code = main(
        ["repair", str(src), "--apply-plan", str(plan_path), "--output", str(tmp_path / "o.jsonl")]
    )
    assert code == 1
    assert "PLAN_SOURCE_MISMATCH" in capsys.readouterr().err


def test_apply_plan_tampered_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Editing plan steps invalidates the fingerprint binding."""
    src = _stage(tmp_path)
    plan_path = tmp_path / "plan.json"
    assert main(["repair", str(src), "--plan-out", str(plan_path)]) == 0
    doc = json.loads(plan_path.read_text(encoding="utf-8"))
    doc["steps"] = []
    plan_path.write_text(json.dumps(doc), encoding="utf-8")

    code = main(
        ["repair", str(src), "--apply-plan", str(plan_path), "--output", str(tmp_path / "o.jsonl")]
    )
    assert code == 1
    assert "PLAN_TAMPERED" in capsys.readouterr().err


def test_apply_plan_salvage_policy_derived(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A salvage plan applies without --policy — the plan is authoritative."""
    src = _stage(tmp_path)
    plan_path = tmp_path / "sp.json"
    assert main(["repair", str(src), "--plan-out", str(plan_path), "--policy", "salvage"]) == 0
    doc = json.loads(plan_path.read_text(encoding="utf-8"))
    assert doc["policy"] == "salvage"

    out = tmp_path / "o.jsonl"
    code = main(["repair", str(src), "--apply-plan", str(plan_path), "--output", str(out)])
    assert code == 0
    manifest = json.loads((tmp_path / "o.jsonl.manifest.json").read_text(encoding="utf-8"))
    assert manifest is not None


def test_apply_plan_dry_run_validates_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """--apply-plan --dry-run re-validates bindings and prints the plan summary."""
    src = _stage(tmp_path)
    plan_path = tmp_path / "plan.json"
    assert main(["repair", str(src), "--plan-out", str(plan_path)]) == 0

    code = main(["repair", str(src), "--apply-plan", str(plan_path), "--dry-run"])
    assert code == 0
    out = capsys.readouterr().out
    assert "Plan fingerprint:" in out
    assert list(tmp_path.glob("*.manifest.json")) == []


@pytest.mark.parametrize("flag", ["--policy", "--profile", "--format"])
def test_apply_plan_refuses_overrides(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], flag: str
) -> None:
    """Plan-authoritative apply rejects execution-shaping overrides."""
    src = _stage(tmp_path)
    plan_path = tmp_path / "plan.json"
    assert main(["repair", str(src), "--plan-out", str(plan_path)]) == 0

    value = {"--policy": "salvage", "--profile": "strict", "--format": "canonical"}[flag]
    code = main(
        [
            "repair",
            str(src),
            "--apply-plan",
            str(plan_path),
            "--output",
            str(tmp_path / "o.jsonl"),
            flag,
            value,
        ]
    )
    assert code == 2
    assert "authoritative" in capsys.readouterr().err


def test_apply_plan_plan_out_conflict(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """--plan-out + --apply-plan is a usage error (nothing is recomputed)."""
    src = _stage(tmp_path)
    plan_path = tmp_path / "plan.json"
    assert main(["repair", str(src), "--plan-out", str(plan_path)]) == 0
    code = main(
        [
            "repair",
            str(src),
            "--apply-plan",
            str(plan_path),
            "--plan-out",
            str(tmp_path / "x.json"),
            "--output",
            str(tmp_path / "o.jsonl"),
        ]
    )
    assert code == 2
    assert "--plan-out" in capsys.readouterr().err


def test_apply_plan_requires_output_unless_dry(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Apply without --output and without --dry-run is a usage error."""
    src = _stage(tmp_path)
    plan_path = tmp_path / "plan.json"
    assert main(["repair", str(src), "--plan-out", str(plan_path)]) == 0
    code = main(["repair", str(src), "--apply-plan", str(plan_path)])
    assert code == 2
    assert "--output is required" in capsys.readouterr().err


def test_api_plan_repair_and_apply_plan(tmp_path: Path) -> None:
    """api.plan_repair exports; api.apply_plan accepts RepairPlan, path, or mapping."""
    src = _stage(tmp_path)
    plan = api.plan_repair(src)
    assert isinstance(plan, RepairPlan)
    assert len(plan.steps) >= 1

    out = tmp_path / "a.jsonl"
    _, manifest = api.apply_plan(src, plan, output_path=out)
    assert manifest is not None and out.is_file()

    plan_file = tmp_path / "plan.json"
    plan_file.write_text(json.dumps(plan.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    out2 = tmp_path / "b.jsonl"
    _, manifest2 = api.apply_plan(src, plan_file, output_path=out2)
    assert manifest2 is not None and _sha(out) == _sha(out2)

    out3 = tmp_path / "c.jsonl"
    _, manifest3 = api.apply_plan(src, plan.to_dict(), output_path=out3)
    assert manifest3 is not None and _sha(out) == _sha(out3)


def test_api_apply_plan_stale_raises(tmp_path: Path) -> None:
    """api.apply_plan propagates PlanSourceMismatch on source drift."""
    src = _stage(tmp_path)
    plan = api.plan_repair(src)
    src.write_bytes(src.read_bytes() + b"\n")
    with pytest.raises(PlanSourceMismatch):
        api.apply_plan(src, plan, output_path=tmp_path / "o.jsonl")


def test_api_apply_plan_tampered_raises(tmp_path: Path) -> None:
    """api.apply_plan propagates PlanTampered for edited plan dicts."""
    src = _stage(tmp_path)
    plan = api.plan_repair(src)
    tampered = plan.to_dict()
    tampered["steps"] = []
    with pytest.raises((PlanTampered, PlanSourceMismatch, ValueError)):
        api.apply_plan(src, tampered, output_path=tmp_path / "o.jsonl")


def test_api_repair_plan_mutex(tmp_path: Path) -> None:
    """api.repair refuses plan + plan_path simultaneously."""
    src = _stage(tmp_path)
    plan = api.plan_repair(src)
    with pytest.raises(ValueError, match="mutually exclusive"):
        api.repair(src, tmp_path / "o.jsonl", plan=plan, plan_path=tmp_path / "p.json")


def test_load_plan_strict_round_trip(tmp_path: Path) -> None:
    """load_plan deserializes an exported doc without policy bias."""
    src = _stage(tmp_path)
    plan = api.plan_repair(src)
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(json.dumps(plan.to_dict()), encoding="utf-8")
    loaded = load_plan(plan_file)
    assert loaded.fingerprint == plan.fingerprint
    assert loaded.source_hash == plan.source_hash
