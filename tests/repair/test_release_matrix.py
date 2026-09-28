"""T-06 public API matrix: profile/policy, plan reload, loss, immutability, idempotence.

Recipe-local positive/refusal cases for all 13 recipes remain in the existing
RECIPE_MATRIX. These integration rows deliberately preserve refusals when newer
detectors make a historical recipe fixture unsafe as a complete session.
"""

import json
from pathlib import Path

import pytest

from sesslint import api
from sesslint.adapters.canonical import dump_canonical
from sesslint.canonical import SessionEvent
from sesslint.errors import SesslintError
from sesslint.repair import load_plan

ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "fixtures/conformance/repair_matrix/cases.json"
PROFILES = ("neutral", "claude-strict", "openai-strict")
POLICIES = ("conservative", "salvage")
SCENARIOS = (
    "recipe_suffix_discard",
    "recipe_parent_restore",
    "recipe_reunion",
    "recipe_projection_removal",
    "salvage_branch",
    "salvage_project",
    "salvage_truncate",
    "adjacent-duplicate",
    "nonadjacent-duplicate",
    "seq-renumber",
    "torn-tail",
    "torn-middle",
    "orphan-result",
    "sl203",
)


def source_bytes(scenario: str) -> bytes:
    paths = {
        "adjacent-duplicate": "repair_cli/basic/source.jsonl",
        "nonadjacent-duplicate": "repair/t04_identical_duplicate_drop/source.jsonl",
        "seq-renumber": "repair/t04_seq_renumber/source.jsonl",
        "orphan-result": "checks/sl101_orphan.json",
        "sl203": "checks/sl203_continuation.json",
    }
    if scenario in paths:
        return (ROOT / "fixtures" / paths[scenario]).read_bytes()
    if scenario.startswith("torn-"):
        lines = (
            (ROOT / "fixtures/cli/check_basic/healthy.jsonl").read_bytes().splitlines(keepends=True)
        )
        if scenario == "torn-tail":
            return b"".join(lines) + b'{"id":"synthetic-torn"'
        return b"".join(lines[:2]) + b'{"id":"synthetic-torn"\n' + b"".join(lines[2:])
    data = json.loads((ROOT / "fixtures/repair" / f"{scenario}.json").read_text())
    data = data.get("happy_path", data)
    events = data.get("input_events", data.get("events"))
    return dump_canonical([SessionEvent(**event) for event in events])


def exercise(root: Path, scenario: str, policy: str, profile: str) -> dict:
    source = root / "source.jsonl"
    original = source_bytes(scenario)
    source.write_bytes(original)
    output = root / "repaired.jsonl"
    manifest_path = root / "repaired.jsonl.manifest.json"
    result: dict = {}
    try:
        plan = api.plan_repair(
            source, policy=policy, profile=profile, acknowledge_side_effects=True
        )
        assert (
            plan.to_dict()
            == api.plan_repair(
                source, policy=policy, profile=profile, acknowledge_side_effects=True
            ).to_dict()
        )
        document = plan.to_dict()
        assert load_plan(document).to_dict() == document
        result["recipes"] = [step.recipe for step in plan.steps]
        result["blocked"] = sorted({blocked.code for blocked in plan.blocked})
        result["loss_preview"] = dict(plan.loss_accounting.preview)
        if plan.steps:
            _, manifest = api.apply_plan(
                source, document, output_path=output, acknowledge_side_effects=True
            )
            assert manifest is not None
            assert api.verify(source, output, manifest_path, acknowledge_side_effects=True).ok
            assert not api.plan_repair(
                output, policy=policy, profile=profile, acknowledge_side_effects=True
            ).steps
            result["declared_loss"] = list(manifest.declared_loss)
            result["outcome"] = "applied-and-verified"
        else:
            result["outcome"] = "blocked" if plan.blocked else "no-op"
    except SesslintError as error:
        result["outcome"] = error.code
        assert not output.exists()
        assert not manifest_path.exists()
    finally:
        assert source.read_bytes() == original
    return result


@pytest.mark.parametrize("scenario", SCENARIOS)
@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize("profile", PROFILES)
def test_public_repair_matrix(tmp_path: Path, scenario: str, policy: str, profile: str) -> None:
    expected = json.loads(MATRIX.read_text(encoding="utf-8"))
    assert (
        exercise(tmp_path, scenario, policy, profile) == expected[f"{scenario}/{policy}/{profile}"]
    )


def test_matrix_scope_is_complete() -> None:
    from tests.test_coverage_matrix import RECIPE_MATRIX, _registered_recipe_names

    assert set(RECIPE_MATRIX) == _registered_recipe_names()
    assert len(RECIPE_MATRIX) == 13
    rows = json.loads(MATRIX.read_text(encoding="utf-8"))
    assert set(rows) == {f"{s}/{p}/{r}" for s in SCENARIOS for p in POLICIES for r in PROFILES}
    for key, row in rows.items():
        if key.startswith("sl203/"):
            assert row["outcome"] in {"REPAIR_REFUSED", "ABSTAINED"}
