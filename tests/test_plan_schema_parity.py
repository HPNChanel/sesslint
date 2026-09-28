"""T-09: malformed emitted v1 plan shapes rejected by schema and stdlib deserializer."""

from copy import deepcopy
from pathlib import Path

import pytest

from sesslint import api
from sesslint.repair import load_plan
from tests.utils.schema import assert_schema

SOURCE = Path(__file__).resolve().parents[1] / "fixtures/repair_cli/basic/source.jsonl"


@pytest.mark.parametrize(
    "path,value",
    [
        (("steps",), None),
        (("steps",), [None]),
        (("blocked",), None),
        (("loss_accounting",), None),
        (("profile",), None),
        (("steps", 0, "seq"), True),
        (("steps", 0, "target_index"), -1),
        (("steps", 0, "params"), []),
        (("steps", 0, "lossy"), "false"),
        (("loss_accounting", "preview"), {"none": -1}),
        (("policy",), "guess"),
    ],
)
def test_schema_runtime_plan_type_parity(path: tuple, value: object) -> None:
    valid = api.plan_repair(SOURCE).to_dict()
    assert_schema(valid, "sesslint.plan.v1.json")
    assert load_plan(valid).to_dict() == valid
    invalid = deepcopy(valid)
    target = invalid
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(AssertionError):
        assert_schema(invalid, "sesslint.plan.v1.json")
    with pytest.raises(ValueError):
        load_plan(invalid)


def test_all_schemas_are_valid_draft_202012() -> None:
    import json

    from jsonschema import Draft202012Validator

    paths = sorted((SOURCE.parents[3] / "schemas").glob("*.json"))
    assert len(paths) == 16
    for path in paths:
        Draft202012Validator.check_schema(json.loads(path.read_text(encoding="utf-8")))
