"""T-05 minimized fuzz failures: malformed containers fail before any write."""

from pathlib import Path

import pytest

from sesslint import api
from sesslint.repair import load_plan
from sesslint.repair.errors import RepairRefused

SOURCE = Path(__file__).resolve().parents[2] / "fixtures/repair_cli/basic/source.jsonl"


@pytest.mark.parametrize(
    "field,value",
    [
        ("steps", None),
        ("steps", [None]),
        ("blocked", None),
        ("loss_accounting", None),
        ("profile", None),
    ],
)
def test_malformed_plan_container_refused(field: str, value: object) -> None:
    doc = api.plan_repair(SOURCE).to_dict()
    doc[field] = value
    with pytest.raises(ValueError):
        load_plan(doc)


def test_unknown_plan_profile_is_typed_and_content_free(tmp_path: Path) -> None:
    doc = api.plan_repair(SOURCE).to_dict()
    doc["profile"] = "SYNTHETIC_PRIVATE_CANARY"
    with pytest.raises(RepairRefused, match="Unsupported repair plan profile") as caught:
        api.apply_plan(SOURCE, doc, output_path=tmp_path / "output.jsonl")
    assert "SYNTHETIC_PRIVATE_CANARY" not in str(caught.value)
    assert list(tmp_path.iterdir()) == []
