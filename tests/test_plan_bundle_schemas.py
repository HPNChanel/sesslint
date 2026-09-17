"""Tests for sesslint.plan/v1 and sesslint.bundle/v1 JSON Schemas (DW-T-09).

Hand-rolled strict validation matching the committed schemas, in the style of
tests/test_scan_schema.py: emitted documents must validate, and representative
malformed documents must be rejected.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sesslint.api import build_bundle
from sesslint.bundle import get_bundle_schema_path, load_bundle_schema
from sesslint.repair.executor import load_plan
from sesslint.repair.planner import (
    get_plan_schema_path,
    load_plan_schema,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
REPAIR_FIXTURES = REPO_ROOT / "fixtures" / "repair"

PLAN_STEP_REQUIRED = (
    "min_policy",
    "params",
    "recipe",
    "recipe_version",
    "seq",
    "target_finding_fp",
    "target_index",
)
PLAN_TOP_REQUIRED = (
    "blocked",
    "fingerprint",
    "loss_accounting",
    "profile",
    "source_hash",
    "steps",
    "version",
)
BUNDLE_TOP_REQUIRED = (
    "bundle_version",
    "created_by",
    "detection",
    "fixture_skeleton",
    "report",
    "source",
)


def _validate_plan_dict(data: dict[str, Any]) -> None:
    """Strict structural check mirroring schemas/sesslint.plan.v1.json."""
    assert set(PLAN_TOP_REQUIRED) <= set(data)
    assert data["version"] == "sesslint.plan/v1"
    assert isinstance(data["source_hash"], str) and len(data["source_hash"]) == 64
    assert isinstance(data["profile"], str) and data["profile"]
    assert isinstance(data["fingerprint"], str) and len(data["fingerprint"]) == 64
    if "policy" in data:
        assert data["policy"] in ("conservative", "salvage")
    for step in data["steps"]:
        assert set(PLAN_STEP_REQUIRED) <= set(step)
        assert isinstance(step["seq"], int) and step["seq"] >= 0
        assert step["min_policy"] in ("conservative", "salvage")
        assert isinstance(step["recipe"], str) and step["recipe"]
        assert isinstance(step["recipe_version"], str) and step["recipe_version"]
        assert isinstance(step["target_index"], (int, type(None)))
        assert isinstance(step["params"], dict)
        if "loss" in step:
            assert all(isinstance(v, int) for v in step["loss"].values())
    for b in data["blocked"]:
        assert set(("code", "finding_fp", "reason")) <= set(b)
    la = data["loss_accounting"]
    assert isinstance(la["preview"], dict)
    for k in ("total_lost", "total_kept"):
        if k in la:
            assert isinstance(la[k], int) and la[k] >= 0


def _validate_bundle_dict(data: dict[str, Any]) -> None:
    """Strict structural check mirroring schemas/sesslint.bundle.v1.json."""
    assert set(BUNDLE_TOP_REQUIRED) <= set(data)
    assert data["bundle_version"] == "sesslint.bundle/v1"

    cb = data["created_by"]
    for k in (
        "adapters",
        "cli",
        "profiles",
        "schema_manifest",
        "schema_report",
        "schema_session",
        "tool",
        "version",
        "versions",
    ):
        assert k in cb
    assert cb["tool"] == "sesslint"

    src = data["source"]
    assert isinstance(src["path"], str)
    assert isinstance(src["sha256"], str) and len(src["sha256"]) == 64
    assert isinstance(src["size"], int) and src["size"] >= 0

    det = data["detection"]
    assert isinstance(det["requested"], str)
    assert isinstance(det["resolved"], (str, type(None)))
    assert isinstance(det["reason"], str)
    assert all(isinstance(v, (int, float)) for v in det["confidences"].values())

    rep = data["report"]
    for k in (
        "assurance",
        "counts",
        "coverage",
        "findings",
        "limitation",
        "schema_version",
        "session_id",
        "source_fingerprint",
        "tool_version",
    ):
        assert k in rep
    for f in rep["findings"]:
        for k in ("code", "fingerprint", "repairability", "severity", "span"):
            assert k in f
        assert isinstance(f["span"]["path"], str)

    sk = data["fixture_skeleton"]
    assert isinstance(sk["codes"], list)
    assert isinstance(sk["kinds"], dict)
    assert isinstance(sk["record_count"], int) and sk["record_count"] >= 0
    assert isinstance(sk["template"], str) and sk["template"]


# ---------------------------------------------------------------------------
# Schema self-consistency
# ---------------------------------------------------------------------------


def test_plan_schema_loads_and_self_consistent() -> None:
    assert get_plan_schema_path().is_file()
    schema = load_plan_schema()
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == "https://sesslint.dev/schemas/sesslint.plan/v1"
    assert set(schema["required"]).issubset(set(schema["properties"].keys()))
    step_item = schema["properties"]["steps"]["items"]
    assert set(step_item["required"]).issubset(set(step_item["properties"].keys()))
    assert set(PLAN_STEP_REQUIRED) <= set(step_item["required"])


def test_bundle_schema_loads_and_self_consistent() -> None:
    assert get_bundle_schema_path().is_file()
    schema = load_bundle_schema()
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == "https://sesslint.dev/schemas/sesslint.bundle/v1"
    assert set(schema["required"]).issubset(set(schema["properties"].keys()))
    assert schema["properties"]["bundle_version"]["const"] == "sesslint.bundle/v1"


# ---------------------------------------------------------------------------
# Positive: emitted documents validate
# ---------------------------------------------------------------------------


def test_conservative_plan_dict_validates() -> None:
    plan = load_plan(REPAIR_FIXTURES / "exec_basic" / "plan.json")
    _validate_plan_dict(plan.to_dict())


def test_refusal_path_plan_dict_validates() -> None:
    """A plan with blocked findings and zero steps still validates."""
    plan = load_plan(REPAIR_FIXTURES / "exec_refuse_sl203" / "plan.json")
    _validate_plan_dict(plan.to_dict())


def test_salvage_plan_dict_validates() -> None:
    data = json.loads((REPAIR_FIXTURES / "salvage_truncate.json").read_bytes())
    _validate_plan_dict(data["expected_plan"])
    assert data["expected_plan"]["policy"] == "salvage"


def test_bundle_dict_validates() -> None:
    b = build_bundle(str(REPO_ROOT / "fixtures" / "checks" / "graph_healthy.json"))
    _validate_bundle_dict(b.to_dict())


def test_detection_failed_bundle_dict_validates(tmp_path: Path) -> None:
    f = tmp_path / "not_a_session.json"
    f.write_bytes(b'{"not": "a session"}\n')
    b = build_bundle(str(f))
    _validate_bundle_dict(b.to_dict())
    assert b.to_dict()["detection"]["resolved"] is None


def test_bundle_json_round_trip_validates() -> None:
    b = build_bundle(str(REPO_ROOT / "fixtures" / "checks" / "graph_healthy.json"))
    parsed = json.loads(b.to_json())
    _validate_bundle_dict(parsed)


# ---------------------------------------------------------------------------
# Negative: malformed documents rejected
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("field", ["seq", "recipe", "min_policy", "recipe_version"])
def test_plan_missing_step_field_fails_validation(field: str) -> None:
    plan_dict = load_plan(REPAIR_FIXTURES / "exec_basic" / "plan.json").to_dict()
    del plan_dict["steps"][0][field]
    with pytest.raises(AssertionError):
        _validate_plan_dict(plan_dict)


def test_plan_wrong_version_fails_validation() -> None:
    plan_dict = load_plan(REPAIR_FIXTURES / "exec_basic" / "plan.json").to_dict()
    plan_dict["version"] = "sesslint.plan/v0"
    with pytest.raises(AssertionError):
        _validate_plan_dict(plan_dict)


def test_bundle_missing_section_fails_validation() -> None:
    b = build_bundle(str(REPO_ROOT / "fixtures" / "checks" / "graph_healthy.json"))
    d = b.to_dict()
    del d["fixture_skeleton"]
    with pytest.raises(AssertionError):
        _validate_bundle_dict(d)


def test_bundle_wrong_version_fails_validation() -> None:
    b = build_bundle(str(REPO_ROOT / "fixtures" / "checks" / "graph_healthy.json"))
    d = b.to_dict()
    d["bundle_version"] = "sesslint.bundle/v2"
    with pytest.raises(AssertionError):
        _validate_bundle_dict(d)
