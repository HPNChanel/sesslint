"""OutcomeGuard contract validation: closed vocabulary, fail closed (CON-01…CON-07, AT-40)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sesslint.outcome import ContractError, contract_from_dict, explain_contract, load_contract
from tests.outcome.helpers import ORDERS
from tests.utils.schema import assert_schema


def _raw(**over: Any) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "schema_version": "sesslint.outcome-contract/v1",
        "name": "c",
        "version": "1",
        "key": {"source": "id", "target": "ref"},
        "conditions": [{"id": "e", "type": "exists"}],
    }
    raw.update(over)
    return raw


def _problems(raw: object) -> tuple[str, ...]:
    with pytest.raises(ContractError) as info:
        contract_from_dict(raw)
    return info.value.problems


def test_fixture_contract_loads_and_matches_schema() -> None:
    raw = json.loads((ORDERS / "contract.json").read_text(encoding="utf-8"))
    assert_schema(raw, "sesslint.outcome-contract.v1.json")
    spec = load_contract(ORDERS / "contract.json")
    assert spec.source_key == ("order_id",)
    assert [c.id for c in spec.conditions][0] == "shipment-exists"
    assert spec.warnings() == ()


def test_empty_contract_is_an_error_not_a_pass() -> None:
    """AT-40: an empty contract proves nothing, so it never yields VERIFIED."""
    assert any("non-empty list" in p for p in _problems(_raw(conditions=[])))


@pytest.mark.parametrize(
    ("over", "needle"),
    [
        ({"surprise": 1}, "unknown key 'surprise'"),
        ({"schema_version": "v0"}, "schema_version"),
        ({"conditions": [{"id": "x", "type": "magic"}]}, "'type' must be one of"),
        ({"conditions": [{"id": "x", "type": "exists", "fieldd": "a"}]}, "unknown key 'fieldd'"),
        (
            {"eligibility": [{"field": "a", "op": "like", "value": "x"}]},
            "'op' must be one of",
        ),
        (
            {"conditions": [{"id": "x", "type": "on_time", "basis": "target_time", "field": "t"}]},
            "due",
        ),
        (
            {
                "due": {"source_time_field": "at", "within_seconds": 1},
                "conditions": [
                    {"id": "x", "type": "on_time", "basis": "observation", "field": "t"}
                ],
            },
            "observation basis takes no 'field'",
        ),
        ({"conditions": [{"id": "x", "type": "count", "min": 0}]}, "never be violated"),
        ({"conditions": [{"id": "x", "type": "count", "max": 0}]}, "cannot prove"),
        ({"conditions": [{"id": "x", "type": "count", "min": 3, "max": 2}]}, "must not exceed"),
        ({"conditions": [{"id": "x", "type": "range", "field": "n"}]}, "needs 'min', 'max'"),
        ({"conditions": [{"id": "x", "type": "one_of", "field": "s", "values": []}]}, "values"),
        (
            {
                "conditions": [
                    {
                        "id": "x",
                        "type": "one_of",
                        "field": "s",
                        "values": ["a"],
                        "normalize": ["stem"],
                    }
                ]
            },
            "unsupported normalize",
        ),
        ({"conditions": [{"id": "x", "type": "route", "field": "w", "values": ["a"]}]}, "'when'"),
        (
            {"conditions": [{"id": "e", "type": "exists"}, {"id": "e", "type": "exists"}]},
            "duplicate",
        ),
        (
            {"conditions": [{"id": "e", "type": "exists", "advisory": True}]},
            "no decisive condition",
        ),
        (
            {"conditions": [{"id": "e", "type": "exists", "disabled": "later"}]},
            "every condition is disabled",
        ),
        ({"key": {"source": ["a", "b"], "target": "r"}}, "same number of fields"),
        ({"key": {"source": [], "target": "r"}}, "key.source"),
        ({"due": {"source_time_field": "at", "within_seconds": -1}}, "within_seconds"),
    ],
)
def test_invalid_contracts_are_rejected(over: dict[str, Any], needle: str) -> None:
    problems = _problems(_raw(**over))
    assert any(needle in p for p in problems), problems


def test_any_of_cannot_nest_or_hide_flags() -> None:
    inner = {"id": "in", "type": "any_of", "conditions": [{"id": "a", "type": "exists"}] * 2}
    problems = _problems(
        _raw(
            conditions=[
                {"id": "o", "type": "any_of", "conditions": [inner, {"id": "b", "type": "exists"}]}
            ]
        )
    )
    assert any("cannot nest" in p for p in problems)
    problems = _problems(
        _raw(
            conditions=[
                {
                    "id": "o",
                    "type": "any_of",
                    "conditions": [
                        {"id": "a", "type": "exists", "advisory": True},
                        {"id": "b", "type": "exists"},
                    ],
                }
            ]
        )
    )
    assert any("advisory or disabled" in p for p in problems)


def test_every_problem_is_reported_at_once() -> None:
    problems = _problems(_raw(name=None, version="", extra=True, conditions=[{"type": "exists"}]))
    assert len(problems) >= 3


@pytest.mark.parametrize(
    "text",
    [
        '{"schema_version": "sesslint.outcome-contract/v1", "schema_version": "x"}',
        '{"n": NaN}',
        "[",
        "﻿﻿{}",
    ],
)
def test_load_rejects_non_strict_json(tmp_path: Path, text: str) -> None:
    path = tmp_path / "c.json"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ContractError):
        load_contract(path)


def test_load_rejects_oversized_and_non_utf8(tmp_path: Path) -> None:
    big = tmp_path / "big.json"
    big.write_bytes(b" " * (1024 * 1024 + 1))
    with pytest.raises(ContractError, match="1 MiB"):
        load_contract(big)
    latin = tmp_path / "latin.json"
    latin.write_bytes(b'{"name": "\xe9"}')
    with pytest.raises(ContractError, match="UTF-8"):
        load_contract(latin)


def test_fingerprint_ignores_key_order_but_not_values() -> None:
    a = contract_from_dict(_raw())
    b = contract_from_dict(dict(reversed(list(_raw().items()))))
    c = contract_from_dict(_raw(version="2"))
    assert a.sha256 == b.sha256 != c.sha256


def test_warnings_flag_gaps_without_failing() -> None:
    spec = contract_from_dict(_raw(conditions=[{"id": "s", "type": "required", "field": "status"}]))
    joined = " ".join(spec.warnings())
    assert "no active exists/count" in joined
    assert "no due window" in joined


def test_explain_is_deterministic_and_lists_every_condition() -> None:
    spec = load_contract(ORDERS / "contract.json")
    text = explain_contract(spec)
    assert text == explain_contract(load_contract(ORDERS / "contract.json"))
    for condition in spec.conditions:
        assert f"- {condition.id}:" in text
    assert "[advisory" in text
    assert "INCONCLUSIVE" in text
