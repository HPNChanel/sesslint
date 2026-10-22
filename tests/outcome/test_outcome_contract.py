"""OutcomeGuard contract validation: closed vocabulary, fail closed (CON-01…CON-07, AT-40)."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any

import pytest

from sesslint._canonical_codec import canonical_json_bytes
from sesslint.outcome import ContractError, contract_from_dict, explain_contract, load_contract
from tests.outcome.helpers import ORDERS, digit_limit
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


# Review regressions before 0.5.0: bounds, exact numbers, malformed values never escape.


@pytest.mark.parametrize("bound", ["min", "max"])
@pytest.mark.parametrize("value", [None, 1.0, "1", True, -1, 1_000_001, 10**400, [1]])
def test_count_bounds_must_be_integers_in_range(bound: str, value: object) -> None:
    """RULE-02: ``"min": null`` is not "no lower bound", and huge bounds are refused."""
    condition: dict[str, Any] = {"id": "n", "type": "count", "min": 1, "max": 2}
    condition[bound] = value
    problems = _problems(_raw(conditions=[condition]))
    assert any(f"'{bound}' must be an integer from 0 to 1000000" in p for p in problems), problems


def test_count_bounds_accept_the_documented_range() -> None:
    raw = _raw(conditions=[{"id": "n", "type": "count", "min": 0, "max": 1_000_000}])
    assert_schema(raw, "sesslint.outcome-contract.v1.json")
    spec = contract_from_dict(raw)
    assert (spec.conditions[0].minimum, spec.conditions[0].maximum) == (0, 1_000_000)


@pytest.mark.parametrize("over", [{"min": None}, {"max": None}, {"max": 1_000_001}, {"min": -1}])
def test_schema_refuses_the_same_count_bounds(over: dict[str, Any]) -> None:
    raw = _raw(conditions=[{"id": "n", "type": "count", **over}])
    assert _problems(raw)
    with pytest.raises(AssertionError, match="Schema violation"):
        assert_schema(raw, "sesslint.outcome-contract.v1.json")


def test_load_turns_malformed_values_into_contract_errors(tmp_path: Path) -> None:
    path = tmp_path / "c.json"
    huge = _raw(conditions=[{"id": "n", "type": "count", "max": 10**400}])
    path.write_text(json.dumps(huge), encoding="utf-8")
    with pytest.raises(ContractError, match="from 0 to 1000000"):
        load_contract(path)
    # A lone surrogate escape decodes, but has no UTF-8 form to fingerprint.
    escape = chr(92) + "ud800"
    path.write_text(
        json.dumps(_raw()).replace('"name": "c"', f'"name": "c{escape}"'), encoding="utf-8"
    )
    with pytest.raises(ContractError, match="not valid Unicode"):
        load_contract(path)


@pytest.mark.parametrize(
    "over",
    [
        {"name": "c" + chr(0xD800)},
        {"description": chr(0xDFFF)},
        {"conditions": [{"id": "e", "type": "exists", "description": "x" + chr(0xD800)}]},
        {"conditions": [{"id": "o", "type": "one_of", "field": chr(0xDC00), "values": ["a"]}]},
        {"eligibility": [{"field": "f", "op": "eq", "value": chr(0xD800)}]},
    ],
)
def test_text_that_is_not_valid_unicode_is_a_contract_error(over: dict[str, Any]) -> None:
    problems = _problems(_raw(**over))
    assert problems == ("contract: holds text that is not valid Unicode (e.g. a lone surrogate)",)


def _range_contract_text(literal: str) -> str:
    text = json.dumps(_raw(conditions=[{"id": "r", "type": "range", "field": "x", "max": 7}]))
    return text.replace('"max": 7', f'"max": {literal}')


@pytest.mark.parametrize(
    "literal",
    [
        "9007199254740993.0",
        "0.1000000000000000055511151231257827",
        "123456789012345678.5",
        "1e400",
        "-1e400",
        "1e-400",
    ],
)
def test_load_rejects_numbers_a_float_cannot_hold_exactly(tmp_path: Path, literal: str) -> None:
    """A rounded threshold would silently test a different number (RULE-06)."""
    path = tmp_path / "c.json"
    path.write_text(_range_contract_text(literal), encoding="utf-8")
    with pytest.raises(ContractError) as info:
        load_contract(path)
    assert info.value.problems == (
        "contract: conditions[0].max: a number with a fraction or exponent must equal a 64-bit "
        "float exactly; up to 15 significant digits are always safe for magnitudes from 1e-307 "
        "to 1e308, and integers are exact up to 4300 digits",
    )


_OUT_OF_RANGE = (
    "number out of range; a JSON number may have at most 4300 characters, not counting a minus sign"
)


@pytest.mark.parametrize("limit", [4300, 640, 0])
@pytest.mark.parametrize("literal", ["7" * 4300, "-" + "7" * 4300, "1." + "0" * 4298])
def test_contract_numbers_may_have_4300_characters(
    tmp_path: Path, literal: str, limit: int
) -> None:
    """RULE-06: ints and decimals of up to 4300 characters (a sign not counted) load."""
    path = tmp_path / "c.json"
    path.write_text(_range_contract_text(literal), encoding="utf-8")
    with digit_limit(4300):
        expected = load_contract(path).sha256
    if limit and limit < 4300 and "." not in literal:
        # The fingerprint writes integers through json, which honours a lowered
        # limit: refused with the reason, never read differently.
        with digit_limit(limit), pytest.raises(ContractError) as info:
            load_contract(path)
        assert info.value.problems == (
            f"contract: conditions[0].max: number out of range; this Python converts integers "
            f"of at most {limit} digits to text (sys.set_int_max_str_digits or "
            "PYTHONINTMAXSTRDIGITS), so the contract cannot be fingerprinted",
        )
        return
    with digit_limit(limit):
        assert load_contract(path).sha256 == expected


@pytest.mark.parametrize("limit", [4300, 640, 0])
@pytest.mark.parametrize(
    "literal", ["7" * 4301, "-" + "7" * 4301, "1." + "0" * 4299, "1e" + "0" * 4299]
)
def test_contract_numbers_over_4300_characters_are_out_of_range(
    tmp_path: Path, literal: str, limit: int
) -> None:
    """RULE-06: the cap is OutcomeGuard's own, located, and the same in every environment.

    Before, a 5000-digit integer read as "not valid strict UTF-8 JSON (ValueError)".
    """
    path = tmp_path / "c.json"
    path.write_text(_range_contract_text(literal), encoding="utf-8")
    with digit_limit(limit), pytest.raises(ContractError) as info:
        load_contract(path)
    assert info.value.problems == (f"contract: conditions[0].max: {_OUT_OF_RANGE}",)


def test_out_of_range_numbers_are_located_inside_lists_and_branches(tmp_path: Path) -> None:
    """RULE-04, RULE-06: the first refused number in document order is named."""
    branch = {"id": "b", "type": "range", "field": "x", "min": 1}
    raw = _raw(
        eligibility=[{"field": "v", "op": "in", "values": ["a", 1]}],
        conditions=[
            {"id": "e", "type": "exists"},
            {"id": "any", "type": "any_of", "conditions": [{"id": "a", "type": "exists"}, branch]},
        ],
    )
    text = json.dumps(raw)
    path = tmp_path / "c.json"
    path.write_text(text.replace('"min": 1', '"min": ' + "9" * 4301), encoding="utf-8")
    with pytest.raises(ContractError) as info:
        load_contract(path)
    assert info.value.problems == (f"contract: conditions[1].conditions[1].min: {_OUT_OF_RANGE}",)
    path.write_text(text.replace('["a", 1]', '["a", 1e400]'), encoding="utf-8")
    with pytest.raises(ContractError) as info:
        load_contract(path)
    assert info.value.problems[0].startswith("contract: eligibility[0].values[1]: a number with")


def test_contract_dicts_are_held_to_the_same_integer_cap() -> None:
    """RULE-06: a Python dict can hold any int; past 4300 digits it is refused, located."""
    widest = 10**4300 - 1
    spec = contract_from_dict(_raw(eligibility=[{"field": "v", "op": "gt", "value": widest}]))
    assert spec.eligibility[0].value == widest
    for value in (10**4300, -(10**4300)):
        problems = _problems(_raw(eligibility=[{"field": "v", "op": "gt", "value": value}]))
        assert problems == (
            "contract: eligibility[0].value: number out of range; an integer may have at most "
            "4300 digits",
        )


@pytest.mark.parametrize("literal", ["0.5", "0.1", "99999.99", "1e-05", "2.5E+3", "1.0", "-0.0"])
def test_exact_float_literals_keep_their_fingerprint(tmp_path: Path, literal: str) -> None:
    """Contracts are fingerprinted as written; exact parsing must not change the hash."""
    text = _range_contract_text(literal)
    path = tmp_path / "c.json"
    path.write_text(text, encoding="utf-8")
    expected = hashlib.sha256(canonical_json_bytes(json.loads(text))).hexdigest()
    assert load_contract(path).sha256 == expected


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
def test_non_finite_numbers_are_refused_everywhere(bad: float) -> None:
    cases: list[tuple[dict[str, Any], str]] = [
        ({"conditions": [{"id": "r", "type": "range", "field": "x", "max": bad}]}, "finite"),
        ({"eligibility": [{"field": "x", "op": "gt", "value": bad}]}, "numeric 'value'"),
        ({"eligibility": [{"field": "x", "op": "eq", "value": bad}]}, "scalar 'value'"),
        (
            {"conditions": [{"id": "o", "type": "one_of", "field": "x", "values": [bad]}]},
            "may only hold",
        ),
    ]
    for over, needle in cases:
        problems = _problems(_raw(**over))
        assert any(needle in p for p in problems), problems


@pytest.mark.parametrize(
    "over",
    [
        {"conditions": [{"id": "x", "type": ["exists"]}]},
        {"conditions": [{"id": "x", "type": {"exists": True}}]},
        {"conditions": [{"id": "x", "type": "type", "field": "f", "kind": ["string"]}]},
        {"eligibility": [{"field": "f", "op": ["eq"], "value": 1}]},
        {
            "due": {"source_time_field": "at", "within_seconds": 60},
            "conditions": [
                {"id": "e", "type": "exists"},
                {"id": "t", "type": "on_time", "basis": {"observation": 1}},
            ],
        },
    ],
)
def test_unhashable_vocabulary_values_are_problems_not_crashes(over: dict[str, Any]) -> None:
    assert _problems(_raw(**over))


@pytest.mark.parametrize("cond_id", ["abc\n", "a b", "-a"])
def test_condition_ids_must_match_in_full(cond_id: str) -> None:
    problems = _problems(_raw(conditions=[{"id": cond_id, "type": "exists"}]))
    assert any("'id' must match" in p for p in problems), problems


def test_explain_prints_numbers_exactly() -> None:
    """CON-03: the restated contract shows each bound as written, never rounded."""
    spec = contract_from_dict(
        _raw(
            conditions=[
                {"id": "e", "type": "exists"},
                {"id": "a", "type": "range", "field": "x", "max": 99999.99},
                {"id": "b", "type": "range", "field": "y", "min": 0.5, "max": 123456789},
                {"id": "c", "type": "range", "field": "z", "min": 12345678901234567890},
            ],
            eligibility=[{"field": "amount", "op": "gt", "value": 9007199254740993}],
        )
    )
    text = explain_contract(spec)
    for needle in (
        "<= 99999.99",
        ">= 0.5 and <= 123456789",
        ">= 12345678901234567890",
        "amount > 9007199254740993",
    ):
        assert needle in text, needle


_ODD_KEYS: dict[Any, str] = {1: "x", None: "y", ("t",): "z"}


@pytest.mark.parametrize(
    ("over", "where"),
    [
        ({**_ODD_KEYS}, "contract"),
        ({"key": {"source": "id", "target": "ref", **_ODD_KEYS}}, "key"),
        ({"due": {"source_time_field": "at", "within_seconds": 60, **_ODD_KEYS}}, "due"),
        ({"conditions": [{"id": "e", "type": "exists", **_ODD_KEYS}]}, "condition 'e'"),
        (
            {
                "conditions": [
                    {
                        "id": "any",
                        "type": "any_of",
                        "conditions": [
                            {"id": "b1", "type": "exists", **_ODD_KEYS},
                            {"id": "b2", "type": "exists"},
                        ],
                    }
                ]
            },
            "condition 'b1'",
        ),
        (
            {"eligibility": [{"field": "f", "op": "eq", "value": 1, **_ODD_KEYS}]},
            "eligibility[0]",
        ),
        (
            {
                "conditions": [
                    {
                        "id": "r",
                        "type": "route",
                        "field": "q",
                        "values": ["a"],
                        "when": [{"field": "f", "op": "present", **_ODD_KEYS}],
                    }
                ]
            },
            "condition 'r' when[0]",
        ),
    ],
    ids=["top", "key", "due", "condition", "any_of-branch", "eligibility", "route-when"],
)
def test_non_string_keys_are_problems_at_every_level(over: dict[Any, Any], where: str) -> None:
    """Python dicts may carry keys that are not strings and do not sort together."""
    raw: dict[Any, Any] = _raw()
    raw.update(over)
    problems = _problems(raw)
    for name in ("NoneType", "int", "tuple"):
        assert f"{where}: keys must be strings, not {name}" in problems, problems


_WHEN = [{"field": "t", "op": "present"}]


@pytest.mark.parametrize(
    ("conditions", "where"),
    [
        ([{"id": "o", "type": "one_of", "field": "x", "values": ["a", None]}], "condition 'o'"),
        (
            [{"id": "r", "type": "route", "field": "q", "values": [None], "when": _WHEN}],
            "condition 'r'",
        ),
        (
            [
                {
                    "id": "any",
                    "type": "any_of",
                    "conditions": [
                        {"id": "e", "type": "exists"},
                        {"id": "o", "type": "one_of", "field": "x", "values": [None, 1]},
                    ],
                }
            ],
            "condition 'o'",
        ),
    ],
    ids=["one_of", "route", "any_of-branch"],
)
def test_null_cannot_widen_one_of_or_route_values(
    conditions: list[dict[str, Any]], where: str
) -> None:
    """CON-02, RULE-04, RULE-08: a null field never matches, so a listed null only misleads."""
    raw = _raw(conditions=conditions)
    assert _problems(raw) == (
        f"{where}: 'values' cannot hold null: a null field never matches these values",
    )
    with pytest.raises(AssertionError, match="Schema violation"):
        assert_schema(raw, "sesslint.outcome-contract.v1.json")


@pytest.mark.parametrize(
    "predicate",
    [
        {"field": "t", "op": "eq", "value": None},
        {"field": "t", "op": "ne", "value": None},
        {"field": "t", "op": "in", "values": [None, 1]},
        {"field": "t", "op": "not_in", "values": [None]},
    ],
)
def test_predicates_may_still_name_null(predicate: dict[str, Any]) -> None:
    """RULE-05: ``eq null`` matches a null field, so predicates and route ``when`` keep it."""
    route = {"id": "r", "type": "route", "field": "q", "values": ["a"], "when": [predicate]}
    raw = _raw(eligibility=[predicate], conditions=[{"id": "e", "type": "exists"}, route])
    assert_schema(raw, "sesslint.outcome-contract.v1.json")
    spec = contract_from_dict(raw)
    assert spec.eligibility[0].op == predicate["op"]


def test_key_fields_count_for_duplicates_only_when_a_check_reads_them() -> None:
    """REC-04: duplicate rows are compared on the fields a check reads; keys match as text."""
    spec = contract_from_dict(_raw(eligibility=[{"field": "v", "op": "gt", "value": 0}]))
    assert spec.relevant_source_fields() == {"id", "v"}
    assert spec.relevant_source_fields(include_key=False) == {"v"}
    keyed = contract_from_dict(_raw(eligibility=[{"field": "id", "op": "gt", "value": 0}]))
    assert keyed.relevant_source_fields(include_key=False) == {"id"}
