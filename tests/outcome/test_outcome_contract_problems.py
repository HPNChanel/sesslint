"""Exact validation problems and edge values of the OutcomeGuard contract parser (CON-01).

Every message is asserted with its location prefix, so a lost or altered
``where`` or wording is a failure, not just a changed substring.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sesslint.outcome import ContractError, contract_from_dict, load_contract
from sesslint.outcome.contract import MAX_CONTRACT_BYTES, Predicate, int_text, parse_strict_json

from .helpers import digit_limit

_OPS = "['absent', 'eq', 'gt', 'gte', 'in', 'lt', 'lte', 'ne', 'not_in', 'present']"


def _base() -> dict[str, Any]:
    return {
        "schema_version": "sesslint.outcome-contract/v1",
        "name": "c",
        "version": "1",
        "key": {"source": "id", "target": "ref"},
        "conditions": [{"id": "e", "type": "exists"}],
    }


def _with(**over: Any) -> dict[str, Any]:
    raw = _base()
    raw.update(over)
    return raw


CASES: list[tuple[str, dict[str, Any], list[str], tuple[str, ...]]] = [
    (
        "schema",
        {"schema_version": "v0"},
        [],
        ("contract: 'schema_version' must be 'sesslint.outcome-contract/v1'",),
    ),
    ("name_missing", {}, ["name"], ("contract: 'name' is required",)),
    (
        "name_bad",
        {"name": 5},
        [],
        ("contract: 'name' must be a non-empty string (at most 2000 characters)",),
    ),
    (
        "description_bad",
        {"description": 5},
        [],
        ("contract: 'description' must be a non-empty string (at most 2000 characters)",),
    ),
    (
        "version_65",
        {"version": "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"},
        [],
        ("contract: 'version' must be a non-empty string (at most 64 characters)",),
    ),
    (
        "key_not_object",
        {"key": 5},
        [],
        ("contract: 'key' must be an object with 'source' and 'target'",),
    ),
    (
        "key_source_bad",
        {"key": {"source": [], "target": "ref"}},
        [],
        ("key.source: must be a field name or a list of 1-8 field names",),
    ),
    (
        "key_target_bad",
        {"key": {"source": "id", "target": [1]}},
        [],
        ("key.target: must be a field name or a list of 1-8 field names",),
    ),
    (
        "key_dup",
        {"key": {"source": ["a", "a"], "target": ["b", "c"]}},
        [],
        ("key.source: lists a field twice",),
    ),
    (
        "key_len",
        {"key": {"source": ["a", "b"], "target": "c"}},
        [],
        ("key: source and target must list the same number of fields",),
    ),
    ("due_not_object", {"due": 5}, [], ("due: must be an object",)),
    (
        "due_field_bad",
        {"due": {"source_time_field": "", "within_seconds": 1}},
        [],
        ("due: 'source_time_field' must be a non-empty field name (at most 256 characters)",),
    ),
    (
        "due_within_bad",
        {"due": {"source_time_field": "t", "within_seconds": "1"}},
        [],
        ("due: 'within_seconds' must be a non-negative integer (<= 10 years)",),
    ),
    (
        "elig_not_list",
        {"eligibility": 5},
        [],
        ("eligibility: must be a list of at most 32 predicates",),
    ),
    ("elig_item", {"eligibility": [5]}, [], ("eligibility[0]: predicate must be an object",)),
    (
        "elig_op",
        {"eligibility": [{"field": "f", "op": "like"}]},
        [],
        (f"eligibility[0]: 'op' must be one of {_OPS}",),
    ),
    (
        "elig_field",
        {"eligibility": [{"op": "present"}]},
        [],
        ("eligibility[0]: 'field' must be a non-empty field name (at most 256 characters)",),
    ),
    (
        "elig_in",
        {"eligibility": [{"field": "f", "op": "in", "values": []}]},
        [],
        ("eligibility[0]: 'values' must be a non-empty list of at most 1000 values",),
    ),
    (
        "elig_gt",
        {"eligibility": [{"field": "f", "op": "gt", "value": "x"}]},
        [],
        ("eligibility[0]: 'gt' needs a numeric 'value'",),
    ),
    (
        "elig_eq",
        {"eligibility": [{"field": "f", "op": "eq", "value": [1]}]},
        [],
        ("eligibility[0]: 'eq' needs a scalar 'value'",),
    ),
    (
        "elig_in_obj",
        {"eligibility": [{"field": "f", "op": "in", "values": [{}]}]},
        [],
        ("eligibility[0]: 'values' may only hold strings, numbers, booleans or null",),
    ),
    (
        "too_many_conditions",
        {
            "conditions": [
                {"id": "c0", "type": "exists"},
                {"id": "c1", "type": "exists"},
                {"id": "c2", "type": "exists"},
                {"id": "c3", "type": "exists"},
                {"id": "c4", "type": "exists"},
                {"id": "c5", "type": "exists"},
                {"id": "c6", "type": "exists"},
                {"id": "c7", "type": "exists"},
                {"id": "c8", "type": "exists"},
                {"id": "c9", "type": "exists"},
                {"id": "c10", "type": "exists"},
                {"id": "c11", "type": "exists"},
                {"id": "c12", "type": "exists"},
                {"id": "c13", "type": "exists"},
                {"id": "c14", "type": "exists"},
                {"id": "c15", "type": "exists"},
                {"id": "c16", "type": "exists"},
                {"id": "c17", "type": "exists"},
                {"id": "c18", "type": "exists"},
                {"id": "c19", "type": "exists"},
                {"id": "c20", "type": "exists"},
                {"id": "c21", "type": "exists"},
                {"id": "c22", "type": "exists"},
                {"id": "c23", "type": "exists"},
                {"id": "c24", "type": "exists"},
                {"id": "c25", "type": "exists"},
                {"id": "c26", "type": "exists"},
                {"id": "c27", "type": "exists"},
                {"id": "c28", "type": "exists"},
                {"id": "c29", "type": "exists"},
                {"id": "c30", "type": "exists"},
                {"id": "c31", "type": "exists"},
                {"id": "c32", "type": "exists"},
                {"id": "c33", "type": "exists"},
                {"id": "c34", "type": "exists"},
                {"id": "c35", "type": "exists"},
                {"id": "c36", "type": "exists"},
                {"id": "c37", "type": "exists"},
                {"id": "c38", "type": "exists"},
                {"id": "c39", "type": "exists"},
                {"id": "c40", "type": "exists"},
                {"id": "c41", "type": "exists"},
                {"id": "c42", "type": "exists"},
                {"id": "c43", "type": "exists"},
                {"id": "c44", "type": "exists"},
                {"id": "c45", "type": "exists"},
                {"id": "c46", "type": "exists"},
                {"id": "c47", "type": "exists"},
                {"id": "c48", "type": "exists"},
                {"id": "c49", "type": "exists"},
                {"id": "c50", "type": "exists"},
                {"id": "c51", "type": "exists"},
                {"id": "c52", "type": "exists"},
                {"id": "c53", "type": "exists"},
                {"id": "c54", "type": "exists"},
                {"id": "c55", "type": "exists"},
                {"id": "c56", "type": "exists"},
                {"id": "c57", "type": "exists"},
                {"id": "c58", "type": "exists"},
                {"id": "c59", "type": "exists"},
                {"id": "c60", "type": "exists"},
                {"id": "c61", "type": "exists"},
                {"id": "c62", "type": "exists"},
                {"id": "c63", "type": "exists"},
                {"id": "c64", "type": "exists"},
            ]
        },
        [],
        ("contract: at most 64 conditions are supported",),
    ),
    (
        "all_disabled",
        {"conditions": [{"id": "e", "type": "exists", "disabled": "why"}]},
        [],
        (
            "contract: every condition is disabled; nothing would be evaluated",
            "contract: no decisive condition: at least one must be non-advisory",
        ),
    ),
    (
        "none_decisive",
        {"conditions": [{"id": "e", "type": "exists", "advisory": True}]},
        [],
        ("contract: no decisive condition: at least one must be non-advisory",),
    ),
    (
        "dup_id",
        {"conditions": [{"id": "e", "type": "exists"}, {"id": "e", "type": "exists"}]},
        [],
        ("condition 'e': duplicate condition id",),
    ),
    ("cond_not_object", {"conditions": [5]}, [], ("conditions[0]: condition must be an object",)),
    (
        "cond_bad_id",
        {"conditions": [{"id": "e", "type": "exists"}, {"id": "-", "type": "exists"}]},
        [],
        ("conditions[1]: 'id' must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}",),
    ),
    (
        "cond_description",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {"id": "d", "type": "exists", "description": 5},
            ]
        },
        [],
        ("condition 'd': 'description' must be a non-empty string (at most 2000 characters)",),
    ),
    (
        "required_field",
        {"conditions": [{"id": "e", "type": "exists"}, {"id": "r", "type": "required"}]},
        [],
        ("condition 'r': 'field' must be a non-empty field name (at most 256 characters)",),
    ),
    (
        "required_flag",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {"id": "r", "type": "required", "field": "f", "allow_null": "y", "allow_empty": 1},
            ]
        },
        [],
        (
            "condition 'r': 'allow_null' must be true or false",
            "condition 'r': 'allow_empty' must be true or false",
        ),
    ),
    (
        "count_min_bad",
        {"conditions": [{"id": "e", "type": "exists"}, {"id": "n", "type": "count", "min": "1"}]},
        [],
        ("condition 'n': 'min' must be an integer from 0 to 1000000",),
    ),
    (
        "count_max_bad",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {"id": "n", "type": "count", "min": 1, "max": -1},
            ]
        },
        [],
        ("condition 'n': 'max' must be an integer from 0 to 1000000",),
    ),
    (
        "count_swap",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {"id": "n", "type": "count", "min": 3, "max": 2},
            ]
        },
        [],
        ("condition 'n': 'min' must not exceed 'max'",),
    ),
    (
        "count_zero",
        {"conditions": [{"id": "e", "type": "exists"}, {"id": "n", "type": "count", "min": 0}]},
        [],
        ("condition 'n': count with min 0 and no max can never be violated",),
    ),
    (
        "count_max0",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {"id": "n", "type": "count", "min": 1, "max": 0},
            ]
        },
        [],
        (
            "condition 'n': 'min' must not exceed 'max'",
            "condition 'n': 'max' 0 asks for absence, which v1 cannot prove; omit it",
        ),
    ),
    (
        "count_bad_not_cascade",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {"id": "n", "type": "count", "min": "x", "max": 0},
            ]
        },
        [],
        ("condition 'n': 'min' must be an integer from 0 to 1000000",),
    ),
    (
        "type_kind",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {"id": "t", "type": "type", "field": "f", "kind": "blob"},
            ]
        },
        [],
        (
            "condition 't': 'kind' must be one of "
            "['boolean', 'date-time', 'integer', 'number', 'string']",
        ),
    ),
    (
        "type_field",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {"id": "t", "type": "type", "kind": "string"},
            ]
        },
        [],
        ("condition 't': 'field' must be a non-empty field name (at most 256 characters)",),
    ),
    (
        "one_of_null",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {"id": "o", "type": "one_of", "field": "f", "values": ["a", None]},
            ]
        },
        [],
        ("condition 'o': 'values' cannot hold null: a null field never matches these values",),
    ),
    (
        "one_of_obj",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {"id": "o", "type": "one_of", "field": "f", "values": [[1]]},
            ]
        },
        [],
        ("condition 'o': 'values' may only hold strings, numbers or booleans",),
    ),
    (
        "one_of_empty",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {"id": "o", "type": "one_of", "field": "f", "values": []},
            ]
        },
        [],
        ("condition 'o': 'values' must be a non-empty list of at most 1000 values",),
    ),
    (
        "normalize_type",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {"id": "o", "type": "one_of", "field": "f", "values": ["a"], "normalize": "trim"},
            ]
        },
        [],
        ("condition 'o': 'normalize' must be a list of step names",),
    ),
    (
        "normalize_unknown",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {"id": "o", "type": "one_of", "field": "f", "values": ["a"], "normalize": ["x"]},
            ]
        },
        [],
        ("condition 'o': unsupported normalize step(s) ['x']; use trim, casefold",),
    ),
    (
        "normalize_twice",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {
                    "id": "o",
                    "type": "one_of",
                    "field": "f",
                    "values": ["a"],
                    "normalize": ["trim", "trim"],
                },
            ]
        },
        [],
        ("condition 'o': 'normalize' lists a step twice",),
    ),
    (
        "equals_source",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {"id": "q", "type": "equals", "field": "f", "normalize": ["x"]},
            ]
        },
        [],
        (
            "condition 'q': 'source_field' must be a non-empty field name (at most 256 characters)",
            "condition 'q': unsupported normalize step(s) ['x']; use trim, casefold",
        ),
    ),
    (
        "range_none",
        {"conditions": [{"id": "e", "type": "exists"}, {"id": "r", "type": "range", "field": "f"}]},
        [],
        ("condition 'r': range needs 'min', 'max' or both",),
    ),
    (
        "range_swap",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {"id": "r", "type": "range", "field": "f", "min": 2, "max": 1},
            ]
        },
        [],
        ("condition 'r': 'min' must not exceed 'max'",),
    ),
    (
        "range_nan_str",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {"id": "r", "type": "range", "field": "f", "min": "1"},
            ]
        },
        [],
        (
            "condition 'r': 'min' must be a finite number",
            "condition 'r': range needs 'min', 'max' or both",
        ),
    ),
    (
        "range_max_bad",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {"id": "r", "type": "range", "field": "f", "max": True},
            ]
        },
        [],
        (
            "condition 'r': 'max' must be a finite number",
            "condition 'r': range needs 'min', 'max' or both",
        ),
    ),
    (
        "route_nowhen",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {"id": "r", "type": "route", "field": "f", "values": ["a"], "when": []},
            ]
        },
        [],
        ("condition 'r': route needs at least one 'when' predicate",),
    ),
    (
        "route_when_bad",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {"id": "r", "type": "route", "field": "f", "values": ["a"], "when": [{"op": "x"}]},
            ]
        },
        [],
        (
            f"condition 'r' when[0]: 'op' must be one of {_OPS}",
            "condition 'r': route needs at least one 'when' predicate",
        ),
    ),
    (
        "route_values",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {
                    "id": "r",
                    "type": "route",
                    "field": "f",
                    "values": [None],
                    "when": [{"field": "k", "op": "present"}],
                    "normalize": ["q"],
                },
            ]
        },
        [],
        (
            "condition 'r': 'values' cannot hold null: a null field never matches these values",
            "condition 'r': unsupported normalize step(s) ['q']; use trim, casefold",
        ),
    ),
    (
        "on_time_basis",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {"id": "o", "type": "on_time", "basis": "x"},
            ],
            "due": {"source_time_field": "t", "within_seconds": 1},
        },
        [],
        ("condition 'o': 'basis' must be 'target_time' or 'observation'",),
    ),
    (
        "on_time_nofield",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {"id": "o", "type": "on_time", "basis": "target_time"},
            ],
            "due": {"source_time_field": "t", "within_seconds": 1},
        },
        [],
        ("condition 'o': 'field' must be a non-empty field name (at most 256 characters)",),
    ),
    (
        "on_time_obs_field",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {"id": "o", "type": "on_time", "basis": "observation", "field": "f"},
            ],
            "due": {"source_time_field": "t", "within_seconds": 1},
        },
        [],
        ("condition 'o': the observation basis takes no 'field'",),
    ),
    (
        "on_time_nodue",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {"id": "o", "type": "on_time", "basis": "observation"},
            ]
        },
        [],
        ("condition 'o': on_time needs a contract-level 'due' window",),
    ),
    (
        "any_of_one",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {"id": "a", "type": "any_of", "conditions": [{"id": "b", "type": "exists"}]},
            ]
        },
        [],
        ("condition 'a': any_of needs at least two branch conditions",),
    ),
    (
        "any_of_nest",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {
                    "id": "a",
                    "type": "any_of",
                    "conditions": [
                        {"id": "b", "type": "exists"},
                        {
                            "id": "c",
                            "type": "any_of",
                            "conditions": [
                                {"id": "d", "type": "exists"},
                                {"id": "f", "type": "exists"},
                            ],
                        },
                    ],
                },
            ]
        },
        [],
        ("condition 'c': any_of branches cannot nest another any_of",),
    ),
    (
        "any_of_flags",
        {
            "conditions": [
                {"id": "e", "type": "exists"},
                {
                    "id": "a",
                    "type": "any_of",
                    "conditions": [
                        {"id": "b", "type": "exists", "advisory": True},
                        {"id": "c", "type": "exists", "disabled": "w"},
                    ],
                },
            ]
        },
        [],
        ("condition 'a': any_of branches cannot be advisory or disabled themselves",),
    ),
    ("unknown_key", {"surprise": 1}, [], ("contract: unknown key 'surprise'",)),
]


@pytest.mark.parametrize(
    ("over", "missing", "problems"),
    [case[1:] for case in CASES],
    ids=[case[0] for case in CASES],
)
def test_problems_are_exact(
    over: dict[str, Any], missing: list[str], problems: tuple[str, ...]
) -> None:
    raw = _base()
    raw.update(over)
    for key in missing:
        del raw[key]
    with pytest.raises(ContractError) as info:
        contract_from_dict(raw)
    assert info.value.problems == problems
    assert str(info.value) == "; ".join(problems)


def test_boundary_values_that_are_accepted() -> None:
    spec = contract_from_dict(
        _with(
            name="n" * 2000,
            description="d" * 2000,
            version="v" * 64,
            due={"source_time_field": "t", "within_seconds": 0},
        )
    )
    assert len(spec.name) == len(spec.description or "") == 2000
    assert spec.due is not None and spec.due.within_seconds == 0
    assert spec.due.source_time_field == "t"
    with pytest.raises(ContractError, match="'name' must be a non-empty string"):
        contract_from_dict(_with(name="n" * 2001))


def test_predicates_keep_only_the_fields_their_operator_uses() -> None:
    spec = contract_from_dict(
        _with(
            eligibility=[
                {"field": "a", "op": "present"},
                {"field": "b", "op": "in", "values": ["x", 2]},
                {"field": "c", "op": "eq", "value": "v"},
            ]
        )
    )
    assert spec.eligibility == (
        Predicate(field="a", op="present", value=None, values=()),
        Predicate(field="b", op="in", value=None, values=("x", 2)),
        Predicate(field="c", op="eq", value="v", values=()),
    )


@pytest.mark.parametrize("op", ["gt", "gte", "lt", "lte"])
def test_a_boolean_is_not_a_number_in_a_comparison(op: str) -> None:
    with pytest.raises(ContractError) as info:
        contract_from_dict(_with(eligibility=[{"field": "f", "op": op, "value": True}]))
    assert info.value.problems == (f"eligibility[0]: '{op}' needs a numeric 'value'",)


def test_warnings_treat_count_as_a_presence_condition() -> None:
    spec = contract_from_dict(
        _with(
            conditions=[{"id": "n", "type": "count", "min": 1}],
            due={"source_time_field": "t", "within_seconds": 5},
        )
    )
    assert spec.warnings() == ()


def test_due_field_is_a_relevant_source_field() -> None:
    spec = contract_from_dict(
        _with(
            due={"source_time_field": "t", "within_seconds": 5}, key={"source": "k", "target": "r"}
        )
    )
    assert spec.relevant_source_fields() == frozenset({"k", "t"})
    assert spec.relevant_source_fields(include_key=False) == frozenset({"t"})


@pytest.mark.parametrize("digits", [1, 599, 600, 601, 1200, 1201, 2500])
@pytest.mark.parametrize("sign", [1, -1])
@pytest.mark.parametrize("limit", [0, 640])
def test_int_text_matches_str_whatever_the_digit_limit(digits: int, sign: int, limit: int) -> None:
    value = sign * (10**digits - 1)
    exact = sign * 10**digits
    with digit_limit(0):
        expected = (str(value), str(exact))
    with digit_limit(limit):
        assert (int_text(value), int_text(exact)) == expected


def test_int_text_of_small_values() -> None:
    assert [int_text(v) for v in (0, 1, -1, 12)] == ["0", "1", "-1", "12"]


def test_non_finite_constants_are_refused_by_name() -> None:
    for token in ("NaN", "Infinity", "-Infinity"):
        with pytest.raises(ValueError, match=f"^non-finite number {token} is not allowed$"):
            parse_strict_json(f"[{token}]")


def test_digit_limit_problem_names_the_first_overlong_integer() -> None:
    """A lowered limit makes a 641-digit integer impossible to fingerprint; name the right one."""
    elig = [
        {"field": "a", "op": "eq", "value": 7000},
        {"field": "b", "op": "eq", "value": 10**640},
    ]
    negative = [
        {"field": "a", "op": "eq", "value": 7000},
        {"field": "b", "op": "eq", "value": -(10**640)},
    ]
    for items, path in ((elig, "eligibility[1].value"), (negative, "eligibility[1].value")):
        with digit_limit(640), pytest.raises(ContractError) as info:
            contract_from_dict(_with(eligibility=items))
        assert info.value.problems == (
            f"contract: {path}: number out of range; this Python converts integers of at most "
            "640 digits to text (sys.set_int_max_str_digits or PYTHONINTMAXSTRDIGITS), so "
            "the contract cannot be fingerprinted",
        )


def test_largest_integer_under_the_digit_limit_still_loads() -> None:
    raw = _with(eligibility=[{"field": "a", "op": "eq", "value": 10**639}])
    with digit_limit(0):
        expected = contract_from_dict(raw).sha256
    with digit_limit(640):
        assert contract_from_dict(raw).sha256 == expected


def test_contract_file_may_be_exactly_one_mebibyte(tmp_path: Path) -> None:
    text = json.dumps(_base())
    padded = text + " " * (MAX_CONTRACT_BYTES - len(text))
    path = tmp_path / "c.json"
    path.write_bytes(padded.encode("ascii"))
    assert load_contract(path).name == "c"
    path.write_bytes(padded.encode("ascii") + b" ")
    with pytest.raises(ContractError) as info:
        load_contract(path)
    assert info.value.problems == ("contract: file exceeds 1 MiB",)


def _problems_of(raw: Any) -> tuple[str, ...]:
    with pytest.raises(ContractError) as info:
        contract_from_dict(raw)
    return info.value.problems


def test_warnings_ignore_advisory_and_disabled_presence_conditions() -> None:
    for extra in ({"advisory": True}, {"disabled": "later"}):
        spec = contract_from_dict(
            _with(
                conditions=[
                    {"id": "r", "type": "required", "field": "f"},
                    {"id": "e", "type": "exists", **extra},
                ]
            )
        )
        assert any(w.startswith("no active exists/count condition") for w in spec.warnings())


def test_top_level_must_be_an_object() -> None:
    assert _problems_of([]) == ("contract: top level must be a JSON object",)


def test_empty_condition_list_is_located_at_the_contract() -> None:
    assert _problems_of(_with(conditions=[])) == (
        "contract: 'conditions' must be a non-empty list (an empty contract proves nothing)",
    )


def test_null_name_is_incomplete() -> None:
    assert _problems_of(_with(name=None)) == ("contract: incomplete",)


def test_unknown_condition_type_is_located_at_the_condition() -> None:
    types = "['any_of', 'count', 'equals', 'exists', 'on_time', 'one_of', 'range', 'required', "
    assert _problems_of(_with(conditions=[{"id": "x", "type": "magic"}])) == (
        f"conditions[0]: 'type' must be one of {types}'route', 'type']",
    )


def test_unusable_condition_ids_do_not_count_as_duplicates() -> None:
    bad = {"id": "-", "type": "required"}
    field = "'field' must be a non-empty field name (at most 256 characters)"
    id_rule = "'id' must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}"
    assert _problems_of(_with(conditions=[bad, dict(bad)])) == (
        f"conditions[0]: {id_rule}",
        f"condition '?': {field}",
        f"conditions[1]: {id_rule}",
        f"condition '?': {field}",
    )


def test_non_boolean_advisory_and_bad_disabled_are_located() -> None:
    assert _problems_of(
        _with(conditions=[{"id": "x", "type": "exists", "advisory": "yes", "disabled": 5}])
    ) == (
        "condition 'x': 'advisory' must be true or false",
        "condition 'x': 'disabled' must be a non-empty string (at most 2000 characters)",
    )


def test_bad_any_of_branch_is_located_at_its_parent_and_index() -> None:
    assert _problems_of(
        _with(
            conditions=[
                {"id": "e", "type": "exists"},
                {"id": "a", "type": "any_of", "conditions": [5, {"id": "b", "type": "exists"}]},
            ]
        )
    ) == ("condition 'a' branch 0: condition must be an object",)


def test_documented_maximums_are_accepted_and_one_more_is_not() -> None:
    fields = [f"f{i}" for i in range(8)]
    spec = contract_from_dict(
        _with(
            key={"source": fields, "target": fields},
            eligibility=[{"field": "f", "op": "present"}] * 32,
            conditions=[
                {"id": "o", "type": "one_of", "field": "f", "values": list(range(1000))},
            ],
            due={"source_time_field": "t", "within_seconds": 10 * 366 * 24 * 3600},
        )
    )
    assert len(spec.source_key) == 8 and len(spec.eligibility) == 32
    assert len(spec.conditions[0].values) == 1000
    assert spec.due is not None and spec.due.within_seconds == 10 * 366 * 24 * 3600
    over = {"source_time_field": "t", "within_seconds": 10 * 366 * 24 * 3600 + 1}
    assert _problems_of(_with(due=over)) == (
        "due: 'within_seconds' must be a non-negative integer (<= 10 years)",
    )
    assert any(
        "1-8 field names" in p
        for p in _problems_of(_with(key={"source": [*fields, "x"], "target": "r"}))
    )
    assert any(
        "at most 32 predicates" in p
        for p in _problems_of(_with(eligibility=[{"field": "f", "op": "present"}] * 33))
    )
    one_of = {"id": "o", "type": "one_of", "field": "f", "values": list(range(1001))}
    assert any("at most 1000 values" in p for p in _problems_of(_with(conditions=[one_of])))


def test_a_top_level_number_that_is_too_long_is_located_at_the_contract(tmp_path: Path) -> None:
    path = tmp_path / "c.json"
    path.write_text("7" * 4301, encoding="utf-8")
    with pytest.raises(ContractError) as info:
        load_contract(path)
    assert info.value.problems[0].startswith("contract: number out of range;")
