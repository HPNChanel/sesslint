"""Exact ``explain_contract`` wording per condition type and predicate (CON-03)."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from sesslint.outcome import contract_from_dict, explain_contract


def _spec(conditions: list[dict[str, Any]], **top: Any) -> Any:
    raw: dict[str, Any] = {
        "schema_version": "sesslint.outcome-contract/v1",
        "name": "c",
        "version": "1",
        "key": {"source": "id", "target": "ref"},
        "conditions": conditions,
    }
    raw.update(top)
    return contract_from_dict(raw)


def _line(condition: dict[str, Any], **top: Any) -> str:
    """The explain line of one condition, without the ``  - id: `` prefix."""
    prefix = f"  - {condition['id']}: "
    extra = (
        [{"id": "anchor", "type": "exists"}]
        if condition.get("disabled") or condition.get("advisory")
        else []
    )
    spec = _spec([condition, *extra], **top)
    matches = [ln for ln in explain_contract(spec).split("\n") if ln.startswith(prefix)]
    assert len(matches) == 1
    return matches[0][len(prefix) :]


DUE = {"source_time_field": "at", "within_seconds": 60}


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        ({"id": "x", "type": "exists"}, "at least one matching target record exists"),
        (
            {"id": "x", "type": "count", "min": 2},
            "at least 2 matching target record(s) exist",
        ),
        (
            {"id": "x", "type": "count"},
            "at least 1 matching target record(s) exist",
        ),
        (
            {"id": "x", "type": "count", "min": 3, "max": 3},
            "exactly 3 matching target record(s) exist",
        ),
        (
            {"id": "x", "type": "count", "min": 1, "max": 4},
            "between 1 and 4 matching target records exist",
        ),
        (
            {"id": "x", "type": "count", "max": 4},
            "between 1 and 4 matching target records exist",
        ),
        (
            {"id": "x", "type": "count", "min": 0, "max": 4},
            "between 0 and 4 matching target records exist",
        ),
        (
            {"id": "x", "type": "required", "field": "f"},
            "target field f is present, non-null and non-empty",
        ),
        (
            {"id": "x", "type": "required", "field": "f", "allow_null": True},
            "target field f is present, non-null and non-empty (null allowed)",
        ),
        (
            {"id": "x", "type": "required", "field": "f", "allow_empty": True},
            "target field f is present, non-null and non-empty (empty allowed)",
        ),
        (
            {
                "id": "x",
                "type": "required",
                "field": "f",
                "allow_null": True,
                "allow_empty": True,
            },
            "target field f is present, non-null and non-empty (null and empty allowed)",
        ),
        (
            {"id": "x", "type": "type", "field": "f", "kind": "string"},
            "target field f, when present, is a string",
        ),
        (
            {"id": "x", "type": "one_of", "field": "f", "values": ["a", 1]},
            'target field f, when present, is one of "a", 1',
        ),
        (
            {
                "id": "x",
                "type": "one_of",
                "field": "f",
                "values": ["a"],
                "normalize": ["casefold", "trim"],
            },
            'target field f, when present, is one of "a" (after trim, casefold)',
        ),
        (
            {"id": "x", "type": "equals", "field": "f", "source_field": "g"},
            "target field f equals source field g",
        ),
        (
            {
                "id": "x",
                "type": "equals",
                "field": "f",
                "source_field": "g",
                "normalize": ["trim"],
            },
            "target field f equals source field g (after trim)",
        ),
        (
            {"id": "x", "type": "range", "field": "f", "min": 1},
            "target field f, when present, is a number >= 1",
        ),
        (
            {"id": "x", "type": "range", "field": "f", "max": 2.5},
            "target field f, when present, is a number <= 2.5",
        ),
        (
            {"id": "x", "type": "range", "field": "f", "min": 0, "max": 9},
            "target field f, when present, is a number >= 0 and <= 9",
        ),
        (
            {
                "id": "x",
                "type": "route",
                "field": "f",
                "values": ["a"],
                "when": [{"field": "k", "op": "eq", "value": "v"}],
            },
            'when k = "v": target field f is one of "a"',
        ),
        (
            {
                "id": "x",
                "type": "route",
                "field": "f",
                "values": ["a", "b"],
                "normalize": ["trim"],
                "when": [
                    {"field": "k", "op": "present"},
                    {"field": "m", "op": "absent"},
                ],
            },
            "when k is present and non-empty and m is absent, null or empty: "
            'target field f is one of "a", "b" (after trim)',
        ),
        (
            {"id": "x", "type": "on_time", "basis": "target_time", "field": "done"},
            "target completion time done is at or before the deadline; only times "
            "from the source event up to the target observation count",
        ),
        (
            {"id": "x", "type": "on_time", "basis": "observation"},
            "the record is visible in a target snapshot taken at or before the deadline "
            "and not before the source event",
        ),
    ],
)
def test_condition_wording(condition: dict[str, Any], expected: str) -> None:
    assert _line(condition, due=DUE) == expected


def test_any_of_joins_branches_with_semicolons() -> None:
    line = _line(
        {
            "id": "x",
            "type": "any_of",
            "conditions": [
                {"id": "a", "type": "exists"},
                {"id": "b", "type": "count", "min": 2, "max": 2},
            ],
        }
    )
    assert line == (
        "any one of: at least one matching target record exists; "
        "exactly 2 matching target record(s) exist"
    )


def test_disabled_and_advisory_suffixes() -> None:
    assert _line({"id": "x", "type": "exists", "disabled": "waiting for data"}) == (
        "at least one matching target record exists [disabled: waiting for data]"
    )
    assert _line({"id": "x", "type": "exists", "advisory": True}) == (
        "at least one matching target record exists "
        "[advisory: reported, does not decide the outcome]"
    )
    # Disabled wins over advisory: only one suffix is printed.
    both = _line({"id": "x", "type": "exists", "advisory": True, "disabled": "why"})
    assert both == "at least one matching target record exists [disabled: why]"


@pytest.mark.parametrize(
    ("predicate", "expected"),
    [
        ({"field": "f", "op": "present"}, "f is present and non-empty"),
        ({"field": "f", "op": "absent"}, "f is absent, null or empty"),
        ({"field": "f", "op": "in", "values": ["a", 2]}, 'f is one of "a", 2'),
        ({"field": "f", "op": "not_in", "values": ["a", 2]}, 'f is not one of "a", 2'),
        ({"field": "f", "op": "eq", "value": "v"}, 'f = "v"'),
        ({"field": "f", "op": "ne", "value": 3}, "f != 3"),
        ({"field": "f", "op": "gt", "value": 3}, "f > 3"),
        ({"field": "f", "op": "gte", "value": 3}, "f >= 3"),
        ({"field": "f", "op": "lt", "value": 3}, "f < 3"),
        ({"field": "f", "op": "lte", "value": 3.5}, "f <= 3.5"),
    ],
)
def test_eligibility_predicate_wording(predicate: dict[str, Any], expected: str) -> None:
    text = explain_contract(_spec([{"id": "e", "type": "exists"}], eligibility=[predicate]))
    assert f"Applies only when all of:\n  - {expected}\n" in text


def test_full_explain_text_is_byte_exact() -> None:
    spec = _spec(
        [
            {"id": "e", "type": "exists"},
            {"id": "s", "type": "required", "field": "status", "advisory": True},
        ],
        description="Orders ship.",
        key={"source": ["a", "b"], "target": ["c", "d"]},
        due=DUE,
        eligibility=[
            {"field": "k", "op": "eq", "value": "v"},
            {"field": "n", "op": "gt", "value": 1},
        ],
    )
    assert explain_contract(spec) == (
        f"Contract c v1 (sha256 {spec.sha256[:16]})\n"
        "  Orders ship.\n"
        "Work items: one per distinct source key (a, b), matched exactly to target key (c, d).\n"
        "Applies only when all of:\n"
        '  - k = "v"\n'
        "  - n > 1\n"
        "Deadline: at + 60s; before it, missing results are PENDING.\n"
        "Conditions:\n"
        "  - e: at least one matching target record exists\n"
        "  - s: target field status is present, non-null and non-empty "
        "[advisory: reported, does not decide the outcome]\n"
        "Absence is proven only from a target snapshot declared complete and observed at "
        "or after the deadline; otherwise the verdict is INCONCLUSIVE."
    )


def test_explain_minimal_contract_has_no_optional_lines() -> None:
    spec = _spec([{"id": "s", "type": "required", "field": "f"}])
    lines = explain_contract(spec).split("\n")
    assert lines[0] == f"Contract c v1 (sha256 {spec.sha256[:16]})"
    assert lines[1].startswith("Work items: one per distinct source key (id)")
    assert lines[2] == "Applies to every keyed source record."
    assert lines[3] == "Conditions:"
    assert lines[4] == "  - s: target field f is present, non-null and non-empty"
    assert lines[5].startswith("Warning: no active exists/count condition")
    assert lines[6] == (
        "Warning: no due window declared: absence is judged at the evaluation instant"
    )
    assert lines[7].startswith("Absence is proven only")
    assert len(lines) == 8


def test_unset_count_bounds_read_as_zero_minimum_and_unbounded() -> None:
    """The parser never yields them, but a hand-built condition must not crash or shift."""
    spec = _spec([{"id": "n", "type": "count", "min": 5}])
    bare = replace(spec.conditions[0], minimum=None, maximum=None)
    text = explain_contract(replace(spec, conditions=(bare,)))
    assert "  - n: at least 0 matching target record(s) exist\n" in text
    open_ended = replace(spec.conditions[0], minimum=7, maximum=None)
    assert "  - n: at least 7 matching" in explain_contract(replace(spec, conditions=(open_ended,)))
