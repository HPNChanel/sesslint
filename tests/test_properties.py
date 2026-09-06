"""Hypothesis property-based tests for core invariant verification."""

from __future__ import annotations

import json
from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from sesslint.canonical import canonical_bytes, to_canonical_json
from sesslint.codes import ALL_CODES, Repairability, Severity
from sesslint.finding import Finding, SourceRef, make_finding, sort_findings

# Strategy generating valid synthetic session and record identifiers
ident_st = st.from_regex(r"evt_[0-9a-z]{1,8}", fullmatch=True)
line_st = st.one_of(st.none(), st.integers(min_value=1, max_value=10_000))
code_st = st.sampled_from(sorted(ALL_CODES))
severity_st = st.sampled_from(list(Severity))
repairability_st = st.sampled_from(list(Repairability))


@st.composite
def findings_strategy(draw: st.DrawFn) -> Finding:
    """Hypothesis composite strategy generating valid Finding instances."""
    code = draw(code_st)
    severity = draw(severity_st)
    repairability = draw(repairability_st)
    line = draw(line_st)
    record_id = draw(st.one_of(st.none(), ident_st))
    related = tuple(draw(st.lists(ident_st, max_size=5, unique=True)))

    line_str = str(line) if line is not None else "1"
    rec_str = record_id if record_id is not None else "rec_0"

    return make_finding(
        code=code,
        severity=severity,
        repairability=repairability,
        message_template="Finding on line {line} for {record_id}",
        template_args={"line": line_str, "record_id": rec_str},
        source=SourceRef(path="session.jsonl", line=line, record_id=record_id),
        related_ids=related,
    )


@given(st.lists(findings_strategy(), max_size=30))
def test_finding_sort_is_idempotent(findings: list[Finding]) -> None:
    """Property: Sorting a list of findings is strictly idempotent."""
    sorted_once = sort_findings(findings)
    sorted_twice = sort_findings(sorted_once)
    assert sorted_once == sorted_twice


@given(findings_strategy(), findings_strategy())
def test_finding_ordering_totality(f1: Finding, f2: Finding) -> None:
    """Property: Any two findings have a strict, well-defined total order."""
    lt = f1 < f2
    gt = f1 > f2
    eq = f1 == f2

    # Exactly one condition must be true
    assert (lt + gt + eq) == 1
    # Reflexivity
    assert (f1 == f1) is True
    # Antisymmetry
    if lt:
        assert (f2 > f1) is True


# Strategy generating arbitrary JSON-compatible primitive structures
json_primitives = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-1_000_000, max_value=1_000_000),
    st.floats(allow_nan=False, allow_infinity=False, min_value=-1e6, max_value=1e6),
    st.text(alphabet=st.characters(blacklist_categories=("Cs", "Cc")), max_size=50),
)

json_values = st.recursive(
    json_primitives,
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(
            st.text(
                alphabet=st.characters(blacklist_categories=("Cs", "Cc")),
                min_size=1,
                max_size=20,
            ),
            children,
            max_size=5,
        ),
    ),
    max_leaves=25,
)


@given(json_values)
def test_canonical_json_roundtrip_and_determinism(data: Any) -> None:
    """Property: Canonical JSON serialization is deterministic and round-trips cleanly."""
    json_str_1 = to_canonical_json(data)
    json_str_2 = to_canonical_json(data)

    # Determinism
    assert json_str_1 == json_str_2
    assert canonical_bytes(json_str_1) == canonical_bytes(json_str_2)

    # Valid JSON roundtrip
    decoded = json.loads(json_str_1)
    if isinstance(data, (dict, list)):
        assert decoded == json.loads(json.dumps(data))
