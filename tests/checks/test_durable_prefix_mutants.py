"""Mutation-driven behaviour tests for SL206 (CL-15)."""

from __future__ import annotations

from typing import Any

import pytest

from sesslint.canonical import SessionEvent
from sesslint.checks.durable_prefix import check_durable_prefix
from sesslint.codes import Repairability, Severity
from sesslint.context import CheckContext

MSG_TRAIL = "Non-durable tail record past the durable prefix on line {l} for record {r}"
MSG_GAP = "Durable-prefix ordinal hole on line {l} for record {r}"
MSG_FIELD = "Reasoning item missing a resume-required field on line {l} for record {r}"


def _ev(eid: Any, line: int, codex: Any = None, *, extra: Any = "auto") -> SessionEvent:
    if extra == "auto":
        extra = {"codex": codex} if codex is not None else {}
    return SessionEvent(
        id=eid,
        parent_id=None,
        seq=line,
        ts="",
        actor="assistant",
        kind="message",
        source_line=line,
        source_adapter="codex-rollout",
        source_location="d\\r.jsonl",
        extra_fields=extra,
    )


def _d(eid: str, line: int, ordinal: int, durable: bool = True, **kw: Any) -> SessionEvent:
    return _ev(eid, line, {"ordinal": ordinal, "durable": durable, **kw})


def _by(findings: list[Any]) -> dict[str, Any]:
    return {f.evidence["divergence"]: f for f in findings}


def test_no_markers_silent() -> None:
    assert check_durable_prefix([_ev("a", 1)]) == []
    assert check_durable_prefix([]) == []


def test_contiguous_durable_silent() -> None:
    assert check_durable_prefix([_d("a", 1, 0), _d("b", 2, 1), _d("c", 3, 2)]) == []


def test_trailing_exact() -> None:
    ctx = CheckContext(adapter_id="ad", adapter_version="1", profile_id="pr", profile_version="2")
    evs = [
        _d("a", 1, 0),
        _d("b", 2, 1),
        _d("c", 3, 5, durable=False, envelope_type=" event_msg ", subagent_history_start_ordinal=5),
    ]
    (f,) = check_durable_prefix(evs, context=ctx)
    assert f.code == "SL206"
    assert f.severity is Severity.WARNING
    assert f.repairability is Repairability.MANUAL
    assert f.message == MSG_TRAIL.format(l=3, r="c")
    assert f.source.path == "d/r.jsonl"
    assert f.source.line == 3
    assert f.source.record_id == "c"
    assert dict(f.evidence or {}) == {
        "divergence": "trailing-non-durable",
        "expected_durable_ordinal": 5,
        "last_durable_ordinal": 1,
        "inherited_prefix_ordinal": 5,
        "tail_ordinal": 5,
        "tail_envelope_family": "event_msg",
    }


def test_claim_equal_to_last_durable_silent() -> None:
    evs = [_d("a", 1, 0), _d("b", 2, 1, subagent_history_start_ordinal=1)]
    assert check_durable_prefix(evs) == []


def test_claim_just_past_last_durable_fires() -> None:
    evs = [_d("a", 1, 0), _d("b", 2, 1, subagent_history_start_ordinal=2)]
    got = _by(check_durable_prefix(evs))
    assert "trailing-non-durable" in got


def test_trailing_requires_a_durable_ordinal() -> None:
    evs = [_d("a", 1, 0, durable=False, subagent_history_start_ordinal=9)]
    assert check_durable_prefix(evs) == []


def test_durable_must_be_exactly_true() -> None:
    evs = [
        _ev("a", 1, {"ordinal": 0, "durable": 1, "subagent_history_start_ordinal": 9}),
        _ev("b", 2, {"ordinal": 1, "durable": "yes"}),
    ]
    assert check_durable_prefix(evs) == []


def test_first_claim_wins() -> None:
    evs = [
        _d("a", 1, 0, subagent_history_start_ordinal=0),
        _d("b", 2, 1, subagent_history_start_ordinal=99),
    ]
    assert check_durable_prefix(evs) == []
    evs = [
        _d("a", 1, 0, subagent_history_start_ordinal="x"),
        _d("b", 2, 1, subagent_history_start_ordinal=True),
        _d("c", 3, 2, subagent_history_start_ordinal=7),
    ]
    got = _by(check_durable_prefix(evs))
    assert dict(got["trailing-non-durable"].evidence)["inherited_prefix_ordinal"] == 7


def test_trailing_anchor_prefers_claimed_ordinal_record() -> None:
    evs = [
        _d("a", 1, 0, subagent_history_start_ordinal=3),
        _d("claim", 2, 3, durable=False, envelope_type="token_count"),
        _d("tail", 3, 8, durable=False, envelope_type="other"),
    ]
    (f,) = check_durable_prefix(evs)
    assert f.source.record_id == "claim"
    ev = dict(f.evidence or {})
    assert ev["tail_ordinal"] == 8
    assert ev["tail_envelope_family"] == "token_count"


def test_trailing_anchor_falls_back_to_highest_ordinal() -> None:
    evs = [
        _d("a", 1, 0, subagent_history_start_ordinal=50),
        _d("hi", 2, 9, durable=False, envelope_type="fam"),
        _d("lo", 3, 4, durable=False),
    ]
    (f,) = check_durable_prefix(evs)
    assert f.source.record_id == "hi"
    assert dict(f.evidence or {})["tail_envelope_family"] == "fam"


def test_trailing_tie_on_ordinal_takes_last() -> None:
    evs = [
        _d("a", 1, 0, subagent_history_start_ordinal=50),
        _d("t1", 2, 9, durable=False),
        _d("t2", 3, 9, durable=False),
    ]
    (f,) = check_durable_prefix(evs)
    assert f.source.record_id == "t2"


def test_trailing_ignores_non_int_ordinals_in_anchor_search() -> None:
    evs = [
        _d("a", 1, 0, subagent_history_start_ordinal=5),
        _ev("t", 2, {"ordinal": True, "durable": False}),
        _ev("u", 3, {"ordinal": "7", "durable": False}),
    ]
    (f,) = check_durable_prefix(evs)
    assert f.source.record_id == "a"
    ev = dict(f.evidence or {})
    assert ev["tail_ordinal"] == 0


@pytest.mark.parametrize("fam", [None, "", "  ", 5])
def test_blank_family_omitted(fam: Any) -> None:
    evs = [_d("a", 1, 0, subagent_history_start_ordinal=3, envelope_type=fam)]
    (f,) = check_durable_prefix(evs)
    assert "tail_envelope_family" not in dict(f.evidence or {})


def test_gap_exact() -> None:
    evs = [_d("a", 1, 0), _d("b", 2, 3), _d("c", 3, 4)]
    (f,) = check_durable_prefix(evs)
    assert f.message == MSG_GAP.format(l=2, r="b")
    assert f.source.record_id == "b"
    assert dict(f.evidence or {}) == {
        "divergence": "durable-gap",
        "missing_ordinal": 1,
        "expected_durable_ordinal": 1,
        "last_durable_ordinal": 4,
    }


def test_gap_reports_first_hole_only() -> None:
    evs = [_d("a", 1, 0), _d("b", 2, 4), _d("c", 3, 7)]
    (f,) = check_durable_prefix(evs)
    assert dict(f.evidence or {})["missing_ordinal"] == 1


def test_envelope_non_durable_fills_hole() -> None:
    evs = [_d("a", 1, 0), _d("n", 2, 1, durable=False), _d("c", 3, 2)]
    assert check_durable_prefix(evs) == []


def test_gap_starts_at_min_durable_not_zero() -> None:
    assert check_durable_prefix([_d("a", 1, 5), _d("b", 2, 6)]) == []


def test_gap_anchor_first_record_after_hole_in_stream_order() -> None:
    evs = [_d("late", 1, 9), _d("a", 2, 0), _d("after", 3, 4)]
    got = _by(check_durable_prefix(evs))
    # hole at ordinal 1; first marked record (stream order) with ordinal > 1 is 'late'
    assert got["durable-gap"].source.record_id == "late"


def test_gap_ordinal_strictly_greater_than_hole() -> None:
    # hole at 1; record at ordinal 1 does not exist; ordinal exactly 1 absent by construction.
    evs = [_d("a", 1, 0), _d("b", 2, 2)]
    (f,) = check_durable_prefix(evs)
    assert f.source.record_id == "b"


def test_reasoning_missing_exact() -> None:
    evs = [
        _ev("ok", 1, {"item_type": "reasoning", "has_encrypted_content": True, "ordinal": 0}),
        _ev("m1", 2, {"item_type": "reasoning", "has_encrypted_content": False, "ordinal": 4}),
        _ev("m2", 3, {"item_type": "reasoning", "has_encrypted_content": False, "ordinal": 6}),
    ]
    (f,) = check_durable_prefix(evs)
    assert f.message == MSG_FIELD.format(l=2, r="m1")
    assert f.source.record_id == "m1"
    assert dict(f.evidence or {}) == {
        "divergence": "missing-required-field",
        "field": "encrypted_content",
        "item_family": "reasoning",
        "missing_count": 2,
        "present_count": 1,
        "first_missing_ordinal": 4,
    }


def test_reasoning_first_missing_ordinal_none_for_bad_ordinal() -> None:
    for bad in (None, True, "1"):
        evs = [
            _ev("ok", 1, {"item_type": "reasoning", "has_encrypted_content": True}),
            _ev("m", 2, {"item_type": "reasoning", "has_encrypted_content": False, "ordinal": bad}),
        ]
        (f,) = check_durable_prefix(evs)
        assert dict(f.evidence or {})["first_missing_ordinal"] is None


def test_reasoning_needs_mixed_state_and_exact_flags() -> None:
    only_missing = [_ev("m", 1, {"item_type": "reasoning", "has_encrypted_content": False})]
    assert check_durable_prefix(only_missing) == []
    only_present = [_ev("p", 1, {"item_type": "reasoning", "has_encrypted_content": True})]
    assert check_durable_prefix(only_present) == []
    nonbool = [
        _ev("p", 1, {"item_type": "reasoning", "has_encrypted_content": True}),
        _ev("m", 2, {"item_type": "reasoning", "has_encrypted_content": None}),
        _ev("m2", 3, {"item_type": "reasoning", "has_encrypted_content": 0}),
    ]
    assert check_durable_prefix(nonbool) == []
    other_type = [
        _ev("p", 1, {"item_type": "reasoning", "has_encrypted_content": True}),
        _ev("m", 2, {"item_type": "message", "has_encrypted_content": False}),
    ]
    assert check_durable_prefix(other_type) == []


def test_findings_order_trailing_gap_field() -> None:
    evs = [
        _d(
            "a",
            1,
            0,
            subagent_history_start_ordinal=20,
            item_type="reasoning",
            has_encrypted_content=True,
        ),
        _d("b", 2, 3, item_type="reasoning", has_encrypted_content=False),
    ]
    out = check_durable_prefix(evs)
    assert [f.evidence["divergence"] for f in out] == [
        "trailing-non-durable",
        "durable-gap",
        "missing-required-field",
    ]


@pytest.mark.parametrize("extra", [None, "s", [], {"codex": None}, {"codex": "s"}, {"codex": []}])
def test_malformed_extra_ignored(extra: Any) -> None:
    assert check_durable_prefix([_ev("a", 1, extra=extra)]) == []


def test_source_path_argument_and_blank_id() -> None:
    evs = [_d("a", 1, 0), _d(None, 2, 3), _d("c", 3, 4)]
    (f,) = check_durable_prefix(evs, source_path="given.jsonl")
    assert f.source.path == "given.jsonl"
    assert f.source.record_id is None
    evs[1] = _d("  ", 2, 3)
    (f,) = check_durable_prefix(evs)
    assert f.source.record_id is None
    evs[1] = _d(" id ", 2, 3)
    (f,) = check_durable_prefix(evs)
    assert f.source.record_id == "id"
