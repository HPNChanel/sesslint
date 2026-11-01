"""Mutation-driven behaviour tests for SL207 (CL-15).

Pin exact finding fields (severity, repairability, message, source,
evidence, adapter/profile metadata) and the input-type guards that
the broader SL207 tests leave unasserted.
"""

from __future__ import annotations

from typing import Any

import pytest

from sesslint.canonical import SessionEvent
from sesslint.checks.context_pressure import check_context_pressure
from sesslint.codes import Repairability, Severity
from sesslint.context import CheckContext

NEAR = {"occupancy": 9000, "window": 10000}


def _ev(
    eid: str | None = "e1",
    line: int | None = 4,
    *,
    cp: Any = NEAR,
    extra: Any = "auto",
    loc: str = "dir\\t.jsonl",
) -> SessionEvent:
    if extra == "auto":
        extra = {"codex": {"context_pressure": cp}}
    return SessionEvent(
        id=eid,  # type: ignore[arg-type]
        parent_id=None,
        seq=0,
        ts="",
        actor="assistant",
        kind="message",
        source_line=line,  # type: ignore[arg-type]
        source_adapter="codex-rollout",
        source_location=loc,
        extra_fields=extra,
    )


def test_finding_envelope_exact() -> None:
    ctx = CheckContext(
        adapter_id="codex-rollout",
        adapter_version="1.2.3",
        profile_id="prof",
        profile_version="9",
    )
    (f,) = check_context_pressure([_ev()], context=ctx)
    assert f.code == "SL207"
    assert f.severity is Severity.WARNING
    assert f.repairability is Repairability.MANUAL
    assert f.message == "Context headroom below 15% of the declared window on line 4 for record e1"
    assert f.source.path == "dir/t.jsonl"
    assert f.source.line == 4
    assert f.source.record_id == "e1"
    assert dict(f.evidence or {}) == {
        "context_tokens": 9000,
        "window_limit": 10000,
        "headroom": 1000,
        "threshold_source": "declared-window:15pct-headroom",
        "last_marker_line": 4,
    }


def test_source_path_argument_wins() -> None:
    (f,) = check_context_pressure([_ev()], source_path="given.jsonl")
    assert f.source.path == "given.jsonl"


def test_default_context_none_is_accepted() -> None:
    assert [f.code for f in check_context_pressure([_ev()])] == ["SL207"]


@pytest.mark.parametrize("eid", [None, "", "   "])
def test_blank_or_missing_id_has_no_record_id(eid: str | None) -> None:
    (f,) = check_context_pressure([_ev(eid=eid)])
    assert f.source.record_id is None


def test_id_is_stripped() -> None:
    (f,) = check_context_pressure([_ev(eid="  e9  ")])
    assert f.source.record_id == "e9"


@pytest.mark.parametrize("line", [None, 0, -3, True])
def test_invalid_line_omits_marker_line(line: Any) -> None:
    (f,) = check_context_pressure([_ev(line=line)])
    assert f.source.line is None
    assert "last_marker_line" not in dict(f.evidence or {})


def test_line_one_is_kept() -> None:
    (f,) = check_context_pressure([_ev(line=1)])
    assert f.source.line == 1
    assert dict(f.evidence or {})["last_marker_line"] == 1


@pytest.mark.parametrize(
    "extra",
    [
        None,
        "x",
        [],
        {},
        {"codex": None},
        {"codex": "x"},
        {"codex": {}},
        {"codex": {"context_pressure": None}},
        {"codex": {"context_pressure": [1, 2]}},
        {"codex": {"context_pressure": {}}},
    ],
)
def test_malformed_extra_fields_skipped(extra: Any) -> None:
    assert check_context_pressure([_ev(extra=extra)]) == []


@pytest.mark.parametrize(
    "cp",
    [
        {"occupancy": True, "window": 10000},
        {"occupancy": 9000, "window": True},
        {"occupancy": "9000", "window": 10000},
        {"occupancy": 9000, "window": "10000"},
        {"occupancy": 9000.0, "window": 10000},
        {"occupancy": 9000, "window": 0},
        {"occupancy": 9000, "window": -5},
        {"occupancy": 9000},
        {"window": 10000},
    ],
)
def test_invalid_marker_values_ignored(cp: dict[str, Any]) -> None:
    assert check_context_pressure([_ev(cp=cp)]) == []


def test_invalid_later_marker_does_not_replace_valid_one() -> None:
    evs = [_ev("a", 1), _ev("b", 2, cp={"occupancy": "x", "window": 10000})]
    (f,) = check_context_pressure(evs)
    assert f.source.record_id == "a"
    assert f.source.line == 1


def test_zero_occupancy_is_valid_and_silent() -> None:
    assert check_context_pressure([_ev(cp={"occupancy": 0, "window": 10})]) == []


def test_window_one_boundary() -> None:
    # headroom*20 < window*3 : window=1, occupancy=1 -> 0 < 3 fires
    assert len(check_context_pressure([_ev(cp={"occupancy": 1, "window": 1})])) == 1
    # window=1, occupancy=0 -> 20 >= 3 silent
    assert check_context_pressure([_ev(cp={"occupancy": 0, "window": 1})]) == []
