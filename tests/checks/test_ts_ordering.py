"""Unit and adversarial tests for the SL008 non-monotonic timestamp check.

Per-edge monotonicity only (child vs uniquely-resolved parent); equality is
legal; epoch-sentinel/missing/ambiguous-parent/unparseable edges are skipped
silently. Content-free evidence carries ids, indices, and ms delta only.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from sesslint.adapters.canonical import load_canonical
from sesslint.canonical import SessionEvent
from sesslint.checks.ordering import check_ordering
from sesslint.checks.runner import run_all_checks
from sesslint.codes import SL008, Repairability, Severity
from sesslint.profiles.profile import apply_rule_selection, get_profile

FIXTURES_CHECKS_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "checks"


def _ev(
    event_id: str,
    parent_id: str | None,
    seq: int,
    ts: str,
    *,
    kind: str = "message",
) -> SessionEvent:
    return SessionEvent(
        id=event_id,
        parent_id=parent_id,
        seq=seq,
        ts=ts,
        actor="user",
        kind=cast(Any, kind),
        payload={"text": "x"},
    )


def test_sl008_fixture_single_regression() -> None:
    """Fixture yields exactly one SL008: evt-3 precedes evt-2 by 3000 ms."""
    events, load_findings = load_canonical(FIXTURES_CHECKS_DIR / "sl008_ts_regression.json")
    assert not load_findings

    findings = check_ordering(events)
    assert len(findings) == 1
    f = findings[0]
    assert f.code == SL008
    assert f.severity == Severity.WARNING
    assert f.repairability == Repairability.MANUAL
    assert f.source.record_id == "evt-3"

    evidence = cast(dict[str, Any], f.evidence)
    assert evidence["record_id"] == "evt-3"
    assert evidence["parent_id"] == "evt-2"
    assert evidence["ts_delta_ms"] == -3000
    assert evidence["child_index"] == 2
    assert evidence["parent_index"] == 1


def test_equal_timestamps_allowed() -> None:
    events = [
        _ev("a", None, 0, "2026-01-01T00:00:00Z"),
        _ev("b", "a", 1, "2026-01-01T00:00:00Z"),
    ]
    assert check_ordering(events) == []


def test_fractional_second_regression_detected() -> None:
    """Sub-second regression must not be lost by string or second-grain compare."""
    events = [
        _ev("a", None, 0, "2026-01-01T00:00:00.500Z"),
        _ev("b", "a", 1, "2026-01-01T00:00:00.250Z"),
    ]
    findings = check_ordering(events)
    assert len(findings) == 1
    assert cast(dict[str, Any], findings[0].evidence)["ts_delta_ms"] == -250


def test_forward_positional_reference_no_finding() -> None:
    """Parent appearing later in the file is legal; only ts order matters."""
    events = [
        _ev("child", "parent", 0, "2026-01-01T00:00:02Z"),
        _ev("parent", None, 1, "2026-01-01T00:00:01Z"),
    ]
    assert check_ordering(events) == []


def test_epoch_sentinel_edges_skipped() -> None:
    """Adapter-synthesized ts (missing in source) cannot support ordering."""
    sentinel = "1970-01-01T00:00:00Z"
    child_missing = [
        _ev("a", None, 0, "2026-01-01T00:00:00Z"),
        _ev("b", "a", 1, sentinel),
    ]
    parent_missing = [
        _ev("a", None, 0, sentinel),
        _ev("b", "a", 1, "2026-01-01T00:00:00Z"),
    ]
    assert check_ordering(child_missing) == []
    assert check_ordering(parent_missing) == []


def test_missing_and_ambiguous_parents_skipped() -> None:
    missing = [
        _ev("a", None, 0, "2026-01-01T00:00:00Z"),
        _ev("b", "ghost", 1, "2025-01-01T00:00:00Z"),
    ]
    assert check_ordering(missing) == []

    dup_parent = [
        _ev("p", None, 0, "2026-01-02T00:00:00Z"),
        _ev("p", None, 1, "2026-01-03T00:00:00Z"),
        _ev("c", "p", 2, "2026-01-01T00:00:00Z"),
    ]
    assert check_ordering(dup_parent) == []


def test_unparseable_and_naive_ts_skipped() -> None:
    unparseable = [
        _ev("a", None, 0, "not-a-timestamp"),
        _ev("b", "a", 1, "2001-01-01T00:00:00Z"),
    ]
    assert check_ordering(unparseable) == []

    naive_vs_aware = [
        _ev("a", None, 0, "2026-01-01T00:00:00Z"),
        _ev("b", "a", 1, "2001-01-01T00:00:00"),  # naive
    ]
    assert check_ordering(naive_vs_aware) == []


def test_multiple_regressions_deterministic() -> None:
    events = [
        _ev("a", None, 0, "2026-01-01T00:00:03Z"),
        _ev("b", "a", 1, "2026-01-01T00:00:02Z"),
        _ev("c", "a", 2, "2026-01-01T00:00:01Z"),
    ]
    first = check_ordering(events)
    second = check_ordering(events)
    assert len(first) == 2
    assert [f.fingerprint for f in first] == [f.fingerprint for f in second]
    assert {f.source.record_id for f in first} == {"b", "c"}


def test_sidechain_interleave_no_finding() -> None:
    """Branch B's later ts interleaved in file order is not a regression."""
    events = [
        _ev("a1", None, 0, "2026-01-01T00:00:00Z"),
        _ev("b1", "a1", 1, "2026-01-01T00:00:05Z"),
        _ev("a2", "a1", 2, "2026-01-01T00:00:01Z"),
    ]
    assert check_ordering(events) == []


def test_empty_and_single_event() -> None:
    assert check_ordering([]) == []
    assert check_ordering([_ev("a", None, 0, "2026-01-01T00:00:00Z")]) == []


def test_runner_select_ignore_gating() -> None:
    events = [
        _ev("a", None, 0, "2026-01-01T00:00:02Z"),
        _ev("b", "a", 1, "2026-01-01T00:00:01Z"),
    ]
    default = run_all_checks(events)
    assert SL008 in {f.code for f in default}

    ignored = apply_rule_selection(get_profile("neutral"), ignore=["SL008"])
    findings = run_all_checks(events, profile=ignored)
    assert SL008 not in {f.code for f in findings}

    selected = apply_rule_selection(get_profile("neutral"), select=["SL008"])
    findings = run_all_checks(events, profile=selected)
    assert {f.code for f in findings} == {SL008}


def test_evidence_is_content_free() -> None:
    events = [
        _ev("a", None, 0, "2026-01-01T00:00:02Z"),
        _ev("b", "a", 1, "2026-01-01T00:00:01Z"),
    ]
    (finding,) = check_ordering(events)
    evidence = cast(dict[str, Any], finding.evidence)
    assert set(evidence) <= {
        "record_id",
        "parent_id",
        "ts_delta_ms",
        "child_index",
        "parent_index",
        "record_ordinal",
    }
    assert "text" not in str(evidence) and "x" not in evidence.values()
