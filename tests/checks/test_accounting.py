"""Unit and adversarial tests for the SL204 token-usage accounting check.

Cumulative markers reconcile against baseline + window contributions with
exact integer equality; compaction boundaries start a fresh epoch whose
first marker only sets the baseline. Evidence is integers only.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from sesslint.api import check_file
from sesslint.canonical import SessionEvent
from sesslint.checks.accounting import check_accounting
from sesslint.codes import SL204, Repairability, Severity
from sesslint.profiles.profile import apply_rule_selection, get_profile

FIXTURES_CHECKS_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "checks"


def _ev(
    event_id: str,
    seq: int,
    *,
    kind: str = "message",
    usage: dict[str, Any] | None = None,
) -> SessionEvent:
    return SessionEvent(
        id=event_id,
        parent_id=None,
        seq=seq,
        ts=f"2026-09-05T12:00:0{seq}Z",
        actor="system",
        kind=cast(Any, kind),
        payload={},
        extra_fields={"usage": usage} if usage else {},
    )


def _contrib(c: dict[str, int]) -> dict[str, Any]:
    return {"contribution": c}


def _marker(c: dict[str, int], t: dict[str, int]) -> dict[str, Any]:
    return {"contribution": c, "cumulative": t}


def test_no_usage_events_clean() -> None:
    """Events without usage slots produce no findings (positive quadrant)."""
    findings = check_accounting([_ev("a", 0), _ev("b", 1)])
    assert findings == []


def test_consistent_markers_clean() -> None:
    """Markers matching baseline + window sums stay silent."""
    events = [
        _ev("m1", 0, usage=_marker({"in": 10, "out": 5}, {"in": 10, "out": 5})),
        _ev("e1", 1, usage=_contrib({"in": 3, "out": 2})),
        _ev("m2", 2, usage=_marker({"in": 4, "out": 1}, {"in": 17, "out": 8})),
    ]
    assert check_accounting(events) == []


def test_divergent_marker_fires() -> None:
    """A doctored cumulative counter fires exactly one SL204 warning."""
    events = [
        _ev("m1", 0, usage=_marker({"in": 10, "out": 5}, {"in": 10, "out": 5})),
        _ev("m2", 1, usage=_marker({"in": 3, "out": 2}, {"in": 99, "out": 7})),
    ]
    findings = check_accounting(events)
    assert len(findings) == 1
    f = findings[0]
    assert f.code == SL204
    assert f.severity == Severity.WARNING
    assert f.repairability == Repairability.MANUAL
    assert f.source.record_id == "m2"
    ev = cast(dict[str, Any], f.evidence)
    assert ev["expected_total"] == 20  # {13, 7}
    assert ev["observed_total"] == 106  # {99, 7}
    assert ev["mismatched_key_count"] == 1
    assert ev["window_start_index"] == 1
    assert ev["window_end_index"] == 1


def test_contributions_without_marker_no_finding() -> None:
    """Bare contributions with no cumulative marker cannot be reconciled."""
    events = [
        _ev("e1", 0, usage=_contrib({"in": 5})),
        _ev("e2", 1, usage=_contrib({"in": 7})),
    ]
    assert check_accounting(events) == []


def test_marker_own_contribution_counts() -> None:
    """The marker record's own contribution is part of its window."""
    events = [
        _ev("m1", 0, usage=_marker({"in": 10}, {"in": 10})),
        # marker claims 13 = 10 + own contribution 3 — consistent
        _ev("m2", 1, usage=_marker({"in": 3}, {"in": 13})),
    ]
    assert check_accounting(events) == []


def test_compaction_resets_epoch() -> None:
    """First post-boundary marker sets baseline unchecked; next is delta-checked."""
    events = [
        _ev("m1", 0, usage=_marker({"in": 10}, {"in": 10})),
        _ev("b1", 1, kind="compaction_boundary"),
        # cumulative continues across compaction — unchecked baseline
        _ev("m2", 2, usage=_marker({"in": 4}, {"in": 14})),
        # delta check: 14 + 2 = 16 — consistent
        _ev("m3", 3, usage=_marker({"in": 2}, {"in": 16})),
    ]
    assert check_accounting(events) == []


def test_post_compaction_delta_divergence_fires() -> None:
    """A bad delta inside the post-compaction epoch still fires."""
    events = [
        _ev("b1", 0, kind="compaction_boundary"),
        _ev("m1", 1, usage=_marker({"in": 4}, {"in": 14})),  # baseline
        _ev("m2", 2, usage=_marker({"in": 2}, {"in": 50})),  # expected 16
    ]
    findings = check_accounting(events)
    assert len(findings) == 1
    assert cast(dict[str, Any], findings[0].evidence)["expected_total"] == 16


def test_zero_baseline_first_marker_checked() -> None:
    """In the stream-start epoch the first marker is checked against window sum."""
    events = [
        _ev("e1", 0, usage=_contrib({"in": 10})),
        _ev("m1", 1, usage=_marker({"in": 2}, {"in": 12})),
    ]
    assert check_accounting(events) == []
    # ...but a marker short of the window sum fires
    events[1] = _ev("m1", 1, usage=_marker({"in": 2}, {"in": 9}))
    findings = check_accounting(events)
    assert len(findings) == 1
    assert cast(dict[str, Any], findings[0].evidence)["expected_total"] == 12


def test_non_int_counters_ignored() -> None:
    """Float/str/bool/negative counters are skipped, not flagged."""
    events = [
        _ev("m1", 0, usage={"contribution": {"in": 10}, "cumulative": {"in": 10.5, "x": True}}),
        _ev("m2", 1, usage=_marker({"in": 3}, {"in": 13})),
    ]
    assert check_accounting(events) == []


def test_two_markers_both_diverge() -> None:
    """Each divergent marker gets its own finding."""
    events = [
        _ev("m1", 0, usage=_marker({"in": 5}, {"in": 50})),
        _ev("m2", 1, usage=_marker({"in": 1}, {"in": 999})),
    ]
    findings = check_accounting(events)
    assert len(findings) == 2
    assert {f.source.record_id for f in findings} == {"m1", "m2"}


def test_fixture_consistent_clean() -> None:
    """Consistent codex-shape fixture yields no SL204."""
    report = check_file(
        FIXTURES_CHECKS_DIR / "sl204_usage_consistent.jsonl", format="codex-rollout"
    )
    assert not [f for f in report.findings if f.code == SL204]


def test_fixture_divergent_fires() -> None:
    """Doctored-total fixture yields exactly one SL204 on the marker."""
    report = check_file(FIXTURES_CHECKS_DIR / "sl204_usage_divergent.jsonl", format="codex-rollout")
    sl204 = [f for f in report.findings if f.code == SL204]
    assert len(sl204) == 1
    assert sl204[0].severity == Severity.WARNING
    ev = cast(dict[str, Any], sl204[0].evidence)
    assert ev["expected_total"] == 20
    assert ev["observed_total"] == 106


def test_fixture_postcompact_clean() -> None:
    """Post-compaction fixture: continued cumulative baseline, clean delta."""
    report = check_file(
        FIXTURES_CHECKS_DIR / "sl204_usage_postcompact.jsonl", format="codex-rollout"
    )
    assert not [f for f in report.findings if f.code == SL204]


def test_gated_by_rule_selection() -> None:
    """SL204 honors profile rule selection like every check family."""
    events = [
        _ev("m1", 0, usage=_marker({"in": 5}, {"in": 50})),
    ]
    from sesslint.checks.runner import run_all_checks

    profile = get_profile("neutral")
    selected = apply_rule_selection(profile, select=["SL204"], ignore=[])
    findings = run_all_checks(events, profile=selected)
    assert any(f.code == SL204 for f in findings)

    ignored = apply_rule_selection(profile, select=[], ignore=["SL204"])
    findings = run_all_checks(events, profile=ignored)
    assert not [f for f in findings if f.code == SL204]
