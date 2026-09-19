"""Unit and adversarial tests for the SL205 compaction coverage check.

A boundary's coverage pointer must reference an existing leaf that
strictly precedes it with a contiguous ancestor chain; pointerless or
ambiguous-pointer boundaries stay silent. Evidence is structural only.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from sesslint.api import check_file
from sesslint.canonical import SessionEvent
from sesslint.checks.checkpoint import check_compaction_coverage
from sesslint.checks.runner import run_all_checks
from sesslint.codes import SL205, Repairability, Severity
from sesslint.profiles.profile import apply_rule_selection, get_profile

FIXTURES_CHECKS_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "checks"


def _ev(
    event_id: str,
    seq: int,
    *,
    parent: str | None = None,
    kind: str = "message",
    covered: str | None = None,
) -> SessionEvent:
    extra: dict[str, Any] = {}
    if covered is not None:
        extra["coverage"] = {"covered_through_id": covered}
    return SessionEvent(
        id=event_id,
        parent_id=parent,
        seq=seq,
        ts=f"2026-09-05T12:00:0{seq}Z",
        actor="system",
        kind=cast(Any, kind),
        payload={},
        extra_fields=extra,
    )


def _sl205(findings: list[Any]) -> list[Any]:
    return [f for f in findings if f.code == SL205]


def test_no_boundaries_clean() -> None:
    """Streams without compaction boundaries produce nothing (positive)."""
    assert check_compaction_coverage([_ev("a", 0), _ev("b", 1, parent="a")]) == []


def test_valid_coverage_clean() -> None:
    """Leaf exists, precedes boundary, contiguous chain — silent."""
    events = [
        _ev("m1", 0),
        _ev("m2", 1, parent="m1"),
        _ev("b1", 2, kind="compaction_boundary", covered="m2"),
    ]
    assert check_compaction_coverage(events) == []


def test_missing_leaf_fires() -> None:
    """Pointer at a nonexistent leaf → one SL205 with missing=true."""
    events = [
        _ev("m1", 0),
        _ev("b1", 1, kind="compaction_boundary", covered="ghost"),
    ]
    findings = check_compaction_coverage(events)
    assert len(findings) == 1
    f = findings[0]
    assert f.code == SL205
    assert f.severity == Severity.WARNING
    assert f.repairability == Repairability.MANUAL
    ev = cast(dict[str, Any], f.evidence)
    assert ev["missing"] is True
    assert ev["non_contiguous"] is False
    assert ev["covered_through_id"] == "ghost"
    assert ev["boundary_id"] == "b1"


def test_leaf_at_or_after_boundary_fires() -> None:
    """A leaf positioned at/after the boundary is non-contiguous."""
    events = [
        _ev("b1", 0, kind="compaction_boundary", covered="m1"),
        _ev("m1", 1),
    ]
    findings = check_compaction_coverage(events)
    assert len(findings) == 1
    ev = cast(dict[str, Any], findings[0].evidence)
    assert ev["missing"] is False
    assert ev["non_contiguous"] is True


def test_broken_ancestor_chain_fires() -> None:
    """Leaf's parent missing → covered span non-contiguous."""
    events = [
        _ev("m1", 0, parent="ghost-parent"),
        _ev("b1", 1, kind="compaction_boundary", covered="m1"),
    ]
    findings = check_compaction_coverage(events)
    assert len(findings) == 1
    assert cast(dict[str, Any], findings[0].evidence)["non_contiguous"] is True


def test_ancestor_after_boundary_fires() -> None:
    """Ancestor link crossing the boundary breaks contiguity."""
    events = [
        _ev("m1", 0, parent="post"),
        _ev("b1", 1, kind="compaction_boundary", covered="m1"),
        _ev("post", 2),
    ]
    findings = check_compaction_coverage(events)
    assert len(findings) == 1
    assert cast(dict[str, Any], findings[0].evidence)["non_contiguous"] is True


def test_pointerless_boundary_silent() -> None:
    """Boundaries without coverage pointers are unverifiable — skip."""
    events = [
        _ev("m1", 0),
        _ev("b1", 1, kind="compaction_boundary"),
    ]
    assert check_compaction_coverage(events) == []


def test_duplicate_leaf_id_silent() -> None:
    """Ambiguous (duplicated) leaf ids are SL003 territory — fail silent."""
    events = [
        _ev("m1", 0),
        _ev("m1", 1),  # duplicate id
        _ev("b1", 2, kind="compaction_boundary", covered="m1"),
    ]
    assert check_compaction_coverage(events) == []


def test_cycle_in_chain_no_finding() -> None:
    """Ancestor cycles belong to SL005 — the walk stops quietly."""
    events = [
        _ev("m1", 0, parent="m2"),
        _ev("m2", 1, parent="m1"),
        _ev("b1", 2, kind="compaction_boundary", covered="m1"),
    ]
    # chain m1->m2->m1 cycles; no missing/post-boundary link -> silent
    assert check_compaction_coverage(events) == []


def test_multiple_boundaries_each_checked() -> None:
    """Each boundary with a pointer is verified independently."""
    events = [
        _ev("m1", 0),
        _ev("b1", 1, kind="compaction_boundary", covered="m1"),  # ok
        _ev("m2", 2),
        _ev("b2", 3, kind="compaction_boundary", covered="ghost"),  # missing
    ]
    findings = check_compaction_coverage(events)
    assert len(findings) == 1
    assert cast(dict[str, Any], findings[0].evidence)["boundary_id"] == "b2"


def test_fixture_valid_clean() -> None:
    report = check_file(
        FIXTURES_CHECKS_DIR / "sl205_valid_coverage.jsonl", format="claude-code-jsonl"
    )
    assert not _sl205(list(report.findings))


def test_fixture_missing_leaf() -> None:
    report = check_file(
        FIXTURES_CHECKS_DIR / "sl205_missing_leaf.jsonl", format="claude-code-jsonl"
    )
    sl205 = _sl205(list(report.findings))
    assert len(sl205) == 1
    assert cast(dict[str, Any], sl205[0].evidence)["missing"] is True


def test_fixture_noncontig() -> None:
    report = check_file(FIXTURES_CHECKS_DIR / "sl205_noncontig.jsonl", format="claude-code-jsonl")
    sl205 = _sl205(list(report.findings))
    assert len(sl205) == 1
    assert cast(dict[str, Any], sl205[0].evidence)["non_contiguous"] is True


def test_fixture_pointerless() -> None:
    report = check_file(FIXTURES_CHECKS_DIR / "sl205_pointerless.jsonl", format="claude-code-jsonl")
    assert not _sl205(list(report.findings))


def test_gated_by_rule_selection() -> None:
    """SL205 honors profile rule selection like every check family."""
    events = [
        _ev("m1", 0),
        _ev("b1", 1, kind="compaction_boundary", covered="ghost"),
    ]
    profile = get_profile("neutral")
    selected = apply_rule_selection(profile, select=["SL205"], ignore=[])
    findings = run_all_checks(events, profile=selected)
    assert any(f.code == SL205 for f in findings)

    ignored = apply_rule_selection(profile, select=[], ignore=["SL205"])
    findings = run_all_checks(events, profile=ignored)
    assert not _sl205(list(findings))
