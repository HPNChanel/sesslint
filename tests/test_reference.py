"""Tests for the A4 reference loader (T-14, AC-027)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from sesslint.adapters.canonical import load_canonical
from sesslint.codes import SL001, SL003, SL101, Repairability, Severity
from sesslint.finding import Finding, SourceRef, make_finding
from sesslint.reference import (
    MAX_REFERENCE_EVENTS,
    reference_equivalent,
    reference_equivalent_if_clean,
)
from sesslint.report import compute_assurance

HEALTHY = (
    Path(__file__).resolve().parent.parent
    / "fixtures"
    / "conformance"
    / "canonical"
    / "healthy.json"
)


def _finding(code: str, severity: Severity) -> Finding:
    return make_finding(
        code=code,
        severity=severity,
        repairability=Repairability.MANUAL,
        message_template="Matrix probe [detail: X]",
        source=SourceRef(path="probe.json"),
    )


def test_clean_healthy_fixture_reaches_a4() -> None:
    events, _ = load_canonical(HEALTHY)
    assert len(events) > 0
    assert reference_equivalent_if_clean(events, []) is True
    level, _ = compute_assurance(
        events, [], reference_equivalent=reference_equivalent_if_clean(events, [])
    )
    assert level == "A4"


def test_loader_skipped_on_warning_or_error() -> None:
    events, _ = load_canonical(HEALTHY)
    with patch("sesslint.reference.dump_canonical", side_effect=AssertionError("loader ran")):
        assert reference_equivalent_if_clean(events, [_finding(SL003, Severity.WARNING)]) is False
        assert reference_equivalent_if_clean(events, [_finding(SL001, Severity.ERROR)]) is False


def test_flag_cannot_launder_errors_or_warnings() -> None:
    events, _ = load_canonical(HEALTHY)
    level, _ = compute_assurance(
        events, [_finding(SL101, Severity.ERROR)], reference_equivalent=True
    )
    assert level == "A1"
    level, _ = compute_assurance(
        events, [_finding(SL003, Severity.WARNING)], reference_equivalent=True
    )
    assert level == "A2"


def test_divergent_reconstruction_caps_at_a3() -> None:
    events, _ = load_canonical(HEALTHY)
    with patch("sesslint.reference.load_canonical", return_value=(events[:-1], [])):
        assert reference_equivalent(events) is False
    level, _ = compute_assurance(events, [], reference_equivalent=False)
    assert level == "A3"


def test_empty_and_foreign_inputs_refuse() -> None:
    assert reference_equivalent(None) is False
    assert reference_equivalent([]) is False
    assert reference_equivalent([{"not": "an event"}]) is False
    assert reference_equivalent_if_clean([], []) is False


def test_scale_bound_skips_loader() -> None:
    big = [{"not": "an event"}] * (MAX_REFERENCE_EVENTS + 1)
    with patch("sesslint.reference.dump_canonical", side_effect=AssertionError("loader ran")):
        assert reference_equivalent(big) is False
        assert reference_equivalent_if_clean(big, []) is False


def test_reconstruction_with_findings_refuses_a4() -> None:
    events, _ = load_canonical(HEALTHY)
    reparse_with_finding = (events, [_finding(SL001, Severity.ERROR)])
    with patch("sesslint.reference.load_canonical", return_value=reparse_with_finding):
        assert reference_equivalent(events) is False
        assert reference_equivalent_if_clean(events, []) is False


def test_reordered_reconstruction_refuses_a4() -> None:
    events, _ = load_canonical(HEALTHY)
    assert len(events) >= 2
    # Reverse events: multiset of hashes will match, but sequential order differs
    reversed_events = list(reversed(events))
    with patch("sesslint.reference.load_canonical", return_value=(reversed_events, [])):
        assert reference_equivalent(events) is False
        assert reference_equivalent_if_clean(events, []) is False
