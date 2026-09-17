"""Parity tests for the shared detector runner (DW-T-07).

`checks.runner.run_all_checks` is the single authoritative detector pipeline:
- `repair.executor` re-exports it (transitional compatibility alias),
- `verify._run_detector_checks` delegates to it.

These tests pin the contract: one implementation, byte-identical findings,
purity (no input mutation, deterministic repeat runs).
"""

from __future__ import annotations

import copy
from pathlib import Path

from sesslint.adapters.canonical import load_canonical
from sesslint.checks.runner import run_all_checks
from sesslint.repair.executor import run_all_checks as executor_run_all_checks
from sesslint.verify import _run_detector_checks

FIXTURES_CHECKS_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "checks"


def _load_graph_healthy() -> list:
    event_list, load_findings = load_canonical(FIXTURES_CHECKS_DIR / "graph_healthy.json")
    assert not load_findings
    return list(event_list)


def test_executor_reexports_shared_runner() -> None:
    """repair.executor.run_all_checks is the same callable as the checks runner."""
    assert executor_run_all_checks is run_all_checks


def test_verify_delegates_to_shared_runner() -> None:
    """verify._run_detector_checks output is identical to a direct runner call."""
    events = _load_graph_healthy()
    via_verify = _run_detector_checks(events, source_path="s.jsonl", profile_name="neutral")
    via_runner = run_all_checks(
        events,
        profile="neutral",
        source_path="s.jsonl",
        adapter="canonical",
    )
    assert [f.to_dict() for f in via_verify] == [f.to_dict() for f in via_runner]


def test_runner_findings_byte_identical_across_entry_points() -> None:
    """Executor alias and direct import produce byte-identical finding dicts."""
    events = _load_graph_healthy()
    f1 = run_all_checks(events, source_path="x")
    f2 = executor_run_all_checks(events, source_path="x")
    assert [f.to_dict() for f in f1] == [f.to_dict() for f in f2]


def test_runner_is_pure_and_deterministic() -> None:
    """Repeat runs on deep-copied input are equal and do not mutate the input."""
    events = _load_graph_healthy()
    snapshot = copy.deepcopy([e.to_canonical_dict() for e in events])
    findings_a, cov_a = run_all_checks(events, return_coverage=True)
    findings_b, cov_b = run_all_checks(events, return_coverage=True)
    assert [f.to_dict() for f in findings_a] == [f.to_dict() for f in findings_b]
    assert cov_a.to_dict() == cov_b.to_dict()
    assert [e.to_canonical_dict() for e in events] == snapshot


def test_runner_profile_gating_parity() -> None:
    """A non-neutral profile gates rules identically via alias and runner."""
    events = _load_graph_healthy()
    f1, cov1 = run_all_checks(events, profile="claude-strict", return_coverage=True)
    f2, cov2 = executor_run_all_checks(events, profile="claude-strict", return_coverage=True)
    assert [f.to_dict() for f in f1] == [f.to_dict() for f in f2]
    assert cov1.to_dict() == cov2.to_dict()
