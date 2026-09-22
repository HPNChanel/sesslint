"""Tests for SL207 context-pressure projection (detector-depth T-04).

Codex-rollout-scoped check: ``event_msg/token_count`` records carry the
vendor's own per-request context footprint
(``info.last_token_usage.input_tokens``) and the declared model window
(``info.model_context_window``). The detector fires when the last
marker leaves less than 15% headroom — approaching the un-compactable
deadlock boundary. Lifetime counters (``total_token_usage`` /
``thread_token_usage``) are billing totals and are never mapped to
window occupancy. Non-codex adapters skip via coverage
``adapter-not-applicable``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sesslint.adapters.codex_rollout import load_codex_rollout
from sesslint.api import check_file
from sesslint.canonical import SessionEvent
from sesslint.checks.context_pressure import check_context_pressure
from sesslint.context import CheckContext

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"
CODEX = FIXTURES_DIR / "adapters" / "codex"
CONFORMANCE_HEALTHY = FIXTURES_DIR / "conformance" / "codex_rollout" / "healthy.jsonl"

NEAR_LIMIT = CODEX / "sl207_near_limit.jsonl"
HEALTHY = CODEX / "sl207_healthy.jsonl"
NO_WINDOW = CODEX / "sl207_no_window.jsonl"
NO_MARKER = CODEX / "sl207_no_marker.jsonl"


def _ev(
    eid: str,
    line: int,
    *,
    cp: dict[str, Any] | None = None,
    loc: str = "t.jsonl",
) -> SessionEvent:
    codex: dict[str, Any] = {}
    if cp is not None:
        codex["context_pressure"] = cp
    extra: dict[str, Any] = {"codex": codex} if codex else {}
    return SessionEvent(
        id=eid,
        parent_id=None,
        seq=0,
        ts="",
        actor="assistant",
        kind="message",
        source_line=line,
        source_adapter="codex-rollout",
        source_location=loc,
        extra_fields=extra,
    )


def _ctx() -> CheckContext:
    return CheckContext(adapter_id="codex-rollout", adapter_version="1.0.0")


def _codes(findings: list[Any]) -> list[str]:
    return [f.code for f in findings]


# --- CODE_MATRIX quadrants -------------------------------------------------


def test_clean_stream_no_finding() -> None:
    evs = [_ev("e1", 1, cp={"occupancy": 150000, "window": 258400})]
    assert check_context_pressure(evs, context=_ctx()) == []


def test_near_limit_fires_once() -> None:
    evs = [_ev("e1", 5, cp={"occupancy": 243127, "window": 258400})]
    findings = check_context_pressure(evs, context=_ctx())
    assert _codes(findings) == ["SL207"]
    ev = findings[0].evidence
    assert ev["context_tokens"] == 243127
    assert ev["window_limit"] == 258400
    assert ev["headroom"] == 15273
    assert ev["last_marker_line"] == 5
    assert ev["threshold_source"] == "declared-window:15pct-headroom"
    assert findings[0].source.line == 5


def test_marker_absent_silent() -> None:
    evs = [_ev("e1", 1), _ev("e2", 2)]
    assert check_context_pressure(evs, context=_ctx()) == []


def test_boundary_exactly_15pct_silent() -> None:
    # headroom == 15% of window exactly → not below → silent
    evs = [_ev("e1", 1, cp={"occupancy": 8500, "window": 10000})]
    assert check_context_pressure(evs, context=_ctx()) == []


def test_boundary_just_below_15pct_fires() -> None:
    # headroom 1499 of 10000 = 14.99% → fires
    evs = [_ev("e1", 1, cp={"occupancy": 8501, "window": 10000})]
    assert _codes(check_context_pressure(evs, context=_ctx())) == ["SL207"]


def test_over_window_fires() -> None:
    # occupancy past the window → negative headroom → fires
    evs = [_ev("e1", 1, cp={"occupancy": 260000, "window": 258400})]
    findings = check_context_pressure(evs, context=_ctx())
    assert _codes(findings) == ["SL207"]
    assert findings[0].evidence["headroom"] == -1600


def test_last_marker_wins() -> None:
    # earlier high-pressure marker followed by recovery → silent
    evs = [
        _ev("e1", 2, cp={"occupancy": 243127, "window": 258400}),
        _ev("e2", 3, cp={"occupancy": 50000, "window": 258400}),
    ]
    assert check_context_pressure(evs, context=_ctx()) == []
    # reverse order → fires on the last marker's line
    evs2 = [
        _ev("e1", 2, cp={"occupancy": 50000, "window": 258400}),
        _ev("e2", 7, cp={"occupancy": 243127, "window": 258400}),
    ]
    findings = check_context_pressure(evs2, context=_ctx())
    assert _codes(findings) == ["SL207"]
    assert findings[0].source.line == 7


def test_window_changes_last_marker_wins() -> None:
    # window re-declared between markers — the latest declaration applies
    evs = [
        _ev("e1", 2, cp={"occupancy": 100000, "window": 258400}),
        _ev("e2", 3, cp={"occupancy": 110000, "window": 121600}),
    ]
    findings = check_context_pressure(evs, context=_ctx())
    assert _codes(findings) == ["SL207"]
    assert findings[0].evidence["window_limit"] == 121600
    assert findings[0].evidence["headroom"] == 11600


def test_malformed_markers_ignored() -> None:
    evs = [
        _ev("e1", 1, cp={"occupancy": "243127", "window": 258400}),
        _ev("e2", 2, cp={"occupancy": 243127, "window": "big"}),
        _ev("e3", 3, cp={"occupancy": 243127}),
        _ev("e4", 4, cp={"occupancy": True, "window": 258400}),
        _ev("e5", 5, cp={"occupancy": 243127, "window": 0}),
    ]
    assert check_context_pressure(evs, context=_ctx()) == []


def test_marker_without_codex_namespace_ignored() -> None:
    ev = SessionEvent(
        id="e1",
        parent_id=None,
        seq=0,
        ts="",
        actor="assistant",
        kind="message",
        source_line=1,
        source_adapter="codex-rollout",
        source_location="t.jsonl",
        extra_fields={"context_pressure": {"occupancy": 999999, "window": 258400}},
    )
    assert check_context_pressure([ev], context=_ctx()) == []


# --- adapter extraction ----------------------------------------------------


def test_adapter_extracts_marker() -> None:
    events, _findings = load_codex_rollout(str(NEAR_LIMIT))
    marked = [
        e
        for e in events
        if isinstance(e.extra_fields.get("codex"), dict)
        and "context_pressure" in e.extra_fields["codex"]
    ]
    assert len(marked) == 2
    cp = marked[-1].extra_fields["codex"]["context_pressure"]
    assert cp == {"occupancy": 243127, "window": 258400}


def test_adapter_lifetime_counters_not_used() -> None:
    # total_token_usage is a billing total (10x occupancy in fixture);
    # the marker must carry last_token_usage.input_tokens instead.
    events, _f = load_codex_rollout(str(NEAR_LIMIT))
    last = [
        e.extra_fields["codex"]["context_pressure"]
        for e in events
        if "context_pressure" in (e.extra_fields.get("codex") or {})
    ][-1]
    assert last["occupancy"] == 243127


def test_adapter_skips_missing_window() -> None:
    events, _f = load_codex_rollout(str(NO_WINDOW))
    assert not any("context_pressure" in (e.extra_fields.get("codex") or {}) for e in events)


# --- fixture / runner / end-to-end -----------------------------------------


def test_fixture_near_limit_fires() -> None:
    report = check_file(str(NEAR_LIMIT))
    sl207 = [f for f in report.findings if f.code == "SL207"]
    assert len(sl207) == 1
    assert sl207[0].source.line == 4
    assert sl207[0].evidence["headroom"] == 15273


def test_fixture_healthy_silent() -> None:
    report = check_file(str(HEALTHY))
    assert "SL207" not in _codes(list(report.findings))
    assert "SL207" in report.coverage.performed


def test_fixture_no_window_silent() -> None:
    report = check_file(str(NO_WINDOW))
    assert "SL207" not in _codes(list(report.findings))


def test_fixture_no_marker_silent() -> None:
    report = check_file(str(NO_MARKER))
    assert "SL207" not in _codes(list(report.findings))


def test_conformance_corpus_silent() -> None:
    report = check_file(str(CONFORMANCE_HEALTHY))
    assert "SL207" not in _codes(list(report.findings))


def test_non_codex_adapter_skips() -> None:
    claude = FIXTURES_DIR / "claude_code" / "malformed-mid.jsonl"
    report = check_file(str(claude))
    assert "SL207" in {s.check for s in report.coverage.skipped}
    skip = next(s for s in report.coverage.skipped if s.check == "SL207")
    assert skip.reason == "adapter-not-applicable"


def test_select_sl207_runs() -> None:
    report = check_file(str(NEAR_LIMIT), format="codex-rollout", select=["SL207"])
    assert _codes(list(report.findings)) == ["SL207"]


def test_ignore_sl207_suppresses() -> None:
    report = check_file(str(NEAR_LIMIT), format="codex-rollout", ignore=["SL207"])
    assert "SL207" not in _codes(list(report.findings))


def test_evidence_content_free() -> None:
    report = check_file(str(NEAR_LIMIT))
    blob = json.dumps([dict(f.evidence) for f in report.findings if f.code == "SL207"])
    for leak in ("session_id", "fx207", "synthetic", "openai", "codex"):
        assert leak not in blob
