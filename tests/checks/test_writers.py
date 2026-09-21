"""Tests for SL010 interleaved writer markers (detector-depth T-02).

Contract: at most one finding per file when an adapter-normalized writer
marker *reappears* after a different marker (A→B→A proves interleaved
writers). Clean ordered upgrades A*→B*, single writers, absent markers, and
adapters emitting no ``extra_fields["writer"]`` all stay clean — the last
via coverage ``adapter-not-applicable``. Evidence is structural only:
counts, first interleave line, sorted sha256-8 marker hashes; raw marker
strings never appear.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from sesslint.adapters.claude_code import load_claude_code
from sesslint.api import check_file
from sesslint.canonical import SessionEvent
from sesslint.checks.runner import run_all_checks
from sesslint.checks.writers import check_writers
from sesslint.context import CheckContext
from sesslint.finding import Severity

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"
CLAUDE = FIXTURES_DIR / "claude_code"

INTERLEAVED = CLAUDE / "sl010_interleaved.jsonl"
UPGRADE = CLAUDE / "sl010_upgrade.jsonl"
SINGLE_WRITER = CLAUDE / "sl010_single_writer.jsonl"
NO_MARKERS = CLAUDE / "basic.jsonl"


def _writer_hash(marker: str) -> str:
    return hashlib.sha256(marker.encode("utf-8")).hexdigest()[:8]


def _ev(
    eid: str,
    line: int,
    *,
    writer: dict[str, Any] | None = None,
    loc: str = "t.jsonl",
) -> SessionEvent:
    extra: dict[str, Any] = {"writer": writer} if writer is not None else {}
    return SessionEvent(
        id=eid,
        parent_id=None,
        seq=0,
        ts="",
        actor="user",
        kind="user_message",
        source_line=line,
        source_adapter="claude-code-jsonl",
        source_location=loc,
        extra_fields=extra,
    )


def _ctx(*, markers: bool = True) -> CheckContext:
    return CheckContext(
        adapter_id="claude-code-jsonl",
        adapter_version="1.0.0",
        profile_id="neutral",
        profile_version="1.0.0",
        source_metadata={"writer_markers": True} if markers else {},
    )


# --- Positive quadrant: healthy inputs stay clean -----------------------


def test_upgrade_transition_stays_clean() -> None:
    events, _ = load_claude_code(UPGRADE)
    findings = run_all_checks(events, profile="neutral", source_path=str(UPGRADE))
    assert [f.code for f in findings] == []


def test_single_writer_stays_clean() -> None:
    events, _ = load_claude_code(SINGLE_WRITER)
    findings = run_all_checks(events, profile="neutral", source_path=str(SINGLE_WRITER))
    assert [f.code for f in findings] == []


def test_missing_markers_stay_clean() -> None:
    events, _ = load_claude_code(NO_MARKERS)
    findings = run_all_checks(events, profile="neutral", source_path=str(NO_MARKERS))
    assert [f.code for f in findings] == []


# --- Negative quadrant: interleave fires exactly once --------------------


def test_interleaved_fires_once_with_structural_evidence() -> None:
    events, _ = load_claude_code(INTERLEAVED)
    findings = run_all_checks(events, profile="neutral", source_path=str(INTERLEAVED))
    sl010 = [f for f in findings if f.code == "SL010"]
    assert len(sl010) == 1
    f = sl010[0]
    assert f.severity == Severity.WARNING
    assert f.source.line == 4
    ev = f.evidence
    assert set(ev.keys()) == {
        "distinct_writer_count",
        "transition_count",
        "first_interleave_line",
        "writer_hashes",
    }
    assert ev["distinct_writer_count"] == 2
    assert ev["transition_count"] == 2
    assert ev["first_interleave_line"] == 4
    assert ev["writer_hashes"] == tuple(sorted([_writer_hash("v:2.0.9"), _writer_hash("v:2.1.0")]))


def test_multi_interleave_still_one_finding() -> None:
    events = [
        _ev("a1", 1, writer={"version": "1.0"}),
        _ev("b1", 2, writer={"version": "2.0"}),
        _ev("a2", 3, writer={"version": "1.0"}),
        _ev("b2", 4, writer={"version": "2.0"}),
        _ev("a3", 5, writer={"version": "1.0"}),
    ]
    findings = check_writers(events, source_path="t.jsonl", context=_ctx())
    assert len(findings) == 1
    assert findings[0].source.line == 3
    assert findings[0].evidence["transition_count"] == 4


def test_instance_marker_takes_precedence_over_version() -> None:
    events = [
        _ev("a", 1, writer={"version": "1.0", "instance": "proc-a"}),
        _ev("b", 2, writer={"version": "1.0", "instance": "proc-b"}),
        _ev("a2", 3, writer={"version": "1.0", "instance": "proc-a"}),
    ]
    findings = check_writers(events, source_path="t.jsonl", context=_ctx())
    assert len(findings) == 1
    assert findings[0].evidence["writer_hashes"] == tuple(
        sorted([_writer_hash("i:proc-a"), _writer_hash("i:proc-b")])
    )


def test_same_version_same_instance_pair_no_fire() -> None:
    # Same instance reappearing is impossible to express here; a single
    # marker repeated interleaved with None-marked records must not fire.
    events = [
        _ev("a", 1, writer={"version": "1.0"}),
        _ev("x", 2),  # no marker — gap, not a different writer
        _ev("a2", 3, writer={"version": "1.0"}),
    ]
    assert check_writers(events, source_path="t.jsonl", context=_ctx()) == []


# --- Boundary quadrant ---------------------------------------------------


def test_minimal_three_record_interleave_fires() -> None:
    events = [
        _ev("a", 1, writer={"version": "1.0"}),
        _ev("b", 2, writer={"version": "2.0"}),
        _ev("a2", 3, writer={"version": "1.0"}),
    ]
    findings = check_writers(events, source_path="t.jsonl", context=_ctx())
    assert len(findings) == 1
    assert findings[0].evidence["transition_count"] == 2


def test_two_record_alternation_does_not_fire() -> None:
    events = [
        _ev("a", 1, writer={"version": "1.0"}),
        _ev("b", 2, writer={"version": "2.0"}),
    ]
    assert check_writers(events, source_path="t.jsonl", context=_ctx()) == []


def test_multi_event_record_deduped_per_line() -> None:
    # Two events sharing one source line + marker count once — a single
    # record cannot fake a transition.
    events = [
        _ev("a", 1, writer={"version": "1.0"}),
        _ev("a-dup", 1, writer={"version": "1.0"}),
        _ev("b", 2, writer={"version": "2.0"}),
        _ev("a2", 3, writer={"version": "1.0"}),
    ]
    findings = check_writers(events, source_path="t.jsonl", context=_ctx())
    assert len(findings) == 1
    assert findings[0].evidence["distinct_writer_count"] == 2


# --- Malformed quadrant: garbage marker shapes ignored -------------------


def test_malformed_writer_shapes_ignored() -> None:
    events = [
        _ev("a", 1, writer={"version": "1.0"}),
        _ev("bad1", 2, writer={"version": 7}),  # non-str version
        _ev("bad2", 3, writer="not-a-mapping"),  # type: ignore[dict-item]
        _ev("bad3", 4, writer={"version": "  "}),  # blank marker
        _ev("a2", 5, writer={"version": "1.0"}),
    ]
    # Only A and A observed — no interleave provable.
    assert check_writers(events, source_path="t.jsonl", context=_ctx()) == []


# --- Coverage & selection semantics --------------------------------------


def test_non_claude_events_skip_adapter_not_applicable() -> None:
    events = [_ev("a", 1), _ev("b", 2), _ev("c", 3)]
    findings, cov = run_all_checks(
        events, profile="neutral", source_path="t.jsonl", return_coverage=True
    )
    assert [f.code for f in findings if f.code == "SL010"] == []
    assert "SL010" not in cov.performed
    assert "writers" not in cov.performed
    skips = {(s.check, s.reason) for s in cov.skipped}
    assert ("SL010", "adapter-not-applicable") in skips
    assert ("writers", "adapter-not-applicable") in skips


def test_select_sl010_runs_and_fires() -> None:
    report = check_file(INTERLEAVED, format="claude-code-jsonl", select=["SL010"])
    codes = [f.code for f in report.findings]
    assert codes == ["SL010"]


def test_ignore_sl010_suppresses() -> None:
    report = check_file(INTERLEAVED, format="claude-code-jsonl", ignore=["SL010"])
    assert [f.code for f in report.findings] == []


def test_determinism_replay_identical() -> None:
    r1 = check_file(INTERLEAVED, format="claude-code-jsonl")
    r2 = check_file(INTERLEAVED, format="claude-code-jsonl")
    f1 = [f for f in r1.findings if f.code == "SL010"][0]
    f2 = [f for f in r2.findings if f.code == "SL010"][0]
    assert f1 == f2
    assert f1.fingerprint == f2.fingerprint


def test_content_free_no_marker_strings(tmp_path: Path) -> None:
    # Raw version strings must not leak into the JSON report.
    report = check_file(INTERLEAVED, format="claude-code-jsonl")
    blob = json.dumps(report.to_dict(), sort_keys=True)
    assert "2.0.9" not in blob
    assert "2.1.0" not in blob
    for f in report.findings:
        if f.code == "SL010":
            for h in f.evidence["writer_hashes"]:
                assert len(h) == 8
                int(h, 16)  # hex chars only


# --- Adapter extraction --------------------------------------------------


def test_adapter_populates_writer_extra(tmp_path: Path) -> None:
    p = tmp_path / "w.jsonl"
    rows = [
        {
            "type": "user",
            "uuid": "u1",
            "sessionId": "s",
            "version": "2.0.9",
            "message": {"role": "user", "content": "x"},
        },
        {
            "type": "user",
            "uuid": "u2",
            "parentUuid": "u1",
            "sessionId": "s",
            "agentVersion": "2.0.10",
            "message": {"role": "user", "content": "x"},
        },
        {
            "type": "user",
            "uuid": "u3",
            "parentUuid": "u2",
            "sessionId": "s",
            "schemaVersion": "3",
            "message": {"role": "user", "content": "x"},
        },
    ]
    with open(p, "w", newline="\n") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    events, _ = load_claude_code(p)
    writers = [e.extra_fields.get("writer") for e in events]
    assert writers[0] == {"version": "2.0.9", "instance": None}
    assert writers[1] == {"version": "2.0.10", "instance": None}
    # schemaVersion is a format marker, never a writer identity.
    assert writers[2] is None


def test_adapter_sets_writer_markers_source_flag() -> None:
    events, _ = load_claude_code(INTERLEAVED)
    assert getattr(events, "source", {}).get("writer_markers") is True


@pytest.mark.parametrize("name", ["sl010_upgrade", "sl010_single_writer"])
def test_clean_fixtures_emit_no_sl010_via_api(name: str) -> None:
    report = check_file(CLAUDE / f"{name}.jsonl", format="claude-code-jsonl")
    assert [f.code for f in report.findings] == []
