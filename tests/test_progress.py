"""Tests for the DW-T-13 progress/cancellation contract in sesslint.api.

Covers: emission order and payload shape (counters/coordinates only),
cooperative cancellation semantics with no leftover artifacts, and output
identical with and without callbacks attached.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import sesslint.api as api
from sesslint.progress import (
    CancellationToken,
    OperationCancelled,
    ProgressEvent,
)
from sesslint.report import dump_report

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
DETECT_DIR = FIXTURES / "detect"
REPAIR_SRC = FIXTURES / "repair" / "exec_basic" / "source.jsonl"


def test_progress_event_to_dict_shape() -> None:
    ev = ProgressEvent(phase="scan", completed=3, total=7, item="a.jsonl")
    assert ev.to_dict() == {"completed": 3, "item": "a.jsonl", "phase": "scan", "total": 7}
    ev2 = ProgressEvent(phase="scan", completed=1)
    assert ev2.to_dict() == {"completed": 1, "phase": "scan"}
    # JSON-serializable, deterministic key order
    assert json.loads(json.dumps(ev.to_dict(), sort_keys=True)) == ev.to_dict()


def test_progress_event_is_frozen() -> None:
    ev = ProgressEvent(phase="scan", completed=1)
    with pytest.raises(AttributeError):
        ev.completed = 2  # type: ignore[misc]


def test_check_file_emits_ordered_phases() -> None:
    events: list[ProgressEvent] = []
    api.check_file(DETECT_DIR / "canonical_sample.json", progress_cb=events.append)
    assert [e.phase for e in events] == [
        "check:detect",
        "check:load",
        "check:analyze",
        "check:report",
    ]
    assert [e.completed for e in events] == [1, 2, 3, 4]
    assert all(e.total == 4 for e in events)


def test_check_file_items_are_basenames_only() -> None:
    events: list[ProgressEvent] = []
    api.check_file(DETECT_DIR / "canonical_sample.json", progress_cb=events.append)
    for e in events:
        assert e.item is not None
        assert os.sep not in e.item
        assert "/" not in e.item


def test_check_file_detection_failure_still_completes() -> None:
    events: list[ProgressEvent] = []
    api.check_file(DETECT_DIR / "ambiguous.json", progress_cb=events.append)
    assert events[0].phase == "check:detect"
    assert events[-1].phase == "check:report"
    assert events[-1].completed == 4


def test_check_dir_emits_per_file_events() -> None:
    events: list[ProgressEvent] = []
    report = api.check_dir(DETECT_DIR, recursive=True, progress_cb=events.append)
    assert all(e.phase == "scan" for e in events)
    assert [e.completed for e in events] == list(range(1, len(events) + 1))
    assert all(e.total is None for e in events)
    for e in events:
        assert e.item is not None
        assert os.sep not in e.item
    # Emitted once per inspected file (skipped entries do not emit)
    inspected = sum(1 for f in report.files if f.verdict != "skipped" or f.skipped_reason is None)
    assert len(events) <= inspected + len(report.files)


def test_check_file_cancelled_token_raises() -> None:
    tok = CancellationToken()
    tok.cancel()
    with pytest.raises(OperationCancelled):
        api.check_file(DETECT_DIR / "canonical_sample.json", cancel_token=tok)


def test_check_dir_cancel_mid_scan() -> None:
    tok = CancellationToken()

    def cb(_ev: ProgressEvent) -> None:
        tok.cancel()

    with pytest.raises(OperationCancelled):
        api.check_dir(DETECT_DIR, recursive=True, progress_cb=cb, cancel_token=tok)


def test_repair_emits_stage_sequence(tmp_path: Path) -> None:
    events: list[ProgressEvent] = []
    plan, manifest = api.repair(REPAIR_SRC, tmp_path / "out.jsonl", progress_cb=events.append)
    assert manifest is not None
    phases = [e.phase for e in events]
    assert phases[0] == "repair:load"
    assert phases[-1] == "repair:done"
    assert "repair:plan" in phases
    assert "repair:execute" in phases
    step_events = [e for e in events if e.phase == "repair:step"]
    assert len(step_events) == len(plan.steps)
    assert all(e.total == len(plan.steps) for e in step_events)


def test_repair_cancel_leaves_no_artifacts(tmp_path: Path) -> None:
    tok = CancellationToken()

    def cb(e: ProgressEvent) -> None:
        if e.phase == "repair:step":
            tok.cancel()

    out = tmp_path / "out.jsonl"
    with pytest.raises(OperationCancelled):
        api.repair(REPAIR_SRC, out, progress_cb=cb, cancel_token=tok)
    assert not out.exists()
    assert not Path(f"{out}.manifest.json").exists()
    # No temp files left behind anywhere in the destination dir
    assert not any(p.name.startswith(".sesslint-tmp") for p in tmp_path.iterdir())


def test_repair_cancel_before_publish_leaves_nothing(tmp_path: Path) -> None:
    # Cancel after planning but before any write: nothing is created.
    tok = CancellationToken()
    seen: list[str] = []

    def cb(e: ProgressEvent) -> None:
        seen.append(e.phase)
        if e.phase == "repair:plan":
            tok.cancel()

    out = tmp_path / "out.jsonl"
    with pytest.raises(OperationCancelled):
        api.repair(REPAIR_SRC, out, progress_cb=cb, cancel_token=tok)
    assert not out.exists()
    assert list(tmp_path.iterdir()) == []


def test_outputs_identical_with_and_without_callback(tmp_path: Path) -> None:
    src = DETECT_DIR / "canonical_sample.json"
    rep_plain = api.check_file(src)
    rep_cb = api.check_file(src, progress_cb=lambda e: None)
    assert dump_report(rep_plain) == dump_report(rep_cb)

    scan_plain = api.check_dir(DETECT_DIR, recursive=True)
    scan_cb = api.check_dir(DETECT_DIR, recursive=True, progress_cb=lambda e: None)
    assert scan_plain.to_json() == scan_cb.to_json()

    plan_plain, man_plain = api.repair(REPAIR_SRC, tmp_path / "a.jsonl")
    plan_cb, man_cb = api.repair(REPAIR_SRC, tmp_path / "b.jsonl", progress_cb=lambda e: None)
    assert plan_plain.fingerprint == plan_cb.fingerprint
    assert man_plain is not None and man_cb is not None
    assert man_plain.output_fingerprint == man_cb.output_fingerprint
    assert (tmp_path / "a.jsonl").read_bytes() == (tmp_path / "b.jsonl").read_bytes()


def test_progress_events_carry_no_content() -> None:
    events: list[ProgressEvent] = []
    api.check_file(DETECT_DIR / "canonical_sample.json", progress_cb=events.append)
    for e in events:
        for value in e.to_dict().values():
            assert isinstance(value, (str, int))
