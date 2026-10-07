"""B19: a repair plan and its execution describe one read of the source.

A writer that completes a torn tail between the planning parse and the hash,
or between planning and apply, must never get that now-complete record dropped
as "torn": planning binds the bytes it parsed, and write-back discards only
lines the bytes being projected still flag.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sesslint import api
from sesslint.adapters.detect import FORMAT_CLAUDE_CODE
from sesslint.checks.runner import run_all_checks
from sesslint.codes import SL002
from sesslint.errors import SesslintError
from sesslint.repair import executor
from sesslint.repair.errors import PlanSourceMismatch
from sesslint.repair.planner import plan as planner_plan

ROOT = Path(__file__).resolve().parents[2]
BASE = (ROOT / "fixtures" / "claude_code" / "basic.jsonl").read_bytes()


def _completed_record() -> bytes:
    last = json.loads(BASE.splitlines()[-1])
    record = dict(last, id="synthetic-late", parentId=last["id"])
    return json.dumps(record, sort_keys=True).encode("utf-8") + b"\n"


COMPLETE = _completed_record()
TORN = COMPLETE[: len(COMPLETE) // 2]


def test_tail_completed_during_planning_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The plan binds the torn bytes it parsed, so the completed file no longer matches."""
    src = tmp_path / "session.jsonl"
    src.write_bytes(BASE + TORN)
    real_load = executor.load_source_for_format
    completed = False

    def racing_load(path: Any, fmt: str | None, *, data: bytes | None = None) -> Any:
        nonlocal completed
        result = real_load(path, fmt, data=data)
        if not completed:
            completed = True
            src.write_bytes(BASE + COMPLETE)  # the writer finishes its append
        return result

    monkeypatch.setattr(executor, "load_source_for_format", racing_load)
    with pytest.raises(PlanSourceMismatch):
        api.plan_repair(src, format=FORMAT_CLAUDE_CODE)
    assert src.read_bytes() == BASE + COMPLETE


def test_write_back_keeps_line_the_current_bytes_no_longer_flag(tmp_path: Path) -> None:
    """Stale caller findings cannot make write-back drop a now-complete record."""
    src = tmp_path / "session.jsonl"
    src.write_bytes(BASE + TORN)
    _hdr, events, stream_findings = executor.load_source_for_format(src, FORMAT_CLAUDE_CODE)
    assert any(f.code == SL002 for f in stream_findings)
    findings = list(stream_findings) + list(
        run_all_checks(events, profile="neutral", source_path=src.name, adapter=FORMAT_CLAUDE_CODE)
    )
    # No source_hash: the plan binds the event set, which the late append leaves intact.
    plan = planner_plan(findings=findings, events=events, input_format=FORMAT_CLAUDE_CODE)
    assert plan.steps

    src.write_bytes(BASE + COMPLETE)
    out = tmp_path / "out.jsonl"
    try:
        executor.execute(
            source_path=src,
            plan=plan,
            output_path=out,
            format=FORMAT_CLAUDE_CODE,
            source_events=events,
            source_findings=findings,
        )
    except SesslintError:
        assert not out.exists()
    else:
        assert out.read_bytes().endswith(COMPLETE)
    assert src.read_bytes() == BASE + COMPLETE
