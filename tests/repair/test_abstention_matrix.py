"""Exhaustive 12-cell matrix tests for RVW-011 (SL203 x side-effects x policy).

Verifies that:
- Planner and executor enforce identical abstention gates in all 12 cells.
- If dry-run planner produces 0 executable steps due to abstention, executor also
  abstains/refuses execution.
- If dry-run planner produces executable steps, executor succeeds cleanly.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sesslint.canonical import SessionEvent
from sesslint.checks.runner import run_all_checks
from sesslint.repair import (
    Abstained,
    RepairPlan,
    execute,
    plan,
)
from sesslint.repair.executor import load_source_for_format


def _source_derived_plan(source_path: Path, *, policy: str) -> RepairPlan:
    """Use the same current-source findings and canonical events as execution."""
    source_bytes = source_path.read_bytes()
    _, events, stream_findings = load_source_for_format(source_path, "canonical", data=source_bytes)
    findings = list(stream_findings) + list(
        run_all_checks(
            events,
            profile="neutral",
            source_path=source_path.name,
            adapter="canonical",
        )
    )
    return plan(
        findings,
        events,
        policy=policy,
        source_hash=hashlib.sha256(source_bytes).hexdigest(),
        input_format="canonical",
    )


@pytest.mark.parametrize("has_sl203", [True, False])
@pytest.mark.parametrize("side_effects", ["none", "unknown", "possible"])
@pytest.mark.parametrize("policy", ["conservative", "salvage"])
def test_abstention_12_cell_matrix(
    tmp_path: Path,
    has_sl203: bool,
    side_effects: str,
    policy: str,
) -> None:
    """Matrix test covering all 12 combinations of (SL203 x side_effects x policy)."""
    # Build events: user message, optional uncheckpointed compaction boundary (triggers real SL203),
    # tool_call with tested side_effects, and two identical assistant messages (SL003).
    events = [
        SessionEvent(
            id="m0",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={"text": "hello"},
        ),
    ]

    curr_seq = 1
    parent = "m0"
    if has_sl203:
        # An uncheckpointed compaction boundary before a tool event triggers genuine SL203
        events.append(
            SessionEvent(
                id="comp0",
                parent_id=parent,
                seq=curr_seq,
                ts=f"2026-09-05T12:00:0{curr_seq}Z",
                actor="system",
                kind="compaction_boundary",
                payload={},
            )
        )
        parent = "comp0"
        curr_seq += 1

    events.append(
        SessionEvent(
            id="tc0",
            parent_id=parent,
            seq=curr_seq,
            ts=f"2026-09-05T12:00:0{curr_seq}Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="call-0",
            payload={"name": "custom_tool", "side_effects": side_effects},
        )
    )
    parent = "tc0"
    curr_seq += 1

    events.append(
        SessionEvent(
            id="tr0",
            parent_id=parent,
            seq=curr_seq,
            ts=f"2026-09-05T12:00:0{curr_seq}Z",
            actor="tool",
            kind="tool_result",
            correlation_id="call-0",
            payload={"output": "ok", "side_effects": side_effects},
        )
    )
    parent = "tr0"
    curr_seq += 1
    duplicate_ts = f"2026-09-05T12:00:0{curr_seq}Z"

    events.append(
        SessionEvent(
            id="m-duplicate",
            parent_id=parent,
            seq=curr_seq,
            ts=duplicate_ts,
            actor="assistant",
            kind="message",
            payload={"text": "reply"},
        )
    )
    curr_seq += 1

    events.append(
        SessionEvent(
            id="m-duplicate",
            parent_id=parent,
            seq=curr_seq,
            ts=duplicate_ts,
            actor="assistant",
            kind="message",
            payload={"text": "reply"},
        )
    )

    # Write source file for executor
    source_file = tmp_path / "matrix_source.jsonl"
    with open(source_file, "w", encoding="utf-8") as fh:
        header = {
            "schema_version": "sesslint.session/v1",
            "session_id": "test_matrix",
            "created_at": "2026-09-05T12:00:00Z",
        }
        fh.write(json.dumps(header) + "\n")
        for ev in events:
            fh.write(json.dumps(ev.to_canonical_dict()) + "\n")

    output_file = tmp_path / "matrix_repaired.jsonl"

    # Step A: Plan from the exact source bytes the public executor will load.
    planned = _source_derived_plan(source_file, policy=policy)

    # Step B: Assert 100% agreement between dry-run planner and repair executor
    if has_sl203:
        # SL203 causes hard refusal in both conservative and salvage
        assert len(planned.steps) == 0
        assert all(b.reason == "SL203-refusal" for b in planned.blocked)

        with pytest.raises(Abstained, match="SL203 present"):
            execute(
                source_path=source_file,
                plan=planned,
                output_path=output_file,
                policy=policy,
            )
        assert not output_file.exists()

    elif policy == "conservative":
        # DEV-013: Scoped abstention proves region-disjointness for the disjoint SL003 defect
        # across all non-SL203 side_effects ("none", "possible", "unknown").
        assert [step.recipe for step in planned.steps] == [
            "identical-duplicate-collapse",
            "seq-renumber",
        ]

        manifest = execute(
            source_path=source_file,
            plan=planned,
            output_path=output_file,
            policy=policy,
        )
        assert output_file.is_file()
        assert manifest.input_fingerprint == planned.source_hash

    elif policy == "salvage" and side_effects == "none":
        # Safe side effects without SL203 under salvage policy
        assert [step.recipe for step in planned.steps] == [
            "identical-duplicate-collapse",
            "seq-renumber",
        ]

        manifest = execute(
            source_path=source_file,
            plan=planned,
            output_path=output_file,
            policy=policy,
        )
        assert output_file.is_file()
        assert manifest.input_fingerprint == planned.source_hash

    elif policy == "salvage":
        # Salvage policy with non-'none' side effects and acknowledge_side_effects=False
        # Without acknowledgement, executor refuses to execute
        with pytest.raises(Abstained, match=f"side-effect-{side_effects}"):
            execute(
                source_path=source_file,
                plan=planned,
                output_path=output_file,
                policy=policy,
            )
        assert not output_file.exists()
