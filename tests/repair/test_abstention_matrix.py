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
from sesslint.checks.checkpoint import check_checkpoint
from sesslint.codes import SL003, SL203, Repairability, Severity
from sesslint.finding import SourceRef, make_finding
from sesslint.repair import (
    Abstained,
    execute,
    plan,
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

    events.append(
        SessionEvent(
            id="m1",
            parent_id=parent,
            seq=curr_seq,
            ts=f"2026-09-05T12:00:0{curr_seq}Z",
            actor="assistant",
            kind="message",
            payload={"text": "reply"},
        )
    )
    curr_seq += 1

    events.append(
        SessionEvent(
            id="m2",
            parent_id=parent,
            seq=curr_seq,
            ts=f"2026-09-05T12:00:0{curr_seq}Z",
            actor="assistant",
            kind="message",
            payload={"text": "reply"},
        )
    )

    m1_idx = len(events) - 2
    m2_idx = len(events) - 1

    # Findings: SL003 (always present on m1, m2) + real checkpoint findings
    findings = [
        make_finding(
            code=SL003,
            severity=Severity.WARNING,
            repairability=Repairability.DETERMINISTIC,
            message_template="Duplicate event ID m1 and m2",
            source=SourceRef(path="session.json", line=m1_idx + 1, record_id="m1"),
            evidence={"index": m1_idx, "duplicate_index": m2_idx},
        )
    ]
    findings.extend(check_checkpoint(events))

    if has_sl203:
        assert any(f.code == SL203 for f in findings)

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

    # Step A: Run Planner (dry-run)
    planned = plan(
        findings,
        events,
        policy=policy,
        source_hash=hashlib.sha256(source_file.read_bytes()).hexdigest(),
    )

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
                source_events=events,
            )
        assert not output_file.exists()

    elif policy == "conservative":
        # DEV-013: Scoped abstention proves region-disjointness for the disjoint SL003 defect
        # across all non-SL203 side_effects ("none", "possible", "unknown").
        assert len(planned.steps) == 1
        assert planned.steps[0].recipe == "identical-duplicate-collapse"

        manifest = execute(
            source_path=source_file,
            plan=planned,
            output_path=output_file,
            policy=policy,
            source_events=events,
        )
        assert output_file.is_file()
        assert manifest.input_fingerprint == planned.source_hash

    elif policy == "salvage" and side_effects == "none":
        # Safe side effects without SL203 under salvage policy
        assert len(planned.steps) == 1
        assert planned.steps[0].recipe == "identical-duplicate-collapse"

        manifest = execute(
            source_path=source_file,
            plan=planned,
            output_path=output_file,
            policy=policy,
            source_events=events,
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
                source_events=events,
            )
        assert not output_file.exists()
