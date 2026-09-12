"""Unit and integration tests for checkpoint detector (SL201, SL202, SL203).

Covers TASK-017 requirements:
- SL201: Checkpoint gap produces error/manual finding.
- SL202: Checkpoint divergence produces error/manual finding with truncated hashes.
- SL203: Unsafe continuation across loss produces single capped error/manual finding.
- Multi-trigger SL203 reports all causes sorted.
- Missing/empty state_hash treated as SL201 gap without crash.
- Idempotent re-emit of same seq+hash does not trigger SL202.
- Deterministic fingerprints, sorting, capping, immutability, vendor-free.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any, cast

from sesslint.adapters.canonical import load_canonical
from sesslint.canonical import SessionEvent
from sesslint.checks.checkpoint import (
    check_checkpoint,
    check_checkpoint_divergence,
    check_checkpoint_gap,
    check_sl201,
    check_sl202,
    check_sl203,
    check_unsafe_continuation,
)
from sesslint.codes import (
    SL201,
    SL202,
    SL203,
    Repairability,
    Severity,
)
from sesslint.finding import Finding

FIXTURES_CHECKS_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "checks"
CHECKPOINT_SRC_FILE = (
    Path(__file__).resolve().parent.parent.parent / "src" / "sesslint" / "checks" / "checkpoint.py"
)


def _evidence(f: Finding) -> dict[str, Any]:
    """Helper to extract and cast non-null evidence mapping for type checkers."""
    assert f.evidence is not None
    return cast(dict[str, Any], f.evidence)


def test_checkpoint_clean() -> None:
    """Clean checkpointed session produces 0 findings."""
    fixture_path = FIXTURES_CHECKS_DIR / "checkpoint_clean.json"
    events, load_findings = load_canonical(fixture_path)
    assert not load_findings

    findings = check_checkpoint(events)
    assert not findings


def test_sl201_gap_fixture() -> None:
    """SL201 gap fixture: seq jump from 1 to 5 produces SL201 error/manual."""
    fixture_path = FIXTURES_CHECKS_DIR / "sl201_gap.json"
    events, load_findings = load_canonical(fixture_path)
    assert not load_findings

    findings = check_checkpoint_gap(events)
    assert len(findings) == 1

    f = findings[0]
    assert f.code == SL201
    assert f.severity == Severity.ERROR
    assert f.repairability == Repairability.MANUAL
    assert f.source.record_id == "chk-2"

    ev = _evidence(f)
    assert ev["at_index"] == 2
    assert ev["expected_seq"] == 2
    assert ev["found_seq"] == 5


def test_sl202_divergence_fixture() -> None:
    """SL202 divergence fixture: same seq with different state_hash produces SL202."""
    fixture_path = FIXTURES_CHECKS_DIR / "sl202_divergence.json"
    events, load_findings = load_canonical(fixture_path)
    assert not load_findings

    findings = check_checkpoint_divergence(events)
    assert len(findings) == 1

    f = findings[0]
    assert f.code == SL202
    assert f.severity == Severity.ERROR
    assert f.repairability == Repairability.MANUAL
    assert f.source.record_id == "chk-branch-b"

    ev = _evidence(f)
    assert ev["seq"] == 1
    assert ev["hash_a"] == "hash_state_branc"  # Truncated to 16 chars
    assert ev["hash_b"] == "hash_state_branc"
    assert len(ev["hash_a"]) == 16
    assert len(ev["hash_b"]) == 16


def test_sl203_continuation_fixture() -> None:
    """SL203 continuation fixture: tool event after SL201 gap fires SL203."""
    fixture_path = FIXTURES_CHECKS_DIR / "sl203_continuation.json"
    events, load_findings = load_canonical(fixture_path)
    assert not load_findings

    findings = check_checkpoint(events)
    codes = [f.code for f in findings]
    assert SL201 in codes
    assert SL203 in codes

    f203 = next(f for f in findings if f.code == SL203)
    assert f203.severity == Severity.ERROR
    assert f203.repairability == Repairability.MANUAL
    assert f203.source.record_id == "tool-call-1"

    ev = _evidence(f203)
    assert ev["first_unsafe_index"] == 3
    assert ev["caused_by"] == ["SL201"]


def test_sl203_single_finding_cap() -> None:
    """Multiple tool events after a trigger produce exactly ONE SL203 finding."""
    events = [
        SessionEvent(
            id="chk-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="system",
            kind="checkpoint",
            payload={"seq": 1, "state_hash": "h1"},
        ),
        SessionEvent(
            id="chk-2",
            parent_id="chk-1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="system",
            kind="checkpoint",
            payload={"seq": 10, "state_hash": "h2"},  # Gap trigger at idx 1
        ),
        SessionEvent(
            id="call-1",
            parent_id="chk-2",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c1",
        ),
        SessionEvent(
            id="res-1",
            parent_id="call-1",
            seq=3,
            ts="2026-09-05T12:00:03Z",
            actor="tool",
            kind="tool_result",
            correlation_id="c1",
        ),
        SessionEvent(
            id="call-2",
            parent_id="res-1",
            seq=4,
            ts="2026-09-05T12:00:04Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c2",
        ),
    ]

    findings = check_unsafe_continuation(events)
    assert len(findings) == 1
    assert findings[0].code == SL203
    assert _evidence(findings[0])["first_unsafe_index"] == 2


def test_idempotent_duplicate_checkpoint_no_sl202() -> None:
    """Idempotent re-emission of duplicate checkpoint with same seq and hash is safe."""
    events = [
        SessionEvent(
            id="chk-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="system",
            kind="checkpoint",
            payload={"seq": 1, "state_hash": "same_hash"},
        ),
        SessionEvent(
            id="chk-2",
            parent_id="chk-1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="system",
            kind="checkpoint",
            payload={"seq": 1, "state_hash": "same_hash"},
        ),
    ]

    findings = check_checkpoint_divergence(events)
    assert not findings


def test_missing_state_hash_triggers_sl201() -> None:
    """Missing or empty state_hash on checkpoint triggers SL201 without crash."""
    events = [
        SessionEvent(
            id="chk-no-hash",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="system",
            kind="checkpoint",
            payload={"seq": 1},  # No state_hash
        )
    ]

    findings = check_checkpoint_gap(events)
    assert len(findings) == 1
    assert findings[0].code == SL201


def test_trigger_at_last_index_no_sl203() -> None:
    """SL201 trigger at last index with no subsequent tool event produces no SL203."""
    events = [
        SessionEvent(
            id="chk-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="system",
            kind="checkpoint",
            payload={"seq": 1, "state_hash": "h1"},
        ),
        SessionEvent(
            id="chk-gap",
            parent_id="chk-1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="system",
            kind="checkpoint",
            payload={"seq": 5, "state_hash": "h2"},
        ),
    ]

    findings = check_unsafe_continuation(events)
    assert not findings


def test_compaction_boundary_without_checkpoint_triggers_sl203() -> None:
    """Compaction boundary followed by tool event without intervening checkpoint triggers SL203."""
    events = [
        SessionEvent(
            id="msg-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
        ),
        SessionEvent(
            id="bound-1",
            parent_id="msg-1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="system",
            kind="compaction_boundary",
        ),
        SessionEvent(
            id="call-1",
            parent_id="bound-1",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c1",
        ),
    ]

    findings = check_unsafe_continuation(events)
    assert len(findings) == 1
    assert findings[0].code == SL203
    assert _evidence(findings[0])["caused_by"] == ["compaction"]


def test_determinism_and_stable_fingerprints() -> None:
    """Repeated runs produce byte-identical sorted outputs and stable fingerprints."""
    events = [
        SessionEvent(
            id="chk-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="system",
            kind="checkpoint",
            payload={"seq": 1, "state_hash": "h1"},
        ),
        SessionEvent(
            id="chk-gap",
            parent_id="chk-1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="system",
            kind="checkpoint",
            payload={"seq": 5, "state_hash": "h2"},
        ),
    ]

    findings_1 = check_checkpoint(events)
    findings_2 = check_checkpoint(events)

    raw_1 = json.dumps([f.to_dict() for f in findings_1], sort_keys=True)
    raw_2 = json.dumps([f.to_dict() for f in findings_2], sort_keys=True)
    assert raw_1 == raw_2


def test_immutability() -> None:
    """check_checkpoint does not mutate input event objects or sequence."""
    events = [
        SessionEvent(
            id="chk-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="system",
            kind="checkpoint",
            payload={"seq": 1, "state_hash": "h1"},
        )
    ]

    events_copy = copy.deepcopy(events)
    _ = check_checkpoint(events)
    assert events == events_copy


def test_vendor_free() -> None:
    """Source file must be strictly vendor-free."""
    assert CHECKPOINT_SRC_FILE.is_file(), f"Missing source file: {CHECKPOINT_SRC_FILE}"
    source_content = CHECKPOINT_SRC_FILE.read_text(encoding="utf-8")

    forbidden_patterns = [
        re.compile(r"\bclaude\b", re.IGNORECASE),
        re.compile(r"\bopenai\b", re.IGNORECASE),
        re.compile(r"\banthropic\b", re.IGNORECASE),
        re.compile(r"\bchatgpt\b", re.IGNORECASE),
        re.compile(r"\btoolUse\b"),
        re.compile(r"\bcall_id\b"),
    ]

    for pattern in forbidden_patterns:
        match = pattern.search(source_content)
        assert match is None, (
            f"Forbidden vendor keyword '{match.group(0)}' found in {CHECKPOINT_SRC_FILE}"
        )


def test_per_code_helpers() -> None:
    """check_sl201, check_sl202, check_sl203 direct aliases work."""
    events = [
        SessionEvent(
            id="chk-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="system",
            kind="checkpoint",
            payload={"seq": 1, "state_hash": "h1"},
        ),
        SessionEvent(
            id="chk-2",
            parent_id="chk-1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="system",
            kind="checkpoint",
            payload={"seq": 5, "state_hash": "h2"},
        ),
    ]

    f201 = check_sl201(events)
    assert len(f201) == 1 and f201[0].code == SL201

    f202 = check_sl202(events)
    assert not f202

    f203 = check_sl203(events)
    assert not f203


def test_sensitivity_parity() -> None:
    """Neutral vs openai-strict sensitivity flag both fire SL201 on gap fixture (pinned parity)."""
    from sesslint.profiles import NEUTRAL_PROFILE, OPENAI_STRICT_PROFILE

    assert NEUTRAL_PROFILE.checkpoint_sensitivity == "default"
    assert OPENAI_STRICT_PROFILE.checkpoint_sensitivity == "high"

    fixture_path = FIXTURES_CHECKS_DIR / "sl201_gap.json"
    events, load_findings = load_canonical(fixture_path)
    assert not load_findings

    f_default = check_checkpoint_gap(
        events, checkpoint_sensitivity=NEUTRAL_PROFILE.checkpoint_sensitivity
    )
    f_high = check_checkpoint_gap(
        events, checkpoint_sensitivity=OPENAI_STRICT_PROFILE.checkpoint_sensitivity
    )

    assert len(f_default) == 1
    assert len(f_high) == 1
    assert f_default[0].code == SL201
    assert f_high[0].code == SL201
    assert f_default[0].to_dict() == f_high[0].to_dict()


def test_sl201_run_state_evidence_preservation() -> None:
    """SL201 finding includes run_state projection when supplied via context or param."""
    events = [
        SessionEvent(
            id="c1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="system",
            kind="checkpoint",
            payload={"seq": 1, "state_hash": "hash1"},
        ),
        SessionEvent(
            id="c2",
            parent_id="c1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="system",
            kind="checkpoint",
            payload={"seq": 5, "state_hash": "hash2"},
        ),
    ]

    proj = {
        "checkpoints": [{"hash": "<str:len=5>", "id": "chk_1", "seq": 1, "ts": True}],
        "keys": ["agent_mode", "step_count"],
        "shapes": {"agent_mode": "<str:len=10>", "step_count": "<int>"},
        "truncated": False,
    }

    # 1. Via explicit run_state_projection param
    findings_param = check_checkpoint_gap(events, run_state_projection=proj)
    assert len(findings_param) == 1
    ev_param = _evidence(findings_param[0])
    assert "run_state" in ev_param
    assert ev_param["run_state"] == proj

    # 2. Via CheckContext.source_metadata
    from sesslint.context import CheckContext

    ctx = CheckContext(
        adapter_id="openai-agents",
        adapter_version="1.0.0",
        profile_id="openai-strict",
        profile_version="1.0.0",
        source_metadata={"run_state_projection": proj},
    )
    findings_ctx = check_checkpoint_gap(events, context=ctx)
    assert len(findings_ctx) == 1
    ev_ctx = _evidence(findings_ctx[0])
    assert "run_state" in ev_ctx
    assert ev_ctx["run_state"] == proj

    # 3. Via EventList.source
    from sesslint.adapters.openai_agents import EventList, SourceMetadata

    src_meta = SourceMetadata(run_state_projection=proj)
    event_list = EventList(events, source=src_meta)
    findings_el = check_checkpoint_gap(event_list)
    assert len(findings_el) == 1
    ev_el = _evidence(findings_el[0])
    assert "run_state" in ev_el
    assert ev_el["run_state"] == proj


def test_sl202_run_state_evidence_preservation() -> None:
    """SL202 finding includes run_state projection when supplied."""
    events = [
        SessionEvent(
            id="c1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="system",
            kind="checkpoint",
            payload={"seq": 1, "state_hash": "hash_a_123456789"},
        ),
        SessionEvent(
            id="c2",
            parent_id="c1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="system",
            kind="checkpoint",
            payload={"seq": 1, "state_hash": "hash_b_987654321"},
        ),
    ]

    proj = {
        "checkpoints": [],
        "keys": ["active_task"],
        "shapes": {"active_task": "<str:len=8>"},
        "truncated": False,
    }

    findings = check_checkpoint_divergence(events, run_state_projection=proj)
    assert len(findings) == 1
    ev = _evidence(findings[0])
    assert "run_state" in ev
    assert ev["run_state"] == proj


def test_run_state_absence_keeps_evidence_minimal() -> None:
    """When run_state is absent, finding evidence contains no run_state key."""
    events = [
        SessionEvent(
            id="c1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="system",
            kind="checkpoint",
            payload={"seq": 1, "state_hash": "hash1"},
        ),
        SessionEvent(
            id="c2",
            parent_id="c1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="system",
            kind="checkpoint",
            payload={"seq": 5, "state_hash": "hash2"},
        ),
    ]

    findings = check_checkpoint_gap(events)
    assert len(findings) == 1
    ev = _evidence(findings[0])
    assert "run_state" not in ev
    assert "at_index" in ev
    assert "expected_seq" in ev
    assert "found_seq" in ev


def test_verdict_matrix_unchanged_by_run_state_projection() -> None:
    """SL201/SL202 finding count, codes, severities, and fingerprints are unchanged."""
    events = [
        SessionEvent(
            id="c1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="system",
            kind="checkpoint",
            payload={"seq": 1, "state_hash": "h1"},
        ),
        SessionEvent(
            id="c2",
            parent_id="c1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="system",
            kind="checkpoint",
            payload={"seq": 5, "state_hash": "h2"},
        ),
    ]

    findings_without = check_checkpoint_gap(events)
    findings_with = check_checkpoint_gap(
        events,
        run_state_projection={
            "checkpoints": [],
            "keys": ["k1"],
            "shapes": {"k1": "<int>"},
            "truncated": False,
        },
    )

    assert len(findings_without) == len(findings_with) == 1
    assert findings_without[0].code == findings_with[0].code == SL201
    assert findings_without[0].severity == findings_with[0].severity
    assert findings_without[0].repairability == findings_with[0].repairability
    assert findings_without[0].source == findings_with[0].source
    # Fingerprint must be identical because run_state is not in CANONICAL_EVIDENCE_KEYS
    assert findings_without[0].fingerprint == findings_with[0].fingerprint


def test_check_checkpoint_composite_run_state_preservation() -> None:
    """Composite check_checkpoint attaches run_state to SL201/SL202 and keeps SL203 minimal."""
    from sesslint.checks.checkpoint import check_checkpoint
    from sesslint.context import CheckContext

    proj = {
        "checkpoints": [{"hash": "<str:len=5>", "id": "chk_1", "seq": 1, "ts": True}],
        "keys": ["agent_mode"],
        "shapes": {"agent_mode": "<str:len=10>"},
        "truncated": False,
    }

    ctx = CheckContext(
        adapter_id="openai-agents",
        adapter_version="1.0.0",
        profile_id="openai-strict",
        profile_version="1.0.0",
        source_metadata={"run_state_projection": proj},
    )

    # Stream with SL201 gap (1 -> 5) followed by tool event triggering SL203
    events = [
        SessionEvent(
            id="c1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="system",
            kind="checkpoint",
            payload={"seq": 1, "state_hash": "hash1"},
        ),
        SessionEvent(
            id="c2",
            parent_id="c1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="system",
            kind="checkpoint",
            payload={"seq": 5, "state_hash": "hash2"},
        ),
        SessionEvent(
            id="t1",
            parent_id="c2",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="assistant",
            kind="tool_call",
            payload={"name": "bash", "call_id": "call_1"},
        ),
    ]

    findings = check_checkpoint(events, context=ctx)
    codes = [f.code for f in findings]
    assert "SL201" in codes
    assert "SL203" in codes

    f201 = [f for f in findings if f.code == "SL201"][0]
    f203 = [f for f in findings if f.code == "SL203"][0]

    # SL201 carries run_state projection
    assert f201.evidence is not None
    assert "run_state" in f201.evidence
    assert f201.evidence["run_state"] == proj

    # SL203 remains strictly minimal (no run_state)
    assert f203.evidence is not None
    assert "run_state" not in f203.evidence
