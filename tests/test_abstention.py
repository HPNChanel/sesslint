"""Unit and integration tests for side-effect-unknown abstention contract (TASK-017).

Covers:
- Hard refusal when SL203 is present, regardless of tool side effects.
- Abstention on tool events with side_effects == "unknown" or "possible" (default unknown).
- Safe evaluation (abstain=False) when all tool events have side_effects == "none" and no SL203.
- Exact-match lowercase requirement: uppercase "NONE" is treated as unsafe/unknown.
- Operator override flag `allow_unknown_side_effects`: bypasses unknown side effects
  while retaining hard refusal on SL203.
- Event format flexibility: SessionEvent objects, plain dicts, and nested payload dicts.
- Non-tool events (messages, checkpoints) do not trigger side-effect abstention.
- Strict content-free reason strings.
- Immutability and pure function contract.
- Vendor-free verification of policy module.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path

from sesslint.canonical import SessionEvent
from sesslint.codes import SL101, SL201, SL203
from sesslint.finding import Finding, Repairability, Severity, SourceRef, make_finding
from sesslint.policy.abstention import (
    Abstention,
    must_abstain,
)

POLICY_SRC_FILE = (
    Path(__file__).resolve().parent.parent / "src" / "sesslint" / "policy" / "abstention.py"
)


def _make_dummy_finding(code: str = SL101) -> Finding:
    """Helper to construct a valid Finding."""
    return make_finding(
        code=code,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template=f"Finding for {code}",
        source=SourceRef(path="session.json", line=1, record_id="rec-1"),
    )


def test_abstention_dataclass() -> None:
    """Abstention dataclass has immutable slots, equality, and to_dict serialization."""
    dec = Abstention(abstain=True, reasons=("SL203 present", "side-effect-unknown at index 2"))
    assert dec.abstain is True
    assert dec.reasons == ("SL203 present", "side-effect-unknown at index 2")

    as_dict = dec.to_dict()
    assert as_dict == {
        "abstain": True,
        "reasons": ["SL203 present", "side-effect-unknown at index 2"],
    }

    # Serialization matches json format
    raw_json = json.dumps(as_dict, sort_keys=True)
    assert "reasons" in raw_json
    assert "abstain" in raw_json


def test_abstention_sl203_hard_refusal() -> None:
    """Findings containing SL203 cause must_abstain to return abstain=True.

    Hard refusal applies regardless of whether tool side effects are safe.
    """
    findings = [_make_dummy_finding(SL203)]
    # Even when all tool events explicitly have safe side_effects == "none"
    events = [
        SessionEvent(
            id="call-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c1",
            payload={"side_effects": "none"},
        ),
    ]

    dec = must_abstain(findings, events)
    assert dec.abstain is True
    assert "SL203 present" in dec.reasons


def test_abstention_safe_session() -> None:
    """Clean session with all tools marked side_effects='none' and no SL203 does not abstain."""
    findings = [_make_dummy_finding(SL101)]  # Non-SL203 finding
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
            id="call-1",
            parent_id="msg-1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c1",
            payload={"side_effects": "none"},
        ),
        SessionEvent(
            id="res-1",
            parent_id="call-1",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="tool",
            kind="tool_result",
            correlation_id="c1",
            payload={"side_effects": "none"},
        ),
    ]

    dec = must_abstain(findings, events)
    assert dec.abstain is False
    assert len(dec.reasons) == 0


def test_abstention_side_effects_unknown() -> None:
    """Absent or unknown side_effects causes abstention."""
    findings: list[Finding] = []
    # Missing side_effects (defaults to None / unknown)
    events = [
        SessionEvent(
            id="call-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c1",
        ),
    ]

    dec = must_abstain(findings, events)
    assert dec.abstain is True
    assert "side-effect-unknown at index 0" in dec.reasons


def test_abstention_side_effects_possible() -> None:
    """Explicit side_effects='possible' causes abstention."""
    findings: list[Finding] = []
    events = [
        SessionEvent(
            id="call-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c1",
            payload={"side_effects": "possible"},
        ),
    ]

    dec = must_abstain(findings, events)
    assert dec.abstain is True
    assert "side-effect-possible at index 0" in dec.reasons


def test_abstention_uppercase_none_is_unsafe() -> None:
    """Uppercase 'NONE' is treated as non-none and causes abstention."""
    findings: list[Finding] = []
    events = [
        SessionEvent(
            id="call-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c1",
            payload={"side_effects": "NONE"},
        ),
    ]

    dec = must_abstain(findings, events)
    assert dec.abstain is True
    assert "side-effect-NONE at index 0" in dec.reasons


def test_allow_unknown_side_effects_override() -> None:
    """Operator override flag allow_unknown_side_effects permits unknown/possible side effects."""
    findings: list[Finding] = []
    events = [
        SessionEvent(
            id="call-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c1",
            payload={"side_effects": "unknown"},
        ),
    ]

    # Without flag: abstains
    dec_default = must_abstain(findings, events)
    assert dec_default.abstain is True

    # With flag: permits
    dec_override = must_abstain(findings, events, allow_unknown_side_effects=True)
    assert dec_override.abstain is False
    assert len(dec_override.reasons) == 0


def test_override_does_not_bypass_sl203() -> None:
    """allow_unknown_side_effects=True does NOT bypass SL203 hard refusal."""
    findings = [_make_dummy_finding(SL203)]
    events = [
        SessionEvent(
            id="call-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c1",
            payload={"side_effects": "unknown"},
        ),
    ]

    dec = must_abstain(findings, events, allow_unknown_side_effects=True)
    assert dec.abstain is True
    assert "SL203 present" in dec.reasons
    # The side-effect reason was bypassed, but SL203 remains
    assert not any(r.startswith("side-effect") for r in dec.reasons)


def test_abstention_event_formats() -> None:
    """must_abstain correctly parses SessionEvent objects, dicts, and nested payloads."""
    findings: list[Finding] = []

    # 1. Plain dictionary with root side_effects
    dict_events_safe = [
        {"kind": "tool_call", "side_effects": "none"},
        {"kind": "tool_result", "side_effects": "none"},
    ]
    assert must_abstain(findings, dict_events_safe).abstain is False

    dict_events_unsafe = [
        {"kind": "tool_call", "side_effects": "possible"},
    ]
    assert must_abstain(findings, dict_events_unsafe).abstain is True

    # 2. Plain dictionary with nested payload
    payload_events_safe = [
        {"kind": "tool_call", "payload": {"side_effects": "none"}},
    ]
    assert must_abstain(findings, payload_events_safe).abstain is False

    payload_events_unsafe = [
        {"kind": "tool_call", "payload": {"side_effects": "unknown"}},
    ]
    assert must_abstain(findings, payload_events_unsafe).abstain is True

    # 3. SessionEvent with nested payload
    session_ev_payload = [
        SessionEvent(
            id="call-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c1",
            payload={"side_effects": "none"},
        )
    ]
    assert must_abstain(findings, session_ev_payload).abstain is False


def test_non_tool_events_do_not_trigger_abstention() -> None:
    """Non-tool events (message, checkpoint, boundary) without side_effects do not abstain."""
    findings: list[Finding] = []
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
            id="chk-1",
            parent_id="msg-1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="system",
            kind="checkpoint",
            payload={"seq": 1, "state_hash": "h1"},
        ),
        SessionEvent(
            id="bound-1",
            parent_id="chk-1",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="system",
            kind="compaction_boundary",
        ),
    ]

    dec = must_abstain(findings, events)
    assert dec.abstain is False
    assert len(dec.reasons) == 0


def test_abstention_immutability() -> None:
    """must_abstain does not mutate input findings or events."""
    findings = [_make_dummy_finding(SL201)]
    events = [
        SessionEvent(
            id="call-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c1",
        )
    ]

    findings_copy = copy.deepcopy(findings)
    events_copy = copy.deepcopy(events)

    _ = must_abstain(findings, events)

    assert findings == findings_copy
    assert events == events_copy


def test_abstention_vendor_free() -> None:
    """Abstention policy module must be strictly vendor-free."""
    assert POLICY_SRC_FILE.is_file(), f"Missing policy source: {POLICY_SRC_FILE}"
    source_content = POLICY_SRC_FILE.read_text(encoding="utf-8")

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
            f"Forbidden vendor keyword '{match.group(0)}' found in {POLICY_SRC_FILE}"
        )
