"""Unit and regression tests for tool-pairing finding fingerprints (TASK DEV-004).

Verifies:
1. Tool-pairing check families (SL101-SL108) compute fingerprints via the unified
   compute_finding_fingerprint scheme.
2. CheckContext (adapter_id, adapter_version, profile_id, profile_version) is correctly threaded
   through tool-pairing check families (tool_pairing_1 and tool_pairing_2).
3. Version-sensitivity matrix: varying any coordinate (adapter_id, adapter_version, profile_id,
   profile_version) yields a distinct 16-hex fingerprint for pairing findings.
4. Content-free invariant: evidence is filtered strictly to CANONICAL_EVIDENCE_KEYS; non-allowlisted
   keys (e.g., arguments, payloads) and unstable record_indexes do not alter the fingerprint.
5. Structural coordinate sensitivity: path, line, ordinal, correlation_id affect the fingerprint.
6. Unknown version normalization: missing or empty versions normalize to "unknown".
7. Legacy compute_pairing_fingerprint helper remains deterministic and returns 16-hex digest.
"""

from __future__ import annotations

import re
from typing import Any

from sesslint.canonical import SessionEvent
from sesslint.checks.tool_pairing_1 import (
    check_tool_pairing_1,
    compute_pairing_fingerprint,
)
from sesslint.checks.tool_pairing_2 import (
    check_tool_pairing_2,
)
from sesslint.context import CheckContext
from sesslint.finding import (
    SourceRef,
    compute_finding_fingerprint,
    make_finding,
)

HEX_16_PATTERN = re.compile(r"^[0-9a-f]{16}$")


def _make_dummy_event(
    record_id: str,
    kind: Any,
    actor: Any = "assistant",
    correlation_id: str | None = None,
    payload: dict[str, Any] | None = None,
    parent_id: str | None = None,
    seq: int = 0,
) -> SessionEvent:
    return SessionEvent(
        id=record_id,
        parent_id=parent_id,
        seq=seq,
        ts="2026-09-09T00:00:00Z",
        actor=actor,
        kind=kind,
        correlation_id=correlation_id,
        payload=payload or {},
    )


def test_legacy_compute_pairing_fingerprint() -> None:
    """Legacy compute_pairing_fingerprint helper returns deterministic 16-hex string."""
    fp1 = compute_pairing_fingerprint("SL101", ["call-1", "call-2"])
    fp2 = compute_pairing_fingerprint("SL101", ["call-2", "call-1"])
    assert HEX_16_PATTERN.match(fp1)
    assert fp1 == fp2


def test_pairing_finding_fingerprint_shape_and_hex() -> None:
    """Tool-pairing findings produce valid 16-hex lowercase fingerprints."""
    source = SourceRef(path="test.json", line=5, record_id="rec-orphan")
    finding = make_finding(
        code="SL101",
        message_template="Orphan tool result for {record_id}",
        source=source,
        ordinal=0,
        evidence={"tool_use_id": "orphan-call"},
        adapter_id="test-adapter",
        adapter_version="2.0.0",
        profile_id="test-profile",
        profile_version="v1",
    )
    assert HEX_16_PATTERN.match(finding.fingerprint)
    assert finding.fingerprint == finding.fingerprint.lower()


def test_tool_pairing_1_context_threading() -> None:
    """CheckContext is threaded into tool_pairing_1 checks and influences fingerprint."""
    orphan_event = _make_dummy_event(
        record_id="r1",
        kind="tool_result",
        actor="tool",
        correlation_id="call-missing",
    )
    events = [orphan_event]

    ctx = CheckContext(
        adapter_id="gemini",
        adapter_version="3.4.1",
        profile_id="safety-profile",
        profile_version="2026.03",
    )

    findings = check_tool_pairing_1(events, source_path="stream.jsonl", context=ctx)
    sl101_findings = [f for f in findings if f.code == "SL101"]
    assert len(sl101_findings) == 1

    f = sl101_findings[0]
    assert HEX_16_PATTERN.match(f.fingerprint)

    # Finding fingerprint matches direct computation with context
    expected_fp = compute_finding_fingerprint(
        code="SL101",
        source=f.source,
        adapter_id="gemini",
        adapter_version="3.4.1",
        profile_id="safety-profile",
        profile_version="2026.03",
        evidence=f.evidence,
    )
    assert f.fingerprint == expected_fp

    # Default / neutral context produces different fingerprint
    neutral_findings = check_tool_pairing_1(
        events, source_path="stream.jsonl", context=CheckContext()
    )
    assert f.fingerprint != neutral_findings[0].fingerprint


def test_tool_pairing_version_sensitivity_matrix() -> None:
    """Altering any coordinate of the version tuple changes the pairing fingerprint."""
    events = [
        _make_dummy_event(
            record_id="r1",
            kind="tool_result",
            actor="tool",
            correlation_id="call-1",
        )
    ]

    base_ctx = CheckContext(
        adapter_id="adapter_a",
        adapter_version="1.0.0",
        profile_id="profile_x",
        profile_version="2026-01-01",
    )
    base_findings = check_tool_pairing_1(events, source_path="test.json", context=base_ctx)
    base_fp = base_findings[0].fingerprint

    variations = [
        ("diff_adapter_id", base_ctx.with_overrides(adapter_id="adapter_b")),
        ("diff_adapter_version", base_ctx.with_overrides(adapter_version="1.0.1")),
        ("diff_profile_id", base_ctx.with_overrides(profile_id="profile_y")),
        ("diff_profile_version", base_ctx.with_overrides(profile_version="2026-01-02")),
        ("neutral_unknown", CheckContext()),
    ]

    seen_fps: dict[str, str] = {"base": base_fp}
    for label, ctx in variations:
        f = check_tool_pairing_1(events, source_path="test.json", context=ctx)[0]
        assert f.fingerprint not in seen_fps.values(), (
            f"Collision between {label} ({f.fingerprint}) and existing fingerprints"
        )
        seen_fps[label] = f.fingerprint

    assert len(seen_fps) == 6


def test_tool_pairing_2_context_threading() -> None:
    """CheckContext is threaded into tool_pairing_2 checks."""
    # Reversed order: tool_result appears before tool_call with the same correlation_id -> SL105
    ev_result = _make_dummy_event(
        record_id="r1",
        kind="tool_result",
        actor="tool",
        correlation_id="call-rev",
        seq=0,
    )
    ev_call = _make_dummy_event(
        record_id="r2",
        kind="tool_call",
        actor="assistant",
        correlation_id="call-rev",
        seq=1,
    )
    events = [ev_result, ev_call]

    ctx = CheckContext(
        adapter_id="openai",
        adapter_version="2.1.0",
        profile_id="default",
        profile_version="2026-02",
    )

    findings = check_tool_pairing_2(events, source_path="dialog.json", context=ctx)
    sl105_findings = [f for f in findings if f.code == "SL105"]
    assert len(sl105_findings) == 1

    f = sl105_findings[0]
    assert HEX_16_PATTERN.match(f.fingerprint)

    expected_fp = compute_finding_fingerprint(
        code="SL105",
        source=f.source,
        adapter_id="openai",
        adapter_version="2.1.0",
        profile_id="default",
        profile_version="2026-02",
        evidence=f.evidence,
    )
    assert f.fingerprint == expected_fp


def test_pairing_evidence_content_free_filtering() -> None:
    """Only CANONICAL_EVIDENCE_KEYS affect the pairing fingerprint; payload data is ignored."""
    source = SourceRef(path="p.json", line=1, record_id="r1")
    canonical_evidence = {"correlation_id": "call-xyz"}
    fp_clean = compute_finding_fingerprint(
        code="SL101",
        source=source,
        adapter_id="test",
        adapter_version="1.0",
        profile_id="prof",
        profile_version="1.0",
        evidence=canonical_evidence,
    )

    # Injected unallowlisted keys (content, arguments, record_indexes) must NOT change fingerprint
    polluted_evidence = {
        "correlation_id": "call-xyz",
        "tool_arguments": {"secret": "dont_leak", "query": "DROP TABLE users"},
        "result_payload": "sensitive data",
        "record_indexes": [1, 2, 3],
        "random_extra": 42,
    }
    fp_polluted = compute_finding_fingerprint(
        code="SL101",
        source=source,
        adapter_id="test",
        adapter_version="1.0",
        profile_id="prof",
        profile_version="1.0",
        evidence=polluted_evidence,
    )
    assert fp_clean == fp_polluted, "Fingerprint was altered by non-canonical evidence keys!"

    # Modifying an allowlisted key DOES change the fingerprint
    altered_evidence = {"correlation_id": "call-abc"}
    fp_altered = compute_finding_fingerprint(
        code="SL101",
        source=source,
        adapter_id="test",
        adapter_version="1.0",
        profile_id="prof",
        profile_version="1.0",
        evidence=altered_evidence,
    )
    assert fp_clean != fp_altered


def test_pairing_structural_coords_sensitivity() -> None:
    """Altering structural coordinates (path, line, ordinal, record_id) alters fingerprint."""
    base_source = SourceRef(path="test.json", line=10, record_id="rec-1")
    base_fp = compute_finding_fingerprint(
        code="SL102",
        source=base_source,
        ordinal=0,
        adapter_id="claude",
        adapter_version="1.0",
        profile_id="prof",
        profile_version="1.0",
        evidence={"correlation_id": "call-1"},
    )

    # Vary line
    fp_line = compute_finding_fingerprint(
        code="SL102",
        source=SourceRef(path="test.json", line=11, record_id="rec-1"),
        ordinal=0,
        adapter_id="claude",
        adapter_version="1.0",
        profile_id="prof",
        profile_version="1.0",
        evidence={"correlation_id": "call-1"},
    )
    assert fp_line != base_fp

    # Vary ordinal
    fp_ord = compute_finding_fingerprint(
        code="SL102",
        source=base_source,
        ordinal=1,
        adapter_id="claude",
        adapter_version="1.0",
        profile_id="prof",
        profile_version="1.0",
        evidence={"correlation_id": "call-1"},
    )
    assert fp_ord != base_fp

    # Vary path
    fp_path = compute_finding_fingerprint(
        code="SL102",
        source=SourceRef(path="other.json", line=10, record_id="rec-1"),
        ordinal=0,
        adapter_id="claude",
        adapter_version="1.0",
        profile_id="prof",
        profile_version="1.0",
        evidence={"correlation_id": "call-1"},
    )
    assert fp_path != base_fp

    # Vary record_id
    fp_rec = compute_finding_fingerprint(
        code="SL102",
        source=SourceRef(path="test.json", line=10, record_id="rec-2"),
        ordinal=0,
        adapter_id="claude",
        adapter_version="1.0",
        profile_id="prof",
        profile_version="1.0",
        evidence={"correlation_id": "call-1"},
    )
    assert fp_rec != base_fp


def test_pairing_unknown_version_normalization() -> None:
    """None and empty versions normalize to 'unknown' in tool-pairing checks."""
    source = SourceRef(path="p.json", line=1, record_id="r1")
    fp_none = compute_finding_fingerprint(
        code="SL101",
        source=source,
        adapter_id=None,
        adapter_version=None,
        profile_id=None,
        profile_version=None,
        evidence={"correlation_id": "call-1"},
    )
    fp_explicit_unknown = compute_finding_fingerprint(
        code="SL101",
        source=source,
        adapter_id="unknown",
        adapter_version="unknown",
        profile_id="unknown",
        profile_version="unknown",
        evidence={"correlation_id": "call-1"},
    )
    fp_empty_str = compute_finding_fingerprint(
        code="SL101",
        source=source,
        adapter_id="",
        adapter_version="",
        profile_id="",
        profile_version="",
        evidence={"correlation_id": "call-1"},
    )
    assert fp_none == fp_explicit_unknown
    assert fp_empty_str == fp_explicit_unknown
