"""Tests for identifier minimization in reports and JSON payloads (TASK-025)."""

from __future__ import annotations

import json

from sesslint.codes import SL001, Repairability, Severity
from sesslint.finding import SourceRef, make_finding
from sesslint.report import (
    build_report,
    minimize_id,
    render_json,
    short_hash,
)


def test_minimize_id_string_default() -> None:
    """Verify minimize_id in string mode returns ordinal or short hash."""
    long_uuid = "550e8400-e29b-41d4-a716-446655440000"
    expected_short = short_hash(long_uuid, 8)

    # Without ordinal: short hash
    assert minimize_id(long_uuid) == expected_short

    # With ordinal: #N
    assert minimize_id(long_uuid, ordinal=3) == "#3"

    # With include_content: full UUID preserved
    assert minimize_id(long_uuid, include_content=True) == long_uuid


def test_minimize_id_dict_mode() -> None:
    """Verify minimize_id in dict mode returns short, ordinal, and conditionally full."""
    long_uuid = "550e8400-e29b-41d4-a716-446655440000"
    expected_short = short_hash(long_uuid, 8)

    # Default dict mode
    res = minimize_id(long_uuid, ordinal=4, as_dict=True)
    assert res == {"short": expected_short, "ordinal": 4}
    assert "full" not in res

    # Include content dict mode
    res_full = minimize_id(long_uuid, ordinal=4, include_content=True, as_dict=True)
    assert res_full == {"short": expected_short, "ordinal": 4, "full": long_uuid}


def test_json_render_minimizes_evidence_identifiers() -> None:
    """Verify that JSON rendering strips full 36-char UUIDs from evidence in default mode."""
    long_uuid = "12345678-abcd-ef01-2345-6789abcdef01"
    f = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Syntax error on line {line}",
        template_args={"line": "1"},
        source=SourceRef(path="session.jsonl", line=1, record_id=long_uuid),
        evidence={"event_id": long_uuid, "count": 2},
    )
    rep = build_report(
        session_id="sess_id_test",
        source_fingerprint="fp_1234567890abcdef",
        tool_version="0.1.0",
        findings=[f],
        assurance="A0",
        limitation="No conclusion.",
    )

    # Default mode
    default_json = render_json(rep, include_content=False)
    assert long_uuid not in default_json
    data = json.loads(default_json)
    evidence = data["findings"][0]["evidence"]
    assert evidence["event_id"] == short_hash(long_uuid, 8)

    # Include content mode
    full_json = render_json(rep, include_content=True)
    assert long_uuid in full_json
    data_full = json.loads(full_json)
    assert data_full["findings"][0]["record_id"] == long_uuid
