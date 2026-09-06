"""Tests for JSON schema conformance of default and --include-content reports (TASK-025)."""

from __future__ import annotations

import json
from typing import Any

from sesslint.codes import SL001, Repairability, Severity
from sesslint.finding import SourceRef, make_finding
from sesslint.report import (
    REPORT_DEFAULT_FINDING_KEYS,
    REPORT_ROOT_KEYS,
    build_report,
    load_report_schema,
    render_json,
)


def _validate_report_dict_strictly(data: dict[str, Any], *, include_content: bool = False) -> None:
    """Hand-rolled strict schema validator conforming to schemas/sesslint.report.v1.json."""
    # Root required keys
    assert data["schema_version"] == "sesslint.report/v1"
    assert isinstance(data["session_id"], str) and data["session_id"]
    assert isinstance(data["source_fingerprint"], str) and data["source_fingerprint"]
    assert isinstance(data["tool_version"], str) and data["tool_version"]
    assert data["assurance"] in ("A0", "A1", "A2", "A3", "A4")
    assert isinstance(data["limitation"], str) and data["limitation"]

    # Root keys ⊆ allowlist
    assert set(data.keys()).issubset(REPORT_ROOT_KEYS)

    if include_content:
        assert data.get("content_warning") is True
        assert data.get("included_content") is True
    else:
        assert "content_warning" not in data
        assert "included_content" not in data

    # Counts validation
    counts = data["counts"]
    assert isinstance(counts["total"], int)
    assert isinstance(counts["by_severity"], dict)
    assert isinstance(counts["by_code"], dict)
    for sev in ("fatal", "error", "warning", "info"):
        assert sev in counts["by_severity"]
        assert isinstance(counts["by_severity"][sev], int)

    # Repro validation if present
    if "repro" in data:
        repro = data["repro"]
        assert "cli_version" in repro
        assert "schema_versions" in repro
        assert "adapter" in repro
        assert "profile" in repro
        assert "detection" in repro
        assert "platform" in repro

    # Findings validation
    findings = data["findings"]
    assert isinstance(findings, list)
    for f in findings:
        assert isinstance(f["code"], str)
        assert f["severity"] in ("fatal", "error", "warning", "info")
        assert f["repairability"] in ("deterministic", "lossy-explicit", "manual", "unsupported")
        assert isinstance(f["fingerprint"], str) and len(f["fingerprint"]) == 16

        if not include_content:
            assert set(f.keys()).issubset(REPORT_DEFAULT_FINDING_KEYS)
            assert "span" in f
            assert "path" in f["span"]


def test_default_report_validates_against_schema() -> None:
    """Verify default render_json output adheres to report schema."""
    f = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Malformed record at line {line}",
        template_args={"line": "1"},
        source=SourceRef(path="session.jsonl", line=1),
    )
    rep = build_report(
        session_id="sess_schema_1",
        source_fingerprint="0" * 64,
        tool_version="0.1.0",
        findings=[f],
        assurance="A0",
        limitation="No conclusion.",
    )

    rendered = render_json(rep, include_content=False)
    data = json.loads(rendered)
    _validate_report_dict_strictly(data, include_content=False)


def test_include_content_report_validates_against_schema() -> None:
    """Verify include-content render_json output adheres to report schema."""
    f = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Malformed record at line {line}",
        template_args={"line": "1"},
        source=SourceRef(path="session.jsonl", line=1),
    )
    rep = build_report(
        session_id="sess_schema_2",
        source_fingerprint="0" * 64,
        tool_version="0.1.0",
        findings=[f],
        assurance="A0",
        limitation="No conclusion.",
    )

    rendered = render_json(rep, include_content=True)
    data = json.loads(rendered)
    _validate_report_dict_strictly(data, include_content=True)


def test_load_report_schema_contains_updated_properties() -> None:
    """Verify committed JSON Schema file contains repro, content_warning, and span."""
    schema = load_report_schema()
    props = schema["properties"]
    assert "repro" in props
    assert "content_warning" in props
    assert "included_content" in props

    finding_props = props["findings"]["items"]["properties"]
    assert "span" in finding_props
    assert "remediation" in finding_props
