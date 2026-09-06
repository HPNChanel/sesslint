"""Tests for finding block format and deterministic ordering (TASK-025)."""

from __future__ import annotations

from sesslint.codes import SL001, SL002, SL003, Repairability, Severity
from sesslint.finding import SourceRef, make_finding
from sesslint.report import build_report, finding_report_sort_key, render_human


def test_finding_block_structure() -> None:
    """Verify finding block contains code-title, Span, Why, Fix, and Fingerprint."""
    f = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Malformed syntax at line {line}",
        template_args={"line": "42"},
        source=SourceRef(path="session.jsonl", line=42),
    )
    rep = build_report(
        session_id="sess_block_test",
        source_fingerprint="0" * 64,
        tool_version="0.1.0",
        findings=[f],
        assurance="A0",
        limitation="Test",
    )
    rendered = render_human(rep)
    assert "[SL001]" in rendered
    assert "Malformed record" in rendered
    assert "Span:        session.jsonl:42" in rendered or "Span:        .._" in rendered
    assert "Why:         Malformed syntax at line 42" in rendered
    assert "Fix:         manual inspection required; automated repair refused" in rendered
    assert f"Fingerprint: {f.fingerprint}" in rendered


def test_deterministic_finding_sort_order() -> None:
    """Verify findings are sorted deterministically by (code, path, line, byte, fingerprint)."""
    # Create findings in non-sorted order
    f1 = make_finding(
        code=SL002,
        severity=Severity.ERROR,
        repairability=Repairability.DETERMINISTIC,
        message_template="Torn terminal record at line {line}",
        template_args={"line": "100"},
        source=SourceRef(path="a.jsonl", line=100),
        evidence={"byte_offset": 500},
    )
    f2 = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Malformed record at line {line}",
        template_args={"line": "50"},
        source=SourceRef(path="b.jsonl", line=50),
        evidence={"byte_offset": 200},
    )
    f3 = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Malformed record at line {line}",
        template_args={"line": "10"},
        source=SourceRef(path="a.jsonl", line=10),
        evidence={"byte_offset": 50},
    )
    f4 = make_finding(
        code=SL003,
        severity=Severity.WARNING,
        repairability=Repairability.DETERMINISTIC,
        message_template="Duplicate event at line {line}",
        template_args={"line": "5"},
        source=SourceRef(path="a.jsonl", line=5),
        evidence={"byte_offset": 10},
    )

    # Scrambled input list
    input_findings = [f1, f2, f3, f4]
    sorted_findings = sorted(input_findings, key=finding_report_sort_key)

    # Expected order:
    # 1. f3: SL001, a.jsonl, line 10
    # 2. f2: SL001, b.jsonl, line 50
    # 3. f1: SL002, a.jsonl, line 100
    # 4. f4: SL003, a.jsonl, line 5
    assert sorted_findings == [f3, f2, f1, f4]

    rep = build_report(
        session_id="sess_sort_test",
        source_fingerprint="0" * 64,
        tool_version="0.1.0",
        findings=input_findings,
        assurance="A0",
        limitation="Test",
    )
    rendered = render_human(rep)

    pos_f3 = rendered.find(f3.fingerprint)
    pos_f2 = rendered.find(f2.fingerprint)
    pos_f1 = rendered.find(f1.fingerprint)
    pos_f4 = rendered.find(f4.fingerprint)

    assert pos_f3 < pos_f2 < pos_f1 < pos_f4
