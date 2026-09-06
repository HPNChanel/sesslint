"""Tests for human summary header, next-action lines, and wording disclaimers (TASK-025)."""

from __future__ import annotations

from pathlib import Path

from sesslint.cli import create_parser
from sesslint.codes import SL001, SL003, Repairability, Severity
from sesslint.finding import SourceRef, make_finding
from sesslint.report import build_report, render_human

DISCLAIMER_REDACTION = "redaction is best-effort minimization, not a completeness guarantee"
DISCLAIMER_SAFETY = "sesslint makes no semantic or side-effect safety claims"


def test_summary_header_healthy() -> None:
    """Verify human header block format for healthy session report."""
    rep = build_report(
        session_id="sess_healthy",
        source_fingerprint="fp_clean_123",
        tool_version="0.1.0",
        findings=[],
        assurance="A2",
        limitation="Graph invariants validated.",
    )
    rendered = render_human(rep, color=False, adapter="canonical", profile="neutral")
    first_line = rendered.splitlines()[0]
    assert "[read-only]" in first_line
    assert "verdict: healthy" in first_line
    assert "errors: 0" in first_line
    assert "warnings: 0" in first_line
    assert "files: H=1 I=0 U=0 R=0 S=0" in first_line
    assert "profile: neutral" in first_line
    assert "adapter: canonical" in first_line
    assert "Next Action: No repair needed." in rendered


def test_summary_header_invalid_with_deterministic_fix() -> None:
    """Verify human header and next-action recommendation for deterministic findings."""
    f = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.DETERMINISTIC,
        message_template="Malformed record at line {line}",
        template_args={"line": "10"},
        source=SourceRef(path="test.jsonl", line=10),
    )
    rep = build_report(
        session_id="sess_bad",
        source_fingerprint="fp_bad_123",
        tool_version="0.1.0",
        findings=[f],
        assurance="A0",
        limitation="No conclusion.",
    )
    rendered = render_human(rep, color=False, adapter="claude-code-jsonl", profile="claude-strict")
    first_line = rendered.splitlines()[0]
    assert "[read-only]" in first_line
    assert "Integrity check failed" in first_line
    assert "verdict: invalid" in first_line
    assert "errors: 1" in first_line
    assert "warnings: 0" in first_line
    assert "profile: claude-strict" in first_line
    assert "adapter: claude-code-jsonl" in first_line
    assert "Next Action: Run 'sesslint repair" in rendered


def test_summary_header_warning_state() -> None:
    """Verify human header for sessions with warnings only."""
    f = make_finding(
        code=SL003,
        severity=Severity.WARNING,
        repairability=Repairability.DETERMINISTIC,
        message_template="Duplicate event ID at line {line}",
        template_args={"line": "2"},
        source=SourceRef(path="test.jsonl", line=2),
    )
    rep = build_report(
        session_id="sess_warn",
        source_fingerprint="fp_warn_123",
        tool_version="0.1.0",
        findings=[f],
        assurance="A1",
        limitation="Relational integrity unverified.",
    )
    rendered = render_human(rep, color=False, adapter="openai-agents", profile="openai-strict")
    first_line = rendered.splitlines()[0]
    assert "verdict: healthy with warnings" in first_line
    assert "errors: 0" in first_line
    assert "warnings: 1" in first_line
    assert "Next Action: Review warnings; session is structurally replayable." in rendered


def test_disclaimer_sentences_present_verbatim() -> None:
    """Verify disclaimer sentences exist verbatim across CLI help, README, and docs."""
    # 1. CLI help
    parser = create_parser()
    help_text = parser.format_help()
    assert DISCLAIMER_REDACTION in help_text
    assert DISCLAIMER_SAFETY in help_text

    # 2. README.md
    readme_path = Path(__file__).resolve().parent.parent.parent / "README.md"
    readme_content = readme_path.read_text(encoding="utf-8")
    assert DISCLAIMER_REDACTION in readme_content
    assert DISCLAIMER_SAFETY in readme_content

    # 3. docs/codes/README.md
    codes_doc = Path(__file__).resolve().parent.parent.parent / "docs" / "codes" / "README.md"
    assert codes_doc.is_file()
    doc_content = codes_doc.read_text(encoding="utf-8")
    assert DISCLAIMER_REDACTION in doc_content
    assert DISCLAIMER_SAFETY in doc_content
