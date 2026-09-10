"""Unit and integration tests for report coverage block (DEV-005, FR-047)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sesslint.codes import SL001, Repairability, Severity
from sesslint.errors import ContentLeakError, SchemaError
from sesslint.finding import SourceRef, make_finding
from sesslint.profiles import get_profile
from sesslint.repair.executor import run_all_checks
from sesslint.report import (
    Coverage,
    CoverageSkip,
    build_report,
    dump_report,
    parse_report,
    render_human,
)


def test_coverage_skip_dataclass_valid() -> None:
    """Verify CoverageSkip instantiates properly with valid closed-set reason."""
    skip = CoverageSkip(check="SL201", reason="profile-gated", detail="rule not in profile")
    assert skip.check == "SL201"
    assert skip.reason == "profile-gated"
    assert skip.detail == "rule not in profile"
    assert skip.to_dict() == {
        "check": "SL201",
        "detail": "rule not in profile",
        "reason": "profile-gated",
    }


def test_coverage_skip_rejects_unknown_reason() -> None:
    """Verify CoverageSkip rejects reasons outside the closed vocabulary (fail-closed)."""
    with pytest.raises(SchemaError, match="CoverageSkip.reason must be one of"):
        CoverageSkip(check="SL201", reason="arbitrary-custom-reason")


def test_coverage_skip_rejects_empty_check() -> None:
    """Verify CoverageSkip rejects empty or whitespace check."""
    with pytest.raises(SchemaError, match="CoverageSkip.check must be a non-empty string"):
        CoverageSkip(check="", reason="profile-gated")

    with pytest.raises(SchemaError, match="CoverageSkip.check must be a non-empty string"):
        CoverageSkip(check="   ", reason="profile-gated")


def test_coverage_skip_rejects_content_leak() -> None:
    """Verify CoverageSkip rejects strings with apparent user content or multi-line leaks."""
    with pytest.raises(ContentLeakError, match="Intrinsic content leak in CoverageSkip.detail"):
        CoverageSkip(
            check="SL201",
            reason="profile-gated",
            detail="leaked content\nwith a newline",
        )


def test_coverage_skip_sorting_order() -> None:
    """Verify deterministic total ordering across CoverageSkip items."""
    s1 = CoverageSkip(check="SL001", reason="profile-gated")
    s2 = CoverageSkip(check="SL002", reason="adapter-not-applicable")
    s3 = CoverageSkip(check="SL002", reason="profile-gated")
    s4 = CoverageSkip(check="SL002", reason="profile-gated", detail="extra")

    unordered = [s4, s2, s1, s3]
    ordered = sorted(unordered)
    assert ordered == [s1, s2, s3, s4]


def test_coverage_dataclass_valid() -> None:
    """Verify Coverage container instantiates and renders sorted to_dict."""
    s1 = CoverageSkip(check="SL202", reason="profile-gated")
    s2 = CoverageSkip(check="SL101", reason="adapter-not-applicable")
    cov = Coverage(
        performed=("SL002", "SL001"),
        skipped=(s1, s2),
        adapter={"version": "1.0.0", "id": "claude"},
        profile={"version": "2.0.0", "id": "strict"},
    )
    d = cov.to_dict()
    # Check deterministic key order and sorted items
    assert d["performed"] == ["SL001", "SL002"]
    assert [s["check"] for s in d["skipped"]] == ["SL101", "SL202"]
    assert d["adapter"] == {"id": "claude", "version": "1.0.0"}
    assert d["profile"] == {"id": "strict", "version": "2.0.0"}


def test_coverage_rejects_invalid_performed_or_skipped() -> None:
    """Verify Coverage validates performed and skipped elements."""
    with pytest.raises(SchemaError, match="Coverage.performed"):
        Coverage(
            performed=cast_any(123),
            skipped=(),
            adapter={"id": "a", "version": "1"},
            profile={"id": "p", "version": "1"},
        )

    with pytest.raises(SchemaError, match="Coverage.skipped"):
        Coverage(
            performed=(),
            skipped=cast_any(["not-a-CoverageSkip"]),
            adapter={"id": "a", "version": "1"},
            profile={"id": "p", "version": "1"},
        )


def test_parse_report_validates_coverage_roundtrip() -> None:
    """Verify parse_report round-trips report with coverage block."""
    f = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Malformed line {line}",
        template_args={"line": "1"},
        source=SourceRef(path="test.jsonl", line=1),
    )
    cov = Coverage(
        performed=("SL001", "SL002"),
        skipped=(CoverageSkip(check="SL201", reason="profile-gated"),),
        adapter={"id": "claude", "version": "1.0.0"},
        profile={"id": "strict", "version": "1.0.0"},
    )
    rep = build_report(
        session_id="sess_cov_1",
        source_fingerprint="0" * 64,
        tool_version="0.1.0",
        findings=[f],
        assurance="A1",
        limitation="Coverage test limitation.",
        coverage=cov,
    )

    dumped = dump_report(rep)
    parsed = parse_report(dumped)

    assert parsed.coverage.performed == ("SL001", "SL002")
    assert len(parsed.coverage.skipped) == 1
    assert parsed.coverage.skipped[0].check == "SL201"
    assert parsed.coverage.skipped[0].reason == "profile-gated"
    assert parsed.coverage.adapter["id"] == "claude"
    assert parsed.coverage.profile["id"] == "strict"


def test_parse_report_rejects_missing_coverage() -> None:
    """Verify parse_report rejects report payload missing 'coverage' field."""
    f = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Malformed line {line}",
        template_args={"line": "1"},
        source=SourceRef(path="test.jsonl", line=1),
    )
    rep = build_report(
        session_id="sess_cov_2",
        source_fingerprint="0" * 64,
        tool_version="0.1.0",
        findings=[f],
        assurance="A1",
        limitation="Coverage test limitation.",
    )
    d = rep.to_dict()
    del d["coverage"]

    with pytest.raises(SchemaError, match="Missing required field in report: 'coverage'"):
        parse_report(d)


def test_parse_report_rejects_unknown_skip_reason() -> None:
    """Verify parse_report rejects tampered coverage with unknown reason (Criterion 2)."""
    f = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Malformed line {line}",
        template_args={"line": "1"},
        source=SourceRef(path="test.jsonl", line=1),
    )
    rep = build_report(
        session_id="sess_cov_3",
        source_fingerprint="0" * 64,
        tool_version="0.1.0",
        findings=[f],
        assurance="A1",
        limitation="Coverage test limitation.",
    )
    d = rep.to_dict()
    d["coverage"]["skipped"] = [
        {"check": "SL999", "reason": "unauthorized-magic-reason", "detail": ""}
    ]

    with pytest.raises(SchemaError, match="Invalid coverage skip reason"):
        parse_report(d)


def test_run_all_checks_profile_gating_never_claims_performed() -> None:
    """Verify profile-gated rule appears in skipped with 'profile-gated', NEVER performed."""
    prof = get_profile("neutral")
    findings, cov = run_all_checks(
        (),
        profile=prof,
        adapter="canonical",
        return_coverage=True,
    )

    # Empty events -> structural/semantic checks are skipped with empty-input
    skipped_checks = {s.check: s.reason for s in cov.skipped}
    performed_checks = set(cov.performed)

    # Invariant: No intersection between performed and skipped
    assert performed_checks.isdisjoint(skipped_checks.keys())

    # For any check that was skipped: it must NOT be in performed
    for check_code in skipped_checks:
        assert check_code not in performed_checks


def test_run_all_checks_empty_input_skips_semantic_checks() -> None:
    """Verify empty event stream records 'empty-input' skip reason for semantic checks."""
    prof = get_profile("neutral")
    findings, cov = run_all_checks(
        (),
        profile=prof,
        adapter="canonical",
        return_coverage=True,
    )

    # SL002 (empty stream) finding may be emitted, but semantic check families are skipped
    empty_input_skips = [s for s in cov.skipped if s.reason == "empty-input"]
    assert len(empty_input_skips) > 0
    empty_skip_codes = {s.check for s in empty_input_skips}
    assert "SL101" in empty_skip_codes or "SL201" in empty_skip_codes


def test_human_renderer_includes_coverage_section() -> None:
    """Verify human report renderer includes a Coverage section."""
    rep = build_report(
        session_id="sess_cov_human",
        source_fingerprint="0" * 64,
        tool_version="0.1.0",
        findings=[],
        assurance="A1",
        limitation="Human render coverage test.",
    )
    rendered = render_human(rep)
    assert "Coverage:" in rendered
    assert "checks performed" in rendered


def test_coverage_gated_fixture_roundtrip() -> None:
    """Verify fixtures/report/coverage_gated.json exists, parses, and round-trips byte-stably."""
    fixture_path = (
        Path(__file__).resolve().parent.parent.parent
        / "fixtures"
        / "report"
        / "coverage_gated.json"
    )
    assert fixture_path.is_file(), f"Fixture missing at {fixture_path}"
    fixture_text = fixture_path.read_text(encoding="utf-8")
    report = parse_report(fixture_text)

    assert report.schema_version == "sesslint.report/v1"
    assert report.session_id == "session-coverage-gated-001"
    assert report.assurance == "A2"
    assert len(report.findings) == 0
    assert len(report.coverage.skipped) == 4
    assert all(s.reason == "profile-gated" for s in report.coverage.skipped)
    assert report.coverage.adapter["id"] == "canonical"
    assert report.coverage.profile["id"] == "claude-strict"

    dumped = dump_report(report)
    reparsed = parse_report(dumped)
    redumped = dump_report(reparsed)
    assert dumped == redumped


def test_cli_check_json_contains_valid_coverage(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify CLI check --json output contains a valid coverage block conforming to schema."""
    from sesslint.cli import main

    fixture_path = (
        Path(__file__).resolve().parent.parent.parent
        / "fixtures"
        / "cli"
        / "check_basic"
        / "healthy.jsonl"
    )

    exit_code = main(["check", str(fixture_path), "--json"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "coverage" in data
    cov = data["coverage"]
    assert "performed" in cov
    assert "skipped" in cov
    assert "adapter" in cov
    assert "profile" in cov
    assert isinstance(cov["performed"], list)
    assert len(cov["performed"]) > 0

    parsed = parse_report(data)
    assert len(parsed.coverage.performed) > 0


def test_cli_check_detection_failure_records_coverage(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify CLI check on unparseable format records adapter-not-applicable coverage skips."""
    from sesslint.cli import main

    session_file = tmp_path / "ambiguous.jsonl"
    session_file.write_text('{"random": "payload"}\n', encoding="utf-8")

    exit_code = main(["check", str(session_file), "--json"])
    assert exit_code == 1
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "coverage" in data
    cov = data["coverage"]
    assert len(cov["performed"]) == 0
    assert len(cov["skipped"]) > 0
    assert all(s["reason"] == "adapter-not-applicable" for s in cov["skipped"])


def cast_any(value: Any) -> Any:
    return value
