"""Tests for self-contained HTML report rendering (ux-reporting T-01)."""

from __future__ import annotations

import pytest

from sesslint.codes import SL001, SL003, Repairability, Severity
from sesslint.finding import SourceRef, make_finding
from sesslint.html_report import MAX_ROWS, render_html, scan_report_html
from sesslint.report import build_report
from sesslint.scan import FileResult, ScanReport, ScanTotals


def _report(findings: list, assurance: str = "A3") -> object:
    return build_report(
        session_id="sess_html",
        source_fingerprint="fp_html_123",
        tool_version="0.2.0",
        findings=findings,
        assurance=assurance,
        limitation="Graph invariants validated.",
    )


def _finding(**over) -> object:
    defaults = {
        "code": SL003,
        "severity": Severity.WARNING,
        "repairability": Repairability.MANUAL,
        "message_template": "Duplicate event id {record_id}",
        "source": SourceRef(path=".._abc123/sess.jsonl", line=4, record_id="evt_2"),
        "evidence": {"byte_offset": 10, "byte_end": 42},
    }
    defaults.update(over)
    return make_finding(**defaults)


def test_html_document_shape() -> None:
    out = render_html(_report([]), adapter="canonical", profile="neutral")
    assert out.startswith("<!DOCTYPE html>")
    assert '<html lang="es">' in out
    assert "<style>" in out
    assert "</html>" in out
    assert "Session is healthy" in out
    assert "sess_html" in out
    assert "0.2.0" in out


def test_html_is_offline_and_scriptless() -> None:
    out = render_html(_report([_finding()]))
    scan = ScanReport(
        root_path=".._abc123/dir",
        totals=ScanTotals(healthy=1),
        files=(FileResult(path=".._abc123/a.jsonl", verdict="healthy"),),
    )
    scan_out = scan_report_html(scan, tool_version="0.2.0")
    for doc in (out, scan_out):
        lowered = doc.lower()
        assert "<script" not in lowered
        assert "http://" not in lowered
        assert "https://" not in lowered
        assert "url(" not in lowered
        assert "src=" not in lowered
        assert "@import" not in lowered


def test_html_deterministic_bytes() -> None:
    rep = _report([_finding(), _finding(code=SL001, severity=Severity.ERROR)])
    assert render_html(rep) == render_html(rep)


def test_html_verdict_banners() -> None:
    assert "banner ok" in render_html(_report([]))
    assert "banner warn" in render_html(_report([_finding()]))
    err = render_html(_report([_finding(severity=Severity.ERROR)]))
    assert "banner err" in err
    assert "Integrity check failed" in err


def test_html_escapes_identifier_fields() -> None:
    rep = _report([_finding(source=SourceRef(path=".._x/<b>&.jsonl", line=1, record_id="a<b"))])
    out = render_html(rep)
    assert "<b>&" not in out
    assert "&lt;b&gt;&amp;" in out


def test_html_no_absolute_paths() -> None:
    rep = _report([_finding(source=SourceRef(path="D:/real/dir/sess.jsonl", line=1))])
    out = render_html(rep)
    assert "D:/real/dir" not in out
    assert ".._" in out or "sess.jsonl" in out


def test_html_findings_table_fields() -> None:
    out = render_html(_report([_finding()]))
    for needle in ("SL003", "warning", "manual", "Duplicate event ID", ".._abc123/sess.jsonl:4"):
        assert needle in out


def test_html_findings_truncation() -> None:
    rep = _report([_finding() for _ in range(MAX_ROWS + 3)])
    out = render_html(rep)
    assert "more finding(s) not shown" in out
    assert f"{MAX_ROWS + 3}" not in out.split("more finding(s)")[0].rsplit("<td", 1)[-1]


def test_scan_html_sections() -> None:
    scan = ScanReport(
        root_path="D:/real/scan-root",
        totals=ScanTotals(healthy=1, invalid=1, skipped=1),
        files=(
            FileResult(path=".._p1/ok.jsonl", verdict="healthy"),
            FileResult(
                path=".._p1/bad.jsonl",
                verdict="invalid",
                error_count=1,
                findings=(_finding(),),
            ),
            FileResult(path=".._p1/skip.bin", verdict="skipped", skipped_reason="extension"),
        ),
    )
    out = scan_report_html(scan, tool_version="0.2.0")
    assert "Scan report" in out
    assert "D:/real/scan-root" not in out
    assert "HEALTHY" in out and "INVALID" in out and "SKIPPED" in out
    assert "extension" in out
    assert "SL003" in out
    assert ".._abc123/sess.jsonl:4" in out
    assert "sesslint 0.2.0" in out


def test_scan_html_summary_and_truncation() -> None:
    from sesslint.scan import ByCodeRow, ScanSummary, WorstFileRow

    files = tuple(
        FileResult(path=f".._p/f{i}.jsonl", verdict="healthy") for i in range(MAX_ROWS + 2)
    )
    scan = ScanReport(
        root_path="r",
        totals=ScanTotals(healthy=MAX_ROWS + 2),
        files=files,
        summary=ScanSummary(
            by_code=(ByCodeRow(code="SL001", severity="error", count=2, files=1),),
            worst_files=(WorstFileRow(path=".._p/f0.jsonl", error_count=2, warning_count=0),),
        ),
    )
    out = scan_report_html(scan, tool_version="0.2.0")
    assert "more file(s) not shown" in out
    assert "Findings by code" in out
    assert "Worst files" in out


@pytest.mark.parametrize("fmt", ["html"])
def test_cli_check_html(fmt: str, capsys: pytest.CaptureFixture[str]) -> None:
    from sesslint.cli import main

    code = main(["check", "fixtures/cli/check_basic/healthy.jsonl", "--output-format", fmt])
    out = capsys.readouterr().out
    assert code == 0
    assert out.startswith("<!DOCTYPE html>")
    assert "Session is healthy" in out


def test_cli_scan_html(capsys: pytest.CaptureFixture[str]) -> None:
    from sesslint.cli import main

    main(["scan", "fixtures/scan/linkage/chain", "--output-format", "html"])
    out = capsys.readouterr().out
    assert out.startswith("<!DOCTYPE html>")
    assert "Scan report" in out
