"""Tests for scan aggregation views: by-code grouping and top-N worst files (T-08)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.api import check_dir
from sesslint.cli import format_scan_report_human, main
from sesslint.finding import SourceRef, make_finding
from sesslint.scan import FileResult, ScanReport, aggregate_scan

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "scan"


def _finding(code: str, severity: str, path: str) -> object:
    return make_finding(
        code=code,
        severity=severity,
        message_template="synthetic",
        source=SourceRef(path),
    )


def _files() -> tuple[FileResult, ...]:
    f203 = _finding("SL203", "error", "a.jsonl")
    f302 = _finding("SL302", "error", "b.jsonl")
    f101 = _finding("SL101", "warning", "a.jsonl")
    return (
        FileResult(
            path="a.jsonl",
            verdict="invalid",
            findings=(f203, f203, f101),  # type: ignore[arg-type]
            error_count=2,
            warning_count=1,
        ),
        FileResult(
            path="b.jsonl",
            verdict="invalid",
            findings=(f302, f203),  # type: ignore[arg-type]
            error_count=3,
            warning_count=0,
        ),
        FileResult(path="ok.jsonl", verdict="healthy"),
    )


def test_aggregate_by_code_exact() -> None:
    """by_code rows match hand-computed counts, files-affected, severity."""
    summary = aggregate_scan(_files())
    assert [(r.code, r.severity, r.count, r.files) for r in summary.by_code] == [
        ("SL203", "error", 3, 2),
        ("SL302", "error", 1, 1),
        ("SL101", "warning", 1, 1),
    ]


def test_aggregate_by_code_sort_order() -> None:
    """Severity rank first, then count desc, then code asc."""
    files = (
        FileResult(
            path="x.jsonl",
            verdict="invalid",
            findings=(
                _finding("SL007", "warning", "x.jsonl"),  # type: ignore[arg-type]
                _finding("SL006", "warning", "x.jsonl"),  # type: ignore[arg-type]
                _finding("SL006", "warning", "x.jsonl"),  # type: ignore[arg-type]
                _finding("SL001", "error", "x.jsonl"),  # type: ignore[arg-type]
            ),
            error_count=1,
            warning_count=3,
        ),
    )
    summary = aggregate_scan(files)
    # SL001 (error) outranks warnings despite lower count; SL006 before SL007
    # on count desc.
    assert [r.code for r in summary.by_code] == ["SL001", "SL006", "SL007"]


def test_aggregate_worst_files_exact() -> None:
    """Worst files rank by error count desc, then warning count desc, then path."""
    summary = aggregate_scan(_files())
    assert [(r.path, r.error_count, r.warning_count) for r in summary.worst_files] == [
        ("b.jsonl", 3, 0),
        ("a.jsonl", 2, 1),
    ]


def test_aggregate_worst_files_excludes_healthy() -> None:
    """Files with zero errors and zero warnings never appear in worst_files."""
    files = (
        FileResult(path="ok.jsonl", verdict="healthy"),
        FileResult(path="also_ok.jsonl", verdict="healthy"),
    )
    summary = aggregate_scan(files)
    assert summary.worst_files == ()
    assert summary.by_code == ()


def test_aggregate_top_limits_and_zero() -> None:
    """top=N caps worst_files; top=0 disables the view."""
    files = _files()
    assert len(aggregate_scan(files, top=1).worst_files) == 1
    assert aggregate_scan(files, top=0).worst_files == ()


def test_aggregate_top_negative_rejected() -> None:
    with pytest.raises(ValueError, match="top must be >= 0"):
        aggregate_scan(_files(), top=-1)


def test_aggregate_group_by_none() -> None:
    """group_by='none' empties by_code but leaves worst_files."""
    summary = aggregate_scan(_files(), group_by="none")
    assert summary.by_code == ()
    assert len(summary.worst_files) == 2


def test_aggregate_group_by_invalid_rejected() -> None:
    with pytest.raises(ValueError, match="group_by"):
        aggregate_scan(_files(), group_by="file")


def test_aggregate_deterministic() -> None:
    """Identical inputs produce identical summary objects."""
    files = _files()
    assert aggregate_scan(files) == aggregate_scan(files)


def test_summary_to_dict_content_free() -> None:
    """Serialized summary contains only codes, counts, severities, paths."""
    d = aggregate_scan(_files()).to_dict()
    for row in d["by_code"]:
        assert sorted(row.keys()) == ["code", "count", "files", "severity"]
    for row in d["worst_files"]:
        assert sorted(row.keys()) == ["error_count", "path", "warning_count"]


def test_scan_report_summary_omitted_when_none() -> None:
    """Reports without an attached summary emit no 'summary' key."""
    rep = ScanReport(root_path="x", files=_files())
    assert "summary" not in rep.to_dict()
    rep2 = ScanReport(root_path="x", files=_files(), summary=aggregate_scan(_files()))
    d = rep2.to_dict()
    assert "summary" in d
    assert sorted(d["summary"].keys()) == ["by_code", "worst_files"]


def test_scan_cli_json_summary(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """`scan --json` embeds the summary object in the emitted document."""
    code = main(["scan", str(FIXTURES_DIR / "mixed"), "--json", "--top", "3"])
    out = capsys.readouterr().out
    assert code in (0, 1)
    doc = json.loads(out)
    assert "summary" in doc
    assert len(doc["summary"]["worst_files"]) <= 3
    for row in doc["summary"]["by_code"]:
        assert set(row.keys()) == {"code", "count", "files", "severity"}


def test_scan_cli_human_summary_block(capsys: pytest.CaptureFixture[str]) -> None:
    """Human output appends the summary block after the per-file table."""
    code = main(["scan", str(FIXTURES_DIR / "mixed")])
    out = capsys.readouterr().out
    assert code == 1
    assert "Findings by code:" in out
    assert "Worst files:" in out
    # summary block comes after the file rows
    assert out.index("Worst files:") > out.index("Findings by code:")


def test_scan_cli_group_by_none_hides_by_code(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["scan", str(FIXTURES_DIR / "mixed"), "--group-by", "none"])
    out = capsys.readouterr().out
    assert code == 1
    assert "Findings by code:" not in out
    assert "Worst files:" in out


def test_scan_cli_top_zero_hides_worst(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["scan", str(FIXTURES_DIR / "mixed"), "--top", "0"])
    out = capsys.readouterr().out
    assert code == 1
    assert "Findings by code:" in out
    assert "Worst files:" not in out


def test_scan_cli_both_disabled_no_block(capsys: pytest.CaptureFixture[str]) -> None:
    """--group-by none --top 0 suppresses the summary entirely."""
    code = main(["scan", str(FIXTURES_DIR / "mixed"), "--group-by", "none", "--top", "0"])
    out = capsys.readouterr().out
    assert code == 1
    assert "Findings by code:" not in out
    assert "Worst files:" not in out
    doc_code = main(
        ["scan", str(FIXTURES_DIR / "mixed"), "--json", "--group-by", "none", "--top", "0"]
    )
    doc = json.loads(capsys.readouterr().out)
    assert doc_code == 1
    assert "summary" not in doc


def test_scan_cli_top_negative_exit_2(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["scan", str(FIXTURES_DIR / "mixed"), "--top", "-1"])
    assert code == 2
    assert "--top must be >= 0" in capsys.readouterr().err


def test_human_renderer_summary_only_when_present() -> None:
    """Formatter renders nothing extra for a report without summary."""
    rep = ScanReport(root_path="x", files=_files())
    plain = format_scan_report_human(rep)
    assert "Findings by code:" not in plain
    rep2 = ScanReport(root_path="x", files=_files(), summary=aggregate_scan(_files()))
    with_summary = format_scan_report_human(rep2)
    assert "Findings by code:" in with_summary
    assert "Worst files:" in with_summary


def test_check_dir_report_has_no_summary_by_default() -> None:
    """API-level scans stay presentation-free (summary is a CLI-layer view)."""
    rep = check_dir(FIXTURES_DIR / "mixed", recursive=True)
    assert rep.summary is None
    assert "summary" not in rep.to_dict()
