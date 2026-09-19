"""Tests for parallel scan workers (``scan_path(jobs=N>1)`` / ``scan --jobs``)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.api import check_dir
from sesslint.cli import main
from sesslint.finding import Finding
from sesslint.scan import FileResult, ScanReport, scan_path

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"
HEALTHY = FIXTURES_DIR / "cli" / "check_basic" / "healthy.jsonl"
MIXED_DIR = FIXTURES_DIR / "scan" / "mixed"


def _build_tree(root: Path, copies: int = 12) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    payload = HEALTHY.read_bytes()
    for i in range(copies):
        (root / f"h{i:03}.jsonl").write_bytes(payload)
    (root / "sub").mkdir(exist_ok=True)
    for i in range(3):
        (root / "sub" / f"junk{i}.txt").write_text("definitely not a session", encoding="utf-8")
    return root


# ---------------------------------------------------------------------------
# Wire codec
# ---------------------------------------------------------------------------


def test_file_result_wire_roundtrip_with_findings() -> None:
    report = scan_path(MIXED_DIR, recursive=True)
    assert report.files, "mixed fixture should produce results"
    for fr in report.files:
        back = FileResult.from_wire(fr.to_wire())
        assert back == fr
        assert back.findings == fr.findings


def test_finding_from_dict_roundtrip() -> None:
    report = scan_path(MIXED_DIR, recursive=True)
    findings = [f for fr in report.files for f in fr.findings]
    assert findings, "mixed fixture should produce findings"
    for f in findings:
        assert Finding.from_dict(f.to_dict()) == f


def test_wire_roundtrip_skipped_result() -> None:
    fr = FileResult(path="x/y.jsonl", verdict="skipped", skipped_reason="symlink-skipped")
    assert FileResult.from_wire(fr.to_wire()) == fr


# ---------------------------------------------------------------------------
# Determinism: parallel output is byte-identical to sequential
# ---------------------------------------------------------------------------


def test_parallel_output_byte_identical(tmp_path: Path) -> None:
    tree = _build_tree(tmp_path / "tree")
    seq = scan_path(tree, recursive=True, jobs=1)
    par = scan_path(tree, recursive=True, jobs=4)
    assert seq.to_json() == par.to_json()
    assert seq.totals == par.totals
    assert [f.path for f in seq.files] == [f.path for f in par.files]


def test_parallel_repeat_runs_identical(tmp_path: Path) -> None:
    tree = _build_tree(tmp_path / "tree")
    a = scan_path(tree, recursive=True, jobs=4)
    b = scan_path(tree, recursive=True, jobs=4)
    assert a.to_json() == b.to_json()


def test_parallel_mixed_fixture_matches_sequential() -> None:
    seq = scan_path(MIXED_DIR, recursive=True, jobs=1)
    par = scan_path(MIXED_DIR, recursive=True, jobs=3)
    assert seq.to_json() == par.to_json()
    assert seq.totals.total >= 4


def test_parallel_progress_emits_in_file_order(tmp_path: Path) -> None:
    tree = _build_tree(tmp_path / "tree", copies=6)
    items: list[str | None] = []

    def cb(ev: object) -> None:
        items.append(getattr(ev, "item", None))

    scan_path(tree, recursive=True, jobs=3, progress_cb=cb)
    scanned = sorted(p.name for p in tree.rglob("*") if p.is_file())
    assert sorted(i for i in items if i is not None) == scanned


# ---------------------------------------------------------------------------
# Validation & CLI wiring
# ---------------------------------------------------------------------------


def test_jobs_validation() -> None:
    with pytest.raises(ValueError, match="jobs"):
        scan_path(MIXED_DIR, recursive=True, jobs=0)
    with pytest.raises(ValueError, match="jobs"):
        scan_path(MIXED_DIR, recursive=True, jobs=-2)
    with pytest.raises(ValueError, match="jobs"):
        scan_path(MIXED_DIR, recursive=True, jobs=True)  # type: ignore[arg-type]


def test_single_file_ignores_jobs() -> None:
    seq = scan_path(HEALTHY, jobs=1)
    par = scan_path(HEALTHY, jobs=4)
    assert seq.to_json() == par.to_json()


def test_cli_scan_jobs_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    tree = _build_tree(tmp_path / "tree")
    code = main(["scan", str(tree), "--json", "--jobs", "4"])
    assert code in (0, 1)
    data = json.loads(capsys.readouterr().out)
    assert data["schema_version"] == "sesslint.scan-report/v1"
    assert data["totals"]["total"] == len(data["files"])


def test_cli_scan_jobs_auto(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    tree = _build_tree(tmp_path / "tree")
    code = main(["scan", str(tree), "--json", "--jobs", "auto"])
    assert code in (0, 1)
    json.loads(capsys.readouterr().out)


def test_cli_scan_jobs_invalid(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    tree = _build_tree(tmp_path / "tree")
    code = main(["scan", str(tree), "--jobs", "bogus"])
    assert code == 2
    assert "--jobs" in capsys.readouterr().err


def test_cli_scan_jobs_single_file_note(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["scan", str(HEALTHY), "--jobs", "4"])
    captured = capsys.readouterr()
    assert code == 0
    assert "ignored for single-file" in captured.err


def test_api_check_dir_jobs_passthrough(tmp_path: Path) -> None:
    tree = _build_tree(tmp_path / "tree")
    seq: ScanReport = check_dir(tree, recursive=True, jobs=1)
    par: ScanReport = check_dir(tree, recursive=True, jobs=3)
    assert seq.to_json() == par.to_json()
