"""Tests proving that error sessions never verdict clean or healthy (FR-049, AC-021).

Professor Tom standard:
"Fail-closed invariant: Under no circumstance shall an erroneous or hostile session
be certified as healthy. The system must degrade gracefully and fail closed."
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.api import check_dir, check_file
from sesslint.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "hostile"
EXPECTATIONS_PATH = FIXTURES_DIR / "EXPECTATIONS.json"


@pytest.fixture(scope="module")
def hostile_error_fixtures() -> list[tuple[str, Path]]:
    """Return all hostile fixtures expected to fail (exit != 0)."""
    assert EXPECTATIONS_PATH.is_file()
    expectations: dict[str, dict[str, object]] = json.loads(
        EXPECTATIONS_PATH.read_text(encoding="utf-8")
    )
    error_list: list[tuple[str, Path]] = []
    for rel_path, spec in expectations.items():
        if int(str(spec["exit"])) != 0:
            p = FIXTURES_DIR / rel_path
            assert p.exists(), f"Fixture file missing: {p}"
            error_list.append((rel_path, p))
    return error_list


def test_hostile_fixtures_never_verdict_clean_in_api(
    hostile_error_fixtures: list[tuple[str, Path]],
) -> None:
    """Every error fixture must yield A0 assurance and non-zero error counts via API."""
    for rel_path, path in hostile_error_fixtures:
        report = check_file(path)
        assert report.assurance == "A0", (
            f"{rel_path}: Expected assurance A0 on error fixture, got {report.assurance}"
        )
        assert len(report.findings) > 0, f"{rel_path}: Findings list cannot be empty"

        err_count = report.counts.by_severity.get("error", 0) + report.counts.by_severity.get(
            "fatal", 0
        )
        assert err_count > 0, (
            f"{rel_path}: Expected >= 1 error/fatal finding, got {report.counts.by_severity}"
        )


def test_hostile_fixtures_never_verdict_clean_in_cli_human(
    hostile_error_fixtures: list[tuple[str, Path]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """CLI check in human mode must exit != 0 and never display 'Valid' or success."""
    for rel_path, path in hostile_error_fixtures:
        code = main(["check", str(path)])
        assert code != 0, f"{rel_path}: CLI exit code must be non-zero, got {code}"
        captured = capsys.readouterr()
        out_lower = captured.out.lower()
        assert "valid canonical session" not in out_lower
        assert "valid claude code session" not in out_lower
        assert "valid openai agents session" not in out_lower


def test_hostile_fixtures_never_verdict_clean_in_cli_json(
    hostile_error_fixtures: list[tuple[str, Path]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """CLI check in JSON mode must output non-healthy report."""
    for rel_path, path in hostile_error_fixtures:
        code = main(["check", str(path), "--json"])
        assert code != 0, f"{rel_path}: JSON CLI exit code must be non-zero, got {code}"
        captured = capsys.readouterr()
        # Ensure valid JSON output
        parsed = json.loads(captured.out)
        if "verdict" in parsed:
            assert parsed["verdict"] != "clean", f"{rel_path}: Verdict was marked clean"
            assert parsed["verdict"] != "healthy", f"{rel_path}: Verdict was marked healthy"
        if "assurance" in parsed:
            assert parsed["assurance"] == "A0", (
                f"{rel_path}: Assurance must be A0, got {parsed['assurance']}"
            )
        if "findings" in parsed:
            assert len(parsed["findings"]) > 0, f"{rel_path}: JSON findings empty"


def test_recursive_directory_scan_detects_all_hostile() -> None:
    """Recursive directory scan of hostile directory must report failures and exit 1."""
    report = check_dir(FIXTURES_DIR, recursive=True)
    # Total invalid files should be > 0
    assert (
        report.totals.invalid > 0 or report.totals.unsupported > 0 or report.totals.unreadable > 0
    )
    # Hostile directory should have non-zero invalid files and scanning should complete
    assert report.totals.total > 0

    # CLI check on directory without -r exits 2
    code_no_r = main(["check", str(FIXTURES_DIR)])
    assert code_no_r == 2

    # CLI check with -r exits 1
    code_r = main(["check", str(FIXTURES_DIR), "-r"])
    assert code_r == 1
