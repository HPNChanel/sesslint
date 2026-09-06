"""Tests for recursive scan aggregate 5-bucket totals (TASK-024)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.api import check_dir
from sesslint.cli import main
from sesslint.scan import ScanReport

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "scan"


def test_aggregate_5_bucket_partitioning() -> None:
    """Scan of mixed fixture dir partitions files into 5 mutually exclusive buckets."""
    mixed_dir = FIXTURES_DIR / "mixed"
    report: ScanReport = check_dir(mixed_dir, recursive=True)

    totals = report.totals
    # Assert each active bucket has at least 1 file
    assert totals.healthy >= 1, "Expected at least 1 healthy file"
    assert totals.invalid >= 1, "Expected at least 1 invalid file"
    assert totals.unsupported >= 1, "Expected at least 1 unsupported file"
    assert totals.unreadable >= 1, "Expected at least 1 unreadable file"

    # Mutual exclusivity and complete sum invariant
    total_sum = (
        totals.healthy + totals.invalid + totals.unsupported + totals.unreadable + totals.skipped
    )
    assert total_sum == totals.total
    assert totals.total == len(report.files)

    # Verify per-file verdict mapping
    verdicts = {f.verdict for f in report.files}
    assert "healthy" in verdicts
    assert "invalid" in verdicts
    assert "unsupported" in verdicts
    assert "unreadable" in verdicts


def test_cli_scan_mixed_dir_exit_code_1(capsys: pytest.CaptureFixture[str]) -> None:
    """CLI check on mixed directory exits 1 due to invalid/unsupported/unreadable files."""
    mixed_dir = FIXTURES_DIR / "mixed"
    code = main(["check", str(mixed_dir), "--recursive", "--json"])
    assert code == 1

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["schema_version"] == "sesslint.scan-report/v1"
    assert data["totals"]["total"] == len(data["files"])
    assert data["totals"]["healthy"] >= 1
    assert data["totals"]["invalid"] >= 1
    assert data["totals"]["unsupported"] >= 1
    assert data["totals"]["unreadable"] >= 1


def test_cli_scan_without_recursive_flag_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Passing a directory without --recursive exits with code 2."""
    code = main(["check", str(tmp_path)])
    assert code == 2
    captured = capsys.readouterr()
    assert "--recursive" in captured.err
