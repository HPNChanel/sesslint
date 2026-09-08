"""Smoke test for benchmark generator and assertions (RVW-037)."""

from __future__ import annotations

import tempfile
from pathlib import Path

from bench.perf_250k import generate_benchmark_file, run_benchmark

from sesslint import api


def test_bench_smoke_assertions() -> None:
    """Verify that benchmark synthetic generator produces 0 findings and assurance A3."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        bench_file = Path(tmp_dir) / "smoke_bench.jsonl"
        generate_benchmark_file(bench_file, num_records=2000)

        report = api.check_file(bench_file)
        assert len(report.findings) == 0
        assert report.assurance == "A3"
        assert report.counts.by_severity.get("error", 0) == 0
        assert report.counts.by_severity.get("warning", 0) == 0

        result = run_benchmark(records=2000, time_budget=10.0, mem_budget=512.0)
        assert result == 0


def test_bench_functional_failure_not_excused() -> None:
    """Verify that functional failures return exit code 1 and cannot be excused (RVW-037)."""
    from unittest.mock import patch

    from sesslint.codes import SL001, Repairability, Severity
    from sesslint.finding import SourceRef, make_finding
    from sesslint.report import build_report

    mock_finding = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Synthetic failure for test",
        source=SourceRef(path="mock.jsonl", line=1),
    )
    bad_report = build_report(
        session_id="mock",
        source_fingerprint="0" * 64,
        tool_version="0.1.0",
        findings=[mock_finding],
        assurance="A0",
        limitation="No structural conclusion.",
    )

    with patch("sesslint.api.check_file", return_value=bad_report):
        result = run_benchmark(records=100, time_budget=10.0, mem_budget=512.0)
        # MUST return 1 despite bench/PERF_NOTES.md existing
        assert result == 1

