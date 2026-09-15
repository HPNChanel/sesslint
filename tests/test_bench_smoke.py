"""Smoke test for benchmark generator and assertions (RVW-037)."""

from __future__ import annotations

import tempfile
from pathlib import Path

import bench.perf_250k as perf_250k
import pytest
from bench.perf_250k import (
    generate_benchmark_file,
    run_benchmark,
    verify_reference_disclosure_recorded,
)

from sesslint import api


def test_bench_smoke_assertions() -> None:
    """Verify that benchmark synthetic generator produces 0 findings and assurance A3."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        bench_file = Path(tmp_dir) / "smoke_bench.jsonl"
        generate_benchmark_file(bench_file, num_records=2000)

        report = api.check_file(bench_file)
        assert len(report.findings) == 0
        assert report.assurance == "A4"
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


# ---------------------------------------------------------------------------
# Reference-baseline disclosure contract (T-05)
# ---------------------------------------------------------------------------

_VALID_BLOCK = """\
<!-- REFERENCE-BASELINE:BEGIN -->
- Run ID: 2026-09-15-perf-250k-win32-amd64
- Date: 2026-09-15
- Host: AMD64 / win32 / CPython 3.11.9
- Records: 250000
- Input size MB: 99.45
- Streaming parse s: 5.647
- Integrity check s: 16.782
- Total time s: 22.429
- Time budget s: 15.0
- Peak RSS MB: 785.90
- Memory budget MB: 512.0
- Breach classes: time, memory
- Status: BREACH — DISCLOSED
<!-- REFERENCE-BASELINE:END -->
"""


def _write_notes(tmp_path: Path, block: str) -> None:
    notes_dir = tmp_path / "bench"
    notes_dir.mkdir(parents=True, exist_ok=True)
    (notes_dir / "PERF_NOTES.md").write_text("# Perf notes\n\n" + block + "\n", encoding="utf-8")


def _fields(**overrides: str) -> str:
    base = {
        "Run ID": "2026-09-15-perf-250k-win32-amd64",
        "Date": "2026-09-15",
        "Host": "AMD64 / win32 / CPython 3.11.9",
        "Records": "250000",
        "Input size MB": "99.45",
        "Total time s": "22.429",
        "Time budget s": "15.0",
        "Peak RSS MB": "785.90",
        "Memory budget MB": "512.0",
        "Breach classes": "time, memory",
        "Status": "BREACH — DISCLOSED",
    }
    base.update(overrides)
    body = "\n".join(f"- {k}: {v}" for k, v in base.items() if v is not None)
    return f"<!-- REFERENCE-BASELINE:BEGIN -->\n{body}\n<!-- REFERENCE-BASELINE:END -->\n"


def test_reference_validator_accepts_committed_block() -> None:
    """The committed PERF_NOTES.md reference baseline validates cleanly."""
    assert verify_reference_disclosure_recorded() is True


def test_reference_validator_missing_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A reference block missing required fields fails validation."""
    monkeypatch.setattr(perf_250k, "_REPO_ROOT", tmp_path)
    _write_notes(tmp_path, _fields(**{"Input size MB": ""}))
    assert verify_reference_disclosure_recorded() is False


def test_reference_validator_stale_status_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Status PASS while recorded values breach budgets fails validation."""
    monkeypatch.setattr(perf_250k, "_REPO_ROOT", tmp_path)
    _write_notes(tmp_path, _fields(Status="PASS"))
    assert verify_reference_disclosure_recorded() is False


def test_reference_validator_partial_breach_classes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Declaring only a subset of derived breach classes fails validation."""
    monkeypatch.setattr(perf_250k, "_REPO_ROOT", tmp_path)
    _write_notes(tmp_path, _fields(**{"Breach classes": "time"}))
    assert verify_reference_disclosure_recorded() is False


def test_reference_validator_missing_date_or_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Missing date or host fails; host may only be honest text incl. unknown."""
    monkeypatch.setattr(perf_250k, "_REPO_ROOT", tmp_path)
    _write_notes(tmp_path, _fields(Date=""))
    assert verify_reference_disclosure_recorded() is False
    _write_notes(tmp_path, _fields(Host=""))
    assert verify_reference_disclosure_recorded() is False


def test_reference_validator_no_markers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Notes without a reference-baseline block fail validation."""
    monkeypatch.setattr(perf_250k, "_REPO_ROOT", tmp_path)
    _write_notes(tmp_path, "no markers here\n")
    assert verify_reference_disclosure_recorded() is False


def test_reference_validator_pass_run_consistent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A within-budget reference block with classes 'none' and status PASS passes."""
    monkeypatch.setattr(perf_250k, "_REPO_ROOT", tmp_path)
    _write_notes(
        tmp_path,
        _fields(
            **{
                "Total time s": "9.5",
                "Peak RSS MB": "180.0",
                "Breach classes": "none",
                "Status": "PASS",
            }
        ),
    )
    assert verify_reference_disclosure_recorded() is True


def test_benchmark_current_run_disclosure_on_breach(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A breaching run's own output carries measured values, budgets, breach
    classes, and run context — the run discloses itself before returning 1."""
    result = run_benchmark(records=100, time_budget=0.0, mem_budget=0.0)
    assert result == 1
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "Run context:" in captured.out
    assert "date=" in captured.out
    assert "host=" in captured.out
    assert "Breach classes: time, memory" in combined
    assert "budget" in combined.lower()


def test_benchmark_breach_nonzero_even_with_valid_reference(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A valid committed reference baseline never converts a breach into a pass."""
    assert verify_reference_disclosure_recorded() is True
    result = run_benchmark(records=100, time_budget=0.0, mem_budget=0.0)
    assert result == 1
    capsys.readouterr()
