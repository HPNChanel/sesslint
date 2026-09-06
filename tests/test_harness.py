"""Tests for the conformance harness and golden fixture execution."""

from __future__ import annotations

from pathlib import Path

import pytest

from sesslint.canonical import canonical_bytes, to_canonical_json
from tests.harness.conformance import CASES, Case, assert_case, discover_cases, run_case
from tests.utils.determinism import assert_deterministic


def test_harness_discovers_minimum_cases() -> None:
    """Verify that discovery locates at least 8 valid golden cases."""
    assert len(CASES) >= 8, f"Expected at least 8 golden cases, found {len(CASES)}"


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.name)
def test_conformance_case_matches_expected(case: Case) -> None:
    """Run every discovered golden case and assert full counts and findings match."""
    assert_case(case)


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.name)
def test_conformance_case_report_is_deterministic(case: Case) -> None:
    """Verify that repeated report generation for each case produces byte-identical results."""

    def _generate_report_bytes() -> bytes:
        report = run_case(case)
        return canonical_bytes(to_canonical_json(report))

    assert_deterministic(_generate_report_bytes, runs=3)


def test_assert_case_fails_on_tampered_counts() -> None:
    """Verify that assert_case loudly fails with diff when expected counts are tampered."""
    valid_case = CASES[0]
    tampered_expected = dict(valid_case.expected)
    tampered_expected["counts"] = {
        "total": 999,
        "by_severity": {"fatal": 999, "error": 0, "warning": 0, "info": 0},
        "by_code": {},
    }
    tampered_case = Case(
        name="tampered_test",
        input_path=valid_case.input_path,
        expected_path=valid_case.expected_path,
        expected=tampered_expected,
    )

    with pytest.raises(AssertionError, match="Counts mismatch"):
        assert_case(tampered_case)


def test_assert_case_fails_on_tampered_findings() -> None:
    """Verify that assert_case loudly fails with diff when expected findings are tampered."""
    valid_case = CASES[0]
    tampered_expected = dict(valid_case.expected)
    tampered_expected["findings"] = [
        {
            "code": "SL001",
            "severity": "fatal",
            "line": 9999,
            "record_id": "nonexistent",
        }
    ]
    tampered_case = Case(
        name="tampered_findings_test",
        input_path=valid_case.input_path,
        expected_path=valid_case.expected_path,
        expected=tampered_expected,
    )

    with pytest.raises(AssertionError, match="Findings mismatch"):
        assert_case(tampered_case)


def test_discover_cases_missing_input_raises(tmp_path: Path) -> None:
    """discover_cases raises FileNotFoundError if .expected.json lacks .jsonl input."""
    orphan_expected = tmp_path / "orphan.expected.json"
    orphan_expected.write_text("{}", encoding="utf-8")

    with pytest.raises(FileNotFoundError, match="Missing input fixture"):
        discover_cases(tmp_path)


def test_discover_cases_nonexistent_root() -> None:
    """discover_cases returns empty list when root directory does not exist."""
    assert discover_cases(Path("nonexistent_directory_abc123")) == []
