"""Tests for hostile negative corpus evaluated against EXPECTATIONS.json (TASK-027).

Guarantees:
- Every hostile fixture fails closed with its designated code and exit status (FR-011..017).
- Hostile error fixtures never verdict healthy (FR-049).
- Non-repairable hostile inputs block repair safely without publishing corrupted outputs.
"""

from __future__ import annotations

import json
from pathlib import Path

from sesslint.api import check_file
from sesslint.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "hostile"
EXPECTATIONS_PATH = FIXTURES_DIR / "EXPECTATIONS.json"


def test_hostile_corpus_expectations() -> None:
    """Evaluate every hostile fixture against EXPECTATIONS.json."""
    assert EXPECTATIONS_PATH.is_file(), f"Missing {EXPECTATIONS_PATH}"
    expectations: dict[str, dict[str, object]] = json.loads(
        EXPECTATIONS_PATH.read_text(encoding="utf-8")
    )

    for rel_path, spec in expectations.items():
        fixture_file = FIXTURES_DIR / rel_path
        assert fixture_file.exists(), f"Fixture file not found: {fixture_file}"

        expected_code = spec.get("code")
        expected_exit = int(str(spec["exit"]))

        # 1. Test programmatic check_file
        report = check_file(fixture_file)
        if expected_exit != 0:
            assert report.assurance == "A0", (
                f"{rel_path}: Expected A0 assurance, got {report.assurance}"
            )
            assert len(report.findings) > 0, f"{rel_path}: Expected findings on hostile input"
            if expected_code is not None:
                finding_codes = {f.code for f in report.findings}
                assert expected_code in finding_codes, (
                    f"{rel_path}: Expected {expected_code} in findings, got {finding_codes}"
                )
        else:
            # Clean fixture (like crlf_mixed or identical duplicate under neutral)
            has_error = (
                report.counts.by_severity.get("error", 0) > 0
                or report.counts.by_severity.get("fatal", 0) > 0
            )
            assert not has_error, f"{rel_path}: Expected zero errors on exit 0 fixture"

        # 2. Test CLI check exit code
        cli_exit = main(["check", str(fixture_file)])
        assert cli_exit == expected_exit, (
            f"{rel_path}: Expected CLI exit {expected_exit}, got {cli_exit}"
        )


def test_hostile_repair_refusal_on_non_repairable(tmp_path: Path) -> None:
    """Non-repairable hostile inputs safely refuse or block repair without corrupted output."""
    expectations: dict[str, dict[str, object]] = json.loads(
        EXPECTATIONS_PATH.read_text(encoding="utf-8")
    )

    for rel_path, spec in expectations.items():
        if not spec.get("repairable", False) and spec.get("exit") != 0:
            fixture_file = FIXTURES_DIR / rel_path
            out_file = tmp_path / f"repaired_{fixture_file.name}.json"

            # Attempt repair via CLI
            exit_code = main(["repair", str(fixture_file), "--output", str(out_file)])
            # Should fail closed (exit 1 or 2) and must not produce valid completed file
            assert exit_code != 0, (
                f"{rel_path}: Non-repairable hostile input should not exit 0 on repair"
            )
            if out_file.exists():
                # If file exists, it must not be valid healthy session
                rep = check_file(out_file)
                has_err = (
                    rep.counts.by_severity.get("error", 0) > 0
                    or rep.counts.by_severity.get("fatal", 0) > 0
                )
                assert has_err or rep.counts.total > 0
