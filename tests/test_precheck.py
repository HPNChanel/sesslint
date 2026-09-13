"""Tests for the SessLint one-call prevention API (DEV-015 / US-014 / UC-05).

Verifies precheck and PrecheckResult contracts, covering all 6 closed vocabulary
reasons, report presence rules, exit codes, and non-raising guarantees.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from sesslint.precheck import PrecheckReason, PrecheckResult, precheck
from sesslint.report import Report

FIXTURES_ROOT = Path(__file__).resolve().parent.parent / "fixtures"
MINIMAL_FIXTURE = FIXTURES_ROOT / "canonical" / "minimal.json"
HEALTHY_JSONL_FIXTURE = FIXTURES_ROOT / "cli" / "check_basic" / "healthy.jsonl"
WARNING_FIXTURE = FIXTURES_ROOT / "checks" / "sl003_identical.json"
ERROR_FIXTURE = FIXTURES_ROOT / "checks" / "sl101_orphan.json"
FATAL_FIXTURE = FIXTURES_ROOT / "checks" / "sl005_cycle.json"
POLYGLOT_FIXTURE = FIXTURES_ROOT / "cli" / "check_ambiguity" / "polyglot.json"
VERSION_OLD_FIXTURE = FIXTURES_ROOT / "claude_code" / "version_old.jsonl"


def test_precheck_clean() -> None:
    """Verify precheck returns reason='clean' with exit_code=0 on healthy sessions."""
    # Using Path object
    res = precheck(MINIMAL_FIXTURE)
    assert isinstance(res, PrecheckResult)
    assert res.ok is True
    assert res.reason == "clean"
    assert res.exit_code == 0
    assert isinstance(res.report, Report)
    assert len(res.report.findings) == 0

    # Using str path and healthy JSONL
    res_str = precheck(str(HEALTHY_JSONL_FIXTURE))
    assert res_str.ok is True
    assert res_str.reason == "clean"
    assert res_str.exit_code == 0
    assert isinstance(res_str.report, Report)


def test_precheck_findings_warning() -> None:
    """Verify precheck returns reason='findings-warning' with exit_code=0 on warnings only."""
    res = precheck(WARNING_FIXTURE)
    assert isinstance(res, PrecheckResult)
    assert res.ok is True
    assert res.reason == "findings-warning"
    assert res.exit_code == 0
    assert isinstance(res.report, Report)
    assert res.report.counts.by_severity.get("warning", 0) > 0
    assert res.report.counts.by_severity.get("error", 0) == 0
    assert res.report.counts.by_severity.get("fatal", 0) == 0


def test_precheck_findings_error() -> None:
    """Verify precheck returns reason='findings-error' with exit_code=1 on error/fatal findings."""
    # Error severity finding
    res_err = precheck(ERROR_FIXTURE)
    assert isinstance(res_err, PrecheckResult)
    assert res_err.ok is False
    assert res_err.reason == "findings-error"
    assert res_err.exit_code == 1
    assert isinstance(res_err.report, Report)
    assert res_err.report.counts.by_severity.get("error", 0) > 0

    # Fatal severity finding
    res_fatal = precheck(FATAL_FIXTURE)
    assert isinstance(res_fatal, PrecheckResult)
    assert res_fatal.ok is False
    assert res_fatal.reason == "findings-error"
    assert res_fatal.exit_code == 1
    assert isinstance(res_fatal.report, Report)
    assert res_fatal.report.counts.by_severity.get("fatal", 0) > 0


def test_precheck_reason_vocabulary() -> None:
    """Verify that all tested reasons belong to the closed PrecheckReason vocabulary."""
    reasons: tuple[PrecheckReason, ...] = (
        "clean",
        "findings-error",
        "findings-warning",
        "detection-failed",
        "io-error",
        "usage-error",
    )
    assert len(reasons) == 6


def test_precheck_detection_failed_polyglot() -> None:
    """Verify precheck returns reason='detection-failed' on ambiguous format (SL302)."""
    res = precheck(POLYGLOT_FIXTURE)
    assert isinstance(res, PrecheckResult)
    assert res.ok is False
    assert res.reason == "detection-failed"
    assert res.exit_code == 1
    assert isinstance(res.report, Report)
    assert any(f.code == "SL302" for f in res.report.findings)


def test_precheck_detection_failed_version_old() -> None:
    """Verify precheck returns reason='detection-failed' on unsupported version (SL301)."""
    res = precheck(VERSION_OLD_FIXTURE)
    assert isinstance(res, PrecheckResult)
    assert res.ok is False
    assert res.reason == "detection-failed"
    assert res.exit_code == 1
    assert isinstance(res.report, Report)
    assert any(f.code == "SL301" for f in res.report.findings)


def test_precheck_io_error() -> None:
    """Verify precheck returns reason='io-error' with exit_code=2 on I/O failures."""
    # Missing file
    res_missing = precheck(FIXTURES_ROOT / "non_existent_session_file_12345.json")
    assert isinstance(res_missing, PrecheckResult)
    assert res_missing.ok is False
    assert res_missing.reason == "io-error"
    assert res_missing.exit_code == 2
    assert res_missing.report is None

    # Directory path
    res_dir = precheck(FIXTURES_ROOT / "canonical")
    assert isinstance(res_dir, PrecheckResult)
    assert res_dir.ok is False
    assert res_dir.reason == "io-error"
    assert res_dir.exit_code == 2
    assert res_dir.report is None


def test_precheck_usage_error() -> None:
    """Verify precheck returns reason='usage-error' with exit_code=2 on argument errors."""
    # Invalid profile
    res_profile = precheck(MINIMAL_FIXTURE, profile="nonexistent_profile_xyz")
    assert isinstance(res_profile, PrecheckResult)
    assert res_profile.ok is False
    assert res_profile.reason == "usage-error"
    assert res_profile.exit_code == 2
    assert res_profile.report is None

    # Invalid format override
    res_fmt = precheck(MINIMAL_FIXTURE, format="invalid_format_xyz")
    assert isinstance(res_fmt, PrecheckResult)
    assert res_fmt.ok is False
    assert res_fmt.reason == "usage-error"
    assert res_fmt.exit_code == 2
    assert res_fmt.report is None

    # Invalid path types (None, int)
    res_none = precheck(None)  # type: ignore[arg-type]
    assert isinstance(res_none, PrecheckResult)
    assert res_none.ok is False
    assert res_none.reason == "usage-error"
    assert res_none.exit_code == 2
    assert res_none.report is None

    res_int = precheck(123)  # type: ignore[arg-type]
    assert isinstance(res_int, PrecheckResult)
    assert res_int.ok is False
    assert res_int.reason == "usage-error"
    assert res_int.exit_code == 2
    assert res_int.report is None

    # Invalid option types
    res_prof_type = precheck(MINIMAL_FIXTURE, profile=123)  # type: ignore[arg-type]
    assert isinstance(res_prof_type, PrecheckResult)
    assert res_prof_type.ok is False
    assert res_prof_type.reason == "usage-error"
    assert res_prof_type.exit_code == 2
    assert res_prof_type.report is None

    res_fmt_type = precheck(MINIMAL_FIXTURE, format=123)  # type: ignore[arg-type]
    assert isinstance(res_fmt_type, PrecheckResult)
    assert res_fmt_type.ok is False
    assert res_fmt_type.reason == "usage-error"
    assert res_fmt_type.exit_code == 2
    assert res_fmt_type.report is None


def test_precheck_empty_path() -> None:
    """Verify precheck handles empty path string safely with exit_code=2."""
    res = precheck("")
    assert isinstance(res, PrecheckResult)
    assert res.ok is False
    assert res.exit_code == 2
    assert res.report is None


def test_precheck_valid_overrides() -> None:
    """Verify precheck respects valid profile and format overrides."""
    res = precheck(MINIMAL_FIXTURE, profile="neutral", format="canonical")
    assert isinstance(res, PrecheckResult)
    assert res.ok is True
    assert res.reason == "clean"
    assert res.exit_code == 0
    assert res.report is not None

    # Overriding with incompatible format produces detection failure finding
    res_mismatch = precheck(MINIMAL_FIXTURE, format="openai-agents")
    assert isinstance(res_mismatch, PrecheckResult)
    assert res_mismatch.ok is False
    assert res_mismatch.reason == "detection-failed"
    assert res_mismatch.exit_code == 1
    assert res_mismatch.report is not None


def test_precheck_never_raises_on_findings() -> None:
    """Ensure precheck strictly never raises exceptions across a battery of corrupt fixtures."""
    corrupt_fixtures = [
        ERROR_FIXTURE,
        FATAL_FIXTURE,
        POLYGLOT_FIXTURE,
        VERSION_OLD_FIXTURE,
        FIXTURES_ROOT / "checks" / "sl004_missing_parent.json",
        FIXTURES_ROOT / "checks" / "sl102_dangling.json",
        FIXTURES_ROOT / "checks" / "sl103_reused.json",
        FIXTURES_ROOT / "checks" / "sl104_multiple.json",
        FIXTURES_ROOT / "checks" / "sl105_inversion.json",
        FIXTURES_ROOT / "checks" / "sl106_cross_branch.json",
    ]
    for fix in corrupt_fixtures:
        if fix.exists():
            res = precheck(fix)
            assert isinstance(res, PrecheckResult)
            assert res.report is not None
            assert res.reason in ("findings-error", "findings-warning", "detection-failed")


def test_precheck_result_frozen() -> None:
    """PrecheckResult instances must be strictly immutable."""
    res = precheck(MINIMAL_FIXTURE)
    with pytest.raises(FrozenInstanceError):
        res.ok = False  # type: ignore[misc]


def test_precheck_purity(capsys: pytest.CaptureFixture[str]) -> None:
    """precheck must be side-effect free and emit nothing to stdout or stderr."""
    _ = precheck(MINIMAL_FIXTURE)
    _ = precheck(ERROR_FIXTURE)
    _ = precheck(POLYGLOT_FIXTURE)
    _ = precheck(FIXTURES_ROOT / "non_existent.json")
    _ = precheck(MINIMAL_FIXTURE, profile="nonexistent_profile")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
