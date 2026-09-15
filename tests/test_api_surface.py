"""Tests for the SessLint public programmatic library API (DEV-010 / TASK-024)."""

from __future__ import annotations

from pathlib import Path

import pytest

from sesslint import api
from sesslint.repair import RepairPlan
from sesslint.repair.errors import RepairRefused
from sesslint.report import Report
from sesslint.scan import ScanReport
from sesslint.verify import Verdict

FIXTURES_ROOT = Path(__file__).resolve().parent.parent / "fixtures"
HEALTHY_FIXTURE = FIXTURES_ROOT / "cli" / "check_basic" / "healthy.jsonl"
POLYGLOT_FIXTURE = FIXTURES_ROOT / "cli" / "check_ambiguity" / "polyglot.json"
SCAN_DIR = FIXTURES_ROOT / "scan" / "mixed"
VERIFY_DIR = FIXTURES_ROOT / "verify" / "ok"


def test_api_module_exports() -> None:
    """Verify sesslint.api exports the mandatory programmatic surface."""
    expected_exports = {
        "Bundle",
        "PrecheckReason",
        "PrecheckResult",
        "ScanReport",
        "VerifyVerdict",
        "build_bundle",
        "build_internal_error_envelope",
        "check",
        "check_dir",
        "check_file",
        "plan",
        "precheck",
        "repair",
        "validate_session",
        "verify",
    }
    assert expected_exports.issubset(set(api.__all__))
    for name in expected_exports:
        assert hasattr(api, name)

    # Verify Verdict alias
    assert api.VerifyVerdict is Verdict


def test_check_file_contract() -> None:
    """Verify check_file return types, parameters, and contracts."""
    # Path argument
    report = api.check_file(HEALTHY_FIXTURE)
    assert isinstance(report, Report)
    assert report.session_id is not None
    assert report.assurance in ("A0", "A1", "A2", "A3", "A4")
    assert report.counts is not None

    # String argument
    report_str = api.check_file(str(HEALTHY_FIXTURE))
    assert isinstance(report_str, Report)
    assert report_str.session_id == report.session_id

    # Format parameter
    report_fmt = api.check_file(HEALTHY_FIXTURE, format="canonical")
    assert isinstance(report_fmt, Report)

    # Profile parameter
    report_prof = api.check_file(HEALTHY_FIXTURE, profile="neutral")
    assert isinstance(report_prof, Report)

    # Missing file raises FileNotFoundError
    with pytest.raises(FileNotFoundError):
        api.check_file("non_existent_file_path_12345.jsonl")


def test_check_file_purity(capsys: pytest.CaptureFixture[str]) -> None:
    """api.check_file must be pure and emit nothing to stdout or stderr."""
    _ = api.check_file(HEALTHY_FIXTURE)
    _ = api.check_file(POLYGLOT_FIXTURE)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_check_dir_contract() -> None:
    """Verify check_dir return types, parameters, and scan totals."""
    # Basic directory scan
    scan_rep = api.check_dir(SCAN_DIR, recursive=True)
    assert isinstance(scan_rep, ScanReport)
    assert scan_rep.totals.total > 0
    assert scan_rep.totals.healthy >= 0
    assert scan_rep.totals.invalid >= 0
    assert isinstance(scan_rep.files, tuple)

    # Parameters: max_files, max_bytes
    bounded_scan = api.check_dir(
        SCAN_DIR,
        recursive=True,
        max_files=2,
        max_bytes=10000,
    )
    assert isinstance(bounded_scan, ScanReport)

    # Directory with recursive=False raises ValueError
    with pytest.raises(ValueError, match="Recursive scanning requires recursive=True"):
        api.check_dir(SCAN_DIR, recursive=False)

    # Missing directory raises FileNotFoundError
    with pytest.raises(FileNotFoundError):
        api.check_dir("non_existent_directory_12345")


def test_repair_and_plan_contract(tmp_path: Path) -> None:
    """Verify repair and plan library functions."""
    # plan() generates a RepairPlan without touching disk
    torn_src = tmp_path / "torn.jsonl"
    torn_src.write_text(
        '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"s_repair"}\n'
        '{"actor":"user","id":"e0","kind":"message","parent_id":null,"payload":{"text":"hi"},"seq":0,"ts":"2026-09-05T12:00:00Z"}\n'
        '{"id":"e1_torn", "actor":"tool", "payload":',
        encoding="utf-8",
    )

    plan_obj = api.plan(torn_src)
    assert isinstance(plan_obj, RepairPlan)
    assert plan_obj.profile == "neutral"
    assert len(plan_obj.steps) > 0

    # dry_run returns plan and None manifest
    dry_plan, dry_manifest = api.repair(torn_src, output_path=None, dry_run=True)
    assert isinstance(dry_plan, RepairPlan)
    assert dry_manifest is None

    # Full repair writes output and returns manifest
    out_file = tmp_path / "repaired.jsonl"
    exec_plan, exec_manifest = api.repair(torn_src, output_path=out_file, dry_run=False)
    assert isinstance(exec_plan, RepairPlan)
    assert exec_manifest is not None
    assert out_file.exists()

    # Repair without output_path on dry_run=False raises ValueError
    with pytest.raises(ValueError, match="output_path is required"):
        api.repair(torn_src, output_path=None, dry_run=False)

    # Non-existent file raises FileNotFoundError
    with pytest.raises(FileNotFoundError):
        api.repair("non_existent_repair_src.jsonl", output_path=out_file)

    # Vendor formats are refused
    claude_fixture = FIXTURES_ROOT / "claude_code" / "basic.jsonl"
    with pytest.raises(RepairRefused, match="Direct repair of vendor format"):
        api.repair(claude_fixture, output_path=out_file)


def test_verify_contract() -> None:
    """Verify verify programmatic function contract."""
    src = VERIFY_DIR / "source.jsonl"
    plan_path = VERIFY_DIR / "plan.json"
    out = VERIFY_DIR / "output.jsonl"
    man = VERIFY_DIR / "manifest.json"

    verdict = api.verify(
        source_path=src,
        output_path=out,
        manifest_path=man,
        plan_path=plan_path,
    )
    assert isinstance(verdict, Verdict)
    assert verdict.ok is True
    assert isinstance(verdict.to_json(), str)


def test_build_bundle_contract() -> None:
    """Verify build_bundle programmatic function contract and returned Bundle instance."""
    bundle = api.build_bundle(HEALTHY_FIXTURE)
    assert isinstance(bundle, api.Bundle)
    assert bundle.bundle_version == "sesslint.bundle/v1"
    assert bundle.source["path"] == HEALTHY_FIXTURE.name
    assert isinstance(bundle.source["sha256"], str)
    assert len(bundle.source["sha256"]) == 64
    assert isinstance(bundle.source["size"], int)
    assert bundle.source["size"] > 0
    assert "tool" in bundle.created_by
    assert bundle.created_by["tool"] == "sesslint"
    assert "report" in bundle.to_dict()
    assert "fixture_skeleton" in bundle.to_dict()
    assert isinstance(bundle.to_json(), str)


def test_precheck_contract() -> None:
    """Verify precheck return types, parameters, and contract on public API surface."""
    from sesslint.precheck import PrecheckResult

    res = api.precheck(HEALTHY_FIXTURE)
    assert isinstance(res, PrecheckResult)
    assert res.ok is True
    assert res.reason == "clean"
    assert res.exit_code == 0
    assert isinstance(res.report, Report)

    # Missing file returns io-error result without raising
    res_missing = api.precheck("non_existent_file_path_12345.jsonl")
    assert isinstance(res_missing, PrecheckResult)
    assert res_missing.ok is False
    assert res_missing.reason == "io-error"
    assert res_missing.exit_code == 2
    assert res_missing.report is None

    # Invalid profile returns usage-error
    res_usage = api.precheck(HEALTHY_FIXTURE, profile="unknown_profile_xyz")
    assert isinstance(res_usage, PrecheckResult)
    assert res_usage.ok is False
    assert res_usage.reason == "usage-error"
    assert res_usage.exit_code == 2
    assert res_usage.report is None

    # Ambiguous format returns detection-failed with report attached
    res_ambig = api.precheck(FIXTURES_ROOT / "cli" / "check_ambiguity" / "polyglot.json")
    assert isinstance(res_ambig, PrecheckResult)
    assert res_ambig.ok is False
    assert res_ambig.reason == "detection-failed"
    assert res_ambig.exit_code == 1
    assert isinstance(res_ambig.report, Report)


def test_api_numeric_range_validation(tmp_path: Path) -> None:
    """Validate numeric ranges in programmatic API entry points (P1-02).

    Contract:
    1. max_files and max_bytes must be strictly positive (> 0) (ReaderLimits contract).
    2. Per sesslint.profiles.profile.resolve_effective_config lines 141-144:
       0.0 < confidence_min < 1.0 (finite float)
       0.0 < margin_min < 1.0 (finite float)
       Boundaries 0.0 and 1.0 are rejected, as well as NaN, inf, negatives, and > 1.0.
    """
    from sesslint.scan import scan_path

    # check_dir and scan_path: reject max_files <= 0 and max_bytes <= 0, including bool
    for bad_int in [0, -1, -500, True, False]:  # type: ignore[list-item]
        with pytest.raises(ValueError, match="max_files must be a positive integer"):
            api.check_dir(tmp_path, max_files=bad_int)
        with pytest.raises(ValueError, match="max_bytes must be a positive integer"):
            api.check_dir(tmp_path, max_bytes=bad_int)
        with pytest.raises(ValueError, match="max_files must be a positive integer"):
            scan_path(tmp_path, max_files=bad_int)
        with pytest.raises(ValueError, match="max_bytes must be a positive integer"):
            scan_path(tmp_path, max_bytes=bad_int)

    # check_file: reject confidence_min and margin_min outside (0.0, 1.0), including bool
    for bad_float in [0.0, 1.0, -0.5, 1.5, float("nan"), float("inf"), True, False]:  # type: ignore[list-item]
        with pytest.raises(ValueError, match="confidence_min must be strictly between"):
            api.check_file(HEALTHY_FIXTURE, confidence_min=bad_float)
        with pytest.raises(ValueError, match="margin_min must be strictly between"):
            api.check_file(HEALTHY_FIXTURE, margin_min=bad_float)

    # build_bundle: reject confidence_min and margin_min outside (0.0, 1.0), including bool
    for bad_float in [0.0, 1.0, -0.5, 1.5, float("nan"), float("inf"), True, False]:  # type: ignore[list-item]
        with pytest.raises(ValueError, match="confidence_min must be strictly between"):
            api.build_bundle(HEALTHY_FIXTURE, confidence_min=bad_float)
        with pytest.raises(ValueError, match="margin_min must be strictly between"):
            api.build_bundle(HEALTHY_FIXTURE, margin_min=bad_float)


# ---------------------------------------------------------------------------
# T-02: Effective detection threshold plumbing (post-alpha hardening)
# ---------------------------------------------------------------------------


def _patch_detector_scores(claude: float, openai: float, canonical: float):
    """Return patch triple pinning all three adapter detector scores."""
    from unittest.mock import patch

    return (
        patch("sesslint.adapters.detect.detect_claude_code", return_value=claude),
        patch("sesslint.adapters.detect.detect_openai_agents", return_value=openai),
        patch("sesslint.adapters.detect.detect_canonical", return_value=canonical),
    )


def _copy_healthy(dst_dir: Path, name: str) -> Path:
    """Copy the real healthy claude-code fixture into dst_dir/name."""
    dst = dst_dir / name
    dst.write_bytes(HEALTHY_FIXTURE.read_bytes())
    return dst


def test_check_file_threshold_override_alters_detection(tmp_path: Path) -> None:
    """check_file applies effective thresholds: 0.60 passes at 0.55, fails at 0.70."""
    p1, p2, p3 = _patch_detector_scores(0.60, 0.10, 0.10)
    with p1, p2, p3:
        report_ok = api.check_file(HEALTHY_FIXTURE)
        assert not any(f.code == "SL302" for f in report_ok.findings)

        report_strict = api.check_file(HEALTHY_FIXTURE, confidence_min=0.70)
        sl302 = [f for f in report_strict.findings if f.code == "SL302"]
        assert sl302, "expected SL302 ambiguous-format finding under raised threshold"
        assert sl302[0].evidence is not None
        assert sl302[0].evidence["confidence_min"] == 0.70


def test_check_dir_threshold_override_applies_once(tmp_path: Path) -> None:
    """check_dir applies effective thresholds to per-file detection."""
    _copy_healthy(tmp_path, "a.jsonl")
    _copy_healthy(tmp_path, "b.jsonl")

    p1, p2, p3 = _patch_detector_scores(0.60, 0.10, 0.10)
    with p1, p2, p3:
        rep_ok = api.check_dir(tmp_path)
        assert rep_ok.totals.healthy == 2
        assert rep_ok.totals.invalid == 0

        rep_strict = api.check_dir(tmp_path, confidence_min=0.70)
        assert rep_strict.totals.invalid == 2
        for fr in rep_strict.files:
            sl302 = [f for f in fr.findings if f.code == "SL302"]
            assert sl302 and sl302[0].evidence["confidence_min"] == 0.70


def test_scan_path_resolves_effective_config_once(tmp_path: Path) -> None:
    """scan_path resolves exactly one EffectiveConfig for a whole directory scan."""
    import sesslint.scan as scan_mod

    for name in ("a.jsonl", "b.jsonl", "c.jsonl"):
        _copy_healthy(tmp_path, name)

    calls = 0
    real_resolve = scan_mod.resolve_effective_config

    def counting_resolve(*args: object, **kwargs: object):
        nonlocal calls
        calls += 1
        return real_resolve(*args, **kwargs)

    from unittest.mock import patch

    with patch.object(scan_mod, "resolve_effective_config", side_effect=counting_resolve):
        rep = scan_mod.scan_path(tmp_path, recursive=True)
    assert rep.totals.healthy == 3
    assert calls == 1


def test_check_unified_forwards_thresholds_to_dir(tmp_path: Path) -> None:
    """api.check on a directory forwards effective thresholds to the scan path."""
    _copy_healthy(tmp_path, "a.jsonl")
    p1, p2, p3 = _patch_detector_scores(0.60, 0.10, 0.10)
    with p1, p2, p3:
        rep = api.check(tmp_path, confidence_min=0.70)
        assert isinstance(rep, ScanReport)
        assert rep.totals.invalid == 1


@pytest.mark.parametrize(
    "bad",
    [True, "0.7", float("nan"), float("inf"), 0.0, 1.0, -0.1, 1.1],
)
def test_threshold_validation_identical_across_paths(tmp_path: Path, bad: object) -> None:
    """Every threshold-accepting public path rejects invalid values identically."""
    from sesslint.scan import scan_path

    target = _copy_healthy(tmp_path, "candidate.jsonl")

    with pytest.raises(ValueError, match="confidence_min must be strictly between"):
        api.check_file(target, confidence_min=bad)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="confidence_min must be strictly between"):
        api.check_dir(tmp_path, confidence_min=bad)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="confidence_min must be strictly between"):
        scan_path(tmp_path, confidence_min=bad)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="confidence_min must be strictly between"):
        api.build_bundle(target, confidence_min=bad)  # type: ignore[arg-type]


def test_repair_performs_single_detection_with_profile_thresholds(tmp_path: Path) -> None:
    """api.repair runs exactly one detection pass using the selected profile's thresholds."""
    import sesslint.adapters.detect as detect_mod
    from sesslint.repair.errors import VendorRepairRefused

    target = _copy_healthy(tmp_path, "candidate.jsonl")

    calls: list[dict[str, float]] = []
    real_detect = detect_mod.detect_format

    def spy_detect(path, *, confidence_min, margin_min):  # type: ignore[no-untyped-def]
        calls.append({"confidence_min": confidence_min, "margin_min": margin_min})
        return real_detect(path, confidence_min=confidence_min, margin_min=margin_min)

    # claude-strict profile pins margin_min=0.20; neutral pins 0.15.
    p1, p2, p3 = _patch_detector_scores(0.60, 0.45, 0.10)
    with p1, p2, p3, pytest.MonkeyPatch.context() as mp:
        mp.setattr(detect_mod, "detect_format", spy_detect)
        # Under neutral (margin 0.15): claude wins (0.60 vs 0.45 -> margin 0.15)
        # -> vendor refusal proves a single detection pass ran under thresholds.
        with pytest.raises(VendorRepairRefused, match="Direct repair of vendor format"):
            api.repair(target, tmp_path / "out.jsonl")
        assert len(calls) == 1
        assert calls[0]["confidence_min"] == 0.55
        assert calls[0]["margin_min"] == 0.15

        calls.clear()
        # Under claude-strict (margin 0.20): 0.60-0.45=0.15 < 0.20 -> ambiguous,
        # so no vendor refusal may fire from the detection pass.
        try:
            api.repair(
                target,
                tmp_path / "out.jsonl",
                profile="claude-strict",
                dry_run=True,
            )
        except VendorRepairRefused:
            raise AssertionError("vendor refusal must not fire under strict margin tie") from None
        except Exception:
            pass  # downstream failure acceptable; assertion target is detection
        assert len(calls) == 1
        assert calls[0]["margin_min"] == 0.20


def test_repair_detection_call_count_exactly_once(tmp_path: Path) -> None:
    """Vendor-detected repair performs exactly one detect_format call (no double sniff)."""
    import sesslint.adapters.detect as detect_mod
    from sesslint.repair.errors import VendorRepairRefused

    target = _copy_healthy(tmp_path, "candidate.jsonl")

    calls = 0
    real_detect = detect_mod.detect_format

    def counting_detect(*args: object, **kwargs: object):
        nonlocal calls
        calls += 1
        return real_detect(*args, **kwargs)

    p1, p2, p3 = _patch_detector_scores(0.60, 0.10, 0.10)
    with p1, p2, p3, pytest.MonkeyPatch.context() as mp:
        mp.setattr(detect_mod, "detect_format", counting_detect)
        with pytest.raises(VendorRepairRefused):
            api.repair(target, tmp_path / "out.jsonl")
    assert calls == 1
