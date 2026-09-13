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
        "ScanReport",
        "VerifyVerdict",
        "build_bundle",
        "check_dir",
        "check_file",
        "plan",
        "repair",
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
