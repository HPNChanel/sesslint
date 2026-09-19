"""Regression tests for codex-rollout dispatch across scan/export/verify/bundle.

DW-T-12 shipped the adapter but hand-rolled dispatch sites in scan.py,
exporter.py, verify.py, and bundle.py were missed — codex files were
misclassified "invalid" by scan, refused by export, unverifiable after repair,
and degraded in bundles. All surfaces now share ``adapters.load`` dispatch
(``load_events_for_format``/``load_vendor_events``/``profile_key_for_format``);
these tests pin that behavior end-to-end.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint import api
from sesslint.adapters.load import (
    FORMAT_PROFILE_KEYS,
    load_events_for_format,
    profile_key_for_format,
)
from sesslint.cli import main
from sesslint.exporter import export_to_canonical
from sesslint.scan import scan_path

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
CODEX_HEALTHY = FIXTURES / "conformance" / "codex_rollout" / "healthy.jsonl"
CODEX_ORPHAN = FIXTURES / "adapters" / "codex" / "orphan_output.jsonl"
CODEX_TORN = FIXTURES / "adapters" / "codex" / "torn_tail.jsonl"
CODEX_UNSUPPORTED = FIXTURES / "conformance" / "codex_rollout" / "version_unsupported.jsonl"


def test_profile_key_map_covers_all_formats() -> None:
    """Every supported format id maps to its short profile key."""
    assert FORMAT_PROFILE_KEYS == {
        "claude-code-jsonl": "claude",
        "openai-agents": "openai",
        "codex-rollout": "codex",
        "canonical": "canonical",
    }
    assert profile_key_for_format("codex-rollout") == "codex"
    assert profile_key_for_format("unknown-fmt") == "unknown-fmt"
    assert profile_key_for_format(None) is None


def test_load_events_for_format_preserves_source_metadata() -> None:
    """The shared loader keeps adapter ``.source`` metadata (EventList)."""
    events, _findings = load_events_for_format(CODEX_HEALTHY, "codex-rollout")
    assert len(events) > 0
    assert getattr(events, "source", None) is not None


def test_scan_classifies_healthy_codex_rollout() -> None:
    """A clean rollout scans healthy — previously misclassified invalid."""
    report = scan_path(CODEX_HEALTHY)
    assert report.totals.healthy == 1
    assert report.totals.invalid == 0
    assert report.files[0].verdict == "healthy"


def test_scan_detects_codex_corruption_findings() -> None:
    """A corrupt rollout yields real detector findings, not a profile refusal."""
    report = scan_path(CODEX_ORPHAN)
    assert report.totals.invalid == 1
    assert any(f.code == "SL101" for f in report.files[0].findings)
    assert not any("not permitted by profile" in f.message for f in report.files[0].findings)


def test_scan_codex_unsupported_version_bucket() -> None:
    """SL301-bearing rollouts land in the unsupported bucket."""
    report = scan_path(CODEX_UNSUPPORTED)
    assert report.totals.unsupported == 1


def test_scan_codex_profile_gate() -> None:
    """claude-strict still refuses codex via the profile gate (short key)."""
    report = scan_path(CODEX_HEALTHY, profile="claude-strict")
    assert report.totals.invalid == 1
    assert any("not permitted by profile" in f.message for f in report.files[0].findings)
    openai_report = scan_path(CODEX_HEALTHY, profile="openai-strict")
    assert openai_report.totals.invalid == 0


def test_cli_scan_agent_codex_real_rollout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """E2E: ``scan --agent codex`` on a root containing real rollout content."""
    cx = tmp_path / "cxhome"
    sessions = cx / "sessions"
    sessions.mkdir(parents=True)
    (sessions / "rollout-2026-09-18T00-00-00-test.jsonl").write_bytes(CODEX_HEALTHY.read_bytes())
    monkeypatch.setenv("CODEX_HOME", str(cx))
    code = main(["scan", "--agent", "codex", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["totals"]["healthy"] == 1
    assert data["totals"]["invalid"] == 0
    assert code == 0


def test_export_codex_rollout(tmp_path: Path) -> None:
    """Export accepts codex-rollout input and emits a canonical file."""
    out = tmp_path / "codex_canonical.jsonl"
    summary = export_to_canonical(CODEX_HEALTHY, out)
    assert summary.input_format == "codex-rollout"
    assert summary.event_count > 0
    from sesslint.adapters.canonical import load_canonical

    events, _ = load_canonical(out)
    assert len(events) == summary.event_count


def test_bundle_codex_rollout_skeleton() -> None:
    """Bundle fixture skeleton reports canonical kinds, not envelope types."""
    bundle = api.build_bundle(CODEX_HEALTHY)
    kinds = bundle.fixture_skeleton["kinds"]
    assert kinds  # non-empty histogram from real events
    assert "message" in kinds
    # Envelope record types must not leak into the canonical kinds histogram.
    for envelope_type in ("session_meta", "response_item", "turn_context", "event_msg"):
        assert envelope_type not in kinds


def test_verify_codex_repair_roundtrip(tmp_path: Path) -> None:
    """A repaired codex source verifies end-to-end (all 7 audit checks)."""
    repaired = tmp_path / "repaired.jsonl"
    _plan, manifest = api.repair(CODEX_TORN, repaired)
    assert manifest is not None
    manifest_path = Path(f"{repaired}.manifest.json")
    assert manifest_path.is_file()

    verdict = api.verify(
        source_path=CODEX_TORN,
        output_path=repaired,
        manifest_path=manifest_path,
    )
    assert verdict.ok is True
    assert all(c.ok for c in verdict.checks)
