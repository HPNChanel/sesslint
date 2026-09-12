"""Integration and privacy tests for run-state evidence plumbing (DEV-011, FR-044, FR-081).

Verifies:
1. End-to-end evidence survival: runtime state and checkpoint metadata reaches
   finding evidence and report JSON as a structured, content-free projection.
2. Zero content leakage proof: secret seeds, API keys, email addresses, and prompt prose
   in run_state are completely absent from report JSON.
3. Healthy fixtures with run-state (run_state_checkpoint.json) remain clean with 0 findings.
4. CLI --json output adheres to content-free guarantees for run-state evidence.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sesslint.api import check_dir, check_file
from sesslint.cli import main
from sesslint.codes import SL201
from sesslint.report import render_json

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"


def test_run_state_evidence_fixture_survival_and_zero_leakage() -> None:
    """Run-state structural projection survives end-to-end with zero raw values in report JSON."""
    fixture_path = FIXTURES_DIR / "openai_agents" / "run_state_evidence.json"
    assert fixture_path.is_file(), f"Fixture missing: {fixture_path}"

    report = check_file(fixture_path)
    assert len(report.findings) == 1

    finding = report.findings[0]
    assert finding.code == SL201
    assert finding.evidence is not None
    assert "run_state" in finding.evidence

    proj: dict[str, Any] = finding.evidence["run_state"]
    assert proj["keys"] == [
        "current_agent",
        "secret_token",
        "thread_id",
        "user_prompt",
    ]
    assert proj["shapes"] == {
        "current_agent": "<str:len=12>",
        "secret_token": "<str:len=37>",
        "thread_id": "<str:len=13>",
        "user_prompt": "<str:len=63>",
    }
    assert proj["truncated"] is False
    assert len(proj["checkpoints"]) == 2
    assert proj["checkpoints"][0] == {
        "hash": "<str:len=71>",
        "id": "chk_01",
        "seq": 1,
        "ts": True,
    }
    assert proj["checkpoints"][1] == {
        "hash": "<str:len=71>",
        "id": "chk_02",
        "seq": 5,
        "ts": True,
    }

    # Render report JSON
    rep_json = render_json(report)

    # Secret seeds and raw values must NOT appear anywhere in the rendered JSON
    assert "sec_seed_secret_token_99999_xyz_alpha" not in rep_json
    assert "Confidential prompt" not in rep_json
    assert "triage_agent" not in rep_json
    assert "thread_abc123" not in rep_json
    assert "sha256:1111111111111111111111111111111111111111111111111111111111111111" not in rep_json
    assert "sha256:2222222222222222222222222222222222222222222222222222222222222222" not in rep_json

    # Structural shapes MUST be present in JSON
    assert "<str:len=37>" in rep_json
    assert "<str:len=63>" in rep_json
    assert "<str:len=71>" in rep_json


def test_cli_json_run_state_evidence(capsys: pytest.CaptureFixture[str]) -> None:
    """CLI check --json emits SL201 with run_state projection and zero raw leakage."""
    fixture_path = FIXTURES_DIR / "openai_agents" / "run_state_evidence.json"
    exit_code = main(["check", str(fixture_path), "--json"])
    assert exit_code == 1

    out = capsys.readouterr().out
    data = json.loads(out)

    assert len(data.get("findings", [])) == 1
    f0 = data["findings"][0]
    assert f0["code"] == SL201
    assert "run_state" in f0["evidence"]
    assert f0["evidence"]["run_state"]["shapes"]["secret_token"] == "<str:len=37>"

    # Absolute assertion: zero secrets anywhere in CLI stdout
    assert "sec_seed_secret_token_99999_xyz_alpha" not in out
    assert "Confidential prompt" not in out
    assert "triage_agent" not in out


def test_healthy_run_state_checkpoint_fixture_remains_clean() -> None:
    """The healthy run_state_checkpoint.json fixture produces 0 findings."""
    fixture_path = FIXTURES_DIR / "openai_agents" / "run_state_checkpoint.json"
    report = check_file(fixture_path)
    assert len(report.findings) == 0
    assert report.counts.total == 0


def test_dynamic_secrets_and_pii_strictly_redacted(tmp_path: Path) -> None:
    """Verify live secrets (API keys, emails) in run_state are strictly redacted end to end."""
    from tests.utils.privacy import assert_no_pii

    test_file = tmp_path / "leak_test.json"
    content = {
        "sdk_version": "1.0.0",
        "run_state": {
            "api_key": "sk-proj-supersecretkey1234567890abcdef",
            "contact_email": "alice@example.com",
            "bearer_token": "bearer secret-auth-token-xyz-12345",
        },
        "checkpoints": [
            {"id": "c1", "seq": 1, "hash": "sha256:1111", "ts": "2026-09-08T00:00:00Z"},
            {"id": "c2", "seq": 5, "hash": "sha256:2222", "ts": "2026-09-08T00:01:00Z"},
        ],
        "items": [
            {"id": "i1", "type": "checkpoint", "seq": 1, "hash": "sha256:1111"},
            {"id": "i2", "parent_id": "i1", "type": "checkpoint", "seq": 5, "hash": "sha256:2222"},
        ],
    }
    test_file.write_text(json.dumps(content), encoding="utf-8")

    report = check_file(test_file)
    assert len(report.findings) == 1
    assert report.findings[0].code == SL201

    rep_json = render_json(report)
    # The rendered report must pass rigorous PII and credential leak scanning
    assert_no_pii(rep_json)


def test_scan_run_state_evidence_preservation() -> None:
    """Directory scan (check_dir) preserves run_state projection in FileResult findings."""
    rep = check_dir(FIXTURES_DIR / "openai_agents", recursive=True)
    target_results = [f for f in rep.files if f.path.endswith("run_state_evidence.json")]
    assert len(target_results) == 1
    f_res = target_results[0]
    assert f_res.verdict == "invalid"
    assert len(f_res.findings) == 1
    finding = f_res.findings[0]
    assert finding.code == SL201
    assert finding.evidence is not None
    assert "run_state" in finding.evidence
    proj = finding.evidence["run_state"]
    assert "secret_token" in proj["shapes"]
    assert proj["shapes"]["secret_token"] == "<str:len=37>"

    # Ensure zero leak in scan report JSON
    scan_json = rep.to_json()
    assert "sec_seed_secret_token_99999_xyz_alpha" not in scan_json
    assert "Confidential prompt" not in scan_json
