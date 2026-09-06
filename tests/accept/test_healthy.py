"""Acceptance tests for healthy transcripts across all supported formats (TASK-028, AC-001).

Guarantees:
- Every healthy fixture in canonical, claude-code, openai-agents, checks, and cli
  evaluates to exit code 0 under the sesslint check CLI.
- Reports zero fatal, zero error, zero warning, and zero total findings on clean sessions.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint import api
from sesslint.cli import main

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

HEALTHY_FIXTURES = [
    REPO_ROOT / "fixtures" / "canonical" / "minimal.json",
    REPO_ROOT / "fixtures" / "checks" / "checkpoint_clean.json",
    REPO_ROOT / "fixtures" / "checks" / "graph_healthy.json",
    REPO_ROOT / "fixtures" / "checks" / "pairing_healthy.json",
    REPO_ROOT / "fixtures" / "claude_code" / "basic.jsonl",
    REPO_ROOT / "fixtures" / "openai_agents" / "items_basic.json",
    REPO_ROOT / "fixtures" / "openai_agents" / "run_state_checkpoint.json",
    REPO_ROOT / "fixtures" / "cli" / "check_basic" / "healthy.jsonl",
]


@pytest.mark.parametrize("fixture_path", HEALTHY_FIXTURES, ids=lambda p: p.name)
def test_healthy_fixtures_cli_exit_zero(
    fixture_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Assert CLI returns exit code 0 and reports no defects on healthy fixtures."""
    assert fixture_path.is_file(), f"Fixture missing: {fixture_path}"

    exit_code = main(["check", str(fixture_path), "--json"])
    assert exit_code == 0, (
        f"Expected exit 0 for healthy fixture {fixture_path.name}, got {exit_code}"
    )

    out = capsys.readouterr().out
    data = json.loads(out)

    assert len(data.get("findings", [])) == 0
    counts = data.get("counts", {})
    assert counts.get("total", 0) == 0
    by_sev = counts.get("by_severity", {})
    assert by_sev.get("error", 0) == 0
    assert by_sev.get("fatal", 0) == 0
    assert by_sev.get("warning", 0) == 0


@pytest.mark.parametrize("fixture_path", HEALTHY_FIXTURES, ids=lambda p: p.name)
def test_healthy_fixtures_api_report(fixture_path: Path) -> None:
    """Assert Python API produces clean report without defects on healthy fixtures."""
    assert fixture_path.is_file()
    report = api.check_file(fixture_path)

    assert len(report.findings) == 0
    assert report.counts.total == 0
    assert report.counts.by_severity.get("error", 0) == 0
    assert report.counts.by_severity.get("fatal", 0) == 0
    assert report.counts.by_severity.get("warning", 0) == 0
