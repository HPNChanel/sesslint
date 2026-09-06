"""Platform smoke tests validating CLI commands from checkout (TASK-028).

Invariants verified:
1. `sesslint version --json` outputs all expected schema versions, cli version, adapters,
   and profiles.
2. `sesslint check` on a healthy fixture returns exit code 0 and empty findings list.
3. `sesslint check --recursive --json` on mixed directory returns exit code 1 with
   exact expected totals shape.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.cli import main

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_smoke_version_json(capsys: pytest.CaptureFixture[str]) -> None:
    """Validate version --json payload structure and presence of required fields."""
    exit_code = main(["version", "--json"])
    assert exit_code == 0

    out = capsys.readouterr().out
    data = json.loads(out)

    assert "cli" in data
    assert "schema_manifest" in data
    assert "schema_report" in data
    assert "schema_session" in data
    assert "adapters" in data
    assert "profiles" in data

    # Verify known adapter keys
    assert "canonical" in data["adapters"]
    assert "claude-code-jsonl" in data["adapters"]
    assert "openai-agents" in data["adapters"]

    # Verify known profile keys
    assert "neutral" in data["profiles"]
    assert "claude-strict" in data["profiles"]
    assert "openai-strict" in data["profiles"]


def test_smoke_healthy_check(capsys: pytest.CaptureFixture[str]) -> None:
    """Validate that checking a healthy fixture outputs clean JSON with zero findings."""
    healthy_file = REPO_ROOT / "fixtures" / "cli" / "check_basic" / "healthy.jsonl"
    assert healthy_file.is_file()

    exit_code = main(["check", str(healthy_file), "--json"])
    assert exit_code == 0

    out = capsys.readouterr().out
    data = json.loads(out)

    assert data.get("schema_version") == "sesslint.report/v1"
    assert len(data.get("findings", [])) == 0
    assert data.get("counts", {}).get("total", 0) == 0


def test_smoke_mixed_directory_scan(capsys: pytest.CaptureFixture[str]) -> None:
    """Validate recursive scan over mixed directory returns exit 1 and well-formed totals."""
    mixed_dir = REPO_ROOT / "fixtures" / "scan" / "mixed"
    assert mixed_dir.is_dir()

    exit_code = main(["check", str(mixed_dir), "--recursive", "--json"])
    assert exit_code == 1

    out = capsys.readouterr().out
    data = json.loads(out)

    assert data.get("schema_version") == "sesslint.scan-report/v1"
    assert "totals" in data
    totals = data["totals"]

    assert totals.get("total") == 5
    assert totals.get("healthy") == 1
    assert totals.get("invalid") == 2
    assert totals.get("unreadable") == 1
    assert totals.get("unsupported") == 1
    assert totals.get("skipped") == 0
