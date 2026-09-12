"""Tests for Library <-> CLI parity across check, scan, and verify (TASK-024 / DEV-010)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint import api
from sesslint.cli import main
from sesslint.report import render_json

FIXTURES_ROOT = Path(__file__).resolve().parent.parent / "fixtures"
CLI_FIXTURES = FIXTURES_ROOT / "cli"
SCAN_FIXTURES = FIXTURES_ROOT / "scan"
VERIFY_FIXTURES = FIXTURES_ROOT / "verify"

SWEEP_SUBDIRS = [
    "cli",
    "checks",
    "io",
    "adapters",
    "canonical",
    "claude_code",
    "openai_agents",
    "profiles",
]


def _collect_sweep_fixtures() -> list[Path]:
    files: list[Path] = []
    for sub in SWEEP_SUBDIRS:
        subpath = FIXTURES_ROOT / sub
        if not subpath.exists():
            continue
        for f in sorted(subpath.rglob("*")):
            if f.is_file() and f.suffix in (".json", ".jsonl"):
                files.append(f)
    return files


SWEEP_FIXTURES = _collect_sweep_fixtures()


def test_parity_check_file_healthy(capsys: pytest.CaptureFixture[str]) -> None:
    """api.check_file produces identical Report data to CLI check --json."""
    fixture = CLI_FIXTURES / "check_basic" / "healthy.jsonl"

    # Library call
    lib_report = api.check_file(fixture)

    # CLI call
    code = main(["check", str(fixture), "--json"])
    assert code == 0
    cli_out = capsys.readouterr().out
    cli_json = json.loads(cli_out)

    lib_json = json.loads(render_json(lib_report, repro=cli_json.get("repro")))
    assert lib_json == cli_json


def test_parity_check_file_ambiguity(capsys: pytest.CaptureFixture[str]) -> None:
    """api.check_file produces identical Report data on ambiguous input to CLI check --json."""
    fixture = CLI_FIXTURES / "check_ambiguity" / "polyglot.json"

    # Library call
    lib_report = api.check_file(fixture)

    # CLI call
    code = main(["check", str(fixture), "--json"])
    assert code == 1
    cli_out = capsys.readouterr().out
    cli_json = json.loads(cli_out)

    lib_json = json.loads(render_json(lib_report, repro=cli_json.get("repro")))
    assert lib_json == cli_json


def test_parity_check_dir_recursive(capsys: pytest.CaptureFixture[str]) -> None:
    """api.check_dir produces identical ScanReport data to CLI check --recursive --json."""
    mixed_dir = SCAN_FIXTURES / "mixed"

    # Library call
    lib_scan = api.check_dir(mixed_dir, recursive=True)
    lib_json = json.loads(lib_scan.to_json())

    # CLI call
    code = main(["check", str(mixed_dir), "--recursive", "--json"])
    assert code == 1
    cli_out = capsys.readouterr().out
    cli_json = json.loads(cli_out)

    assert lib_json == cli_json


def test_parity_verify_command(capsys: pytest.CaptureFixture[str]) -> None:
    """api.verify produces identical verdict data to CLI verify."""
    d = VERIFY_FIXTURES / "ok"
    src = d / "source.jsonl"
    plan = d / "plan.json"
    out = d / "output.jsonl"
    man = d / "manifest.json"

    # Library call
    lib_verdict = api.verify(source_path=src, plan_path=plan, output_path=out, manifest_path=man)
    lib_json = json.loads(lib_verdict.to_json())

    # CLI call
    code = main(
        [
            "verify",
            "--source",
            str(src),
            "--plan",
            str(plan),
            "--output",
            str(out),
            "--manifest",
            str(man),
        ]
    )
    assert code == 0
    cli_out = capsys.readouterr().out
    cli_json = json.loads(cli_out)

    assert lib_json == cli_json


@pytest.mark.parametrize(
    "fixture_file",
    SWEEP_FIXTURES,
    ids=lambda p: str(p.relative_to(FIXTURES_ROOT)),
)
def test_parity_check_file_tree(fixture_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Differential parity test: CLI JSON matches api.check_file across fixture tree."""
    lib_report = api.check_file(fixture_file)

    code = main(["check", str(fixture_file), "--json"])
    has_error = (
        lib_report.counts.by_severity.get("error", 0) > 0
        or lib_report.counts.by_severity.get("fatal", 0) > 0
    )
    expected_exit = 1 if has_error else 0
    assert code == expected_exit

    cli_out = capsys.readouterr().out
    cli_json = json.loads(cli_out)
    lib_json = json.loads(render_json(lib_report, repro=cli_json.get("repro")))

    assert cli_json == lib_json


def test_check_detection_failure_json_shape(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify format detection failure JSON has identical top-level keys as normal check."""
    polyglot = CLI_FIXTURES / "check_ambiguity" / "polyglot.json"
    code = main(["check", str(polyglot), "--json"])
    assert code == 1

    cli_out = capsys.readouterr().out
    data = json.loads(cli_out)

    expected_keys = {
        "assurance",
        "counts",
        "coverage",
        "findings",
        "limitation",
        "repro",
        "schema_version",
        "session_id",
        "source_fingerprint",
        "tool_version",
    }
    assert set(data.keys()) == expected_keys
    assert data["assurance"] == "A0"
    assert data["limitation"] == "No structural conclusion."
    assert any(f["code"] in ("SL301", "SL302") for f in data["findings"])


def test_check_policy_flag_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    """Passing --policy to 'check' command errors with exit code 2 and guidance."""
    fixture = CLI_FIXTURES / "check_basic" / "healthy.jsonl"
    code = main(["check", str(fixture), "--policy", "conservative"])
    assert code == 2

    err = capsys.readouterr().err
    assert "Error: The --policy option is only valid for 'repair', not 'check'." in err


def test_repair_salvage_unsupported_flag_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    """Passing deprecated --salvage-unsupported to 'repair' errors with exit code 2 and guidance."""
    fixture = CLI_FIXTURES / "check_basic" / "healthy.jsonl"
    code = main(["repair", str(fixture), "--salvage-unsupported"])
    assert code == 2

    err = capsys.readouterr().err
    assert (
        "Error: The --salvage-unsupported flag has been deprecated and removed. "
        "Please use '--policy salvage' instead."
    ) in err


def test_parity_scan_command(capsys: pytest.CaptureFixture[str]) -> None:
    """'scan <dir> --json' produces output matching api.check_dir."""
    mixed_dir = SCAN_FIXTURES / "mixed"
    lib_scan = api.check_dir(mixed_dir, recursive=True)
    lib_json = json.loads(lib_scan.to_json())

    code = main(["scan", str(mixed_dir), "--json"])
    assert code == 1

    cli_out = capsys.readouterr().out
    cli_json = json.loads(cli_out)
    assert cli_json == lib_json
