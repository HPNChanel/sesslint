"""Tests for Library <-> CLI parity across check, scan, and verify (TASK-024)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint import api
from sesslint.cli import main
from sesslint.report import render_json

CLI_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "cli"
SCAN_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "scan"
VERIFY_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "verify"


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
