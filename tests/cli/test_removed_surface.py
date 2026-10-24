"""Tests for the 0.5.0 removed CLI surface (commands and flags).

Every removed command exits 2 with an actionable replacement hint; every
removed flag exits 2 after printing a migration hint (argparse emits its
own usage error afterwards). The ``scan`` alias is byte-identical to
``check``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"
HEALTHY = FIXTURES_DIR / "cli" / "check_basic" / "healthy.jsonl"
SCAN_DIR = FIXTURES_DIR / "scan" / "mixed"

REMOVED_COMMANDS = {
    "validate-session": "check --adapter canonical",
    "baseline": "--write-baseline",
    "formats": "doctor",
    "init-hooks": "hook --init",
}

REMOVED_FLAGS = {
    "--output-format": "--format",
    "--recursive": "always recursive",
    "-r": "always recursive",
    "--batch": "--output-dir",
    "--files": "--output-dir",
    "--salvage-unsupported": "--policy salvage",
    "--show-limits": "sesslint doctor",
    "--format-a": "--adapter-a",
    "--format-b": "--adapter-b",
    "--out": "--output",
}


def _run(argv: list[str]) -> int:
    try:
        return main(argv)
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 0


@pytest.mark.parametrize("command,replacement", sorted(REMOVED_COMMANDS.items()))
def test_removed_command_exits_2_with_replacement(
    capsys: pytest.CaptureFixture[str], command: str, replacement: str
) -> None:
    code = main([command])
    assert code == 2
    err = capsys.readouterr().err
    assert command in err
    assert replacement in err


@pytest.mark.parametrize("flag,replacement", sorted(REMOVED_FLAGS.items()))
def test_removed_flag_exits_2_with_hint(
    capsys: pytest.CaptureFixture[str], flag: str, replacement: str
) -> None:
    code = _run(["check", str(HEALTHY), flag])
    assert code == 2
    err = capsys.readouterr().err
    assert flag in err
    assert replacement in err


def test_adapter_misuse_via_format_flag_hints_adapter(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`--format <adapter-name>` hints at `--adapter` (output format moved)."""
    code = _run(["check", str(HEALTHY), "--format", "claude-code-jsonl"])
    assert code == 2
    err = capsys.readouterr().err
    assert "--adapter" in err


def test_scan_alias_stdout_byte_identical_to_check(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`scan` is an alias for `check`: identical JSON stdout, same exit code."""
    code_check = main(["check", str(SCAN_DIR), "--json"])
    out_check = capsys.readouterr().out
    code_scan = main(["scan", str(SCAN_DIR), "--json"])
    out_scan = capsys.readouterr().out

    assert code_check == code_scan
    assert out_check == out_scan
    json.loads(out_check)  # stdout is a single JSON document


def test_check_directory_recursive_without_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`check <dir>` scans recursively — no -r/--recursive flag needed."""
    nested = tmp_path / "sub"
    nested.mkdir()
    (nested / "s.jsonl").write_bytes(HEALTHY.read_bytes())
    code = main(["check", str(tmp_path), "--json"])
    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["totals"]["healthy"] == 1


def test_check_agent_all_latest_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    """`check --agent all --latest` is a usage error (one file only)."""
    assert main(["check", "--agent", "all", "--latest"]) == 2


def test_repair_multi_path_requires_output_dir(capsys: pytest.CaptureFixture[str]) -> None:
    """`repair a.jsonl b.jsonl` without --output-dir is a usage error."""
    code = main(["repair", "a.jsonl", "b.jsonl"])
    assert code == 2
    assert "--output-dir" in capsys.readouterr().err
