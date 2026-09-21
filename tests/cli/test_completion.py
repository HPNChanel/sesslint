"""Tests for shell completion generation (T-13)."""

from __future__ import annotations

import pytest

from sesslint.cli import create_parser, main
from sesslint.completion import COMPLETION_SHELLS, generate_completion

PINNED_COMMANDS = (
    "baseline",
    "bundle",
    "check",
    "completion",
    "diff",
    "doctor",
    "export",
    "formats",
    "hook",
    "init-hooks",
    "mcp",
    "repair",
    "scan",
    "stats",
    "validate-session",
    "verify",
    "version",
    "watch",
)


def _live_subcommands() -> set[str]:
    parser = create_parser()
    names: set[str] = set()
    for action in parser._actions:
        choices_obj = getattr(action, "choices", None)
        if isinstance(choices_obj, dict):
            names.update(str(k) for k in choices_obj.keys())
    return names


def test_pinned_commands_present_in_all_shells() -> None:
    for shell in COMPLETION_SHELLS:
        script = generate_completion(shell)
        for cmd in PINNED_COMMANDS:
            assert cmd in script


def test_every_live_subcommand_covered() -> None:
    live = _live_subcommands()
    assert live == set(PINNED_COMMANDS)
    for shell in COMPLETION_SHELLS:
        script = generate_completion(shell)
        for cmd in live:
            assert cmd in script


def test_flags_and_choices_present() -> None:
    for shell in COMPLETION_SHELLS:
        script = generate_completion(shell)
        for flag in ("--format", "--profile", "--json", "--output", "--policy"):
            assert flag in script
        for choice in (
            "claude-code-jsonl",
            "openai-agents",
            "canonical",
            "conservative",
            # --profile values are harvested live from the profile registry
            "claude-strict",
            "neutral",
            "openai-strict",
        ):
            assert choice in script


def test_generation_deterministic() -> None:
    for shell in COMPLETION_SHELLS:
        assert generate_completion(shell) == generate_completion(shell)


def test_rejects_unknown_shell() -> None:
    with pytest.raises(ValueError, match="Unsupported shell"):
        generate_completion("elvish")


def test_powershell_script_shape() -> None:
    script = generate_completion("powershell")
    assert "Register-ArgumentCompleter" in script
    assert "-Native -CommandName sesslint" in script
    assert "CompletionResult" in script
    assert "GetNewClosure" in script
    # data maps harvested from the live parser
    assert "$sesslintFlagMap" in script
    assert "$sesslintChoiceMap" in script
    assert "'check' = @(" in script
    assert "'check --format' = @('auto'" in script
    # --profile enum values come from the live profile registry
    assert "'check --profile' = @('claude-strict', 'neutral', 'openai-strict')" in script
    # graceful fallback for pre-backport Windows PowerShell 5.1 builds
    assert "Parameters.ContainsKey('Native')" in script


def test_powershell_script_is_deterministic_sorted() -> None:
    script = generate_completion("powershell")
    lines = script.splitlines()
    flag_rows = [ln for ln in lines if ln.startswith("    '") and " = @(" in ln]
    keys = [ln.split(" = @(")[0] for ln in flag_rows]
    # map rows are emitted in sorted command order; within a command,
    # flag options are sorted
    cmd_order = [k for k in keys if "--" not in k]
    assert cmd_order == sorted(cmd_order)


def test_cli_completion_command(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["completion", "bash"])
    assert code == 0
    out = capsys.readouterr().out
    assert "complete" in out
    assert "sesslint" in out


def test_cli_completion_rejects_unknown_shell() -> None:
    parser = create_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["completion", "elvish"])
    assert exc_info.value.code == 2


def test_cli_completion_powershell(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["completion", "powershell"])
    assert code == 0
    out = capsys.readouterr().out
    assert "Register-ArgumentCompleter" in out
    assert "sesslint" in out


def test_zsh_completion_escapes_brackets() -> None:
    zsh_script = generate_completion("zsh")
    # Brackets inside descriptions must be escaped to avoid syntax errors in zsh _arguments
    assert "\\[lossy\\: follows links\\]" in zsh_script
    assert "\\[Invalid for check\\]" in zsh_script


def test_cli_completion_all_supported_shells(capsys: pytest.CaptureFixture[str]) -> None:
    for shell in COMPLETION_SHELLS:
        code = main(["completion", shell])
        assert code == 0
        out = capsys.readouterr().out
        assert "sesslint" in out
