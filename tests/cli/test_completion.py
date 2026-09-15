"""Tests for shell completion generation (T-13)."""

from __future__ import annotations

import pytest

from sesslint.cli import create_parser, main
from sesslint.completion import COMPLETION_SHELLS, generate_completion

PINNED_COMMANDS = (
    "bundle",
    "check",
    "completion",
    "export",
    "formats",
    "repair",
    "scan",
    "validate-session",
    "verify",
    "version",
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
        for choice in ("claude-code-jsonl", "openai-agents", "canonical", "conservative"):
            assert choice in script


def test_generation_deterministic() -> None:
    for shell in COMPLETION_SHELLS:
        assert generate_completion(shell) == generate_completion(shell)


def test_rejects_unknown_shell() -> None:
    with pytest.raises(ValueError, match="Unsupported shell"):
        generate_completion("powershell")


def test_cli_completion_command(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["completion", "bash"])
    assert code == 0
    out = capsys.readouterr().out
    assert "complete" in out
    assert "sesslint" in out


def test_cli_completion_rejects_unknown_shell() -> None:
    parser = create_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["completion", "powershell"])
    assert exc_info.value.code == 2


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
