"""CLI surface lists derive from one source of truth (B12).

Regression guards for three drift bugs in ``cli.py``:

- repair flags that shipped in 0.3.0 kept a stale ``*(next release)*``
  marker in their ``--help`` text;
- ``formats`` reported per-adapter ``default_profile`` values
  (``claude-strict``/``openai-strict``) that no command ever applies — the
  real built-in default is ``neutral`` for every adapter;
- every ``--format`` choice list was hard-coded per subcommand (one of them
  in a different order) instead of being derived from the adapter registry.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from sesslint.adapters.detect import FORMAT_AUTO, SUPPORTED_FORMATS
from sesslint.cli import create_parser, main

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "fixtures"

# One synthetic, auto-detectable fixture per registered adapter.
ADAPTER_FIXTURES: dict[str, Path] = {
    "canonical": FIXTURES / "sessions" / "minimal-valid.jsonl",
    "claude-code-jsonl": FIXTURES / "claude_code" / "basic.jsonl",
    "codex-rollout": FIXTURES / "adapters" / "codex" / "healthy_min.jsonl",
    "openai-agents": FIXTURES / "openai_agents" / "items_basic.json",
}

FORMAT_DESTS = ("format", "format_a", "format_b")


def _subparsers(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return dict(action.choices)
    raise AssertionError("no subparsers action in CLI parser")


def _format_actions() -> list[tuple[str, argparse.Action]]:
    parser = create_parser()
    found: list[tuple[str, argparse.Action]] = [
        ("<global>", a) for a in parser._actions if a.dest in FORMAT_DESTS and a.option_strings
    ]
    for name, sub in sorted(_subparsers(parser).items()):
        found.extend(
            (name, a) for a in sub._actions if a.dest in FORMAT_DESTS and a.option_strings
        )
    return found


def _formats_rows(capsys: pytest.CaptureFixture[str]) -> list[dict[str, object]]:
    assert main(["formats", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert isinstance(rows, list)
    return rows


def test_shipped_repair_flags_carry_no_next_release_marker(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--preview/--plan/--plan-out/batch flags shipped in 0.3.0 (B12)."""
    with pytest.raises(SystemExit) as exc_info:
        main(["repair", "--help"])
    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert "next release" not in out.lower()
    for flag in ("--preview", "--apply-plan", "--plan-out", "--batch", "--from-scan"):
        assert flag in out


def test_no_cli_help_text_carries_next_release_marker() -> None:
    parser = create_parser()
    texts = [parser.format_help()]
    texts.extend(sub.format_help() for sub in _subparsers(parser).values())
    for text in texts:
        assert "next release" not in text.lower()


def test_every_format_option_lists_the_registry_in_one_order() -> None:
    """All --format choice lists are one derived list, not 13 hand copies (B12)."""
    actions = _format_actions()
    assert len(actions) >= 13
    with_auto = {tuple(a.choices or ()) for _, a in actions if a.dest == "format"}
    without_auto = {tuple(a.choices or ()) for _, a in actions if a.dest != "format"}
    assert len(with_auto) == 1, f"--format choice lists diverge: {sorted(with_auto)}"
    assert len(without_auto) == 1, f"--format-a/-b choice lists diverge: {sorted(without_auto)}"
    (auto_choices,) = with_auto
    (plain_choices,) = without_auto
    assert auto_choices == (FORMAT_AUTO, *plain_choices)
    assert frozenset(plain_choices) == SUPPORTED_FORMATS
    assert len(plain_choices) == len(SUPPORTED_FORMATS)


def test_formats_lists_exactly_the_adapter_registry(
    capsys: pytest.CaptureFixture[str],
) -> None:
    names = [str(row["name"]) for row in _formats_rows(capsys)]
    assert len(names) == len(set(names))
    assert frozenset(names) == SUPPORTED_FORMATS
    assert set(ADAPTER_FIXTURES) == SUPPORTED_FORMATS


def test_formats_default_profile_is_the_profile_check_applies(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """formats' default_profile equals what check uses with no --profile (B12)."""
    # Run outside the repo so no [tool.sesslint] config can override the
    # built-in default under test.
    monkeypatch.chdir(tmp_path)
    advertised = {str(row["name"]): row["default_profile"] for row in _formats_rows(capsys)}
    for adapter, fixture in sorted(ADAPTER_FIXTURES.items()):
        main(["check", str(fixture), "--json"])
        report = json.loads(capsys.readouterr().out)
        coverage = report["coverage"]
        assert coverage["adapter"]["id"] == adapter
        assert advertised[adapter] == coverage["profile"]["id"], (
            f"formats advertises default_profile={advertised[adapter]!r} for "
            f"{adapter}, but check applies {coverage['profile']['id']!r}"
        )
