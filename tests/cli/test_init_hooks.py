"""Tests for ``sesslint hook --init`` (integrations/T-02).

The generator is print-only by permanent design: these tests pin the
emitted Claude Code and Codex snippets, the JSON shape, and prove zero
files are created or modified by the command.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from sesslint.hooks import SCHEMA_VERSION, VALID_AGENTS, init_hooks_doc

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _run_cli(*argv: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sesslint", *argv],
        capture_output=True,
        text=True,
        cwd=cwd or REPO_ROOT,
    )


def test_claude_print_matches_documented_recipes() -> None:
    doc = init_hooks_doc("claude")
    assert len(doc.files) == 4
    by_hook = {f.recipe: f for f in doc.files}
    ss = by_hook["SessionStart corruption warning (non-blocking)"].merge_block
    pc = by_hook["PreCompact integrity check (non-blocking)"].merge_block
    pxc = by_hook["PostCompact boundary check (non-blocking)"].merge_block
    se = by_hook["SessionEnd secret check (non-blocking)"].merge_block
    assert ss is not None and pc is not None and pxc is not None and se is not None
    # Verbatim contract with docs/INTEGRATIONS.md recipes (agent-hooks T-02):
    # every command is `sesslint hook --event <X> || true` — the payload
    # arrives on stdin, so no path substitution or glob is needed.
    entry = ss["hooks"]["SessionStart"][0]
    assert entry["matcher"] == "resume|compact|fork"
    assert entry["hooks"][0]["command"] == (
        "sesslint hook --event SessionStart --format claude-json || true"
    )
    assert pc["hooks"]["PreCompact"][0]["matcher"] == "auto|manual"
    assert pc["hooks"]["PreCompact"][0]["hooks"][0]["command"] == (
        "sesslint hook --event PreCompact || true"
    )
    # PostCompact has no matcher key (fires unconditionally).
    assert "matcher" not in pxc["hooks"]["PostCompact"][0]
    assert pxc["hooks"]["PostCompact"][0]["hooks"][0]["command"] == (
        "sesslint hook --event PostCompact || true"
    )
    assert pxc["hooks"]["PostCompact"][0]["hooks"][0]["timeout"] == 5
    # SessionEnd hygiene recipe sweeps persisted secrets via SL009.
    se_entry = se["hooks"]["SessionEnd"][0]
    assert se_entry["matcher"] == "clear|logout|prompt_input_exit|other"
    assert se_entry["hooks"][0]["command"] == "sesslint hook --event SessionEnd || true"
    assert se_entry["hooks"][0]["timeout"] == 5


def test_codex_print_matches_documented_recipes() -> None:
    doc = init_hooks_doc("codex")
    assert len(doc.files) == 4
    assert {f.target_path_hint for f in doc.files} == {"~/.codex/hooks.json (hooks section)"}
    by_hook = {f.recipe: f for f in doc.files}
    ss = by_hook["SessionStart corruption warning (non-blocking)"].merge_block
    pc = by_hook["PreCompact integrity check (non-blocking)"].merge_block
    pxc = by_hook["PostCompact boundary check (non-blocking)"].merge_block
    se = by_hook["SessionEnd secret check (non-blocking)"].merge_block
    assert ss is not None and pc is not None and pxc is not None and se is not None
    # Codex adds plain SessionStart stdout to model context and ignores plain
    # PreCompact/PostCompact stdout, so all three print the systemMessage
    # envelope (--format claude-json). SessionStart leaves out "compact":
    # PostCompact already checks the compacted transcript.
    entry = ss["hooks"]["SessionStart"][0]
    assert entry["matcher"] == "resume|fork"
    assert entry["hooks"][0]["command"] == (
        "sesslint hook --event SessionStart --format claude-json || true"
    )
    assert pc["hooks"]["PreCompact"][0]["matcher"] == "auto|manual"
    assert pc["hooks"]["PreCompact"][0]["hooks"][0]["command"] == (
        "sesslint hook --event PreCompact --format claude-json || true"
    )
    assert "matcher" not in pxc["hooks"]["PostCompact"][0]
    assert pxc["hooks"]["PostCompact"][0]["hooks"][0]["command"] == (
        "sesslint hook --event PostCompact --format claude-json || true"
    )
    assert pxc["hooks"]["PostCompact"][0]["hooks"][0]["timeout"] == 5
    # Codex reports only the "other" SessionEnd reason (no matcher needed),
    # and caps SessionEnd timeouts at 3 seconds.
    se_entry = se["hooks"]["SessionEnd"][0]
    assert "matcher" not in se_entry
    assert se_entry["hooks"][0]["command"] == "sesslint hook --event SessionEnd || true"
    assert se_entry["hooks"][0]["timeout"] == 3
    # Trust review is part of the copy-paste contract.
    assert "/hooks" in doc.note


@pytest.mark.parametrize(
    ("section", "agent"),
    [("## Claude Code hooks", "claude"), ("## Codex hooks", "codex")],
)
def test_documented_recipe_block_matches_emitted_blocks(section: str, agent: str) -> None:
    """docs/INTEGRATIONS.md shows the merge of every emitted block per agent."""
    text = (REPO_ROOT / "docs" / "INTEGRATIONS.md").read_text(encoding="utf-8")
    recipes = text.split(section + "\n", 1)[1].split("### Recipes", 1)[1]
    documented = json.loads(recipes.split("```json\n", 1)[1].split("```", 1)[0])
    merged: dict[str, Any] = {"hooks": {}}
    for f in init_hooks_doc(agent).files:
        assert f.merge_block is not None
        for event, entries in f.merge_block["hooks"].items():
            merged["hooks"].setdefault(event, []).extend(entries)
    assert documented == merged


def test_snippets_have_no_placeholder_or_glob() -> None:
    """Zero-config contract: no /path/to placeholder, no project glob."""
    doc = init_hooks_doc("all")
    blob = json.dumps(doc.to_dict())
    assert "/path/to" not in blob
    assert "$CLAUDE_PROJECT_DIR" not in blob
    assert "$CODEX_HOME" not in blob
    assert "*.jsonl" not in blob
    assert "jq" not in blob
    assert "xargs" not in blob
    for f in doc.files:
        assert f.merge_block is not None
        for event_entries in f.merge_block["hooks"].values():
            for entry in event_entries:
                for hook in entry["hooks"]:
                    cmd = hook["command"]
                    assert cmd.startswith("sesslint hook --event ")
                    assert cmd.endswith("|| true")
                    # commandWindows is Codex-only; Windows hooks may run in
                    # PowerShell or cmd, so the override drops '|| true'.
                    is_codex = f.target_path_hint.startswith("~/.codex/")
                    assert ("commandWindows" in hook) == is_codex
                    if is_codex:
                        assert hook["commandWindows"] == cmd.removesuffix(" || true")


def test_all_combines_claude_and_codex() -> None:
    doc = init_hooks_doc("all")
    claude, codex = init_hooks_doc("claude"), init_hooks_doc("codex")
    assert doc.files == claude.files + codex.files
    # Both halves are labelled: the default text output opens with this note.
    assert doc.note == "claude: " + claude.note + " | codex: " + codex.note


def test_unknown_agent_rejected() -> None:
    with pytest.raises(ValueError):
        init_hooks_doc("bogus")


@pytest.mark.parametrize("agent", VALID_AGENTS)
def test_json_shape_is_deterministic(agent: str) -> None:
    doc = init_hooks_doc(agent)
    d = doc.to_dict()
    assert d["schema"] == SCHEMA_VERSION == "sesslint.init-hooks/v1"
    assert d["agent"] == agent
    assert {f["recipe"] for f in d["files"]}
    assert doc.to_json() == init_hooks_doc(agent).to_json()
    assert doc.render_human() == init_hooks_doc(agent).render_human()


def test_cli_print_and_json_modes() -> None:
    res = _run_cli("hook", "--init", "--agent", "claude")
    assert res.returncode == 0
    assert "SessionStart" in res.stdout and "PreCompact" in res.stdout
    assert "PostCompact" in res.stdout and "SessionEnd" in res.stdout

    res = _run_cli("hook", "--init", "--agent", "codex", "--json")
    assert res.returncode == 0
    d = json.loads(res.stdout)
    assert d["agent"] == "codex" and len(d["files"]) == 4
    assert {f["target_path_hint"] for f in d["files"]} == {"~/.codex/hooks.json (hooks section)"}
    assert "note" in d


def test_command_writes_nothing(tmp_path: Path) -> None:
    """Print-only contract: zero files created or modified under cwd."""
    res = _run_cli("hook", "--init", "--agent", "all", cwd=tmp_path)
    assert res.returncode == 0
    assert list(tmp_path.iterdir()) == []
    # No stray files anywhere new under the working tree.
    assert not (tmp_path / "settings.json").exists()


def test_merge_blocks_are_valid_json_fragments() -> None:
    """Each printed block parses as JSON and is merge-shaped."""
    doc = init_hooks_doc("all")
    for f in doc.files:
        assert f.merge_block is not None
        parsed = json.loads(json.dumps(f.merge_block))
        assert "hooks" in parsed
