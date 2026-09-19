"""Tests for ``sesslint init-hooks`` (integrations/T-02).

The generator is print-only by permanent design: these tests pin the
emitted snippets, the honest codex note, the JSON shape, and prove zero
files are created or modified by the command.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from sesslint.hooks import SCHEMA_VERSION, init_hooks_doc

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
    assert len(doc.files) == 2
    by_hook = {f.recipe: f for f in doc.files}
    ss = by_hook["SessionStart corruption warning (non-blocking)"].merge_block
    pc = by_hook["PreCompact gate"].merge_block
    assert ss is not None and pc is not None
    # Verbatim contract with docs/INTEGRATIONS.md recipes.
    entry = ss["hooks"]["SessionStart"][0]
    assert entry["matcher"] == "startup|resume|clear"
    cmd = entry["hooks"][0]["command"]
    assert cmd == 'sesslint check "$CLAUDE_PROJECT_DIR"/*.jsonl --json --skip-undetected || true'
    assert pc["hooks"]["PreCompact"][0]["matcher"] == "auto|manual"


def test_codex_prints_honest_note_no_snippet() -> None:
    doc = init_hooks_doc("codex")
    assert doc.files == ()
    assert "no documented user-facing hook surface" in doc.note
    # Never invents config.
    assert "merge_block" not in json.dumps(doc.to_dict())


def test_all_combines_claude_files_and_codex_note() -> None:
    doc = init_hooks_doc("all")
    assert len(doc.files) == 2
    assert "codex" in doc.note


def test_unknown_agent_rejected() -> None:
    with pytest.raises(ValueError):
        init_hooks_doc("bogus")


def test_json_shape_is_deterministic() -> None:
    doc = init_hooks_doc("claude")
    d = doc.to_dict()
    assert d["schema"] == SCHEMA_VERSION == "sesslint.init-hooks/v1"
    assert d["agent"] == "claude"
    assert {f["recipe"] for f in d["files"]}
    assert doc.to_json() == init_hooks_doc("claude").to_json()


def test_cli_print_and_json_modes() -> None:
    res = _run_cli("init-hooks", "--agent", "claude", "--print")
    assert res.returncode == 0
    assert "SessionStart" in res.stdout and "PreCompact" in res.stdout

    res = _run_cli("init-hooks", "--agent", "codex", "--json")
    assert res.returncode == 0
    d = json.loads(res.stdout)
    assert d["agent"] == "codex" and d["files"] == []
    assert "note" in d


def test_command_writes_nothing(tmp_path: Path) -> None:
    """Print-only contract: zero files created or modified under cwd."""
    res = _run_cli("init-hooks", "--agent", "all", "--print", cwd=tmp_path)
    assert res.returncode == 0
    assert list(tmp_path.iterdir()) == []
    # No stray files anywhere new under the working tree.
    assert not (tmp_path / "settings.json").exists()


def test_merge_blocks_are_valid_json_fragments() -> None:
    """Each printed block parses as JSON and is merge-shaped."""
    doc = init_hooks_doc("claude")
    for f in doc.files:
        assert f.merge_block is not None
        parsed = json.loads(json.dumps(f.merge_block))
        assert "hooks" in parsed
