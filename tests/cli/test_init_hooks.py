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
    assert entry["matcher"] == "startup|resume|clear|compact|fork"
    assert entry["hooks"][0]["command"] == "sesslint hook --event SessionStart || true"
    assert pc["hooks"]["PreCompact"][0]["matcher"] == "auto|manual"
    assert pc["hooks"]["PreCompact"][0]["hooks"][0]["command"] == (
        "sesslint hook --event PreCompact || true"
    )
    # PostCompact has no matcher key (fires unconditionally).
    assert "matcher" not in pxc["hooks"]["PostCompact"][0]
    assert pxc["hooks"]["PostCompact"][0]["hooks"][0]["command"] == (
        "sesslint hook --event PostCompact || true"
    )
    # SessionEnd hygiene recipe sweeps persisted secrets via SL009.
    se_entry = se["hooks"]["SessionEnd"][0]
    assert se_entry["matcher"] == "clear|logout|prompt_input_exit|other"
    assert se_entry["hooks"][0]["command"] == "sesslint hook --event SessionEnd || true"


def test_snippets_have_no_placeholder_or_glob() -> None:
    """Zero-config contract: no /path/to placeholder, no project glob."""
    doc = init_hooks_doc("claude")
    blob = json.dumps(doc.to_dict())
    assert "/path/to" not in blob
    assert "$CLAUDE_PROJECT_DIR" not in blob
    assert "*.jsonl" not in blob
    assert "jq" not in blob
    assert "xargs" not in blob
    for f in doc.files:
        for event_entries in f.merge_block["hooks"].values():
            for entry in event_entries:
                for hook in entry["hooks"]:
                    cmd = hook["command"]
                    assert cmd.startswith("sesslint hook --event ")
                    assert cmd.endswith("|| true")


def test_codex_prints_honest_note_no_snippet() -> None:
    doc = init_hooks_doc("codex")
    assert doc.files == ()
    # Honest wording (agent-hooks T-03 memo): Codex documents hooks, but
    # snippets are deferred pending matcher/timeout/trust verification.
    assert "not emitted yet" in doc.note
    # Never invents config.
    assert "merge_block" not in json.dumps(doc.to_dict())


def test_all_combines_claude_files_and_codex_note() -> None:
    doc = init_hooks_doc("all")
    assert len(doc.files) == 4
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
    assert doc.render_human() == init_hooks_doc("claude").render_human()


def test_cli_print_and_json_modes() -> None:
    res = _run_cli("init-hooks", "--agent", "claude", "--print")
    assert res.returncode == 0
    assert "SessionStart" in res.stdout and "PreCompact" in res.stdout
    assert "PostCompact" in res.stdout and "SessionEnd" in res.stdout

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
