"""Session-root auto-discovery tests for scan --agent and the API (DW-T-05).

Covers: deterministic ordering, env overrides (CLAUDE_CONFIG_DIR, CODEX_HOME),
default home resolution, missing/non-directory root classification, explicit
path precedence, and a synthetic-home end-to-end scan. All read-only.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from sesslint.api import discover_session_roots
from sesslint.cli import main

SESSION_LINE = (
    '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1",'
    '"session_id":"disc-sess"}\n'
    '{"actor":"user","id":"m0","kind":"message","parent_id":null,'
    '"payload":{"text":"hi"},"seq":0,"ts":"2026-09-05T12:00:00Z"}\n'
)


def test_discovery_order_is_deterministic() -> None:
    roots = discover_session_roots()
    assert [r.agent for r in roots] == ["claude", "codex"]


def test_discovery_env_overrides(tmp_path: Path) -> None:
    ccfg = tmp_path / "ccfg"
    cx = tmp_path / "cxhome"
    (ccfg / "projects").mkdir(parents=True)
    (cx / "sessions").mkdir(parents=True)
    roots = discover_session_roots(
        env={"CLAUDE_CONFIG_DIR": str(ccfg), "CODEX_HOME": str(cx)},
        home=tmp_path / "nohome",
    )
    by_agent = {r.agent: r for r in roots}
    assert by_agent["claude"].path == ccfg / "projects"
    assert by_agent["claude"].source == "env"
    assert by_agent["claude"].exists is True
    assert by_agent["codex"].path == cx / "sessions"
    assert by_agent["codex"].source == "env"
    assert by_agent["codex"].exists is True


def test_discovery_default_home(tmp_path: Path) -> None:
    fake_home = tmp_path / "home"
    (fake_home / ".claude" / "projects").mkdir(parents=True)
    (fake_home / ".codex" / "sessions").mkdir(parents=True)
    roots = discover_session_roots(env={}, home=fake_home)
    by_agent = {r.agent: r for r in roots}
    assert by_agent["claude"].path == fake_home / ".claude" / "projects"
    assert by_agent["claude"].source == "default"
    assert by_agent["claude"].exists is True
    assert by_agent["codex"].path == fake_home / ".codex" / "sessions"
    assert by_agent["codex"].exists is True


def test_discovery_missing_and_nondir_roots(tmp_path: Path) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    # .claude/projects missing entirely; .codex/sessions is a FILE, not a dir
    (fake_home / ".codex").mkdir()
    (fake_home / ".codex" / "sessions").write_text("not a dir")
    roots = discover_session_roots(env={}, home=fake_home)
    by_agent = {r.agent: r for r in roots}
    assert by_agent["claude"].exists is False
    assert by_agent["codex"].exists is False


def test_discovery_unknown_agent_rejected() -> None:
    with pytest.raises(ValueError):
        discover_session_roots(["cursor"], env={}, home=Path("/tmp"))


def test_discovery_symlinked_root_not_followed(tmp_path: Path) -> None:
    fake_home = tmp_path / "home"
    real = tmp_path / "real_projects"
    real.mkdir()
    (fake_home / ".claude").mkdir(parents=True)
    link = fake_home / ".claude" / "projects"
    try:
        os.symlink(real, link, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation requires privilege on this platform")
    roots = discover_session_roots(["claude"], env={}, home=fake_home)
    assert roots[0].exists is False


def test_cli_scan_agent_discovers_env_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ccfg = tmp_path / "ccfg"
    proj = ccfg / "projects"
    proj.mkdir(parents=True)
    (proj / "sess1.jsonl").write_text(SESSION_LINE)
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(ccfg))
    code = main(["scan", "--agent", "claude", "--json"])
    assert code in (0, 1)
    data = json.loads(capsys.readouterr().out)
    assert data["schema_version"] == "sesslint.scan-report/v1"
    assert data["totals"]["total"] >= 1


def test_cli_scan_agent_missing_root_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "nowhere"
    monkeypatch.setenv("CODEX_HOME", str(missing))
    code = main(["scan", "--agent", "codex", "--json"])
    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["totals"]["skipped"] == 1
    assert data["files"][0]["skipped_reason"] == "agent-root-missing"


def test_cli_scan_agent_nondir_root_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    cx = tmp_path / "cx"
    (cx / "sessions").mkdir(parents=True)
    (cx / "sessions").rmdir()
    (cx / "sessions").write_text("file not dir")
    monkeypatch.setenv("CODEX_HOME", str(cx))
    code = main(["scan", "--agent", "codex", "--json"])
    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["files"][0]["skipped_reason"] == "agent-root-not-directory"


def test_cli_scan_explicit_path_overrides_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sess = tmp_path / "sess.jsonl"
    sess.write_text(SESSION_LINE)
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "nope"))
    code = main(["scan", str(tmp_path), "--agent", "codex", "--json"])
    assert code == 0
    captured = capsys.readouterr()
    assert "overrides --agent" in captured.err
    data = json.loads(captured.out)
    # Scanned the explicit dir, not any codex root
    assert data["totals"]["skipped"] == 0


def test_cli_scan_agent_all_merges_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ccfg = tmp_path / "ccfg"
    cx = tmp_path / "cx"
    (ccfg / "projects").mkdir(parents=True)
    (cx / "sessions").mkdir(parents=True)
    (ccfg / "projects" / "a.jsonl").write_text(SESSION_LINE)
    (cx / "sessions" / "b.jsonl").write_text(SESSION_LINE)
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(ccfg))
    monkeypatch.setenv("CODEX_HOME", str(cx))
    code = main(["scan", "--agent", "all", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["totals"]["total"] == 2
    assert code in (0, 1)
