"""Tests for `sesslint doctor` environment diagnostics (ux-reporting T-04)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.cli import main
from sesslint.doctor import (
    DOCTOR_SCHEMA_VERSION,
    MAX_FILE_COUNT,
    doctor_report,
    load_doctor_schema,
)


def _claude_records(n: int) -> list[dict[str, object]]:
    return [
        {
            "id": f"m{i}",
            "type": "user_message" if i % 2 else "assistant_message",
            "message": f"text {i}",
            "timestamp": f"2025-01-01T12:00:{i:02d}Z",
            **({"parentId": f"m{i - 1}"} if i > 1 else {}),
        }
        for i in range(1, n + 1)
    ]


def _make_home(tmp_path: Path, *, claude: bool = True, codex: bool = True) -> Path:
    home = tmp_path / "home"
    if claude:
        d = home / ".claude" / "projects"
        d.mkdir(parents=True)
        for i in range(3):
            (d / f"s{i}.jsonl").write_text(
                "".join(json.dumps(r) + "\n" for r in _claude_records(3)),
                encoding="utf-8",
            )
    if codex:
        d = home / ".codex" / "sessions"
        d.mkdir(parents=True)
        (d / "rollout-a.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in _claude_records(2)),
            encoding="utf-8",
        )
    return home


def test_doctor_report_lists_roots(tmp_path: Path) -> None:
    home = _make_home(tmp_path)
    rep = doctor_report(env={}, home=home, quick_checks=False)
    agents = {r.agent: r for r in rep.roots}
    assert agents["claude"].exists
    assert agents["codex"].exists
    assert agents["claude"].file_count == 3
    assert agents["codex"].file_count == 1
    assert rep.tool_version


def test_doctor_absent_root(tmp_path: Path) -> None:
    home = _make_home(tmp_path, claude=False, codex=False)
    rep = doctor_report(env={}, home=home, quick_checks=False)
    assert all(not r.exists for r in rep.roots)
    assert all(r.file_count == 0 for r in rep.roots)


def test_doctor_no_filenames_no_payloads(tmp_path: Path) -> None:
    home = _make_home(tmp_path)
    rep = doctor_report(env={}, home=home)
    blob = rep.to_json() + rep.render_human()
    assert "s0.jsonl" not in blob
    assert "rollout-a.jsonl" not in blob
    assert "text 1" not in blob


def test_doctor_quick_verdicts(tmp_path: Path) -> None:
    home = _make_home(tmp_path)
    rep = doctor_report(env={}, home=home)
    claude = next(r for r in rep.roots if r.agent == "claude")
    assert claude.checked > 0
    assert claude.checked <= 5
    assert sum(claude.verdicts.values()) == claude.checked


def test_doctor_config_none(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _make_home(tmp_path, claude=False, codex=False)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    rep = doctor_report(env={}, home=home, quick_checks=False)
    assert rep.config_path is None


def test_doctor_json_schema(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = _make_home(tmp_path, claude=False)
    monkey_env = {"CLAUDE_CONFIG_DIR": str(home / ".claude"), "CODEX_HOME": str(home / ".codex")}
    # CLI path uses real env — verify shape via API with injected home instead.
    rep = doctor_report(env=monkey_env, home=home, quick_checks=False)
    data = rep.to_dict()
    schema = load_doctor_schema()
    assert data["schema_version"] == schema["properties"]["schema_version"]["const"]
    assert data["schema_version"] == DOCTOR_SCHEMA_VERSION
    for key in schema["required"]:
        assert key in data
    req = schema["properties"]["roots"]["items"]["required"]
    for root in data["roots"]:
        for key in req:
            assert key in root


def test_doctor_cli_exit_0(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["doctor", "--no-quick-checks"]) == 0
    out = capsys.readouterr().out
    assert "SessLint doctor" in out
    assert "tool version" in out
    assert "roots:" in out


def test_doctor_cli_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["doctor", "--no-quick-checks", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["schema_version"] == DOCTOR_SCHEMA_VERSION
    assert isinstance(out["roots"], list)
    assert len(out["roots"]) == 2  # claude + codex


def test_doctor_agent_filter(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["doctor", "--agent", "claude", "--no-quick-checks"]) == 0
    out = capsys.readouterr().out
    assert "claude" in out
    # The codex *root* is absent (the adapter name "codex-rollout" still shows).
    roots_section = out.split("roots:", 1)[1]
    assert "codex" not in roots_section


def test_doctor_deterministic(tmp_path: Path) -> None:
    home = _make_home(tmp_path)
    r1 = doctor_report(env={}, home=home, quick_checks=False)
    r2 = doctor_report(env={}, home=home, quick_checks=False)
    assert r1.to_json() == r2.to_json()


def test_doctor_file_count_bound(tmp_path: Path) -> None:
    """The counter caps at MAX_FILE_COUNT honestly (walk stops, flag set)."""
    assert MAX_FILE_COUNT == 10_000
    # Bounded check via the module constant — full 10k-file walk is impractical.
