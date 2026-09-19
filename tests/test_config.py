"""Tests for ``[tool.sesslint]`` / ``sesslint.toml`` configuration loading.

Discovery walks upward from the cwd (``sesslint.toml`` > ``.sesslint.toml`` >
``pyproject.toml`` carrying ``[tool.sesslint]``); explicit CLI options always
beat config values; unknown keys, bad types, and unreadable explicit paths
fail closed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.cli import main
from sesslint.config import ConfigError, find_config_file, load_config

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
CORRUPT = FIXTURES / "adapters" / "codex" / "orphan_output.jsonl"  # SL101


def test_load_pyproject_section(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[tool.sesslint]\nignore = ["SL101"]\n', encoding="utf-8"
    )
    cfg = load_config(start=tmp_path)
    assert cfg == {"ignore": ["SL101"]}


def test_load_standalone_toml(tmp_path: Path) -> None:
    (tmp_path / "sesslint.toml").write_text('select = ["SL101"]\n', encoding="utf-8")
    cfg = load_config(start=tmp_path)
    assert cfg == {"select": ["SL101"]}


def test_pyproject_without_section_ignored(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")
    assert load_config(start=tmp_path) == {}
    assert find_config_file(tmp_path) is None


def test_discovery_walks_upward(tmp_path: Path) -> None:
    (tmp_path / "sesslint.toml").write_text('fail_on = "warning"\n', encoding="utf-8")
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    assert find_config_file(nested) == tmp_path / "sesslint.toml"


def test_nearest_file_wins(tmp_path: Path) -> None:
    (tmp_path / "sesslint.toml").write_text('fail_on = "error"\n', encoding="utf-8")
    nested = tmp_path / "sub"
    nested.mkdir()
    (nested / "sesslint.toml").write_text('fail_on = "warning"\n', encoding="utf-8")
    assert find_config_file(nested) == nested / "sesslint.toml"


def test_unknown_key_rejected(tmp_path: Path) -> None:
    (tmp_path / "sesslint.toml").write_text("bogus = true\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="Unknown sesslint config key"):
        load_config(start=tmp_path)


def test_bad_type_rejected(tmp_path: Path) -> None:
    (tmp_path / "sesslint.toml").write_text("fail_on = 3\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="non-empty string"):
        load_config(start=tmp_path)


def test_bad_enum_rejected(tmp_path: Path) -> None:
    (tmp_path / "sesslint.toml").write_text('fail_on = "fatal"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="one of"):
        load_config(start=tmp_path)


def test_malformed_toml_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "sesslint.toml"
    bad.write_text("not = [valid\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="Invalid TOML"):
        load_config(start=tmp_path)


def test_explicit_missing_path_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config(explicit=tmp_path / "nope.toml")


def test_explicit_pyproject_without_section_rejected(tmp_path: Path) -> None:
    proj = tmp_path / "pyproject.toml"
    proj.write_text("[project]\nname = 'x'\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="tool.sesslint"):
        load_config(explicit=proj)


def test_cli_honors_config_ignore(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "sesslint.toml").write_text('ignore = ["SL101"]\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    code = main(["check", str(CORRUPT), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["counts"]["by_code"].get("SL101", 0) == 0
    assert code == 0


def test_cli_explicit_flag_overrides_config(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "sesslint.toml").write_text('ignore = ["SL101"]\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    code = main(["check", str(CORRUPT), "--select", "SL101", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["counts"]["by_code"] == {"SL101": 1}
    assert code == 1


def test_cli_explicit_config_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg_file = tmp_path / "custom.toml"
    cfg_file.write_text('ignore = ["SL101"]\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    code = main(["check", str(CORRUPT), "--config", str(cfg_file), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["counts"]["by_code"].get("SL101", 0) == 0
    assert code == 0


def test_cli_bad_config_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "sesslint.toml").write_text("bogus = true\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    code = main(["check", str(CORRUPT)])
    assert code == 2
    assert "Unknown sesslint config key" in capsys.readouterr().err


def test_scan_honors_config_select(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    import shutil

    sessions = tmp_path / "sessions"
    sessions.mkdir()
    shutil.copy(CORRUPT, sessions / "rollout.jsonl")
    (tmp_path / "sesslint.toml").write_text('ignore = ["SL101"]\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    code = main(["scan", str(sessions), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["totals"]["invalid"] == 0
    assert data["totals"]["healthy"] == 1
    assert code == 0


_WARN_SESSION = {
    "created_at": "2026-09-13T00:00:00Z",
    "events": [
        {
            "actor": "user",
            "id": "e1",
            "kind": "message",
            "parent_id": None,
            "payload": {"text": "a"},
            "seq": 0,
            "ts": "2026-09-13T00:00:00Z",
        },
        {
            "actor": "user",
            "id": "e2",
            "kind": "message",
            "parent_id": None,
            "payload": {"text": "b"},
            "seq": 1,
            "ts": "2026-09-13T00:00:01Z",
        },
    ],
    "schema_version": "sesslint.session/v1",
    "session_id": "warn-test",
    "version": 1,
}


def test_config_fail_on_warning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """fail_on = "warning" in config turns warning-only findings fatal."""
    warn_file = tmp_path / "warn.json"
    warn_file.write_text(json.dumps(_WARN_SESSION), encoding="utf-8")
    (tmp_path / "sesslint.toml").write_text('fail_on = "warning"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert main(["check", str(warn_file)]) == 1


def test_cli_fail_on_flag_overrides_config(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    warn_file = tmp_path / "warn.json"
    warn_file.write_text(json.dumps(_WARN_SESSION), encoding="utf-8")
    (tmp_path / "sesslint.toml").write_text('fail_on = "warning"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert main(["check", str(warn_file), "--fail-on", "error"]) == 0
