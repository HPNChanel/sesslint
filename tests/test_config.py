"""Tests for ``[tool.sesslint]`` / ``sesslint.toml`` configuration loading.

Discovery walks upward from the cwd (``sesslint.toml`` > ``.sesslint.toml`` >
``pyproject.toml`` carrying ``[tool.sesslint]``); explicit CLI options always
beat config values; unknown keys, bad types, a file that sets both ``select``
and ``ignore``, and unreadable explicit paths fail closed.

A ``pyproject.toml`` whose bytes contain the literal marker ``[tool.sesslint``
but which cannot be parsed fails closed (``ConfigError`` / CLI exit 2) and
must not be replaced by a parent config. A ``pyproject.toml`` that does not
contain that marker is not a sesslint config: invalid TOML there is skipped
so a parent config can still be used.
"""

from __future__ import annotations

import json
import tomllib
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


def _toml_decode_error(text: str) -> str:
    try:
        tomllib.loads(text)
    except tomllib.TOMLDecodeError as err:
        return str(err)
    raise AssertionError("fixture TOML was valid")


def test_malformed_pyproject_with_sesslint_marker_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Present-but-unparseable ``[tool.sesslint`` must not use a parent config."""
    (tmp_path / "sesslint.toml").write_text('ignore = ["SL101"]\n', encoding="utf-8")
    nested = tmp_path / "sub"
    nested.mkdir()
    bad = nested / "pyproject.toml"
    text = '[tool.sesslint]\nignore = ["SL101"\n'
    bad.write_text(text, encoding="utf-8")
    parse_error = _toml_decode_error(text)

    with pytest.raises(ConfigError, match="Invalid TOML") as exc_info:
        load_config(start=nested)
    message = str(exc_info.value)
    assert str(bad) in message
    assert parse_error in message

    with pytest.raises(ConfigError, match="Invalid TOML") as found:
        find_config_file(nested)
    assert str(bad) in str(found.value)
    assert parse_error in str(found.value)

    monkeypatch.chdir(nested)
    code = main(["check", str(CORRUPT), "--json"])
    captured = capsys.readouterr()
    assert code == 2
    assert "Invalid TOML" in captured.err
    assert str(bad) in captured.err
    assert parse_error in captured.err
    assert captured.out == ""


def test_malformed_pyproject_without_sesslint_marker_falls_back(tmp_path: Path) -> None:
    """Invalid ``pyproject.toml`` with no sesslint marker is not a sesslint config.

    Discovery skips it. A parent ``sesslint.toml`` is still used. When nothing
    above the file declares sesslint config, discovery yields no config
    instead of raising.
    """
    lone = tmp_path / "lone"
    lone.mkdir()
    (lone / "pyproject.toml").write_text("not = [valid\n", encoding="utf-8")
    assert find_config_file(lone) is None
    assert load_config(start=lone) == {}

    (tmp_path / "sesslint.toml").write_text('fail_on = "warning"\n', encoding="utf-8")
    nested = tmp_path / "sub"
    nested.mkdir()
    (nested / "pyproject.toml").write_text("[project]\nname = [broken\n", encoding="utf-8")
    assert find_config_file(nested) == tmp_path / "sesslint.toml"
    assert load_config(start=nested) == {"fail_on": "warning"}


def test_undecodable_pyproject_with_sesslint_marker_fails_closed(tmp_path: Path) -> None:
    """Invalid UTF-8 plus the sesslint marker is a parse failure, not a skip."""
    (tmp_path / "sesslint.toml").write_text('ignore = ["SL101"]\n', encoding="utf-8")
    nested = tmp_path / "sub"
    nested.mkdir()
    bad = nested / "pyproject.toml"
    bad.write_bytes(b"[tool.sesslint]\xff")
    with pytest.raises(ConfigError, match="Invalid TOML") as exc_info:
        load_config(start=nested)
    message = str(exc_info.value)
    assert str(bad) in message
    assert "utf-8" in message


def test_undecodable_pyproject_without_sesslint_marker_falls_back(tmp_path: Path) -> None:
    """Invalid UTF-8 without the marker is skipped, same as invalid TOML."""
    (tmp_path / "sesslint.toml").write_text('fail_on = "warning"\n', encoding="utf-8")
    nested = tmp_path / "sub"
    nested.mkdir()
    (nested / "pyproject.toml").write_bytes(b"\xffnot sesslint")
    assert find_config_file(nested) == tmp_path / "sesslint.toml"
    assert load_config(start=nested) == {"fail_on": "warning"}


def test_doctor_malformed_pyproject_with_marker_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    nested = tmp_path / "sub"
    nested.mkdir()
    bad = nested / "pyproject.toml"
    bad.write_text("[tool.sesslint]\nignore = [\n", encoding="utf-8")
    monkeypatch.chdir(nested)
    code = main(["doctor", "--no-quick-checks"])
    captured = capsys.readouterr()
    assert code == 2
    assert "Operational error" not in captured.err
    assert "Invalid TOML" in captured.err
    assert str(bad) in captured.err
    assert captured.out == ""


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


def test_select_and_ignore_together_rejected(tmp_path: Path) -> None:
    """Both keys are a usage error; the message names the config file."""
    cfg_path = tmp_path / "sesslint.toml"
    cfg_path.write_text('select = ["SL001"]\nignore = ["SL002"]\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="mutually exclusive") as exc:
        load_config(start=tmp_path)
    message = str(exc.value)
    assert str(cfg_path) in message
    assert "select" in message and "ignore" in message


def test_cli_select_and_ignore_config_exits_nonzero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """``sesslint check`` must not succeed when the config sets both keys."""
    cfg_path = tmp_path / "sesslint.toml"
    cfg_path.write_text('select = ["SL001"]\nignore = ["SL002"]\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    code = main(["check", str(CORRUPT)])
    err = capsys.readouterr().err
    assert code != 0
    assert code == 2
    assert str(cfg_path) in err
    assert "select" in err and "ignore" in err


def test_cli_config_only_select_still_applies(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "sesslint.toml").write_text('select = ["SL101"]\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    code = main(["check", str(CORRUPT), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["counts"]["by_code"] == {"SL101": 1}
    assert code == 1


def test_cli_config_only_ignore_still_applies(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "sesslint.toml").write_text('ignore = ["SL101"]\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    code = main(["check", str(CORRUPT), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["counts"]["by_code"].get("SL101", 0) == 0
    assert code == 0


def test_cli_config_neither_select_nor_ignore_unchanged(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "sesslint.toml").write_text('fail_on = "error"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    code = main(["check", str(CORRUPT), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["counts"]["by_code"].get("SL101", 0) == 1
    assert code == 1


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
