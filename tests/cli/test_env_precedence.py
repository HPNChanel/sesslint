"""Settings precedence tests: CLI > environment > config file > default.

Each test chdirs into ``tmp_path`` so the repository ``pyproject.toml`` is
never discovered, and clears the ``SESSLINT_*`` variables it does not set.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"
HEALTHY = FIXTURES_DIR / "cli" / "check_basic" / "healthy.jsonl"

SESSLINT_ENV = ("SESSLINT_CONFIG", "SESSLINT_PROFILE", "SESSLINT_ADAPTER", "SESSLINT_FORMAT")


def _run(argv: list[str]) -> int:
    try:
        return main(argv)
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 0


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for var in SESSLINT_ENV:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)


def _write_config(directory: Path, body: str, name: str = "sesslint.toml") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(body, encoding="utf-8")
    return path


def _adapter_id(capsys: pytest.CaptureFixture[str]) -> str:
    doc = json.loads(capsys.readouterr().out)
    return str(doc["coverage"]["adapter"]["id"])


def _profile_id(capsys: pytest.CaptureFixture[str]) -> str:
    doc = json.loads(capsys.readouterr().out)
    return str(doc["coverage"]["profile"]["id"])


def test_config_beats_default_adapter(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _write_config(tmp_path, 'adapter = "canonical"\n')
    rc = _run(["check", str(HEALTHY), "--json"])
    assert rc in (0, 1)
    assert _adapter_id(capsys) == "canonical"


def test_env_beats_config_adapter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_config(tmp_path, 'adapter = "canonical"\n')
    monkeypatch.setenv("SESSLINT_ADAPTER", "claude-code-jsonl")
    rc = _run(["check", str(HEALTHY), "--json"])
    assert rc in (0, 1)
    assert _adapter_id(capsys) == "claude-code-jsonl"


def test_cli_beats_env_adapter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_config(tmp_path, 'adapter = "canonical"\n')
    monkeypatch.setenv("SESSLINT_ADAPTER", "canonical")
    rc = _run(["check", str(HEALTHY), "--adapter", "claude-code-jsonl", "--json"])
    assert rc in (0, 1)
    assert _adapter_id(capsys) == "claude-code-jsonl"


def test_config_beats_default_profile(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _write_config(tmp_path, 'profile = "claude-strict"\n')
    rc = _run(["check", str(HEALTHY), "--json"])
    assert rc in (0, 1)
    assert _profile_id(capsys) == "claude-strict"


def test_env_beats_config_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_config(tmp_path, 'profile = "neutral"\n')
    monkeypatch.setenv("SESSLINT_PROFILE", "claude-strict")
    rc = _run(["check", str(HEALTHY), "--json"])
    assert rc in (0, 1)
    assert _profile_id(capsys) == "claude-strict"


def test_cli_beats_env_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SESSLINT_PROFILE", "claude-strict")
    rc = _run(["check", str(HEALTHY), "--profile", "neutral", "--json"])
    assert rc in (0, 1)
    assert _profile_id(capsys) == "neutral"


def test_env_output_format_applies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SESSLINT_FORMAT", "json")
    rc = _run(["check", str(HEALTHY)])
    assert rc in (0, 1)
    assert _adapter_id(capsys) == "claude-code-jsonl"


def test_cli_format_beats_env_output_format(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SESSLINT_FORMAT", "json")
    rc = _run(["check", str(HEALTHY), "--format", "sarif"])
    assert rc in (0, 1)
    assert '"$schema"' in capsys.readouterr().out


def test_config_path_from_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = _write_config(tmp_path / "conf", 'adapter = "canonical"\n')
    monkeypatch.setenv("SESSLINT_CONFIG", str(cfg))
    rc = _run(["check", str(HEALTHY), "--json"])
    assert rc in (0, 1)
    assert _adapter_id(capsys) == "canonical"


def test_cli_config_beats_env_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    env_cfg = _write_config(tmp_path, 'adapter = "canonical"\n', name="env.toml")
    cli_cfg = _write_config(tmp_path, 'adapter = "claude-code-jsonl"\n', name="cli.toml")
    monkeypatch.setenv("SESSLINT_CONFIG", str(env_cfg))
    rc = _run(["check", str(HEALTHY), "--config", str(cli_cfg), "--json"])
    assert rc in (0, 1)
    assert _adapter_id(capsys) == "claude-code-jsonl"


def test_invalid_env_adapter_exits_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SESSLINT_ADAPTER", "bogus")
    rc = _run(["check", str(HEALTHY)])
    assert rc == 2
    assert "SESSLINT_ADAPTER" in capsys.readouterr().err


def test_env_format_rejected_on_command_without_choice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SESSLINT_FORMAT", "sarif")
    rc = _run(["doctor", "--no-quick-checks"])
    assert rc == 2
    assert "SESSLINT_FORMAT" in capsys.readouterr().err
