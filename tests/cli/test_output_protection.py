"""Release-05: reports never overwrite consumed sources or auxiliary evidence."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

from sesslint.cli import main

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


def healthy(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((FIXTURES / "cli/check_basic/healthy.jsonl").read_bytes())
    return path


@pytest.mark.parametrize("command", ["check", "scan", "stats"])
def test_scan_cannot_replace_its_child(command: str, tmp_path: Path) -> None:
    source = healthy(tmp_path / "sessions/source.jsonl")
    original = source.read_bytes()
    assert main([command, str(source.parent), "--json", "-o", str(source)]) == 2
    assert source.read_bytes() == original


@pytest.mark.parametrize("target", ["manifest.json", "plan.json"])
def test_verify_preserves_auxiliary_evidence(target: str, tmp_path: Path) -> None:
    source = FIXTURES / "verify/ok"
    for path in source.iterdir():
        (tmp_path / path.name).write_bytes(path.read_bytes())
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    assert (
        main(
            [
                "verify",
                str(tmp_path / "source.jsonl"),
                str(tmp_path / "output.jsonl"),
                "--manifest",
                str(tmp_path / "manifest.json"),
                "--plan",
                str(tmp_path / "plan.json"),
                "--json",
                "-o",
                str(tmp_path / target),
            ]
        )
        == 2
    )
    assert before == {p.name: p.read_bytes() for p in tmp_path.iterdir()}


def test_triage_preserves_state_copy(tmp_path: Path) -> None:
    identity = "11111111-1111-4111-8111-111111111111"
    source = tmp_path / f"rollout-{identity}.jsonl"
    source.write_bytes((FIXTURES / "adapters/codex/healthy_min.jsonl").read_bytes())
    database = tmp_path / "copy.sqlite"
    with sqlite3.connect(database) as con:
        con.execute("CREATE TABLE threads (id TEXT, rollout_path TEXT)")
        con.execute("INSERT INTO threads VALUES (?,?)", (identity, source.name))
    before = database.read_bytes()
    assert main(["triage", str(source), "--state-copy", str(database), "-o", str(database)]) == 2
    assert database.read_bytes() == before


@pytest.mark.parametrize("option", ["-o", "--write-baseline"])
def test_alias_and_baseline_cannot_replace_source(option: str, tmp_path: Path) -> None:
    source = healthy(tmp_path / "source.jsonl")
    alias = tmp_path / "alias.jsonl"
    os.link(source, alias)
    original = source.read_bytes()
    assert main(["check", str(source), option, str(alias)]) == 2
    assert source.read_bytes() == alias.read_bytes() == original


@pytest.mark.parametrize("command", ["check", "stats", "triage"])
def test_discovered_store_cannot_be_report_destination(
    command: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "codex"
    source = healthy(home / "sessions/rollout-11111111-1111-4111-8111-111111111111.jsonl")
    monkeypatch.setenv("CODEX_HOME", str(home))
    original = source.read_bytes()
    options = ["--latest"] if command == "triage" else []
    assert main([command, "--agent", "codex", *options, "-o", str(source)]) == 2
    assert source.read_bytes() == original


def test_config_and_baseline_are_protected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = healthy(tmp_path / "source.jsonl")
    config = tmp_path / "sesslint.toml"
    config.write_text('profile = "neutral"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    original = config.read_bytes()
    assert main(["check", str(source), "-o", str(config)]) == 2
    assert config.read_bytes() == original
    baseline = tmp_path / "baseline.json"
    assert main(["check", str(source), "--write-baseline", str(baseline)]) == 0
    original = baseline.read_bytes()
    assert main(["check", str(source), "--baseline", str(baseline), "-o", str(baseline)]) == 2
    assert baseline.read_bytes() == original


def test_new_report_inside_scan_root_is_safe(tmp_path: Path) -> None:
    source = healthy(tmp_path / "source.jsonl")
    output = tmp_path / "report.json"
    original = source.read_bytes()
    assert main(["check", str(tmp_path), "--json", "-o", str(output)]) == 0
    assert json.loads(output.read_text())["totals"]["healthy"] == 1
    assert source.read_bytes() == original


@pytest.mark.parametrize("option", ["-o", "--write-baseline"])
@pytest.mark.parametrize("existing", [False, True])
def test_seal_ledger_cannot_be_report_destination(
    option: str, existing: bool, tmp_path: Path
) -> None:
    source = healthy(tmp_path / "source.jsonl")
    ledger = tmp_path / "ledger.jsonl"
    if existing:
        assert main(["check", str(source), "--seal", str(ledger)]) == 0
    before = ledger.read_bytes() if existing else None
    assert main(["check", str(source), "--seal", str(ledger), option, str(ledger)]) == 2
    assert (ledger.read_bytes() if ledger.exists() else None) == before
