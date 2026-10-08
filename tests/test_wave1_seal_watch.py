"""Concurrent append and snapshot regressions (B26-B28)."""

from __future__ import annotations

import hashlib
import json
import multiprocessing
from pathlib import Path
from types import SimpleNamespace

import pytest

from sesslint.cli import main
from sesslint.seal import append_seal, verify_ledger


def _append_worker(path: str) -> None:
    for _ in range(3):
        append_seal(
            path,
            tool="check",
            file_sha256="a" * 64,
            path=None,
            verdict="ok",
            codes={},
            report_sha256="b" * 64,
        )


def test_two_processes_append_one_continuous_chain(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ctx = multiprocessing.get_context("spawn")
    children = [ctx.Process(target=_append_worker, args=(str(ledger),)) for _ in range(2)]
    for child in children:
        child.start()
    try:
        for child in children:
            child.join(25)
            assert child.exitcode == 0
        assert verify_ledger(ledger) == (6, None)
    finally:
        for child in children:
            if child.is_alive():
                child.terminate()
                child.join(5)


def test_unterminated_valid_ledger_line_gets_separator(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    _append_worker(str(ledger))
    ledger.write_bytes(ledger.read_bytes().rstrip(b"\n"))
    _append_worker(str(ledger))
    assert verify_ledger(ledger) == (6, None)


@pytest.mark.parametrize("bad", ["[" * 1100 + "]" * 1100, "9" * 5000])
def test_hostile_ledger_reports_divergence_without_crashing(tmp_path: Path, bad: str) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text(bad)
    count, failure = verify_ledger(ledger)
    assert count == 0
    assert failure is not None and failure["kind"] == "malformed-line"


def test_watch_over_capacity_does_not_starve_active_files(tmp_path: Path, monkeypatch) -> None:
    import sesslint.watch as module

    monkeypatch.setattr(module, "MAX_TRACKED_FILES", 3)
    files = [tmp_path / f"{i}.jsonl" for i in range(5)]
    for path in files:
        path.write_text("synthetic")
    checked = []

    def check(path):
        checked.append(path)
        return SimpleNamespace(counts=SimpleNamespace(by_severity={}), findings=[])

    with pytest.warns(RuntimeWarning, match="active-file count"):
        module.watch([tmp_path], check_fn=check, sleep_fn=lambda _: None, max_polls=3)
    assert sorted(checked) == files


def test_cli_seal_uses_snapshot_before_concurrent_append(tmp_path: Path, monkeypatch) -> None:
    from sesslint.adapters import load
    from tests.test_wave1_scan import _session

    source = tmp_path / "input.jsonl"
    before = _session(source)
    ledger = tmp_path / "ledger.jsonl"
    real_loader = load.load_events_for_format

    def load_then_append(*args, **kwargs):
        result = real_loader(*args, **kwargs)
        source.write_bytes(before + b"changed\n")
        return result

    monkeypatch.setattr(load, "load_events_for_format", load_then_append)
    assert main(["check", str(source), "--seal", str(ledger)]) == 0
    entry = json.loads(ledger.read_text())
    assert entry["file_sha256"] == hashlib.sha256(before).hexdigest()
