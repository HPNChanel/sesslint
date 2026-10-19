"""Tests for interactive TTY progress (Step 3).

``TtyProgress`` renders single-line ``\r``-prefixed counters on stderr
only when stderr is a TTY and neither ``-q`` nor ``--no-progress`` was
given. stdout report bytes are never affected.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

from sesslint.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"
HEALTHY = FIXTURES_DIR / "cli" / "check_basic" / "healthy.jsonl"
SCAN_DIR = FIXTURES_DIR / "scan" / "mixed"


class _FakeTty(io.StringIO):
    def isatty(self) -> bool:
        return True


def _run(argv: list[str]) -> int:
    try:
        return main(argv)
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 0


def test_tty_progress_writes_stderr(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = _FakeTty()
    monkeypatch.setattr(sys, "stderr", fake)
    rc = _run(["check", str(SCAN_DIR), "--json"])
    assert rc in (0, 1)
    assert "\r" in fake.getvalue()
    # stdout remains a clean JSON report.
    assert capsys.readouterr().out.startswith("{")


def test_stdout_unchanged_by_tty_progress(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = _run(["check", str(SCAN_DIR), "--json"])
    assert rc in (0, 1)
    baseline = capsys.readouterr().out
    fake = _FakeTty()
    monkeypatch.setattr(sys, "stderr", fake)
    rc = _run(["check", str(SCAN_DIR), "--json"])
    assert rc in (0, 1)
    assert capsys.readouterr().out == baseline


def test_no_progress_on_non_tty(capsys: pytest.CaptureFixture[str]) -> None:
    rc = _run(["check", str(SCAN_DIR), "--json"])
    assert rc in (0, 1)
    captured = capsys.readouterr()
    assert "\r" not in captured.err


def test_no_progress_flag_suppresses(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = _FakeTty()
    monkeypatch.setattr(sys, "stderr", fake)
    rc = _run(["check", str(SCAN_DIR), "--json", "--no-progress"])
    assert rc in (0, 1)
    assert "\r" not in fake.getvalue()


def test_quiet_suppresses_tty_progress(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = _FakeTty()
    monkeypatch.setattr(sys, "stderr", fake)
    rc = _run(["check", str(SCAN_DIR), "--json", "-q"])
    assert rc in (0, 1)
    assert "\r" not in fake.getvalue()
