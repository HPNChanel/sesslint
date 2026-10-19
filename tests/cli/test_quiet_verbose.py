"""Tests for ``-q/--quiet`` and ``-v/--verbose`` (Step 3).

Report bytes on stdout are never affected by the verbosity flags: JSON
output is compared byte-for-byte. ``-q`` suppresses non-error stderr
channels and the ``Valid ... session`` human banner; ``-v`` adds
``debug:`` provenance and elapsed-time lines to stderr.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sesslint.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"
HEALTHY = FIXTURES_DIR / "cli" / "check_basic" / "healthy.jsonl"


def _run(argv: list[str]) -> int:
    try:
        return main(argv)
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 0


def test_quiet_drops_valid_banner(capsys: pytest.CaptureFixture[str]) -> None:
    rc = _run(["check", str(HEALTHY), "-q"])
    assert rc == 0
    assert "Valid Claude Code session" not in capsys.readouterr().out


def test_valid_banner_without_quiet(capsys: pytest.CaptureFixture[str]) -> None:
    rc = _run(["check", str(HEALTHY)])
    assert rc == 0
    assert "Valid Claude Code session" in capsys.readouterr().out


def test_quiet_suppresses_stderr_hints(capsys: pytest.CaptureFixture[str]) -> None:
    # --jobs on a single file emits an informational stderr note.
    rc = _run(["check", str(HEALTHY), "--jobs", "2"])
    assert rc == 0
    loud_err = capsys.readouterr().err
    assert "Note: --jobs is ignored" in loud_err
    rc = _run(["check", str(HEALTHY), "--jobs", "2", "-q"])
    assert rc == 0
    quiet_err = capsys.readouterr().err
    assert "Note: --jobs is ignored" not in quiet_err


def test_verbose_emits_debug_lines(capsys: pytest.CaptureFixture[str]) -> None:
    rc = _run(["check", str(HEALTHY), "-v"])
    assert rc == 0
    err = capsys.readouterr().err
    assert "debug:" in err
    assert "elapsed" in err


def test_no_debug_lines_without_verbose(capsys: pytest.CaptureFixture[str]) -> None:
    rc = _run(["check", str(HEALTHY)])
    assert rc == 0
    assert "debug:" not in capsys.readouterr().err


def test_json_stdout_bytes_identical_across_verbosity(
    capsys: pytest.CaptureFixture[str],
) -> None:
    outputs: list[bytes] = []
    for extra in ([], ["-q"], ["-v"]):
        rc = _run(["check", str(HEALTHY), "--json", *extra])
        assert rc == 0
        captured = capsys.readouterr()
        outputs.append(captured.out.encode("utf-8"))
    assert outputs[0] == outputs[1] == outputs[2]
