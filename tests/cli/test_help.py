"""Tests for CLI help and documentation annotations (TASK-023)."""

from __future__ import annotations

import pytest

from sesslint.cli import main


def test_top_level_help(capsys: pytest.CaptureFixture[str]) -> None:
    """Top-level --help contains description, subcommand list, and exit codes."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "sesslint" in captured.out
    assert "check" in captured.out
    assert "formats" in captured.out
    assert "version" in captured.out
    assert "repair" in captured.out
    assert "verify" in captured.out
    assert "Exit codes:" in captured.out
    assert "0" in captured.out
    assert "1" in captured.out
    assert "2" in captured.out


def test_subcommand_read_write_annotations(capsys: pytest.CaptureFixture[str]) -> None:
    """Each subcommand description has read-only or writes annotations."""

    # check
    with pytest.raises(SystemExit):
        main(["check", "--help"])
    out = capsys.readouterr().out
    assert "[read-only]" in out

    # formats
    with pytest.raises(SystemExit):
        main(["formats", "--help"])
    out = capsys.readouterr().out
    assert "[read-only]" in out

    # version
    with pytest.raises(SystemExit):
        main(["version", "--help"])
    out = capsys.readouterr().out
    assert "[read-only]" in out

    # repair
    with pytest.raises(SystemExit):
        main(["repair", "--help"])
    out = capsys.readouterr().out
    assert "[writes:" in out

    # verify
    with pytest.raises(SystemExit):
        main(["verify", "--help"])
    out = capsys.readouterr().out
    assert "[read-only]" in out
