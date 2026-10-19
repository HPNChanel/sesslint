"""Tests for ``-o/--output FILE`` atomic report output (Step 3).

The file receives exactly the bytes stdout would have received (text plus
the trailing newline ``print`` appends); a ``wrote ...`` summary line goes
to stdout unless ``-q``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sesslint.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"
HEALTHY = FIXTURES_DIR / "cli" / "check_basic" / "healthy.jsonl"
TRIAGEABLE = FIXTURES_DIR / "claude_code" / "basic.jsonl"


def _run(argv: list[str]) -> int:
    try:
        return main(argv)
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 0


def test_check_output_file_bytes_match_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = _run(["check", str(HEALTHY), "--json"])
    assert rc == 0
    stdout_bytes = capsys.readouterr().out.encode("utf-8")

    out = tmp_path / "report.json"
    rc = _run(["check", str(HEALTHY), "--json", "-o", str(out)])
    assert rc == 0
    assert out.read_bytes() == stdout_bytes


def test_output_file_summary_on_stdout(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "report.json"
    rc = _run(["check", str(HEALTHY), "--json", "-o", str(out)])
    assert rc == 0
    captured = capsys.readouterr()
    assert f"wrote {out}" in captured.out
    assert "finding(s)" in captured.out


def test_quiet_suppresses_summary(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "report.json"
    rc = _run(["check", str(HEALTHY), "--json", "-o", str(out), "-q"])
    assert rc == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert out.is_file()


def test_output_must_not_be_input(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = _run(["check", str(HEALTHY), "--json", "-o", str(HEALTHY)])
    assert rc == 2
    assert "--output" in capsys.readouterr().err


def test_existing_report_overwritten(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "report.json"
    out.write_text("stale", encoding="utf-8")
    rc = _run(["check", str(HEALTHY), "--json", "-o", str(out)])
    assert rc == 0
    assert out.read_bytes().startswith(b"{")


def test_triage_output_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = tmp_path / "session.jsonl"
    source.write_bytes(TRIAGEABLE.read_bytes())
    out = tmp_path / "triage.json"
    rc = _run(["triage", str(source), "--json", "-o", str(out)])
    assert rc in (0, 1)
    assert out.is_file()
    assert "wrote" in capsys.readouterr().out


def test_doctor_output_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "doctor.json"
    rc = _run(["doctor", "--no-quick-checks", "--json", "-o", str(out)])
    assert rc == 0
    assert out.is_file()
    assert "wrote" in capsys.readouterr().out


def test_stats_output_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "stats.json"
    rc = _run(["stats", str(HEALTHY), "--json", "-o", str(out)])
    assert rc == 0
    assert out.is_file()
    assert "wrote" in capsys.readouterr().out
