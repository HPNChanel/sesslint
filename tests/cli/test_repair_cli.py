"""Tests for sesslint repair CLI command wiring and refusals (TASK-024)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from sesslint.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "repair_cli"


def test_repair_cli_basic_success(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Repair execution writes repaired session and manifest, exiting 0."""
    src = FIXTURES_DIR / "basic" / "source.jsonl"
    out = tmp_path / "repaired.jsonl"

    code = main(["repair", str(src), "--out", str(out)])
    assert code == 0
    assert out.is_file()
    assert (tmp_path / "repaired.jsonl.manifest.json").is_file()

    captured = capsys.readouterr()
    assert "Repair successful" in captured.out
    assert "Manifest written to" in captured.out


def test_repair_cli_dry_run_creates_no_files(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Repair with --dry-run prints plan summary and writes no files to disk."""
    src = FIXTURES_DIR / "basic" / "source.jsonl"
    out = tmp_path / "should_not_exist.jsonl"

    code = main(["repair", str(src), "--out", str(out), "--dry-run"])
    assert code == 0
    assert not out.exists()
    assert not (tmp_path / "should_not_exist.jsonl.manifest.json").exists()

    captured = capsys.readouterr()
    assert "Plan fingerprint:" in captured.out


def test_repair_cli_refuses_existing_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Repair refuses to overwrite an existing output file, exiting 1."""
    src = FIXTURES_DIR / "basic" / "source.jsonl"
    out = tmp_path / "existing.jsonl"
    out.write_text("existing content", encoding="utf-8")

    code = main(["repair", str(src), "--out", str(out)])
    assert code == 1
    assert out.read_text(encoding="utf-8") == "existing content"

    captured = capsys.readouterr()
    assert (
        "refusing to overwrite" in captured.err.lower() or "repair refused" in captured.err.lower()
    )


def test_repair_cli_refuses_self_path(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Repair refuses when output resolves to source path, exiting 1."""
    src = tmp_path / "self_source.jsonl"
    shutil.copyfile(FIXTURES_DIR / "basic" / "source.jsonl", src)

    code = main(["repair", str(src), "--out", str(src)])
    assert code == 1

    captured = capsys.readouterr()
    assert (
        "resolves to source path" in captured.err.lower()
        or "repair refused" in captured.err.lower()
    )


def test_repair_cli_refuses_live_store(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Repair refuses to write to a detected live store path, exiting 1."""
    src = FIXTURES_DIR / "basic" / "source.jsonl"
    live_out = tmp_path / ".claude" / "projects" / "out.jsonl"

    code = main(["repair", str(src), "--out", str(live_out)])
    assert code == 1

    captured = capsys.readouterr()
    assert "live-store" in captured.err.lower() or "repair refused" in captured.err.lower()


def test_repair_cli_invalid_policy_shorthand_exits_2(tmp_path: Path) -> None:
    """Invalid policy option or shorthand causes parser exit 2."""
    src = FIXTURES_DIR / "basic" / "source.jsonl"
    out = tmp_path / "out.jsonl"

    with pytest.raises(SystemExit) as exc_info:
        main(["repair", str(src), "--out", str(out), "--policy", "s"])
    assert exc_info.value.code == 2
