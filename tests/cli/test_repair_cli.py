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
    """Repair refuses to write to a live store (.db, .sqlite, magic bytes), exiting 1."""
    src = FIXTURES_DIR / "basic" / "source.jsonl"

    # 1. Refusal on .sqlite extension
    live_out_sqlite = tmp_path / "live_state.sqlite"
    code_sqlite = main(["repair", str(src), "--out", str(live_out_sqlite)])
    assert code_sqlite == 1
    captured_sqlite = capsys.readouterr()
    assert "refusing to write to live-store path" in captured_sqlite.err.lower()
    assert not live_out_sqlite.exists()

    # 2. Refusal on .db extension
    live_out_db = tmp_path / "app_database.db"
    code_db = main(["repair", str(src), "--out", str(live_out_db)])
    assert code_db == 1
    captured_db = capsys.readouterr()
    assert "refusing to write to live-store path" in captured_db.err.lower()
    assert not live_out_db.exists()

    # 3. Refusal on file with SQLite magic header
    fake_db = tmp_path / "custom_magic_file.bin"
    fake_db.write_bytes(b"SQLite format 3\x00" + b"\x00" * 48)
    code_magic = main(["repair", str(src), "--out", str(fake_db)])
    assert code_magic == 1
    captured_magic = capsys.readouterr()
    assert "refusing to write to live-store path" in captured_magic.err.lower()


def test_repair_cli_invalid_policy_shorthand_exits_2(tmp_path: Path) -> None:
    """Invalid policy option or shorthand causes parser exit 2."""
    src = FIXTURES_DIR / "basic" / "source.jsonl"
    out = tmp_path / "out.jsonl"

    with pytest.raises(SystemExit) as exc_info:
        main(["repair", str(src), "--out", str(out), "--policy", "s"])
    assert exc_info.value.code == 2


def test_repair_cli_rejects_vendor_format_flag_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Repair with explicit vendor --format option exits 2 with instructive message (RVW-019)."""
    src = FIXTURES_DIR / "basic" / "source.jsonl"
    out = tmp_path / "out.jsonl"

    code = main(["repair", str(src), "--out", str(out), "--format", "claude-code-jsonl"])
    assert code == 2
    captured = capsys.readouterr()
    assert "Direct repair of vendor format 'claude-code-jsonl' is not supported" in captured.err
    assert not out.exists()


def test_repair_cli_rejects_detected_vendor_format_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Repair on auto-detected vendor format file exits 2 with instructive message (RVW-019)."""
    fixtures_root = Path(__file__).resolve().parent.parent.parent / "fixtures"
    claude_fixture = fixtures_root / "detect" / "claude_sample.jsonl"
    out = tmp_path / "out.jsonl"

    code = main(["repair", str(claude_fixture), "--out", str(out)])
    assert code == 2
    captured = capsys.readouterr()
    assert "Direct repair of vendor format" in captured.err
    assert "canonical session streams" in captured.err
    assert not out.exists()


def test_repair_api_rejects_vendor_format(tmp_path: Path) -> None:
    """Programmatic api.repair rejects vendor format with RepairRefused (RVW-019)."""
    from sesslint import api
    from sesslint.repair.errors import RepairRefused

    fixtures_root = Path(__file__).resolve().parent.parent.parent / "fixtures"
    claude_fixture = fixtures_root / "detect" / "claude_sample.jsonl"
    out = tmp_path / "out.jsonl"

    with pytest.raises(RepairRefused, match="Direct repair of vendor format"):
        api.repair(claude_fixture, out)
    assert not out.exists()


def test_repair_cli_salvage_unsupported_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Repair with deprecated --salvage-unsupported flag exits 2 with migration guidance."""
    src = FIXTURES_DIR / "basic" / "source.jsonl"
    out = tmp_path / "out.jsonl"

    cmd = [
        "repair",
        str(src),
        "--out",
        str(out),
        "--salvage-unsupported",
        "--dry-run",
        "--json",
    ]
    code = main(cmd)
    assert code == 2
    captured = capsys.readouterr()
    assert (
        "Error: The --salvage-unsupported flag has been deprecated and removed. "
        "Please use '--policy salvage' instead."
    ) in captured.err


def test_repair_cli_sl002_success(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Repair execution on canonical session with SL002 torn tail exits 0 and fixes session."""
    from sesslint import api

    src = tmp_path / "torn_source.jsonl"
    src.write_text(
        '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"s_sl002"}\n'
        '{"actor":"user","id":"e0","kind":"message","parent_id":null,"payload":{"text":"hi"},"seq":0,"ts":"2026-09-05T12:00:00Z"}\n'
        '{"id":"e1_torn", "actor":"tool", "payload":',
        encoding="utf-8",
    )
    out = tmp_path / "repaired_sl002.jsonl"

    code = main(["repair", str(src), "--out", str(out)])
    assert code == 0
    assert out.is_file()
    assert (tmp_path / "repaired_sl002.jsonl.manifest.json").is_file()

    recheck = api.check_file(out)
    assert recheck.counts.total == 0
    assert len(recheck.findings) == 0
