"""End-to-End Integration Tests for check -> repair -> verify cycle (TASK-4.2).

Verifies the complete round-trip lifecycle of session artifacts:
1. Canonical sessions with identical duplicates (SL003) -> repair -> verify -> re-check.
2. Canonical sessions with torn terminal records (SL002) -> repair -> verify -> re-check.
3. Full CLI invocation parity across check, repair, verify subcommands.
4. Idempotency guarantees: repairing an already-repaired session produces identical content.
5. Vendor format boundary: direct repair attempts on vendor sessions safely refuse with exit code 2.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint import api
from sesslint.cli import main


def test_e2e_cycle_canonical_identical_duplicates(tmp_path: Path) -> None:
    """E2E cycle for SL003 identical duplicates: check -> repair -> verify -> re-check."""
    src_file = tmp_path / "source_duplicates.jsonl"
    repaired_file = tmp_path / "repaired_duplicates.jsonl"

    lines = [
        '{"created_at":"2026-09-08T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"sess_e2e_dup"}',
        '{"actor":"user","id":"evt_001","kind":"message","parent_id":null,"payload":{"text":"hello"},"seq":0,"ts":"2026-09-08T12:00:00Z"}',
        '{"actor":"assistant","id":"evt_002","kind":"message","parent_id":"evt_001","payload":{"text":"ack"},"seq":1,"ts":"2026-09-08T12:00:01Z"}',
        '{"actor":"assistant","id":"evt_002","kind":"message","parent_id":"evt_001","payload":{"text":"ack"},"seq":1,"ts":"2026-09-08T12:00:01Z"}',
        '{"actor":"user","id":"evt_003","kind":"message","parent_id":"evt_002","payload":{"text":"next"},"seq":2,"ts":"2026-09-08T12:00:02Z"}',
    ]
    src_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Step 1: Initial check detects SL003 finding
    report_initial = api.check_file(src_file)
    assert len(report_initial.findings) == 1
    assert report_initial.findings[0].code == "SL003"
    assert report_initial.assurance == "A2"

    # Step 2: Repair generates repaired output and manifest
    plan_obj, manifest = api.repair(src_file, repaired_file)
    assert manifest is not None
    assert repaired_file.is_file()
    manifest_path = Path(f"{repaired_file}.manifest.json")
    assert manifest_path.is_file()

    # Step 3: Verify confirms hash bindings, audit, and idempotence
    verdict = api.verify(
        source_path=src_file,
        output_path=repaired_file,
        manifest_path=manifest_path,
    )
    assert verdict.ok is True
    assert all(c.ok for c in verdict.checks)

    # Step 4: Re-check on repaired session yields 0 findings and A3 assurance
    report_recheck = api.check_file(repaired_file)
    assert len(report_recheck.findings) == 0
    assert report_recheck.assurance == "A3"
    assert report_recheck.counts.by_severity.get("error", 0) == 0
    assert report_recheck.counts.by_severity.get("warning", 0) == 0

    # Step 5: Idempotence test - second repair produces identical output
    re_repaired_file = tmp_path / "re_repaired.jsonl"
    plan_obj2, manifest2 = api.repair(repaired_file, re_repaired_file)
    assert re_repaired_file.read_bytes() == repaired_file.read_bytes()


def test_e2e_cycle_canonical_torn_terminal_record(tmp_path: Path) -> None:
    """E2E cycle for SL002 torn terminal record: check -> repair -> verify -> re-check."""
    src_file = tmp_path / "source_torn.jsonl"
    repaired_file = tmp_path / "repaired_torn.jsonl"

    lines = [
        '{"created_at":"2026-09-08T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"sess_e2e_torn"}',
        '{"actor":"user","id":"evt_001","kind":"message","parent_id":null,"payload":{"text":"start"},"seq":0,"ts":"2026-09-08T12:00:00Z"}',
        '{"actor":"assistant","id":"evt_002","kind":"message","parent_id":"evt_001","payload":{"text":"middle"},"seq":1,"ts":"2026-09-08T12:00:01Z"}',
        '{"id":"evt_003","actor":"tool","payload":',
    ]
    src_file.write_text("\n".join(lines), encoding="utf-8")

    # Step 1: Initial check detects SL002 error with A0 assurance
    report_initial = api.check_file(src_file)
    assert any(f.code == "SL002" for f in report_initial.findings)
    assert report_initial.assurance == "A0"

    # Step 2: Repair truncates torn suffix and emits manifest
    plan_obj, manifest = api.repair(src_file, repaired_file)
    assert manifest is not None
    assert repaired_file.is_file()
    manifest_path = Path(f"{repaired_file}.manifest.json")
    assert manifest_path.is_file()

    # Step 3: Verify validates transformation audit and declared loss
    verdict = api.verify(
        source_path=src_file,
        output_path=repaired_file,
        manifest_path=manifest_path,
    )
    assert verdict.ok is True

    # Step 4: Re-check on repaired session is clean with A3 assurance
    report_recheck = api.check_file(repaired_file)
    assert len(report_recheck.findings) == 0
    assert report_recheck.assurance == "A3"


def test_e2e_cli_full_cycle(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """E2E cycle using CLI subcommands: check -> repair -> verify -> check."""
    src = tmp_path / "cli_cycle_src.jsonl"
    out = tmp_path / "cli_cycle_out.jsonl"

    lines = [
        '{"created_at":"2026-09-08T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"sess_cli_e2e"}',
        '{"actor":"user","id":"evt_001","kind":"message","parent_id":null,"payload":{"text":"init"},"seq":0,"ts":"2026-09-08T12:00:00Z"}',
        '{"actor":"assistant","id":"evt_002","kind":"message","parent_id":"evt_001","payload":{"text":"dupe"},"seq":1,"ts":"2026-09-08T12:00:01Z"}',
        '{"actor":"assistant","id":"evt_002","kind":"message","parent_id":"evt_001","payload":{"text":"dupe"},"seq":1,"ts":"2026-09-08T12:00:01Z"}',
    ]
    src.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # 1. CLI Check (neutral profile -> warning SL003, exit 0)
    exit_check1 = main(["check", str(src)])
    assert exit_check1 == 0
    captured1 = capsys.readouterr()
    assert "1 warning(s)" in captured1.out or "SL003" in captured1.out

    # 2. CLI Repair
    exit_repair = main(["repair", str(src), "--out", str(out)])
    assert exit_repair == 0
    capsys.readouterr()
    assert out.is_file()
    man_path = Path(f"{out}.manifest.json")
    assert man_path.is_file()

    # 3. CLI Verify
    exit_verify = main(["verify", str(src), str(out), "--manifest", str(man_path), "--json"])
    assert exit_verify == 0
    captured_ver = capsys.readouterr()
    ver_json = json.loads(captured_ver.out)
    assert ver_json["ok"] is True

    # 4. CLI Re-check on repaired session (0 findings, exit 0)
    exit_check2 = main(["check", str(out)])
    assert exit_check2 == 0
    captured2 = capsys.readouterr()
    assert "Session is healthy" in captured2.out
    assert "errors: 0" in captured2.out
    assert "warnings: 0" in captured2.out


def test_e2e_vendor_format_boundary_rejection(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """E2E format boundary: vendor sessions checkable, but repair refused with exit 2."""
    claude_file = tmp_path / "vendor_session.jsonl"
    out_file = tmp_path / "vendor_repaired.jsonl"

    record1 = {
        "id": "msg_01",
        "type": "user_message",
        "message": "hello",
        "timestamp": "2026-09-08T12:00:00Z",
    }
    record2 = {
        "id": "msg_02",
        "parentId": "msg_01",
        "type": "assistant_message",
        "message": "world",
        "timestamp": "2026-09-08T12:00:01Z",
    }
    claude_file.write_text(
        json.dumps(record1) + "\n" + json.dumps(record2) + "\n", encoding="utf-8"
    )

    # Check works seamlessly on vendor format
    rep = api.check_file(claude_file)
    assert rep.assurance in ("A2", "A3")

    # Repair is refused per Alpha format boundary contract
    exit_code = main(["repair", str(claude_file), "--out", str(out_file)])
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "Direct repair of vendor format" in captured.err
    assert "Repair operates exclusively on canonical session streams" in captured.err
    assert not out_file.exists()
