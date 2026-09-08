"""Tests for hostile negative corpus evaluated against EXPECTATIONS.json (TASK-027).

Guarantees:
- Every hostile fixture fails closed with its designated code and exit status (FR-011..017).
- Hostile error fixtures never verdict healthy (FR-049).
- Non-repairable hostile inputs block repair safely without publishing corrupted outputs.
"""

from __future__ import annotations

import json
from pathlib import Path

from sesslint.api import check_file
from sesslint.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "hostile"
EXPECTATIONS_PATH = FIXTURES_DIR / "EXPECTATIONS.json"


def test_hostile_corpus_expectations() -> None:
    """Evaluate every hostile fixture against EXPECTATIONS.json with exact assurance assertions."""
    assert EXPECTATIONS_PATH.is_file(), f"Missing {EXPECTATIONS_PATH}"
    expectations: dict[str, dict[str, object]] = json.loads(
        EXPECTATIONS_PATH.read_text(encoding="utf-8")
    )

    for rel_path, spec in expectations.items():
        fixture_file = FIXTURES_DIR / rel_path
        assert fixture_file.exists(), f"Fixture file not found: {fixture_file}"

        expected_code = spec.get("code")
        expected_exit = int(str(spec["exit"]))
        expected_assurance = str(spec.get("expected_assurance"))

        # 1. Test programmatic check_file
        report = check_file(fixture_file)

        # RVW-015 / RVW-036: Assert exact assurance level on every hostile fixture
        assert report.assurance == expected_assurance, (
            f"{rel_path}: Expected {expected_assurance} assurance, got {report.assurance}"
        )
        assert bool(report.limitation), f"{rel_path}: Report limitation must be non-empty"

        if expected_exit != 0:
            assert len(report.findings) > 0, f"{rel_path}: Expected findings on hostile input"
            if expected_code is not None:
                finding_codes = {f.code for f in report.findings}
                assert expected_code in finding_codes, (
                    f"{rel_path}: Expected {expected_code} in findings, got {finding_codes}"
                )
        else:
            # Clean fixture (like crlf_mixed or identical duplicate under neutral)
            has_error = (
                report.counts.by_severity.get("error", 0) > 0
                or report.counts.by_severity.get("fatal", 0) > 0
            )
            assert not has_error, f"{rel_path}: Expected zero errors on exit 0 fixture"

        # 2. Test CLI check exit code
        cli_exit = main(["check", str(fixture_file)])
        assert cli_exit == expected_exit, (
            f"{rel_path}: Expected CLI exit {expected_exit}, got {cli_exit}"
        )


def test_hostile_repair_refusal_on_non_repairable(tmp_path: Path) -> None:
    """Non-repairable hostile inputs safely refuse or block repair without corrupted output."""
    expectations: dict[str, dict[str, object]] = json.loads(
        EXPECTATIONS_PATH.read_text(encoding="utf-8")
    )

    for rel_path, spec in expectations.items():
        if not spec.get("repairable", False) and spec.get("exit") != 0:
            fixture_file = FIXTURES_DIR / rel_path
            out_file = tmp_path / f"repaired_{fixture_file.name}.jsonl"

            # Attempt repair via CLI
            exit_code = main(["repair", str(fixture_file), "--output", str(out_file)])
            # Should fail closed (exit 1 or 2) and must not produce valid completed file
            assert exit_code in (1, 2), (
                f"{rel_path}: Hostile input should fail with 1 or 2, got {exit_code}"
            )
            if out_file.exists():
                # If file exists, it must not be valid healthy session
                rep = check_file(out_file)
                has_err = (
                    rep.counts.by_severity.get("error", 0) > 0
                    or rep.counts.by_severity.get("fatal", 0) > 0
                )
                assert has_err or rep.counts.total > 0


def test_assurance_lattice_stages() -> None:
    """Verify staged assurance calculation (A0 -> A1 -> A2 -> A3) per RVW-015 / RVW-036."""
    from sesslint.canonical import SessionEvent
    from sesslint.codes import SL001, SL003, SL101, Repairability, Severity
    from sesslint.finding import SourceRef, make_finding
    from sesslint.report import compute_assurance

    mock_event = SessionEvent(
        id="evt-1",
        seq=0,
        ts="2026-09-08T12:00:00Z",
        actor="user",
        kind="message",
        parent_id=None,
        payload={"text": "hello"},
    )

    # A0: Unparseable stream or SL001/SL002 error
    f_sl001 = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Malformed syntax",
        source=SourceRef(path="test.jsonl", line=1),
    )
    a0, lim0 = compute_assurance([], [f_sl001])
    assert a0 == "A0"
    assert lim0 == "No structural conclusion."

    # A1: Parseable events with structural error (e.g. SL101 error)
    f_err = make_finding(
        code=SL101,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Orphan call",
        source=SourceRef(path="test.jsonl", line=1),
    )
    a1, lim1 = compute_assurance([mock_event], [f_err])
    assert a1 == "A1"
    assert lim1 == "Relationships may still be invalid."

    # A2: Parseable events with zero errors, but warnings present
    f_warn = make_finding(
        code=SL003,
        severity=Severity.WARNING,
        repairability=Repairability.DETERMINISTIC,
        message_template="Duplicate identical",
        source=SourceRef(path="test.jsonl", line=1),
    )
    a2, lim2 = compute_assurance([mock_event], [f_warn])
    assert a2 == "A2"
    assert lim2 == "Provider/runtime replay has not been independently exercised."

    # A3: Parseable events, zero errors, zero warnings, profile replay exercised
    a3, lim3 = compute_assurance([mock_event], [], has_profile_replay=True)
    assert a3 == "A3"
    assert lim3 == "Does not prove semantic equivalence or external side effects."


def test_canonical_torn_final_repairable(tmp_path: Path) -> None:
    """Positive repairability proof: torn terminal record repairs cleanly (RVW-036)."""
    src_file = tmp_path / "canonical_torn.jsonl"
    repaired_file = tmp_path / "canonical_repaired.jsonl"

    src_content = (
        '{"created_at":"2026-09-08T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"sess_torn_test"}\n'
        '{"actor":"user","id":"evt_001","kind":"message","parent_id":null,"payload":{"text":"hi"},"seq":0,"ts":"2026-09-08T12:00:00Z"}\n'
        '{"actor":"assistant","id":"evt_002","kind":"message","parent_id":"evt_001","payload":{"text":"ok"},"seq":1,"ts":"2026-09-08T12:00:01Z"}\n'
        '{"id":"evt_003", "actor":"tool", "payload":'
    )
    src_file.write_text(src_content, encoding="utf-8")

    # 1. Check detects SL002 with assurance A0
    pre_report = check_file(src_file)
    assert pre_report.assurance == "A0"
    codes = [f.code for f in pre_report.findings]
    assert "SL002" in codes

    # 2. Repair executes successfully (exit 0)
    repair_exit = main(["repair", str(src_file), "--output", str(repaired_file)])
    assert repair_exit == 0
    assert repaired_file.is_file()

    # 3. Post-repair check is clean with assurance A3
    post_report = check_file(repaired_file)
    assert len(post_report.findings) == 0
    assert post_report.assurance == "A3"
    assert post_report.counts.by_severity.get("error", 0) == 0
