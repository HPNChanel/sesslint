"""Tests for SL001 (malformed record) and SL002 (torn terminal record) detectors.

Verifies the tear-vs-malformed decision rule, coordinate extraction, and taxonomy
properties established in DEMAND.md, FR-017, AC-003, and AC-004.
"""

from __future__ import annotations

from pathlib import Path

from sesslint.canonical import SessionEvent
from sesslint.codes import SL001, SL002, Repairability, Severity
from sesslint.finding import Finding
from sesslint.io import iter_events

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "sessions"


class TestDecisionMatrix:
    """SL001 vs SL002 classification matrix:

    {mid-file broken, last-line broken, last-line broken + trailing newlines}
    -> {SL001, SL002, SL002}
    """

    def test_mid_file_broken_produces_sl001(self, tmp_path: Path) -> None:
        file_path = tmp_path / "mid_broken.jsonl"
        file_path.write_text(
            '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1",'
            '"session_id":"sess_matrix"}\n'
            '{"actor":"user","id":"evt_001","kind":"message","parent_id":null,"payload":{},"seq":0,"ts":"2026-09-05T12:00:00Z"}\n'
            '{"id":"evt_broken", malformed mid-stream line\n'
            '{"actor":"assistant","id":"evt_002","kind":"message","parent_id":"evt_001","payload":{},"seq":1,"ts":"2026-09-05T12:00:01Z"}\n',
            encoding="utf-8",
        )

        items = list(iter_events(file_path))
        assert len(items) == 3
        assert isinstance(items[0], SessionEvent)
        assert items[0].id == "evt_001"

        assert isinstance(items[1], Finding)
        assert items[1].code == SL001
        assert items[1].source.line == 3
        assert items[1].source.record_id == "evt_broken"
        assert items[1].severity == Severity.ERROR
        assert items[1].repairability == Repairability.MANUAL

        assert isinstance(items[2], SessionEvent)
        assert items[2].id == "evt_002"

    def test_last_line_broken_produces_sl002(self, tmp_path: Path) -> None:
        file_path = tmp_path / "last_broken.jsonl"
        file_path.write_text(
            '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1",'
            '"session_id":"sess_matrix"}\n'
            '{"actor":"user","id":"evt_001","kind":"message","parent_id":null,"payload":{},"seq":0,"ts":"2026-09-05T12:00:00Z"}\n'
            '{"id":"evt_torn", "actor":"tool", "payload":',
            encoding="utf-8",
        )

        items = list(iter_events(file_path))
        assert len(items) == 2
        assert isinstance(items[0], SessionEvent)
        assert items[0].id == "evt_001"

        assert isinstance(items[1], Finding)
        assert items[1].code == SL002
        assert items[1].source.line == 3
        assert items[1].source.record_id == "evt_torn"
        assert items[1].severity == Severity.ERROR
        assert items[1].repairability == Repairability.DETERMINISTIC

    def test_last_line_broken_with_trailing_newlines_produces_sl002(self, tmp_path: Path) -> None:
        file_path = tmp_path / "last_broken_newlines.jsonl"
        file_path.write_text(
            '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1",'
            '"session_id":"sess_matrix"}\n'
            '{"actor":"user","id":"evt_001","kind":"message","parent_id":null,"payload":{},"seq":0,"ts":"2026-09-05T12:00:00Z"}\n'
            '{"id":"evt_torn_tail", "kind":"tool_result", \n'
            "\n"
            "   \n"
            "\t\n",
            encoding="utf-8",
        )

        items = list(iter_events(file_path))
        assert len(items) == 2
        assert isinstance(items[0], SessionEvent)
        assert items[0].id == "evt_001"

        assert isinstance(items[1], Finding)
        assert items[1].code == SL002
        assert items[1].source.line == 3
        assert items[1].source.record_id == "evt_torn_tail"
        assert items[1].severity == Severity.ERROR
        assert items[1].repairability == Repairability.DETERMINISTIC


class TestGoldenFixtures:
    """Conformance against golden session fixtures."""

    def test_minimal_valid_fixture(self) -> None:
        """Clean 3-event session produces 3 events and 0 findings."""
        fixture_path = FIXTURES_DIR / "minimal-valid.jsonl"
        items = list(iter_events(fixture_path))
        assert len(items) == 3
        assert all(isinstance(item, SessionEvent) for item in items)
        events = [item for item in items if isinstance(item, SessionEvent)]
        assert [e.id for e in events] == ["evt_001", "evt_002", "evt_003"]

    def test_torn_tail_fixture(self) -> None:
        """Torn tail produces prior events + exactly 1 SL002 (AC-003)."""
        fixture_path = FIXTURES_DIR / "torn-tail.jsonl"
        items = list(iter_events(fixture_path))
        assert len(items) == 3

        # Prior events preserved
        assert isinstance(items[0], SessionEvent)
        assert items[0].id == "evt_001"
        assert isinstance(items[1], SessionEvent)
        assert items[1].id == "evt_002"

        # Exactly one SL002 finding with exact coordinates
        assert isinstance(items[2], Finding)
        finding = items[2]
        assert finding.code == SL002
        assert finding.source.line == 4
        assert finding.source.record_id == "evt_003"
        assert finding.severity == Severity.ERROR
        assert finding.repairability == Repairability.DETERMINISTIC
        assert "Torn terminal record" in finding.message

    def test_malformed_line_fixture(self) -> None:
        """Malformed line 2 of 5 produces 4 events + 1 SL001 with line==2 (AC-004)."""
        fixture_path = FIXTURES_DIR / "malformed-line.jsonl"
        items = list(iter_events(fixture_path))
        assert len(items) == 5

        events = [item for item in items if isinstance(item, SessionEvent)]
        findings = [item for item in items if isinstance(item, Finding)]

        assert len(events) == 4
        assert len(findings) == 1

        # Event IDs
        assert [e.id for e in events] == ["evt_001", "evt_003", "evt_004", "evt_005"]

        # Malformed line 2 finding
        finding = findings[0]
        assert finding.code == SL001
        assert finding.source.line == 2
        assert finding.source.record_id == "evt_002"
        assert finding.severity == Severity.ERROR
        assert finding.repairability == Repairability.MANUAL
        assert "Malformed record" in finding.message

    def test_deep_nesting_fixture(self) -> None:
        """Deep nesting fixture produces prior event + SL002 finding."""
        fixture_path = FIXTURES_DIR / "deep-nesting.jsonl"
        items = list(iter_events(fixture_path))
        assert len(items) == 2
        assert isinstance(items[0], SessionEvent)
        assert items[0].id == "evt_001"

        assert isinstance(items[1], Finding)
        finding = items[1]
        assert finding.code == SL002
        assert finding.source.line == 3
        assert finding.source.record_id == "evt_002"
        assert "LIMIT" in finding.message


class TestEdgeCases:
    """Boundary and adversarial edge cases."""

    def test_single_line_torn(self, tmp_path: Path) -> None:
        file_path = tmp_path / "single_torn.jsonl"
        file_path.write_text('{"id":"evt_single", "actor":', encoding="utf-8")

        items = list(iter_events(file_path))
        assert len(items) == 1
        assert isinstance(items[0], Finding)
        assert items[0].code == SL002
        assert items[0].source.line == 1
        assert items[0].source.record_id == "evt_single"

    def test_single_line_valid_event(self, tmp_path: Path) -> None:
        file_path = tmp_path / "single_valid.jsonl"
        file_path.write_text(
            '{"actor":"user","id":"evt_single","kind":"message","parent_id":null,"payload":{},"seq":0,"ts":"2026-09-05T12:00:00Z"}\n',
            encoding="utf-8",
        )

        items = list(iter_events(file_path))
        assert len(items) == 1
        assert isinstance(items[0], SessionEvent)
        assert items[0].id == "evt_single"

    def test_broken_line_without_record_id(self, tmp_path: Path) -> None:
        file_path = tmp_path / "no_id.jsonl"
        file_path.write_text(
            '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1",'
            '"session_id":"sess_no_id"}\n'
            "GARBAGE_NO_ID_HERE\n",
            encoding="utf-8",
        )

        items = list(iter_events(file_path))
        assert len(items) == 1
        assert isinstance(items[0], Finding)
        assert items[0].code == SL002
        assert items[0].source.line == 2
        assert items[0].source.record_id is None
        assert "<none>" in items[0].message

    def test_broken_line_with_credential_in_id_suppressed(self, tmp_path: Path) -> None:
        """If broken line contains credentials in id, finding suppresses it."""
        file_path = tmp_path / "leak_id.jsonl"
        file_path.write_text(
            '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1",'
            '"session_id":"sess_leak"}\n'
            '{"id": "sk-secret1234567890abcdef", bad_json\n',
            encoding="utf-8",
        )

        items = list(iter_events(file_path))
        assert len(items) == 1
        assert isinstance(items[0], Finding)
        assert items[0].source.record_id is None
        assert "sk-secret" not in items[0].message

    def test_continuation_after_multiple_sl001(self, tmp_path: Path) -> None:
        """Reader continues across multiple nonterminal errors."""
        file_path = tmp_path / "multi_sl001.jsonl"
        file_path.write_text(
            '{"actor":"user","id":"evt_001","kind":"message","parent_id":null,"payload":{},"seq":0,"ts":"2026-09-05T12:00:00Z"}\n'
            "BAD_1\n"
            "BAD_2\n"
            '{"actor":"assistant","id":"evt_002","kind":"message","parent_id":"evt_001","payload":{},"seq":1,"ts":"2026-09-05T12:00:01Z"}\n',
            encoding="utf-8",
        )

        items = list(iter_events(file_path))
        assert len(items) == 4
        assert isinstance(items[0], SessionEvent)
        assert items[0].id == "evt_001"
        assert isinstance(items[1], Finding)
        assert items[1].code == SL001
        assert items[1].source.line == 2
        assert isinstance(items[2], Finding)
        assert items[2].code == SL001
        assert items[2].source.line == 3
        assert isinstance(items[3], SessionEvent)
        assert items[3].id == "evt_002"


def test_sl002_repair_round_trip(tmp_path: Path) -> None:
    """Detector -> Planner -> Executor -> Re-check round-trip for SL002 (RVW-002)."""
    from sesslint import api
    from sesslint.repair.planner import plan

    source_file = tmp_path / "torn_canonical.jsonl"
    source_file.write_text(
        '{"schema_version":"sesslint.session/v1","session_id":"sess_sl002_rt","created_at":"2026-09-05T12:00:00Z"}\n'
        '{"actor":"user","id":"e0","kind":"message","parent_id":null,"payload":{"text":"hello"},"seq":0,"ts":"2026-09-05T12:00:00Z"}\n'
        '{"actor":"assistant","id":"e1","kind":"message","parent_id":"e0","payload":{"text":"hi"},"seq":1,"ts":"2026-09-05T12:00:01Z"}\n'
        '{"actor":"assistant","id":"e2","kind":"message","parent_id":"e1","payload":',
        encoding="utf-8",
    )

    # 1. Detector: check_file emits SL002 with deterministic repairability
    report = api.check_file(source_file)
    assert report.counts.by_code.get("SL002") == 1
    sl002_findings = [f for f in report.findings if f.code == "SL002"]
    assert len(sl002_findings) == 1
    assert sl002_findings[0].repairability == Repairability.DETERMINISTIC

    # 2. Planner: plans torn-terminal-record-discard
    events = [
        SessionEvent(
            id="e0",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={"text": "hello"},
        ),
        SessionEvent(
            id="e1",
            parent_id="e0",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="message",
            payload={"text": "hi"},
        ),
    ]
    p = plan(sl002_findings, events)
    assert len(p.steps) == 1
    assert p.steps[0].recipe == "torn-terminal-record-discard"

    # 3. Executor: api.repair executes cleanly
    output_file = tmp_path / "repaired_sl002.jsonl"
    res_plan, manifest = api.repair(source_file, output_file)
    assert output_file.is_file()
    assert len(res_plan.steps) == 1
    assert res_plan.steps[0].recipe == "torn-terminal-record-discard"
    assert manifest is not None

    # 4. Re-check: output has 0 findings
    recheck_report = api.check_file(output_file)
    assert recheck_report.counts.total == 0
    assert len(recheck_report.findings) == 0
