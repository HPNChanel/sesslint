"""Tests for finding sort stability and canonical ordering contracts (FR-094).

Total ordering hierarchy:
1. path (lexicographical, forward-slash normalized)
2. line (None sorts as -1 before line 0, then ascending integer)
3. ordinal (stream record ordinal from evidence['record_ordinal'], None/-1 sorts before 0)
4. severity_rank (fatal < error < warning < info)
5. code (lexicographical)
6. record_id (None sorts as empty string before any non-empty string, then lexicographical)
7. fingerprint (16-character sha256 hex string)

Verifies:
- Shuffled finding sequences sort to the identical sequence under stable_sort_findings.
- Exact order pinning across sort_findings, stable_sort_findings, and render_json.
- Event dict key permutations yield identical canonical JSON bytes and hashes.
"""

from __future__ import annotations

import json
import random

from sesslint.codes import SL001, SL002, SL003, SL101, Repairability, Severity
from sesslint.determinism import canonical_json_bytes, repeat_hash, stable_sort_findings
from sesslint.finding import SourceRef, make_finding, sort_findings
from sesslint.report import build_report, render_json


def test_shuffled_findings_sort_identically() -> None:
    """Findings provided in any arbitrary order sort into identical deterministic order."""
    f1 = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Malformed syntax at line {line}",
        template_args={"line": "5"},
        source=SourceRef(path="session.jsonl", line=5),
        evidence={"byte_offset": 120},
    )
    f2 = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Malformed syntax at line {line}",
        template_args={"line": "12"},
        source=SourceRef(path="session.jsonl", line=12),
        evidence={"byte_offset": 350},
    )
    f3 = make_finding(
        code=SL003,
        severity=Severity.ERROR,
        repairability=Repairability.DETERMINISTIC,
        message_template="Duplicate identifier {record_id}",
        template_args={"record_id": "evt_dup"},
        source=SourceRef(path="session.jsonl", line=8),
        evidence={"byte_offset": 200},
    )
    f4 = make_finding(
        code=SL101,
        severity=Severity.ERROR,
        repairability=Repairability.DETERMINISTIC,
        message_template="Orphan tool return at line {line}",
        template_args={"line": "2"},
        source=SourceRef(path="session.jsonl", line=2),
        evidence={"byte_offset": 50},
    )

    base_list = [f1, f2, f3, f4]
    sorted_reference = stable_sort_findings(base_list)

    # Shuffle repeatedly with different seeds and verify sorted output is identical
    rng = random.Random(0x026)
    for _ in range(10):
        shuffled = list(base_list)
        rng.shuffle(shuffled)
        assert stable_sort_findings(shuffled) == sorted_reference


def test_event_dict_permutation_produces_identical_bytes() -> None:
    """Canonical JSON bytes must be invariant to dict key insertion order."""
    evt1 = {
        "actor": "user",
        "id": "evt_001",
        "kind": "message",
        "parent_id": None,
        "payload": {"text": "hello"},
        "seq": 1,
        "ts": "2026-09-06T00:00:00Z",
    }
    evt2 = {
        "ts": "2026-09-06T00:00:00Z",
        "seq": 1,
        "payload": {"text": "hello"},
        "parent_id": None,
        "kind": "message",
        "id": "evt_001",
        "actor": "user",
    }

    assert canonical_json_bytes(evt1) == canonical_json_bytes(evt2)
    assert repeat_hash(evt1) == repeat_hash(evt2)


def test_fr094_position_first_exact_order_three_entry_points() -> None:
    """Pins exact sequence across sort_findings, stable_sort_findings, and render_json (FR-094).

    Constructs >=8 findings spanning:
    - 2 paths (sessions/a.jsonl, sessions/b.jsonl)
    - multiple line values (None, 1, 2)
    - all severities (FATAL, ERROR, WARNING, INFO)
    - multiple codes (SL001, SL002)
    - ties at every level of the sort hierarchy:
      1. path tie: sessions/a.jsonl
      2. line tie: line 1
      3. ordinal tie: ordinal 1
      4. severity tie: ERROR
      5. code tie: SL002
      6. record_id tie: rec_2
      7. fingerprint tie: exact sha256 tiebreak
    """
    f1 = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        message_template="Syntax error at header line None",
        source=SourceRef(path="sessions/a.jsonl", line=None),
    )

    f2 = make_finding(
        code=SL001,
        severity=Severity.WARNING,
        message_template="Ordinal 0 warning on line 1",
        source=SourceRef(path="sessions/a.jsonl", line=1),
        evidence={"record_ordinal": 0},
    )

    f3 = make_finding(
        code=SL001,
        severity=Severity.FATAL,
        message_template="Ordinal 1 fatal on line 1",
        source=SourceRef(path="sessions/a.jsonl", line=1),
        evidence={"record_ordinal": 1},
    )

    f4 = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        message_template="Ordinal 1 error SL001 on line 1",
        source=SourceRef(path="sessions/a.jsonl", line=1),
        evidence={"record_ordinal": 1},
    )

    f5 = make_finding(
        code=SL002,
        severity=Severity.ERROR,
        message_template="Ordinal 1 error SL002 no rec on line 1",
        source=SourceRef(path="sessions/a.jsonl", line=1),
        evidence={"record_ordinal": 1},
    )

    f6 = make_finding(
        code=SL002,
        severity=Severity.ERROR,
        message_template="Ordinal 1 error SL002 rec_1 on line 1",
        source=SourceRef(path="sessions/a.jsonl", line=1, record_id="rec_1"),
        evidence={"record_ordinal": 1},
    )

    f7_candidate_a = make_finding(
        code=SL002,
        severity=Severity.ERROR,
        message_template="Ordinal 1 error SL002 rec_2 candidate A on line 1",
        source=SourceRef(path="sessions/a.jsonl", line=1, record_id="rec_2"),
        evidence={"record_ordinal": 1, "variant": "cand_a"},
    )
    f7_candidate_b = make_finding(
        code=SL002,
        severity=Severity.ERROR,
        message_template="Ordinal 1 error SL002 rec_2 candidate B on line 1",
        source=SourceRef(path="sessions/a.jsonl", line=1, record_id="rec_2"),
        evidence={"record_ordinal": 1, "variant": "cand_b"},
    )
    # Ensure deterministic tiebreak by fingerprint
    if f7_candidate_a.fingerprint < f7_candidate_b.fingerprint:
        f7_first, f7_second = f7_candidate_a, f7_candidate_b
    else:
        f7_first, f7_second = f7_candidate_b, f7_candidate_a

    f8 = make_finding(
        code=SL001,
        severity=Severity.FATAL,
        message_template="Fatal finding on path b line 1",
        source=SourceRef(path="sessions/b.jsonl", line=1),
    )

    f9 = make_finding(
        code=SL001,
        severity=Severity.INFO,
        message_template="Info finding on path b line 2",
        source=SourceRef(path="sessions/b.jsonl", line=2),
    )

    expected_order = [f1, f2, f3, f4, f5, f6, f7_first, f7_second, f8, f9]
    expected_fingerprints = [f.fingerprint for f in expected_order]

    # Deterministic pseudo-random permutations
    rng = random.Random(0x094)
    for _ in range(5):
        shuffled = list(expected_order)
        rng.shuffle(shuffled)

        # Entry Point 1: sort_findings
        res_sort = sort_findings(shuffled)
        assert res_sort == expected_order

        # Entry Point 2: stable_sort_findings
        res_stable = stable_sort_findings(shuffled)
        assert res_stable == expected_order

        # Entry Point 3: render_json findings array
        report = build_report(
            session_id="00000000-0000-0000-0000-000000000000",
            source_fingerprint="0123456789abcdef",
            tool_version="0.1.0",
            findings=shuffled,
            assurance="A1",
            limitation="Testing FR-094 order pinning",
        )
        rendered_json = render_json(report)
        payload = json.loads(rendered_json)
        rendered_fps = [finding_dict["fingerprint"] for finding_dict in payload["findings"]]
        assert rendered_fps == expected_fingerprints
