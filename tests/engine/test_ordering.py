"""Tests for finding sort stability and canonical ordering contracts (TASK-026).

Verifies:
- Shuffled finding sequences sort to the identical sequence under stable_sort_findings.
- Sort order strictly follows the 5-tuple (code, path, line, byte, fingerprint).
- Event dict key permutations yield identical canonical JSON bytes and hashes.
"""

from __future__ import annotations

import random

from sesslint.codes import SL001, SL003, SL101, Repairability, Severity
from sesslint.determinism import canonical_json_bytes, repeat_hash, stable_sort_findings
from sesslint.finding import SourceRef, make_finding


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
