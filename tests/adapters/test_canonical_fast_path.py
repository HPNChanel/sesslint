"""T-10: optimized common records remain equivalent to the diagnostic parser."""

import json
from copy import deepcopy
from unittest.mock import patch

import pytest

from sesslint.adapters import canonical
from sesslint.io import ReaderLimits


@pytest.mark.parametrize(
    "change",
    [
        {},
        {"parent_id": "root"},
        {"id": ""},
        {"id": "unsafe\nvalue"},
        {"seq": True},
        {"seq": -1},
        {"ts": "2026-02-30T00:00:00Z"},
        {"ts": "2026-09-26T01:02:03.123456Z"},
        {"actor": "invalid"},
        {"parent_id": " "},
        {"kind": "tool_result"},
        {"critical_future": 1},
        {"source_line": 7},
        {"payload": {"side_effects": "possible"}},
        {"payload": None},
    ],
)
def test_common_matches_diagnostic(change: dict) -> None:
    raw = {
        "id": "e1",
        "parent_id": None,
        "seq": 0,
        "ts": "2026-09-26T00:00:00Z",
        "actor": "user",
        "kind": "message",
        "payload": {"text": "synthetic"},
    } | change
    original = deepcopy(raw)
    actual_findings, expected_findings = [], []
    actual = canonical._parse_canonical_event_record(
        raw, 0, 2, "synthetic.jsonl", actual_findings.append, validated_timestamps=set()
    )
    with patch.object(canonical, "_common_event", return_value=None):
        expected = canonical._parse_canonical_event_record(
            raw, 0, 2, "synthetic.jsonl", expected_findings.append
        )
    assert actual == expected
    assert actual_findings == expected_findings
    assert raw == original


@pytest.mark.parametrize("depth", [0, 1, 2, 97, 98, 99, 100])
@pytest.mark.parametrize("limit", [1, 2, 100])
@pytest.mark.parametrize("extension", [False, True])
def test_stream_depth_matches_full_record_validation(depth, limit, extension):
    payload = {}
    for _ in range(depth):
        payload = {"nested": payload}
    raw = {
        "id": "e1",
        "parent_id": None,
        "seq": 0,
        "ts": "2026-09-26T00:00:00Z",
        "actor": "user",
        "kind": "message",
        "payload": payload,
    }
    if extension:
        raw["critical_future"] = payload
    header = {
        "schema_version": "sesslint.session/v1",
        "session_id": "synthetic-depth",
        "created_at": raw["ts"],
    }
    # Interleave a candidate fast shape with a diagnostic shape and a clean
    # sibling. Repeated loads must not retain decoder/depth/timestamp state.
    records = [header, raw, dict(raw, actor="invalid"), dict(raw, id="e2", payload={})]
    data = "".join(json.dumps(row) + "\n" for row in records).encode()
    for _ in range(2):
        actual, actual_findings = canonical.load_canonical(
            data, limits=ReaderLimits(max_depth=limit)
        )
        with patch.object(canonical, "_common_event", return_value=None):
            expected, expected_findings = canonical.load_canonical(
                data, limits=ReaderLimits(max_depth=limit)
            )
        assert actual == expected
        assert actual.source == expected.source
        assert actual_findings == expected_findings
