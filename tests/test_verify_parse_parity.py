"""Strict-parse parity and unified plan (de)serialization tests (DW-T-08).

Two contracts pinned here:

1. ``verify._parse_session_events`` enforces the same hostile-input semantics
   as ``sesslint.io``: strict JSON constants (no NaN/Infinity/out-of-range
   floats), bounded nesting depth, bounded line size, bounded file size, and
   NUL rejection — while still tolerating a missing session header.

2. ``RepairPlan.from_dict`` is the single authoritative plan deserializer:
   ``min_policy``/``recipe_version`` round-trip and are REQUIRED (fail closed
   on plans missing them, rather than silently defaulting safety fields).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sesslint.io import DEFAULT_READER_LIMITS
from sesslint.repair.executor import load_plan
from sesslint.repair.fingerprint import compute_plan_fingerprint
from sesslint.repair.planner import RepairPlan
from sesslint.verify import _parse_session_events, verify

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "repair"

HEADER_LINE = (
    '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1",'
    '"session_id":"parity-sess"}'
)
EVENT_LINE = (
    '{"actor":"user","id":"msg-0","kind":"message","parent_id":null,'
    '"payload":{"text":"hi"},"seq":0,"ts":"2026-09-05T12:00:00Z"}'
)


# ---------------------------------------------------------------------------
# Strict-parse parity: hostile inputs rejected identically to io.py
# ---------------------------------------------------------------------------


def test_parse_events_rejects_nan() -> None:
    raw = (HEADER_LINE + "\n" + EVENT_LINE.replace('"hi"', "NaN") + "\n").encode()
    with pytest.raises(ValueError):
        _parse_session_events(raw)


def test_parse_events_rejects_infinity() -> None:
    raw = (HEADER_LINE + "\n" + EVENT_LINE.replace('"hi"', "Infinity") + "\n").encode()
    with pytest.raises(ValueError):
        _parse_session_events(raw)


def test_parse_events_rejects_out_of_range_float() -> None:
    """1e999 overflows to inf — strict reader rejects, verify must too."""
    raw = (HEADER_LINE + "\n" + EVENT_LINE.replace('"hi"', "1e999") + "\n").encode()
    with pytest.raises(ValueError):
        _parse_session_events(raw)


def test_parse_events_rejects_deep_nesting() -> None:
    depth = DEFAULT_READER_LIMITS.max_depth + 10
    nested = "[" * depth + "]" * depth
    raw = (HEADER_LINE + "\n" + nested + "\n").encode()
    with pytest.raises(ValueError):
        _parse_session_events(raw)


def test_parse_events_rejects_oversized_line() -> None:
    big = "x" * (DEFAULT_READER_LIMITS.max_line_bytes + 1)
    line = EVENT_LINE.replace('"hi"', '"' + big + '"')
    raw = (HEADER_LINE + "\n" + line + "\n").encode()
    with pytest.raises(ValueError):
        _parse_session_events(raw)


def test_parse_events_rejects_nul_byte() -> None:
    raw = (HEADER_LINE + "\n" + EVENT_LINE.replace('"hi"', '"a\x00b"') + "\n").encode("utf-8")
    with pytest.raises(ValueError):
        _parse_session_events(raw)


def test_parse_events_rejects_invalid_utf8() -> None:
    raw = HEADER_LINE.encode() + b"\n" + b'{"actor":"user","id":"m",\xff\xfe}' + b"\n"
    with pytest.raises(ValueError):
        _parse_session_events(raw)


def test_parse_events_rejects_oversized_file() -> None:
    """File-size cap is enforced in the fallback too — a session that check
    refuses for size must not be tolerated by verify (DW-T-08)."""
    raw = b"x" * (DEFAULT_READER_LIMITS.max_file_bytes + 1)
    with pytest.raises(ValueError):
        _parse_session_events(raw)


def test_parse_events_tolerates_headerless_jsonl() -> None:
    """Missing header remains tolerated — that is the fallback's purpose."""
    raw = (EVENT_LINE + "\n").encode()
    header, events = _parse_session_events(raw)
    assert header is None
    assert len(events) == 1
    assert events[0].id == "msg-0"


def test_parse_events_accepts_valid_jsonl() -> None:
    raw = (HEADER_LINE + "\n" + EVENT_LINE + "\n").encode()
    header, events = _parse_session_events(raw)
    assert header is not None
    assert header.session_id == "parity-sess"
    assert len(events) == 1


# ---------------------------------------------------------------------------
# Plan (de)serialization: unified path, required safety fields
# ---------------------------------------------------------------------------


def _fixture_plan() -> RepairPlan:
    return load_plan(FIXTURES_DIR / "exec_basic" / "plan.json")


def test_plan_roundtrip_preserves_safety_fields() -> None:
    plan = _fixture_plan()
    loaded = RepairPlan.from_dict(plan.to_dict())
    assert loaded == plan
    for step in loaded.steps:
        assert step.min_policy
        assert step.recipe_version


def test_plan_roundtrip_through_file(tmp_path: Path) -> None:
    plan = _fixture_plan()
    p = tmp_path / "plan.json"
    p.write_text(json.dumps(plan.to_dict()), encoding="utf-8")
    loaded = load_plan(p)
    assert loaded == plan


@pytest.mark.parametrize("field", ["seq", "recipe", "min_policy", "recipe_version"])
def test_plan_from_dict_rejects_missing_required_step_field(field: str) -> None:
    plan_dict = _fixture_plan().to_dict()
    del plan_dict["steps"][0][field]
    with pytest.raises(ValueError):
        RepairPlan.from_dict(plan_dict)


def test_plan_from_dict_unwraps_expected_plan() -> None:
    plan_dict = _fixture_plan().to_dict()
    wrapped: dict[str, Any] = {"expected_plan": plan_dict, "note": "fixture"}
    assert RepairPlan.from_dict(wrapped) == RepairPlan.from_dict(plan_dict)


def test_plan_from_dict_recomputes_missing_fingerprint() -> None:
    plan_dict = _fixture_plan().to_dict()
    del plan_dict["fingerprint"]
    loaded = RepairPlan.from_dict(plan_dict)
    assert loaded.fingerprint == compute_plan_fingerprint(plan_dict)


def test_load_plan_rejects_plan_missing_safety_fields(tmp_path: Path) -> None:
    """A plan file whose steps lack min_policy fails closed (DW-T-08)."""
    plan_dict = _fixture_plan().to_dict()
    for step in plan_dict["steps"]:
        del step["min_policy"]
    p = tmp_path / "plan.json"
    p.write_text(json.dumps(plan_dict), encoding="utf-8")
    with pytest.raises(ValueError):
        load_plan(p)


# ---------------------------------------------------------------------------
# verify() end-to-end: hostile output artifact fails closed
# ---------------------------------------------------------------------------


def test_verify_rejects_nan_in_output(tmp_path: Path) -> None:
    """A headerless output artifact containing NaN fails closed in verify.

    The missing header forces the strict-reader fallback path; the NaN line
    must then be rejected rather than silently tolerated (DW-T-08).
    """
    from tests.test_verify import _write_ok_bundle

    d = tmp_path / "bundle"
    src, plan_p, out, man = _write_ok_bundle(d)
    hostile = (
        EVENT_LINE.replace('"hi"', "NaN")
        + "\n"
        + EVENT_LINE.replace("msg-0", "msg-1").replace('"seq":0', '"seq":1')
        + "\n"
    )
    out.write_bytes(hostile.encode())

    v = verify(source_path=src, output_path=out, manifest_path=man, plan_path=plan_p)
    c_map = {c.name: c for c in v.checks}
    assert c_map["transformation_audit"].ok is False
    assert "output-parse-failed" in c_map["transformation_audit"].detail
