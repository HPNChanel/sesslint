"""Mutation-driven unit tests for adapters/codex_rollout.py (CL-20)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from sesslint.adapters import codex_rollout as cr
from sesslint.codes import SL302, Repairability, Severity
from sesslint.errors import MaxRecordsExceededError
from sesslint.finding import Finding
from sesslint.io import ReaderLimits


def _env(ordinal: int, type_: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "ordinal": ordinal,
        "payload": payload,
        "timestamp": f"2026-09-17T10:{ordinal:02d}:00Z",
        "type": type_,
    }


def _jsonl(*records: dict[str, Any]) -> bytes:
    return ("\n".join(json.dumps(r, sort_keys=True) for r in records) + "\n").encode()


# ------------------------------------------------------------- _emit_sl302


def _emit(type_value: Any, **kw: Any) -> Finding:
    findings: list[Finding] = []
    cr._emit_sl302(
        path_str="p.jsonl",
        line_number=7,
        rec_id="rec-1",
        field_path="payload.type",
        type_value=type_value,
        coord_ev=kw.get("coord_ev", {}),
        findings=findings,
    )
    assert len(findings) == 1
    return findings[0]


def test_emit_sl302_shape_and_severity() -> None:
    f = _emit("weird_type")
    assert f.code == SL302
    assert f.severity is Severity.ERROR
    assert f.repairability is Repairability.MANUAL
    assert f.message == "Unknown critical record on line 7 for record rec-1"
    assert f.source.line == 7
    assert f.source.path == "p.jsonl"
    assert f.source.record_id == "rec-1"
    assert f.evidence["type_value"] == "weird_type"
    assert f.evidence["field_path"] == "payload.type"
    assert "type_truncated" not in f.evidence


def test_emit_sl302_truncated_flag_is_literal_true() -> None:
    f = _emit({"nested": "x"})
    assert f.evidence["type_truncated"] is True
    assert f.evidence["type_value"].startswith("<dict")


def test_emit_sl302_merges_coordinate_evidence() -> None:
    f = _emit("t", coord_ev={"byte_offset": 12})
    assert f.evidence["byte_offset"] == 12


# ------------------------------------------------------ _tool_input_payload


def test_tool_input_payload_variants() -> None:
    assert cr._tool_input_payload(None) == {}
    assert cr._tool_input_payload('{"a": 1}') == {"a": 1}
    assert cr._tool_input_payload("[1, 2]") == {"value": [1, 2]}
    assert cr._tool_input_payload("123") == {"value": 123}
    assert cr._tool_input_payload("not json") == {"value": "not json"}
    src = {"k": "v"}
    out = cr._tool_input_payload(src)
    assert out == {"k": "v"}
    assert out is not src
    assert cr._tool_input_payload(5) == {"value": 5}
    assert cr._tool_input_payload([1]) == {"value": [1]}


# ------------------------------------------------------------ _is_agent_path


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("/morpheus", True),
        ("/root", True),
        ("/root/a_1/b2", True),
        ("/root/", False),  # trailing slash only
        ("/root/a/", False),
        ("/root/root", False),
        ("/root/A", False),
        ("/other", False),
        ("root/a", False),
        ("", False),
        (None, False),
        (5, False),
    ],
)
def test_is_agent_path(value: Any, expected: bool) -> None:
    assert cr._is_agent_path(value) is expected


def test_is_agent_path_slash_prefix_and_suffix_are_independent() -> None:
    # startswith("/") false AND endswith("/") true must still be rejected.
    assert cr._is_agent_path("root/") is False
    assert cr._is_agent_path("root/a/") is False


# ------------------------------------------------------- _version_field_name

_KEYS = ("rollout_version", "format_version", "schema_version", "export_version")


@pytest.mark.parametrize("key", [*_KEYS, "version"])
def test_version_field_name_envelope_keys(key: str) -> None:
    assert cr._version_field_name({key: "1"}, {}) == key


@pytest.mark.parametrize("key", _KEYS)
def test_version_field_name_payload_keys(key: str) -> None:
    assert cr._version_field_name({}, {key: "1"}) == f"payload.{key}"


def test_version_field_name_precedence_and_fallbacks() -> None:
    env = {"version": "1", "format_version": "1"}
    assert cr._version_field_name(env, {"rollout_version": "1"}) == "format_version"
    assert cr._version_field_name({"rollout_version": "", "version": "1"}, {}) == "version"
    assert cr._version_field_name({}, {"version": "1"}) == "version"  # payload has no bare key
    assert cr._version_field_name({}, "not-a-mapping") == "version"
    assert cr._version_field_name({}, {}) == "version"


# ------------------------------------------------ load_codex_rollout_session


def test_session_defaults_when_empty() -> None:
    session, _ = cr.load_codex_rollout_session(b"")
    assert session.events == ()
    assert session.header.created_at == "1970-01-01T00:00:00Z"
    assert session.header.session_id == "codex-rollout-session"
    assert session.header.source is not None
    assert session.header.source["format"] == "codex-rollout"


def test_session_meta_without_session_id_keeps_default() -> None:
    data = _jsonl(_env(0, "session_meta", {}))
    session, _ = cr.load_codex_rollout_session(data)
    assert session.header.session_id == "codex-rollout-session"
    assert session.header.created_at == session.events[0].ts


def test_session_without_session_meta_keeps_default() -> None:
    data = _jsonl(_env(0, "event_msg", {}))
    session, _ = cr.load_codex_rollout_session(data)
    assert session.header.session_id == "codex-rollout-session"


def test_session_id_taken_from_session_meta_and_first_event_ts() -> None:
    data = _jsonl(
        _env(0, "session_meta", {"session_id": "abc"}),
        _env(1, "event_msg", {}),
    )
    session, _ = cr.load_codex_rollout_session(data)
    assert session.header.session_id == "abc"
    assert session.header.created_at == session.events[0].ts
    assert session.header.created_at != session.events[1].ts
    assert session.header.source is not None
    assert session.header.source["session_meta"] == {"session_id": "abc"}
    assert session.header.source["format"] == "codex-rollout"


def test_session_forwards_reader_limits() -> None:
    data = _jsonl(_env(0, "session_meta", {}), _env(1, "event_msg", {}))
    with pytest.raises(MaxRecordsExceededError):
        cr.load_codex_rollout_session(data, limits=ReaderLimits(max_records=1))
