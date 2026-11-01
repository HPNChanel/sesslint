"""Mutation-driven unit tests for the private helpers in checks/checkpoint.py (CL-15).

The helpers accept either ``SessionEvent`` objects, arbitrary attribute
objects, or plain mappings; the broader checkpoint tests only drive the
``SessionEvent`` path.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from sesslint.canonical import SessionEvent
from sesslint.checks import checkpoint as cp
from sesslint.codes import SL201, Repairability, Severity
from sesslint.finding import SourceRef, make_finding

# ------------------------------------------------------------- _safe_id


def test_safe_id_passthrough_none_and_redaction() -> None:
    assert cp._safe_id("abc-1") == "abc-1"
    assert cp._safe_id(None) == "<redacted>"
    assert cp._safe_id("user@example.com") == "<redacted>"
    assert cp._safe_id("line\nbreak") == "<redacted>"


def test_source_record_id() -> None:
    assert cp._source_record_id(None) is None
    assert cp._source_record_id("   ") is None
    assert cp._source_record_id("") is None
    assert cp._source_record_id(" id ") == " id "
    assert cp._source_record_id("a@b.com") == "<redacted>"


# --------------------------------------------------- _cap_finding_sort_key


def _f(code_rec: str, evidence: Any = None, rec: str | None = None) -> Any:
    return make_finding(
        code=SL201,
        severity=Severity.WARNING,
        repairability=Repairability.MANUAL,
        message_template="Checkpoint gap for record {record_id}",
        source=SourceRef(path="p", line=None, record_id=rec),
        evidence=evidence,
    )


def test_cap_sort_key_overflow_flag() -> None:
    plain = _f("x", {"a": 1}, "r")
    no_ev = _f("x", None, "r")
    flagged = _f("x", {"overflow": True}, "r")
    not_true = _f("x", {"overflow": 1}, "r")
    assert cp._cap_finding_sort_key(plain)[1] == 0
    assert cp._cap_finding_sort_key(no_ev)[1] == 0
    assert cp._cap_finding_sort_key(flagged)[1] == 1
    assert cp._cap_finding_sort_key(not_true)[1] == 0
    key = cp._cap_finding_sort_key(plain)
    assert key == ("SL201", 0, "r", plain.fingerprint)
    assert cp._cap_finding_sort_key(_f("x", None, None))[2] == ""


def test_cap_sort_places_overflow_after_regular_for_same_code() -> None:
    flagged = _f("x", {"overflow": True}, "a")
    plain = _f("x", {"k": 1}, "z")
    assert cp.cap_checkpoint_findings([flagged, plain], code="SL201") == [plain, flagged]


# -------------------------------------------------- _resolve_source_coords


def test_coords_from_attributes_and_mappings() -> None:
    ev = SimpleNamespace(source_location="a\\b.jsonl", source_line=7)
    assert cp._resolve_source_coords(ev, "<canonical>") == ("a/b.jsonl", 7)
    dev = {"source_location": "c\\d.jsonl", "source_line": 9}
    assert cp._resolve_source_coords(dev, "<canonical>") == ("c/d.jsonl", 9)


def test_coords_default_path_rules() -> None:
    ev = SimpleNamespace(source_location="loc.jsonl", source_line=1)
    # explicit path wins even when event has a location
    assert cp._resolve_source_coords(ev, "given\\p.jsonl") == ("given/p.jsonl", 1)
    # canonical placeholder + empty location keeps the placeholder
    empty = SimpleNamespace(source_location="", source_line=1)
    assert cp._resolve_source_coords(empty, "<canonical>")[0] == "<canonical>"
    assert cp._resolve_source_coords({}, "<canonical>") == ("<canonical>", None)
    # non-str location is stringified
    num = SimpleNamespace(source_location=5, source_line=1)
    assert cp._resolve_source_coords(num, "<canonical>")[0] == "5"


@pytest.mark.parametrize("line", [None, 0, -1, True, False, "3", 2.0])
def test_coords_invalid_lines(line: Any) -> None:
    ev = SimpleNamespace(source_location="x", source_line=line)
    assert cp._resolve_source_coords(ev, "p")[1] is None
    assert cp._resolve_source_coords({"source_line": line}, "p")[1] is None


def test_coords_line_one_and_two_accepted() -> None:
    assert cp._resolve_source_coords({"source_line": 1}, "p")[1] == 1
    assert cp._resolve_source_coords({"source_line": 2}, "p")[1] == 2


# ----------------------------------------------- _get_event_kind / _get_event_id


def _se(**kw: Any) -> SessionEvent:
    base: dict[str, Any] = {
        "id": "e1",
        "parent_id": None,
        "seq": 0,
        "ts": "",
        "actor": "assistant",
        "kind": "message",
        "source_line": 1,
        "source_adapter": "x",
        "source_location": "l",
        "extra_fields": {},
    }
    base.update(kw)
    return SessionEvent(**base)


def test_event_kind_all_shapes() -> None:
    assert cp._get_event_kind(_se(kind="checkpoint")) == "checkpoint"
    assert cp._get_event_kind(SimpleNamespace(kind="k")) == "k"
    assert cp._get_event_kind({"kind": "m"}) == "m"
    assert cp._get_event_kind({}) is None
    assert cp._get_event_kind(SimpleNamespace(kind=5)) == "5"
    assert cp._get_event_kind(object()) is None


def test_event_id_all_shapes() -> None:
    assert cp._get_event_id(_se(id="zz")) == "zz"
    assert cp._get_event_id(SimpleNamespace(id="a")) == "a"
    assert cp._get_event_id({"id": "b"}) == "b"
    assert cp._get_event_id({}) is None
    assert cp._get_event_id(object()) is None
    assert cp._get_event_id(None) is None


# ------------------------------------------------- _extract_checkpoint_fields


def test_fields_from_payload_primary_keys() -> None:
    ev = SimpleNamespace(payload={"checkpoint_id": "c1", "seq": 3, "state_hash": "h1"})
    assert cp._extract_checkpoint_fields(ev) == ("c1", 3, "h1")


def test_fields_from_payload_fallback_keys() -> None:
    ev = SimpleNamespace(payload={"id": "c2", "checkpoint_seq": 4, "hash": "h2"})
    assert cp._extract_checkpoint_fields(ev) == ("c2", 4, "h2")


def test_fields_payload_primary_beats_fallback() -> None:
    ev = SimpleNamespace(
        payload={
            "checkpoint_id": "p",
            "id": "q",
            "seq": 1,
            "checkpoint_seq": 2,
            "state_hash": "a",
            "hash": "b",
        }
    )
    assert cp._extract_checkpoint_fields(ev) == ("p", 1, "a")


def test_fields_payload_from_mapping_event() -> None:
    ev = {"payload": {"checkpoint_id": "c", "seq": 5, "state_hash": "h"}}
    assert cp._extract_checkpoint_fields(ev) == ("c", 5, "h")
    assert cp._extract_checkpoint_fields({"payload": {"id": "c", "checkpoint_seq": 6}}) == (
        "c",
        6,
        None,
    )


def test_fields_from_event_attributes_when_no_payload() -> None:
    ev = SimpleNamespace(checkpoint_id="c", seq=2, state_hash="h")
    assert cp._extract_checkpoint_fields(ev) == ("c", 2, "h")


def test_fields_from_mapping_event_top_level() -> None:
    ev = {"checkpoint_id": "c", "seq": 2, "state_hash": "h"}
    assert cp._extract_checkpoint_fields(ev) == ("c", 2, "h")


def test_fields_payload_gaps_filled_from_event() -> None:
    # payload has only an id; seq/hash come from the event itself
    ev = SimpleNamespace(payload={"checkpoint_id": "c"}, seq=8, state_hash="hh")
    assert cp._extract_checkpoint_fields(ev) == ("c", 8, "hh")
    evm = {"payload": {"checkpoint_id": "c"}, "seq": 9, "state_hash": "h9"}
    assert cp._extract_checkpoint_fields(evm) == ("c", 9, "h9")
    # payload missing id -> event-level id
    ev2 = SimpleNamespace(payload={"seq": 1}, checkpoint_id="top")
    assert cp._extract_checkpoint_fields(ev2) == ("top", 1, None)
    evm2 = {"payload": {"seq": 1}, "checkpoint_id": "topm"}
    assert cp._extract_checkpoint_fields(evm2) == ("topm", 1, None)


def test_fields_normalisation() -> None:
    blank = SimpleNamespace(payload={"checkpoint_id": "  ", "state_hash": " "}, seq=True)
    assert cp._extract_checkpoint_fields(blank) == (None, None, None)
    num = SimpleNamespace(payload={"checkpoint_id": 12, "seq": "7", "state_hash": 5})
    assert cp._extract_checkpoint_fields(num) == ("12", None, "5")
    assert cp._extract_checkpoint_fields(SimpleNamespace(seq=0)) == (None, 0, None)
    assert cp._extract_checkpoint_fields(object()) == (None, None, None)
    assert cp._extract_checkpoint_fields({}) == (None, None, None)


def test_fields_seq_key_presence_beats_value() -> None:
    # "seq" present (even None) means checkpoint_seq is not consulted
    ev = SimpleNamespace(payload={"seq": None, "checkpoint_seq": 9})
    assert cp._extract_checkpoint_fields(ev)[1] is None


# -------------------------------------------------------- _coverage_pointer


def test_coverage_pointer_shapes() -> None:
    cov = {"coverage": {"covered_through_id": "e9"}}
    assert cp._coverage_pointer(_se(extra_fields=cov)) == "e9"
    assert cp._coverage_pointer(SimpleNamespace(extra_fields=cov)) == "e9"
    assert cp._coverage_pointer({"extra_fields": cov}) == "e9"
    assert cp._coverage_pointer({}) is None
    assert cp._coverage_pointer(object()) is None
    assert cp._coverage_pointer(SimpleNamespace(extra_fields="x")) is None
    assert cp._coverage_pointer(SimpleNamespace(extra_fields={"coverage": "x"})) is None


@pytest.mark.parametrize("ptr", ["", "  ", None, 5, ["a"]])
def test_coverage_pointer_invalid_values(ptr: Any) -> None:
    ev = SimpleNamespace(extra_fields={"coverage": {"covered_through_id": ptr}})
    assert cp._coverage_pointer(ev) is None


# ------------------------------------------ _extract_run_state_checkpoints


def test_run_state_checkpoint_mapping_aliases() -> None:
    ctx = SimpleNamespace(
        source_metadata={
            "checkpoints": [
                {"id": "a", "seq": 1, "hash": "H"},
                {"checkpoint_id": "b", "checkpoint_seq": 2, "state_hash": "S"},
                {"checkpoint_id": "c", "payload_hash": "P"},
                {},
            ]
        }
    )
    out = cp._extract_run_state_checkpoints(context=ctx)  # type: ignore[arg-type]
    assert out == [
        {"hash": "H", "id": "a", "index": 0, "seq": 1},
        {"hash": "S", "id": "b", "index": 1, "seq": 2},
        {"hash": "P", "id": "c", "index": 2, "seq": None},
        {"hash": None, "id": "chk-runstate-3", "index": 3, "seq": None},
    ]


def test_run_state_checkpoint_object_items_and_seq_strings() -> None:
    ctx = SimpleNamespace(
        source_metadata={
            "checkpoints": [
                SimpleNamespace(id="o", seq=4, hash="h"),
                SimpleNamespace(checkpoint_id="p", checkpoint_seq=5, state_hash="s"),
                SimpleNamespace(id="q", payload_hash="ph"),
                {"id": "r", "seq": " 12 "},
                {"id": "s", "seq": "x1"},
                {"id": "t", "seq": True},
                {"id": "u", "hash": "None"},
                {"id": "v", "hash": "null"},
                {"id": "w", "hash": "  H  "},
                "str-item",
            ]
        }
    )
    out = cp._extract_run_state_checkpoints(context=ctx)  # type: ignore[arg-type]
    assert [(o["id"], o["seq"], o["hash"]) for o in out] == [
        ("o", 4, "h"),
        ("p", 5, "s"),
        ("q", None, "ph"),
        ("r", 12, None),
        ("s", None, None),
        ("t", None, None),
        ("u", None, None),
        ("v", None, None),
        ("w", None, "H"),
        ("chk-runstate-9", None, None),
    ]
