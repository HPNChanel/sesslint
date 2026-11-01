"""Mutation-driven behaviour tests for SL305 (CL-15)."""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from sesslint.canonical import SessionEvent
from sesslint.checks.foreign_shape import check_foreign_shape
from sesslint.codes import Repairability, Severity
from sesslint.context import CheckContext


def _ev(
    eid: str | None = "e1",
    line: Any = 3,
    *,
    codex: Any = "auto",
    extra: Any = "auto",
    loc: str = "d\\f.jsonl",
) -> SessionEvent:
    if codex == "auto":
        codex = {"item_type": "reasoning", "reasoning_content_shape": "array", "ordinal": 7}
    if extra == "auto":
        extra = {"codex": codex}
    return SessionEvent(
        id=eid,  # type: ignore[arg-type]
        parent_id=None,
        seq=0,
        ts="",
        actor="assistant",
        kind="message",
        source_line=line,
        source_adapter="codex-rollout",
        source_location=loc,
        extra_fields=extra,
    )


def _h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:8]


def test_finding_exact() -> None:
    ctx = CheckContext(
        adapter_id="a",
        adapter_version="1",
        profile_id="p",
        profile_version="2",
        source_metadata={"session_meta": {"model_provider": " acme ", "originator": "x"}},
    )
    (f,) = check_foreign_shape([_ev()], context=ctx)
    assert f.code == "SL305"
    assert f.severity is Severity.WARNING
    assert f.repairability is Repairability.MANUAL
    assert f.message == ("Record shape outside the replay vocabulary on line 3 for record e1")
    assert f.source.path == "d/f.jsonl"
    assert f.source.line == 3
    assert f.source.record_id == "e1"
    assert dict(f.evidence or {}) == {
        "shape_violation": "reasoning-content-non-null",
        "item_family": "reasoning",
        "item_count": 1,
        "first_ordinal": 7,
        "declared_provider_hash": _h("acme"),
        "declared_originator_present": True,
    }


def test_source_path_argument() -> None:
    (f,) = check_foreign_shape([_ev()], source_path="given.jsonl")
    assert f.source.path == "given.jsonl"


@pytest.mark.parametrize("shape", ["array", "other"])
def test_both_foreign_shapes_fire(shape: str) -> None:
    ev = _ev(codex={"item_type": "reasoning", "reasoning_content_shape": shape})
    assert len(check_foreign_shape([ev])) == 1


@pytest.mark.parametrize("shape", ["null", "string", "", None, 5, ["array"]])
def test_non_foreign_shapes_silent(shape: Any) -> None:
    ev = _ev(codex={"item_type": "reasoning", "reasoning_content_shape": shape})
    assert check_foreign_shape([ev]) == []


@pytest.mark.parametrize("item_type", ["message", "Reasoning", None, 3, ""])
def test_other_item_types_silent(item_type: Any) -> None:
    ev = _ev(codex={"item_type": item_type, "reasoning_content_shape": "array"})
    assert check_foreign_shape([ev]) == []


@pytest.mark.parametrize(
    "extra", [None, "s", [], {}, {"codex": None}, {"codex": "s"}, {"codex": []}]
)
def test_malformed_extra_silent(extra: Any) -> None:
    assert check_foreign_shape([_ev(extra=extra)]) == []


def test_count_and_first_event_anchor() -> None:
    evs = [
        _ev("ok", 1, codex={"item_type": "message"}),
        _ev(
            "a",
            2,
            codex={"item_type": "reasoning", "reasoning_content_shape": "array", "ordinal": 4},
        ),
        _ev(
            "b",
            5,
            codex={"item_type": "reasoning", "reasoning_content_shape": "other", "ordinal": 1},
        ),
    ]
    (f,) = check_foreign_shape(evs)
    ev = dict(f.evidence or {})
    assert ev["item_count"] == 2
    assert ev["first_ordinal"] == 4
    assert f.source.record_id == "a"
    assert f.source.line == 2


@pytest.mark.parametrize("ordinal", [None, True, "3", 2.0, -1])
def test_invalid_or_negative_ordinal_omitted(ordinal: Any) -> None:
    ev = _ev(
        codex={"item_type": "reasoning", "reasoning_content_shape": "array", "ordinal": ordinal}
    )
    (f,) = check_foreign_shape([ev])
    assert "first_ordinal" not in dict(f.evidence or {})


def test_ordinal_zero_is_reported() -> None:
    ev = _ev(codex={"item_type": "reasoning", "reasoning_content_shape": "array", "ordinal": 0})
    (f,) = check_foreign_shape([ev])
    assert dict(f.evidence or {})["first_ordinal"] == 0


def _ctx_meta(sm: Any) -> CheckContext:
    return CheckContext(source_metadata=sm)


def test_no_provider_evidence_without_meta() -> None:
    for sm in (None, {}, {"session_meta": None}, {"session_meta": "x"}, {"session_meta": {}}):
        (f,) = check_foreign_shape([_ev()], context=_ctx_meta(sm))
        ev = dict(f.evidence or {})
        assert "declared_provider_hash" not in ev
        assert "declared_originator_present" not in ev


@pytest.mark.parametrize("prov", ["", "   ", None, 4])
def test_blank_provider_omitted(prov: Any) -> None:
    ctx = _ctx_meta({"session_meta": {"model_provider": prov}})
    (f,) = check_foreign_shape([_ev()], context=ctx)
    assert "declared_provider_hash" not in dict(f.evidence or {})


def test_originator_presence_only_when_not_none() -> None:
    ctx = _ctx_meta({"session_meta": {"originator": None}})
    (f,) = check_foreign_shape([_ev()], context=ctx)
    assert "declared_originator_present" not in dict(f.evidence or {})
    ctx = _ctx_meta({"session_meta": {"originator": ""}})
    (f,) = check_foreign_shape([_ev()], context=ctx)
    assert dict(f.evidence or {})["declared_originator_present"] is True


@pytest.mark.parametrize("eid", [None, "", "  "])
def test_blank_id_no_record_id(eid: str | None) -> None:
    (f,) = check_foreign_shape([_ev(eid)])
    assert f.source.record_id is None


def test_id_stripped_and_invalid_line_none() -> None:
    (f,) = check_foreign_shape([_ev("  z  ", line=0)])
    assert f.source.record_id == "z"
    assert f.source.line is None
