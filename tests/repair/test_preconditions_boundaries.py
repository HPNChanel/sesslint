"""Behaviour pins for repair precondition predicates (CL-08 mutation triage).

Each case asserts an exact boolean outcome at a decision boundary of
``sesslint.repair.preconditions`` (SL203 / SL005 cut selection, tool
side-effect proof, repairability class, source-hash pin).
"""

from __future__ import annotations

from typing import Any

import pytest

from sesslint.finding import Finding, Repairability, Severity, SourceRef, make_finding
from sesslint.repair.preconditions import (
    PreconditionContext,
    no_prior_safe_tool_after_cut,
    repairability_is_safe_auto,
    repairability_is_salvage,
    side_effects_known,
    source_hash_pinned,
)

_HASH = "a" * 64


def _finding(
    code: str = "SL203",
    *,
    severity: Severity = Severity.ERROR,
    repairability: Repairability | str = Repairability.DETERMINISTIC,
    evidence: dict[str, Any] | None = None,
) -> Finding:
    return make_finding(
        code=code,
        severity=severity,
        repairability=repairability,
        message_template="Finding for record {record_id}",
        source=SourceRef(path="session.json", line=1, record_id="rec-0"),
        evidence=evidence,
        fingerprint="0123456789abcdef",
    )


def _events(n: int, **overrides: str) -> list[dict[str, Any]]:
    return [{"kind": overrides.get(str(i), "message"), "id": f"e{i}"} for i in range(n)]


def _ctx(
    findings: list[Finding],
    events: list[Any],
    *,
    finding: Finding | None = None,
    source_hash: str = _HASH,
) -> PreconditionContext:
    return PreconditionContext(
        findings=findings,
        events=events,
        profile="generic",
        source_hash=source_hash,
        finding=finding,
    )


# --- no_prior_safe_tool_after_cut ------------------------------------------


def test_cut_requires_sl203_or_fatal_sl005_trigger() -> None:
    ev = {"first_unsafe_index": 2}
    events = _events(5)
    assert no_prior_safe_tool_after_cut(_ctx([_finding("SL203", evidence=ev)], events)) is True
    fatal = _finding("SL005", severity=Severity.FATAL, evidence=ev)
    assert no_prior_safe_tool_after_cut(_ctx([fatal], events)) is True
    non_fatal = _finding("SL005", severity=Severity.ERROR, evidence=ev)
    assert no_prior_safe_tool_after_cut(_ctx([non_fatal], events)) is False
    other = _finding("SL001", evidence=ev)
    assert no_prior_safe_tool_after_cut(_ctx([other], events)) is False
    assert no_prior_safe_tool_after_cut(_ctx([], events)) is False


@pytest.mark.parametrize("key", ["first_unsafe_index", "at_index", "index", "entry_index"])
def test_cut_read_from_each_target_evidence_key(key: str) -> None:
    target = _finding(evidence={key: 3})
    events = _events(5, **{"3": "checkpoint"})
    # cut == 3 -> checkpoint at index 3 sits in the discarded suffix.
    assert no_prior_safe_tool_after_cut(_ctx([target], events, finding=target)) is False
    events = _events(5, **{"2": "checkpoint"})
    # cut == 3 -> checkpoint at index 2 is kept, suffix is clean.
    assert no_prior_safe_tool_after_cut(_ctx([target], events, finding=target)) is True


def test_cut_key_priority_on_target_finding() -> None:
    events = _events(6, **{"1": "checkpoint"})
    # first_unsafe_index (4) wins over at_index (1): the checkpoint stays outside the cut.
    target = _finding(
        evidence={"first_unsafe_index": 4, "at_index": 1, "index": 1, "entry_index": 1}
    )
    assert no_prior_safe_tool_after_cut(_ctx([target], events, finding=target)) is True
    # at_index wins over index / entry_index.
    target = _finding(evidence={"at_index": 4, "index": 1, "entry_index": 1})
    assert no_prior_safe_tool_after_cut(_ctx([target], events, finding=target)) is True
    # index wins over entry_index.
    target = _finding(evidence={"index": 4, "entry_index": 1})
    assert no_prior_safe_tool_after_cut(_ctx([target], events, finding=target)) is True
    target = _finding(evidence={"entry_index": 4})
    assert no_prior_safe_tool_after_cut(_ctx([target], events, finding=target)) is True


def test_cut_bounds_and_types() -> None:
    events = _events(4)

    def run(value: object) -> bool:
        f = _finding(evidence={"first_unsafe_index": value})
        return no_prior_safe_tool_after_cut(_ctx([f], events, finding=f))

    assert run(0) is False  # cut <= 0
    assert run(-1) is False
    assert run(1) is True  # smallest valid cut
    assert run(3) is True  # last valid cut
    assert run(4) is False  # cut == len(events)
    assert run(9) is False
    assert run(True) is False  # bool is not an index
    assert run("2") is False


def test_cut_derived_from_findings_when_target_has_no_index() -> None:
    events = _events(8, **{"2": "checkpoint"})
    a = _finding(evidence={"first_unsafe_index": 5})
    b = _finding(evidence={"at_index": 3})
    # minimum candidate (3) is chosen; checkpoint at 2 is outside the suffix.
    assert no_prior_safe_tool_after_cut(_ctx([a, b], events)) is True
    # minimum candidate (2) puts the checkpoint inside the suffix.
    c = _finding(evidence={"index": 2})
    assert no_prior_safe_tool_after_cut(_ctx([a, b, c], events)) is False


def test_cut_candidate_key_priority_and_code_filter() -> None:
    events = _events(8, **{"3": "checkpoint"})
    # first_unsafe_index (5) wins over later keys in the same finding.
    f = _finding(evidence={"first_unsafe_index": 5, "at_index": 1, "index": 1, "entry_index": 1})
    assert no_prior_safe_tool_after_cut(_ctx([f], events)) is True
    f = _finding(evidence={"at_index": 5, "index": 1, "entry_index": 1})
    assert no_prior_safe_tool_after_cut(_ctx([f], events)) is True
    f = _finding(evidence={"index": 5, "entry_index": 1})
    assert no_prior_safe_tool_after_cut(_ctx([f], events)) is True
    f = _finding(evidence={"entry_index": 5})
    assert no_prior_safe_tool_after_cut(_ctx([f], events)) is True
    # non-SL203/SL005 findings never contribute a cut candidate.
    trigger = _finding("SL203", evidence={"first_unsafe_index": 5})
    other = _finding("SL001", evidence={"first_unsafe_index": 1})
    assert no_prior_safe_tool_after_cut(_ctx([trigger, other], events)) is True
    fatal = _finding("SL005", severity=Severity.FATAL, evidence={"index": 2})
    assert no_prior_safe_tool_after_cut(_ctx([trigger, fatal], events)) is False
    # bool candidates are ignored.
    boolean = _finding(evidence={"first_unsafe_index": True})
    assert no_prior_safe_tool_after_cut(_ctx([boolean], events)) is False


def test_cut_without_any_index_is_refused() -> None:
    assert no_prior_safe_tool_after_cut(_ctx([_finding()], _events(4))) is False
    assert (
        no_prior_safe_tool_after_cut(_ctx([_finding(evidence={"other": 2})], _events(4))) is False
    )


def test_cut_refused_on_unknown_side_effects() -> None:
    f = _finding(evidence={"first_unsafe_index": 2})
    events: list[Any] = _events(5)
    events[0] = {"kind": "tool_call", "id": "t0", "side_effects": "write"}
    assert no_prior_safe_tool_after_cut(_ctx([f], events, finding=f)) is False
    events[0] = {"kind": "tool_call", "id": "t0", "side_effects": "none"}
    assert no_prior_safe_tool_after_cut(_ctx([f], events, finding=f)) is True


# --- side_effects_known -----------------------------------------------------


@pytest.mark.parametrize("kind", ["tool_call", "tool_use", "tool_result"])
def test_side_effects_each_tool_kind_checked(kind: str) -> None:
    assert side_effects_known(_ctx([], [{"kind": kind, "side_effects": "none"}])) is True
    assert side_effects_known(_ctx([], [{"kind": kind, "side_effects": "write"}])) is False
    assert side_effects_known(_ctx([], [{"kind": kind}])) is False


def test_side_effects_non_tool_kinds_ignored() -> None:
    assert side_effects_known(_ctx([], [{"kind": "message", "side_effects": "write"}])) is True
    assert side_effects_known(_ctx([], [])) is True


def test_side_effects_read_from_payload_and_attributes() -> None:
    assert (
        side_effects_known(_ctx([], [{"kind": "tool_call", "payload": {"side_effects": "none"}}]))
        is True
    )
    assert (
        side_effects_known(_ctx([], [{"kind": "tool_call", "payload": {"side_effects": "net"}}]))
        is False
    )
    assert side_effects_known(_ctx([], [{"kind": "tool_call", "payload": "none"}])) is False
    # top-level field wins over payload.
    mixed = {"kind": "tool_call", "side_effects": "none", "payload": {"side_effects": "net"}}
    assert side_effects_known(_ctx([], [mixed])) is True

    class Obj:
        kind = "tool_result"
        side_effects = "none"

    class ObjPayload:
        kind = "tool_use"
        side_effects = None
        payload = {"side_effects": "none"}

    class ObjBad:
        kind = "tool_use"
        side_effects = "fs"

    assert side_effects_known(_ctx([], [Obj()])) is True
    assert side_effects_known(_ctx([], [ObjPayload()])) is True
    assert side_effects_known(_ctx([], [ObjBad()])) is False


def test_side_effects_one_unsafe_event_among_safe_ones() -> None:
    events = [
        {"kind": "tool_call", "side_effects": "none"},
        {"kind": "tool_result", "side_effects": "none"},
        {"kind": "tool_call", "side_effects": "write"},
    ]
    assert side_effects_known(_ctx([], events)) is False


# --- repairability predicates ----------------------------------------------


@pytest.mark.parametrize(
    ("rep", "safe", "salvage"),
    [
        (Repairability.DETERMINISTIC, True, False),
        (Repairability.LOSSY_EXPLICIT, False, True),
        ("safe-auto", True, False),
        ("deterministic", True, False),
        ("salvage", False, True),
        ("lossy-explicit", False, True),
        ("manual", False, False),
        ("", False, False),
        ("SAFE-AUTO", False, False),
        ("SALVAGE", False, False),
        ("xsalvagex", False, False),
        ("xsafe-autox", False, False),
    ],
)
def test_repairability_classes(rep: Repairability | str, safe: bool, salvage: bool) -> None:
    class F:
        repairability = rep

    ctx = PreconditionContext(findings=[], events=[], profile="g", source_hash=_HASH, finding=F())  # type: ignore[arg-type]
    assert repairability_is_safe_auto(ctx) is safe
    assert repairability_is_salvage(ctx) is salvage


def test_repairability_requires_target_finding() -> None:
    ctx = _ctx([], [], finding=None)
    assert repairability_is_safe_auto(ctx) is False
    assert repairability_is_salvage(ctx) is False


# --- source_hash_pinned -----------------------------------------------------


def test_source_hash_pinned_length_boundary() -> None:
    assert source_hash_pinned(_ctx([], [], source_hash="a" * 64)) is True
    assert source_hash_pinned(_ctx([], [], source_hash="a" * 63)) is False
    assert source_hash_pinned(_ctx([], [], source_hash="a" * 65)) is False
    assert source_hash_pinned(_ctx([], [], source_hash="")) is False


def test_cut_taken_from_target_finding_not_from_session_findings() -> None:
    trigger = _finding("SL203")  # no index of its own
    events = _events(5, **{"3": "checkpoint"})
    for key in ("first_unsafe_index", "at_index", "index", "entry_index"):
        target = _finding("SL001", evidence={key: 3})
        assert no_prior_safe_tool_after_cut(_ctx([trigger], events, finding=target)) is False
        target = _finding("SL001", evidence={key: 4})
        assert no_prior_safe_tool_after_cut(_ctx([trigger], events, finding=target)) is True


def test_fatal_sl005_trigger_accepts_plain_string_severity() -> None:
    class F:
        code = "SL005"
        severity = "fatal"
        evidence = {"first_unsafe_index": 2}

    assert no_prior_safe_tool_after_cut(_ctx([F()], _events(5))) is True  # type: ignore[list-item]
