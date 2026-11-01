"""Mutation-driven tests for accounting, identity, ordering, tool_pairing_1 and
runner context handling (CL-15)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from sesslint.canonical import SessionEvent
from sesslint.checks import accounting as acc
from sesslint.checks import identity as ident
from sesslint.checks import ordering as order
from sesslint.checks import tool_pairing_1 as tp1
from sesslint.checks.runner import run_all_checks
from sesslint.context import CheckContext


def _se(
    eid: Any,
    *,
    kind: str = "message",
    parent: Any = None,
    seq: int = 0,
    ts: str = "2026-01-01T00:00:00Z",
    line: Any = None,
    extra: Any = None,
    corr: Any = None,
    loc: str = "t.jsonl",
) -> SessionEvent:
    return SessionEvent(
        id=eid,
        parent_id=parent,
        seq=seq,
        ts=ts,
        actor="assistant",
        kind=kind,
        source_line=line,
        source_adapter="x",
        source_location=loc,
        extra_fields=extra if extra is not None else {},
        correlation_id=corr,
    )


# ---------------------------------------------------------------- accounting


def test_clean_counters_keep_zero_and_one_drop_negative_bool_nonstr() -> None:
    raw = {"zero": 0, "one": 1, "neg": -1, "b": True, "f": 1.5, 7: 3, "s": "9"}
    assert acc._clean_counters(raw) == {"zero": 0, "one": 1}
    assert acc._clean_counters(None) == {}
    assert acc._clean_counters([1]) == {}


def _usage(contribution: Any = None, cumulative: Any = None) -> dict[str, Any]:
    u: dict[str, Any] = {}
    if contribution is not None:
        u["contribution"] = contribution
    if cumulative is not None:
        u["cumulative"] = cumulative
    return {"usage": u}


def test_accounting_cumulative_key_missing_from_window() -> None:
    evs = [
        _se("a", extra=_usage(contribution={"in": 5}, cumulative={"in": 5}), line=1),
        _se("b", extra=_usage(contribution={"in": 2}, cumulative={"in": 7, "out": 4}), line=2),
    ]
    (f,) = acc.check_accounting(evs)
    ev = dict(f.evidence or {})
    assert ev["mismatched_key_count"] == 1
    assert ev["expected_total"] == 7
    assert ev["observed_total"] == 11
    assert ev["window_start_index"] == 1
    assert ev["window_end_index"] == 1
    assert ev["record_ordinal"] == 1
    assert f.source.line == 2


def test_accounting_zero_valued_counters_are_checked() -> None:
    evs = [_se("a", extra=_usage(contribution={"in": 0}, cumulative={"in": 0}))]
    assert acc.check_accounting(evs) == []
    evs = [_se("a", extra=_usage(contribution={"in": 0}, cumulative={"in": 1}))]
    assert len(acc.check_accounting(evs)) == 1


# ------------------------------------------------------------------ identity


def test_diff_field_names_on_objects_and_mappings() -> None:
    a = _se("x", seq=1, ts="2026-01-01T00:00:00Z")
    b = _se("x", seq=2, ts="2026-01-01T00:00:01Z")
    assert ident.diff_field_names([a, b]) == ["seq", "ts"]
    assert ident.diff_field_names([a]) == []
    assert ident.diff_field_names([]) == []
    plain = SimpleNamespace(to_canonical_dict=lambda: {"id": "x", "k": 1})
    other = SimpleNamespace(to_canonical_dict=lambda: {"id": "x", "k": 2, "extra": 1})
    assert ident.diff_field_names([plain, other]) == ["extra", "k"]
    # present-with-None differs from absent
    n1 = SimpleNamespace(to_canonical_dict=lambda: {"id": "x", "k": None})
    n2 = SimpleNamespace(to_canonical_dict=lambda: {"id": "x"})
    assert ident.diff_field_names([n1, n2]) == ["k"]
    assert ident.diff_field_names([n2, n1]) == ["k"]
    # differing only in a key that is absent on the first event
    m1 = SimpleNamespace(to_canonical_dict=lambda: {"id": "x"})
    m2 = SimpleNamespace(to_canonical_dict=lambda: {"id": "x", "k": None})
    assert ident.diff_field_names([m1, m2]) == ["k"]
    # non-callable to_canonical_dict falls back to the module serializer
    weird = SimpleNamespace(to_canonical_dict=5, id="x")
    with pytest.raises(Exception):  # noqa: B017, PT011
        ident.diff_field_names([weird, weird])


def test_identity_fingerprint_joins_hashes_with_comma() -> None:
    import hashlib

    got = ident.compute_identity_fingerprint("id1", ["b", "a"])
    assert got == hashlib.sha256(b"SL003|id1|a,b").hexdigest()[:16]


def test_identity_cap_sort_key_uses_evidence_id() -> None:
    evs = [_se("dup", line=1), _se("dup", line=2)]
    (f,) = ident.check_identities(evs)
    key = ident._cap_finding_sort_key(f)
    assert key[0] == "SL003"
    assert key[1] == f.source.record_id == "dup"
    # No record id on the source: falls back to the evidence id
    from sesslint.finding import SourceRef, make_finding

    bare = make_finding(
        code="SL003",
        message_template="Duplicate id for record {record_id}",
        template_args={"record_id": "zz"},
        source=SourceRef(path="p"),
        evidence={"id": "from-evidence"},
    )
    assert ident._cap_finding_sort_key(bare)[1] == "from-evidence"


def test_identity_loop_skips_blank_ids_but_keeps_scanning() -> None:
    evs = [
        SimpleNamespace(id=None),
        SimpleNamespace(id="  "),
        _se("dup", line=1),
        _se("dup", line=2),
    ]
    (f,) = ident.check_identities(evs)
    assert f.source.record_id == "dup"


def test_identity_loop_skips_blank_coerced_ids_but_keeps_scanning() -> None:
    class Blank:
        def __str__(self) -> str:
            return "   "

    evs = [SimpleNamespace(id=Blank()), _se("dup", line=1), _se("dup", line=2)]
    (f,) = ident.check_identities(evs)
    assert f.source.record_id == "dup"


@pytest.mark.parametrize(
    ("line", "expected"), [(1, 1), (2, 2), (0, None), (-4, None), (True, None)]
)
def test_identity_source_line_bounds(line: Any, expected: int | None) -> None:
    evs = [
        {"id": "d", "source_line": line, "source_location": "f", "k": 1},
        {"id": "d", "source_line": line, "source_location": "f", "k": 1},
    ]
    (f,) = ident.check_identities(evs)
    assert f.source.line == expected


def test_identity_unsafe_id_reports_redacted_evidence_id() -> None:
    evs = [_se("a@b.com", line=1), _se("a@b.com", line=2)]
    (f,) = ident.check_identities(evs)
    assert dict(f.evidence or {})["id"] == "<redacted>"
    assert f.source.record_id is None


# ------------------------------------------------------------------ ordering


@pytest.mark.parametrize(
    ("raw", "expected_none"),
    [
        (None, True),
        (5, True),
        ("", True),
        ("   ", True),
        ("1970-01-01T00:00:00Z", True),
        ("not a date", True),
        ("2026-01-01T00:00:00Z", False),
        ("2026-01-01T00:00:00+00:00", False),
        ("2026-01-01T00:00:00", False),
    ],
)
def test_parse_ts(raw: Any, expected_none: bool) -> None:
    assert (order._parse_ts(raw) is None) is expected_none


def test_parse_ts_zulu_is_utc_aware() -> None:
    parsed = order._parse_ts("2026-01-01T00:00:00Z")
    assert parsed is not None
    assert parsed.utcoffset() is not None
    assert parsed.utcoffset().total_seconds() == 0  # type: ignore[union-attr]


def test_ordering_flags_child_before_parent_and_pins_metadata() -> None:
    evs = [
        _se("p", ts="2026-01-01T00:00:10Z", line=1),
        _se("c", parent="p", ts="2026-01-01T00:00:00Z", line=2),
    ]
    ctx = CheckContext(adapter_id="ad", adapter_version="1", profile_id="pr", profile_version="2")
    other = CheckContext(adapter_id="ad", adapter_version="9", profile_id="pr", profile_version="2")
    (f,) = order.check_ordering(evs, context=ctx)
    (g,) = order.check_ordering(evs, context=other)
    assert f.fingerprint != g.fingerprint
    assert f.source.line == 2


# -------------------------------------------------------------- tool_pairing_1


def test_tp1_resolve_source_coords_reads_attributes_case_sensitively() -> None:
    ev = SimpleNamespace(source_location="a\\b.jsonl", source_line=4)
    assert tp1._resolve_source_coords(ev, "<canonical>") == ("a/b.jsonl", 4)
    assert tp1._resolve_source_coords(
        {"source_location": "q", "source_line": 2}, "<canonical>"
    ) == (
        "q",
        2,
    )
    assert tp1._resolve_source_coords(ev, "<CANONICAL>") == ("<CANONICAL>", 4)


def test_tp1_safe_id_redaction_literal() -> None:
    assert tp1._safe_id("a@b.com") == "<redacted>"
    assert tp1._safe_id("fine") == "fine"


def test_tp1_dangling_default_source_path_and_mapping_events() -> None:
    events = [{"kind": "tool_use", "id": "u1", "correlation_id": None}]
    (f,) = tp1.check_dangling(events)
    assert f.source.path == "<canonical>"
    assert f.source.record_id == "u1"
    assert dict(f.evidence or {})["event_id"] == "u1"
    assert dict(f.evidence or {})["correlation_id"] is None


def test_tp1_dangling_mapping_event_without_id_gets_placeholder() -> None:
    events = [{"kind": "tool_use", "correlation_id": None}]
    (f,) = tp1.check_dangling(events)
    assert dict(f.evidence or {})["event_id"] == "<call:0>"


# --------------------------------------------------------------------- runner


class _Events(list):  # type: ignore[type-arg]
    source = {"marker": 1}


def test_runner_attaches_events_source_to_supplied_context() -> None:
    evs = _Events([_se("a", line=1)])
    out = run_all_checks(evs, context=CheckContext(adapter_id="ad", adapter_version="1"))
    assert out == []


def _size_events(n: int) -> _Events:
    out = _Events([_se(f"e{i}", seq=i, line=i + 1) for i in range(n)])
    return out


class _SizedEvents(list):  # type: ignore[type-arg]
    source = {"record_sizes": [100] * 8 + [10_000_000]}


def test_runner_size_skip_names_both_checks_below_minimum() -> None:
    _, cov = run_all_checks(
        _size_events(3),
        context=CheckContext(adapter_id="claude-code-jsonl", adapter_version="1"),
        return_coverage=True,
    )
    skipped = {(s.check, s.reason, s.detail) for s in cov.skipped}
    detail = "fewer than 8 records — size distribution not meaningful"
    assert ("size", "adapter-not-applicable", detail) in skipped
    assert ("SL011", "adapter-not-applicable", detail) in skipped
    assert "size" not in cov.performed
    assert "SL011" not in cov.performed


@pytest.mark.parametrize("with_context", [False, True])
def test_runner_feeds_events_source_into_size_check(with_context: bool) -> None:
    evs = _SizedEvents(_se(f"e{i}", seq=i, line=i + 1) for i in range(9))
    kwargs: dict[str, Any] = {}
    if with_context:
        kwargs["context"] = CheckContext(adapter_id="claude-code-jsonl", adapter_version="1")
    else:
        kwargs["adapter"] = "claude-code-jsonl"
    out = run_all_checks(evs, **kwargs)
    assert [f.code for f in out if f.code == "SL011"] == ["SL011"]


def test_identity_object_events_use_attribute_ids_and_lines() -> None:
    def obj(line: int) -> Any:
        return SimpleNamespace(
            id="dup",
            source_line=line,
            source_location="f.jsonl",
            to_canonical_dict=lambda: {"id": "dup"},
        )

    (f,) = ident.check_identities([obj(5), obj(9)])
    assert f.source.record_id == "dup"
    assert f.source.line == 5
    assert f.source.path == "<canonical>" or f.source.path == "f.jsonl"


def test_diff_field_names_on_plain_mapping_events() -> None:
    assert ident.diff_field_names([{"id": "a", "k": 1}, {"id": "a", "k": 2}]) == ["k"]


def test_tp1_cap_sort_key_overflow_flag_and_coords() -> None:
    from sesslint.codes import SL101, Repairability, Severity
    from sesslint.finding import SourceRef, make_finding

    def mk(evidence: Any, rec: str | None) -> Any:
        return make_finding(
            code=SL101,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message_template="Orphan tool result for record {record_id}",
            source=SourceRef(path="p", record_id=rec),
            evidence=evidence,
        )

    assert tp1._cap_finding_sort_key(mk({"overflow": True}, "r"))[1] == 1
    assert tp1._cap_finding_sort_key(mk({"k": 1}, "r"))[1] == 0
    assert tp1._cap_finding_sort_key(mk(None, "r"))[1] == 0
    for bad in (None, 0, -1, True, "3"):
        assert tp1._resolve_source_coords(SimpleNamespace(source_line=bad), "p")[1] is None


def test_checkpoint_run_state_projection_fallback_shapes() -> None:
    from sesslint.checks import checkpoint as cp

    chks = [{"id": "a", "seq": 0, "hash": "h"}]
    ex = cp._extract_run_state_checkpoints
    assert [c["id"] for c in ex(run_state_projection={"checkpoints": chks})] == ["a"]
    assert ex(run_state_projection={"checkpoints": "abc"}) == []
    assert ex(run_state_projection={"checkpoints": b"abc"}) == []
    assert ex(run_state_projection={"CHECKPOINTS": chks}) == []
    for sm in (
        {"run_state": {"checkpoints": chks}},
        {"metadata": {"checkpoints": chks}},
        {"metadata": {"run_state": {"checkpoints": chks}}},
        {"run_state_projection": {"checkpoints": chks}},
    ):
        ctx = SimpleNamespace(source_metadata=sm)
        assert [c["id"] for c in ex(context=ctx)] == ["a"], sm  # type: ignore[arg-type]
    for sm in (
        {"run_state": {"checkpoints": "abc"}},
        {"metadata": {"checkpoints": "abc"}},
        {"metadata": {"run_state": {"checkpoints": "abc"}}},
        {"run_state_projection": {"checkpoints": "abc"}},
        {"checkpoints": "abc"},
    ):
        ctx = SimpleNamespace(source_metadata=sm)
        assert ex(context=ctx) == [], sm  # type: ignore[arg-type]
