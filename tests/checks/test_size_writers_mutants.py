"""Mutation-driven behaviour tests for SL011 and SL010 (CL-15)."""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from sesslint.canonical import SessionEvent
from sesslint.checks.size import SIZE_FLOOR_BYTES, check_size_anomaly
from sesslint.checks.writers import check_writers
from sesslint.codes import Repairability, Severity
from sesslint.context import CheckContext

# --------------------------------------------------------------- SL011


def _sctx(sizes: Any) -> CheckContext:
    return CheckContext(source_metadata={"record_sizes": sizes})


def _base(n: int = 8, size: int = 100) -> list[int]:
    return [size] * n


def test_size_constants() -> None:
    assert SIZE_FLOOR_BYTES == 262144


def test_size_finding_exact() -> None:
    sizes = _base() + [SIZE_FLOOR_BYTES + 1]
    (f,) = check_size_anomaly([], source_path="a/b.jsonl", context=_sctx(sizes))
    assert f.code == "SL011"
    assert f.severity is Severity.INFO
    assert f.repairability is Repairability.MANUAL
    assert f.message == "Record is a byte-size outlier within this file"
    assert f.source.path == "a/b.jsonl"
    assert f.source.line is None
    assert dict(f.evidence or {}) == {
        "file_median_bytes": 100,
        "ratio": round((SIZE_FLOOR_BYTES + 1) / 100, 3),
        "record_bytes": SIZE_FLOOR_BYTES + 1,
        "record_index": 8,
    }


def test_size_at_floor_is_silent_above_fires() -> None:
    at = _base() + [SIZE_FLOOR_BYTES]
    assert check_size_anomaly([], source_path="p", context=_sctx(at)) == []
    above = _base() + [SIZE_FLOOR_BYTES + 1]
    assert len(check_size_anomaly([], source_path="p", context=_sctx(above))) == 1


def test_size_ratio_threshold_boundary() -> None:
    # median 20000 -> 20*median = 400000 > floor; threshold is exclusive
    med = 20000
    base = _base(8, med)
    assert check_size_anomaly([], source_path="p", context=_sctx(base + [400000])) == []
    (f,) = check_size_anomaly([], source_path="p", context=_sctx(base + [400001]))
    assert dict(f.evidence or {})["file_median_bytes"] == med


def test_size_min_records_boundary() -> None:
    big = SIZE_FLOOR_BYTES * 10
    assert check_size_anomaly([], source_path="p", context=_sctx([1] * 6 + [big])) == []
    assert len(check_size_anomaly([], source_path="p", context=_sctx([1] * 7 + [big]))) == 1


def test_size_upper_median_used() -> None:
    # 10 sizes: upper median is index 5 of sorted
    sizes = [10, 10, 10, 10, 10, 30000, 30000, 30000, 30000, 600001]
    (f,) = check_size_anomaly([], source_path="p", context=_sctx(sizes))
    ev = dict(f.evidence or {})
    assert ev["file_median_bytes"] == 30000
    assert ev["record_index"] == 9


def test_size_first_of_equal_largest_index() -> None:
    sizes = _base(8) + [SIZE_FLOOR_BYTES + 5, SIZE_FLOOR_BYTES + 5]
    (f,) = check_size_anomaly([], source_path="p", context=_sctx(sizes))
    assert dict(f.evidence or {})["record_index"] == 8


def test_size_zero_median_ratio_none() -> None:
    sizes = [0] * 8 + [SIZE_FLOOR_BYTES + 1]
    (f,) = check_size_anomaly([], source_path="p", context=_sctx(sizes))
    ev = dict(f.evidence or {})
    assert ev["ratio"] is None
    assert ev["file_median_bytes"] == 0


def test_size_invalid_entries_filtered() -> None:
    big = SIZE_FLOOR_BYTES + 1
    # bool, negative, float, str entries are dropped; 7 valid remain -> too few
    noisy = [1] * 7 + [True, -1, 2.5, "9", big]
    assert big > 0
    # valid = 7 ones + big = 8 -> fires; invalid ones must not shift index
    (f,) = check_size_anomaly([], source_path="p", context=_sctx(noisy))
    assert dict(f.evidence or {})["record_index"] == 7
    # drop one valid -> 7 valid only -> silent
    assert check_size_anomaly([], source_path="p", context=_sctx([1] * 6 + [True, -1, big])) == []


def test_size_zero_is_valid_entry() -> None:
    sizes = [0] * 7 + [SIZE_FLOOR_BYTES + 1]
    assert len(check_size_anomaly([], source_path="p", context=_sctx(sizes))) == 1


@pytest.mark.parametrize("raw", [None, "abc", (1,) * 20, {"a": 1}, 5])
def test_size_non_list_sizes_silent(raw: Any) -> None:
    assert check_size_anomaly([], source_path="p", context=_sctx(raw)) == []


def test_size_no_context_or_metadata_silent() -> None:
    assert check_size_anomaly([], source_path="p") == []
    assert check_size_anomaly([], source_path="p", context=CheckContext()) == []


# --------------------------------------------------------------- SL010


def _wev(
    eid: str | None,
    line: Any,
    writer: Any = None,
    *,
    extra: Any = "auto",
    loc: str = "w.jsonl",
) -> SessionEvent:
    if extra == "auto":
        extra = {"writer": writer} if writer is not None else {}
    return SessionEvent(
        id=eid,  # type: ignore[arg-type]
        parent_id=None,
        seq=0,
        ts="",
        actor="assistant",
        kind="message",
        source_line=line,
        source_adapter="x",
        source_location=loc,
        extra_fields=extra,
    )


def _v(version: str) -> dict[str, str]:
    return {"version": version}


def _h(marker: str) -> str:
    return hashlib.sha256(marker.encode()).hexdigest()[:8]


def _aba() -> list[SessionEvent]:
    return [
        _wev("e1", 1, _v("A")),
        _wev("e2", 2, _v("B")),
        _wev("e3", 3, _v("A")),
    ]


def test_writers_finding_exact() -> None:
    ctx = CheckContext(adapter_id="ad", adapter_version="1", profile_id="pr", profile_version="2")
    (f,) = check_writers(_aba(), context=ctx)
    assert f.code == "SL010"
    assert f.severity is Severity.WARNING
    assert f.repairability is Repairability.MANUAL
    assert f.message == "Interleaved writer markers in session file for record e3"
    assert f.source.path == "w.jsonl"
    assert f.source.line == 3
    assert f.source.record_id == "e3"
    ev = dict(f.evidence or {})
    assert ev["distinct_writer_count"] == 2
    assert ev["transition_count"] == 2
    assert ev["first_interleave_line"] == 3
    assert tuple(ev["writer_hashes"]) == tuple(sorted([_h("v:A"), _h("v:B")]))


def test_writers_source_path_argument() -> None:
    (f,) = check_writers(_aba(), source_path="given.jsonl")
    assert f.source.path == "given.jsonl"


def test_writers_instance_preferred_over_version() -> None:
    evs = [
        _wev("e1", 1, {"instance": "i1", "version": "same"}),
        _wev("e2", 2, {"instance": "i2", "version": "same"}),
        _wev("e3", 3, {"instance": "i1", "version": "same"}),
    ]
    (f,) = check_writers(evs)
    assert tuple(dict(f.evidence or {})["writer_hashes"]) == tuple(sorted([_h("i:i1"), _h("i:i2")]))


def test_writers_markers_are_stripped() -> None:
    evs = [
        _wev("e1", 1, {"instance": " i1 "}),
        _wev("e2", 2, {"instance": "i2"}),
        _wev("e3", 3, {"instance": "i1"}),
    ]
    assert len(check_writers(evs)) == 1


def test_writers_blank_instance_falls_back_to_version() -> None:
    evs = [
        _wev("e1", 1, {"instance": "  ", "version": "A"}),
        _wev("e2", 2, {"instance": "", "version": "B"}),
        _wev("e3", 3, {"instance": 5, "version": "A"}),
    ]
    (f,) = check_writers(evs)
    assert tuple(dict(f.evidence or {})["writer_hashes"]) == tuple(sorted([_h("v:A"), _h("v:B")]))


@pytest.mark.parametrize(
    "writer",
    [
        None,
        "str",
        [1],
        {},
        {"version": ""},
        {"version": "  "},
        {"version": 3},
        {"instance": None, "version": None},
    ],
)
def test_writers_invalid_markers_ignored(writer: Any) -> None:
    evs = [
        _wev("e1", 1, _v("A")),
        _wev("e2", 2, _v("B")),
        _wev("x", 3, extra={"writer": writer}),
        _wev("e3", 4, _v("B")),
    ]
    assert check_writers(evs) == []


@pytest.mark.parametrize("extra", [None, "s", [], 5])
def test_writers_non_mapping_extra_ignored(extra: Any) -> None:
    evs = [_wev("e1", 1, _v("A")), _wev("e2", 2, _v("B")), _wev("e3", 3, extra=extra)]
    assert check_writers(evs) == []


def test_writers_clean_upgrade_silent() -> None:
    evs = [_wev(f"e{i}", i, _v("A" if i < 3 else "B")) for i in range(1, 6)]
    assert check_writers(evs) == []


def test_writers_fewer_than_three_markers_silent() -> None:
    assert check_writers(_aba()[:2]) == []


def test_writers_same_line_same_marker_counted_once() -> None:
    # A@1, A@1 (dup), B@2 -> 2 distinct entries only -> silent (needs >=3)
    evs = [_wev("e1", 1, _v("A")), _wev("e1b", 1, _v("A")), _wev("e2", 2, _v("B"))]
    assert check_writers(evs) == []


def test_writers_same_line_different_marker_counted() -> None:
    evs = [_wev("e1", 1, _v("A")), _wev("e1b", 1, _v("B")), _wev("e2", 2, _v("A"))]
    assert len(check_writers(evs)) == 1


def test_writers_none_lines_dedupe_per_marker() -> None:
    evs = [_wev("e1", None, _v("A")), _wev("e2", None, _v("A")), _wev("e3", 3, _v("B"))]
    assert check_writers(evs) == []


def test_writers_non_int_line_treated_as_none() -> None:
    evs = [_wev("e1", "1", _v("A")), _wev("e2", "2", _v("A")), _wev("e3", 3, _v("B"))]
    assert check_writers(evs) == []


def test_writers_consecutive_duplicates_collapse() -> None:
    evs = [
        _wev("e1", 1, _v("A")),
        _wev("e2", 2, _v("A")),
        _wev("e3", 3, _v("B")),
        _wev("e4", 4, _v("B")),
        _wev("e5", 5, _v("A")),
    ]
    (f,) = check_writers(evs)
    ev = dict(f.evidence or {})
    assert ev["transition_count"] == 2
    assert f.source.record_id == "e5"
    assert f.source.line == 5


def test_writers_first_reappearance_reported() -> None:
    evs = [
        _wev("e1", 1, _v("A")),
        _wev("e2", 2, _v("B")),
        _wev("e3", 3, _v("C")),
        _wev("e4", 4, _v("B")),
        _wev("e5", 5, _v("A")),
    ]
    (f,) = check_writers(evs)
    assert f.source.record_id == "e4"
    assert dict(f.evidence or {})["distinct_writer_count"] == 3


@pytest.mark.parametrize("eid", [None, "", "  "])
def test_writers_blank_id_no_record_id(eid: str | None) -> None:
    evs = [_wev("e1", 1, _v("A")), _wev("e2", 2, _v("B")), _wev(eid, 3, _v("A"))]
    (f,) = check_writers(evs)
    assert f.source.record_id is None


def test_writers_id_is_stripped() -> None:
    evs = [_wev("e1", 1, _v("A")), _wev("e2", 2, _v("B")), _wev("  e3  ", 3, _v("A"))]
    (f,) = check_writers(evs)
    assert f.source.record_id == "e3"
