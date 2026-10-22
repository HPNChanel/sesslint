"""OutcomeGuard snapshot readers: bounded, metadata never inferred (EVD-02/03/07)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.outcome import SnapshotError, load_snapshot, parse_instant
from sesslint.outcome.snapshot import NON_SCALAR
from tests.outcome.helpers import ORDERS, at
from tests.utils.schema import assert_schema


def _write(tmp_path: Path, name: str, data: str | bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
    return path


def test_fixture_envelope_matches_schema_and_loads() -> None:
    raw = json.loads((ORDERS / "target_complete.json").read_text(encoding="utf-8"))
    assert_schema(raw, "sesslint.snapshot.v1.json")
    snap = load_snapshot(ORDERS / "target_complete.json", role="target")
    assert (snap.input_format, snap.completeness, snap.origin) == (
        "envelope",
        "complete",
        "target_system",
    )
    assert snap.observed_at == at("2026-10-20T12:00:00Z")


def test_plain_files_default_to_unknown_completeness() -> None:
    for name, fmt in (("source.csv", "csv"), ("target.jsonl", "jsonl")):
        snap = load_snapshot(ORDERS / name, role="source")
        assert (snap.input_format, snap.completeness, snap.origin) == (fmt, "unknown", "user_file")
        assert snap.observed_at is None


def test_csv_keeps_text_exact_and_leading_zeros() -> None:
    snap = load_snapshot(ORDERS / "source.csv", role="source")
    assert snap.records[0]["order_id"] == "0001"
    assert all(isinstance(v, str) for v in snap.records[0].values())


def test_csv_short_row_leaves_fields_absent(tmp_path: Path) -> None:
    snap = load_snapshot(_write(tmp_path, "s.csv", "id,a,b\n1,x\n2,,\n"), role="source")
    assert "b" not in snap.records[0]
    assert snap.records[1]["b"] == ""


@pytest.mark.parametrize(
    ("text", "needle"),
    [
        ("", "no header"),
        ("id,id\n1,2\n", "duplicate"),
        ("id,\n1,2\n", "empty"),
        ("id\n1,2\n", "more cells"),
        ('id\n"1\n', "malformed"),
    ],
)
def test_csv_rejects_ambiguous_shapes(tmp_path: Path, text: str, needle: str) -> None:
    with pytest.raises(SnapshotError, match=needle):
        load_snapshot(_write(tmp_path, "s.csv", text), role="source")


def test_json_nested_values_are_marked_not_compared(tmp_path: Path) -> None:
    snap = load_snapshot(_write(tmp_path, "t.json", '[{"ref": "1", "x": {"y": 1}}]'), role="target")
    assert snap.records[0]["x"] is NON_SCALAR
    assert snap.input_format == "json"


@pytest.mark.parametrize(
    ("name", "text", "needle"),
    [
        ("t.json", '{"records": []}', "schema_version"),
        ("t.json", '{"schema_version": "sesslint.snapshot/v1", "extra": 1}', "unknown key"),
        ("t.json", '{"schema_version": "sesslint.snapshot/v1", "demo": "yes"}', "demo"),
        ("t.json", "[1]", "not a JSON object"),
        ("t.json", '[{"a": 1, "a": 2}]', "strict JSON"),
        ("t.jsonl", '{"a": 1}\n{"a": NaN}\n', "line 2"),
        ("t.txt", "a", "must end in"),
        (
            "t.json",
            '{"schema_version": "sesslint.snapshot/v1", "observed_at": "2026-10-20T12:00:00"}',
            "offset",
        ),
        (
            "t.json",
            '{"schema_version": "sesslint.snapshot/v1", "completeness": "mostly"}',
            "one of",
        ),
        (
            "t.json",
            '{"schema_version": "sesslint.snapshot/v1", "completeness": "unavailable",'
            ' "records": [{"a": 1}]}',
            "cannot carry records",
        ),
    ],
)
def test_snapshot_rejections(tmp_path: Path, name: str, text: str, needle: str) -> None:
    with pytest.raises(SnapshotError, match=needle):
        load_snapshot(_write(tmp_path, name, text), role="target")


def test_flags_fill_gaps_but_never_contradict_the_file(tmp_path: Path) -> None:
    plain = load_snapshot(
        ORDERS / "target.jsonl",
        role="target",
        completeness="partial",
        origin="workflow_log",
        observed_at=at("2026-10-20T12:00:00Z"),
    )
    assert (plain.completeness, plain.origin) == ("partial", "workflow_log")
    with pytest.raises(SnapshotError, match="contradicts"):
        load_snapshot(ORDERS / "target_complete.json", role="target", completeness="partial")
    with pytest.raises(SnapshotError, match="contradicts"):
        load_snapshot(
            ORDERS / "target_complete.json",
            role="target",
            observed_at=at("2026-10-20T11:00:00Z"),
        )
    same = load_snapshot(ORDERS / "target_complete.json", role="target", completeness="complete")
    assert same.completeness == "complete"


def test_size_limit_and_encoding(tmp_path: Path) -> None:
    with pytest.raises(SnapshotError, match="exceeds"):
        load_snapshot(_write(tmp_path, "t.json", "[" + " " * 64 + "]"), role="target", max_bytes=8)
    with pytest.raises(SnapshotError, match="UTF-8"):
        load_snapshot(_write(tmp_path, "t.csv", b"id\n\xff\n"), role="target")
    with pytest.raises(ValueError):
        load_snapshot(ORDERS / "source.csv", role="other")


@pytest.mark.parametrize(
    ("text", "ok"),
    [
        ("2026-10-20T12:00:00Z", True),
        ("2026-10-20T19:00:00+07:00", True),
        ("2026-10-20T12:00:00", False),
        ("2026-10-20", False),
        ("yesterday", False),
        (1760000000, False),
    ],
)
def test_parse_instant_requires_offset(text: object, ok: bool) -> None:
    value = parse_instant(text)
    assert (value is not None) is ok
    if ok:
        assert value == at("2026-10-20T12:00:00Z")


def test_snapshot_metadata_is_content_free() -> None:
    meta = load_snapshot(ORDERS / "target_complete.json", role="target").to_dict()
    assert set(meta) == {
        "role",
        "name",
        "sha256",
        "input_format",
        "record_count",
        "observed_at",
        "completeness",
        "origin",
        "demo",
    }
    assert meta["name"] == "target_complete.json"
