"""OutcomeGuard snapshot readers: bounded, metadata never inferred (EVD-02/03/07)."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path

import pytest

from sesslint.outcome import SnapshotError, load_snapshot, parse_instant
from sesslint.outcome.snapshot import EMPTY_NESTED, NON_SCALAR
from tests.outcome.helpers import ORDERS, at, digit_limit
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


# Review regressions before 0.5.0: JSON Lines framing and exact numbers.


def test_jsonl_ends_records_at_line_feeds_only(tmp_path: Path) -> None:
    """U+2028, U+2029 and U+0085 are legal inside JSON strings and never split a record."""
    note = "a" + chr(0x2028) + "b" + chr(0x2029) + "c" + chr(0x85) + "d"
    text = '{"ref": "1", "note": "' + note + '"}\r\n' + "\r\n" + "  \t\n" + '{"ref": "2"}\n'
    snap = load_snapshot(_write(tmp_path, "t.jsonl", text), role="target")
    assert [r["ref"] for r in snap.records] == ["1", "2"]
    assert snap.records[0]["note"] == note
    with pytest.raises(SnapshotError, match="line 5"):
        load_snapshot(_write(tmp_path, "t.jsonl", text + "{oops}\n"), role="target")
    # A carriage return alone does not end a record.
    with pytest.raises(SnapshotError, match="line 1"):
        load_snapshot(_write(tmp_path, "t.jsonl", '{"ref": "1"}\r{"ref": "2"}\n'), role="target")


def test_json_numbers_stay_exact_and_empty_nesting_is_marked(tmp_path: Path) -> None:
    text = '[{"ref": "1", "a": 0.1, "b": 9007199254740993, "c": [], "d": {}, "e": [1], "f": 1E2}]'
    record = load_snapshot(_write(tmp_path, "t.json", text), role="target").records[0]
    assert type(record["a"]) is Decimal and record["a"] == Decimal("0.1")
    assert type(record["b"]) is int and record["b"] == 2**53 + 1
    assert record["c"] is EMPTY_NESTED and record["d"] is EMPTY_NESTED
    assert record["e"] is NON_SCALAR
    assert type(record["f"]) is Decimal and record["f"] == 100


@pytest.mark.parametrize(
    ("name", "template"),
    [("t.json", '[{"n": NUMBER}]'), ("t.jsonl", '{"n": NUMBER}' + "\n")],
)
def test_snapshot_number_exponents_are_bounded(tmp_path: Path, name: str, template: str) -> None:
    """Exponents over six digits would make exact comparison platform-dependent."""

    def first_number(literal: str) -> object:
        path = _write(tmp_path, name, template.replace("NUMBER", literal))
        return load_snapshot(path, role="target").records[0]["n"]

    assert first_number("1e999999") == Decimal("1e999999")
    for literal in ("1e1000000", "-1E+0001000000", "2.5e-1000000"):
        with pytest.raises(SnapshotError, match="out of range"):
            first_number(literal)


_LONG = "number is longer than 4300 characters, not counting its sign"


@pytest.mark.parametrize("limit", [4300, 640, 0])
@pytest.mark.parametrize(
    ("name", "template", "where"),
    [
        ("t.json", '[{"n": 1}, {"n": NUMBER}]', "target snapshot record 2"),
        ("t.jsonl", '{"n": 1}\n{"n": NUMBER}\n', "JSONL line 2"),
    ],
)
def test_snapshot_numbers_may_have_4300_characters_whatever_the_digit_limit(
    tmp_path: Path, name: str, template: str, where: str, limit: int
) -> None:
    """RULE-05, RULE-06, AT-38: the cap is OutcomeGuard's own, so every Python reads alike.

    Before, a long decimal had no cap at all, and a long integer was reported
    as "not strict JSON" at Python's own, environment-dependent digit limit.
    """

    def number(literal: str) -> object:
        path = _write(tmp_path, name, template.replace("NUMBER", literal))
        return load_snapshot(path, role="target").records[1]["n"]

    ones = (10**4300 - 1) // 9
    with digit_limit(limit):
        assert number("1" * 4300) == ones
        assert number("-" + "1" * 4300) == -ones
        assert number("1." + "0" * 4298) == 1
        for literal in ("1" * 4301, "-1" + "0" * 4300, "1." + "0" * 4299, "1e" + "0" * 4299):
            with pytest.raises(SnapshotError) as info:
                number(literal)
            assert str(info.value) == f"{where} has a number out of range ({_LONG})"


def test_number_errors_name_the_record_not_the_field_or_value(tmp_path: Path) -> None:
    """EVD-04: content-free errors name a 1-based record position, never a key or a digit."""
    secret = "9" * 4301
    envelope = (
        '{"schema_version": "sesslint.snapshot/v1", "records": '
        f'[{{"a": 1}}, {{"secret_field": {secret}}}]}}'
    )
    with pytest.raises(SnapshotError) as info:
        load_snapshot(_write(tmp_path, "s.json", envelope), role="source")
    assert str(info.value) == f"source snapshot record 2 has a number out of range ({_LONG})"
    # Outside the records nothing can be counted, so no position is named.
    metadata = '{"schema_version": "sesslint.snapshot/v1", "demo": ' + secret + ', "records": []}'
    with pytest.raises(SnapshotError) as info:
        load_snapshot(_write(tmp_path, "s.json", metadata), role="source")
    assert str(info.value) == f"source snapshot has a number out of range ({_LONG})"
