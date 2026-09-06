"""Tests for sesslint.io streaming reader, hostile-input limits, and source coordinates."""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from sesslint.canonical import SessionEvent, SessionHeader
from sesslint.codes import SL001, SL002
from sesslint.errors import (
    FileTooLargeError,
    HeaderMissingError,
    MaxRecordsExceededError,
    SchemaError,
)
from sesslint.finding import Finding
from sesslint.io import (
    ReaderLimits,
    check_nesting_depth,
    extract_record_id,
    iter_events,
    read_header,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "sessions"


class _CountingStream(io.BytesIO):
    """BytesIO wrapper tracking the number of readline calls."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.readline_call_count = 0

    def readline(self, size: int | None = -1) -> bytes:
        self.readline_call_count += 1
        return super().readline(size if size is not None else -1)


def _make_session_content(num_events: int = 5) -> bytes:
    """Helper to generate a minimal canonical session file in bytes."""
    lines = [
        '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1",'
        '"session_id":"sess_test_io"}'
    ]
    for i in range(num_events):
        lines.append(
            f'{{"actor":"user","id":"evt_{i:03d}","kind":"message","parent_id":null,'
            f'"payload":{{"idx":{i}}},"seq":{i},"ts":"2026-09-05T12:00:00Z"}}'
        )
    return ("\n".join(lines) + "\n").encode("utf-8")


class TestReaderLimits:
    """Validation of ReaderLimits dataclass invariants."""

    def test_default_limits(self) -> None:
        limits = ReaderLimits()
        assert limits.max_line_bytes == 1_000_000
        assert limits.max_depth == 100
        assert limits.max_file_bytes == 100 * 1024 * 1024
        assert limits.max_records is None

    def test_custom_valid_limits(self) -> None:
        limits = ReaderLimits(
            max_line_bytes=500,
            max_depth=10,
            max_file_bytes=1024,
            max_records=50,
        )
        assert limits.max_line_bytes == 500
        assert limits.max_depth == 10
        assert limits.max_file_bytes == 1024
        assert limits.max_records == 50

    @pytest.mark.parametrize(
        ("field", "bad_val"),
        [
            ("max_line_bytes", 0),
            ("max_line_bytes", -1),
            ("max_line_bytes", "100"),
            ("max_line_bytes", True),
            ("max_depth", 0),
            ("max_depth", -5),
            ("max_depth", False),
            ("max_file_bytes", 0),
            ("max_file_bytes", -10),
            ("max_records", 0),
            ("max_records", -1),
            ("max_records", "10"),
            ("max_records", False),
        ],
    )
    def test_invalid_limits(self, field: str, bad_val: Any) -> None:
        kwargs: dict[str, Any] = {field: bad_val}
        with pytest.raises(ValueError, match=field):
            ReaderLimits(**kwargs)


class TestStreamingProof:
    """Proof that iter_events streams incrementally and bounds memory (FR-014)."""

    def test_iter_events_returns_iterator(self, tmp_path: Path) -> None:
        file_path = tmp_path / "test.jsonl"
        file_path.write_bytes(_make_session_content(3))
        res = iter_events(file_path)
        assert isinstance(res, Iterator)

    def test_consuming_one_event_does_not_read_entire_file(self) -> None:
        """Consuming the first item must not read all lines from a 100-line file."""
        data = _make_session_content(num_events=100)
        stream = _CountingStream(data)

        it = iter_events(stream)
        first_event = next(it)
        assert isinstance(first_event, SessionEvent)
        assert first_event.id == "evt_000"

        # Reading 1 event with 1-record lookahead requires reading:
        # line 1 (header), line 2 (evt 0), line 3 (evt 1).
        # It must NOT read all 101 lines.
        assert stream.readline_call_count < 10
        assert stream.readline_call_count >= 2


class TestSourceCoordinates:
    """Line number and coordinate accuracy tests (FR-015)."""

    def test_line_coordinates_with_blank_lines(self, tmp_path: Path) -> None:
        """Blanks increment line numbers but are not yielded as events."""
        lines = [
            '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1",'
            '"session_id":"sess_coords"}',
            "",
            "   ",
            '{"actor":"user","id":"evt_001","kind":"message","parent_id":null,"payload":{},"seq":0,"ts":"2026-09-05T12:00:00Z"}',
            "",
            '{"actor":"assistant","id":"evt_002","kind":"message","parent_id":"evt_001","payload":{},"seq":1,"ts":"2026-09-05T12:00:01Z"}',
        ]
        file_path = tmp_path / "coords.jsonl"
        file_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        events = list(iter_events(file_path))
        assert len(events) == 2
        assert isinstance(events[0], SessionEvent)
        assert events[0].id == "evt_001"
        assert isinstance(events[1], SessionEvent)
        assert events[1].id == "evt_002"

    def test_malformed_coordinate_accuracy(self, tmp_path: Path) -> None:
        """Malformed line coordinate points to the exact physical line number."""
        lines = [
            '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1",'
            '"session_id":"sess_bad_line"}',
            "",
            '{"id":"evt_broken", invalid json on line 3',
            '{"actor":"user","id":"evt_002","kind":"message","parent_id":null,"payload":{},"seq":1,"ts":"2026-09-05T12:00:00Z"}',
        ]
        file_path = tmp_path / "bad.jsonl"
        file_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        items = list(iter_events(file_path))
        assert len(items) == 2
        assert isinstance(items[0], Finding)
        assert items[0].code == SL001
        assert items[0].source.line == 3
        assert items[0].source.record_id == "evt_broken"
        assert isinstance(items[1], SessionEvent)
        assert items[1].id == "evt_002"


class TestLimitsEnforcement:
    """Hostile-input limit tests (FR-013)."""

    def test_max_file_bytes_exceeded_on_file(self, tmp_path: Path) -> None:
        file_path = tmp_path / "large.jsonl"
        file_path.write_bytes(_make_session_content(10))
        file_size = file_path.stat().st_size

        limits = ReaderLimits(max_file_bytes=file_size - 1)
        with pytest.raises(FileTooLargeError, match="exceeds maximum limit"):
            list(iter_events(file_path, limits=limits))

    def test_max_file_bytes_exceeded_on_stream(self) -> None:
        data = _make_session_content(10)
        stream = io.BytesIO(data)
        limits = ReaderLimits(max_file_bytes=len(data) - 5)
        with pytest.raises(FileTooLargeError, match="maximum file size limit"):
            list(iter_events(stream, limits=limits))

    def test_max_line_bytes_nonterminal_produces_sl001(self, tmp_path: Path) -> None:
        """Line exceeding max_line_bytes mid-file produces SL001 with detail=LIMIT."""
        huge_line = '{"id":"evt_giant", "pad":"' + ("x" * 200) + '"}\n'
        file_path = tmp_path / "giant.jsonl"
        content = (
            '{"created_at":"2026-09-05T00:00:00Z","schema_version":"sesslint.session/v1",'
            '"session_id":"s1"}\n'
            + huge_line
            + (
                '{"actor":"user","id":"evt_tail","kind":"message","parent_id":null,'
                '"payload":{},"seq":1,"ts":"2026-09-05T12:00:00Z"}\n'
            )
        )
        file_path.write_text(content, encoding="utf-8")

        limits = ReaderLimits(max_line_bytes=150)
        items = list(iter_events(file_path, limits=limits))
        assert len(items) == 2
        assert isinstance(items[0], Finding)
        assert items[0].code == SL001
        assert "LIMIT" in items[0].message
        assert items[0].source.line == 2
        assert isinstance(items[1], SessionEvent)
        assert items[1].id == "evt_tail"

    def test_max_line_bytes_terminal_produces_sl002(self, tmp_path: Path) -> None:
        """Line exceeding max_line_bytes at end of file produces SL002."""
        huge_line = '{"id":"evt_giant_term", "pad":"' + ("x" * 200) + '"}\n'
        file_path = tmp_path / "giant_term.jsonl"
        content = (
            '{"created_at":"2026-09-05T00:00:00Z","schema_version":"sesslint.session/v1",'
            '"session_id":"s1"}\n' + huge_line
        )
        file_path.write_text(content, encoding="utf-8")

        limits = ReaderLimits(max_line_bytes=150)
        items = list(iter_events(file_path, limits=limits))
        assert len(items) == 1
        assert isinstance(items[0], Finding)
        assert items[0].code == SL002
        assert "LIMIT" in items[0].message
        assert items[0].source.line == 2

    def test_adversarial_10mb_line_bounded_memory(self, tmp_path: Path) -> None:
        """Ensure a 10 MB line does not crash or OOM the length-guarded reader."""
        file_path = tmp_path / "ten_mb.jsonl"
        header = (
            '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1",'
            '"session_id":"sess_10mb"}\n'
        )
        with open(file_path, "wb") as f:
            f.write(header.encode("utf-8"))
            f.write(b'{"id":"evt_big","payload":"' + b"A" * (10 * 1024 * 1024) + b'"}\n')
            f.write(
                b'{"actor":"user","id":"evt_end","kind":"message","parent_id":null,"payload":{},"seq":1,"ts":"2026-09-05T12:00:00Z"}\n'
            )

        limits = ReaderLimits(max_line_bytes=500_000)
        items = list(iter_events(file_path, limits=limits))
        assert len(items) == 2
        assert isinstance(items[0], Finding)
        assert items[0].code == SL001
        assert "LIMIT" in items[0].message
        assert items[0].source.line == 2
        assert isinstance(items[1], SessionEvent)
        assert items[1].id == "evt_end"

    def test_max_depth_exceeded(self, tmp_path: Path) -> None:
        """Deep nesting exceeding max_depth produces finding with detail=LIMIT."""
        # 15 levels of nested dict
        nested_val: dict[str, Any] = {"a": "deep"}
        for _ in range(15):
            nested_val = {"a": nested_val}

        event_str = json.dumps(
            {
                "actor": "user",
                "id": "evt_deep",
                "kind": "message",
                "parent_id": None,
                "payload": nested_val,
                "seq": 0,
                "ts": "2026-09-05T12:00:00Z",
            }
        )
        file_path = tmp_path / "deep.jsonl"
        file_path.write_text(
            '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1",'
            '"session_id":"sess_deep"}\n' + event_str + "\n",
            encoding="utf-8",
        )

        limits = ReaderLimits(max_depth=10)
        items = list(iter_events(file_path, limits=limits))
        assert len(items) == 1
        assert isinstance(items[0], Finding)
        assert items[0].code == SL002  # terminal line
        assert "LIMIT" in items[0].message

    def test_max_records_exceeded(self, tmp_path: Path) -> None:
        file_path = tmp_path / "records.jsonl"
        file_path.write_bytes(_make_session_content(10))

        limits = ReaderLimits(max_records=3)
        with pytest.raises(MaxRecordsExceededError, match="exceeds limit of 3"):
            list(iter_events(file_path, limits=limits))


class TestEncodingAndSpecialCharacters:
    """Encoding and hostile character tests (FR-016)."""

    def test_crlf_bom_fixture(self) -> None:
        """Fixture with UTF-8 BOM and CRLF line endings streams cleanly."""
        fixture_path = FIXTURES_DIR / "crlf-bom.jsonl"
        events = list(iter_events(fixture_path))
        assert len(events) == 1
        assert isinstance(events[0], SessionEvent)
        assert events[0].id == "evt_001"

    def test_invalid_utf8_bytes_detail_encoding(self, tmp_path: Path) -> None:
        """Invalid UTF-8 sequence produces finding with detail=ENCODING."""
        file_path = tmp_path / "bad_utf8.jsonl"
        file_path.write_bytes(
            b'{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1",'
            b'"session_id":"sess_bad_utf8"}\n'
            b'{"id":"evt_bad_enc", "data":"\xff\xfe\x80"}\n'
            b'{"actor":"user","id":"evt_good","kind":"message","parent_id":null,"payload":{},"seq":1,"ts":"2026-09-05T12:00:00Z"}\n'
        )

        items = list(iter_events(file_path))
        assert len(items) == 2
        assert isinstance(items[0], Finding)
        assert items[0].code == SL001
        assert "ENCODING" in items[0].message
        assert items[0].source.line == 2
        assert isinstance(items[1], SessionEvent)
        assert items[1].id == "evt_good"

    def test_nul_byte_in_record(self, tmp_path: Path) -> None:
        """NUL bytes inside a record produce SL001."""
        file_path = tmp_path / "nul.jsonl"
        file_path.write_bytes(
            b'{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1",'
            b'"session_id":"sess_nul"}\n'
            b'{"id":"evt_nul", "data":"hello\x00world"}\n'
            b'{"actor":"user","id":"evt_after","kind":"message","parent_id":null,"payload":{},"seq":1,"ts":"2026-09-05T12:00:00Z"}\n'
        )

        items = list(iter_events(file_path))
        assert len(items) == 2
        assert isinstance(items[0], Finding)
        assert items[0].code == SL001
        assert "NUL byte" in items[0].message
        assert items[0].source.line == 2


class TestStrictNumericConstants:
    """Rejection of non-standard numbers NaN, Infinity, and 1e999 (RFC 8785)."""

    @pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity", "1e999"])
    def test_strict_numbers_produce_finding(self, tmp_path: Path, constant: str) -> None:
        file_path = tmp_path / "numbers.jsonl"
        content = (
            '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1",'
            '"session_id":"sess_num"}\n'
            f'{{"id":"evt_num", "val":{constant}}}\n'
            '{"actor":"user","id":"evt_ok","kind":"message","parent_id":null,"payload":{},"seq":1,"ts":"2026-09-05T12:00:00Z"}\n'
        )
        file_path.write_text(content, encoding="utf-8")

        items = list(iter_events(file_path))
        assert len(items) == 2
        assert isinstance(items[0], Finding)
        assert items[0].code == SL001
        assert items[0].source.line == 2
        assert isinstance(items[1], SessionEvent)
        assert items[1].id == "evt_ok"


class TestEmptyFileAndHeader:
    """Empty files and header parsing edge cases."""

    def test_zero_byte_file_raises_typed_error(self, tmp_path: Path) -> None:
        empty_file = tmp_path / "empty.jsonl"
        empty_file.write_bytes(b"")

        with pytest.raises(HeaderMissingError, match="contains no records"):
            list(iter_events(empty_file))

    def test_whitespace_only_file_raises_typed_error(self, tmp_path: Path) -> None:
        blank_file = tmp_path / "blank.jsonl"
        blank_file.write_text("   \n\n\t  \r\n", encoding="utf-8")

        with pytest.raises(HeaderMissingError, match="contains no records"):
            list(iter_events(blank_file))

    def test_read_header_success(self) -> None:
        fixture_path = FIXTURES_DIR / "minimal-valid.jsonl"
        header = read_header(fixture_path)
        assert isinstance(header, SessionHeader)
        assert header.session_id == "sess_min_001"
        assert header.schema_version == "sesslint.session/v1"

    def test_read_header_empty_file_raises(self, tmp_path: Path) -> None:
        empty_file = tmp_path / "empty.jsonl"
        empty_file.write_bytes(b"")
        with pytest.raises(HeaderMissingError):
            read_header(empty_file)

    def test_read_header_wrong_version(self) -> None:
        fixture_path = FIXTURES_DIR / "wrong-version.jsonl"
        with pytest.raises(SchemaError):
            read_header(fixture_path)


class TestHelpers:
    """Unit tests for check_nesting_depth and extract_record_id."""

    def test_check_nesting_depth_flat(self) -> None:
        assert check_nesting_depth({"a": 1, "b": [1, 2, 3]}, max_depth=5) is True

    def test_check_nesting_depth_exceeded(self) -> None:
        deep = {"a": {"b": {"c": 1}}}
        assert check_nesting_depth(deep, max_depth=2) is False

    def test_extract_record_id_from_dict(self) -> None:
        assert extract_record_id(None, {"id": "evt_test"}) == "evt_test"

    def test_extract_record_id_regex_fallback(self) -> None:
        text = '{"some": "prefix", "id": "evt_regex", "broken":'
        assert extract_record_id(text) == "evt_regex"

    def test_extract_record_id_rejects_credential(self) -> None:
        text = '{"id": "sk-123456789012345678", "other": 1}'
        assert extract_record_id(text) is None


class TestReadHeaderEdgeCases:
    """Comprehensive error path testing for read_header."""

    def test_read_header_from_stream(self) -> None:
        data = _make_session_content(1)
        stream = io.BytesIO(data)
        header = read_header(stream)
        assert header.session_id == "sess_test_io"

    def test_read_header_file_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            read_header(tmp_path / "nonexistent.jsonl")

    def test_read_header_file_too_large(self, tmp_path: Path) -> None:
        file_path = tmp_path / "large_hdr.jsonl"
        file_path.write_bytes(_make_session_content(1))
        limits = ReaderLimits(max_file_bytes=10)
        with pytest.raises(FileTooLargeError):
            read_header(file_path, limits=limits)

    def test_read_header_line_too_long(self, tmp_path: Path) -> None:
        file_path = tmp_path / "long_hdr.jsonl"
        file_path.write_bytes(
            b'{"created_at":"2026-09-05T00:00:00Z","schema_version":"sesslint.session/v1","session_id":"s"}\n'
        )
        limits = ReaderLimits(max_line_bytes=50)
        with pytest.raises(SchemaError, match="exceeds maximum line byte limit"):
            read_header(file_path, limits=limits)

    def test_read_header_nul_byte(self, tmp_path: Path) -> None:
        file_path = tmp_path / "nul_hdr.jsonl"
        file_path.write_bytes(
            b'{"created_at":"\x00","schema_version":"sesslint.session/v1","session_id":"s"}\n'
        )
        with pytest.raises(SchemaError, match="Forbidden NUL byte"):
            read_header(file_path)

    def test_read_header_invalid_utf8(self, tmp_path: Path) -> None:
        file_path = tmp_path / "bad_utf8_hdr.jsonl"
        file_path.write_bytes(b"\xff\xfe\x80\n")
        with pytest.raises(SchemaError, match="Invalid UTF-8"):
            read_header(file_path)

    def test_read_header_malformed_json(self, tmp_path: Path) -> None:
        file_path = tmp_path / "bad_json_hdr.jsonl"
        file_path.write_text("{broken json\n", encoding="utf-8")
        with pytest.raises(SchemaError, match="Malformed JSON"):
            read_header(file_path)

    def test_read_header_non_dict(self, tmp_path: Path) -> None:
        file_path = tmp_path / "list_hdr.jsonl"
        file_path.write_text("[1, 2, 3]\n", encoding="utf-8")
        with pytest.raises(SchemaError, match="Session header must be a mapping"):
            read_header(file_path)

    def test_read_header_deep_nesting(self, tmp_path: Path) -> None:
        nested: dict[str, Any] = {"a": 1}
        for _ in range(15):
            nested = {"a": nested}
        file_path = tmp_path / "deep_hdr.jsonl"
        doc = {
            "created_at": "2026-09-05T00:00:00Z",
            "schema_version": "sesslint.session/v1",
            "session_id": "s1",
            "metadata": nested,
        }
        file_path.write_text(json.dumps(doc) + "\n", encoding="utf-8")
        limits = ReaderLimits(max_depth=5)
        with pytest.raises(SchemaError, match="Header nesting depth exceeds limit"):
            read_header(file_path, limits=limits)


class TestIterEventsEdgeCases:
    """Additional edge cases for iter_events to complete coverage."""

    def test_iter_events_file_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            list(iter_events(tmp_path / "nonexistent.jsonl"))

    def test_iter_events_non_dict_json_line(self, tmp_path: Path) -> None:
        """Non-dict JSON line (e.g. array) produces finding."""
        file_path = tmp_path / "array_line.jsonl"
        file_path.write_text(
            '{"created_at":"2026-09-05T00:00:00Z","schema_version":"sesslint.session/v1","session_id":"s1"}\n'
            "[1, 2, 3]\n"
            '{"actor":"user","id":"evt_001","kind":"message","parent_id":null,"payload":{},"seq":0,"ts":"2026-09-05T12:00:00Z"}\n',
            encoding="utf-8",
        )
        items = list(iter_events(file_path))
        assert len(items) == 2
        assert isinstance(items[0], Finding)
        assert items[0].code == SL001
        assert isinstance(items[1], SessionEvent)

    def test_terminal_event_schema_error_produces_sl002(self, tmp_path: Path) -> None:
        """Event with schema violation on terminal line produces SL002."""
        file_path = tmp_path / "bad_term_event.jsonl"
        file_path.write_text(
            '{"created_at":"2026-09-05T00:00:00Z","schema_version":"sesslint.session/v1","session_id":"s1"}\n'
            '{"actor":"user","id":"evt_001","kind":"message","parent_id":null,"payload":{},"seq":0,"ts":"2026-09-05T12:00:00Z"}\n'
            '{"actor":"invalid_actor","id":"evt_bad","kind":"message","parent_id":null,"payload":{},"seq":1,"ts":"2026-09-05T12:00:01Z"}\n',
            encoding="utf-8",
        )
        items = list(iter_events(file_path))
        assert len(items) == 2
        assert isinstance(items[0], SessionEvent)
        assert isinstance(items[1], Finding)
        assert items[1].code == SL002
        assert items[1].source.record_id == "evt_bad"

    def test_terminal_broken_header_produces_sl002(self, tmp_path: Path) -> None:
        """Single-line file with invalid schema header produces SL002."""
        file_path = tmp_path / "bad_term_hdr.jsonl"
        file_path.write_text(
            '{"schema_version":"sesslint.session/v0","session_id":"bad_v"}\n',
            encoding="utf-8",
        )
        items = list(iter_events(file_path))
        assert len(items) == 1
        assert isinstance(items[0], Finding)
        assert items[0].code == SL002

    def test_adversarial_deep_nesting_recursion_error(self, tmp_path: Path) -> None:
        """2000 levels of nesting triggering Python RecursionError maps to LIMIT finding."""
        deep_obj = '{"a":' * 2000 + "1" + "}" * 2000
        # Terminal case
        term_file = tmp_path / "deep_term.jsonl"
        term_file.write_text(deep_obj + "\n", encoding="utf-8")
        items = list(iter_events(term_file))
        assert len(items) == 1
        assert isinstance(items[0], Finding)
        assert items[0].code == SL002
        assert "LIMIT" in items[0].message

        # Nonterminal case
        nonterm_file = tmp_path / "deep_nonterm.jsonl"
        nonterm_file.write_text(
            deep_obj
            + "\n"
            + '{"actor":"user","id":"evt_after","kind":"message","parent_id":null,'
            + '"payload":{},"seq":0,"ts":"2026-09-05T12:00:00Z"}\n',
            encoding="utf-8",
        )
        items2 = list(iter_events(nonterm_file))
        assert len(items2) == 2
        assert isinstance(items2[0], Finding)
        assert items2[0].code == SL001
        assert "LIMIT" in items2[0].message
        assert isinstance(items2[1], SessionEvent)

    def test_read_header_adversarial_deep_nesting_recursion_error(self, tmp_path: Path) -> None:
        """2000 levels of nesting in read_header raises SchemaError with recursion limit."""
        deep_obj = '{"a":' * 2000 + "1" + "}" * 2000
        file_path = tmp_path / "deep_hdr_rec.jsonl"
        file_path.write_text(deep_obj + "\n", encoding="utf-8")
        with pytest.raises(SchemaError, match="recursion limit"):
            read_header(file_path)

    def test_extract_record_id_whitespace_only(self, tmp_path: Path) -> None:
        """Malformed line with whitespace-only id does not crash and sets record_id to None."""
        file_path = tmp_path / "ws_id.jsonl"
        file_path.write_text('{"id": "   ", broken_syntax\n', encoding="utf-8")
        items = list(iter_events(file_path))
        assert len(items) == 1
        assert isinstance(items[0], Finding)
        assert items[0].source.record_id is None

    def test_oversized_whitespace_line_mid_stream(self, tmp_path: Path) -> None:
        """Mid-stream whitespace line exceeding max_line_bytes produces SL001 with LIMIT."""
        file_path = tmp_path / "ws_mid.jsonl"
        content = (
            '{"created_at":"2026-09-05T00:00:00Z","schema_version":"sesslint.session/v1",'
            '"session_id":"s1"}\n'
            + (" " * 200)
            + "\n"
            + '{"actor":"user","id":"evt_1","kind":"message","parent_id":null,'
            + '"payload":{},"seq":0,"ts":"2026-09-05T12:00:00Z"}\n'
        )
        file_path.write_text(content, encoding="utf-8")
        limits = ReaderLimits(max_line_bytes=150)
        items = list(iter_events(file_path, limits=limits))
        assert len(items) == 2
        assert isinstance(items[0], Finding)
        assert items[0].code == SL001
        assert items[0].source.line == 2
        assert "LIMIT" in items[0].message
        assert isinstance(items[1], SessionEvent)

    def test_oversized_whitespace_line_terminal(self, tmp_path: Path) -> None:
        """Terminal whitespace line exceeding max_line_bytes produces SL002 with LIMIT."""
        file_path = tmp_path / "ws_term.jsonl"
        content = (
            '{"created_at":"2026-09-05T00:00:00Z","schema_version":"sesslint.session/v1",'
            '"session_id":"s1"}\n' + (" " * 200) + "\n"
        )
        file_path.write_text(content, encoding="utf-8")
        limits = ReaderLimits(max_line_bytes=150)
        items = list(iter_events(file_path, limits=limits))
        assert len(items) == 1
        assert isinstance(items[0], Finding)
        assert items[0].code == SL002
        assert items[0].source.line == 2
        assert "LIMIT" in items[0].message

    def test_read_header_first_record_is_event(self, tmp_path: Path) -> None:
        """read_header raises HeaderMissingError when first line is an event instead of header."""
        file_path = tmp_path / "event_first.jsonl"
        file_path.write_text(
            '{"actor":"user","id":"evt_001","kind":"message","parent_id":null,'
            '"payload":{},"seq":0,"ts":"2026-09-05T12:00:00Z"}\n',
            encoding="utf-8",
        )
        with pytest.raises(HeaderMissingError, match="First record is not a session header"):
            read_header(file_path)

    def test_is_directory_error_raised_for_dir_path(self, tmp_path: Path) -> None:
        """Passing a directory path raises IsADirectoryError consistently cross-platform."""
        with pytest.raises(IsADirectoryError, match="Expected session file"):
            read_header(tmp_path)
        with pytest.raises(IsADirectoryError, match="Expected session file"):
            list(iter_events(tmp_path))

    def test_max_line_bytes_exact_boundary(self, tmp_path: Path) -> None:
        """Line exactly max_line_bytes succeeds; line of max_line_bytes + 1 produces LIMIT."""
        payload_dict: dict[str, str] = {"pad": ""}
        doc: dict[str, Any] = {
            "actor": "user",
            "id": "evt_exact_001",
            "kind": "message",
            "parent_id": None,
            "payload": payload_dict,
            "seq": 0,
            "ts": "2026-09-05T12:00:00Z",
        }
        raw_json = json.dumps(doc, separators=(",", ":"))
        needed = 200 - (len(raw_json.encode("utf-8")) + 1)
        payload_dict["pad"] = "X" * needed
        line_exact = (json.dumps(doc, separators=(",", ":")) + "\n").encode("utf-8")
        assert len(line_exact) == 200

        file_exact = tmp_path / "exact.jsonl"
        file_exact.write_bytes(line_exact)
        limits_200 = ReaderLimits(max_line_bytes=200)
        items_exact = list(iter_events(file_exact, limits=limits_200))
        assert len(items_exact) == 1
        assert isinstance(items_exact[0], SessionEvent)

        payload_dict["pad"] = "X" * (needed + 1)
        line_plus_one = (json.dumps(doc, separators=(",", ":")) + "\n").encode("utf-8")
        assert len(line_plus_one) == 201
        file_plus_one = tmp_path / "plus_one.jsonl"
        file_plus_one.write_bytes(line_plus_one)
        items_plus_one = list(iter_events(file_plus_one, limits=limits_200))
        assert len(items_plus_one) == 1
        assert isinstance(items_plus_one[0], Finding)
        assert items_plus_one[0].code == SL002
        assert "LIMIT" in items_plus_one[0].message

    def test_max_depth_exact_boundary(self) -> None:
        """Structure of depth exactly max_depth passes; depth of max_depth + 1 fails."""
        depth_3 = {"a": {"b": {"c": 1}}}
        assert check_nesting_depth(depth_3, max_depth=3) is True
        assert check_nesting_depth(depth_3, max_depth=2) is False


class TestCliScanLimits:
    """CLI test for scan --show-limits."""

    def test_cli_scan_show_limits(self, capsys: pytest.CaptureFixture[str]) -> None:
        from sesslint.cli import main as cli_main

        exit_code = cli_main(["scan", "--show-limits"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "ReaderLimits" in captured.out
        assert "max_line_bytes=1000000" in captured.out

    def test_cli_scan_no_flags_prints_help(self, capsys: pytest.CaptureFixture[str]) -> None:
        from sesslint.cli import main as cli_main

        exit_code = cli_main(["scan"])
        assert exit_code == 2
        captured = capsys.readouterr()
        assert "usage:" in captured.err.lower()
