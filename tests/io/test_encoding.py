"""Tests for encoding edge cases, split UTF-8, BOM, and forbidden bytes (TASK-027, FR-016)."""

from __future__ import annotations

import io

from sesslint.canonical import SessionEvent
from sesslint.codes import SL002
from sesslint.finding import Finding
from sesslint.io import iter_events


def test_utf8_bom_stripped_cleanly() -> None:
    """UTF-8 BOM on the first line is stripped and the header is parsed cleanly."""
    bom_header = (
        b"\xef\xbb\xbf"
        b'{"schema_version": "sesslint.session/v1", "session_id": "bom_test", '
        b'"created_at": "2026-09-06T12:00:00Z"}\n'
    )
    evt = (
        b'{"actor": "user", "id": "evt_1", "kind": "message", "parent_id": null, '
        b'"payload": {}, "seq": 0, "ts": "2026-09-06T12:00:01Z"}\n'
    )
    items = list(iter_events(io.BytesIO(bom_header + evt)))

    assert len(items) == 1
    assert isinstance(items[0], SessionEvent)
    assert items[0].id == "evt_1"


def test_split_multibyte_utf8_at_eof() -> None:
    """Split multibyte sequence at EOF triggers SL002 encoding finding."""
    header = (
        b'{"schema_version": "sesslint.session/v1", "session_id": "split_test", '
        b'"created_at": "2026-09-06T12:00:00Z"}\n'
    )
    # Truncate a 3-byte Euro sign (€ = \xe2\x82\xac) mid-byte
    broken_tail = b'{"actor": "user", "id": "evt_1", "payload": "\xe2\x82'
    items = list(iter_events(io.BytesIO(header + broken_tail)))

    assert len(items) == 1
    assert isinstance(items[0], Finding)
    assert items[0].code == SL002


def test_forbidden_nul_byte_in_body() -> None:
    """Forbidden NUL byte in JSON body triggers fail-closed finding."""
    header = (
        b'{"schema_version": "sesslint.session/v1", "session_id": "nul_test", '
        b'"created_at": "2026-09-06T12:00:00Z"}\n'
    )
    nul_line = b'{"actor": "user", "id": "evt_1", "payload": "before\x00after"}\n'
    items = list(iter_events(io.BytesIO(header + nul_line)))

    assert len(items) == 1
    assert isinstance(items[0], Finding)
    assert items[0].code == SL002


def test_utf16_bom_mismatch() -> None:
    """UTF-16 LE BOM mismatch triggers SL001/SL002 finding."""
    utf16_content = b"\xff\xfe" + '{"schema_version": "sesslint.session/v1"}\n'.encode("utf-16le")
    items = list(iter_events(io.BytesIO(utf16_content)))

    assert len(items) >= 1
    assert isinstance(items[0], Finding)
