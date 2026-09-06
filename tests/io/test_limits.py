"""Tests for bounded input limits and DoS defenses (TASK-027, FR-011, FR-013)."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from sesslint.codes import SL002
from sesslint.errors import FileTooLargeError, MaxRecordsExceededError
from sesslint.finding import Finding
from sesslint.io import (
    ReaderLimits,
    iter_events,
)


def test_reader_limits_validation() -> None:
    """ReaderLimits strictly validates integer and positivity invariants."""
    limits = ReaderLimits(max_line_bytes=100, max_depth=10, max_file_bytes=1000, max_records=5)
    assert limits.max_line_bytes == 100
    assert limits.max_depth == 10
    assert limits.max_file_bytes == 1000
    assert limits.max_records == 5

    with pytest.raises(ValueError, match="max_line_bytes"):
        ReaderLimits(max_line_bytes=0)
    with pytest.raises(ValueError, match="max_line_bytes"):
        ReaderLimits(max_line_bytes=-1)
    with pytest.raises(ValueError, match="max_depth"):
        ReaderLimits(max_depth=0)
    with pytest.raises(ValueError, match="max_file_bytes"):
        ReaderLimits(max_file_bytes=0)
    with pytest.raises(ValueError, match="max_records"):
        ReaderLimits(max_records=0)


def test_max_line_bytes_exceeded() -> None:
    """Lines exceeding max_line_bytes produce bounded limit finding and drain cleanly."""
    header = (
        b'{"schema_version": "sesslint.session/v1", '
        b'"session_id": "limits_test", "created_at": "2026-09-06T12:00:00Z"}\n'
    )
    long_line = b'{"id": "evt_1", "blob": "' + (b"x" * 200) + b'"}\n'
    content = header + long_line

    limits = ReaderLimits(max_line_bytes=120)
    items = list(iter_events(io.BytesIO(content), limits=limits))

    assert len(items) == 1
    assert isinstance(items[0], Finding)
    assert items[0].code == SL002  # terminal line
    assert "LIMIT" in items[0].message


def test_max_records_exceeded() -> None:
    """Exceeding max_records raises MaxRecordsExceededError."""
    header = (
        b'{"schema_version": "sesslint.session/v1", '
        b'"session_id": "limits_test", "created_at": "2026-09-06T12:00:00Z"}\n'
    )
    evt1 = (
        b'{"id": "evt_1", "actor": "user", "kind": "message", '
        b'"parent_id": null, "ts": "2026-09-06T12:00:01Z", "payload": {}}\n'
    )
    evt2 = (
        b'{"id": "evt_2", "actor": "assistant", "kind": "message", '
        b'"parent_id": "evt_1", "ts": "2026-09-06T12:00:02Z", "payload": {}}\n'
    )
    content = header + evt1 + evt2

    limits = ReaderLimits(max_records=1)
    stream = io.BytesIO(content)
    with pytest.raises(MaxRecordsExceededError):
        list(iter_events(stream, limits=limits))


def test_max_file_bytes_exceeded(tmp_path: Path) -> None:
    """Exceeding max_file_bytes raises FileTooLargeError."""
    test_file = tmp_path / "oversized.jsonl"
    header = (
        '{"schema_version": "sesslint.session/v1", '
        '"session_id": "s", "created_at": "2026-09-06T12:00:00Z"}\n'
    )
    test_file.write_text(header + ("x" * 200) + "\n", encoding="utf-8")

    limits = ReaderLimits(max_file_bytes=100)
    with pytest.raises(FileTooLargeError):
        list(iter_events(test_file, limits=limits))


def test_nesting_depth_limit() -> None:
    """Nesting depth beyond max_depth produces LIMIT finding without RecursionError."""
    header = (
        b'{"schema_version": "sesslint.session/v1", '
        b'"session_id": "nest_test", "created_at": "2026-09-06T12:00:00Z"}\n'
    )
    nested = '{"k": ' * 20 + '{"leaf": 1}' + "}" * 20
    evt_line = (
        f'{{"id": "evt_1", "actor": "user", "kind": "message", '
        f'"parent_id": null, "ts": "2026-09-06T12:00:01Z", "payload": {nested}}}\n'
    ).encode()

    limits = ReaderLimits(max_depth=5)
    items = list(iter_events(io.BytesIO(header + evt_line), limits=limits))

    assert len(items) == 1
    assert isinstance(items[0], Finding)
    assert items[0].code == SL002
    assert "LIMIT" in items[0].message
