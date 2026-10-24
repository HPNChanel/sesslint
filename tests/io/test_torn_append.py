"""B17: SL002 is reserved for a provable torn append on the final line.

A final line that ends in a newline, decodes to a complete JSON value, carries
interior NUL bytes or mid-line invalid UTF-8, or exceeds the line limit is
malformed data (SL001) — the conservative SL002 suffix drop must never discard
a complete record.
"""

from __future__ import annotations

import io

import pytest

from sesslint.codes import SL001, SL002
from sesslint.finding import Finding
from sesslint.io import ReaderLimits, is_torn_append, iter_events

HEADER = (
    b'{"schema_version": "sesslint.session/v1", "session_id": "torn", '
    b'"created_at": "2026-09-06T12:00:00Z"}\n'
)
EVENT = (
    b'{"id": "e1", "actor": "user", "kind": "message", "parent_id": null, '
    b'"seq": 1, "ts": "2026-09-06T12:00:01Z", "payload": {"text": "hi"}}'
)


@pytest.mark.parametrize(
    ("line", "torn"),
    [
        (b'{"id": "e2", "payl', True),
        (b'{"id": "e2", "text": "caf\xc3', True),
        (b'{"id": "e2", "pay' + b"\x00" * 16, True),
        (b"\x00\x00\x00\x00", True),
        (b'{"id": "e2", "n": 12.', True),
        (b'{"id": "e2", "n": -', True),
        (b'{"id": "e2", "ok": tr', True),
        (b'{"id": "e2", "s": "a\\u00', True),
        (b'{"id": "e2", "list": [1, {"k": [', True),
        (b"{", True),
        (b'"unterminated string', False),
        (b"GARBAGE_NO_ID_HERE", False),
        (b'{"id": "e2", GARBAGE', False),
        (b'{"id": "e2" "kind"', False),
        (b'{"id": "e2", "n": 01', False),
        (b'{"id": "e2", "s": "a\\x', False),
        (b'{"id": "e2", "ok": tx', False),
        (b'{"id": "e2", "list": [1,]', False),
        (b'{"id": "e2"}', False),
        (b'{"id": "e2"}' + b"\x00" * 4, False),
        (b'{"id": "e2"}{"id": "e3", "pay', False),
        (b'{"id": "e2", "pay\x00load": 1', False),
        (b'{"id": "e2", \xff "text": "x"', False),
        (b'{"id": "e2", "payl\n', False),
        (b'{"id": "e2", "payl\r\n', False),
        (b"[1, 2, 3]", False),
    ],
)
def test_is_torn_append_shapes(line: bytes, torn: bool) -> None:
    assert is_torn_append(line) is torn


def test_is_torn_append_strips_bom_only_when_asked() -> None:
    assert is_torn_append(b'\xef\xbb\xbf{"id": "e2"', strip_bom=True) is True
    assert is_torn_append(b'\xef\xbb\xbf{"id": "e2"}', strip_bom=True) is False


def _terminal_finding(tail: bytes, limits: ReaderLimits | None = None) -> Finding:
    items = list(iter_events(io.BytesIO(HEADER + EVENT + b"\n" + tail), limits=limits))
    findings = [item for item in items if isinstance(item, Finding)]
    assert len(findings) == 1
    return findings[0]


def test_unterminated_undecodable_tail_is_sl002_with_marker() -> None:
    finding = _terminal_finding(b'{"id": "e2", "actor": "assist')
    assert finding.code == SL002
    assert finding.evidence["unterminated"] is True


@pytest.mark.parametrize(
    "tail",
    [
        b'{"id": "e2", "actor": "assist\n',
        b'{"id": "e2", "payload": "a\x00b"}\n',
        b'{"id": "e2", "payload": "caf\xe9"}\n',
        b'{"id": "e2", "payload": "caf\xe9"}',
        b'{"id": "e2", "actor": "user"}',
        b'{"id": "e2", "payload": NaN}',
    ],
)
def test_complete_or_corrupt_tail_is_sl001(tail: bytes) -> None:
    finding = _terminal_finding(tail)
    assert finding.code == SL001
    assert "unterminated" not in finding.evidence


def test_over_limit_unterminated_tail_is_sl001() -> None:
    tail = b'{"id": "e2", "blob": "' + b"x" * 400
    finding = _terminal_finding(tail, limits=ReaderLimits(max_line_bytes=300))
    assert finding.code == SL001
