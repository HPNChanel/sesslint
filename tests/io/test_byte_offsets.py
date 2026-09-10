"""Tests for byte-offset source coordinates and slice round-trip invariants (DEV-006).

Covers:
- Exact-offset tables for all 6 edge shapes:
  1. ASCII stream
  2. Multibyte intact (UTF-8)
  3. Multibyte split at EOF / invalid UTF-8
  4. CRLF line endings
  5. UTF-8 BOM
  6. Terminal tear (truncated record without newline)
- Overlong-line truncation point offset
- Ordinal continuity across 1-record lookahead boundary
- Contract test for all 4 streaming readers (io, canonical, claude_code, openai_agents)
- Slice-round-trip property test across synthetic streams
- span.byte population in render_json and (bytes a-b) in render_human
"""

from __future__ import annotations

import io
import json

import pytest

from sesslint.adapters.canonical import load_canonical
from sesslint.adapters.claude_code import load_claude_code
from sesslint.adapters.openai_agents import load_openai_agents
from sesslint.codes import SL001, SL002
from sesslint.finding import Finding
from sesslint.io import ReaderLimits, iter_events
from sesslint.report import (
    build_report,
    format_finding_content_free,
    render_human,
    render_json,
)


def _collect_stream_findings(data: bytes, limits: ReaderLimits | None = None) -> list[Finding]:
    """Helper to collect findings from io.py iter_events."""
    findings: list[Finding] = []
    for item in iter_events(io.BytesIO(data), limits=limits):
        if isinstance(item, Finding):
            findings.append(item)
    return findings


# =============================================================================
# 1. Exact-offset Tables for Edge Shapes
# =============================================================================


def test_exact_offsets_ascii() -> None:
    """Exact byte coordinates for pure ASCII stream with non-terminal and terminal errors."""
    line1 = (
        b'{"schema_version": "sesslint.session/v1", "session_id": "s1", '
        b'"created_at": "2026-09-06T12:00:00Z"}\n'
    )
    line2 = (
        b'{"actor": "user", "id": "e1", "kind": "message", "parent_id": null, '
        b'"payload": {}, "seq": 1, "ts": "2026-09-06T12:00:01Z"}\n'
    )
    line3 = b'{"malformed": "json" broken\n'
    line4 = (
        b'{"actor": "assistant", "id": "e2", "kind": "message", "parent_id": "e1", '
        b'"payload": {}, "seq": 2, "ts": "2026-09-06T12:00:02Z"}\n'
    )
    line5 = b'{"incomplete": "tear"'

    raw = line1 + line2 + line3 + line4 + line5

    # Calculate exact byte boundaries
    l1_start = 0
    l1_end = len(line1)
    l2_start = l1_end
    l2_end = l2_start + len(line2)
    l3_start = l2_end
    l3_end = l3_start + len(line3)
    l4_start = l3_end
    l4_end = l4_start + len(line4)
    l5_start = l4_end
    l5_end = l5_start + len(line5)

    assert l1_start == 0
    assert l5_end == len(raw)

    findings = _collect_stream_findings(raw)
    assert len(findings) == 2

    # Finding 1: line3 non-terminal malformed -> SL001
    f_non_term = findings[0]
    assert f_non_term.code == SL001
    assert f_non_term.source.line == 3
    assert f_non_term.evidence["byte_offset"] == l3_start
    assert f_non_term.evidence["byte_end"] == l3_end
    assert f_non_term.evidence["record_ordinal"] == 3
    assert raw[f_non_term.evidence["byte_offset"] : f_non_term.evidence["byte_end"]] == line3

    # Finding 2: line5 terminal tear -> SL002
    f_term = findings[1]
    assert f_term.code == SL002
    assert f_term.source.line == 5
    assert f_term.evidence["byte_offset"] == l5_start
    assert f_term.evidence["byte_end"] == l5_end
    assert f_term.evidence["record_ordinal"] == 5
    assert raw[f_term.evidence["byte_offset"] : f_term.evidence["byte_end"]] == line5


def test_exact_offsets_multibyte_intact() -> None:
    """Exact byte coordinates when lines contain multibyte UTF-8 characters."""
    # "日本語テスト" = 15 UTF-8 bytes (5 chars * 3 bytes)
    # "🚀✨" = 8 UTF-8 bytes (2 chars * 4 bytes)
    line1 = (
        b'{"schema_version": "sesslint.session/v1", "session_id": "s1", '
        b'"created_at": "2026-09-06T12:00:00Z"}\n'
    )
    line2 = (
        '{"actor": "user", "id": "e1", "kind": "message", "parent_id": null, '
        '"payload": {"text": "日本語テスト🚀✨"}, "seq": 1, "ts": "2026-09-06T12:00:01Z"}\n'
    ).encode()
    line3 = '{"actor": "assistant", "id": "e2", "bad": "日本語" broken}\n'.encode()

    raw = line1 + line2 + line3

    l1_end = len(line1)
    l2_start = l1_end
    l2_end = l2_start + len(line2)
    l3_start = l2_end
    l3_end = l3_start + len(line3)

    findings = _collect_stream_findings(raw)
    assert len(findings) == 1

    f = findings[0]
    assert f.code == SL002  # Terminal since line3 is last line
    assert f.source.line == 3
    assert f.evidence["byte_offset"] == l3_start
    assert f.evidence["byte_end"] == l3_end
    assert f.evidence["record_ordinal"] == 3
    # Critical verification: offset matches byte length, NOT character index
    assert f.evidence["byte_end"] - f.evidence["byte_offset"] == len(line3)
    assert raw[f.evidence["byte_offset"] : f.evidence["byte_end"]] == line3


def test_exact_offsets_multibyte_split_eof() -> None:
    """Exact byte coordinates when terminal record has split multibyte bytes at EOF."""
    line1 = (
        b'{"schema_version": "sesslint.session/v1", "session_id": "s1", '
        b'"created_at": "2026-09-06T12:00:00Z"}\n'
    )
    # Truncated UTF-8 3-byte sequence prefix (\xe3\x81) without the 3rd byte
    line2 = b'{"text": "broken \xe3\x81'

    raw = line1 + line2
    l1_end = len(line1)
    l2_start = l1_end
    l2_end = l2_start + len(line2)

    # 1. io.py iter_events
    findings = _collect_stream_findings(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f.code == SL002
    assert f.source.line == 2
    assert f.evidence["byte_offset"] == l2_start
    assert f.evidence["byte_end"] == l2_end
    assert f.evidence["record_ordinal"] == 2
    assert raw[f.evidence["byte_offset"] : f.evidence["byte_end"]] == line2

    # 2. canonical load_canonical
    _, canon_findings = load_canonical(raw)
    assert len(canon_findings) == 1
    f_canon = canon_findings[0]
    assert f_canon.code == SL002
    assert f_canon.source.line == 2
    assert f_canon.evidence["byte_offset"] == l2_start
    assert f_canon.evidence["byte_end"] == l2_end
    assert f_canon.evidence["record_ordinal"] == 2
    assert raw[f_canon.evidence["byte_offset"] : f_canon.evidence["byte_end"]] == line2

    # 3. claude_code load_claude_code
    claude_l1 = b'{"type": "user", "message": {"content": "hello"}}\n'
    claude_l2 = b'{"type": "broken \xe3\x81'
    claude_raw = claude_l1 + claude_l2
    _, claude_findings = load_claude_code(claude_raw)
    assert len(claude_findings) == 1
    f_cl = claude_findings[0]
    assert f_cl.code == SL002
    assert f_cl.source.line == 2
    assert f_cl.evidence["byte_offset"] == len(claude_l1)
    assert f_cl.evidence["byte_end"] == len(claude_raw)
    assert f_cl.evidence["record_ordinal"] == 2
    assert claude_raw[f_cl.evidence["byte_offset"] : f_cl.evidence["byte_end"]] == claude_l2

    # 4. openai_agents load_openai_agents
    openai_l1 = b'{"type": "user", "content": "hello"}\n'
    openai_l2 = b'{"type": "broken \xe3\x81'
    openai_raw = openai_l1 + openai_l2
    _, openai_findings = load_openai_agents(openai_raw)
    assert len(openai_findings) == 1
    f_oa = openai_findings[0]
    assert f_oa.code == SL002
    assert f_oa.source.line == 2
    assert f_oa.evidence["byte_offset"] == len(openai_l1)
    assert f_oa.evidence["byte_end"] == len(openai_raw)
    assert f_oa.evidence["record_ordinal"] == 2
    assert openai_raw[f_oa.evidence["byte_offset"] : f_oa.evidence["byte_end"]] == openai_l2


def test_exact_offsets_crlf() -> None:
    """Exact byte coordinates with Windows CRLF (\\r\\n) line terminators."""
    line1 = (
        b'{"schema_version": "sesslint.session/v1", "session_id": "s1", '
        b'"created_at": "2026-09-06T12:00:00Z"}\r\n'
    )
    line2 = b'{"malformed": "record" broken\r\n'
    line3 = (
        b'{"actor": "user", "id": "e1", "kind": "message", "parent_id": null, '
        b'"payload": {}, "seq": 1, "ts": "2026-09-06T12:00:01Z"}\r\n'
    )

    raw = line1 + line2 + line3
    l1_end = len(line1)
    l2_start = l1_end
    l2_end = l2_start + len(line2)

    findings = _collect_stream_findings(raw)
    assert len(findings) == 1

    f = findings[0]
    assert f.code == SL001
    assert f.source.line == 2
    assert f.evidence["byte_offset"] == l2_start
    assert f.evidence["byte_end"] == l2_end
    assert f.evidence["record_ordinal"] == 2
    # Ensure slice includes \r\n
    assert raw[f.evidence["byte_offset"] : f.evidence["byte_end"]] == line2
    assert raw[f.evidence["byte_offset"] : f.evidence["byte_end"]].endswith(b"\r\n")


def test_exact_offsets_bom() -> None:
    """Exact byte coordinates with UTF-8 BOM prefix in physical stream domain."""
    bom = b"\xef\xbb\xbf"
    line1_content = (
        b'{"schema_version": "sesslint.session/v1", "session_id": "s1", '
        b'"created_at": "2026-09-06T12:00:00Z"}\n'
    )
    line1 = bom + line1_content
    line2 = b'{"corrupted": "syntax" broken\n'
    line3 = (
        b'{"actor": "user", "id": "e1", "kind": "message", "parent_id": null, '
        b'"payload": {}, "seq": 1, "ts": "2026-09-06T12:00:01Z"}\n'
    )

    raw = line1 + line2 + line3
    l1_end = len(line1)  # Includes 3 BOM bytes
    l2_start = l1_end
    l2_end = l2_start + len(line2)

    # 1. io.py iter_events
    findings = _collect_stream_findings(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f.code == SL001
    assert f.source.line == 2
    assert f.evidence["byte_offset"] == l2_start
    assert f.evidence["byte_end"] == l2_end
    assert f.evidence["record_ordinal"] == 2
    assert raw[f.evidence["byte_offset"] : f.evidence["byte_end"]] == line2

    # Also verify if line 1 itself with BOM is corrupted, offset starts at byte 0
    corrupt_line1 = bom + b'{"schema_version": "sesslint.session/v1" broken\n'
    corrupt_raw = corrupt_line1 + line3
    corrupt_findings = _collect_stream_findings(corrupt_raw)
    assert len(corrupt_findings) == 1
    f_l1 = corrupt_findings[0]
    assert f_l1.source.line == 1
    assert f_l1.evidence["byte_offset"] == 0
    assert f_l1.evidence["byte_end"] == len(corrupt_line1)
    assert corrupt_raw[f_l1.evidence["byte_offset"] : f_l1.evidence["byte_end"]].startswith(bom)

    # 2. canonical load_canonical
    _, canon_findings = load_canonical(raw)
    assert len(canon_findings) == 1
    f_c = canon_findings[0]
    assert f_c.code == SL001
    assert f_c.source.line == 2
    assert f_c.evidence["byte_offset"] == l2_start
    assert f_c.evidence["byte_end"] == l2_end
    assert f_c.evidence["record_ordinal"] == 2
    assert raw[f_c.evidence["byte_offset"] : f_c.evidence["byte_end"]] == line2

    # 3. claude_code load_claude_code
    claude_l1 = bom + b'{"type": "user", "message": {"content": "hello"}}\n'
    claude_l2 = b'{"type": "broken_claude" broken\n'
    claude_l3 = b'{"type": "assistant", "message": {"content": "world"}}\n'
    raw_cl = claude_l1 + claude_l2 + claude_l3
    _, cl_findings = load_claude_code(raw_cl)
    assert len(cl_findings) == 1
    f_cl = cl_findings[0]
    assert f_cl.code == SL001
    assert f_cl.source.line == 2
    assert f_cl.evidence["byte_offset"] == len(claude_l1)
    assert f_cl.evidence["byte_end"] == len(claude_l1) + len(claude_l2)
    assert f_cl.evidence["record_ordinal"] == 2
    assert raw_cl[f_cl.evidence["byte_offset"] : f_cl.evidence["byte_end"]] == claude_l2

    # 4. openai_agents load_openai_agents
    oa_l1 = bom + b'{"type": "user", "content": "hello"}\n'
    oa_l2 = b'{"type": "broken_oa" broken\n'
    oa_l3 = b'{"type": "assistant", "content": "world"}\n'
    raw_oa = oa_l1 + oa_l2 + oa_l3
    _, oa_findings = load_openai_agents(raw_oa)
    assert len(oa_findings) == 1
    f_oa = oa_findings[0]
    assert f_oa.code == SL001
    assert f_oa.source.line == 2
    assert f_oa.evidence["byte_offset"] == len(oa_l1)
    assert f_oa.evidence["byte_end"] == len(oa_l1) + len(oa_l2)
    assert f_oa.evidence["record_ordinal"] == 2
    assert raw_oa[f_oa.evidence["byte_offset"] : f_oa.evidence["byte_end"]] == oa_l2


def test_exact_offsets_terminal_tear() -> None:
    """Exact byte coordinates for a terminal record torn mid-token without newline."""
    line1 = (
        b'{"schema_version": "sesslint.session/v1", "session_id": "s1", '
        b'"created_at": "2026-09-06T12:00:00Z"}\n'
    )
    line2 = b'{"actor": "user", "id": "e1", "kind": "mess'

    raw = line1 + line2
    l1_end = len(line1)
    l2_start = l1_end
    l2_end = len(raw)

    findings = _collect_stream_findings(raw)
    assert len(findings) == 1

    f = findings[0]
    assert f.code == SL002
    assert f.source.line == 2
    assert f.evidence["byte_offset"] == l2_start
    assert f.evidence["byte_end"] == l2_end
    assert f.evidence["record_ordinal"] == 2
    assert raw[f.evidence["byte_offset"] : f.evidence["byte_end"]] == line2


def test_overlong_line_truncation_offset() -> None:
    """Exact byte coordinates when a line exceeds max_line_bytes."""
    limits = ReaderLimits(max_line_bytes=110)

    # 1. io.py iter_events
    line1 = (
        b'{"schema_version": "sesslint.session/v1", "session_id": "s1", '
        b'"created_at": "2026-09-06T12:00:00Z"}\n'
    )
    line2 = (
        b'{"actor": "user", "id": "e1", "kind": "message", "parent_id": null, '
        b'"payload": {"padding": "1234567890123456789012345678901234567890"}}\n'
    )
    line3 = (
        b'{"actor": "assistant", "id": "e2", "kind": "message", "parent_id": "e1", '
        b'"payload": {}, "seq": 2, "ts": "2026-09-06T12:00:02Z"}\n'
    )

    raw = line1 + line2 + line3
    l1_end = len(line1)
    l2_start = l1_end
    # The reader reads up to max_line_bytes + 1 before truncating and draining
    l2_truncation_point = l2_start + limits.max_line_bytes + 1

    findings = _collect_stream_findings(raw, limits=limits)
    assert len(findings) >= 1

    # First finding must be line 2 overlong limit
    f = findings[0]
    assert f.source.line == 2
    assert f.evidence["byte_offset"] == l2_start
    assert f.evidence["byte_end"] == l2_truncation_point
    assert f.evidence["record_ordinal"] == 2
    assert (
        raw[f.evidence["byte_offset"] : f.evidence["byte_end"]] == raw[l2_start:l2_truncation_point]
    )

    # 2. claude_code load_claude_code
    cl_l1 = b'{"type": "user", "message": {"content": "hello"}}\n'
    cl_l2 = b'{"type": "assistant", "padding": "' + b"x" * 150 + b'"}\n'
    cl_l3 = b'{"type": "user", "message": {"content": "world"}}\n'
    raw_cl = cl_l1 + cl_l2 + cl_l3
    cl_l2_start = len(cl_l1)
    cl_trunc_point = cl_l2_start + limits.max_line_bytes + 1

    _, cl_findings = load_claude_code(raw_cl, limits=limits)
    assert len(cl_findings) >= 1
    f_cl = cl_findings[0]
    assert f_cl.source.line == 2
    assert f_cl.evidence["byte_offset"] == cl_l2_start
    assert f_cl.evidence["byte_end"] == cl_trunc_point
    assert f_cl.evidence["record_ordinal"] == 2
    assert (
        raw_cl[f_cl.evidence["byte_offset"] : f_cl.evidence["byte_end"]]
        == raw_cl[cl_l2_start:cl_trunc_point]
    )

    # 3. openai_agents load_openai_agents
    oa_l1 = b'{"type": "user", "content": "hello"}\n'
    oa_l2 = b'{"type": "assistant", "padding": "' + b"x" * 150 + b'"}\n'
    oa_l3 = b'{"type": "user", "content": "world"}\n'
    raw_oa = oa_l1 + oa_l2 + oa_l3
    oa_l2_start = len(oa_l1)
    oa_trunc_point = oa_l2_start + limits.max_line_bytes + 1

    _, oa_findings = load_openai_agents(raw_oa, limits=limits)
    assert len(oa_findings) >= 1
    f_oa = oa_findings[0]
    assert f_oa.source.line == 2
    assert f_oa.evidence["byte_offset"] == oa_l2_start
    assert f_oa.evidence["byte_end"] == oa_trunc_point
    assert f_oa.evidence["record_ordinal"] == 2
    assert (
        raw_oa[f_oa.evidence["byte_offset"] : f_oa.evidence["byte_end"]]
        == raw_oa[oa_l2_start:oa_trunc_point]
    )


# =============================================================================
# 2. Ordinal Continuity Across Lookahead
# =============================================================================


def test_ordinal_continuity_with_blank_lines() -> None:
    """Record ordinals increment strictly per non-empty record across blank lines and lookahead."""
    line1 = (
        b'{"schema_version": "sesslint.session/v1", "session_id": "s1", '
        b'"created_at": "2026-09-06T12:00:00Z"}\n'
    )
    blank1 = b"\n"
    blank2 = b"   \r\n"
    line4 = (
        b'{"actor": "user", "id": "e1", "kind": "message", "parent_id": null, '
        b'"payload": {}, "seq": 1, "ts": "2026-09-06T12:00:01Z"}\n'
    )
    blank3 = b"\t\n"
    line6 = b'{"malformed": "json" broken\n'
    line7 = (
        b'{"actor": "assistant", "id": "e2", "kind": "message", "parent_id": "e1", '
        b'"payload": {}, "seq": 2, "ts": "2026-09-06T12:00:02Z"}\n'
    )

    raw = line1 + blank1 + blank2 + line4 + blank3 + line6 + line7
    # Non-empty records:
    # record_ordinal 1: line 1 (header)
    # record_ordinal 2: line 4 (line_number 4)
    # record_ordinal 3: line 6 (line_number 6) -> malformed
    # record_ordinal 4: line 7 (line_number 7)

    l6_start = len(line1 + blank1 + blank2 + line4 + blank3)
    l6_end = l6_start + len(line6)

    findings = _collect_stream_findings(raw)
    assert len(findings) == 1

    f = findings[0]
    assert f.code == SL001
    assert f.source.line == 6
    assert f.evidence["record_ordinal"] == 3
    assert f.evidence["byte_offset"] == l6_start
    assert f.evidence["byte_end"] == l6_end
    assert raw[f.evidence["byte_offset"] : f.evidence["byte_end"]] == line6


# =============================================================================
# 3. Contract Test Across All Four Stream Readers
# =============================================================================


def test_all_four_stream_readers_contract() -> None:
    """Verify all four streaming readers emit valid coordinates and satisfy slice round-trip."""
    # 1. sesslint.io :: iter_events
    raw_io = (
        b'{"schema_version": "sesslint.session/v1", "session_id": "s1", '
        b'"created_at": "2026-09-06T12:00:00Z"}\n'
        b'{"invalid": 1 broken\n'
        b'{"actor": "user", "id": "e1", "kind": "message", "parent_id": null, '
        b'"payload": {}, "seq": 1, "ts": "2026-09-06T12:00:01Z"}\n'
        b'{"torn": "end"'
    )
    io_findings = [f for f in iter_events(io.BytesIO(raw_io)) if isinstance(f, Finding)]
    assert len(io_findings) == 2
    for f in io_findings:
        assert f.evidence["byte_offset"] >= 0
        assert f.evidence["byte_end"] >= f.evidence["byte_offset"]
        assert f.evidence["record_ordinal"] >= 1
        sliced = raw_io[f.evidence["byte_offset"] : f.evidence["byte_end"]]
        assert len(sliced) == f.evidence["byte_end"] - f.evidence["byte_offset"]

    # 2. adapters.canonical :: load_canonical (JSONL)
    raw_canon = (
        b'{"schema_version": "sesslint.session/v1", "session_id": "s1", '
        b'"created_at": "2026-09-06T12:00:00Z"}\n'
        b'{"id": "e1", "actor": "user", "kind": "message", "parent_id": null, '
        b'"payload": {}, "seq": 1, "ts": "2026-09-06T12:00:01Z"}\n'
        b'{"invalid_canon": broken\n'
        b'{"torn_canon": true'
    )
    _, canon_findings = load_canonical(raw_canon)
    assert len(canon_findings) == 2
    for f in canon_findings:
        assert f.evidence["byte_offset"] >= 0
        assert f.evidence["byte_end"] >= f.evidence["byte_offset"]
        assert f.evidence["record_ordinal"] >= 1
        sliced = raw_canon[f.evidence["byte_offset"] : f.evidence["byte_end"]]
        assert len(sliced) == f.evidence["byte_end"] - f.evidence["byte_offset"]

    # 3. adapters.claude_code :: load_claude_code
    raw_claude = (
        b'{"type": "user", "message": {"content": "hello"}}\n'
        b'{"type": "bad_claude" broken\n'
        b'{"type": "assistant", "message": {"content": "world"}}\n'
        b'{"torn_claude": true'
    )
    _, claude_findings = load_claude_code(raw_claude)
    assert len(claude_findings) == 2
    for f in claude_findings:
        assert f.evidence["byte_offset"] >= 0
        assert f.evidence["byte_end"] >= f.evidence["byte_offset"]
        assert f.evidence["record_ordinal"] >= 1
        sliced = raw_claude[f.evidence["byte_offset"] : f.evidence["byte_end"]]
        assert len(sliced) == f.evidence["byte_end"] - f.evidence["byte_offset"]

    # 4. adapters.openai_agents :: load_openai_agents (JSONL path)
    raw_openai = (
        b'{"type": "user", "content": "hi"}\n'
        b'{"type": "bad_openai" broken\n'
        b'{"type": "assistant", "content": "there"}\n'
        b'{"torn_openai": true'
    )
    _, openai_findings = load_openai_agents(raw_openai)
    assert len(openai_findings) == 2
    for f in openai_findings:
        assert f.evidence["byte_offset"] >= 0
        assert f.evidence["byte_end"] >= f.evidence["byte_offset"]
        assert f.evidence["record_ordinal"] >= 1
        sliced = raw_openai[f.evidence["byte_offset"] : f.evidence["byte_end"]]
        assert len(sliced) == f.evidence["byte_end"] - f.evidence["byte_offset"]


# =============================================================================
# 4. Property Test: Slice-Round-Trip on Generated Streams Across All Readers
# =============================================================================


@pytest.mark.parametrize(
    "reader_name,delim,use_bom",
    [
        (r, d, b)
        for r in ["io", "canonical", "claude_code", "openai_agents"]
        for d in [b"\n", b"\r\n"]
        for b in [False, True]
    ],
)
def test_slice_round_trip_property(reader_name: str, delim: bytes, use_bom: bool) -> None:
    """Verify that source_bytes[byte_offset:byte_end] exactly matches the raw line bytes."""
    bom = b"\xef\xbb\xbf" if use_bom else b""
    if reader_name in ("io", "canonical"):
        header = (
            b'{"schema_version": "sesslint.session/v1", "session_id": "test_prop", '
            b'"created_at": "2026-09-06T12:00:00Z"}'
        )
        l2 = (
            b'{"actor": "user", "id": "e1", "kind": "message", "parent_id": null, '
            b'"payload": {"msg": "\xc3\xa9l\xc3\xa8ve"}, "seq": 1, "ts": "2026-09-06T12:00:01Z"}'
        )
        l5 = (
            b'{"actor": "assistant", "id": "e2", "kind": "message", "parent_id": "e1", '
            b'"payload": {"msg": "\xe4\xb8\x96\xe7\x95\x8c"}, '
            b'"seq": 2, "ts": "2026-09-06T12:00:02Z"}'
        )
    elif reader_name == "claude_code":
        header = b'{"type": "user", "message": {"content": "\xc3\xa9l\xc3\xa8ve"}}'
        l2 = b'{"type": "assistant", "message": {"content": "ok"}}'
        l5 = b'{"type": "assistant", "message": {"content": "\xe4\xb8\x96\xe7\x95\x8c"}}'
    else:  # openai_agents
        header = b'{"type": "user", "content": "\xc3\xa9l\xc3\xa8ve"}'
        l2 = b'{"type": "assistant", "content": "ok"}'
        l5 = b'{"type": "assistant", "content": "\xe4\xb8\x96\xe7\x95\x8c"}'

    lines: list[bytes] = [bom + header]
    lines.append(l2)
    lines.append(b"")  # blank line
    lines.append(b'{"corrupt_1": [1, 2, 3')  # missing bracket -> corrupt
    lines.append(l5)
    lines.append(b"   ")  # whitespace line
    lines.append(b'{"corrupt_2": "incomplete"')  # torn terminal line

    raw = delim.join(lines)

    findings: list[Finding] = []
    if reader_name == "io":
        findings = [f for f in iter_events(io.BytesIO(raw)) if isinstance(f, Finding)]
    elif reader_name == "canonical":
        _, findings = load_canonical(raw)
    elif reader_name == "claude_code":
        _, findings = load_claude_code(raw)
    elif reader_name == "openai_agents":
        _, findings = load_openai_agents(raw)

    assert len(findings) == 2  # corrupt_1 (SL001) and corrupt_2 (SL002)

    for f in findings:
        b_offset = f.evidence["byte_offset"]
        b_end = f.evidence["byte_end"]
        assert b_offset >= 0
        assert b_end > b_offset
        sliced = raw[b_offset:b_end]

        # Sliced content must start with the corrupted line prefix
        if f.code == SL001:
            assert sliced.startswith(b'{"corrupt_1"')
            assert sliced.endswith(delim)
        elif f.code == SL002:
            assert sliced.startswith(b'{"corrupt_2"')


# =============================================================================
# 5. Renderer Golden Assertions: JSON and Human
# =============================================================================


def test_span_byte_renders_in_json_and_human() -> None:
    """Verify span.byte in JSON output and (bytes a-b) in human output."""
    raw = (
        b'{"schema_version": "sesslint.session/v1", "session_id": "s1", '
        b'"created_at": "2026-09-06T12:00:00Z"}\n'
        b'{"actor": "user", "id": "e1", "kind": "message", "parent_id": null, '
        b'"payload": {}, "seq": 1, "ts": "2026-09-06T12:00:01Z"}\n'
        b'{"malformed_syntax": 123 broken\n'
    )
    findings = _collect_stream_findings(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["byte_offset"] > 0
    assert f.evidence["byte_end"] > f.evidence["byte_offset"]

    # 1. format_finding_content_free
    formatted = format_finding_content_free(f)
    assert formatted["span"]["line"] == 3
    assert formatted["span"]["byte"] == f.evidence["byte_offset"]

    # 2. render_json
    report = build_report(
        session_id="s1",
        source_fingerprint="a" * 64,
        tool_version="0.1.0",
        findings=[f],
        assurance="A0",
        limitation="Hostile input",
    )
    rendered_json_str = render_json(report)
    parsed = json.loads(rendered_json_str)
    assert parsed["findings"][0]["span"]["byte"] == f.evidence["byte_offset"]
    assert parsed["findings"][0]["span"]["line"] == 3

    # 3. render_human
    rendered_human_str = render_human(report)
    expected_bytes_str = f"(bytes {f.evidence['byte_offset']}-{f.evidence['byte_end']})"
    assert expected_bytes_str in rendered_human_str
    assert f"Span:        <stream>:3 {expected_bytes_str}" in rendered_human_str
