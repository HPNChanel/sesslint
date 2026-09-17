"""Bounded binary/UTF-8 probe tests for _scan_single_file (DW-T-11).

The scan probe must stream files in bounded chunks while preserving the
original whole-file semantics: a NUL byte or invalid UTF-8 sequence anywhere —
head, tail, or straddling a chunk boundary — classifies the file unreadable.
"""

from __future__ import annotations

import tracemalloc
from pathlib import Path

from sesslint.scan import _PROBE_CHUNK_BYTES, scan_path


def _scan_verdict(path: Path) -> tuple[str, list[dict]]:
    report = scan_path(path)
    res = report.files[0]
    return res.verdict, [f.to_dict() for f in res.findings]


def test_nul_in_tail_classified_unreadable(tmp_path: Path) -> None:
    """NUL byte beyond the first probe chunk still marks the file unreadable."""
    f = tmp_path / "tail_nul.jsonl"
    f.write_bytes(b"x" * (_PROBE_CHUNK_BYTES + 100) + b"\x00")
    verdict, findings = _scan_verdict(f)
    assert verdict == "unreadable"
    assert not any("encoding_error" in str(f_.get("evidence", {})) for f_ in findings)


def test_nul_at_chunk_boundary(tmp_path: Path) -> None:
    f = tmp_path / "boundary_nul.jsonl"
    f.write_bytes(b"x" * (_PROBE_CHUNK_BYTES - 1) + b"\x00" + b"y" * 100)
    verdict, _ = _scan_verdict(f)
    assert verdict == "unreadable"


def test_invalid_utf8_in_tail(tmp_path: Path) -> None:
    f = tmp_path / "tail_utf8.jsonl"
    f.write_bytes(b"x" * (_PROBE_CHUNK_BYTES + 50) + b"\xff\xfe")
    verdict, findings = _scan_verdict(f)
    assert verdict == "unreadable"
    assert any(f_.get("evidence", {}).get("detail") == "invalid_utf8" for f_ in findings)


def test_multibyte_char_split_across_chunks_is_valid(tmp_path: Path) -> None:
    """A 3-byte UTF-8 char straddling the chunk boundary must not be flagged."""
    f = tmp_path / "split_char.jsonl"
    euro = "€".encode()  # E2 82 AC
    assert len(euro) == 3
    head = b"x" * (_PROBE_CHUNK_BYTES - 2) + euro[:2]  # E2 82 at end of chunk 1
    f.write_bytes(head + euro[2:] + b"y" * 64)
    verdict, findings = _scan_verdict(f)
    assert not any(f_.get("evidence", {}).get("detail") == "invalid_utf8" for f_ in findings)
    assert verdict != "unreadable" or not any(
        "encoding" in f_.get("message", "") for f_ in findings
    )


def test_truncated_multibyte_at_eof_is_unreadable(tmp_path: Path) -> None:
    f = tmp_path / "truncated.jsonl"
    f.write_bytes(b"x" * (_PROBE_CHUNK_BYTES + 10) + b"\xe2\x82")
    verdict, findings = _scan_verdict(f)
    assert verdict == "unreadable"
    assert any(f_.get("evidence", {}).get("detail") == "invalid_utf8" for f_ in findings)


def test_probe_memory_is_bounded(tmp_path: Path) -> None:
    """Peak allocation during the probe stays O(chunk), not O(file size)."""
    f = tmp_path / "big.jsonl"
    file_size = 16 * 1024 * 1024  # 16 MiB >> 1 MiB chunk
    f.write_bytes(b"x" * file_size)
    tracemalloc.start()
    try:
        scan_path(f)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    # Allow generous headroom for report objects; must stay far below file size.
    assert peak < file_size // 2


def test_clean_utf8_file_not_flagged(tmp_path: Path) -> None:
    """A >chunk-size valid UTF-8 file passes the probe untouched."""
    f = tmp_path / "clean.jsonl"
    f.write_bytes(b"x" * (2 * _PROBE_CHUNK_BYTES + 7))
    _verdict, findings = _scan_verdict(f)
    assert not any(f_.get("evidence", {}).get("detail") == "invalid_utf8" for f_ in findings)
