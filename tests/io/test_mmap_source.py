"""Byte-source equivalence tests for the mmap reader (perf-scale T-03).

``_open_byte_source`` must be behavior-neutral: identical bounded
``readline(limit)`` semantics on mapped and buffered paths, identical
``iter_events`` output on every hostile fixture, and silent fallback
wherever mapping is unavailable. mmap only engages for large files with
large lines (copy-bound workloads); everything else stays buffered.
"""

from __future__ import annotations

import mmap
from pathlib import Path

import pytest

import sesslint.io as io_mod
from sesslint.io import _MMapLineSource, _open_byte_source, iter_events

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"
HOSTILE = sorted(FIXTURES_DIR.glob("hostile/*.jsonl"))
MIXED = sorted((FIXTURES_DIR / "scan" / "mixed").glob("*"))

_BIG_LINE = b'{"k":"' + b"x" * 100_000 + b'"}\n'  # ~100 KiB line
_SMALL_LINE = b'{"a":1}\n'


def _write_lines(path: Path, lines: list[bytes]) -> Path:
    path.write_bytes(b"".join(lines))
    return path


def _big_line_file(path: Path, lines: int = 50) -> Path:
    """~5 MiB of ~100 KiB lines — above both mmap gates."""
    return _write_lines(path, [_BIG_LINE] * lines)


# ---------------------------------------------------------------------------
# Source selection
# ---------------------------------------------------------------------------


def test_small_file_uses_buffered(tmp_path: Path) -> None:
    p = _write_lines(tmp_path / "small.jsonl", [_SMALL_LINE])
    src = _open_byte_source(p)
    try:
        assert not isinstance(src, _MMapLineSource)
        assert src.readline(100) == _SMALL_LINE
    finally:
        src.close()


def test_big_file_small_lines_uses_buffered(tmp_path: Path) -> None:
    """Large file with small lines stays buffered — per-line dispatch wins."""
    line = b'{"k":"' + b"x" * 4096 + b'"}\n'
    p = _write_lines(tmp_path / "big.jsonl", [line] * 1100)  # ~4.5 MiB, ~4 KiB lines
    src = _open_byte_source(p)
    try:
        assert not isinstance(src, _MMapLineSource)
        assert src.readline(100) == line[:100]
    finally:
        src.close()


def test_big_file_big_lines_uses_mmap(tmp_path: Path) -> None:
    p = _big_line_file(tmp_path / "big.jsonl")
    src = _open_byte_source(p)
    try:
        assert isinstance(src, _MMapLineSource)
        assert src.readline(100) == _BIG_LINE[:100]
    finally:
        src.close()
    # Windows: mapping must be closed before unlink succeeds.
    p.unlink()


def test_single_huge_line_uses_mmap(tmp_path: Path) -> None:
    """No newline in the head sample -> one huge line -> mmap."""
    p = _write_lines(tmp_path / "huge.jsonl", [_BIG_LINE * 50])
    src = _open_byte_source(p)
    try:
        assert isinstance(src, _MMapLineSource)
    finally:
        src.close()


def test_mmap_failure_falls_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = _big_line_file(tmp_path / "big.jsonl")

    def _boom(*args: object, **kwargs: object) -> mmap.mmap:
        raise OSError("mmap unavailable")

    monkeypatch.setattr(io_mod.mmap, "mmap", _boom)
    src = _open_byte_source(p)
    try:
        assert not isinstance(src, _MMapLineSource)
        # Buffered fallback still reads from the start.
        assert src.readline(100) == _BIG_LINE[:100]
    finally:
        src.close()


# ---------------------------------------------------------------------------
# readline() equivalence vs BufferedReader
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cap", [1, 7, 64, 4096, -1])
def test_readline_equivalence_capped(tmp_path: Path, cap: int) -> None:
    p = _big_line_file(tmp_path / "big.jsonl")
    src = _open_byte_source(p)
    buf = open(p, "rb")
    try:
        assert isinstance(src, _MMapLineSource)
        while True:
            a, b = src.readline(cap), buf.readline(cap)
            assert a == b
            if not a:
                break
    finally:
        src.close()
        buf.close()


def test_readline_no_trailing_newline(tmp_path: Path) -> None:
    p = _write_lines(tmp_path / "big.jsonl", [_BIG_LINE] * 50 + [b"tail-no-newline"])
    src = _open_byte_source(p)
    buf = open(p, "rb")
    try:
        while True:
            a, b = src.readline(8192), buf.readline(8192)
            assert a == b
            if not a:
                break
        assert a == b""
    finally:
        src.close()
        buf.close()


def test_readline_position_after_cap_split(tmp_path: Path) -> None:
    p = _big_line_file(tmp_path / "big.jsonl")
    src = _open_byte_source(p)
    buf = open(p, "rb")
    try:
        # A cap smaller than the line splits it across consecutive calls.
        a = b"".join(src.readline(100) for _ in range(11))
        b = b"".join(buf.readline(100) for _ in range(11))
        assert a == b
        assert src.readline() == buf.readline()
    finally:
        src.close()
        buf.close()


# ---------------------------------------------------------------------------
# iter_events equivalence — parametrized force-mmap / force-buffered
# ---------------------------------------------------------------------------


def _events_signature(path: Path) -> list[tuple[str, str]]:
    """Compact comparable signature of the yielded event/finding stream.

    Raised exceptions are part of the signature — both byte sources must
    surface the same failure at the same point.
    """
    sig: list[tuple[str, str]] = []
    try:
        for item in iter_events(path):
            kind = type(item).__name__
            code = getattr(item, "code", None) or getattr(item, "kind", "")
            sig.append((kind, str(code)))
    except Exception as err:
        sig.append(("raise", type(err).__name__))
    return sig


def _force_mapped(monkeypatch: pytest.MonkeyPatch) -> None:
    """Lower both gates so any non-empty file takes the mmap path."""
    monkeypatch.setattr(io_mod, "_MMAP_MIN_BYTES", 0)
    monkeypatch.setattr(io_mod, "_MMAP_MIN_LINE_BYTES", 0)


def _force_buffered(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(io_mod, "_MMAP_MIN_BYTES", 10**12)


@pytest.mark.parametrize("fixture", HOSTILE + MIXED, ids=lambda p: p.name)
def test_iter_events_identical_mmap_vs_buffered(
    fixture: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every fixture produces the same yielded stream under both byte sources."""
    _force_buffered(monkeypatch)
    buffered = _events_signature(fixture)
    _force_mapped(monkeypatch)
    mapped = _events_signature(fixture)
    assert mapped == buffered


@pytest.mark.parametrize("fixture", HOSTILE, ids=lambda p: p.name)
def test_iter_events_small_file_mapped_path(fixture: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Gates at zero force even small files through the mmap source."""
    buffered = _events_signature(fixture)
    _force_mapped(monkeypatch)
    assert _events_signature(fixture) == buffered
