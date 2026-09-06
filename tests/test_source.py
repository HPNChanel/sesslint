"""Unit tests for source file fingerprinting, guarding, and concurrent-mutation verification."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from sesslint.canonical import SessionEvent
from sesslint.errors import SourceChangedError
from sesslint.io import ReaderLimits
from sesslint.source import (
    SourceGuard,
    fingerprint_file,
    guard,
    guarded,
    guarded_iter_events,
    verify,
)


def test_fingerprint_file_stability() -> None:
    """Repeated calls to fingerprint_file return identical SHA-256 digests."""
    fixture_path = Path("fixtures/sessions/stable-small.jsonl")
    h1 = fingerprint_file(fixture_path)
    h2 = fingerprint_file(fixture_path)
    assert h1 == h2
    assert len(h1) == 64
    assert all(c in "0123456789abcdef" for c in h1)


def test_fingerprint_file_matches_sidecar() -> None:
    """fingerprint_file matches the committed .sha256 sidecar digest."""
    fixture_path = Path("fixtures/sessions/stable-small.jsonl")
    sidecar_path = Path("fixtures/sessions/stable-small.jsonl.sha256")
    expected_hash = sidecar_path.read_text(encoding="utf-8").split()[0].strip().lower()

    computed_hash = fingerprint_file(fixture_path)
    assert computed_hash == expected_hash


def test_fingerprint_file_empty_file(tmp_path: Path) -> None:
    """Fingerprinting a 0-byte file returns standard SHA-256 empty digest."""
    empty_file = tmp_path / "empty.jsonl"
    empty_file.write_bytes(b"")
    digest = fingerprint_file(empty_file)
    assert digest == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_fingerprint_file_invalid_chunk_size(tmp_path: Path) -> None:
    """Non-positive chunk_size raises ValueError."""
    f = tmp_path / "file.txt"
    f.write_text("content", encoding="utf-8")
    with pytest.raises(ValueError, match="chunk_size must be positive"):
        fingerprint_file(f, chunk_size=0)
    with pytest.raises(ValueError, match="chunk_size must be positive"):
        fingerprint_file(f, chunk_size=-100)


def test_fingerprint_file_directory_raises(tmp_path: Path) -> None:
    """Passing a directory to fingerprint_file raises IsADirectoryError."""
    with pytest.raises(IsADirectoryError, match="Expected file, got directory"):
        fingerprint_file(tmp_path)


def test_fingerprint_file_missing_file_raises(tmp_path: Path) -> None:
    """Passing a nonexistent file path raises FileNotFoundError."""
    missing = tmp_path / "missing.jsonl"
    with pytest.raises(FileNotFoundError):
        fingerprint_file(missing)


def test_fingerprint_file_chunked_streaming(tmp_path: Path) -> None:
    """Verify chunked reading accurately digests large multi-chunk data."""
    large_file = tmp_path / "large.bin"
    payload = b"A" * 150_000 + b"B" * 50_000
    large_file.write_bytes(payload)

    expected = hashlib.sha256(payload).hexdigest()
    assert fingerprint_file(large_file, chunk_size=4096) == expected


def test_guard_and_verify_clean(tmp_path: Path) -> None:
    """guard creates a valid snapshot that passes verify when unmodified."""
    sample = tmp_path / "test.jsonl"
    sample.write_text('{"schema_version": "sesslint.session/v1"}\n', encoding="utf-8")

    g = guard(sample)
    assert isinstance(g, SourceGuard)
    assert g.path == sample.resolve()
    assert len(g.sha256) == 64
    assert g.size > 0
    assert g.mtime_ns > 0

    # Verification must succeed cleanly without raising
    verify(g)


def test_guard_directory_raises(tmp_path: Path) -> None:
    """guard raises IsADirectoryError on directory path."""
    with pytest.raises(IsADirectoryError):
        guard(tmp_path)


def test_verify_raises_on_content_append(tmp_path: Path) -> None:
    """verify detects append modification and raises SourceChangedError."""
    sample = tmp_path / "test.jsonl"
    sample.write_text("initial content\n", encoding="utf-8")

    g = guard(sample)
    # Mutate file by appending
    sample.write_text("initial content\nappended line\n", encoding="utf-8")

    with pytest.raises(SourceChangedError, match="Source file metadata changed concurrently"):
        verify(g)


def test_verify_raises_on_same_size_content_change(tmp_path: Path) -> None:
    """verify detects same-size byte changes and raises SourceChangedError."""
    sample = tmp_path / "test.jsonl"
    sample.write_bytes(b"ABCDEFGHIJ")

    g = guard(sample)
    # Overwrite with same byte length
    sample.write_bytes(b"KLMNOPQRST")

    with pytest.raises(SourceChangedError):
        verify(g)


def test_verify_raises_on_file_deletion(tmp_path: Path) -> None:
    """verify raises SourceChangedError when the guarded file is removed."""
    sample = tmp_path / "test.jsonl"
    sample.write_text("temp", encoding="utf-8")

    g = guard(sample)
    sample.unlink()

    with pytest.raises(SourceChangedError, match="Source file inaccessible or removed"):
        verify(g)


def test_guarded_contextmanager_success(tmp_path: Path) -> None:
    """guarded context manager executes and verifies successfully when untouched."""
    sample = tmp_path / "test.jsonl"
    sample.write_text("unmodified line\n", encoding="utf-8")

    with guarded(sample) as g:
        assert g.size == sample.stat().st_size


def test_guarded_contextmanager_mutation_raises(tmp_path: Path) -> None:
    """guarded context manager raises SourceChangedError upon exit if mutated."""
    sample = tmp_path / "test.jsonl"
    sample.write_text("original\n", encoding="utf-8")

    with pytest.raises(SourceChangedError):
        with guarded(sample):
            sample.write_text("modified\n", encoding="utf-8")


def test_guarded_iter_events_success() -> None:
    """guarded_iter_events yields events from fixture and verifies immutability."""
    fixture_path = Path("fixtures/sessions/stable-small.jsonl")
    items = list(guarded_iter_events(fixture_path))
    # 4 event records (header line is consumed internally)
    assert len(items) == 4
    assert all(isinstance(it, SessionEvent) for it in items)


def test_guarded_iter_events_mutation_aborts(tmp_path: Path) -> None:
    """guarded_iter_events raises SourceChangedError on stream exhaustion if mutated."""
    source_fixture = Path("fixtures/sessions/stable-small.jsonl").read_bytes()
    test_file = tmp_path / "session_concurrent.jsonl"
    test_file.write_bytes(source_fixture)

    stream = guarded_iter_events(test_file, limits=ReaderLimits())
    first_item = next(stream)
    assert isinstance(first_item, SessionEvent)

    # Mutate the file while iteration is active
    test_file.write_bytes(source_fixture + b'{"extra":"bad"}\n')

    # Consuming the remaining stream must detect the concurrent mutation and abort
    with pytest.raises(SourceChangedError):
        list(stream)
