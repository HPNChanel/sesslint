"""Hypothesis fuzz tests for JSONL streaming reader (TASK-027, FR-011..017, AC-003..006).

Guarantees:
- Total function: iter_events and read_header handle ANY stream without uncaught exceptions.
- Fail-closed: hostile/corrupt inputs yield typed Findings or raise typed SesslintError.
- Deterministic: identical inputs produce identical outputs across repeated runs.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from sesslint.canonical import SessionEvent, SessionHeader
from sesslint.errors import SesslintError
from sesslint.finding import Finding
from sesslint.io import ReaderLimits, iter_events, read_header

CORPUS_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "fuzz" / "corpus"


def test_seed_corpus_playback() -> None:
    """Verify all seed corpus files parse without uncaught exceptions."""
    seed_files = list(CORPUS_DIR.glob("*.jsonl"))
    assert len(seed_files) >= 3, (
        f"Expected at least 3 seeds in {CORPUS_DIR}, found {len(seed_files)}"
    )

    for seed_file in seed_files:
        items = list(iter_events(seed_file))
        assert all(isinstance(x, (SessionEvent, Finding)) for x in items)


@given(st.binary(max_size=32768))
@settings(max_examples=50, deadline=None)
def test_fuzz_read_header_arbitrary_bytes(data: bytes) -> None:
    """read_header is a total function over arbitrary byte streams."""
    stream = io.BytesIO(data)
    try:
        header = read_header(stream)
        assert isinstance(header, SessionHeader)
    except SesslintError:
        # Expected fail-closed behavior for malformed inputs
        pass


@given(st.binary(max_size=32768))
@settings(max_examples=50, deadline=None)
def test_fuzz_iter_events_arbitrary_bytes(data: bytes) -> None:
    """iter_events is a total function over arbitrary byte streams."""
    stream1 = io.BytesIO(data)
    stream2 = io.BytesIO(data)

    limits = ReaderLimits(max_line_bytes=4096, max_depth=20, max_file_bytes=65536)

    try:
        items1 = list(iter_events(stream1, limits=limits))
    except SesslintError:
        items1 = None

    try:
        items2 = list(iter_events(stream2, limits=limits))
    except SesslintError:
        items2 = None

    # Determinism check: both runs must produce identical results
    if items1 is None:
        assert items2 is None
    else:
        assert items2 is not None
        assert len(items1) == len(items2)
        for a, b in zip(items1, items2, strict=True):
            if isinstance(a, SessionEvent):
                assert isinstance(b, SessionEvent)
                assert a.id == b.id
            elif isinstance(a, Finding):
                assert isinstance(b, Finding)
                assert a.code == b.code
                assert a.fingerprint == b.fingerprint


@given(
    st.lists(
        st.one_of(
            st.text(max_size=200),
            st.dictionaries(
                keys=st.text(max_size=10),
                values=st.one_of(st.integers(), st.text(max_size=20), st.none()),
                max_size=5,
            ).map(json.dumps),
        ),
        max_size=30,
    )
)
@settings(max_examples=40, deadline=None)
def test_fuzz_iter_events_random_lines(lines: list[str]) -> None:
    """iter_events correctly partitions lines into SessionEvents or Findings."""
    content = "\n".join(lines).encode("utf-8")
    stream = io.BytesIO(content)

    try:
        items = list(iter_events(stream))
        for item in items:
            assert isinstance(item, (SessionEvent, Finding))
            if isinstance(item, Finding):
                assert item.code in ("SL001", "SL002", "SL302")
    except SesslintError:
        # Typed limits errors are acceptable fail-closed behavior
        pass
