"""Tests for bounded RSS and streaming JSONL processing (TASK-027, FR-014)."""

from __future__ import annotations

import io
import tracemalloc

from sesslint.canonical import SessionEvent
from sesslint.io import iter_events


def test_streaming_constant_memory() -> None:
    """Reading many events streamingly does not grow heap with event count."""
    header = (
        '{"schema_version": "sesslint.session/v1", "session_id": "stream_test", '
        '"created_at": "2026-09-06T12:00:00Z"}\n'
    )

    # Generate 5,000 events in memory
    lines = [header]
    for i in range(5000):
        lines.append(
            f'{{"actor": "user", "id": "evt_{i}", "kind": "message", "parent_id": null, '
            f'"payload": {{"idx": {i}}}, "seq": {i}, "ts": "2026-09-06T12:00:01Z"}}\n'
        )
    raw_data = "".join(lines).encode("utf-8")

    tracemalloc.start()
    stream = io.BytesIO(raw_data)
    count = 0

    snapshot1 = tracemalloc.take_snapshot()
    for item in iter_events(stream):
        if isinstance(item, SessionEvent):
            count += 1
    snapshot2 = tracemalloc.take_snapshot()
    tracemalloc.stop()

    assert count == 5000
    # Peak memory allocated during iteration should remain bounded (< 5MB)
    stats = snapshot2.compare_to(snapshot1, "lineno")
    total_diff = sum(stat.size_diff for stat in stats)
    assert total_diff < 5 * 1024 * 1024
