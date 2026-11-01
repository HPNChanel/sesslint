"""Regression (CL-17): reading a registry must never create WAL sidecars.

A file whose SQLite header declares WAL mode made the plain read-only open
create ``-wal``/``-shm`` beside it, writing into agent storage.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sesslint.state_db import read_codex_state

HEADERS = [
    b"SQLite format 3\x00\x00\x00\x00\x02",
    b"SQLite format 3\x00" + b"\x10\x00\x02\x02" + b"\x00" * 80,
]


@pytest.mark.parametrize("data", HEADERS)
@pytest.mark.parametrize("immutable", [False, True])
def test_read_codex_state_creates_no_sidecars(tmp_path: Path, data: bytes, immutable: bool) -> None:
    db = tmp_path / "state_5.sqlite"
    db.write_bytes(data)
    snapshot = read_codex_state(db, immutable=immutable)
    assert not snapshot.membership_complete
    assert sorted(p.name for p in tmp_path.iterdir()) == ["state_5.sqlite"]
    assert db.read_bytes() == data
