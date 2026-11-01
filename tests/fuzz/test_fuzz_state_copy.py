"""CL-17: ``triage --state-copy`` and ``read_codex_state`` on hostile SQLite.

Real SQLite files are built with odd schemas and cell types, then truncated or
bit-flipped; raw junk and SQLite-header-prefixed junk are also tried. The
reader must return a snapshot (never raise), the CLI must exit with a published
code without the internal-error handler, runs must be deterministic, and no
cell content may reach the output.
"""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sesslint.state_db import read_codex_state
from tests.fuzz.test_fuzz_cli_surfaces import _assert_clean
from tests.fuzz.test_fuzz_hostile_inputs import FIXTURES, MARKER

_UUID = "11111111-2222-3333-4444-555555555555"
_ROLLOUT = FIXTURES / "adapters" / "codex" / "healthy_min.jsonl"
_CELL = st.one_of(
    st.none(),
    st.integers(-(2**63), 2**63 - 1),
    st.floats(allow_nan=False),
    st.text(max_size=20),
    st.binary(max_size=20),
    st.just(MARKER),
    st.just(f"/x/rollout-2026-01-01T00-00-00-{_UUID}.jsonl"),
    st.just(f"C:\\x\\rollout-{_UUID}.jsonl"),
    st.just(_UUID),
)
_COLTYPE = st.sampled_from(["TEXT", "INTEGER", "BLOB", "", "REAL"])
_SCHEMAS = st.sampled_from(
    [
        "CREATE TABLE threads (id {t}, rollout_path {t}, thread_source {t}, archived {t})",
        "CREATE TABLE threads (id {t}, rollout_path {t})",
        "CREATE TABLE threads (id {t})",
        "CREATE TABLE threads (rollout_path {t}, id {t}, title {t})",
        "CREATE TABLE other (id {t}, rollout_path {t}); "
        "CREATE VIEW threads AS SELECT id, rollout_path FROM other",
        "CREATE TABLE threads (id {t}, rollout_path {t}); "
        "CREATE TABLE thread_spawn_edges (parent_thread_id {t}, child_thread_id {t}); "
        "CREATE TABLE rollout_migration_skipped_rollouts (skip_reason {t})",
    ]
)


@st.composite
def _databases(draw: st.DrawFn) -> bytes:
    work = Path(tempfile.mkdtemp(prefix="sl-cl17-db-"))
    try:
        db = work / "build.sqlite"
        con = sqlite3.connect(db)
        try:
            con.executescript(draw(_SCHEMAS).format(t=draw(_COLTYPE)))
            tables = [
                r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")
            ]
            for table in tables:
                n = len(list(con.execute(f"PRAGMA table_info({table})")))
                for _ in range(draw(st.integers(0, 4))):
                    row = [draw(_CELL) for _ in range(n)]
                    con.execute(f"INSERT INTO {table} VALUES ({','.join('?' * n)})", row)
            con.commit()
        except sqlite3.Error:
            pass
        finally:
            con.close()
        data = db.read_bytes()
    finally:
        shutil.rmtree(work, ignore_errors=True)
    for _ in range(draw(st.integers(0, 3))):
        if not data:
            break
        op = draw(st.sampled_from(["flip", "cut", "pad", "none"]))
        at = draw(st.integers(0, len(data)))
        if op == "flip":
            i = min(at, len(data) - 1)
            data = data[:i] + bytes([data[i] ^ draw(st.integers(1, 255))]) + data[i + 1 :]
        elif op == "cut":
            data = data[:at]
        elif op == "pad":
            data += draw(st.binary(max_size=64))
    return data


_RAW = st.one_of(
    st.binary(max_size=200),
    st.binary(max_size=200).map(lambda b: b"SQLite format 3\x00" + b),
    st.just(b""),
)


def _check(data: bytes) -> None:
    work = Path(tempfile.mkdtemp(prefix="sl-cl17-sc-"))
    try:
        db = work / "state_5.sqlite"
        db.write_bytes(data)
        first = read_codex_state(db, immutable=True)
        assert first == read_codex_state(db, immutable=True)
        assert read_codex_state(db) == read_codex_state(db)
        rollout = work / f"rollout-2026-01-01T00-00-00-{_UUID}.jsonl"
        rollout.write_bytes(_ROLLOUT.read_bytes())
        for fmt in ([], ["-f", "json"]):
            _assert_clean(["triage", str(rollout), "--state-copy", str(db), *fmt])
        assert not list(work.glob("*-wal")) and not list(work.glob("*-shm"))
    finally:
        shutil.rmtree(work, ignore_errors=True)


@given(data=_databases())
@settings(deadline=None, max_examples=60, suppress_health_check=[HealthCheck.too_slow])
def test_state_copy_structured_sqlite(data: bytes) -> None:
    _check(data)


@given(data=_RAW)
@settings(deadline=None, max_examples=60, suppress_health_check=[HealthCheck.too_slow])
def test_state_copy_raw_bytes(data: bytes) -> None:
    _check(data)
