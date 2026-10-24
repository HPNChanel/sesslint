"""Codex ``state_*.sqlite`` registry reader — bounded, read-only (T-05).

Codex keeps its authoritative session registry in ``state_*.sqlite`` at
the vendor home: the ``threads`` table is a membership ledger keyed by
thread id (the rollout-filename UUID), ``thread_spawn_edges`` is the
sub-agent spawn graph, and ``rollout_migration_skipped_rollouts`` is the
vendor's own ledger of skipped (unmigratable) rollouts.

Read-only by construction: stdlib ``sqlite3`` opened with
``file:…?mode=ro`` plus ``PRAGMA query_only = ON`` — the reader can never
write, create WAL sidecars, or mutate the registry. Bounded: file size
and per-table row caps; ``LIMIT``-guarded queries. Content-free: a strict
column allowlist means title/name/preview/first_user_message and other
content columns are never selected — only ids, paths-as-uuid-sources, and
status enums cross the boundary.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from sesslint.report import short_hash

MAX_STATE_DB_BYTES: int = 256 * 1024 * 1024
MAX_STATE_ROWS: int = 1_000_000
MAX_STATE_QUERY_STEPS: int = 50_000_000

STATE_DB_GLOB: str = "state_*.sqlite"

_ROLLOUT_UUID = re.compile(
    r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
)

# Columns this reader may touch — anything else (title, name, preview,
# first_user_message, objective, raw_memory, payloads) is content and
# never crosses the boundary.
_THREADS_COLS = ("id", "rollout_path", "thread_source", "archived")
_SPAWN_COLS = ("parent_thread_id", "child_thread_id")
_SKIP_COLS = ("skip_reason",)


def rollout_uuid_from_name(name: str) -> str | None:
    """Extract the thread UUID from a ``rollout-<ts>-<uuid>.jsonl`` name."""
    m = _ROLLOUT_UUID.search(name)
    return m.group(1).lower() if m else None


def is_state_db_name(name: str) -> bool:
    """True for Codex registry files (``state_*.sqlite``)."""
    return name.startswith("state_") and name.endswith(".sqlite")


@dataclass(frozen=True, slots=True)
class CodexStateSnapshot:
    """Structural membership snapshot of one ``state_*.sqlite`` registry.

    ``parse_ok`` is False when the file cannot be interpreted as a Codex
    registry (locked, unreadable, oversized, wrong schema). ``schema_note``
    records why claims are not provable (``"absent"``, ``"locked"``,
    ``"io-error"``, ``"unrecognized-shape"``, ``"oversized"``,
    ``"symlink"``). Membership is complete only when ``parse_ok`` is True
    and ``schema_note`` is None.
    """

    parse_ok: bool
    schema_note: str | None
    thread_ids: frozenset[str]
    rollout_uuids: frozenset[str]
    thread_rows: int
    spawn_edge_orphans: int
    migration_skips: int
    migration_skip_reason_hashes: tuple[str, ...]
    thread_rollout_pairs: frozenset[tuple[str, str]] = frozenset()

    @property
    def membership_complete(self) -> bool:
        return self.parse_ok and self.schema_note is None


def _empty(*, parse_ok: bool, note: str | None) -> CodexStateSnapshot:
    return CodexStateSnapshot(
        parse_ok=parse_ok,
        schema_note=note,
        thread_ids=frozenset(),
        rollout_uuids=frozenset(),
        thread_rows=0,
        spawn_edge_orphans=0,
        migration_skips=0,
        migration_skip_reason_hashes=(),
    )


def _table_columns(con: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in con.execute(f"PRAGMA table_info({table})")}


def read_codex_state(path: Path, *, immutable: bool = False) -> CodexStateSnapshot:
    """Read one Codex ``state_*.sqlite`` into a :class:`CodexStateSnapshot`.

    Never raises on bad input: every failure mode is a deterministic
    snapshot field. Never follows symlinks, never writes.
    """
    try:
        if path.is_symlink():
            return _empty(parse_ok=False, note="symlink")
        if not path.is_file():
            return _empty(parse_ok=True, note="absent")
        if path.stat().st_size > MAX_STATE_DB_BYTES:
            return _empty(parse_ok=False, note="oversized")
    except OSError:
        return _empty(parse_ok=False, note="io-error")

    uri = path.absolute().as_uri() + "?mode=ro"
    if immutable:
        uri += "&immutable=1"
    try:
        con = sqlite3.connect(uri, uri=True)
    except sqlite3.Error:
        return _empty(parse_ok=False, note="io-error")
    try:
        query_budget = MAX_STATE_QUERY_STEPS

        def limit_query() -> int:
            nonlocal query_budget
            query_budget -= 1000
            return int(query_budget <= 0)

        if immutable:
            con.set_progress_handler(limit_query, 1000)
        con.execute("PRAGMA query_only = ON")
        con.execute("PRAGMA busy_timeout = 0")
        tcols = _table_columns(con, "threads")
        if not tcols or "id" not in tcols or "rollout_path" not in tcols:
            return _empty(parse_ok=False, note="unrecognized-shape")

        thread_ids: set[str] = set()
        rollout_uuids: set[str] = set()
        thread_rollout_pairs: set[tuple[str, str]] = set()
        rows = 0
        for tid, rpath in con.execute(
            "SELECT id, rollout_path FROM threads LIMIT ?", (MAX_STATE_ROWS + 1,)
        ):
            rows += 1
            if rows > MAX_STATE_ROWS:
                return _empty(parse_ok=False, note="oversized")
            if isinstance(tid, str) and tid:
                thread_ids.add(tid)
            if isinstance(rpath, str) and rpath:
                # ``rollout_path`` may carry Windows separators regardless
                # of the scanning host — normalize before basename.
                base = rpath.replace("\\", "/").rsplit("/", 1)[-1]
                u = rollout_uuid_from_name(base)
                if u:
                    rollout_uuids.add(u)
                    if isinstance(tid, str) and tid:
                        thread_rollout_pairs.add((tid, u))

        orphans = 0
        if _table_columns(con, "thread_spawn_edges") >= set(_SPAWN_COLS):
            # Bound rows before relationship work; correlated COUNT queries
            # can be quadratic on unindexed, user-supplied registry copies.
            for i, (parent, child) in enumerate(
                con.execute(
                    "SELECT parent_thread_id, child_thread_id FROM thread_spawn_edges LIMIT ?",
                    (MAX_STATE_ROWS + 1,),
                )
            ):
                if i >= MAX_STATE_ROWS:
                    return _empty(parse_ok=False, note="oversized")
                if parent not in thread_ids or child not in thread_ids:
                    orphans += 1

        skips = 0
        reason_hashes: set[str] = set()
        if _table_columns(con, "rollout_migration_skipped_rollouts") >= set(_SKIP_COLS):
            for i, (reason,) in enumerate(
                con.execute(
                    "SELECT skip_reason FROM rollout_migration_skipped_rollouts LIMIT ?",
                    (MAX_STATE_ROWS + 1,),
                )
            ):
                if i >= MAX_STATE_ROWS:
                    return _empty(parse_ok=False, note="oversized")
                skips += 1
                reason_hashes.add(short_hash(reason if isinstance(reason, str) else ""))
    except sqlite3.OperationalError as err:
        note = (
            "query-limit"
            if immutable and query_budget <= 0
            else "locked"
            if "locked" in str(err).lower()
            else "io-error"
        )
        return _empty(parse_ok=False, note=note)
    except sqlite3.DatabaseError:
        return _empty(parse_ok=False, note="malformed")
    finally:
        con.close()
    return CodexStateSnapshot(
        parse_ok=True,
        schema_note=None,
        thread_ids=frozenset(thread_ids),
        rollout_uuids=frozenset(rollout_uuids),
        thread_rows=rows,
        spawn_edge_orphans=orphans,
        migration_skips=skips,
        migration_skip_reason_hashes=tuple(sorted(reason_hashes)),
        thread_rollout_pairs=frozenset(thread_rollout_pairs),
    )


__all__ = [
    "CodexStateSnapshot",
    "MAX_STATE_DB_BYTES",
    "MAX_STATE_ROWS",
    "STATE_DB_GLOB",
    "is_state_db_name",
    "read_codex_state",
    "rollout_uuid_from_name",
]
