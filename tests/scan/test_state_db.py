"""Tests for SL402 Codex ``state_*.sqlite`` registry reconciliation (T-05).

The sqlite ``threads`` table is Codex's authoritative membership ledger:
a rollout file with no ``threads`` row is a partial-write orphan
(``file-not-in-index``), while the reverse — a ``threads`` row whose
``rollout_path`` is gone — is retention-normal and stays silent. The
named-threads JSONL index is arbitrated against ``threads`` when the
registry is in scope.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from sesslint.scan import scan_path
from sesslint.state_db import read_codex_state

UA = "01a0c4d8-a9f7-7973-8155-dba14d25a377"
UB = "01a0c4d8-a9f7-7973-8155-dba14d25a378"
UC = "01a0c4d8-a9f7-7973-8155-dba14d25a379"


def _rollout(dirpath: Path, uuid: str) -> Path:
    dirpath.mkdir(parents=True, exist_ok=True)
    p = dirpath / f"rollout-2026-09-20T00-00-00-{uuid}.jsonl"
    rows = [
        {
            "type": "session_meta",
            "ordinal": 0,
            "payload": {
                "session_id": uuid,
                "cli_version": "0.0.0-test",
                "model_provider": "openai",
                "originator": "codex",
            },
        },
        {
            "type": "response_item",
            "ordinal": 1,
            "payload": {"type": "message", "role": "user", "content": []},
        },
    ]
    p.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8", newline="\n")
    return p


def _mk_db(
    home: Path,
    *,
    threads: list[tuple[str, str | None]],
    edges: list[tuple[str, str]] | None = None,
    skips: list[str] | None = None,
    name: str = "state_1.sqlite",
) -> Path:
    db = home / name
    con = sqlite3.connect(db)
    con.execute(
        "CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT, "
        "thread_source TEXT, archived INTEGER, title TEXT)"
    )
    con.execute(
        "CREATE TABLE thread_spawn_edges (parent_thread_id TEXT, child_thread_id TEXT, status TEXT)"
    )
    con.execute(
        "CREATE TABLE rollout_migration_skipped_rollouts (rollout_path TEXT, skip_reason TEXT)"
    )
    for tid, rp in threads:
        con.execute(
            "INSERT INTO threads (id, rollout_path, thread_source, archived, title) "
            "VALUES (?,?,?,?,?)",
            (tid, rp, "user", 0, "synthetic-title-never-read"),
        )
    for a, b in edges or []:
        con.execute("INSERT INTO thread_spawn_edges VALUES (?,?,?)", (a, b, "open"))
    for r in skips or []:
        con.execute(
            "INSERT INTO rollout_migration_skipped_rollouts VALUES (?,?)",
            ("rollout-x", r),
        )
    con.commit()
    con.close()
    return db


def _named_index(home: Path, ids: list[str]) -> Path:
    p = home / "session_index.jsonl"
    p.write_text(
        "".join(
            json.dumps({"id": i, "thread_name": "synthetic", "updated_at": "t"}) + "\n" for i in ids
        ),
        encoding="utf-8",
        newline="\n",
    )
    return p


def _sl402(report, suffix: str | None = None):
    out = []
    for fr in report.files:
        for f in fr.findings:
            if f.code == "SL402" and (suffix is None or fr.path.endswith(suffix)):
                out.append((fr, f))
    return out


@pytest.fixture()
def codex_home(tmp_path: Path) -> Path:
    return tmp_path / ".codex"


def test_state_db_consistent_clean(codex_home: Path) -> None:
    sess = codex_home / "sessions" / "2026" / "09" / "20"
    rp = _rollout(sess, UA)
    _mk_db(codex_home, threads=[(UA, str(rp))])
    rep = scan_path(codex_home, recursive=True)
    assert _sl402(rep) == []


def test_state_db_unregistered_rollout_flagged(codex_home: Path) -> None:
    sess = codex_home / "sessions" / "2026" / "09" / "20"
    rp_a = _rollout(sess, UA)
    _rollout(sess, UB)  # on disk but no threads row
    _mk_db(codex_home, threads=[(UA, str(rp_a))])
    rep = scan_path(codex_home, recursive=True)
    hits = _sl402(rep, UB + ".jsonl")
    assert len(hits) == 1
    _, f = hits[0]
    assert f.evidence["divergence"] == "file-not-in-index"
    assert f.evidence["store"] == "state-sqlite"
    assert _sl402(rep, UA + ".jsonl") == []


def test_state_db_threads_row_missing_rollout_silent(codex_home: Path) -> None:
    """Retention deletes ledgers but keeps rows — never divergence."""
    sess = codex_home / "sessions" / "2026" / "09" / "20"
    rp_a = _rollout(sess, UA)
    _mk_db(
        codex_home,
        threads=[(UA, str(rp_a)), (UB, str(sess / f"rollout-x-{UB}.jsonl"))],
    )
    rep = scan_path(codex_home, recursive=True)
    assert _sl402(rep) == []


def test_state_db_named_id_resolved_by_registry(codex_home: Path) -> None:
    """Named id with a threads row but no rollout is vendor-known, not dangling."""
    sess = codex_home / "sessions" / "2026" / "09" / "20"
    rp_a = _rollout(sess, UA)
    _mk_db(codex_home, threads=[(UA, str(rp_a)), (UB, str(sess / f"gone-{UB}.jsonl"))])
    _named_index(codex_home, [UA, UB])
    rep = scan_path(codex_home, recursive=True)
    assert _sl402(rep) == []


def test_state_db_named_id_nowhere_flagged(codex_home: Path) -> None:
    """Named id with no threads row AND no rollout — stores disagree.

    The JSONL index is in scan scope, so the standard dangling check owns
    the finding (state-db ``thread_ids`` only *rescue* entries there).
    """
    sess = codex_home / "sessions" / "2026" / "09" / "20"
    rp_a = _rollout(sess, UA)
    _mk_db(codex_home, threads=[(UA, str(rp_a))])
    _named_index(codex_home, [UA, UC])
    rep = scan_path(codex_home, recursive=True)
    hits = _sl402(rep, "session_index.jsonl")
    assert len(hits) == 1
    _, f = hits[0]
    assert f.evidence["divergence"] == "index-entry-no-file"


def test_state_db_cross_check_when_jsonl_out_of_scope(codex_home: Path) -> None:
    """State db scanned without the JSONL index: the cross-check still
    catches named ids that resolve to nothing, attached to the db result.
    The JSONL sits beside the db but is excluded from the scan scope.
    """
    sess = codex_home / "sessions" / "2026" / "09" / "20"
    rp_a = _rollout(sess, UA)
    _mk_db(codex_home, threads=[(UA, str(rp_a))])
    _named_index(codex_home, [UA, UC])
    rep = scan_path(codex_home, recursive=True, exclude=["session_index.jsonl"])
    hits = _sl402(rep, "state_1.sqlite")
    assert len(hits) == 1
    _, f = hits[0]
    assert f.evidence["divergence"] == "index-entry-no-file"
    assert f.evidence["claim_source"] == "session_index.jsonl"
    assert f.evidence["store"] == "state-sqlite"


def test_state_db_spawn_edge_orphan(codex_home: Path) -> None:
    sess = codex_home / "sessions" / "2026" / "09" / "20"
    rp_a = _rollout(sess, UA)
    _mk_db(
        codex_home,
        threads=[(UA, str(rp_a))],
        edges=[(UA, UB), (UC, UA)],  # UB and UC have no threads rows
    )
    rep = scan_path(codex_home, recursive=True)
    hits = _sl402(rep, "state_1.sqlite")
    assert len(hits) == 1
    _, f = hits[0]
    assert f.evidence["divergence"] == "spawn-edge-orphan"
    assert f.evidence["orphan_edge_count"] == 2


def test_state_db_migration_skip_recorded(codex_home: Path) -> None:
    sess = codex_home / "sessions" / "2026" / "09" / "20"
    rp_a = _rollout(sess, UA)
    _mk_db(codex_home, threads=[(UA, str(rp_a))], skips=["schema-too-new", "io"])
    rep = scan_path(codex_home, recursive=True)
    hits = _sl402(rep, "state_1.sqlite")
    assert len(hits) == 1
    _, f = hits[0]
    assert f.evidence["divergence"] == "migration-skip-recorded"
    assert f.evidence["resolution"] == "vendor-reported"
    assert f.evidence["skip_count"] == 2
    # reason strings never emitted raw — hashed only
    assert "schema-too-new" not in json.dumps(dict(f.evidence or {}))


def test_state_db_malformed_file(codex_home: Path) -> None:
    sess = codex_home / "sessions" / "2026" / "09" / "20"
    _rollout(sess, UA)
    (codex_home / "state_1.sqlite").write_bytes(b"not a sqlite file at all")
    rep = scan_path(codex_home, recursive=True)
    hits = _sl402(rep, "state_1.sqlite")
    assert len(hits) == 1
    _, f = hits[0]
    assert f.evidence["divergence"] == "index-malformed"


def test_state_db_foreign_sqlite_silent(codex_home: Path) -> None:
    """A state_*.sqlite without the Codex schema is not ours — silent."""
    sess = codex_home / "sessions" / "2026" / "09" / "20"
    _rollout(sess, UA)
    db = codex_home / "state_9.sqlite"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE other (x TEXT)")
    con.commit()
    con.close()
    rep = scan_path(codex_home, recursive=True)
    assert _sl402(rep) == []


def test_state_db_no_sessions_subtree(codex_home: Path) -> None:
    codex_home.mkdir(parents=True)
    _mk_db(codex_home, threads=[(UA, "nonexistent")])
    rep = scan_path(codex_home, recursive=True)
    # threads→file direction is retention-normal — silent
    assert _sl402(rep) == []


# ---- reader unit tests -----------------------------------------------------


def test_reader_absent(tmp_path: Path) -> None:
    snap = read_codex_state(tmp_path / "state_1.sqlite")
    assert snap.parse_ok
    assert snap.schema_note == "absent"


def test_reader_symlink(tmp_path: Path) -> None:
    target = tmp_path / "real.sqlite"
    _mk_db(tmp_path, threads=[], name="real.sqlite")
    link = tmp_path / "state_1.sqlite"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink unavailable")
    snap = read_codex_state(link)
    assert not snap.parse_ok
    assert snap.schema_note == "symlink"


def test_reader_content_columns_never_selected(tmp_path: Path) -> None:
    """Registry carries content columns — snapshot must never retain them."""
    db = _mk_db(tmp_path, threads=[(UA, "rollout-a.jsonl")])
    snap = read_codex_state(db)
    assert snap.parse_ok
    blob = json.dumps(
        {
            "ids": sorted(snap.thread_ids),
            "uuids": sorted(snap.rollout_uuids),
        }
    )
    assert "synthetic-title-never-read" not in blob
