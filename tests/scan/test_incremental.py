"""Tests for the opt-in incremental scan cache (``--incremental`` / perf-scale T-02).

Contract: a cold incremental run is byte-identical to a non-incremental run;
a warm run replays provably-unchanged files and marks them ``"cache": "hit"``.
Content hashing (never mtime) is the correctness floor; unreadable verdicts
are never stored; every cache failure degrades to an uncached scan.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from sesslint.api import check_dir
from sesslint.cache import ScanCache, analysis_fingerprint, default_cache_dir
from sesslint.cli import main
from sesslint.scan import scan_path

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"
HEALTHY = FIXTURES_DIR / "cli" / "check_basic" / "healthy.jsonl"


def _build_tree(root: Path, copies: int = 8) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    payload = HEALTHY.read_bytes()
    for i in range(copies):
        (root / f"h{i:03}.jsonl").write_bytes(payload)
    return root


def _files(report_json: str) -> list[dict[str, object]]:
    return json.loads(report_json)["files"]  # type: ignore[no-any-return]


def _strip_markers(files: list[dict[str, object]]) -> list[dict[str, object]]:
    return [{k: v for k, v in f.items() if k != "cache"} for f in files]


# ---------------------------------------------------------------------------
# Byte-identical output + hit marking
# ---------------------------------------------------------------------------


def test_cold_incremental_byte_identical_to_plain(tmp_path: Path) -> None:
    tree = _build_tree(tmp_path / "tree")
    plain = scan_path(tree, recursive=True)
    cold = scan_path(tree, recursive=True, incremental=True, cache_dir=tmp_path / "cdb")
    assert cold.to_json() == plain.to_json()


def test_warm_run_marks_hits_and_matches(tmp_path: Path) -> None:
    tree = _build_tree(tmp_path / "tree")
    cache_dir = tmp_path / "cdb"
    cold = scan_path(tree, recursive=True, incremental=True, cache_dir=cache_dir)
    warm = scan_path(tree, recursive=True, incremental=True, cache_dir=cache_dir)
    warm_files = _files(warm.to_json())
    assert warm_files, "expected results"
    assert all(f.get("cache") == "hit" for f in warm_files)
    # Replayed content is identical modulo the explicit hit markers.
    assert _strip_markers(warm_files) == _files(cold.to_json())


def test_no_incremental_flag_means_no_cache(tmp_path: Path) -> None:
    tree = _build_tree(tmp_path / "tree")
    scan_path(tree, recursive=True, incremental=True, cache_dir=tmp_path / "cdb")
    plain = scan_path(tree, recursive=True)
    assert all("cache" not in f for f in _files(plain.to_json()))


def test_single_file_incremental(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cdb"
    cold = scan_path(HEALTHY, incremental=True, cache_dir=cache_dir)
    warm = scan_path(HEALTHY, incremental=True, cache_dir=cache_dir)
    assert cold.files[0].cache_hit is False
    assert warm.files[0].cache_hit is True
    assert warm.files[0].verdict == cold.files[0].verdict


# ---------------------------------------------------------------------------
# Invalidation
# ---------------------------------------------------------------------------


def test_one_byte_change_invalidates_only_that_file(tmp_path: Path) -> None:
    tree = _build_tree(tmp_path / "tree")
    cache_dir = tmp_path / "cdb"
    scan_path(tree, recursive=True, incremental=True, cache_dir=cache_dir)
    victim = tree / "h003.jsonl"
    victim.write_bytes(victim.read_bytes() + b" ")
    warm = scan_path(tree, recursive=True, incremental=True, cache_dir=cache_dir)
    hits = {f.path for f in warm.files if f.cache_hit}
    misses = {f.path for f in warm.files if not f.cache_hit}
    assert len(misses) == 1
    assert "h003.jsonl" in next(iter(misses))
    assert len(hits) == len(warm.files) - 1


def test_rule_selection_change_invalidates(tmp_path: Path) -> None:
    tree = _build_tree(tmp_path / "tree")
    cache_dir = tmp_path / "cdb"
    scan_path(tree, recursive=True, incremental=True, cache_dir=cache_dir)
    warm = scan_path(
        tree,
        recursive=True,
        incremental=True,
        cache_dir=cache_dir,
        ignore=("SL004",),
    )
    assert not any(f.cache_hit for f in warm.files)


def test_format_change_invalidates(tmp_path: Path) -> None:
    tree = _build_tree(tmp_path / "tree")
    cache_dir = tmp_path / "cdb"
    scan_path(tree, recursive=True, incremental=True, cache_dir=cache_dir)
    warm = scan_path(
        tree,
        recursive=True,
        incremental=True,
        cache_dir=cache_dir,
        format="claude-code-jsonl",
    )
    assert not any(f.cache_hit for f in warm.files)


def test_fingerprint_covers_engine_and_rules() -> None:
    a = analysis_fingerprint(
        format=None,
        profile="neutral",
        select=None,
        ignore=None,
        confidence_min=None,
        margin_min=None,
        skip_undetected=False,
        baseline=None,
    )
    b = analysis_fingerprint(
        format=None,
        profile="neutral",
        select=("SL001",),
        ignore=None,
        confidence_min=None,
        margin_min=None,
        skip_undetected=False,
        baseline=None,
    )
    assert a != b
    assert len(a) == 64  # sha256 hex


# ---------------------------------------------------------------------------
# Failure tolerance + scope guards
# ---------------------------------------------------------------------------


def test_corrupt_db_tolerated(tmp_path: Path) -> None:
    tree = _build_tree(tmp_path / "tree")
    cache_dir = tmp_path / "cdb"
    cache_dir.mkdir()
    (cache_dir / "cache.db").write_bytes(b"NOT A SQLITE DATABASE")
    rep = scan_path(tree, recursive=True, incremental=True, cache_dir=cache_dir)
    assert rep.totals.total == 8
    assert not any(f.cache_hit for f in rep.files)


def test_unwritable_cache_dir_tolerated(tmp_path: Path) -> None:
    tree = _build_tree(tmp_path / "tree")
    # A path that cannot be a directory: cache-dir pointing at an existing file.
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    rep = scan_path(tree, recursive=True, incremental=True, cache_dir=blocker / "sub")
    assert rep.totals.total == 8


def test_unreadable_verdicts_never_cached(tmp_path: Path) -> None:
    tree = _build_tree(tmp_path / "tree")
    (tree / "bad.jsonl").write_bytes(b'{"a":1}\n\xff\xfe not utf8\n')
    cache_dir = tmp_path / "cdb"
    scan_path(tree, recursive=True, incremental=True, cache_dir=cache_dir)
    warm = scan_path(tree, recursive=True, incremental=True, cache_dir=cache_dir)
    bad = next(f for f in warm.files if "bad.jsonl" in f.path)
    assert bad.verdict == "unreadable"
    assert bad.cache_hit is False
    con = sqlite3.connect(str(cache_dir / "cache.db"))
    try:
        rows = con.execute("SELECT path FROM cache_v1").fetchall()
    finally:
        con.close()
    assert not any("bad.jsonl" in row[0] for row in rows)


def test_cache_dir_inside_scanned_tree_ignored(tmp_path: Path) -> None:
    tree = _build_tree(tmp_path / "tree")
    inside = tree / ".sesslint-cache"
    rep = scan_path(tree, recursive=True, incremental=True, cache_dir=inside)
    assert rep.totals.total == 8
    assert not inside.exists(), "cache must never be created inside the scanned tree"


def test_cache_db_lives_in_cache_dir(tmp_path: Path) -> None:
    tree = _build_tree(tmp_path / "tree")
    cache_dir = tmp_path / "cdb"
    scan_path(tree, recursive=True, incremental=True, cache_dir=cache_dir)
    assert (cache_dir / "cache.db").is_file()


# ---------------------------------------------------------------------------
# Privacy: cached payloads carry no session content
# ---------------------------------------------------------------------------


def test_cached_payload_has_no_session_content(tmp_path: Path) -> None:
    tree = _build_tree(tmp_path / "tree")
    cache_dir = tmp_path / "cdb"
    scan_path(tree, recursive=True, incremental=True, cache_dir=cache_dir)
    con = sqlite3.connect(str(cache_dir / "cache.db"))
    try:
        rows = con.execute("SELECT result FROM cache_v1").fetchall()
    finally:
        con.close()
    assert rows
    blob = "\n".join(row[0] for row in rows)
    # Wire payloads carry verdict/counts/finding metadata only — never raw
    # session records or payload text.
    for forbidden in ("payload", "content", "message_body", "transcript"):
        assert forbidden not in blob
    # Spot-check against a distinctive string from the fixture bytes.
    marker = HEALTHY.read_text(encoding="utf-8")[:40].strip()
    assert marker not in blob


# ---------------------------------------------------------------------------
# Cache unit behavior + CLI + env resolution
# ---------------------------------------------------------------------------


def test_scan_cache_get_put_roundtrip(tmp_path: Path) -> None:
    cache = ScanCache(tmp_path / "cdb" / "cache.db")
    assert cache.healthy
    payload = {"path": "a/b.jsonl", "verdict": "healthy", "findings": []}
    cache.put("a/b.jsonl", "fp", "sha", payload)
    assert cache.get("a/b.jsonl", "fp", "sha") == payload
    assert cache.get("a/b.jsonl", "fp", "other-sha") is None
    assert cache.get("a/b.jsonl", "other-fp", "sha") is None
    cache.close()


def test_scan_cache_put_replaces_on_content_change(tmp_path: Path) -> None:
    cache = ScanCache(tmp_path / "cdb" / "cache.db")
    cache.put("p", "fp", "sha1", {"v": 1})
    cache.put("p", "fp", "sha2", {"v": 2})
    assert cache.get("p", "fp", "sha1") is None
    assert cache.get("p", "fp", "sha2") == {"v": 2}
    cache.close()


def test_default_cache_dir_env_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SESSLINT_CACHE_DIR", str(tmp_path / "envcache"))
    assert default_cache_dir() == tmp_path / "envcache"


def test_env_cache_dir_used_by_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tree = _build_tree(tmp_path / "tree")
    env_dir = tmp_path / "envcache"
    monkeypatch.setenv("SESSLINT_CACHE_DIR", str(env_dir))
    scan_path(tree, recursive=True, incremental=True)
    assert (env_dir / "cache.db").is_file()


def test_parallel_incremental_combines(tmp_path: Path) -> None:
    tree = _build_tree(tmp_path / "tree")
    cache_dir = tmp_path / "cdb"
    scan_path(tree, recursive=True, jobs=2, incremental=True, cache_dir=cache_dir)
    warm = scan_path(tree, recursive=True, jobs=2, incremental=True, cache_dir=cache_dir)
    assert all(f.cache_hit for f in warm.files)


def test_cli_incremental_and_cache_dir(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    tree = _build_tree(tmp_path / "tree")
    cache_dir = tmp_path / "cdb"
    code = main(["scan", str(tree), "--json", "--incremental", "--cache-dir", str(cache_dir)])
    assert code == 0
    capsys.readouterr()
    code = main(["scan", str(tree), "--json", "--incremental", "--cache-dir", str(cache_dir)])
    assert code == 0
    files = _files(capsys.readouterr().out)
    assert all(f.get("cache") == "hit" for f in files)


def test_cli_incremental_human_marks_hits(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tree = _build_tree(tmp_path / "tree")
    cache_dir = tmp_path / "cdb"
    main(["scan", str(tree), "--incremental", "--cache-dir", str(cache_dir)])
    capsys.readouterr()
    code = main(["scan", str(tree), "--incremental", "--cache-dir", str(cache_dir)])
    assert code == 0
    out = capsys.readouterr().out
    assert "[cache-hit]" in out


def test_check_dir_passthrough(tmp_path: Path) -> None:
    tree = _build_tree(tmp_path / "tree")
    cache_dir = tmp_path / "cdb"
    check_dir(tree, incremental=True, cache_dir=cache_dir)
    warm = check_dir(tree, incremental=True, cache_dir=cache_dir)
    assert all(f.cache_hit for f in warm.files)
