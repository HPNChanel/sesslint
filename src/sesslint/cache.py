"""Incremental scan result cache — opt-in, sqlite3-backed (perf-scale T-02).

Re-running ``scan --incremental`` on an unchanged tree replays provably
identical per-file results instead of re-analyzing. Design guarantees:

- **Determinism**: cached values are full-fidelity ``FileResult`` wire
  payloads; replay and compute converge on one serializer, so verdicts,
  findings, and ordering are identical. Only an explicit ``cache_hit``
  marker distinguishes replayed entries.
- **Fail-closed**: every sqlite/JSON/OSError degrades to an empty cache —
  a corrupt or locked database never blocks or alters a scan.
- **No negative caching**: ``unreadable`` verdicts (transient I/O) are
  never stored; they always re-run.
- **Privacy**: rows hold a path string, a content hash, an analysis
  fingerprint, and a content-free result payload — no session payload.
- **Key correctness**: ``(path, analysis_fp)`` identifies the row and
  ``file_sha256`` validates content freshness; ``analysis_fp`` covers
  format/profile/rule-selection/thresholds/baseline/engine+adapter+profile
  versions, so any config change invalidates naturally — no TTL.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
from collections.abc import Collection, Sequence
from pathlib import Path
from typing import Any

SCHEMA_TABLE = "cache_v1"


def default_cache_dir() -> Path:
    """Platform-appropriate cache directory (``SESSLINT_CACHE_DIR`` wins)."""
    env = os.environ.get("SESSLINT_CACHE_DIR")
    if env:
        return Path(env)
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / "sesslint"
        return Path.home() / "AppData" / "Local" / "sesslint"
    base = os.environ.get("XDG_CACHE_HOME")
    if base:
        return Path(base) / "sesslint"
    return Path.home() / ".cache" / "sesslint"


def analysis_fingerprint(
    *,
    format: str | None,
    profile: str,
    select: Sequence[str] | None,
    ignore: Sequence[str] | None,
    confidence_min: float | None,
    margin_min: float | None,
    skip_undetected: bool,
    baseline: Collection[str] | None,
) -> str:
    """Stable fingerprint of every input that can change analysis output.

    Any CLI/profile/rule/version change yields a different fingerprint, so
    stale entries are unreachable rather than evicted.
    """
    from sesslint._version import ADAPTER_VERSIONS, PROFILE_VERSIONS, __version__
    from sesslint.codes import ALL_CODES

    payload = {
        "adapter_versions": ADAPTER_VERSIONS,
        "baseline": sorted(baseline) if baseline else None,
        "confidence_min": confidence_min,
        "engine": __version__,
        "format": format or "auto",
        "ignore": sorted(ignore) if ignore else None,
        "margin_min": margin_min,
        "profile": profile,
        "profile_versions": PROFILE_VERSIONS,
        "rules": sorted(ALL_CODES),
        "select": sorted(select) if select else None,
        "skip_undetected": skip_undetected,
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


class ScanCache:
    """sqlite-backed FileResult wire-payload cache.

    Single-writer-per-process; every operation fails soft so a corrupt or
    locked store behaves as an empty cache.
    """

    def __init__(self, db_path: Path) -> None:
        self._db: sqlite3.Connection | None = None
        self._ok = False
        try:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(str(db_path))
            self._db.execute(
                f"CREATE TABLE IF NOT EXISTS {SCHEMA_TABLE} ("
                "  path TEXT NOT NULL,"
                "  analysis_fp TEXT NOT NULL,"
                "  file_sha256 TEXT NOT NULL,"
                "  result TEXT NOT NULL,"
                "  PRIMARY KEY (path, analysis_fp)"
                ")"
            )
            self._ok = True
        except (sqlite3.Error, OSError):
            self._db = None

    @property
    def healthy(self) -> bool:
        """Whether the backing store is usable."""
        return self._ok

    def get(self, path: str, analysis_fp: str, file_sha256: str) -> dict[str, Any] | None:
        """Return the cached wire payload when the stored content hash matches."""
        if not self._ok or self._db is None:
            return None
        try:
            row = self._db.execute(
                f"SELECT file_sha256, result FROM {SCHEMA_TABLE} WHERE path=? AND analysis_fp=?",
                (path, analysis_fp),
            ).fetchone()
        except sqlite3.Error:
            self._ok = False
            return None
        if row is None or row[0] != file_sha256:
            return None
        try:
            data = json.loads(row[1])
        except (json.JSONDecodeError, TypeError):
            return None
        return data if isinstance(data, dict) else None

    def put(self, path: str, analysis_fp: str, file_sha256: str, result: dict[str, Any]) -> None:
        """Store a wire payload keyed by path+config, tagged with content hash."""
        if not self._ok or self._db is None:
            return
        try:
            self._db.execute(
                f"INSERT OR REPLACE INTO {SCHEMA_TABLE} "
                "(path, analysis_fp, file_sha256, result) VALUES (?,?,?,?)",
                (path, analysis_fp, file_sha256, json.dumps(result, sort_keys=True)),
            )
            self._db.commit()
        except (sqlite3.Error, TypeError, ValueError):
            self._ok = False

    def close(self) -> None:
        """Release the connection; safe to call repeatedly."""
        if self._db is not None:
            try:
                self._db.close()
            except sqlite3.Error:
                pass
            self._db = None
        self._ok = False
