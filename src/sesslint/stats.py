"""Content-free aggregate statistics over session files (ux-reporting T-03).

``sesslint stats <path|--agent>`` answers "how big / what shape is my session
corpus" without reading transcripts: file counts by adapter, event counts by
kind and actor, tool-call volume per *hashed* tool name, compaction boundary
and checkpoint counts, and per-file byte/event percentiles.

Privacy contract: counters only — never payload values, never raw tool names
(only truncated sha256 name hashes), paths only via ``minimize_path`` in
the root label. Deterministic: sorted keys, fixed percentile ranks, no
timestamps — same corpus produces byte-identical output.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, cast

from sesslint._version import CLI_VERSION
from sesslint.adapters.detect import resolve_format
from sesslint.canonical import SessionEvent

STATS_SCHEMA_VERSION: Final[str] = "sesslint.stats/v1"

# Built-in scope exclusions for directory walks — same policy as scan:
# VCS internals are never session artifacts; sesslint's own config would
# only self-flag as undetected noise.
_EXCLUDED_DIRS: Final[frozenset[str]] = frozenset({".git", ".hg", ".svn"})
_EXCLUDED_NAMES: Final[frozenset[str]] = frozenset({"sesslint.toml", ".sesslint.toml"})

# Per-tool breakdown bound — deterministic top-N by (count desc, hash asc).
MAX_TOOL_ROWS: Final[int] = 100


def _percentile(sorted_vals: Sequence[int], q: float) -> int:
    """Nearest-rank percentile over an ascending-sorted int sequence."""
    if not sorted_vals:
        return 0
    idx = int(q * len(sorted_vals))
    if idx >= len(sorted_vals):
        idx = len(sorted_vals) - 1
    return sorted_vals[idx]


def _dist(values: Sequence[int]) -> dict[str, int]:
    srt = sorted(values)
    return {
        "max": srt[-1] if srt else 0,
        "p50": _percentile(srt, 0.50),
        "p95": _percentile(srt, 0.95),
        "total": sum(srt),
    }


def _tool_hash(name: str) -> str:
    """Truncated sha256 of a tool name — never the name itself."""
    return hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True, slots=True)
class SessionStats:
    """Frozen aggregate statistics result (``sesslint.stats/v1``)."""

    root_path: str
    tool_version: str
    files_processed: int
    files_undetected: int
    files_unreadable: int
    by_adapter: Mapping[str, int]
    events_total: int
    by_kind: Mapping[str, int]
    by_actor: Mapping[str, int]
    tool_calls_total: int
    by_tool_hash: Mapping[str, int]
    compaction_boundaries: int
    checkpoints: int
    file_bytes: Mapping[str, int]
    events_per_file: Mapping[str, int]

    @property
    def files_total(self) -> int:
        return self.files_processed + self.files_undetected + self.files_unreadable

    def to_dict(self, *, home: Path | None = None) -> dict[str, Any]:
        from sesslint.report import minimize_path

        return {
            "schema_version": STATS_SCHEMA_VERSION,
            "tool_version": self.tool_version,
            "root_path": minimize_path(self.root_path, home=home),
            "files": {
                "processed": self.files_processed,
                "undetected": self.files_undetected,
                "unreadable": self.files_unreadable,
                "total": self.files_total,
            },
            "by_adapter": dict(sorted(self.by_adapter.items())),
            "events": {
                "total": self.events_total,
                "by_kind": dict(sorted(self.by_kind.items())),
                "by_actor": dict(sorted(self.by_actor.items())),
            },
            "tool_calls": {
                "total": self.tool_calls_total,
                "by_tool_hash": dict(
                    sorted(
                        self.by_tool_hash.items(),
                        key=lambda kv: (-kv[1], kv[0]),
                    )[:MAX_TOOL_ROWS]
                ),
            },
            "compaction_boundaries": self.compaction_boundaries,
            "checkpoints": self.checkpoints,
            "file_bytes": dict(self.file_bytes),
            "events_per_file": dict(self.events_per_file),
        }

    def to_json(self, *, home: Path | None = None) -> str:
        return json.dumps(self.to_dict(home=home), indent=2, sort_keys=True)

    def render_human(self, *, home: Path | None = None) -> str:
        from sesslint.report import minimize_path

        lines = [
            "SessLint corpus statistics",
            f"  root: {minimize_path(self.root_path, home=home)}",
            "",
            f"Files: {self.files_total} "
            f"({self.files_processed} processed, "
            f"{self.files_undetected} undetected, "
            f"{self.files_unreadable} unreadable)",
        ]
        if self.by_adapter:
            lines.append("  by adapter:")
            for fmt, n in sorted(self.by_adapter.items()):
                lines.append(f"    {fmt:<24} {n}")
        lines.append("")
        lines.append(f"Events: {self.events_total}")
        if self.by_kind:
            for kind, n in sorted(self.by_kind.items()):
                lines.append(f"  {kind:<24} {n}")
        if self.by_actor:
            lines.append("  by actor:")
            for actor, n in sorted(self.by_actor.items()):
                lines.append(f"    {actor:<22} {n}")
        lines.append("")
        lines.append(f"Tool calls: {self.tool_calls_total}")
        top_tools = sorted(self.by_tool_hash.items(), key=lambda kv: (-kv[1], kv[0]))[
            :MAX_TOOL_ROWS
        ]
        for th, n in top_tools:
            lines.append(f"  sha256:{th}  {n}")
        if len(self.by_tool_hash) > len(top_tools):
            lines.append(f"  ... {len(self.by_tool_hash) - len(top_tools)} more tools")
        lines.append("")
        lines.append(f"Compaction boundaries: {self.compaction_boundaries}")
        lines.append(f"Checkpoints: {self.checkpoints}")
        fb, epf = self.file_bytes, self.events_per_file
        lines.append("")
        lines.append(
            f"File bytes:    p50={fb.get('p50', 0)}  p95={fb.get('p95', 0)}  "
            f"max={fb.get('max', 0)}  total={fb.get('total', 0)}"
        )
        lines.append(
            f"Events/file:   p50={epf.get('p50', 0)}  p95={epf.get('p95', 0)}  "
            f"max={epf.get('max', 0)}"
        )
        return "\n".join(lines)


def _iter_files(
    roots: Sequence[Path],
    *,
    max_files: int,
) -> tuple[list[Path], list[Path]]:
    """Enumerate (files, skipped_special) under roots in deterministic order.

    Mirrors scan's iterative sorted walk with the same built-in exclusions.
    Files beyond ``max_files`` are out of scope (the walk stops honestly).
    """
    out: list[Path] = []
    for root in roots:
        if root.is_symlink() or not root.is_dir():
            out.append(root)
            continue
        stack: list[Path] = [root]
        while stack:
            curr = stack.pop()
            try:
                entries = sorted(os.scandir(curr), key=lambda e: e.name)
            except OSError:
                continue
            for entry in entries:
                if len(out) >= max_files:
                    return out, []
                try:
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name not in _EXCLUDED_DIRS:
                            stack.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=False):
                        if entry.name not in _EXCLUDED_NAMES:
                            out.append(Path(entry.path))
                except OSError:
                    continue
    return out, []


def _count_events(events: Sequence[SessionEvent], counters: dict[str, Any]) -> None:
    """Fold one file's events into the aggregate counters (no payloads kept)."""
    counters["events_total"] += len(events)
    by_kind = counters["by_kind"]
    by_actor = counters["by_actor"]
    by_tool = counters["by_tool_hash"]
    for ev in events:
        by_kind[ev.kind] = by_kind.get(ev.kind, 0) + 1
        by_actor[ev.actor] = by_actor.get(ev.actor, 0) + 1
        if ev.kind == "tool_call":
            counters["tool_calls_total"] += 1
            name = ev.payload.get("tool_name") or ev.payload.get("name") or ""
            if isinstance(name, str) and name:
                th = _tool_hash(name)
                by_tool[th] = by_tool.get(th, 0) + 1
        elif ev.kind == "compaction_boundary":
            counters["compaction_boundaries"] += 1
        elif ev.kind == "checkpoint":
            counters["checkpoints"] += 1


def stats_paths(
    paths: Sequence[Path | str],
    *,
    recursive: bool = False,
    format: str | None = None,
    max_files: int | None = None,
    max_bytes: int | None = None,
) -> SessionStats:
    """Aggregate content-free statistics over session files or directories.

    Explicit file paths are always processed; directories require
    ``recursive=True`` (same contract as ``check``). Files that fail format
    detection count as ``undetected``; I/O or parse failures count as
    ``unreadable`` — stats never raises on a bad corpus member.
    """
    if max_files is None or max_bytes is None:
        from sesslint.scan import DEFAULT_MAX_BYTES, DEFAULT_MAX_FILES

        if max_files is None:
            max_files = DEFAULT_MAX_FILES
        if max_bytes is None:
            max_bytes = DEFAULT_MAX_BYTES

    roots = [Path(p) for p in paths]
    for r in roots:
        if not r.exists() and not r.is_symlink():
            raise FileNotFoundError(f"Path not found: {r}")
        if r.is_dir() and not recursive:
            raise ValueError(f"Path {r} is a directory. Use recursive=True (--recursive) to scan.")

    explicit = [r for r in roots if not r.is_dir() or r.is_symlink()]
    dirs = [r for r in roots if r.is_dir() and not r.is_symlink()]
    walked, _special = _iter_files(dirs, max_files=max_files)
    candidates = explicit + [w for w in walked if w not in explicit][:max_files]

    counters: dict[str, Any] = {
        "events_total": 0,
        "by_kind": {},
        "by_actor": {},
        "by_tool_hash": {},
        "tool_calls_total": 0,
        "compaction_boundaries": 0,
        "checkpoints": 0,
    }
    by_adapter: dict[str, int] = {}
    processed = undetected = unreadable = 0
    sizes: list[int] = []
    ev_counts: list[int] = []
    cumulative = 0

    from sesslint.adapters.load import load_events_for_format
    from sesslint.io import probe_text_encoding

    for f in candidates:
        if cumulative >= max_bytes:
            break
        try:
            size = f.stat().st_size
        except OSError:
            unreadable += 1
            continue
        cumulative += size

        if probe_text_encoding(f) is not None:
            unreadable += 1
            continue
        try:
            fmt, _res, _findings = resolve_format(format, f)
        except (OSError, ValueError):
            unreadable += 1
            continue
        if fmt is None:
            undetected += 1
            continue
        try:
            events, _load_findings = load_events_for_format(f, fmt)
        except Exception:
            unreadable += 1
            continue

        processed += 1
        by_adapter[fmt] = by_adapter.get(fmt, 0) + 1
        sizes.append(size)
        ev_counts.append(len(events))
        _count_events(list(events), counters)

    root_label = str(roots[0]) if len(roots) == 1 else str(Path.cwd())
    return SessionStats(
        root_path=root_label,
        tool_version=CLI_VERSION,
        files_processed=processed,
        files_undetected=undetected,
        files_unreadable=unreadable,
        by_adapter=by_adapter,
        events_total=counters["events_total"],
        by_kind=counters["by_kind"],
        by_actor=counters["by_actor"],
        tool_calls_total=counters["tool_calls_total"],
        by_tool_hash=counters["by_tool_hash"],
        compaction_boundaries=counters["compaction_boundaries"],
        checkpoints=counters["checkpoints"],
        file_bytes=_dist(sizes),
        events_per_file=_dist(ev_counts),
    )


def get_stats_schema_path() -> Path:
    """Return the filesystem path to schemas/sesslint.stats.v1.json."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    dev_path = repo_root / "schemas" / "sesslint.stats.v1.json"
    if dev_path.is_file():
        return dev_path
    prefix_path = Path(sys.prefix) / "share" / "sesslint" / "schemas" / "sesslint.stats.v1.json"
    if prefix_path.is_file():
        return prefix_path
    return dev_path


def load_stats_schema() -> dict[str, Any]:
    """Load the committed JSON Schema for sesslint.stats/v1 as a dict."""
    schema_path = get_stats_schema_path()
    if not schema_path.is_file():
        raise FileNotFoundError(f"Stats schema not found at {schema_path}")
    return cast(dict[str, Any], json.loads(schema_path.read_text(encoding="utf-8")))


__all__ = [
    "MAX_TOOL_ROWS",
    "STATS_SCHEMA_VERSION",
    "SessionStats",
    "get_stats_schema_path",
    "load_stats_schema",
    "stats_paths",
]
