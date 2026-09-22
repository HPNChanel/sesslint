"""Vendor session-index readers — bounded, shape-only (index-reconciliation T-01).

Extracts *membership sets* from vendor session-index files — which session
IDs/paths the vendor believes exist — without interpreting transcript
content. Read-only by construction: readers never write and never follow
symlinks.

Bounded: index files are capped at ``MAX_INDEX_BYTES`` and
``MAX_INDEX_ENTRIES``; parsing is stdlib ``json`` only. Content-free:
snapshots carry ID sets for internal diffing — nothing from other entry
fields (titles, previews, prompts) is retained.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

MAX_INDEX_BYTES: int = 16 * 1024 * 1024
MAX_INDEX_ENTRIES: int = 65536
MAX_PROJECT_DIRS: int = 4096

_INDEX_FORMAT_CLAUDE = "claude-sessions-index"
_INDEX_FORMAT_CODEX = "codex-session-index"
_INDEX_FORMAT_UNKNOWN = "unknown"

# Per-runtime index-file names discoverable under a session root. Codex
# keeps a JSONL thread index at the vendor home (``session_index.jsonl``)
# while ledgers live under ``sessions/**`` — reconciled as a subtree
# scope, not a sibling set (index-reconciliation T-04).
_INDEX_FILENAMES: dict[str, tuple[str, ...]] = {
    "claude": ("sessions-index.json",),
    "codex": ("session_index.jsonl",),
}

# Flat set of every vendor index filename the scanner recognizes (SL402).
INDEX_FILE_NAMES: frozenset[str] = frozenset(
    name for names in _INDEX_FILENAMES.values() for name in names
)


@dataclass(frozen=True, slots=True)
class IndexEntry:
    """One index row: the session id it claims plus its declared path."""

    session_id: str | None
    full_path: str | None


@dataclass(frozen=True, slots=True)
class IndexSnapshot:
    """Membership set claimed by one vendor index file (index-reconciliation).

    ``parse_ok`` is False when the file cannot be interpreted as an index at
    all (binary garbage, unreadable, oversized, symlink). ``truncated`` marks
    the picker-crash signature: JSON-shaped content cut mid-structure, with
    ``entry_*`` carrying the salvaged partial set. ``schema_note`` records
    why membership is not provable (``"absent"``, ``"unrecognized-shape"``,
    ``"oversized"``, ``"symlink"``…) — detectors must only claim *absence*
    of a session when ``membership_complete`` is True.
    """

    format: str
    entries: tuple[IndexEntry, ...]
    parse_ok: bool
    truncated: bool
    schema_note: str | None

    @property
    def entry_ids(self) -> frozenset[str]:
        """Distinct ``sessionId`` values claimed across entries."""
        return frozenset(e.session_id for e in self.entries if e.session_id)

    @property
    def entry_paths(self) -> frozenset[str]:
        """Distinct ``fullPath`` values claimed across entries."""
        return frozenset(e.full_path for e in self.entries if e.full_path)

    @property
    def entry_count(self) -> int:
        """Distinct session ids — deduped membership size, not raw rows."""
        return len(self.entry_ids)

    @property
    def membership_complete(self) -> bool:
        """True only when the whole membership set was enumerated."""
        return self.parse_ok and not self.truncated and self.schema_note is None

    @property
    def normalized_ids(self) -> frozenset[str]:
        """IDs plus filename stems — ``<uuid>.jsonl`` ↔ bare ``<uuid>``."""
        out: set[str] = set(self.entry_ids)
        for p in self.entry_paths | self.entry_ids:
            stem = Path(p).stem
            if stem:
                out.add(stem)
        return frozenset(out)


def _snapshot(
    *,
    fmt: str = _INDEX_FORMAT_CLAUDE,
    entries: tuple[IndexEntry, ...] = (),
    parse_ok: bool,
    truncated: bool = False,
    note: str | None,
) -> IndexSnapshot:
    return IndexSnapshot(
        format=fmt,
        entries=entries,
        parse_ok=parse_ok,
        truncated=truncated,
        schema_note=note,
    )


def _extract_entries(doc: object) -> tuple[tuple[IndexEntry, ...], str | None]:
    """Pull ``sessionId``/``fullPath`` pairs from a decoded index document."""
    if not isinstance(doc, dict):
        return (), "unrecognized-shape"
    entries = doc.get("entries")
    if not isinstance(entries, list):
        return (), "unrecognized-shape"
    out: list[IndexEntry] = []
    missing_id = 0
    for e in entries:
        if not isinstance(e, dict):
            missing_id += 1
            continue
        sid = e.get("sessionId")
        sid_v = sid if isinstance(sid, str) and sid else None
        if sid_v is None:
            missing_id += 1
        fp = e.get("fullPath")
        fp_v = fp if isinstance(fp, str) and fp else None
        out.append(IndexEntry(session_id=sid_v, full_path=fp_v))
    note = f"{missing_id} entries lack sessionId" if missing_id else None
    return tuple(out), note


def _salvage_partial(text: str) -> tuple[IndexEntry, ...]:
    """Recover complete entries before a mid-structure cut."""
    marker = text.find('"entries"')
    start = text.find("[", marker) if marker != -1 else -1
    if start == -1:
        return ()
    dec = json.JSONDecoder()
    pos = start + 1
    out: list[IndexEntry] = []
    end = len(text)
    while pos < end and len(out) < MAX_INDEX_ENTRIES:
        while pos < end and text[pos] in " \t\r\n,":
            pos += 1
        if pos >= end or text[pos] == "]":
            break
        try:
            obj, nxt = dec.raw_decode(text, pos)
        except json.JSONDecodeError:
            break
        pos = nxt
        if isinstance(obj, dict):
            sid = obj.get("sessionId")
            fp = obj.get("fullPath")
            out.append(
                IndexEntry(
                    session_id=sid if isinstance(sid, str) and sid else None,
                    full_path=fp if isinstance(fp, str) and fp else None,
                )
            )
    return tuple(out)


def _looks_like_index(text: str) -> bool:
    head = text[:4096]
    return '"entries"' in head or '"sessionId"' in head or '"originalPath"' in head


def read_index(path: Path) -> IndexSnapshot:
    """Read one vendor index file into an :class:`IndexSnapshot`.

    Never raises on bad input: every failure mode is a deterministic
    snapshot field, never an exception. Never follows symlinks, never
    writes.
    """
    try:
        if path.is_symlink():
            return _snapshot(parse_ok=False, note="symlink")
        if not path.is_file():
            return _snapshot(parse_ok=True, note="absent")
        if path.stat().st_size > MAX_INDEX_BYTES:
            return _snapshot(parse_ok=False, note="oversized")
        raw = path.read_bytes()
    except OSError:
        return _snapshot(parse_ok=False, note="io-error")

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return _snapshot(parse_ok=False, note="malformed")

    if path.name == "session_index.jsonl":
        return _read_jsonl_index(text)

    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        stripped = text.lstrip()
        if stripped.startswith("{") and _looks_like_index(text):
            return _snapshot(
                entries=_salvage_partial(text),
                parse_ok=False,
                truncated=True,
                note="truncated",
            )
        return _snapshot(parse_ok=False, note="malformed")

    entries, note = _extract_entries(doc)
    if len(entries) > MAX_INDEX_ENTRIES:
        return _snapshot(parse_ok=False, note="oversized")
    fmt = _INDEX_FORMAT_CLAUDE if note != "unrecognized-shape" else _INDEX_FORMAT_UNKNOWN
    return _snapshot(fmt=fmt, entries=entries, parse_ok=True, note=note)


def _read_jsonl_index(text: str) -> IndexSnapshot:
    """Read a Codex ``session_index.jsonl`` thread index (T-04).

    One ``{"id", "thread_name", "updated_at"}`` object per line; only
    ``id`` is retained — ``thread_name`` is content and is dropped at
    the reader boundary. A malformed final line marks the snapshot
    ``truncated`` (salvaged prefix kept); a malformed mid-file line
    fails the whole index — a corrupted middle is not a clean cut.
    """
    entries: list[IndexEntry] = []
    lines = text.splitlines()
    missing_id = 0
    saw_object = False
    for pos, line in enumerate(lines):
        if len(entries) >= MAX_INDEX_ENTRIES:
            return _snapshot(fmt=_INDEX_FORMAT_CODEX, parse_ok=False, note="oversized")
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            tail = pos == len(lines) - 1
            return _snapshot(
                fmt=_INDEX_FORMAT_CODEX,
                entries=tuple(entries),
                parse_ok=False,
                truncated=tail,
                note="truncated" if tail else "malformed",
            )
        if not isinstance(obj, dict):
            return _snapshot(fmt=_INDEX_FORMAT_CODEX, parse_ok=False, note="unrecognized-shape")
        saw_object = True
        sid = obj.get("id")
        sid_v = sid if isinstance(sid, str) and sid else None
        if sid_v is None:
            missing_id += 1
        entries.append(IndexEntry(session_id=sid_v, full_path=None))
    if not saw_object:
        return _snapshot(fmt=_INDEX_FORMAT_CODEX, parse_ok=False, note="unrecognized-shape")
    note = f"{missing_id} entries lack id" if missing_id else None
    return _snapshot(
        fmt=_INDEX_FORMAT_CODEX,
        entries=tuple(entries),
        parse_ok=True,
        note=note,
    )


def has_index_format(agent: str) -> bool:
    """True when the runtime has a verified file-readable index format."""
    return agent in _INDEX_FILENAMES


def discover_index_files(root: Path, agent: str) -> tuple[Path, ...]:
    """Enumerate vendor index files under a session root, deterministically.

    Claude keeps ``sessions-index.json`` inside each per-project directory
    (``<root>/<proj>/sessions-index.json``) — a root passed directly is also
    checked so a scan pointed at a single project dir still finds it.
    Missing files are not errors; callers decide what "absent" means.
    Unknown agents yield an empty tuple (recorded limitation, not failure).
    """
    names = _INDEX_FILENAMES.get(agent)
    if not names:
        return ()
    out: list[Path] = []
    for name in names:
        direct = root / name
        try:
            if direct.is_file() and not direct.is_symlink():
                out.append(direct)
        except OSError:
            pass
        if agent == "codex":
            # Codex keeps the index at the vendor home (``~/.codex/``) —
            # one level above the ``sessions/`` root callers pass in.
            try:
                parent_idx = root.parent / name
                if parent_idx.is_file() and not parent_idx.is_symlink():
                    out.append(parent_idx)
            except OSError:
                pass
        try:
            if not root.is_dir() or root.is_symlink():
                return tuple(out)
            with os.scandir(root) as it:
                subdirs = sorted(
                    (e for e in it if e.is_dir() and not e.is_symlink()),
                    key=lambda e: e.name,
                )
        except OSError:
            return tuple(out)
        for e in subdirs[:MAX_PROJECT_DIRS]:
            cand = Path(e.path) / name
            try:
                if cand.is_file() and not cand.is_symlink():
                    out.append(cand)
            except OSError:
                continue
    return tuple(out)


__all__ = [
    "INDEX_FILE_NAMES",
    "IndexEntry",
    "MAX_INDEX_BYTES",
    "MAX_INDEX_ENTRIES",
    "IndexSnapshot",
    "discover_index_files",
    "has_index_format",
    "read_index",
]
