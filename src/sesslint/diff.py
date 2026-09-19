"""Structural session comparator (ux-reporting T-02).

``sesslint diff A B`` answers "what structurally changed between these two
session files" — event-identity alignment, not text diff — for before/after
comparisons (vendor update, pre/post compaction, repair output sanity review).

Alignment is two-pass and deterministic:

1. Primary key ``event.id`` — duplicate ids pair earliest-first.
2. Fallback for unpaired events: ``(kind, parent_id, content_identity_hash)``
   multiset match — deterministic, still content-free (hashes only).

Remaining unpaired events report ``removed`` (A side) / ``added`` (B side).
Paired events compare ``kind`` / ``parent_id`` / ``content_identity_hash``;
a pair whose B position violates left-to-right order reports
``seq-reordered``. No payload text is ever emitted — only bounded
identifiers, kinds, indices and content hashes.
"""

from __future__ import annotations

import json
import sys
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Literal, cast

from sesslint._version import CLI_VERSION
from sesslint.adapters.detect import resolve_format
from sesslint.canonical import SessionEvent

DIFF_SCHEMA_VERSION: Final[str] = "sesslint.diff/v1"

DeltaCategory = Literal[
    "added",
    "removed",
    "kind-changed",
    "parent-relinked",
    "seq-reordered",
    "content-changed",
]

DELTA_CATEGORIES: Final[tuple[DeltaCategory, ...]] = (
    "added",
    "removed",
    "kind-changed",
    "parent-relinked",
    "seq-reordered",
    "content-changed",
)

# Human output bound — same truncation contract as report tables.
MAX_ROWS: Final[int] = 100

_CATEGORY_ORDER: Final[dict[str, int]] = {c: i for i, c in enumerate(DELTA_CATEGORIES)}


class DiffInputError(Exception):
    """Structured input failure for diff (detection or load), exit code 2."""


@dataclass(frozen=True, slots=True)
class Delta:
    """One structural difference between the two sessions (content-free)."""

    category: DeltaCategory
    event_id: str | None
    a_index: int | None
    b_index: int | None
    detail: Mapping[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"category": self.category}
        if self.event_id is not None:
            out["event_id"] = self.event_id
        if self.a_index is not None:
            out["a_index"] = self.a_index
        if self.b_index is not None:
            out["b_index"] = self.b_index
        if self.detail:
            out["detail"] = dict(self.detail)
        return out


@dataclass(frozen=True, slots=True)
class SessionDiff:
    """Frozen structural diff result (``sesslint.diff/v1``)."""

    a_path: str
    b_path: str
    a_format: str
    b_format: str
    a_event_count: int
    b_event_count: int
    tool_version: str
    deltas: tuple[Delta, ...]

    @property
    def identical(self) -> bool:
        return not self.deltas

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {c: 0 for c in DELTA_CATEGORIES}
        for d in self.deltas:
            out[d.category] += 1
        return out

    def to_dict(self, *, home: Path | None = None) -> dict[str, Any]:
        from sesslint.report import minimize_path

        return {
            "schema_version": DIFF_SCHEMA_VERSION,
            "tool_version": self.tool_version,
            "a": {
                "path": minimize_path(self.a_path, home=home),
                "format": self.a_format,
                "event_count": self.a_event_count,
            },
            "b": {
                "path": minimize_path(self.b_path, home=home),
                "format": self.b_format,
                "event_count": self.b_event_count,
            },
            "identical": self.identical,
            "counts": self.counts(),
            "deltas": [d.to_dict() for d in self.deltas],
        }

    def to_json(self, *, home: Path | None = None) -> str:
        return json.dumps(self.to_dict(home=home), indent=2, sort_keys=True)

    def render_human(self, *, home: Path | None = None) -> str:
        from sesslint.report import minimize_path

        a_min = minimize_path(self.a_path, home=home)
        b_min = minimize_path(self.b_path, home=home)
        lines = [
            "SessLint structural diff",
            f"  a: {a_min} ({self.a_format}, {self.a_event_count} events)",
            f"  b: {b_min} ({self.b_format}, {self.b_event_count} events)",
        ]
        if self.identical:
            lines.append("")
            lines.append("Identical structure: 0 differences.")
            return "\n".join(lines)

        counts = self.counts()
        lines.append("")
        lines.append(f"Differences: {len(self.deltas)}")
        for cat in DELTA_CATEGORIES:
            if counts[cat]:
                lines.append(f"  {cat:<16} {counts[cat]}")
        for cat in DELTA_CATEGORIES:
            group = [d for d in self.deltas if d.category == cat]
            if not group:
                continue
            lines.append("")
            lines.append(f"{cat}:")
            for d in group[:MAX_ROWS]:
                lines.append(f"  {_delta_label(d)}")
            hidden = len(group) - min(len(group), MAX_ROWS)
            if hidden:
                lines.append(f"  ... {hidden} more")
        return "\n".join(lines)


def _delta_label(d: Delta) -> str:
    side = f"a[{d.a_index}]" if d.a_index is not None else f"b[{d.b_index}]"
    if d.a_index is not None and d.b_index is not None:
        side = f"a[{d.a_index}] -> b[{d.b_index}]"
    label = side
    if d.event_id is not None:
        label += f" id={d.event_id}"
    if d.detail:
        label += " " + " ".join(f"{k}={v}" for k, v in sorted(d.detail.items()))
    return label


def _fallback_key(ev: SessionEvent) -> tuple[str, str, str]:
    return (ev.kind, ev.parent_id or "", ev.content_identity_hash())


def diff_events(
    events_a: Sequence[SessionEvent],
    events_b: Sequence[SessionEvent],
) -> tuple[Delta, ...]:
    """Align two event sequences and emit sorted content-free deltas.

    Deterministic: equal inputs always yield the same delta tuple.
    """
    # Pass 1: pair by event id — duplicate ids pair earliest-first.
    b_by_id: dict[str, deque[int]] = {}
    for j, ev in enumerate(events_b):
        b_by_id.setdefault(ev.id, deque()).append(j)

    pairs: list[tuple[int, int]] = []
    unmatched_a: list[int] = []
    matched_b: set[int] = set()
    for i, ev in enumerate(events_a):
        bucket = b_by_id.get(ev.id)
        while bucket and bucket[0] in matched_b:
            bucket.popleft()
        if bucket:
            j = bucket.popleft()
            matched_b.add(j)
            pairs.append((i, j))
        else:
            unmatched_a.append(i)

    # Pass 2: fallback (kind, parent_id, content_identity_hash) multiset.
    b_by_key: dict[tuple[str, str, str], deque[int]] = {}
    for j, ev in enumerate(events_b):
        if j not in matched_b:
            b_by_key.setdefault(_fallback_key(ev), deque()).append(j)

    still_unmatched_a: list[int] = []
    for i in unmatched_a:
        key = _fallback_key(events_a[i])
        bucket = b_by_key.get(key)
        while bucket and bucket[0] in matched_b:
            bucket.popleft()
        if bucket:
            j = bucket.popleft()
            matched_b.add(j)
            pairs.append((i, j))
        else:
            still_unmatched_a.append(i)

    deltas: list[Delta] = []

    for i, j in pairs:
        ea, eb = events_a[i], events_b[j]
        if ea.kind != eb.kind:
            deltas.append(
                Delta(
                    category="kind-changed",
                    event_id=ea.id,
                    a_index=i,
                    b_index=j,
                    detail={"kind_a": ea.kind, "kind_b": eb.kind},
                )
            )
        if ea.parent_id != eb.parent_id:
            deltas.append(
                Delta(
                    category="parent-relinked",
                    event_id=ea.id,
                    a_index=i,
                    b_index=j,
                    detail={"parent_a": ea.parent_id or "", "parent_b": eb.parent_id or ""},
                )
            )
        if ea.content_identity_hash() != eb.content_identity_hash():
            deltas.append(
                Delta(
                    category="content-changed",
                    event_id=ea.id,
                    a_index=i,
                    b_index=j,
                    detail={
                        "hash_a": ea.content_identity_hash()[:16],
                        "hash_b": eb.content_identity_hash()[:16],
                    },
                )
            )

    # Reorder detection: a-ordered pairs whose b position regresses below
    # the running maximum broke left-to-right order.
    running_max = -1
    for i, j in sorted(pairs):
        if j < running_max:
            deltas.append(
                Delta(
                    category="seq-reordered",
                    event_id=events_a[i].id,
                    a_index=i,
                    b_index=j,
                )
            )
        else:
            running_max = j

    for i in still_unmatched_a:
        ev = events_a[i]
        deltas.append(
            Delta(
                category="removed",
                event_id=ev.id,
                a_index=i,
                b_index=None,
                detail={"kind": ev.kind},
            )
        )
    for j, ev in enumerate(events_b):
        if j not in matched_b:
            deltas.append(
                Delta(
                    category="added",
                    event_id=ev.id,
                    a_index=None,
                    b_index=j,
                    detail={"kind": ev.kind},
                )
            )

    deltas.sort(
        key=lambda d: (
            _CATEGORY_ORDER[d.category],
            d.a_index if d.a_index is not None else -1,
            d.b_index if d.b_index is not None else -1,
            d.event_id or "",
        )
    )
    return tuple(deltas)


def _load_side(
    path: Path,
    explicit_format: str | None,
) -> tuple[list[SessionEvent], str]:
    """Detect + load one diff input; raises DiffInputError on failure."""
    try:
        resolved_fmt, detection_res, det_findings = resolve_format(explicit_format, path)
    except ValueError as err:
        raise DiffInputError(str(err)) from err
    from sesslint.report import minimize_path

    if resolved_fmt is None:
        reason = detection_res.reason if detection_res else "unknown"
        detail = "; ".join(f.message for f in det_findings[:3])
        raise DiffInputError(
            f"Format detection failed for {minimize_path(path)}: {reason}"
            + (f" ({detail})" if detail else "")
        )

    from sesslint.adapters.load import load_events_for_format

    events, _findings = load_events_for_format(path, resolved_fmt)
    return list(events), resolved_fmt


def diff_sessions(
    a: Path | str,
    b: Path | str,
    *,
    format_a: str | None = None,
    format_b: str | None = None,
) -> SessionDiff:
    """Compare two session files structurally and return a frozen SessionDiff.

    Both inputs go through normal detection + adapter parse. Raises
    ``DiffInputError`` for undetectable/unloadable inputs and
    ``FileNotFoundError`` for missing paths (CLI maps both to exit 2).
    """
    path_a, path_b = Path(a), Path(b)
    for p in (path_a, path_b):
        if not p.exists():
            raise FileNotFoundError(f"Path not found: {p}")
        if p.is_dir():
            raise DiffInputError(f"Diff input must be a file, not a directory: {p}")

    events_a, fmt_a = _load_side(path_a, format_a)
    events_b, fmt_b = _load_side(path_b, format_b)
    deltas = diff_events(events_a, events_b)
    return SessionDiff(
        a_path=str(path_a),
        b_path=str(path_b),
        a_format=fmt_a,
        b_format=fmt_b,
        a_event_count=len(events_a),
        b_event_count=len(events_b),
        tool_version=CLI_VERSION,
        deltas=deltas,
    )


def get_diff_schema_path() -> Path:
    """Return the filesystem path to schemas/sesslint.diff.v1.json."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    dev_path = repo_root / "schemas" / "sesslint.diff.v1.json"
    if dev_path.is_file():
        return dev_path
    prefix_path = Path(sys.prefix) / "share" / "sesslint" / "schemas" / "sesslint.diff.v1.json"
    if prefix_path.is_file():
        return prefix_path
    return dev_path


def load_diff_schema() -> dict[str, Any]:
    """Load the committed JSON Schema for sesslint.diff/v1 as a dict."""
    schema_path = get_diff_schema_path()
    if not schema_path.is_file():
        raise FileNotFoundError(f"Diff schema not found at {schema_path}")
    return cast(dict[str, Any], json.loads(schema_path.read_text(encoding="utf-8")))


__all__ = [
    "DELTA_CATEGORIES",
    "DIFF_SCHEMA_VERSION",
    "MAX_ROWS",
    "Delta",
    "DeltaCategory",
    "DiffInputError",
    "SessionDiff",
    "diff_events",
    "diff_sessions",
    "get_diff_schema_path",
    "load_diff_schema",
]
