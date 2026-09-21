"""SL010 interleaved writer-marker detector (detector-depth T-02).

Flags session files whose records carry *interleaved* writer-identity
markers — the corruption precondition behind dropped writes (SL101
orphans, SL003 id collisions). A marker is an adapter-normalized
``extra_fields["writer"]`` mapping: ``instance`` when the vendor records a
per-process discriminator, else ``version`` (application build). Adapters
that emit no markers produce an empty sequence and zero findings —
absence is never a violation.

Firing rule (conservative):
- One SL010 per file, only when a marker *reappears* after a different
  marker (A→B→A). Interleaving is the concurrency proof.
- A clean ordered transition A*→B* (all A records precede all B) is a
  legitimate mid-session upgrade — no finding.
- Marker values are hashed (sha256-8) for evidence: a version string is
  near-public, but hashing keeps the content-free contract uniform and
  still lets operators diff writer sets across files.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from typing import Any, Final

from sesslint.canonical import SessionEvent
from sesslint.checks.graph import _resolve_source_coords, _safe_id
from sesslint.codes import SL010, Repairability, Severity
from sesslint.context import CheckContext
from sesslint.finding import Finding, SourceRef, make_finding

_MSG_SL010: Final[str] = "Interleaved writer markers in session file for record {record_id}"


def _writer_marker(ev: SessionEvent) -> str | None:
    """Return the normalized writer marker for an event, or None."""
    extra = ev.extra_fields
    if not isinstance(extra, Mapping):
        return None
    w = extra.get("writer")
    if not isinstance(w, Mapping):
        return None
    instance = w.get("instance")
    if isinstance(instance, str) and instance.strip():
        return f"i:{instance.strip()}"
    version = w.get("version")
    if isinstance(version, str) and version.strip():
        return f"v:{version.strip()}"
    return None


def _marker_hash(marker: str) -> str:
    """sha256-8 of a marker string — stable, content-free identity."""
    return hashlib.sha256(marker.encode("utf-8")).hexdigest()[:8]


def check_writers(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    context: CheckContext | None = None,
) -> list[Finding]:
    """SL010: at most one finding when writer markers interleave.

    Marker sequence is deduped per source line first (one record may emit
    several events sharing ``source_line``), then consecutive duplicates
    collapse into a transition sequence. The first marker observed again
    after a different marker proves interleaved writers.
    """
    ctx = context if context is not None else CheckContext()

    # Ordered (marker, event) sequence — one entry per (line, marker)
    # pair so multi-event records count once.
    seq: list[tuple[str, SessionEvent]] = []
    seen_line_marker: set[tuple[int | None, str]] = set()
    for ev in events:
        marker = _writer_marker(ev)
        if marker is None:
            continue
        line = ev.source_line if isinstance(ev.source_line, int) else None
        key = (line, marker)
        if key in seen_line_marker:
            continue
        seen_line_marker.add(key)
        seq.append((marker, ev))

    if len(seq) < 3:
        return []

    # Collapse consecutive duplicates into a transition sequence.
    reduced: list[tuple[str, SessionEvent]] = []
    for entry in seq:
        if not reduced or reduced[-1][0] != entry[0]:
            reduced.append(entry)

    seen_markers: set[str] = set()
    interleave_ev: SessionEvent | None = None
    for marker, ev in reduced:
        if marker in seen_markers:
            interleave_ev = ev
            break
        seen_markers.add(marker)
    if interleave_ev is None:
        return []  # single marker or clean ordered upgrade — legitimate

    distinct = {m for m, _ in seq}
    resolved_path, line_num = _resolve_source_coords(interleave_ev, source_path)
    raw_id = getattr(interleave_ev, "id", None)
    rec_id = _safe_id(raw_id.strip()) if isinstance(raw_id, str) and raw_id.strip() else None
    evidence: dict[str, Any] = {
        "distinct_writer_count": len(distinct),
        "transition_count": len(reduced) - 1,
        "first_interleave_line": line_num,
        "writer_hashes": tuple(sorted(_marker_hash(m) for m in distinct)),
    }
    return [
        make_finding(
            code=SL010,
            severity=Severity.WARNING,
            repairability=Repairability.MANUAL,
            message_template=_MSG_SL010,
            source=SourceRef(path=resolved_path, line=line_num, record_id=rec_id),
            evidence=evidence,
            adapter_id=ctx.adapter_id,
            adapter_version=ctx.adapter_version,
            profile_id=ctx.profile_id,
            profile_version=ctx.profile_version,
        )
    ]


__all__ = ["check_writers"]
