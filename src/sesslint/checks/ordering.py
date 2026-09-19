"""SL008 non-monotonic timestamp detector (checks-rules T-01).

Compares ``ts`` along causal edges (event → resolved parent), never across
global file order — sidechains legitimately interleave. A child whose
timestamp is strictly earlier than its parent's fires one warning per edge.

Design notes:
- ``SessionEvent.ts`` is always a populated RFC3339 string; adapters
  substitute the fixed epoch ``1970-01-01T00:00:00Z`` when the source record
  lacks a timestamp. Edges touching that sentinel are skipped as "lacking
  ts" — a synthesized value cannot support a monotonicity claim, and a real
  1970 timestamp is not a plausible agent-session artifact (fail quiet over
  false-positive).
- Edges whose ``parent_id`` is absent, unresolvable (SL004 territory), or
  ambiguous (duplicated parent id, SL003 territory) are skipped — ordering
  is only claimed where the parent edge is uniquely resolved.
- ``ts`` values that fail RFC3339 parsing are skipped defensively; the
  malformed record is already flagged upstream. Naive-vs-aware mixing on
  one edge is likewise skipped (no reliable ordering).
- Pure, deterministic, content-free: evidence carries ids, stream indices,
  and the integer millisecond delta — never payload or raw timestamps.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from datetime import datetime
from typing import Any, Final

from sesslint.canonical import SessionEvent
from sesslint.checks.graph import (
    MAX_GRAPH_FINDINGS,
    _event_get,
    _event_id_safe,
    _event_parent_id_safe,
    _resolve_source_coords,
    _safe_id,
    cap_graph_findings,
)
from sesslint.codes import SL008, Repairability, Severity
from sesslint.context import CheckContext
from sesslint.finding import Finding, SourceRef, make_finding

_TS_EPOCH_SENTINEL: Final[str] = "1970-01-01T00:00:00Z"
_MSG_SL008: Final[str] = "Non-monotonic timestamp for record {record_id}"


def _parse_ts(raw: Any) -> datetime | None:
    """Parse an RFC3339 timestamp; None for sentinel/missing/unparseable values."""
    if not isinstance(raw, str) or not raw.strip() or raw == _TS_EPOCH_SENTINEL:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def check_ordering(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    max_findings: int = MAX_GRAPH_FINDINGS,
    context: CheckContext | None = None,
) -> list[Finding]:
    """SL008: flag causal edges where a child's ``ts`` precedes its parent's.

    Per-branch monotonicity only: each event is compared against its uniquely
    resolved parent — never against positional neighbours. Skipped silently
    (coverage note in docs/codes/SL008.md): missing/ambiguous parent edges,
    epoch-sentinel timestamps, unparseable values, naive/aware mixing.
    """
    ctx = context if context is not None else CheckContext()

    id_to_indices: dict[str, list[int]] = {}
    for idx, ev in enumerate(events):
        eid = _event_id_safe(ev)
        if eid:
            id_to_indices.setdefault(eid, []).append(idx)

    findings: list[Finding] = []
    for child_idx, child in enumerate(events):
        parent_id = _event_parent_id_safe(child)
        if not parent_id:
            continue
        parent_indices = id_to_indices.get(parent_id)
        if parent_indices is None or len(parent_indices) != 1:
            continue  # missing parent (SL004) or duplicated parent id (SL003)
        parent_idx = parent_indices[0]
        parent = events[parent_idx]

        child_ts_raw = _event_get(child, "ts")
        parent_ts_raw = _event_get(parent, "ts")
        # Fast path: fixed-length RFC3339 UTC strings (``...Z``) sort
        # chronologically — equal-length lexicographic compare is exact and
        # skips two datetime parses on the dominant clean edge.
        child_ts: datetime | None = None
        parent_ts: datetime | None = None
        fast_violation = False
        if (
            isinstance(child_ts_raw, str)
            and isinstance(parent_ts_raw, str)
            and len(child_ts_raw) == len(parent_ts_raw)
            and child_ts_raw.endswith("Z")
            and parent_ts_raw.endswith("Z")
        ):
            if child_ts_raw == _TS_EPOCH_SENTINEL or parent_ts_raw == _TS_EPOCH_SENTINEL:
                continue
            if child_ts_raw >= parent_ts_raw:
                continue
            fast_violation = True
        else:
            child_ts = _parse_ts(child_ts_raw)
            parent_ts = _parse_ts(parent_ts_raw)
            if child_ts is None or parent_ts is None:
                continue
            if (child_ts.tzinfo is None) != (parent_ts.tzinfo is None):
                continue  # naive-vs-aware mixing cannot be ordered reliably
            if not child_ts < parent_ts:
                continue

        if fast_violation:
            child_ts = _parse_ts(child_ts_raw)
            parent_ts = _parse_ts(parent_ts_raw)
            if child_ts is None or parent_ts is None:
                continue
        if child_ts is None or parent_ts is None:
            continue  # unreachable: both branches above narrow or continue
        delta_ms = math.floor((child_ts - parent_ts).total_seconds() * 1000)
        resolved_path, line_num = _resolve_source_coords(child, source_path)
        clean_rec_id = _safe_id(str(_event_id_safe(child) or ""))
        clean_parent_id = _safe_id(parent_id)

        findings.append(
            make_finding(
                code=SL008,
                severity=Severity.WARNING,
                repairability=Repairability.MANUAL,
                message_template=_MSG_SL008,
                source=SourceRef(path=resolved_path, line=line_num, record_id=clean_rec_id),
                related_ids=(clean_rec_id, clean_parent_id),
                evidence={
                    "record_id": clean_rec_id,
                    "parent_id": clean_parent_id,
                    "ts_delta_ms": delta_ms,
                    "child_index": child_idx,
                    "parent_index": parent_idx,
                    "record_ordinal": child_idx,
                },
                adapter_id=ctx.adapter_id,
                adapter_version=ctx.adapter_version,
                profile_id=ctx.profile_id,
                profile_version=ctx.profile_version,
            )
        )

    return cap_graph_findings(
        findings,
        code=SL008,
        max_findings=max_findings,
        source_path=source_path,
        context=ctx,
    )


__all__ = ["check_ordering"]
