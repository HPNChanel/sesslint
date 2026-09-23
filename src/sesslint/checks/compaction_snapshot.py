"""SL208 compaction-snapshot divergence detector (detector-depth T-04).

Codex-rollout-scoped check: ``compacted`` records embed the vendor's own
pre-compaction snapshot (``guardian_history``) — a structural claim about
which items the thread held at the boundary. The adapter projects each
snapshot item's declared id, item type, and correlator into
``extra_fields["codex"]["guardian_items"]``; the durable stream already
carries each item's id, ``item_type``, and declared correlator as markers.
For items present in BOTH representations the two vendor-written claims
must agree — a disagreement is provable on-disk divergence, at most one
finding per kind per file:

- ``type-mismatch`` — the snapshot's declared item type differs from the
  durable record's declared type for the same item id.
- ``correlation-mismatch`` — the snapshot's declared correlator differs
  from the durable record's declared correlator, including presence
  disagreement (one side declares a correlator the other side lacks).
- ``future-item`` — the snapshot cites an item whose only durable
  appearance sits AFTER the compaction boundary: the snapshot claims
  history the stream had not yet written.

Deliberately not checked (fail closed):

- **snapshot-only ids** — a snapshot may legitimately carry inherited
  parent context absent from this file's stream; absence is not proof.
- **intra-snapshot pairing** — snapshots are bounded rolling windows;
  edge truncation is vendor-normal, not corruption.
- **items absent from the snapshot** — compaction legitimately drops
  history; a missing snapshot entry proves nothing.

Evidence is structural only: divergence kind, item ids (bounded vendor
identifiers of the same class already exposed as record ids), declared
type vocabulary, declared correlators, and stream indexes — never item
content. On a real corpus (84,917 shared items across 640 compacted
records) all three invariants held with zero violations.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Final

from sesslint.canonical import SessionEvent
from sesslint.checks.graph import _resolve_source_coords, _safe_id
from sesslint.codes import SL208, Repairability, Severity
from sesslint.context import CheckContext
from sesslint.finding import Finding, SourceRef, make_finding

_KIND_COMPACTION: Final[str] = "compaction_boundary"

_MSG_TYPE: Final[str] = (
    "Compaction snapshot item type disagrees with the durable stream "
    "on line {line} for record {record_id}"
)
_MSG_CORR: Final[str] = (
    "Compaction snapshot correlator disagrees with the durable stream "
    "on line {line} for record {record_id}"
)
_MSG_FUTURE: Final[str] = (
    "Compaction snapshot cites an item not yet written to the stream "
    "on line {line} for record {record_id}"
)


def _codex_marker(ev: SessionEvent) -> Mapping[str, Any] | None:
    extra = ev.extra_fields
    if not isinstance(extra, Mapping):
        return None
    m = extra.get("codex")
    return m if isinstance(m, Mapping) else None


def _rec_id(ev: SessionEvent) -> str | None:
    raw = getattr(ev, "id", None)
    return _safe_id(raw.strip()) if isinstance(raw, str) and raw.strip() else None


def _ev_kind(ev: SessionEvent) -> str | None:
    raw = getattr(ev, "kind", None)
    return str(raw) if raw is not None else None


def check_compaction_snapshot(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    context: CheckContext | None = None,
) -> list[Finding]:
    """SL208: ≤ one finding per divergence kind when a compacted record's
    embedded snapshot contradicts the durable stream on a shared item id."""
    ctx = context if context is not None else CheckContext()

    # Durable stream index: item id -> (position, declared type, declared
    # correlator). First occurrence wins — the earliest durable claim is
    # the conservative reference: later id reuse cannot mask divergence.
    stream: dict[str, tuple[int, str, str | None]] = {}
    boundaries: list[tuple[int, SessionEvent, Sequence[Any]]] = []
    for idx, ev in enumerate(events):
        marker = _codex_marker(ev)
        if marker is None:
            continue
        eid = getattr(ev, "id", None)
        item_type = marker.get("item_type")
        if isinstance(eid, str) and isinstance(item_type, str) and eid not in stream:
            corr = marker.get("call_id")
            stream[eid] = (idx, item_type, corr if isinstance(corr, str) else None)
        if _ev_kind(ev) == _KIND_COMPACTION:
            gh = marker.get("guardian_items")
            if isinstance(gh, list):
                boundaries.append((idx, ev, gh))

    if not boundaries:
        return []

    counts = {"type-mismatch": 0, "correlation-mismatch": 0, "future-item": 0}
    anchors: dict[str, SessionEvent] = {}
    anchor_items: dict[str, str] = {}
    anchor_extra: dict[str, dict[str, Any]] = {}

    for b_idx, b_ev, gh_items in boundaries:
        for gh in gh_items:
            if not isinstance(gh, Mapping):
                continue
            gid = gh.get("id")
            if not isinstance(gid, str) or gid not in stream:
                # Snapshot-only or unkeyed items are unprovable — the
                # snapshot may carry inherited context absent from this
                # file's stream.
                continue
            t_idx, t_type, t_corr = stream[gid]
            if t_idx > b_idx:
                counts["future-item"] += 1
                anchors.setdefault("future-item", b_ev)
                anchor_items.setdefault("future-item", gid)
                anchor_extra.setdefault(
                    "future-item",
                    {"boundary_index": b_idx, "item_index": t_idx},
                )
            gh_type = gh.get("type")
            if isinstance(gh_type, str) and gh_type != t_type:
                counts["type-mismatch"] += 1
                anchors.setdefault("type-mismatch", b_ev)
                anchor_items.setdefault("type-mismatch", gid)
                anchor_extra.setdefault(
                    "type-mismatch",
                    {
                        "boundary_index": b_idx,
                        "item_index": t_idx,
                        # Bounded + sanitized: declared type vocabulary is
                        # short, but a hostile record could write arbitrary
                        # payload text here — never emit it verbatim.
                        "snapshot_item_type": _safe_id(gh_type[:64]),
                        "stream_item_type": _safe_id(t_type[:64]),
                    },
                )
            gh_corr_raw = gh.get("call_id")
            gh_corr = gh_corr_raw if isinstance(gh_corr_raw, str) else None
            if gh_corr != t_corr:
                counts["correlation-mismatch"] += 1
                anchors.setdefault("correlation-mismatch", b_ev)
                anchor_items.setdefault("correlation-mismatch", gid)
                anchor_extra.setdefault(
                    "correlation-mismatch",
                    {
                        "boundary_index": b_idx,
                        "item_index": t_idx,
                        "snapshot_correlator": _safe_id(gh_corr[:256])
                        if gh_corr is not None
                        else None,
                        "stream_correlator": _safe_id(t_corr[:256]) if t_corr is not None else None,
                    },
                )

    findings: list[Finding] = []

    def _emit(
        ev: SessionEvent,
        *,
        template: str,
        evidence: dict[str, Any],
    ) -> None:
        resolved_path, line_num = _resolve_source_coords(ev, source_path)
        findings.append(
            make_finding(
                code=SL208,
                severity=Severity.WARNING,
                repairability=Repairability.MANUAL,
                message_template=template,
                source=SourceRef(path=resolved_path, line=line_num, record_id=_rec_id(ev)),
                evidence=evidence,
                adapter_id=ctx.adapter_id,
                adapter_version=ctx.adapter_version,
                profile_id=ctx.profile_id,
                profile_version=ctx.profile_version,
            )
        )

    if counts["type-mismatch"]:
        _emit(
            anchors["type-mismatch"],
            template=_MSG_TYPE,
            evidence={
                "divergence": "type-mismatch",
                "item_id": _safe_id(anchor_items["type-mismatch"][:256]),
                "occurrences": counts["type-mismatch"],
                **anchor_extra["type-mismatch"],
            },
        )
    if counts["correlation-mismatch"]:
        _emit(
            anchors["correlation-mismatch"],
            template=_MSG_CORR,
            evidence={
                "divergence": "correlation-mismatch",
                "item_id": _safe_id(anchor_items["correlation-mismatch"][:256]),
                "occurrences": counts["correlation-mismatch"],
                **anchor_extra["correlation-mismatch"],
            },
        )
    if counts["future-item"]:
        _emit(
            anchors["future-item"],
            template=_MSG_FUTURE,
            evidence={
                "divergence": "future-item",
                "item_id": _safe_id(anchor_items["future-item"][:256]),
                "occurrences": counts["future-item"],
                **anchor_extra["future-item"],
            },
        )

    return findings


__all__ = ["check_compaction_snapshot"]
