"""SL305 provider-incompatible record shape detector (detector-depth T-05).

Codex-rollout-scoped check (evidence-assurance T-02 memo — GO verdict):
session records written against a third-party Responses-compatible
provider can carry shapes the official replay path rejects — the file
parses cleanly but the resume target refuses it (openai/codex#36551:
``reasoning`` items persisted with a non-null ``content`` array;
official shape is ``content: null`` or absent — "Expected maximum
length 0").

This is a *shape-vocabulary* check, not provenance inference: it can
only prove "shape outside the cited official vocabulary", never "the
file came from a foreign provider". Provider identity on disk is
self-reported (``session_meta.model_provider``/``originator``) and is
surfaced as a bounded hash, never a claim. Known-shapes list only —
absent or novel shapes stay silent; unknown is never foreign.

Fires at most once per file, anchored at the first offending record.
Evidence is structural only: shape class labels, counts, ordinals,
and hashed config metadata — never payload content.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from typing import Any, Final

from sesslint.canonical import SessionEvent
from sesslint.checks.graph import _resolve_source_coords, _safe_id
from sesslint.codes import SL305, Repairability, Severity
from sesslint.context import CheckContext
from sesslint.finding import Finding, SourceRef, make_finding

_MSG_FOREIGN: Final[str] = (
    "Record shape outside the replay vocabulary on line {line} for record {record_id}"
)

# Official replay vocabulary per item family — each entry carries an
# upstream citation. Additive only: a shape must be *cited* as
# provider-rejected before it can fire; unknown shapes are silent.
_FOREIGN_SHAPES: Final[Mapping[str, frozenset[str]]] = {
    # openai/codex#36551: official reasoning items expect content=null
    # (maximum length 0); non-null content is a third-party shape.
    "reasoning": frozenset({"array", "other"}),
}


def _marker_hash(value: str) -> str:
    """sha256-8 of a config marker string — same contract as writers.py."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]


def check_foreign_shape(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    context: CheckContext | None = None,
) -> list[Finding]:
    """SL305: ≤ one finding when reasoning items carry a non-null
    ``content`` shape outside the official replay vocabulary."""
    ctx = context if context is not None else CheckContext()

    offending: list[tuple[SessionEvent, int]] = []
    for ev in events:
        extra = ev.extra_fields
        if not isinstance(extra, Mapping):
            continue
        m = extra.get("codex")
        if not isinstance(m, Mapping):
            continue
        item_type = m.get("item_type")
        shape = m.get("reasoning_content_shape")
        if not isinstance(item_type, str):
            continue
        foreign = _FOREIGN_SHAPES.get(item_type)
        if foreign is None or not isinstance(shape, str) or shape not in foreign:
            continue
        o = m.get("ordinal")
        offending.append((ev, o if isinstance(o, int) and not isinstance(o, bool) else -1))

    if not offending:
        return []

    first_ev, first_ord = offending[0]
    evidence: dict[str, Any] = {
        "shape_violation": "reasoning-content-non-null",
        "item_family": "reasoning",
        "item_count": len(offending),
    }
    if first_ord >= 0:
        evidence["first_ordinal"] = first_ord

    # Declared provider context — self-reported config metadata, surfaced
    # as a bounded hash (SL010 writer_hashes precedent); never asserted
    # as provenance.
    sm = ctx.source_metadata
    if isinstance(sm, Mapping):
        meta = sm.get("session_meta")
        if isinstance(meta, Mapping):
            provider = meta.get("model_provider")
            if isinstance(provider, str) and provider.strip():
                evidence["declared_provider_hash"] = _marker_hash(provider.strip())
            if meta.get("originator") is not None:
                evidence["declared_originator_present"] = True

    resolved_path, line_num = _resolve_source_coords(first_ev, source_path)
    raw_id = getattr(first_ev, "id", None)
    rec_id = _safe_id(raw_id.strip()) if isinstance(raw_id, str) and raw_id.strip() else None
    return [
        make_finding(
            code=SL305,
            severity=Severity.WARNING,
            repairability=Repairability.MANUAL,
            message_template=_MSG_FOREIGN,
            source=SourceRef(path=resolved_path, line=line_num, record_id=rec_id),
            evidence=evidence,
            adapter_id=ctx.adapter_id,
            adapter_version=ctx.adapter_version,
            profile_id=ctx.profile_id,
            profile_version=ctx.profile_version,
        )
    ]
