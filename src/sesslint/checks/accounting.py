"""SL204 token-usage arithmetic inconsistency detector (checks-rules T-03).

Reconciles cumulative token-usage markers against the sum of per-event
usage contributions inside one accounting window. Adapters normalize
vendor usage fields into ``SessionEvent.extra_fields["usage"]`` with two
optional slots:

- ``contribution``: ``{counter: int}`` — this record's usage delta
  (per-turn usage fields in vendor envelopes).
- ``cumulative``: ``{counter: int}`` — a running-total marker asserting
  cumulative state at this position.

Window rule (exact integer equality, per counter):

- The window opens at stream start (baseline zero) or at the previous
  cumulative marker. A marker's counters must equal
  ``baseline + window contributions`` — where the window sum includes
  the marker record's own ``contribution`` (the turn it closes).
- After a successful check the marker becomes the new baseline and the
  window resets.
- ``compaction_boundary`` resets the accounting epoch (post-compaction
  history is a new audit epoch, mirroring SL203): contributions
  accumulate fresh, and the *first* marker after a boundary establishes
  a new baseline unchecked — cumulative counters may legitimately
  restart or continue across compaction.

Design notes:

- Content-free: evidence carries record coordinates and integer
  totals only — never usage-key names or payload text.
- Counters that are not non-negative ints (bool, float, str, negative)
  are ignored per-key — shape anomalies are SL304 territory, not an
  accounting claim.
- One finding per divergent marker; ``expected_total``/``observed_total``
  are the sums over the marker's counters, ``mismatched_key_count``
  reports how many counters disagreed.
- Files without usage slots produce zero findings and no coverage
  noise — consistent with other absence-tolerant detectors.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Final

from sesslint.canonical import SessionEvent
from sesslint.checks.graph import (
    MAX_GRAPH_FINDINGS,
    _event_get,
    _event_id_safe,
    _resolve_source_coords,
    _safe_id,
    cap_graph_findings,
)
from sesslint.codes import SL204, Repairability, Severity
from sesslint.context import CheckContext
from sesslint.finding import Finding, SourceRef, make_finding

_MSG_SL204: Final[str] = "Token usage arithmetic inconsistency for record {record_id}"


def _clean_counters(raw: Any) -> dict[str, int]:
    """Return the non-negative int counters of a usage mapping (skip others)."""
    if not isinstance(raw, Mapping):
        return {}
    return {
        k: v
        for k, v in raw.items()
        if isinstance(k, str) and isinstance(v, int) and not isinstance(v, bool) and v >= 0
    }


def _usage_slot(ev: SessionEvent) -> tuple[dict[str, int], dict[str, int]]:
    """Return ``(contribution, cumulative)`` counter dicts for an event."""
    extra = _event_get(ev, "extra_fields")
    if not isinstance(extra, Mapping):
        return {}, {}
    usage = extra.get("usage")
    if not isinstance(usage, Mapping):
        return {}, {}
    return (
        _clean_counters(usage.get("contribution")),
        _clean_counters(usage.get("cumulative")),
    )


def check_accounting(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    max_findings: int = MAX_GRAPH_FINDINGS,
    context: CheckContext | None = None,
) -> list[Finding]:
    """SL204: flag cumulative usage markers that contradict window sums."""
    ctx = context if context is not None else CheckContext()

    baseline: dict[str, int] | None = None
    window: dict[str, int] = {}
    window_start_idx = 0
    # First cumulative marker in the stream-start epoch is checked against
    # a zero baseline; the first marker after a compaction boundary only
    # establishes the new epoch's baseline (unchecked).
    unchecked_next_marker = False

    findings: list[Finding] = []
    for idx, ev in enumerate(events):
        if _event_get(ev, "kind") == "compaction_boundary":
            baseline = None
            window = {}
            window_start_idx = idx + 1
            unchecked_next_marker = True
            continue

        contribution, cumulative = _usage_slot(ev)
        for key, val in contribution.items():
            window[key] = window.get(key, 0) + val

        if not cumulative:
            continue
        if unchecked_next_marker:
            baseline = dict(cumulative)
            window = {}
            window_start_idx = idx + 1
            unchecked_next_marker = False
            continue

        mismatched = 0
        expected_total = 0
        observed_total = 0
        base = baseline if baseline is not None else {}
        for key, observed in cumulative.items():
            expected = base.get(key, 0) + window.get(key, 0)
            expected_total += expected
            observed_total += observed
            if expected != observed:
                mismatched += 1

        if mismatched:
            resolved_path, line_num = _resolve_source_coords(ev, source_path)
            clean_rec_id = _safe_id(str(_event_id_safe(ev) or ""))
            findings.append(
                make_finding(
                    code=SL204,
                    severity=Severity.WARNING,
                    repairability=Repairability.MANUAL,
                    message_template=_MSG_SL204,
                    source=SourceRef(path=resolved_path, line=line_num, record_id=clean_rec_id),
                    related_ids=(clean_rec_id,),
                    evidence={
                        "record_id": clean_rec_id,
                        "expected_total": expected_total,
                        "observed_total": observed_total,
                        "mismatched_key_count": mismatched,
                        "window_start_index": window_start_idx,
                        "window_end_index": idx,
                        "record_ordinal": idx,
                    },
                    adapter_id=ctx.adapter_id,
                    adapter_version=ctx.adapter_version,
                    profile_id=ctx.profile_id,
                    profile_version=ctx.profile_version,
                )
            )

        baseline = dict(cumulative)
        window = {}
        window_start_idx = idx + 1

    return cap_graph_findings(
        findings,
        code=SL204,
        max_findings=max_findings,
        source_path=source_path,
        context=ctx,
    )


__all__ = ["check_accounting"]
