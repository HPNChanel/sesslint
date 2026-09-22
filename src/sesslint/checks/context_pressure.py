"""SL207 context-pressure projection detector (detector-depth T-04).

Codex-rollout-scoped check: ``event_msg/token_count`` records carry the
vendor's own per-request context footprint
(``info.last_token_usage.input_tokens`` — the input side is what
occupies the window; ``cached_input_tokens`` is a subset of it) and the
declared model window (``info.model_context_window``). The adapter
normalizes both into ``extra_fields["codex"]["context_pressure"]`` as
``{occupancy, window}`` integers.

Two counters are deliberately *not* used: ``total_token_usage`` and
``thread_token_usage`` are cumulative lifetime billing totals (corpus
observation: they routinely exceed the window by orders of magnitude)
— mapping them to window occupancy would be the wrong counter and
produce false confidence.

Fires at most once per file, anchored at the last marker: when
``headroom = window - occupancy`` drops under 15% of the declared
window the session is approaching the un-compactable deadlock boundary
(too large to continue AND too large to compact — contextspectre
``docs/deadlock.md``). Integer arithmetic only; files without markers
stay silent (absence-tolerant — no coverage noise).

The under-reporting caveat from the deadlock reference applies: the
metered footprint may exclude system-prompt/tool overhead, so the 15%
margin is a floor, not a guarantee. Evidence is integers plus a
threshold-source id — never estimated values, never payload content.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Final

from sesslint.canonical import SessionEvent
from sesslint.checks.graph import _resolve_source_coords, _safe_id
from sesslint.codes import SL207, Repairability, Severity
from sesslint.context import CheckContext
from sesslint.finding import Finding, SourceRef, make_finding

_MSG_PRESSURE: Final[str] = (
    "Context headroom below 15% of the declared window on line {line} for record {record_id}"
)

# Warn when headroom < 15% of the declared window: headroom * 20 <
# window * 3. Integer comparison only — deterministic everywhere.
_HEADROOM_NUM: Final[int] = 3
_HEADROOM_DEN: Final[int] = 20
_THRESHOLD_SOURCE: Final[str] = "declared-window:15pct-headroom"


def check_context_pressure(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    context: CheckContext | None = None,
) -> list[Finding]:
    """SL207: ≤ one finding when the last declared context occupancy
    leaves less than 15% headroom under the declared model window."""
    ctx = context if context is not None else CheckContext()

    last_ev: SessionEvent | None = None
    occupancy = -1
    window = -1
    for ev in events:
        extra = ev.extra_fields
        if not isinstance(extra, Mapping):
            continue
        m = extra.get("codex")
        if not isinstance(m, Mapping):
            continue
        cp = m.get("context_pressure")
        if not isinstance(cp, Mapping):
            continue
        occ = cp.get("occupancy")
        win = cp.get("window")
        if (
            isinstance(occ, int)
            and not isinstance(occ, bool)
            and isinstance(win, int)
            and not isinstance(win, bool)
            and win > 0
        ):
            last_ev = ev
            occupancy = occ
            window = win

    if last_ev is None:
        return []

    headroom = window - occupancy
    if headroom * _HEADROOM_DEN >= window * _HEADROOM_NUM:
        return []

    resolved_path, line_num = _resolve_source_coords(last_ev, source_path)
    raw_id = getattr(last_ev, "id", None)
    rec_id = _safe_id(raw_id.strip()) if isinstance(raw_id, str) and raw_id.strip() else None
    evidence: dict[str, Any] = {
        "context_tokens": occupancy,
        "window_limit": window,
        "headroom": headroom,
        "threshold_source": _THRESHOLD_SOURCE,
    }
    if line_num is not None:
        evidence["last_marker_line"] = line_num
    return [
        make_finding(
            code=SL207,
            severity=Severity.WARNING,
            repairability=Repairability.MANUAL,
            message_template=_MSG_PRESSURE,
            source=SourceRef(path=resolved_path, line=line_num, record_id=rec_id),
            evidence=evidence,
            adapter_id=ctx.adapter_id,
            adapter_version=ctx.adapter_version,
            profile_id=ctx.profile_id,
            profile_version=ctx.profile_version,
        )
    ]
