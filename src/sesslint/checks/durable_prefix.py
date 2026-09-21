"""SL206 durable-prefix boundary detector (detector-depth T-03).

Codex-rollout-scoped check: the paginated resume path expects a contiguous
durable record sequence up to the inherited-prefix ordinal. The adapter
normalizes per-record durability into ``extra_fields["codex"]`` —
``{durable, ordinal, envelope_type, ...}`` — and this check proves three
on-disk violations, at most one finding per kind per file:

- ``trailing-non-durable`` — the file declares an inherited-prefix
  ordinal (``subagent_history_start_ordinal``) *past* the last durable
  ordinal: the resume path expects durable coverage through the claimed
  ordinal and finds a non-durable record there instead
  (openai/codex#40747: "expected inherited prefix through ordinal 828,
  found final durable ordinal 827"). Files without the claim keep
  ordinary non-durable tails clean — a bare non-durable tail proves
  nothing on its own.
- ``durable-gap`` — an ordinal strictly inside the durable range has no
  record at all: a durable hole inside the prefix. Ordinals held by
  non-durable records are legitimate interleave, not holes.
- ``missing-required-field`` — ``reasoning`` response_items lacking
  ``encrypted_content`` while sibling reasoning items carry it: the
  resume projection may silently drop required state (openai/codex#19661
  class). Uniform absence cannot prove the field is required — silent.

Evidence is structural only: ordinals, counts, and envelope type names
(schema vocabulary), never payload content.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Final

from sesslint.canonical import SessionEvent
from sesslint.checks.graph import _resolve_source_coords, _safe_id
from sesslint.codes import SL206, Repairability, Severity
from sesslint.context import CheckContext
from sesslint.finding import Finding, SourceRef, make_finding

_MSG_TRAILING: Final[str] = (
    "Non-durable tail record past the durable prefix on line {line} for record {record_id}"
)
_MSG_GAP: Final[str] = "Durable-prefix ordinal hole on line {line} for record {record_id}"
_MSG_FIELD: Final[str] = (
    "Reasoning item missing a resume-required field on line {line} for record {record_id}"
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


def check_durable_prefix(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    context: CheckContext | None = None,
) -> list[Finding]:
    """SL206: ≤ one finding per divergence kind when the durable-prefix
    contract is broken on a codex-rollout stream."""
    ctx = context if context is not None else CheckContext()

    marked: list[tuple[SessionEvent, Mapping[str, Any]]] = []
    for ev in events:
        m = _codex_marker(ev)
        if m is not None:
            marked.append((ev, m))
    if not marked:
        return []

    envelope_ordinals: set[int] = set()
    durable_ordinals: set[int] = set()
    inherited_prefix_ordinal: int | None = None
    for _ev, m in marked:
        o = m.get("ordinal")
        if isinstance(o, int) and not isinstance(o, bool):
            envelope_ordinals.add(o)
            if m.get("durable") is True:
                durable_ordinals.add(o)
        if inherited_prefix_ordinal is None:
            shso = m.get("subagent_history_start_ordinal")
            if isinstance(shso, int) and not isinstance(shso, bool):
                inherited_prefix_ordinal = shso

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
                code=SL206,
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

    # --- trailing-non-durable -----------------------------------------
    # The violation is provable only when the file declares an inherited
    # prefix claim (subagent_history_start_ordinal): resume expects the
    # durable sequence to cover ordinals through that claim, so a claim
    # pointing past the last durable ordinal mismatches (#40747). A bare
    # telemetry tail with no claim is normal rollout shape — silent.
    if (
        durable_ordinals
        and inherited_prefix_ordinal is not None
        and inherited_prefix_ordinal > max(durable_ordinals)
    ):
        last_durable = max(durable_ordinals)
        claim = inherited_prefix_ordinal
        # Anchor at the record holding the claimed ordinal when present
        # (#40747: the claim itself sat on a non-durable token_count),
        # else at the file's highest-ordinal record.
        anchor: SessionEvent | None = None
        anchor_m: Mapping[str, Any] | None = None
        tail_ev: SessionEvent | None = None
        tail_m: Mapping[str, Any] | None = None
        tail_ord = -1
        for ev, m in marked:
            o = m.get("ordinal")
            if not isinstance(o, int) or isinstance(o, bool):
                continue
            if o >= tail_ord:
                tail_ev, tail_m, tail_ord = ev, m, o
            if o == claim:
                anchor, anchor_m = ev, m
        if anchor is None:
            anchor, anchor_m = tail_ev, tail_m
        if anchor is None:
            anchor = marked[-1][0]
        evidence: dict[str, Any] = {
            "divergence": "trailing-non-durable",
            "expected_durable_ordinal": claim,
            "last_durable_ordinal": last_durable,
            "inherited_prefix_ordinal": claim,
        }
        if tail_ord >= 0:
            evidence["tail_ordinal"] = tail_ord
        if anchor_m is not None:
            fam = anchor_m.get("envelope_type")
            if isinstance(fam, str) and fam.strip():
                evidence["tail_envelope_family"] = fam.strip()
        _emit(anchor, template=_MSG_TRAILING, evidence=evidence)

    # --- durable-gap ---------------------------------------------------
    if durable_ordinals:
        min_d = min(durable_ordinals)
        max_d = max(durable_ordinals)
        gap_after: int | None = None
        for n in range(min_d, max_d):
            if n not in envelope_ordinals:
                gap_after = n
                break
        if gap_after is not None:
            # Anchor on the first marked record after the hole.
            gap_anchor: SessionEvent | None = None
            for ev, m in marked:
                o = m.get("ordinal")
                if isinstance(o, int) and not isinstance(o, bool) and o > gap_after:
                    gap_anchor = ev
                    break
            if gap_anchor is None:
                gap_anchor = marked[-1][0]
            _emit(
                gap_anchor,
                template=_MSG_GAP,
                evidence={
                    "divergence": "durable-gap",
                    "missing_ordinal": gap_after,
                    "expected_durable_ordinal": gap_after,
                    "last_durable_ordinal": max_d,
                },
            )

    # --- missing-required-field (#19661) -------------------------------
    reasoning_missing: list[tuple[SessionEvent, int | None]] = []
    reasoning_present = 0
    for ev, m in marked:
        if m.get("item_type") != "reasoning":
            continue
        if m.get("has_encrypted_content") is True:
            reasoning_present += 1
        elif m.get("has_encrypted_content") is False:
            o = m.get("ordinal")
            reasoning_missing.append(
                (ev, o if isinstance(o, int) and not isinstance(o, bool) else None)
            )
    if reasoning_missing and reasoning_present:
        # Mixed state proves the field is expected on this stream while
        # some reasoning items lack it — resume projection may drop it.
        first_ev, first_ord = reasoning_missing[0]
        _emit(
            first_ev,
            template=_MSG_FIELD,
            evidence={
                "divergence": "missing-required-field",
                "field": "encrypted_content",
                "item_family": "reasoning",
                "missing_count": len(reasoning_missing),
                "present_count": reasoning_present,
                "first_missing_ordinal": first_ord,
            },
        )

    return findings


__all__ = ["check_durable_prefix"]
