"""Side-effect-unknown abstention contract (TASK-017, DEV-013).

This module implements the safeguard gate that prevents automated session repair
from mutating history whenever:
1. SL203 (unsafe continuation across loss/corruption) is present (global refusal).
2. For conservative repair: the planned transformation cannot prove region-disjointness
   from ambiguous tool execution (dangling calls, unknown side-effects, unresolved results).
3. For salvage repair: any tool event in the session has unknown or possible external
   side effects without an explicit operator override.

Normative Note: Global vs. Scoped Side-Effect Abstention (DEV-013)
Automated session repair enforces side-effect safety at two distinct layers:
1. Global Gate (SL203): Unsafe continuation across loss (SL203) represents unresolved
   causal corruption. When SL203 is present, automated repair refuses all conservative
   and salvage transformations globally across the entire session ('SL203-refusal').
2. Scoped Gate (Conservative Recipes): For sessions containing side-effect-bearing tool
   calls without SL203, conservative repair does not refuse globally. Instead, each
   candidate repair step must prove region-disjointness: the step's affected record set
   (target records, relinked ancestors, and truncated spans) must have zero intersection
   with any event whose execution state is ambiguous (dangling calls, unknown side-effects,
   or unresolved results). If disjointness is proven, safe conservative repairs proceed
   cleanly. If the proof fails, repair fail-closes with 'side-effect-scope-unproven' at
   both planning and execution layers.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from sesslint.canonical import READ_ONLY_TOOL_NAMES
from sesslint.determinism import canonical_json_bytes
from sesslint.finding import Finding

TOOL_KINDS: Final[frozenset[str]] = frozenset({"tool_call", "tool_use", "tool_result"})
SAFE_SIDE_EFFECT: Final[str] = "none"


@dataclass(frozen=True, slots=True)
class Abstention:
    """Decision indicating whether automated repair must abstain from mutating a session."""

    abstain: bool
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Serialize abstention decision to standard dictionary."""
        return {
            "abstain": self.abstain,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True, slots=True)
class AffectedRegion:
    """Affected record region declared by a repair recipe for a plan step."""

    indices: frozenset[int] = frozenset()
    ids: frozenset[str] = frozenset()
    ranges: tuple[tuple[int, int], ...] = ()
    unproven: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.indices, frozenset):
            object.__setattr__(self, "indices", frozenset(self.indices))
        if not isinstance(self.ids, frozenset):
            object.__setattr__(self, "ids", frozenset(self.ids))
        if (
            isinstance(self.ranges, tuple)
            and len(self.ranges) == 2
            and isinstance(self.ranges[0], int)
            and isinstance(self.ranges[1], int)
        ):
            object.__setattr__(self, "ranges", (self.ranges,))

    def all_indices(self, total_len: int | None = None) -> frozenset[int]:
        """Compute the flat set of 0-based indices covered by indices and ranges."""
        res = set(self.indices)
        for start_ord, end_ord in self.ranges:
            if total_len is not None:
                start_c = max(0, start_ord)
                end_c = min(total_len - 1, end_ord)
                for i in range(start_c, end_c + 1):
                    res.add(i)
            else:
                for i in range(start_ord, end_ord + 1):
                    res.add(i)
        return frozenset(res)


@dataclass(frozen=True, slots=True)
class AmbiguousEvents:
    """Record indices and identifiers whose execution state is ambiguous."""

    indices: frozenset[int]
    ids: frozenset[str]
    reasons: tuple[str, ...] = ()


def _event_kind(ev: Any) -> str | None:
    k = getattr(ev, "kind", None)
    if k is None and isinstance(ev, Mapping):
        k = ev.get("kind")
    return str(k) if k is not None else None


def _event_id(ev: Any) -> str | None:
    i = getattr(ev, "id", None)
    if i is None and isinstance(ev, Mapping):
        i = ev.get("id")
    return str(i) if i is not None else None


def _event_corr_id(ev: Any) -> str | None:
    c = getattr(ev, "correlation_id", None)
    if c is None and isinstance(ev, Mapping):
        c = ev.get("correlation_id")
    return str(c) if c is not None else None


def _extract_side_effects(ev: Any, raw_kind: str | None = None) -> str:
    if raw_kind is None:
        raw_kind = _event_kind(ev)
    raw_se = getattr(ev, "side_effects", None)
    if raw_se is None and isinstance(ev, Mapping):
        raw_se = ev.get("side_effects")
    if raw_se is None:
        payload = getattr(ev, "payload", None)
        if payload is None and isinstance(ev, Mapping):
            payload = ev.get("payload")
        if isinstance(payload, Mapping):
            raw_se = payload.get("side_effects")
    if raw_se is None:
        extra = getattr(ev, "extra_fields", None)
        if extra is None and isinstance(ev, Mapping):
            extra = ev.get("extra_fields")
        if isinstance(extra, Mapping):
            raw_se = extra.get("side_effects")

    if raw_se is None and raw_kind == "tool_result":
        raw_se = SAFE_SIDE_EFFECT
    elif raw_se is None and raw_kind in ("tool_call", "tool_use"):
        tool_name = ""
        payload = getattr(ev, "payload", None)
        if payload is None and isinstance(ev, Mapping):
            payload = ev.get("payload")
        if isinstance(payload, Mapping):
            tool_name = str(payload.get("name") or payload.get("tool_name") or "").lower()
        if not tool_name:
            tool_name = str(
                getattr(ev, "name", "") or (ev.get("name") if isinstance(ev, Mapping) else "") or ""
            ).lower()
        if tool_name in READ_ONLY_TOOL_NAMES:
            raw_se = SAFE_SIDE_EFFECT

    return str(raw_se) if raw_se is not None else "unknown"


def _event_content_fingerprint(ev: Any) -> str:
    ch = getattr(ev, "content_hash", None)
    if ch is None and isinstance(ev, Mapping):
        ch = ev.get("content_hash")
    if isinstance(ch, str) and ch:
        return ch
    if hasattr(ev, "payload_hash"):
        return str(ev.payload_hash())
    payload = getattr(ev, "payload", None)
    if payload is None and isinstance(ev, Mapping):
        payload = ev.get("payload")
    if isinstance(payload, Mapping):
        return hashlib.sha256(canonical_json_bytes(payload, newline=False)).hexdigest()
    if hasattr(ev, "to_canonical_bytes"):
        return hashlib.sha256(ev.to_canonical_bytes()).hexdigest()
    if isinstance(ev, Mapping):
        return hashlib.sha256(canonical_json_bytes(ev, newline=False)).hexdigest()
    return hashlib.sha256(str(ev).encode("utf-8")).hexdigest()


def find_ambiguous_events(
    events: Sequence[Any],
    findings: Sequence[Finding] | None = None,
) -> AmbiguousEvents:
    """Identify all session events whose execution state is ambiguous.

    An event has ambiguous execution iff:
    - kind in ('tool_call', 'tool_use') AND:
      (side_effects == 'unknown' OR no paired tool_result OR paired result has execution unknown)
    - OR multiple calls share a correlation ID (SL103 reused ID)
    - OR orphan tool result without a paired call (SL101)
    - OR direct subject of an SL203 finding.
    """
    ambiguous_indices: set[int] = set()
    ambiguous_ids: set[str] = set()
    reasons: list[str] = []

    # 1. SL203 finding subjects
    if findings:
        for f in findings:
            if f.code == "SL203":
                if f.source and f.source.record_id:
                    ambiguous_ids.add(f.source.record_id)
                if f.evidence and isinstance(f.evidence, Mapping):
                    for k in ("record_ordinal", "at_index", "index"):
                        ord_val = f.evidence.get(k)
                        if isinstance(ord_val, int) and 0 <= ord_val < len(events):
                            ambiguous_indices.add(ord_val)
                    if isinstance(f.evidence.get("first_unsafe_index"), int):
                        first_unsafe = f.evidence["first_unsafe_index"]
                        for idx in range(max(0, first_unsafe), len(events)):
                            if _event_kind(events[idx]) in TOOL_KINDS:
                                ambiguous_indices.add(idx)
                                eid = _event_id(events[idx])
                                if eid:
                                    ambiguous_ids.add(eid)

    # 2. Tool pairing and side-effects evaluation
    calls_by_corr: dict[str, list[tuple[int, str | None, str, Any]]] = defaultdict(list)
    results_by_corr: dict[str, list[tuple[int, str | None, str, Any]]] = defaultdict(list)

    for idx, ev in enumerate(events):
        kind = _event_kind(ev)
        eid = _event_id(ev)
        corr = _event_corr_id(ev)
        se = _extract_side_effects(ev, kind)

        if kind in ("tool_call", "tool_use"):
            if corr is None:
                ambiguous_indices.add(idx)
                if eid:
                    ambiguous_ids.add(eid)
                reasons.append(f"unpaired-call-no-correlation at index {idx}")
            else:
                calls_by_corr[corr].append((idx, eid, se, ev))

        elif kind == "tool_result":
            if corr is None:
                ambiguous_indices.add(idx)
                if eid:
                    ambiguous_ids.add(eid)
                reasons.append(f"orphan-result-no-correlation at index {idx}")
            else:
                results_by_corr[corr].append((idx, eid, se, ev))

    all_corrs = set(calls_by_corr.keys()) | set(results_by_corr.keys())
    for corr in all_corrs:
        calls = calls_by_corr[corr]
        results = results_by_corr[corr]

        if len(calls) > 1:
            # Reused call ID (SL103): pairing is ambiguous
            for c_idx, c_id, _, _ in calls:
                ambiguous_indices.add(c_idx)
                if c_id:
                    ambiguous_ids.add(c_id)
            for r_idx, r_id, _, _ in results:
                ambiguous_indices.add(r_idx)
                if r_id:
                    ambiguous_ids.add(r_id)
            reasons.append(f"reused-correlation-{corr}")

        elif len(calls) == 1 and len(results) == 0:
            # Dangling call (SL102)
            c_idx, c_id, _, _ = calls[0]
            ambiguous_indices.add(c_idx)
            if c_id:
                ambiguous_ids.add(c_id)
            reasons.append(f"dangling-call-{corr} at index {c_idx}")

        elif len(calls) == 0 and len(results) > 0:
            # Orphan result (SL101)
            for r_idx, r_id, _, _ in results:
                ambiguous_indices.add(r_idx)
                if r_id:
                    ambiguous_ids.add(r_id)
            reasons.append(f"orphan-result-{corr}")

        elif len(results) > 1:
            # Check whether results are conflicting vs identical duplicate projections
            first_fp = _event_content_fingerprint(results[0][3])
            are_identical = all(_event_content_fingerprint(r[3]) == first_fp for r in results[1:])
            if not are_identical:
                # Conflicting results: execution outcome is ambiguous
                for c_idx, c_id, _, _ in calls:
                    ambiguous_indices.add(c_idx)
                    if c_id:
                        ambiguous_ids.add(c_id)
                for r_idx, r_id, _, _ in results:
                    ambiguous_indices.add(r_idx)
                    if r_id:
                        ambiguous_ids.add(r_id)
            else:
                # Identical duplicate projections: check tool_call side_effects & execution
                if calls:
                    c_idx, c_id, c_se, _ = calls[0]
                    if c_se == "unknown":
                        ambiguous_indices.add(c_idx)
                        if c_id:
                            ambiguous_ids.add(c_id)
                        for r_idx, r_id, _, _ in results:
                            ambiguous_indices.add(r_idx)
                            if r_id:
                                ambiguous_ids.add(r_id)
                        reasons.append(f"unknown-side-effects-{corr}")
                for r_idx, r_id, _, r_ev in results:
                    r_payload = getattr(r_ev, "payload", None)
                    if r_payload is None and isinstance(r_ev, Mapping):
                        r_payload = r_ev.get("payload")
                    if isinstance(r_payload, Mapping) and r_payload.get("execution") == "unknown":
                        ambiguous_indices.add(r_idx)
                        if r_id:
                            ambiguous_ids.add(r_id)
                        reasons.append(f"unknown-execution-{corr} at index {r_idx}")

        elif len(calls) == 1 and len(results) == 1:
            c_idx, c_id, c_se, c_ev = calls[0]
            r_idx, r_id, r_se, r_ev = results[0]

            if r_idx < c_idx:
                ambiguous_indices.add(c_idx)
                ambiguous_indices.add(r_idx)
                if c_id:
                    ambiguous_ids.add(c_id)
                if r_id:
                    ambiguous_ids.add(r_id)
                reasons.append(f"reversed-pairing-{corr} at indices ({r_idx}, {c_idx})")

            if c_se == "unknown":
                ambiguous_indices.add(c_idx)
                ambiguous_indices.add(r_idx)
                if c_id:
                    ambiguous_ids.add(c_id)
                if r_id:
                    ambiguous_ids.add(r_id)
                reasons.append(f"unknown-side-effects-{corr} at index {c_idx}")

            r_payload = getattr(r_ev, "payload", None)
            if r_payload is None and isinstance(r_ev, Mapping):
                r_payload = r_ev.get("payload")
            r_exec = None
            if isinstance(r_payload, Mapping):
                r_exec = r_payload.get("execution")
            if r_exec == "unknown":
                ambiguous_indices.add(c_idx)
                ambiguous_indices.add(r_idx)
                if c_id:
                    ambiguous_ids.add(c_id)
                if r_id:
                    ambiguous_ids.add(r_id)
                reasons.append(f"unknown-execution-{corr} at index {r_idx}")

    # Ensure bidirectional completeness between ambiguous_indices and ambiguous_ids
    for idx, ev in enumerate(events):
        eid = _event_id(ev)
        if idx in ambiguous_indices and eid:
            ambiguous_ids.add(eid)
        if eid and eid in ambiguous_ids:
            ambiguous_indices.add(idx)

    return AmbiguousEvents(
        indices=frozenset(ambiguous_indices),
        ids=frozenset(ambiguous_ids),
        reasons=tuple(reasons),
    )


def check_step_scope(
    step: Any,
    events: Sequence[Any],
    *,
    recipe_region_fn: Callable[[Any, Sequence[Any]], AffectedRegion] | None = None,
    findings: Sequence[Finding] | None = None,
    excludes_execution_dependence: bool = False,
    ambiguous: AmbiguousEvents | None = None,
) -> tuple[bool, str | None]:
    """Prove region-disjointness for a candidate repair step.

    Returns:
        (True, None) if the step's affected record set provably intersects no
        event with ambiguous execution or unexcluded side-effects.
        (False, 'side-effect-scope-unproven') if the proof fails (fail-closed).
    """
    # Doubt rule: missing region function -> unproven -> abstain
    if recipe_region_fn is None:
        return False, "side-effect-scope-unproven"

    try:
        region = recipe_region_fn(step, events)
    except Exception:
        # Doubt rule: exception in region computation -> unproven -> abstain
        return False, "side-effect-scope-unproven"

    if region is None or region.unproven:
        return False, "side-effect-scope-unproven"

    # Global SL203 check: SL203 presence blocks conservative repair
    if findings and any(f.code == "SL203" for f in findings):
        return False, "side-effect-scope-unproven"

    ambiguous_set = (
        ambiguous if ambiguous is not None else find_ambiguous_events(events, findings=findings)
    )

    aff_indices = set(region.all_indices(total_len=len(events)))
    aff_ids = set(region.ids)
    for idx in aff_indices:
        if 0 <= idx < len(events):
            eid = _event_id(events[idx])
            if eid:
                aff_ids.add(eid)
    for idx, ev in enumerate(events):
        eid = _event_id(ev)
        if eid and eid in aff_ids:
            aff_indices.add(idx)

    # Intersection proof against ambiguous events
    if aff_indices & ambiguous_set.indices:
        return False, "side-effect-scope-unproven"

    if aff_ids & ambiguous_set.ids:
        return False, "side-effect-scope-unproven"

    # Tool events inside affected region: completed calls with side-effects
    # inside the region must abstain unless the recipe explicitly excludes
    # execution dependence (DEV-013 doubt rule).
    for idx in aff_indices:
        if 0 <= idx < len(events):
            ev = events[idx]
            kind = _event_kind(ev)
            if kind in TOOL_KINDS:
                se = _extract_side_effects(ev, kind)
                if se != SAFE_SIDE_EFFECT and not excludes_execution_dependence:
                    return False, "side-effect-scope-unproven"

    return True, None


def should_abstain_from_repair(
    findings: Sequence[Finding],
    events: Sequence[Any],
    *,
    policy: str = "conservative",
    acknowledge_side_effects: bool = False,
    step: Any | None = None,
    recipe_region_fn: Callable[[Any, Sequence[Any]], AffectedRegion] | None = None,
    excludes_execution_dependence: bool = False,
) -> Abstention:
    """Determine whether automated repair must abstain from processing this session.

    Guarantees:
    - Pure function: no I/O, no mutation of inputs.
    - Abstains if any SL203 finding is present (hard refusal across both conservative and salvage).
    - Under conservative policy:
      - If step is provided: scoped evaluation against ambiguous tool events.
      - If step is None: SL203-only global refusal
        (conservative repair proceeds for disjoint repairs).
    - Under salvage policy: abstains if any tool event has non-'none' side_effects unless
      acknowledge_side_effects is True.
    - Content-free reason strings.
    """
    reasons: list[str] = []

    # Condition (a): Hard refusal on SL203 in BOTH conservative and salvage
    has_sl203 = any(f.code == "SL203" for f in findings)
    if has_sl203:
        reasons.append("SL203 present")
        return Abstention(abstain=True, reasons=tuple(reasons))

    # Condition (b): Policy-specific evaluation
    if policy == "salvage":
        if not acknowledge_side_effects:
            for idx, ev in enumerate(events):
                raw_kind = _event_kind(ev)
                if raw_kind in TOOL_KINDS:
                    raw_se = _extract_side_effects(ev, raw_kind)
                    if raw_se != SAFE_SIDE_EFFECT:
                        reasons.append(f"side-effect-{raw_se} at index {idx}")
    elif policy == "conservative":
        if step is not None:
            is_disjoint, refusal_reason = check_step_scope(
                step,
                events,
                recipe_region_fn=recipe_region_fn,
                findings=findings,
                excludes_execution_dependence=excludes_execution_dependence,
            )
            if not is_disjoint:
                reasons.append(refusal_reason or "side-effect-scope-unproven")

    return Abstention(
        abstain=bool(reasons),
        reasons=tuple(reasons),
    )


def must_abstain(
    findings: Sequence[Finding],
    events: Sequence[Any],
    *,
    allow_unknown_side_effects: bool = False,
) -> Abstention:
    """Determine whether automated repair must abstain from processing this session.

    Guarantees:
    - Pure function: no I/O, no mutation of inputs.
    - Abstains if any SL203 finding is present (hard refusal).
    - Abstains if any tool event has non-'none' side_effects (default is 'unknown')
      unless allow_unknown_side_effects is True.
    - Content-free reason strings.
    """
    reasons: list[str] = []

    has_sl203 = any(f.code == "SL203" for f in findings)
    if has_sl203:
        reasons.append("SL203 present")
        return Abstention(abstain=True, reasons=tuple(reasons))

    if not allow_unknown_side_effects:
        for idx, ev in enumerate(events):
            raw_kind = _event_kind(ev)
            if raw_kind in TOOL_KINDS:
                raw_se = _extract_side_effects(ev, raw_kind)
                if raw_se != SAFE_SIDE_EFFECT:
                    se_str = str(raw_se) if raw_se is not None else "unknown"
                    reasons.append(f"side-effect-{se_str} at index {idx}")

    return Abstention(
        abstain=bool(reasons),
        reasons=tuple(reasons),
    )


__all__ = [
    "SAFE_SIDE_EFFECT",
    "TOOL_KINDS",
    "Abstention",
    "AffectedRegion",
    "AmbiguousEvents",
    "check_step_scope",
    "find_ambiguous_events",
    "must_abstain",
    "should_abstain_from_repair",
]
