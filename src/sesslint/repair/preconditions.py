"""Precondition engine for deterministic repair planning (TASK-018).

This module defines the machine-checkable precondition predicates and context
required before a repair recipe may be assigned to a finding in a repair plan.

Guarantees:
- Pure functions: no I/O, no disk access, no mutation of inputs.
- Fail-fast validation of precondition names.
- Zero vendor dependencies.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from sesslint.finding import Finding, Repairability
from sesslint.policy.abstention import must_abstain
from sesslint.repair.fingerprint import canonical_json_bytes

_TOOL_KINDS: Final[frozenset[str]] = frozenset({"tool_call", "tool_use", "tool_result"})


@dataclass(frozen=True, slots=True)
class PreconditionContext:
    """Evaluation context passed to recipe precondition predicates."""

    findings: Sequence[Finding]
    events: Sequence[Any]
    profile: str
    source_hash: str
    finding: Finding | None = None
    policy: str = "conservative"
    acknowledge_side_effects: bool = False


def no_sl203(ctx: PreconditionContext) -> bool:
    """Precondition: session contains no SL203 (unsafe continuation across loss) findings."""
    return not any(f.code == "SL203" for f in ctx.findings)


def side_effects_known(ctx: PreconditionContext) -> bool:
    """Precondition: all tool events in session have safe side_effects == 'none'."""
    for ev in ctx.events:
        raw_kind = getattr(ev, "kind", None)
        if raw_kind is None and isinstance(ev, Mapping):
            raw_kind = ev.get("kind")
        if raw_kind in _TOOL_KINDS:
            raw_se = getattr(ev, "side_effects", None)
            if raw_se is None and isinstance(ev, Mapping):
                raw_se = ev.get("side_effects")
            if raw_se is None:
                payload = getattr(ev, "payload", None)
                if payload is None and isinstance(ev, Mapping):
                    payload = ev.get("payload")
                if isinstance(payload, Mapping):
                    raw_se = payload.get("side_effects")
            if raw_se != "none":
                return False
    return True


def repairability_is_safe_auto(ctx: PreconditionContext) -> bool:
    """Precondition: target finding has repairability in ('safe-auto', 'deterministic')."""
    if ctx.finding is None:
        return False
    rep = ctx.finding.repairability
    rep_val = rep.value if isinstance(rep, Repairability) else str(rep)
    return rep_val in ("safe-auto", "deterministic", Repairability.DETERMINISTIC.value)


def repairability_is_salvage(ctx: PreconditionContext) -> bool:
    """Precondition: target finding has repairability in ('salvage', 'lossy-explicit')."""
    if ctx.finding is None:
        return False
    rep = ctx.finding.repairability
    rep_val = rep.value if isinstance(rep, Repairability) else str(rep)
    return rep_val in ("salvage", "lossy-explicit", Repairability.LOSSY_EXPLICIT.value)


def source_hash_pinned(ctx: PreconditionContext) -> bool:
    """Precondition: source hash is present and conforms to SHA-256 hex format."""
    return bool(ctx.source_hash and len(ctx.source_hash) == 64)


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


def _event_parent_id(ev: Any) -> str | None:
    p = getattr(ev, "parent_id", None)
    if p is None and isinstance(ev, Mapping):
        p = ev.get("parent_id")
    return str(p) if p is not None else None


def _event_corr_id(ev: Any) -> str | None:
    c = getattr(ev, "correlation_id", None)
    if c is None and isinstance(ev, Mapping):
        c = ev.get("correlation_id")
    return str(c) if c is not None else None


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
        return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    if hasattr(ev, "to_canonical_bytes"):
        return hashlib.sha256(ev.to_canonical_bytes()).hexdigest()
    if isinstance(ev, Mapping):
        return hashlib.sha256(canonical_json_bytes(ev)).hexdigest()
    return hashlib.sha256(str(ev).encode("utf-8")).hexdigest()


def _event_canonical_hash(ev: Any) -> str:
    if hasattr(ev, "canonical_hash"):
        return str(ev.canonical_hash())
    if hasattr(ev, "to_canonical_bytes"):
        return hashlib.sha256(ev.to_canonical_bytes()).hexdigest()
    if isinstance(ev, Mapping):
        return hashlib.sha256(canonical_json_bytes(ev)).hexdigest()
    return hashlib.sha256(str(ev).encode("utf-8")).hexdigest()


def no_prior_safe_tool_after_cut(ctx: PreconditionContext) -> bool:
    """Precondition: valid cut index exists with no checkpoints in discarded suffix."""
    has_trigger = any(
        f.code == "SL203"
        or (f.code == "SL005" and getattr(f.severity, "value", str(f.severity)) == "fatal")
        for f in ctx.findings
    )
    if not has_trigger:
        return False

    abst = must_abstain(ctx.findings, ctx.events)
    if any(r.startswith("side-effect-") for r in abst.reasons):
        return False

    if not side_effects_known(ctx):
        return False

    cut: int | None = None
    if ctx.finding and ctx.finding.evidence and isinstance(ctx.finding.evidence, Mapping):
        c = ctx.finding.evidence.get("first_unsafe_index")
        if c is None:
            c = ctx.finding.evidence.get("at_index")
        if c is None:
            c = ctx.finding.evidence.get("index")
        if c is None:
            c = ctx.finding.evidence.get("entry_index")
        if isinstance(c, int) and not isinstance(c, bool):
            cut = c

    if cut is None:
        candidate_cuts: list[int] = []
        for f in ctx.findings:
            if f.code in ("SL203", "SL005") and f.evidence and isinstance(f.evidence, Mapping):
                v = (
                    f.evidence.get("first_unsafe_index")
                    or f.evidence.get("at_index")
                    or f.evidence.get("index")
                    or f.evidence.get("entry_index")
                )
                if isinstance(v, int) and not isinstance(v, bool):
                    candidate_cuts.append(v)
        if candidate_cuts:
            cut = min(candidate_cuts)

    if cut is None or cut <= 0 or cut >= len(ctx.events):
        return False

    for ev in ctx.events[cut:]:
        k = _event_kind(ev)
        if k == "checkpoint":
            return False

    return True


def adjacent_identical_duplicate(ctx: PreconditionContext) -> bool:
    """Precondition: adjacent events have equal content fingerprints, same kind, not boundary."""
    idx: int | None = None
    if ctx.finding and ctx.finding.evidence and isinstance(ctx.finding.evidence, Mapping):
        for k in ("at_index", "index", "first_index"):
            v = ctx.finding.evidence.get(k)
            if isinstance(v, int) and not isinstance(v, bool):
                idx = v
                break
        if idx is None:
            rec_idxs = ctx.finding.evidence.get("record_indexes")
            if isinstance(rec_idxs, Sequence) and not isinstance(rec_idxs, (str, bytes)):
                for r_idx in rec_idxs:
                    if isinstance(r_idx, int) and not isinstance(r_idx, bool):
                        idx = r_idx
                        break

    if idx is not None:
        if 0 <= idx < len(ctx.events) - 1:
            e1, e2 = ctx.events[idx], ctx.events[idx + 1]
            k1, k2 = _event_kind(e1), _event_kind(e2)
            if k1 == k2 and k1 not in ("checkpoint", "compaction_boundary"):
                if _event_content_fingerprint(e1) == _event_content_fingerprint(e2):
                    return True
        if 0 < idx < len(ctx.events):
            e1, e2 = ctx.events[idx - 1], ctx.events[idx]
            k1, k2 = _event_kind(e1), _event_kind(e2)
            if k1 == k2 and k1 not in ("checkpoint", "compaction_boundary"):
                if _event_content_fingerprint(e1) == _event_content_fingerprint(e2):
                    return True
        return False

    for i in range(len(ctx.events) - 1):
        e1, e2 = ctx.events[i], ctx.events[i + 1]
        k1, k2 = _event_kind(e1), _event_kind(e2)
        if k1 == k2 and k1 not in ("checkpoint", "compaction_boundary"):
            if _event_content_fingerprint(e1) == _event_content_fingerprint(e2):
                return True
    return False


def unique_parent_candidate(ctx: PreconditionContext) -> bool:
    """Precondition: exactly one non-self candidate parent matches prefix."""
    if not ctx.finding:
        return False
    evidence = ctx.finding.evidence if isinstance(ctx.finding.evidence, Mapping) else {}

    target_idx = evidence.get("index")
    if target_idx is None:
        target_idx = evidence.get("at_index")

    if (
        target_idx is None
        or not isinstance(target_idx, int)
        or isinstance(target_idx, bool)
        or not (0 <= target_idx < len(ctx.events))
    ):
        rec_id = ctx.finding.source.record_id or evidence.get("id")
        target_idx = next((i for i, e in enumerate(ctx.events) if _event_id(e) == rec_id), None)

    if target_idx is None or not (0 <= target_idx < len(ctx.events)):
        return False

    target_ev = ctx.events[target_idx]
    target_id = _event_id(target_ev)

    prefix = evidence.get("parent_fingerprint_prefix") or evidence.get("parent_id")
    if not prefix:
        prefix = _event_parent_id(target_ev)
    if not prefix:
        return False
    prefix_str = str(prefix)

    candidates: list[int] = []
    for i in range(target_idx):
        cand = ctx.events[i]
        c_id = _event_id(cand)
        if c_id == target_id:
            continue
        c_hash = _event_canonical_hash(cand)
        if (c_id and c_id.startswith(prefix_str)) or (c_hash and c_hash.startswith(prefix_str)):
            candidates.append(i)

    return len(candidates) == 1


def single_boundary_split(ctx: PreconditionContext) -> bool:
    """Precondition: clean tool pair has exactly one compaction boundary strictly between."""
    if not ctx.finding:
        return False
    evidence = ctx.finding.evidence if isinstance(ctx.finding.evidence, Mapping) else {}
    corr = evidence.get("correlation_id")
    if not corr:
        return False

    calls = [
        i
        for i, e in enumerate(ctx.events)
        if _event_kind(e) in ("tool_call", "tool_use") and _event_corr_id(e) == corr
    ]
    results = [
        i
        for i, e in enumerate(ctx.events)
        if _event_kind(e) == "tool_result" and _event_corr_id(e) == corr
    ]

    if len(calls) != 1 or len(results) != 1:
        return False

    min_idx = min(calls[0], results[0])
    max_idx = max(calls[0], results[0])

    boundaries = [
        i
        for i in range(min_idx + 1, max_idx)
        if _event_kind(ctx.events[i]) == "compaction_boundary"
    ]
    return len(boundaries) == 1


def duplicate_projection_identical(ctx: PreconditionContext) -> bool:
    """Precondition: two tool_results for correlation_id have identical fingerprints."""
    if not ctx.finding:
        return False
    evidence = ctx.finding.evidence if isinstance(ctx.finding.evidence, Mapping) else {}
    corr = evidence.get("correlation_id")
    if not corr:
        t_idx = evidence.get("at_index") or evidence.get("index") or evidence.get("result_index")
        if isinstance(t_idx, int) and not isinstance(t_idx, bool) and 0 <= t_idx < len(ctx.events):
            corr = _event_corr_id(ctx.events[t_idx])
    if not corr:
        return False

    results = [
        e for e in ctx.events if _event_kind(e) == "tool_result" and _event_corr_id(e) == corr
    ]
    if len(results) < 2:
        return False

    fp1 = _event_content_fingerprint(results[0])
    return any(_event_content_fingerprint(r) == fp1 for r in results[1:])


def salvage_policy(ctx: PreconditionContext) -> bool:
    """Precondition: planner is operating under explicit 'salvage' policy."""
    return ctx.policy == "salvage"


def acknowledge_side_effects(ctx: PreconditionContext) -> bool:
    """Precondition: operator explicitly acknowledged potential external side effects."""
    return bool(ctx.acknowledge_side_effects)


def _find_component_indices(events: Sequence[Any], seed_idx: int) -> set[int]:
    """Find all event indices in the weakly-connected parent component of seed_idx."""
    id_to_idx: dict[str, int] = {}
    for i, ev in enumerate(events):
        eid = _event_id(ev)
        if eid is not None:
            id_to_idx[eid] = i

    adj: dict[int, set[int]] = {i: set() for i in range(len(events))}
    for i, ev in enumerate(events):
        pid = _event_parent_id(ev)
        if pid is not None and pid in id_to_idx:
            p_idx = id_to_idx[pid]
            adj[i].add(p_idx)
            adj[p_idx].add(i)

    visited: set[int] = set()
    queue = [seed_idx]
    visited.add(seed_idx)
    while queue:
        curr = queue.pop(0)
        for neighbor in adj.get(curr, ()):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)
    return visited


def branch_has_no_checkpoint(ctx: PreconditionContext) -> bool:
    """Precondition: the weakly-connected branch containing target event has no checkpoints."""
    seed_idx: int | None = None
    if ctx.finding and ctx.finding.evidence and isinstance(ctx.finding.evidence, Mapping):
        for k in ("at_index", "index", "first_index", "entry_index"):
            v = ctx.finding.evidence.get(k)
            if isinstance(v, int) and not isinstance(v, bool) and 0 <= v < len(ctx.events):
                seed_idx = v
                break
        if seed_idx is None:
            rec_idxs = ctx.finding.evidence.get("record_indexes")
            if isinstance(rec_idxs, Sequence) and not isinstance(rec_idxs, (str, bytes)):
                for r_idx in rec_idxs:
                    if (
                        isinstance(r_idx, int)
                        and not isinstance(r_idx, bool)
                        and 0 <= r_idx < len(ctx.events)
                    ):
                        seed_idx = r_idx
                        break

    if seed_idx is None and ctx.finding and ctx.finding.source and ctx.finding.source.record_id:
        rec_id = ctx.finding.source.record_id
        for i, ev in enumerate(ctx.events):
            if _event_id(ev) == rec_id:
                seed_idx = i
                break

    if seed_idx is None:
        return not any(_event_kind(ev) == "checkpoint" for ev in ctx.events)

    component_indices = _find_component_indices(ctx.events, seed_idx)
    for idx in component_indices:
        if _event_kind(ctx.events[idx]) == "checkpoint":
            return False
    return True


def _find_torn_compaction_dropped_indices(
    events: Sequence[Any],
    boundary_idx: int,
) -> set[int]:
    """Find event indices to drop for torn compaction projection.

    Identifies split pairs and orphaned halves across boundary_idx, selects the
    minority side (tie-break prefers trailing side), and includes the boundary.

    Raises:
        ValueError: If boundary_idx is invalid, not a compaction_boundary,
            or the boundary has no split pairs or orphaned halves.
    """
    if not events:
        raise ValueError("Cannot project across compaction in empty session")
    if boundary_idx < 0 or boundary_idx >= len(events):
        raise ValueError(f"Invalid compaction boundary index {boundary_idx!r}")
    if _event_kind(events[boundary_idx]) != "compaction_boundary":
        raise ValueError(f"Event at index {boundary_idx} is not a compaction_boundary")

    calls_before: dict[str, list[int]] = {}
    results_before: dict[str, list[int]] = {}
    for i in range(boundary_idx):
        e = events[i]
        k = _event_kind(e)
        c = _event_corr_id(e)
        if c:
            if k in ("tool_call", "tool_use"):
                calls_before.setdefault(c, []).append(i)
            elif k == "tool_result":
                results_before.setdefault(c, []).append(i)

    calls_after: dict[str, list[int]] = {}
    results_after: dict[str, list[int]] = {}
    for i in range(boundary_idx + 1, len(events)):
        e = events[i]
        k = _event_kind(e)
        c = _event_corr_id(e)
        if c:
            if k in ("tool_call", "tool_use"):
                calls_after.setdefault(c, []).append(i)
            elif k == "tool_result":
                results_after.setdefault(c, []).append(i)

    orphans_A: set[int] = set()
    orphans_B: set[int] = set()

    all_corrs = (
        set(calls_before.keys())
        | set(results_before.keys())
        | set(calls_after.keys())
        | set(results_after.keys())
    )
    for corr in all_corrs:
        c_bef = calls_before.get(corr, [])
        r_bef = results_before.get(corr, [])
        c_aft = calls_after.get(corr, [])
        r_aft = results_after.get(corr, [])

        if c_bef and r_aft:
            orphans_A.update(c_bef)
            orphans_B.update(r_aft)
        elif c_aft and r_bef:
            orphans_A.update(r_bef)
            orphans_B.update(c_aft)
        elif c_bef and not r_bef and not c_aft and not r_aft:
            orphans_A.update(c_bef)
        elif r_aft and not c_aft and not c_bef and not r_bef:
            orphans_B.update(r_aft)

    if not orphans_A and not orphans_B:
        raise ValueError(
            f"Compaction boundary at index {boundary_idx} has no split pairs or orphaned halves"
        )

    if len(orphans_A) < len(orphans_B):
        minority = orphans_A
    else:
        minority = orphans_B

    return {boundary_idx} | minority


def sl108_present(ctx: PreconditionContext) -> bool:
    """Precondition: finding SL108 is present and compaction boundary exists with split/orphans."""
    if not any(f.code == "SL108" for f in ctx.findings):
        return False
    b_indices = [i for i, ev in enumerate(ctx.events) if _event_kind(ev) == "compaction_boundary"]
    if not b_indices:
        return False
    for b_idx in b_indices:
        try:
            _find_torn_compaction_dropped_indices(ctx.events, b_idx)
            return True
        except ValueError:
            continue
    return False


def torn_terminal_record(ctx: PreconditionContext) -> bool:
    """Precondition: finding SL002 is present on terminal incomplete record."""
    if ctx.finding is not None:
        return ctx.finding.code == "SL002"
    return any(f.code == "SL002" for f in ctx.findings)


PRECONDITION_FUNCS: dict[str, Callable[[PreconditionContext], bool]] = {
    "acknowledge_side_effects": acknowledge_side_effects,
    "adjacent_identical_duplicate": adjacent_identical_duplicate,
    "branch_has_no_checkpoint": branch_has_no_checkpoint,
    "duplicate_projection_identical": duplicate_projection_identical,
    "no_prior_safe_tool_after_cut": no_prior_safe_tool_after_cut,
    "no_sl203": no_sl203,
    "repairability_is_safe_auto": repairability_is_safe_auto,
    "repairability_is_salvage": repairability_is_salvage,
    "salvage_policy": salvage_policy,
    "side_effects_known": side_effects_known,
    "single_boundary_split": single_boundary_split,
    "sl108_present": sl108_present,
    "source_hash_pinned": source_hash_pinned,
    "torn_terminal_record": torn_terminal_record,
    "unique_parent_candidate": unique_parent_candidate,
}


def register_precondition(name: str, fn: Callable[[PreconditionContext], bool]) -> None:
    """Register a custom precondition predicate."""
    if not name or not isinstance(name, str):
        raise ValueError("Precondition name must be a non-empty string")
    PRECONDITION_FUNCS[name] = fn


def check_preconditions(
    names: Sequence[str],
    ctx: PreconditionContext,
) -> tuple[bool, str | None]:
    """Evaluate a sequence of precondition names against a context.

    Returns:
        (True, None) if all preconditions pass.
        (False, failed_name) on the first failing precondition.
    """
    for name in names:
        fn = PRECONDITION_FUNCS.get(name)
        if fn is None:
            raise ValueError(f"Unknown precondition: {name}")
        if not fn(ctx):
            return False, name
    return True, None


__all__ = [
    "PRECONDITION_FUNCS",
    "PreconditionContext",
    "_find_component_indices",
    "_find_torn_compaction_dropped_indices",
    "acknowledge_side_effects",
    "adjacent_identical_duplicate",
    "branch_has_no_checkpoint",
    "check_preconditions",
    "duplicate_projection_identical",
    "no_prior_safe_tool_after_cut",
    "no_sl203",
    "register_precondition",
    "repairability_is_safe_auto",
    "repairability_is_salvage",
    "salvage_policy",
    "side_effects_known",
    "single_boundary_split",
    "sl108_present",
    "source_hash_pinned",
    "torn_terminal_record",
    "unique_parent_candidate",
]
