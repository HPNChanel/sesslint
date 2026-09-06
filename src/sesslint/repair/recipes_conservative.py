"""Conservative repair recipe pack (TASK-019).

This module implements the five conservative (non-salvage, non-lossy-beyond-explicit)
repair recipes as pure event-list transforms:
1. terminal-suffix-discard: drop trailing events after the first unsafe index when
   every dropped event is after the last checkpoint and finding set includes SL203/SL005.
2. identical-duplicate-collapse: collapse two adjacent events with equal content
   fingerprints and matching kinds into one.
3. proven-unique-parent-restore: reattach an SL004 missing parent link when exactly
   one non-self candidate exists matching the prefix.
4. compaction-projection-reunion: relocate a compaction_boundary separating a clean
   call/result pair to immediately after the pair.
5. duplicate-projection-removal: drop the later of two identical tool_result projections
   for the same correlation ID.

Guarantees:
- Zero I/O, zero disk access, zero network calls.
- Pure functions: inputs are deep-copied and never mutated.
- No-synthetic-success: recipes NEVER construct a tool_result or invent success states.
- Dedicated PreconditionFailed exception raised on direct invalid application.
- Vendor-free: operates strictly on canonical event dictionaries.
"""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Mapping, Sequence
from typing import Any, Final

from sesslint.canonical import to_canonical_dict
from sesslint.codes import SL003, SL004, SL005, SL104, SL108, SL203
from sesslint.repair.fingerprint import canonical_json_bytes
from sesslint.repair.planner import PlanStep
from sesslint.repair.registry import Recipe, get_recipe, register_recipe


class PreconditionFailed(ValueError):
    """Raised when a repair recipe is applied directly to invalid events."""


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


def _to_event_dict(ev: Any) -> dict[str, Any]:
    if hasattr(ev, "to_canonical_dict"):
        return copy.deepcopy(ev.to_canonical_dict())
    if isinstance(ev, Mapping):
        return copy.deepcopy(dict(ev))
    try:
        return copy.deepcopy(to_canonical_dict(ev))
    except Exception:
        return copy.deepcopy(dict(ev))


def _copy_events_as_dicts(events: Sequence[Any]) -> list[dict[str, Any]]:
    return [_to_event_dict(e) for e in events]


# ---------------------------------------------------------------------------
# 1. Terminal Suffix Discard
# ---------------------------------------------------------------------------


def apply_terminal_suffix_discard(
    events: Sequence[Any],
    step: PlanStep,
) -> list[dict[str, Any]]:
    """Drop trailing events after the cut index.

    Raises:
        PreconditionFailed: If cut index is invalid, would empty the session,
            or if a checkpoint exists in the discarded suffix.
    """
    cut = step.target_index
    if cut is None and isinstance(step.params, Mapping):
        p_cut = step.params.get("cut_index")
        if isinstance(p_cut, int) and not isinstance(p_cut, bool):
            cut = p_cut

    if cut is None or not isinstance(cut, int) or isinstance(cut, bool):
        raise PreconditionFailed("terminal-suffix-discard: missing or invalid cut index")

    if cut <= 0:
        raise PreconditionFailed(
            f"terminal-suffix-discard: cut at index {cut} would empty session (refused)"
        )

    if cut >= len(events):
        raise PreconditionFailed(
            f"terminal-suffix-discard: cut at index {cut} >= session length {len(events)}"
        )

    # Validate that no checkpoint exists in the discarded tail
    for i, ev in enumerate(events[cut:], start=cut):
        if _event_kind(ev) == "checkpoint":
            raise PreconditionFailed(
                f"terminal-suffix-discard: checkpoint at index {i} cannot be discarded"
            )

    out = _copy_events_as_dicts(events[:cut])
    return out


terminal_suffix_discard = apply_terminal_suffix_discard


# ---------------------------------------------------------------------------
# 2. Identical Duplicate Collapse
# ---------------------------------------------------------------------------


def apply_identical_duplicate_collapse(
    events: Sequence[Any],
    step: PlanStep,
) -> list[dict[str, Any]]:
    """Collapse two adjacent identical duplicate events into one.

    Raises:
        PreconditionFailed: If no eligible identical duplicate pair exists.
    """
    if len(events) < 2:
        raise PreconditionFailed("identical-duplicate-collapse: requires at least 2 events")

    idx = step.target_index
    if idx is None and isinstance(step.params, Mapping):
        for k in ("at_index", "index", "first_index"):
            p_val = step.params.get(k)
            if isinstance(p_val, int) and not isinstance(p_val, bool):
                idx = p_val
                break

    if idx is not None and isinstance(idx, int) and not isinstance(idx, bool):
        if idx < 0 or idx >= len(events):
            raise PreconditionFailed(
                f"identical-duplicate-collapse: target index {idx} out of bounds"
            )

        # Check candidate pairs around idx: (idx, idx + 1) or (idx - 1, idx)
        candidate_pairs: list[tuple[int, int]] = []
        if idx < len(events) - 1:
            candidate_pairs.append((idx, idx + 1))
        if idx > 0:
            candidate_pairs.append((idx - 1, idx))

        # Check if any candidate pair is fully eligible
        for keep_i, drop_i in candidate_pairs:
            e1, e2 = events[keep_i], events[drop_i]
            k1, k2 = _event_kind(e1), _event_kind(e2)
            if k1 == k2 and k1 not in ("checkpoint", "compaction_boundary"):
                if _event_content_fingerprint(e1) == _event_content_fingerprint(e2):
                    out = _copy_events_as_dicts(events)
                    dropped = out.pop(drop_i)
                    kept_id = _event_id(out[keep_i])
                    dropped_id = _event_id(dropped)
                    if kept_id and dropped_id and kept_id != dropped_id:
                        for ev_dict in out:
                            if ev_dict.get("parent_id") == dropped_id:
                                ev_dict["parent_id"] = kept_id
                    return out

        # If none matched, report specific precondition failure on primary pair
        primary_keep, primary_drop = candidate_pairs[0]
        e1, e2 = events[primary_keep], events[primary_drop]
        k1, k2 = _event_kind(e1), _event_kind(e2)
        if k1 != k2:
            raise PreconditionFailed(
                f"identical-duplicate-collapse: kind mismatch between '{k1}' and '{k2}'"
            )
        if k1 in ("checkpoint", "compaction_boundary"):
            raise PreconditionFailed(
                f"identical-duplicate-collapse: cannot collapse boundary kind '{k1}'"
            )
        if _event_content_fingerprint(e1) != _event_content_fingerprint(e2):
            raise PreconditionFailed(
                "identical-duplicate-collapse: event content fingerprints differ"
            )
        raise PreconditionFailed("identical-duplicate-collapse: no eligible duplicate pair found")

    # Scan for first eligible adjacent duplicate pair
    for i in range(len(events) - 1):
        e1, e2 = events[i], events[i + 1]
        k1, k2 = _event_kind(e1), _event_kind(e2)
        if k1 == k2 and k1 not in ("checkpoint", "compaction_boundary"):
            if _event_content_fingerprint(e1) == _event_content_fingerprint(e2):
                out = _copy_events_as_dicts(events)
                dropped = out.pop(i + 1)
                kept_id = _event_id(out[i])
                dropped_id = _event_id(dropped)
                if kept_id and dropped_id and kept_id != dropped_id:
                    for ev_dict in out:
                        if ev_dict.get("parent_id") == dropped_id:
                            ev_dict["parent_id"] = kept_id
                return out

    raise PreconditionFailed("identical-duplicate-collapse: no eligible duplicate pair found")


identical_duplicate_collapse = apply_identical_duplicate_collapse


# ---------------------------------------------------------------------------
# 3. Proven Unique Parent Restore
# ---------------------------------------------------------------------------


def apply_proven_unique_parent_restore(
    events: Sequence[Any],
    step: PlanStep,
) -> list[dict[str, Any]]:
    """Reattach missing parent pointer when exactly one non-self candidate matches prefix.

    Raises:
        PreconditionFailed: If target index invalid or candidates != 1.
    """
    target_idx = step.target_index
    if target_idx is None and isinstance(step.params, Mapping):
        p_idx = step.params.get("index")
        if p_idx is None:
            p_idx = step.params.get("at_index")
        if isinstance(p_idx, int) and not isinstance(p_idx, bool):
            target_idx = p_idx

    if (
        target_idx is None
        or not isinstance(target_idx, int)
        or isinstance(target_idx, bool)
        or not (0 <= target_idx < len(events))
    ):
        raise PreconditionFailed("proven-unique-parent-restore: missing or invalid target_index")

    target_ev = events[target_idx]
    target_id = _event_id(target_ev)

    prefix: Any = None
    if isinstance(step.params, Mapping):
        prefix = step.params.get("parent_fingerprint_prefix") or step.params.get("parent_id")
    if not prefix:
        prefix = _event_parent_id(target_ev)

    if not prefix:
        raise PreconditionFailed("proven-unique-parent-restore: missing parent_fingerprint_prefix")
    prefix_str = str(prefix)

    candidates: list[int] = []
    for i in range(target_idx):
        cand = events[i]
        c_id = _event_id(cand)
        if c_id == target_id:
            continue
        c_hash = _event_canonical_hash(cand)
        if (c_id and c_id.startswith(prefix_str)) or (c_hash and c_hash.startswith(prefix_str)):
            candidates.append(i)

    if len(candidates) == 0:
        raise PreconditionFailed(
            f"proven-unique-parent-restore: zero candidates matching prefix '{prefix_str}'"
        )
    if len(candidates) > 1:
        raise PreconditionFailed(
            f"proven-unique-parent-restore: ambiguous candidates ({len(candidates)}) "
            f"matching '{prefix_str}'"
        )

    winning_cand = events[candidates[0]]
    winning_id = _event_id(winning_cand)
    if not winning_id:
        raise PreconditionFailed("proven-unique-parent-restore: candidate parent has empty ID")

    out = _copy_events_as_dicts(events)
    out[target_idx]["parent_id"] = winning_id
    return out


proven_unique_parent_restore = apply_proven_unique_parent_restore


# ---------------------------------------------------------------------------
# 4. Compaction Projection Reunion
# ---------------------------------------------------------------------------


def apply_compaction_projection_reunion(
    events: Sequence[Any],
    step: PlanStep,
) -> list[dict[str, Any]]:
    """Relocate a single compaction_boundary separating a tool pair to immediately after the pair.

    Raises:
        PreconditionFailed: If pair is not clean-cardinality or boundaries != 1.
    """
    corr: Any = None
    if isinstance(step.params, Mapping):
        corr = step.params.get("correlation_id")

    if not corr and step.target_index is not None and 0 <= step.target_index < len(events):
        corr = _event_corr_id(events[step.target_index])

    if not corr:
        raise PreconditionFailed("compaction-projection-reunion: missing correlation_id")
    corr_str = str(corr)

    calls = [
        i
        for i, e in enumerate(events)
        if _event_kind(e) in ("tool_call", "tool_use") and _event_corr_id(e) == corr_str
    ]
    results = [
        i
        for i, e in enumerate(events)
        if _event_kind(e) == "tool_result" and _event_corr_id(e) == corr_str
    ]

    if len(calls) != 1 or len(results) != 1:
        raise PreconditionFailed(
            f"compaction-projection-reunion: pair for correlation '{corr_str}' "
            "must have exactly 1 call and 1 result"
        )

    min_idx = min(calls[0], results[0])
    max_idx = max(calls[0], results[0])

    # Check if a boundary sits exactly at an endpoint or is targeted at an endpoint
    b_idx_hint = None
    if isinstance(step.params, Mapping):
        b_idx_hint = step.params.get("boundary_index")
    if b_idx_hint is None and step.target_index is not None:
        if (
            0 <= step.target_index < len(events)
            and _event_kind(events[step.target_index]) == "compaction_boundary"
        ):
            b_idx_hint = step.target_index

    if b_idx_hint is not None and (b_idx_hint == min_idx or b_idx_hint == max_idx):
        raise PreconditionFailed(
            "compaction-projection-reunion: boundary sits at pair endpoint (not strictly between)"
        )

    # Also check if boundary sits at endpoint
    if min_idx < len(events) and _event_kind(events[min_idx]) == "compaction_boundary":
        raise PreconditionFailed(
            "compaction-projection-reunion: boundary sits at pair endpoint (not strictly between)"
        )
    if max_idx < len(events) and _event_kind(events[max_idx]) == "compaction_boundary":
        raise PreconditionFailed(
            "compaction-projection-reunion: boundary sits at pair endpoint (not strictly between)"
        )

    boundaries = [
        i for i in range(min_idx + 1, max_idx) if _event_kind(events[i]) == "compaction_boundary"
    ]

    if len(boundaries) != 1:
        raise PreconditionFailed(
            f"compaction-projection-reunion: expected exactly 1 boundary strictly between pair, "
            f"found {len(boundaries)}"
        )

    b_idx = boundaries[0]
    out = _copy_events_as_dicts(events)
    boundary_ev = out.pop(b_idx)
    # After popping b_idx (< max_idx), max_idx shifted left by 1 to (max_idx - 1)
    # We want to place boundary immediately after the pair (after index max_idx - 1)
    # Therefore insert at index max_idx
    out.insert(max_idx, boundary_ev)
    return out


compaction_projection_reunion = apply_compaction_projection_reunion


# ---------------------------------------------------------------------------
# 5. Duplicate Projection Removal
# ---------------------------------------------------------------------------


def apply_duplicate_projection_removal(
    events: Sequence[Any],
    step: PlanStep,
) -> list[dict[str, Any]]:
    """Remove the later duplicate tool_result projection for the same correlation ID.

    Raises:
        PreconditionFailed: If results < 2 or fingerprints differ.
    """
    corr: Any = None
    if isinstance(step.params, Mapping):
        corr = step.params.get("correlation_id")

    if not corr and step.target_index is not None and 0 <= step.target_index < len(events):
        corr = _event_corr_id(events[step.target_index])

    if not corr:
        raise PreconditionFailed("duplicate-projection-removal: missing correlation_id")
    corr_str = str(corr)

    results = [
        (i, e)
        for i, e in enumerate(events)
        if _event_kind(e) == "tool_result" and _event_corr_id(e) == corr_str
    ]

    if len(results) < 2:
        raise PreconditionFailed(
            f"duplicate-projection-removal: expected at least 2 results for "
            f"correlation '{corr_str}', found {len(results)}"
        )

    idx1, res1 = results[0]
    fp1 = _event_content_fingerprint(res1)

    target_cand: tuple[int, Any] | None = None
    if step.target_index is not None:
        for idx_cand, res_cand in results[1:]:
            if idx_cand == step.target_index:
                target_cand = (idx_cand, res_cand)
                break

    if target_cand is not None:
        drop_idx, res2 = target_cand
        if _event_content_fingerprint(res2) != fp1:
            raise PreconditionFailed(
                "duplicate-projection-removal: projection fingerprints differ "
                "(refusing near-match collapse)"
            )
    else:
        # Match first subsequent result with equal fingerprint
        matched_pair: tuple[int, Any] | None = None
        for idx_cand, res_cand in results[1:]:
            if _event_content_fingerprint(res_cand) == fp1:
                matched_pair = (idx_cand, res_cand)
                break

        if matched_pair is None:
            raise PreconditionFailed(
                "duplicate-projection-removal: projection fingerprints differ "
                "(refusing near-match collapse)"
            )
        drop_idx, res2 = matched_pair

    r1_id = _event_id(res1)
    r2_id = _event_id(res2)
    out = _copy_events_as_dicts(events)
    out.pop(drop_idx)

    # Update any child references to the removed duplicate result
    if r1_id and r2_id and r1_id != r2_id:
        for ev_dict in out:
            if ev_dict.get("parent_id") == r2_id:
                ev_dict["parent_id"] = r1_id

    return out


duplicate_projection_removal = apply_duplicate_projection_removal


# ---------------------------------------------------------------------------
# Recipe Registry Definitions
# ---------------------------------------------------------------------------

RECIPE_TERMINAL_SUFFIX_DISCARD: Final[Recipe] = Recipe(
    name="terminal-suffix-discard",
    handles=(SL005, SL203),
    preconditions=("no_prior_safe_tool_after_cut",),
    lossy=True,
    salvage_only=False,
    apply=apply_terminal_suffix_discard,
)

RECIPE_IDENTICAL_DUPLICATE_COLLAPSE: Final[Recipe] = Recipe(
    name="identical-duplicate-collapse",
    handles=(SL003,),
    preconditions=("no_sl203", "adjacent_identical_duplicate"),
    lossy=False,
    salvage_only=False,
    apply=apply_identical_duplicate_collapse,
)

RECIPE_PROVEN_UNIQUE_PARENT_RESTORE: Final[Recipe] = Recipe(
    name="proven-unique-parent-restore",
    handles=(SL004,),
    preconditions=("no_sl203", "unique_parent_candidate"),
    lossy=False,
    salvage_only=False,
    apply=apply_proven_unique_parent_restore,
)

RECIPE_COMPACTION_PROJECTION_REUNION: Final[Recipe] = Recipe(
    name="compaction-projection-reunion",
    handles=(SL108,),
    preconditions=("no_sl203", "single_boundary_split"),
    lossy=False,
    salvage_only=False,
    apply=apply_compaction_projection_reunion,
)

RECIPE_DUPLICATE_PROJECTION_REMOVAL: Final[Recipe] = Recipe(
    name="duplicate-projection-removal",
    handles=(SL104,),
    preconditions=("no_sl203", "duplicate_projection_identical"),
    lossy=False,
    salvage_only=False,
    apply=apply_duplicate_projection_removal,
)

RECIPES: Final[tuple[Recipe, ...]] = (
    RECIPE_TERMINAL_SUFFIX_DISCARD,
    RECIPE_IDENTICAL_DUPLICATE_COLLAPSE,
    RECIPE_PROVEN_UNIQUE_PARENT_RESTORE,
    RECIPE_COMPACTION_PROJECTION_REUNION,
    RECIPE_DUPLICATE_PROJECTION_REMOVAL,
)
CONSERVATIVE_RECIPES: Final[tuple[Recipe, ...]] = RECIPES


def register_all() -> None:
    """Register all five conservative recipes into the repair registry."""
    for r in RECIPES:
        if get_recipe(r.name) is None:
            register_recipe(r)


__all__ = [
    "CONSERVATIVE_RECIPES",
    "PreconditionFailed",
    "RECIPES",
    "RECIPE_COMPACTION_PROJECTION_REUNION",
    "RECIPE_DUPLICATE_PROJECTION_REMOVAL",
    "RECIPE_IDENTICAL_DUPLICATE_COLLAPSE",
    "RECIPE_PROVEN_UNIQUE_PARENT_RESTORE",
    "RECIPE_TERMINAL_SUFFIX_DISCARD",
    "apply_compaction_projection_reunion",
    "apply_duplicate_projection_removal",
    "apply_identical_duplicate_collapse",
    "apply_proven_unique_parent_restore",
    "apply_terminal_suffix_discard",
    "compaction_projection_reunion",
    "duplicate_projection_removal",
    "identical_duplicate_collapse",
    "proven_unique_parent_restore",
    "register_all",
    "terminal_suffix_discard",
]
