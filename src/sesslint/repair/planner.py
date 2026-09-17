"""Deterministic repair planner and plan data structures (TASK-018).

This module implements the dry-run repair planning core. It evaluates findings
against registered recipes and preconditions to produce a deterministic,
fingerprinted RepairPlan with zero disk writes.

Guarantees:
- Zero I/O, zero file writes: strictly in-memory computation.
- Hard refusal on SL203: returns an empty plan with all findings blocked as 'SL203-refusal'.
- Deterministic ordering: steps sorted by (target_index, recipe, finding_fp).
- Bounded capacity: capped at 256 steps; excess findings blocked as 'cap-overflow'.
- Stable 64-character SHA-256 fingerprint.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, cast

from sesslint._events import _event_id, _event_kind
from sesslint.finding import Finding, Repairability
from sesslint.policy.abstention import (
    check_step_scope,
    find_ambiguous_events,
    must_abstain,
    should_abstain_from_repair,
)
from sesslint.repair.fingerprint import canonical_json_bytes, compute_plan_fingerprint
from sesslint.repair.preconditions import (
    PreconditionContext,
    _find_component_indices,
    _find_torn_compaction_dropped_indices,
    check_preconditions,
)
from sesslint.repair.recipes_sl002 import register_all as register_all_sl002_recipes
from sesslint.repair.refusals import RefusalRationale, refusal_rationale_for
from sesslint.repair.registry import recipes_for

MAX_STEPS: Final[int] = 256
PLAN_VERSION: Final[str] = "sesslint.plan/v1"
EMPTY_EVENTS_HASH: Final[str] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

ALLOWED_LOSS_CLASSES: Final[frozenset[str]] = frozenset(
    {
        "amputated-branch",
        "discarded-suffix",
        "none",
        "orphan-result",
        "projected-orphans",
        "truncated-projection",
        "truncated-side-effects",
    }
)


@dataclass(frozen=True, slots=True)
class PlanStep:
    """An individual proposed repair step in a repair plan."""

    seq: int
    recipe: str
    target_finding_fp: str
    target_index: int | None
    params: Mapping[str, Any] = field(default_factory=dict)
    lossy: bool = False
    loss: Mapping[str, int] = field(default_factory=dict)
    min_policy: str = "conservative"
    recipe_version: str = "1.0.0"

    def __post_init__(self) -> None:
        """Validate step fields and ensure loss classes are in allowlist."""
        for k in self.loss:
            if k not in ALLOWED_LOSS_CLASSES:
                raise ValueError(
                    f"Invalid loss class: {k!r}. Must be one of {sorted(ALLOWED_LOSS_CLASSES)}"
                )

    def to_dict(self) -> dict[str, Any]:
        """Serialize plan step to dictionary."""
        d: dict[str, Any] = {
            "min_policy": self.min_policy,
            "params": dict(self.params),
            "recipe": self.recipe,
            "recipe_version": self.recipe_version,
            "seq": self.seq,
            "target_finding_fp": self.target_finding_fp,
            "target_index": self.target_index,
        }
        if self.lossy and self.loss:
            d["lossy"] = self.lossy
            d["loss"] = dict(self.loss)
        return d

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PlanStep:
        """Deserialize a plan step, requiring execution-safety fields (DW-T-08).

        ``seq``, ``recipe``, ``min_policy``, and ``recipe_version`` are required:
        silently defaulting ``min_policy`` would let a salvage-gated step pass a
        conservative policy check, so plans missing them fail closed.
        """
        for field_name in ("seq", "recipe", "min_policy", "recipe_version"):
            if field_name not in data:
                raise ValueError(f"Plan step missing required field {field_name!r}")
        return cls(
            seq=int(data["seq"]),
            recipe=str(data["recipe"]),
            target_finding_fp=str(data.get("target_finding_fp", "")),
            target_index=data.get("target_index"),
            params=dict(data.get("params", {})),
            lossy=bool(data.get("lossy", False)),
            loss=dict(data.get("loss", {})),
            min_policy=str(data["min_policy"]),
            recipe_version=str(data["recipe_version"]),
        )


@dataclass(frozen=True, slots=True)
class Blocked:
    """Record of a finding that could not be automatically planned.

    'reason' is the stable machine token serialized into plans and fingerprints.
    'describe()' adds the documented, content-free refusal rationale for human
    surfaces without changing any serialized or fingerprinted field.
    """

    finding_fp: str
    code: str
    reason: str

    @property
    def refusal(self) -> RefusalRationale | None:
        """Documented refusal rationale for this code, if one is registered."""
        return refusal_rationale_for(self.code)

    def describe(self) -> str:
        """Human-readable detail: stable reason plus documented refusal rationale.

        Content-free: never embeds session data, only policy-level rationale and
        DEMAND citations. Falls back to the bare machine reason when the code has
        no registered refusal rationale.
        """
        entry = self.refusal
        if entry is None:
            return self.reason
        return f"{self.reason}: {entry.render()}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize blocked finding record to dictionary."""
        return {
            "code": self.code,
            "finding_fp": self.finding_fp,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Blocked:
        """Deserialize a blocked-finding record."""
        return cls(
            finding_fp=str(data.get("finding_fp", "")),
            code=str(data.get("code", "")),
            reason=str(data.get("reason", "")),
        )


@dataclass(frozen=True, slots=True)
class Loss:
    """Preview of anticipated data loss counts for the proposed plan."""

    preview: Mapping[str, int] = field(
        default_factory=lambda: {
            "discarded-suffix": 0,
            "none": 0,
            "truncated-projection": 0,
        }
    )
    total_lost: int = 0
    total_kept: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize loss accounting preview to dictionary."""
        return {
            "preview": dict(self.preview),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Loss:
        """Deserialize loss accounting, tolerating absent totals."""
        loss_preview = data.get("preview", {})
        return cls(
            preview=dict(loss_preview),
            total_lost=int(data.get("total_lost", 0)),
            total_kept=int(data.get("total_kept", 0)),
        )


@dataclass(frozen=True, slots=True)
class RepairPlan:
    """Complete deterministic dry-run proposal for session repair."""

    source_hash: str
    profile: str
    steps: tuple[PlanStep, ...]
    blocked: tuple[Blocked, ...]
    loss_accounting: Loss
    fingerprint: str
    version: str = PLAN_VERSION
    policy: str = "conservative"

    @property
    def total_lost(self) -> int:
        """Total count of lost events."""
        return self.loss_accounting.total_lost

    @property
    def total_kept(self) -> int:
        """Total count of kept events."""
        return self.loss_accounting.total_kept

    def to_dict(self) -> dict[str, Any]:
        """Serialize full repair plan to dictionary."""
        d: dict[str, Any] = {
            "blocked": [b.to_dict() for b in self.blocked],
            "fingerprint": self.fingerprint,
            "loss_accounting": self.loss_accounting.to_dict(),
            "profile": self.profile,
            "source_hash": self.source_hash,
            "steps": [s.to_dict() for s in self.steps],
            "version": self.version,
        }
        if self.policy != "conservative":
            d["policy"] = self.policy
            d["loss_accounting"]["total_lost"] = self.loss_accounting.total_lost
            d["loss_accounting"]["total_kept"] = self.loss_accounting.total_kept
        return d

    @classmethod
    def from_dict(cls, raw_data: Mapping[str, Any]) -> RepairPlan:
        """Deserialize a RepairPlan from a dictionary (single authoritative path, DW-T-08).

        Accepts an optional ``{"expected_plan": {...}}`` wrapper. A missing or
        non-string ``fingerprint`` is recomputed over the (unwrapped) plan
        dictionary. Required fields are enforced per :meth:`PlanStep.from_dict`.
        """
        data = dict(raw_data)
        if "expected_plan" in data and isinstance(data["expected_plan"], Mapping):
            data = dict(data["expected_plan"])

        steps_list = [PlanStep.from_dict(s) for s in data.get("steps", [])]
        blocked_list = [Blocked.from_dict(b) for b in data.get("blocked", [])]
        loss = Loss.from_dict(data.get("loss_accounting", {}))

        fingerprint = data.get("fingerprint")
        if not fingerprint or not isinstance(fingerprint, str):
            fingerprint = compute_plan_fingerprint(data)

        return cls(
            source_hash=str(data.get("source_hash", "")),
            profile=str(data.get("profile", "neutral")),
            steps=tuple(steps_list),
            blocked=tuple(blocked_list),
            loss_accounting=loss,
            fingerprint=str(fingerprint),
            version=str(data.get("version", PLAN_VERSION)),
            policy=str(data.get("policy", "conservative")),
        )


def compute_events_source_hash(events: Sequence[Any]) -> str:
    """Compute deterministic SHA-256 digest over sequence of canonical events."""
    if not events:
        return EMPTY_EVENTS_HASH

    hasher = hashlib.sha256()
    for ev in events:
        if hasattr(ev, "to_canonical_bytes"):
            hasher.update(ev.to_canonical_bytes())
        elif isinstance(ev, Mapping):
            hasher.update(canonical_json_bytes(ev, newline=False))
        else:
            hasher.update(str(ev).encode("utf-8"))
    return hasher.hexdigest()


def _resolve_target_index(f: Finding, events: Sequence[Any] | None = None) -> int | None:
    """Extract 0-based target event index from finding evidence or record ID."""
    if f.evidence and isinstance(f.evidence, Mapping):
        for key in (
            "at_index",
            "first_unsafe_index",
            "index",
            "first_index",
            "cut_index",
            "boundary_index",
            "entry_index",
            "use_index",
        ):
            val = f.evidence.get(key)
            if isinstance(val, int) and not isinstance(val, bool):
                return val
        for list_key in ("record_indexes", "result_indexes"):
            vals = f.evidence.get(list_key)
            if isinstance(vals, Sequence) and not isinstance(vals, (str, bytes)):
                for v in vals:
                    if isinstance(v, int) and not isinstance(v, bool):
                        return v

    if events is not None:
        rec_id: Any = None
        if f.evidence and isinstance(f.evidence, Mapping):
            rec_id = f.evidence.get("root_id") or f.evidence.get("event_id")
        if rec_id is None and f.source and f.source.record_id:
            rec_id = f.source.record_id
        if rec_id is not None:
            rec_id_str = str(rec_id)
            for i, ev in enumerate(events):
                if _event_id(ev) == rec_id_str:
                    return i

    return None


def _compute_torn_compaction_loss(events: Sequence[Any], boundary_idx: int) -> int:
    """Compute count of dropped events for torn compaction project."""
    if boundary_idx < 0 or boundary_idx >= len(events):
        return 1
    try:
        dropped = _find_torn_compaction_dropped_indices(events, boundary_idx)
        return len(dropped)
    except ValueError:
        return 1


def plan(
    findings: Sequence[Finding],
    events: Sequence[Any],
    *,
    profile: Any = "neutral",
    source_hash: str | None = None,
    policy: str = "conservative",
    acknowledge_side_effects: bool = False,
) -> RepairPlan:
    """Generate a deterministic, fingerprinted dry-run repair plan.

    Guarantees:
    - Pure in-memory computation: zero writes, zero file touches.
    - If SL203 is present, all findings are blocked with reason 'SL203-refusal'.
    - Manual/unknown repairability findings are blocked with pinned reasons.
    - Out-of-bounds target indices are blocked as 'target-missing'.
    - Duplicate finding fingerprints are deduplicated to single step candidates.
    - Capped at MAX_STEPS (256); excess findings blocked as 'cap-overflow'.
    - Salvage recipes require explicit policy='salvage'.
    """
    if policy not in ("conservative", "salvage"):
        raise ValueError(f"Invalid repair policy: {policy!r}. Must be 'conservative' or 'salvage'")

    resolved_source_hash = (
        source_hash if source_hash is not None else compute_events_source_hash(events)
    )
    profile_name = getattr(profile, "name", str(profile))

    # Register SL002 torn-terminal-record recipe
    register_all_sl002_recipes()

    # 1. Deduplicate findings by fingerprint (preserving first encounter)
    unique_findings: list[Finding] = []
    seen_fps: set[str] = set()
    for f in findings:
        if f.fingerprint not in seen_fps:
            seen_fps.add(f.fingerprint)
            unique_findings.append(f)

    # Sort unique findings by fingerprint for deterministic processing order
    sorted_findings = sorted(unique_findings, key=lambda x: x.fingerprint)

    # 2. Hard refusal gate on SL203 (RVW-011)
    abstention = should_abstain_from_repair(
        findings,
        events,
        policy=policy,
        acknowledge_side_effects=acknowledge_side_effects,
    )

    has_sl203 = any(f.code == "SL203" for f in findings) or any(
        r == "SL203 present" for r in abstention.reasons
    )
    if has_sl203:
        blocked_sl203 = tuple(
            Blocked(finding_fp=f.fingerprint, code=f.code, reason="SL203-refusal")
            for f in sorted_findings
        )
        empty_loss = Loss(
            preview={
                "discarded-suffix": 0,
                "none": 0,
                "truncated-projection": 0,
            },
            total_lost=0,
            total_kept=len(events),
        )
        empty_plan_dict: dict[str, Any] = {
            "blocked": [b.to_dict() for b in blocked_sl203],
            "loss_accounting": empty_loss.to_dict(),
            "profile": profile_name,
            "source_hash": resolved_source_hash,
            "steps": [],
            "version": PLAN_VERSION,
        }
        if policy != "conservative":
            empty_plan_dict["policy"] = policy
            empty_plan_dict["loss_accounting"]["total_lost"] = 0
            empty_plan_dict["loss_accounting"]["total_kept"] = len(events)
        fp = compute_plan_fingerprint(empty_plan_dict)
        return RepairPlan(
            version=PLAN_VERSION,
            source_hash=resolved_source_hash,
            profile=profile_name,
            steps=(),
            blocked=blocked_sl203,
            loss_accounting=empty_loss,
            fingerprint=fp,
            policy=policy,
        )

    # 3. Partition findings and match recipes
    candidate_steps: list[
        tuple[int | None, str, str, str, Mapping[str, Any], bool, Mapping[str, int], str, str]
    ] = []
    blocked_items: list[Blocked] = []
    num_events = len(events)

    global_abst = must_abstain(sorted_findings, events) if policy == "conservative" else None
    precomputed_ambiguous = (
        find_ambiguous_events(events, findings=sorted_findings)
        if policy == "conservative"
        else None
    )

    for f in sorted_findings:
        target_idx = _resolve_target_index(f, events=events)

        # Check target index bounds if index is specified
        if target_idx is not None:
            if target_idx < 0 or target_idx >= num_events:
                blocked_items.append(
                    Blocked(
                        finding_fp=f.fingerprint,
                        code=f.code,
                        reason="target-missing",
                    )
                )
                continue

        # Check repairability classification
        rep_val = (
            f.repairability.value
            if isinstance(f.repairability, Repairability)
            else str(f.repairability)
        )

        if rep_val in ("unsupported", Repairability.UNSUPPORTED.value):
            blocked_items.append(
                Blocked(
                    finding_fp=f.fingerprint,
                    code=f.code,
                    reason="repairability-unsupported",
                )
            )
            continue

        if rep_val in ("unknown",):
            blocked_items.append(
                Blocked(
                    finding_fp=f.fingerprint,
                    code=f.code,
                    reason="repairability-unknown",
                )
            )
            continue

        # Match registered recipes
        available_recipes = recipes_for(f.code)
        if not available_recipes:
            blocked_items.append(
                Blocked(
                    finding_fp=f.fingerprint,
                    code=f.code,
                    reason="no-recipe",
                )
            )
            continue

        if policy == "conservative" and all(r.salvage_only for r in available_recipes):
            blocked_items.append(
                Blocked(
                    finding_fp=f.fingerprint,
                    code=f.code,
                    reason="needs-salvage-policy",
                )
            )
            continue

        if (
            rep_val
            in (
                "lossy-explicit",
                Repairability.LOSSY_EXPLICIT.value,
                "salvage",
            )
            and policy != "salvage"
        ):
            blocked_items.append(
                Blocked(
                    finding_fp=f.fingerprint,
                    code=f.code,
                    reason="needs-salvage-policy",
                )
            )
            continue

        if rep_val in ("manual", Repairability.MANUAL.value):
            if policy == "salvage" and any(r.salvage_only for r in available_recipes):
                pass
            else:
                blocked_items.append(
                    Blocked(
                        finding_fp=f.fingerprint,
                        code=f.code,
                        reason="repairability-manual",
                    )
                )
                continue

        if rep_val not in (
            "safe-auto",
            "salvage",
            "deterministic",
            "lossy-explicit",
            "manual",
            Repairability.DETERMINISTIC.value,
            Repairability.LOSSY_EXPLICIT.value,
            Repairability.MANUAL.value,
        ):
            blocked_items.append(
                Blocked(
                    finding_fp=f.fingerprint,
                    code=f.code,
                    reason="repairability-unsupported",
                )
            )
            continue

        # Check preconditions (first-match-wins)
        matched_recipe: Any = None
        last_failed_precondition: str | None = None

        ctx = PreconditionContext(
            findings=findings,
            events=events,
            profile=profile_name,
            source_hash=resolved_source_hash,
            finding=f,
            policy=policy,
            acknowledge_side_effects=acknowledge_side_effects,
        )

        for recipe in available_recipes:
            passed, failed_prec = check_preconditions(recipe.preconditions, ctx)
            if passed:
                matched_recipe = recipe
                break
            last_failed_precondition = failed_prec

        if matched_recipe is None:
            if last_failed_precondition == "salvage_policy":
                reason_str = "needs-salvage-policy"
            elif last_failed_precondition == "acknowledge_side_effects":
                reason_str = "needs-acknowledgement"
            elif last_failed_precondition:
                reason_str = f"precondition-failed:{last_failed_precondition}"
            else:
                reason_str = "precondition-failed"
            blocked_items.append(
                Blocked(
                    finding_fp=f.fingerprint,
                    code=f.code,
                    reason=reason_str,
                )
            )
            continue

        # Guard: component size limit for amputation (10k events)
        if matched_recipe.name == "unresolvable-branch-amputate":
            seed_idx = target_idx if target_idx is not None else 0
            comp = _find_component_indices(events, seed_idx)
            if len(comp) > 10_000:
                blocked_items.append(
                    Blocked(
                        finding_fp=f.fingerprint,
                        code=f.code,
                        reason="component-too-large",
                    )
                )
                continue

        step_params: dict[str, Any] = {}
        if f.evidence and isinstance(f.evidence, Mapping):
            for p_key in (
                "correlation_id",
                "parent_fingerprint_prefix",
                "parent_id",
                "cut_index",
                "boundary_index",
            ):
                if p_key in f.evidence and f.evidence[p_key] is not None:
                    step_params[p_key] = f.evidence[p_key]

        # Calculate step loss delta
        step_loss: dict[str, int] = {}
        if matched_recipe.name == "terminal-suffix-discard" and target_idx is not None:
            step_loss = {"discarded-suffix": max(0, len(events) - target_idx)}
        elif matched_recipe.name == "unresolvable-branch-amputate":
            seed_idx = target_idx if target_idx is not None else 0
            step_loss = {"amputated-branch": len(_find_component_indices(events, seed_idx))}
        elif matched_recipe.name == "torn-compaction-project":
            b_idx = target_idx if target_idx is not None else step_params.get("boundary_index")
            if b_idx is None:
                b_idxs = [
                    i for i, e in enumerate(events) if _event_kind(e) == "compaction_boundary"
                ]
                b_idx = b_idxs[0] if b_idxs else 0
            step_loss = {"projected-orphans": _compute_torn_compaction_loss(events, b_idx)}
        elif matched_recipe.name == "side-effect-unknown-truncate":
            cut_idx = target_idx
            if cut_idx is None:
                cut_idx = step_params.get("first_unsafe_index") or step_params.get("cut_index")
            eff_idx = cut_idx if cut_idx is not None else 0
            step_loss = {"truncated-side-effects": max(0, len(events) - eff_idx)}
        elif matched_recipe.name == "orphan-result-drop":
            step_loss = {"orphan-result": 1}
        elif matched_recipe.lossy:
            step_loss = {"none": 0}

        # Validate step loss keys against allowlist
        for k in step_loss:
            if k not in ALLOWED_LOSS_CLASSES:
                raise ValueError(
                    f"Invalid loss class: {k!r}. Must be one of {sorted(ALLOWED_LOSS_CLASSES)}"
                )

        # Abstention check:
        # If matched recipe declares affected_region, enforce transformation-scoped gate (DEV-013).
        # If recipe does not declare affected_region, fall back to global gating.
        reg_fn = getattr(matched_recipe, "affected_region", None)
        if policy == "conservative":
            if reg_fn is not None:
                temp_step = PlanStep(
                    seq=0,
                    recipe=matched_recipe.name,
                    target_finding_fp=f.fingerprint,
                    target_index=target_idx,
                    params=step_params,
                    lossy=matched_recipe.lossy,
                    loss=step_loss,
                    min_policy=getattr(matched_recipe, "min_policy", "conservative"),
                    recipe_version=getattr(matched_recipe, "version", "1.0.0"),
                )
                is_disjoint, refusal_reason = check_step_scope(
                    temp_step,
                    events,
                    recipe_region_fn=reg_fn,
                    findings=findings,
                    excludes_execution_dependence=getattr(
                        matched_recipe, "excludes_execution_dependence", False
                    ),
                    ambiguous=precomputed_ambiguous,
                )
                if not is_disjoint:
                    blocked_items.append(
                        Blocked(
                            finding_fp=f.fingerprint,
                            code=f.code,
                            reason=refusal_reason or "side-effect-scope-unproven",
                        )
                    )
                    continue
            else:
                # Recipe does not declare affected_region: keeps global gating.
                # Must abstain if session has side-effect-bearing tool calls or SL203.
                if global_abst is not None and global_abst.abstain:
                    blocked_items.append(
                        Blocked(
                            finding_fp=f.fingerprint,
                            code=f.code,
                            reason="side-effect-abstention",
                        )
                    )
                    continue

        candidate_steps.append(
            (
                target_idx,
                matched_recipe.name,
                f.fingerprint,
                f.code,
                step_params,
                matched_recipe.lossy,
                step_loss,
                getattr(matched_recipe, "min_policy", "conservative"),
                getattr(matched_recipe, "version", "1.0.0"),
            )
        )

    # 4. Sort steps by (target_index, recipe, finding_fp)
    def _step_sort_key(
        item: tuple[
            int | None, str, str, str, Mapping[str, Any], bool, Mapping[str, int], str, str
        ],
    ) -> tuple[int, str, str]:
        idx_val = item[0] if item[0] is not None else 0
        return (idx_val, item[1], item[2])

    candidate_steps.sort(key=_step_sort_key)

    # 5. Apply MAX_STEPS capacity cap
    final_steps: list[PlanStep] = []
    if len(candidate_steps) <= MAX_STEPS:
        for seq_idx, (
            t_idx,
            rec_name,
            f_fp,
            _,
            params,
            is_lossy,
            s_loss,
            rec_min_policy,
            rec_version,
        ) in enumerate(candidate_steps):
            final_steps.append(
                PlanStep(
                    seq=seq_idx,
                    recipe=rec_name,
                    target_finding_fp=f_fp,
                    target_index=t_idx,
                    params=params,
                    lossy=is_lossy,
                    loss=s_loss,
                    min_policy=rec_min_policy,
                    recipe_version=rec_version,
                )
            )
    else:
        for seq_idx, (
            t_idx,
            rec_name,
            f_fp,
            _,
            params,
            is_lossy,
            s_loss,
            rec_min_policy,
            rec_version,
        ) in enumerate(candidate_steps[:MAX_STEPS]):
            final_steps.append(
                PlanStep(
                    seq=seq_idx,
                    recipe=rec_name,
                    target_finding_fp=f_fp,
                    target_index=t_idx,
                    params=params,
                    lossy=is_lossy,
                    loss=s_loss,
                    min_policy=rec_min_policy,
                    recipe_version=rec_version,
                )
            )
        for _, _, f_fp, f_code, _, _, _, _, _ in candidate_steps[MAX_STEPS:]:
            blocked_items.append(
                Blocked(
                    finding_fp=f_fp,
                    code=f_code,
                    reason="cap-overflow",
                )
            )

    loss_preview: dict[str, int] = {
        "discarded-suffix": 0,
        "none": 0,
        "truncated-projection": 0,
    }
    for s in final_steps:
        for k, v in s.loss.items():
            loss_preview[k] = loss_preview.get(k, 0) + v

    total_lost = sum(sum(s.loss.values()) for s in final_steps)
    total_kept = max(0, len(events) - total_lost)

    loss_accounting = Loss(
        preview=loss_preview,
        total_lost=total_lost,
        total_kept=total_kept,
    )

    if policy == "conservative":
        for s in final_steps:
            if s.lossy or any(v > 0 for v in s.loss.values()) or s.min_policy == "salvage":
                raise ValueError(
                    f"Conservative plan cannot include salvage-class or lossy step: {s.recipe}"
                )

    # Sort blocked entries deterministically
    sorted_blocked = tuple(sorted(blocked_items, key=lambda b: (b.finding_fp, b.code, b.reason)))

    plan_dict: dict[str, Any] = {
        "blocked": [b.to_dict() for b in sorted_blocked],
        "loss_accounting": loss_accounting.to_dict(),
        "profile": profile_name,
        "source_hash": resolved_source_hash,
        "steps": [s.to_dict() for s in final_steps],
        "version": PLAN_VERSION,
    }
    if policy != "conservative":
        plan_dict["policy"] = policy
        plan_dict["loss_accounting"]["total_lost"] = total_lost
        plan_dict["loss_accounting"]["total_kept"] = total_kept

    fingerprint = compute_plan_fingerprint(plan_dict)

    return RepairPlan(
        version=PLAN_VERSION,
        source_hash=resolved_source_hash,
        profile=profile_name,
        steps=tuple(final_steps),
        blocked=sorted_blocked,
        loss_accounting=loss_accounting,
        fingerprint=fingerprint,
        policy=policy,
    )


def get_plan_schema_path() -> Path:
    """Return the filesystem path to schemas/sesslint.plan.v1.json."""
    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    dev_path = repo_root / "schemas" / "sesslint.plan.v1.json"
    if dev_path.is_file():
        return dev_path
    prefix_path = Path(sys.prefix) / "share" / "sesslint" / "schemas" / "sesslint.plan.v1.json"
    if prefix_path.is_file():
        return prefix_path
    return dev_path


def load_plan_schema() -> dict[str, Any]:
    """Load the committed JSON Schema for sesslint.plan/v1 as a dict."""
    schema_path = get_plan_schema_path()
    if not schema_path.is_file():
        raise FileNotFoundError(f"Repair plan schema not found at {schema_path}")
    return cast(dict[str, Any], json.loads(schema_path.read_text(encoding="utf-8")))


__all__ = [
    "ALLOWED_LOSS_CLASSES",
    "EMPTY_EVENTS_HASH",
    "MAX_STEPS",
    "PLAN_VERSION",
    "Blocked",
    "Loss",
    "PlanStep",
    "RepairPlan",
    "compute_events_source_hash",
    "get_plan_schema_path",
    "load_plan_schema",
    "plan",
]
