"""Assurance lattice and downgrade cap for repair planning (TASK-020).

This module defines the 4-level assurance lattice:
    unrepairable < salvaged < repaired-lossless < clean

And the pure helper cap_assurance() that caps report assurance based on whether
a repair plan contains lossy, lossless, or blocked steps.

Guarantees:
- Zero I/O, zero network calls, zero state mutation.
- Pure lattice ordering with strict input validation.
- Vendor-free implementation.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, Final

ASSURANCE_LATTICE: Final[tuple[str, ...]] = (
    "unrepairable",
    "salvaged",
    "repaired-lossless",
    "clean",
)

_LATTICE_RANK: Final[dict[str, int]] = {name: idx for idx, name in enumerate(ASSURANCE_LATTICE)}


def _is_step_lossy(step: Any) -> bool:
    """Check if a plan step is flagged as lossy."""
    if hasattr(step, "lossy"):
        return bool(step.lossy)
    if isinstance(step, Mapping):
        return bool(step.get("lossy", False))
    return False


def cap_assurance(base: str, plan: Any) -> str:
    """Cap a base assurance level based on proposed repair plan characteristics.

    Lattice order (ascending quality):
        ["unrepairable", "salvaged", "repaired-lossless", "clean"]

    Rules:
    - If any step in plan is lossy -> min(base, "salvaged").
    - If plan has only lossless steps and base was "clean" -> "repaired-lossless".
    - If plan has only lossless steps and base was below "clean" -> min(base, "repaired-lossless").
    - Blocked-only or empty plans leave base assurance unchanged.

    Args:
        base: Starting assurance string (must be in ASSURANCE_LATTICE).
        plan: RepairPlan instance, dictionary containing 'steps', or iterable of steps.

    Returns:
        Capped assurance string from ASSURANCE_LATTICE.

    Raises:
        ValueError: If base is not in ASSURANCE_LATTICE.
    """
    if base not in _LATTICE_RANK:
        valid_sorted = sorted(ASSURANCE_LATTICE)
        raise ValueError(f"Unknown base assurance: {base!r}. Must be one of {valid_sorted}")

    # Extract steps
    steps: list[Any]
    if hasattr(plan, "steps"):
        steps = list(plan.steps)
    elif isinstance(plan, Mapping) and "steps" in plan:
        raw_steps = plan["steps"]
        steps = list(raw_steps) if isinstance(raw_steps, Iterable) else []
    elif isinstance(plan, Iterable) and not isinstance(plan, (str, bytes)):
        steps = list(plan)
    else:
        steps = []

    if not steps:
        # Blocked-only or empty plans leave base unchanged
        return base

    has_lossy = any(_is_step_lossy(s) for s in steps)

    if has_lossy:
        # min(base, "salvaged")
        salvaged_rank = _LATTICE_RANK["salvaged"]
        base_rank = _LATTICE_RANK[base]
        return base if base_rank < salvaged_rank else "salvaged"

    # Plan has steps and none are lossy (all lossless)
    lossless_rank = _LATTICE_RANK["repaired-lossless"]
    base_rank = _LATTICE_RANK[base]
    return base if base_rank < lossless_rank else "repaired-lossless"


ASSURANCE_CEILING_TABLE: Final[dict[str, dict[str, str]]] = {
    "conservative": {
        "A0": "A0",
        "A1": "A1",
        "A2": "A2",
        "A3": "A3",
        "A4": "A4",
    },
    "salvage": {
        "A0": "A0",
        "A1": "A1",
        "A2": "A2",
        "A3": "A2",
        "A4": "A2",
    },
}


def compute_assurance_ceiling(revalidation_assurance: str, policy_or_pedigree: str) -> str:
    """Derive bounded assurance ceiling based on revalidation A-level and repair pedigree.

    Vocabulary relationship:
    - Revalidation A-level: Evaluated under active profile rules (A0-A4).
    - Repair Pedigree: Invasiveness of applied transformations ('conservative'/'repaired-lossless'
      vs 'salvage'/'salvaged').

    Ceiling Rules:
    - Conservative (lossless) preserves the output's revalidation A-level.
    - Salvage (lossy) is bounded at A2 (structural replay ceiling); it cannot claim A3/A4 even
      if post-repair checks pass completely with zero warnings.

    Args:
        revalidation_assurance: A-level string ('A0', 'A1', 'A2', 'A3', 'A4').
        policy_or_pedigree: Policy ('conservative', 'salvage') or lattice pedigree
            ('clean', 'repaired-lossless', 'salvaged').

    Returns:
        Bounded assurance ceiling string ('A0'-'A4').

    Raises:
        ValueError: If revalidation_assurance or policy_or_pedigree is invalid.
    """
    clean_reval = revalidation_assurance.strip().upper()
    valid_a = ("A0", "A1", "A2", "A3", "A4")
    if clean_reval not in valid_a:
        raise ValueError(
            f"Invalid revalidation assurance: {revalidation_assurance!r}. Must be one of {valid_a}"
        )

    norm_pol = policy_or_pedigree.strip().lower()
    if norm_pol in ("conservative", "repaired-lossless", "clean"):
        key = "conservative"
    elif norm_pol in ("salvage", "salvaged"):
        key = "salvage"
    else:
        raise ValueError(
            f"Invalid policy or pedigree: {policy_or_pedigree!r}. "
            "Must be one of ('conservative', 'salvage', 'repaired-lossless', 'salvaged', 'clean')"
        )

    return ASSURANCE_CEILING_TABLE[key][clean_reval]


__all__ = [
    "ASSURANCE_CEILING_TABLE",
    "ASSURANCE_LATTICE",
    "cap_assurance",
    "compute_assurance_ceiling",
]
