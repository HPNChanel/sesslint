"""Side-effect-unknown abstention contract (TASK-017).

This module implements the safeguard gate that prevents automated session repair
from mutating history whenever:
1. SL203 (unsafe continuation across loss/corruption) is present.
2. Any tool event in the session has unknown or possible external side effects
   without an explicit operator override.

Rationale:
Automated repair can safely drop torn tails or re-link benign messages, but if an external
tool invocation performed irreversible mutations (e.g. database write, external API call),
dropping or fabricating records would create desynchronization between reality and the log.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

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
    - Abstains if any tool event has non-'none' side_effects (default is 'unknown').
    - Content-free reason strings.
    """
    reasons: list[str] = []

    # Condition (a): Hard refusal on SL203
    has_sl203 = any(f.code == "SL203" for f in findings)
    if has_sl203:
        reasons.append("SL203 present")

    # Condition (b): Tool side-effects validation
    for idx, ev in enumerate(events):
        raw_kind = getattr(ev, "kind", None)
        if raw_kind is None and isinstance(ev, Mapping):
            raw_kind = ev.get("kind")

        if raw_kind in TOOL_KINDS:
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

            # Default is "unknown". Only exact literal "none" is considered safe.
            if raw_se != SAFE_SIDE_EFFECT and not allow_unknown_side_effects:
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
    "must_abstain",
]
