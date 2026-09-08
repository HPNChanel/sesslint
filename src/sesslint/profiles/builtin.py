"""Built-in replay profiles definition as pure data.

This module defines the three standard SessLint profiles:
- neutral: Standard baseline with default generic rules and detection margins.
- claude-strict: Strict profile for Claude Code sessions (tight format margins, strict unknown).
- openai-strict: Strict profile for OpenAI Agents sessions (high checkpoint sensitivity).
"""

from __future__ import annotations

from typing import Final

from sesslint.codes import (
    SL001,
    SL002,
    SL003,
    SL004,
    SL005,
    SL006,
    SL007,
    SL101,
    SL102,
    SL103,
    SL104,
    SL105,
    SL106,
    SL107,
    SL108,
    SL201,
    SL202,
    SL203,
    SL301,
    SL302,
    Severity,
)
from sesslint.profiles.profile import Profile

ALL_RULES: Final[tuple[str, ...]] = (
    SL001,
    SL002,
    SL003,
    SL004,
    SL005,
    SL006,
    SL007,
    SL101,
    SL102,
    SL103,
    SL104,
    SL105,
    SL106,
    SL107,
    SL108,
    SL201,
    SL202,
    SL203,
    SL301,
    SL302,
)

NEUTRAL_PROFILE: Final[Profile] = Profile(
    name="neutral",
    version="1.0.0",
    description=(
        "Vendor-neutral baseline profile using standard generic rules and default thresholds."
    ),
    allowed_adapters=("canonical", "claude", "openai", "auto"),
    enabled_rules=ALL_RULES,
    thresholds={"confidence_min": 0.55, "margin_min": 0.15},
    strict_unknown_critical=False,
    checkpoint_sensitivity="default",
    rule_severities={"SL107": Severity.WARNING, "SL108": Severity.WARNING},
)

CLAUDE_STRICT_PROFILE: Final[Profile] = Profile(
    name="claude-strict",
    version="1.0.0",
    description=(
        "Strict profile for Claude Code sessions with tight format margins "
        "and strict version checks."
    ),
    allowed_adapters=("claude", "canonical", "auto"),
    enabled_rules=ALL_RULES,
    thresholds={"confidence_min": 0.55, "margin_min": 0.20},
    strict_unknown_critical=True,
    checkpoint_sensitivity="default",
    rule_severities={"SL107": Severity.ERROR, "SL108": Severity.ERROR},
)

OPENAI_STRICT_PROFILE: Final[Profile] = Profile(
    name="openai-strict",
    version="1.0.0",
    description="Strict profile for OpenAI Agents SDK sessions with high checkpoint sensitivity.",
    allowed_adapters=("openai", "canonical", "auto"),
    enabled_rules=ALL_RULES,
    thresholds={"confidence_min": 0.55, "margin_min": 0.15},
    strict_unknown_critical=True,
    checkpoint_sensitivity="high",
    rule_severities={"SL107": Severity.ERROR, "SL108": Severity.ERROR},
)

REGISTRY: Final[dict[str, Profile]] = {
    NEUTRAL_PROFILE.name: NEUTRAL_PROFILE,
    CLAUDE_STRICT_PROFILE.name: CLAUDE_STRICT_PROFILE,
    OPENAI_STRICT_PROFILE.name: OPENAI_STRICT_PROFILE,
}

__all__ = [
    "ALL_RULES",
    "CLAUDE_STRICT_PROFILE",
    "NEUTRAL_PROFILE",
    "OPENAI_STRICT_PROFILE",
    "REGISTRY",
]
