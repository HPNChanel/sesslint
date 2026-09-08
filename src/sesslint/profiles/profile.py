"""Profile data structures, configuration resolution, and canonical guard.

This module provides the frozen Profile and EffectiveConfig dataclasses, profile lookup
and listing helpers, threshold/format override resolution, and the runtime require_canonical
type guard.
"""

from __future__ import annotations

import difflib
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from sesslint.canonical import SCHEMA_VERSION, SessionEvent
from sesslint.codes import Severity


@dataclass(frozen=True, slots=True)
class Profile:
    """Immutable specification of a SessLint replay validation profile."""

    name: str
    description: str
    allowed_adapters: tuple[str, ...]
    enabled_rules: tuple[str, ...]
    thresholds: Mapping[str, float]
    strict_unknown_critical: bool
    checkpoint_sensitivity: str
    version: str = "1.0.0"
    rule_severities: Mapping[str, Severity] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize profile definition to standard dictionary with sorted keys."""
        res: dict[str, Any] = {
            "allowed_adapters": list(self.allowed_adapters),
            "checkpoint_sensitivity": self.checkpoint_sensitivity,
            "description": self.description,
            "enabled_rules": list(self.enabled_rules),
            "name": self.name,
            "strict_unknown_critical": self.strict_unknown_critical,
            "thresholds": dict(self.thresholds),
            "version": self.version,
        }
        if self.rule_severities:
            res["rule_severities"] = {
                k: v.value if hasattr(v, "value") else str(v)
                for k, v in sorted(self.rule_severities.items())
            }
        return res


@dataclass(frozen=True, slots=True)
class EffectiveConfig:
    """Resolved runtime configuration merging profile defaults with explicit CLI overrides."""

    profile: str
    description: str
    allowed_adapters: tuple[str, ...]
    enabled_rules: tuple[str, ...]
    confidence_min: float
    margin_min: float
    strict_unknown_critical: bool
    checkpoint_sensitivity: str
    format_override: str | None
    thresholds_source: str  # "profile" | "cli"
    version: str = "1.0.0"

    def to_dict(self) -> dict[str, Any]:
        """Serialize effective config to dictionary suitable for JSON snapshots."""
        return {
            "allowed_adapters": list(self.allowed_adapters),
            "checkpoint_sensitivity": self.checkpoint_sensitivity,
            "confidence_min": round(self.confidence_min, 4),
            "description": self.description,
            "enabled_rules": list(self.enabled_rules),
            "format_override": self.format_override,
            "margin_min": round(self.margin_min, 4),
            "profile": self.profile,
            "strict_unknown_critical": self.strict_unknown_critical,
            "thresholds_source": self.thresholds_source,
        }

    def to_source_resolution(self) -> dict[str, Any]:
        """Emit source.resolution audit block for inclusion in reports."""
        return {
            "confidence_min": round(self.confidence_min, 4),
            "format_override": self.format_override,
            "margin_min": round(self.margin_min, 4),
            "profile": self.profile,
            "thresholds_source": self.thresholds_source,
        }


VALID_FORMATS: Final[frozenset[str]] = frozenset(
    {
        "auto",
        "canonical",
        "claude",
        "openai",
        "claude-code-jsonl",
        "openai-agents",
    }
)


def get_profile(name: str) -> Profile:
    """Retrieve registered profile by exact name.

    Raises:
        KeyError: If profile name is not found (includes suggestions).
    """
    from sesslint.profiles.builtin import REGISTRY

    if name in REGISTRY:
        return REGISTRY[name]

    available = sorted(REGISTRY.keys())
    matches = difflib.get_close_matches(name, available, n=1, cutoff=0.4)
    suggestion = f" Did you mean {matches[0]!r}?" if matches else ""
    raise KeyError(f"Unknown profile {name!r}. Available profiles: {available}.{suggestion}")


def list_profiles() -> list[str]:
    """Return sorted list of all registered profile names."""
    from sesslint.profiles.builtin import REGISTRY

    return sorted(REGISTRY.keys())


def resolve_effective_config(
    profile: Profile | str,
    *,
    format: str | None = None,
    confidence_min: float | None = None,
    margin_min: float | None = None,
) -> EffectiveConfig:
    """Resolve effective configuration with pinned precedence (CLI overrides beat profile).

    Validation rules:
    - 0.0 < confidence_min < 1.0 (finite float)
    - 0.0 < margin_min < 1.0 (finite float)
    - margin_min <= confidence_min
    - format must be valid if provided
    """
    prof = get_profile(profile) if isinstance(profile, str) else profile

    # 1. Format override validation
    fmt_override: str | None = None
    if format is not None:
        fmt_clean = format.strip().lower()
        if not fmt_clean or fmt_clean not in VALID_FORMATS:
            valid_list = sorted(VALID_FORMATS)
            raise ValueError(f"Invalid format override {format!r}. Must be one of {valid_list}")
        fmt_override = fmt_clean

    # 2. Thresholds resolution
    is_cli_threshold = confidence_min is not None or margin_min is not None
    thresholds_source = "cli" if is_cli_threshold else "profile"

    conf = (
        prof.thresholds.get("confidence_min", 0.55)
        if confidence_min is None
        else float(confidence_min)
    )
    marg = prof.thresholds.get("margin_min", 0.15) if margin_min is None else float(margin_min)

    if math.isnan(conf) or math.isinf(conf):
        raise ValueError("confidence_min must be a finite float")
    if math.isnan(marg) or math.isinf(marg):
        raise ValueError("margin_min must be a finite float")

    if not (0.0 < conf < 1.0):
        raise ValueError(
            f"confidence_min must be strictly between 0.0 and 1.0 exclusive, got {conf}"
        )
    if not (0.0 < marg < 1.0):
        raise ValueError(f"margin_min must be strictly between 0.0 and 1.0 exclusive, got {marg}")

    if marg > conf:
        raise ValueError(f"margin_min ({marg}) cannot exceed confidence_min ({conf})")

    return EffectiveConfig(
        profile=prof.name,
        description=prof.description,
        allowed_adapters=prof.allowed_adapters,
        enabled_rules=prof.enabled_rules,
        confidence_min=conf,
        margin_min=marg,
        strict_unknown_critical=prof.strict_unknown_critical,
        checkpoint_sensitivity=prof.checkpoint_sensitivity,
        format_override=fmt_override,
        thresholds_source=thresholds_source,
        version=prof.version,
    )


def require_canonical(session_or_events: Any) -> None:
    """Runtime guard ensuring input is a canonical sesslint.session/v1 structure.

    Raises:
        TypeError: If input is not a canonical session or sequence of canonical events.
    """
    if session_or_events is None:
        raise TypeError("Input cannot be None; expected canonical session or events")

    # Check if dict-like session
    if isinstance(session_or_events, Mapping):
        schema = session_or_events.get("schema") or session_or_events.get("schema_version")
        if schema != SCHEMA_VERSION:
            raise TypeError(f"Expected canonical session schema {SCHEMA_VERSION!r}, got {schema!r}")
        if "events" not in session_or_events and "session_id" not in session_or_events:
            raise TypeError(
                "Canonical session dictionary must contain 'events' array or 'session_id'"
            )
        return

    # Check if sequence of events
    if isinstance(session_or_events, Sequence) and not isinstance(session_or_events, (str, bytes)):
        if not session_or_events:
            return  # Empty sequence is structurally acceptable

        first = session_or_events[0]
        if isinstance(first, SessionEvent):
            return
        if isinstance(first, Mapping):
            if "kind" not in first:
                raise TypeError("Non-canonical event dictionary missing required 'kind' field")
            return
        raise TypeError(f"Expected SessionEvent or event Mapping, got {type(first).__name__}")

    actual_type = type(session_or_events).__name__
    raise TypeError(f"Expected canonical session Mapping or Sequence of events, got {actual_type}")


def stamp_source_profile(
    source_block: dict[str, Any] | None,
    effective_config: EffectiveConfig,
) -> dict[str, Any]:
    """Stamp profile and resolution metadata into a source dictionary."""
    block = dict(source_block) if source_block else {}
    block["profile"] = effective_config.profile
    block["resolution"] = effective_config.to_source_resolution()
    return block


__all__ = [
    "EffectiveConfig",
    "Profile",
    "VALID_FORMATS",
    "get_profile",
    "list_profiles",
    "require_canonical",
    "resolve_effective_config",
    "stamp_source_profile",
]
