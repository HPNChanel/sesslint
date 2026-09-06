"""SessLint replay profiles package."""

from sesslint.profiles.builtin import (
    ALL_RULES,
    CLAUDE_STRICT_PROFILE,
    NEUTRAL_PROFILE,
    OPENAI_STRICT_PROFILE,
    REGISTRY,
)
from sesslint.profiles.profile import (
    EffectiveConfig,
    Profile,
    get_profile,
    list_profiles,
    require_canonical,
    resolve_effective_config,
    stamp_source_profile,
)

__all__ = [
    "ALL_RULES",
    "CLAUDE_STRICT_PROFILE",
    "EffectiveConfig",
    "NEUTRAL_PROFILE",
    "OPENAI_STRICT_PROFILE",
    "Profile",
    "REGISTRY",
    "get_profile",
    "list_profiles",
    "require_canonical",
    "resolve_effective_config",
    "stamp_source_profile",
]
