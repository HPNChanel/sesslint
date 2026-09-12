"""Check execution context and version metadata (DEV-004, FR-046).

This module defines CheckContext, which threads adapter and profile identity and version
information through check runners into finding fingerprint computations.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sesslint._version import ADAPTER_VERSIONS, PROFILE_VERSIONS

if TYPE_CHECKING:
    from sesslint.profiles.profile import Profile

_UNSET: Any = object()


@dataclass(frozen=True, slots=True)
class CheckContext:
    """Context carrying adapter and profile version metadata into checks (FR-046).

    Per FR-046, every finding fingerprint is derived from rule ID + adapter/profile
    versions + structural coords.
    When a version coordinate is unavailable or omitted, it MUST be explicit "unknown"
    (never empty string) so absence is visible in the fingerprint preimage.
    Also threads preserved source metadata / projections into checks (DEV-011).
    """

    adapter_id: str = "unknown"
    adapter_version: str = "unknown"
    profile_id: str = "unknown"
    profile_version: str = "unknown"
    source_metadata: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if not self.adapter_id or not self.adapter_id.strip():
            object.__setattr__(self, "adapter_id", "unknown")
        if not self.adapter_version or not self.adapter_version.strip():
            object.__setattr__(self, "adapter_version", "unknown")
        if not self.profile_id or not self.profile_id.strip():
            object.__setattr__(self, "profile_id", "unknown")
        if not self.profile_version or not self.profile_version.strip():
            object.__setattr__(self, "profile_version", "unknown")

    @classmethod
    def create(
        cls,
        *,
        adapter_id: str | None = None,
        adapter_version: str | None = None,
        profile_id: str | None = None,
        profile_version: str | None = None,
        source_metadata: Mapping[str, Any] | None = None,
    ) -> CheckContext:
        """Create a CheckContext, looking up registered version strings when unspecified."""
        clean_ad_id = adapter_id.strip() if adapter_id and adapter_id.strip() else "unknown"
        if adapter_version and adapter_version.strip():
            clean_ad_ver = adapter_version.strip()
        elif clean_ad_id in ADAPTER_VERSIONS:
            clean_ad_ver = ADAPTER_VERSIONS[clean_ad_id]
        else:
            clean_ad_ver = "unknown"

        clean_prof_id = profile_id.strip() if profile_id and profile_id.strip() else "unknown"
        if profile_version and profile_version.strip():
            clean_prof_ver = profile_version.strip()
        elif clean_prof_id in PROFILE_VERSIONS:
            clean_prof_ver = PROFILE_VERSIONS[clean_prof_id]
        else:
            clean_prof_ver = "unknown"

        return cls(
            adapter_id=clean_ad_id,
            adapter_version=clean_ad_ver,
            profile_id=clean_prof_id,
            profile_version=clean_prof_ver,
            source_metadata=source_metadata,
        )

    @classmethod
    def from_profile_and_adapter(
        cls,
        profile: Profile | str | None = None,
        adapter: str | None = None,
        source_metadata: Mapping[str, Any] | None = None,
    ) -> CheckContext:
        """Construct CheckContext by resolving a Profile (or profile name) and adapter name."""
        from sesslint.profiles.builtin import NEUTRAL_PROFILE
        from sesslint.profiles.profile import Profile as ProfileClass
        from sesslint.profiles.profile import get_profile

        resolved_prof: ProfileClass
        if profile is None:
            resolved_prof = NEUTRAL_PROFILE
        elif isinstance(profile, str):
            resolved_prof = get_profile(profile)
        else:
            resolved_prof = profile

        prof_id = resolved_prof.name
        prof_ver = getattr(resolved_prof, "version", None) or PROFILE_VERSIONS.get(
            prof_id, "unknown"
        )

        clean_ad_id = adapter.strip() if adapter and adapter.strip() else "unknown"
        clean_ad_ver = (
            ADAPTER_VERSIONS.get(clean_ad_id, "unknown") if clean_ad_id != "unknown" else "unknown"
        )

        return cls(
            adapter_id=clean_ad_id,
            adapter_version=clean_ad_ver,
            profile_id=prof_id,
            profile_version=prof_ver,
            source_metadata=source_metadata,
        )

    def to_dict(self) -> dict[str, str]:
        """Return a mapping of context fields."""
        return {
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
        }

    def with_overrides(
        self,
        *,
        adapter_id: str | None = None,
        adapter_version: str | None = None,
        profile_id: str | None = None,
        profile_version: str | None = None,
        source_metadata: Mapping[str, Any] | None | object = _UNSET,
    ) -> CheckContext:
        """Return a copy of CheckContext with overridden fields."""
        return CheckContext(
            adapter_id=self.adapter_id if adapter_id is None else adapter_id,
            adapter_version=self.adapter_version if adapter_version is None else adapter_version,
            profile_id=self.profile_id if profile_id is None else profile_id,
            profile_version=self.profile_version if profile_version is None else profile_version,
            source_metadata=(
                self.source_metadata
                if source_metadata is _UNSET
                else (
                    source_metadata
                    if (isinstance(source_metadata, Mapping) or source_metadata is None)
                    else None
                )
            ),
        )


__all__ = ["CheckContext"]
