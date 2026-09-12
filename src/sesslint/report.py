"""Report and manifest envelopes, aggregation builders, and content-free enforcement.

This module provides the frozen Report and RepairManifest envelopes, deterministic builders
(build_report, build_manifest), canonical JSON serialization/parsing, assurance level models
with mandatory limitations, and content-free validation (enforce_content_free).
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Literal, cast

from sesslint.canonical import to_canonical_json
from sesslint.errors import (
    AssuranceError,
    ContentLeakError,
    FindingError,
    OperationalError,
    SchemaError,
    UnknownFieldError,
    VersionError,
)
from sesslint.finding import (
    Finding,
    enforce_content_free_text,
    finding_sort_key,
    parse_finding_dict,
    sort_findings,
)
from sesslint.repair.assurance import cap_assurance

ReportSchemaVersionLiteral = Literal["sesslint.report/v1"]
REPORT_SCHEMA_VERSION: Final[ReportSchemaVersionLiteral] = "sesslint.report/v1"

ManifestSchemaVersionLiteral = Literal["sesslint.repair-manifest/v1"]
MANIFEST_SCHEMA_VERSION: Final[ManifestSchemaVersionLiteral] = "sesslint.repair-manifest/v1"

Assurance = Literal["A0", "A1", "A2", "A3", "A4"]
VALID_ASSURANCE_LEVELS: Final[frozenset[str]] = frozenset({"A0", "A1", "A2", "A3", "A4"})

Policy = Literal["conservative", "salvage"]
VALID_POLICIES: Final[frozenset[str]] = frozenset({"conservative", "salvage"})

ASSURANCE_LIMITATIONS: Final[dict[Assurance, str]] = {
    "A0": "No structural conclusion.",
    "A1": "Relationships may still be invalid.",
    "A2": "Provider/runtime replay has not been independently exercised.",
    "A3": "Does not prove semantic equivalence or external side effects.",
    "A4": "Still not proof of model behavior, business correctness, or exactly-once effects.",
}

ASSURANCE_DESCRIPTIONS: Final[dict[Assurance, str]] = {
    "A0": "unreadable",
    "A1": "parseable",
    "A2": "structurally valid",
    "A3": "profile-replay valid",
    "A4": "reference-replay valid",
}


def compute_assurance(
    events: Sequence[Any] | None,
    findings: Sequence[Finding],
    *,
    has_profile_replay: bool = True,
) -> tuple[Assurance, str]:
    """Compute staged assurance level and limitation based on pipeline outcomes (RVW-015).

    Pipeline stages mapped to A-levels:
    - A0: unreadable (could not safely parse raw artifact into events: len(events) == 0
          with findings, or findings contain parse/stream integrity codes SL001/SL002).
    - A1: parseable (events parsed successfully, but structural or profile errors found).
    - A2: structurally valid (zero errors, but warnings found or replay not independently
          exercised).
    - A3: profile-replay valid (zero errors and zero warnings under active replay profile).
    - A4: reference-replay valid (reserved/reference equivalent).
    """
    from sesslint.codes import SL001, SL002, Severity

    has_error = any(f.severity in (Severity.ERROR, Severity.FATAL) for f in findings)
    has_warning = any(f.severity == Severity.WARNING for f in findings)

    # A0: Could not safely parse raw artifact
    is_unparseable = (
        events is None or len(events) == 0 or any(f.code in (SL001, SL002) for f in findings)
    )
    if is_unparseable and (
        has_error or (events is not None and len(events) == 0 and bool(findings))
    ):
        assurance: Assurance = "A0"
        return assurance, ASSURANCE_LIMITATIONS["A0"]

    if has_error:
        assurance = "A1"
        return assurance, ASSURANCE_LIMITATIONS["A1"]

    if has_warning or not has_profile_replay:
        assurance = "A2"
        return assurance, ASSURANCE_LIMITATIONS["A2"]

    assurance = "A3"
    return assurance, ASSURANCE_LIMITATIONS["A3"]


VALID_COVERAGE_SKIP_REASONS: Final[frozenset[str]] = frozenset(
    {
        "profile-gated",
        "adapter-not-applicable",
        "version-gated",
        "empty-input",
        "cap-exceeded",
        "single-doc-fallback",
    }
)

KNOWN_REPORT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "session_id",
        "source_fingerprint",
        "tool_version",
        "findings",
        "counts",
        "assurance",
        "limitation",
        "coverage",
        "repro",
        "content_warning",
        "included_content",
    }
)
REPORT_ROOT_KEYS: Final[frozenset[str]] = KNOWN_REPORT_FIELDS
REPORT_FINDING_KEYS: Final[frozenset[str]] = frozenset(
    {
        "code",
        "severity",
        "repairability",
        "fingerprint",
        "span",
        "evidence",
        "remediation",
    }
)
REPORT_DEFAULT_FINDING_KEYS: Final[frozenset[str]] = REPORT_FINDING_KEYS
REPORT_FORBIDDEN_FINDING_KEYS: Final[frozenset[str]] = frozenset(
    {"text", "content", "message", "payload"}
)

REQUIRED_REPORT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "session_id",
        "source_fingerprint",
        "tool_version",
        "findings",
        "counts",
        "assurance",
        "limitation",
        "coverage",
    }
)

KNOWN_MANIFEST_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "input_fingerprint",
        "output_fingerprint",
        "plan_fingerprint",
        "assurance",
        "assurance_ceiling",
        "recipe_versions",
        "profile_version",
        "adapter_id",
        "adapter_version",
        "byte_counts",
        "record_counts",
        "policy",
        "actions",
        "declared_loss",
        "revalidate_report",
        "revalidation",
        "idempotency_key",
    }
)

REQUIRED_MANIFEST_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "input_fingerprint",
        "output_fingerprint",
        "policy",
        "actions",
        "declared_loss",
        "revalidate_report",
        "idempotency_key",
        "revalidation",
        "assurance_ceiling",
    }
)

REQUIRED_SEVERITIES: Final[tuple[str, ...]] = ("fatal", "error", "warning", "info")
_SHA256_HEX_64_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class Counts:
    """Aggregate finding metrics broken down by severity and rule code.

    Counts are always derived from the finding collection by build_report()
    to maintain a single source of truth and prevent caller-supplied drift.
    """

    by_severity: Mapping[str, int]
    by_code: Mapping[str, int]
    total: int

    def __post_init__(self) -> None:
        if not isinstance(self.total, int) or isinstance(self.total, bool) or self.total < 0:
            raise SchemaError(f"Counts.total must be a non-negative integer, got {self.total!r}")

        if not isinstance(self.by_severity, Mapping):
            raise SchemaError(
                f"Counts.by_severity must be a Mapping, got {type(self.by_severity).__name__}"
            )
        for sev in REQUIRED_SEVERITIES:
            val = self.by_severity.get(sev, 0)
            if not isinstance(val, int) or isinstance(val, bool) or val < 0:
                raise SchemaError(
                    f"Counts.by_severity[{sev!r}] must be non-negative int, got {val!r}"
                )
        for sev in self.by_severity:
            if sev not in REQUIRED_SEVERITIES:
                raise SchemaError(f"Counts.by_severity contains unknown severity: {sev!r}")

        if not isinstance(self.by_code, Mapping):
            raise SchemaError(
                f"Counts.by_code must be a Mapping, got {type(self.by_code).__name__}"
            )
        for code, count in self.by_code.items():
            if not isinstance(code, str):
                raise SchemaError(f"Counts.by_code key must be str, got {code!r}")
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                raise SchemaError(
                    f"Counts.by_code[{code!r}] must be non-negative int, got {count!r}"
                )

    def to_dict(self) -> dict[str, Any]:
        """Convert Counts to schema-compliant dictionary representation."""
        return {
            "by_severity": {sev: self.by_severity.get(sev, 0) for sev in REQUIRED_SEVERITIES},
            "by_code": dict(sorted(self.by_code.items())),
            "total": self.total,
        }


def _skip_sort_key(s: CoverageSkip) -> tuple[str, str, str]:
    return (s.check, s.reason, s.detail)


@dataclass(frozen=True, slots=True)
class CoverageSkip:
    """Record of a check or check-family skipped during evaluation (FR-047)."""

    check: str
    reason: str
    detail: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.check, str) or not self.check.strip():
            raise SchemaError(f"CoverageSkip.check must be a non-empty string, got {self.check!r}")
        if self.reason not in VALID_COVERAGE_SKIP_REASONS:
            valid_sorted = sorted(VALID_COVERAGE_SKIP_REASONS)
            raise SchemaError(
                f"CoverageSkip.reason must be one of {valid_sorted}, got {self.reason!r}"
            )
        if not isinstance(self.detail, str):
            raise SchemaError(
                f"CoverageSkip.detail must be a string, got {type(self.detail).__name__}"
            )

        norm_check = self.check.strip()
        norm_detail = self.detail.strip()
        try:
            enforce_content_free_text(norm_check, context="CoverageSkip.check")
        except FindingError as err:
            raise ContentLeakError(f"Intrinsic content leak in CoverageSkip.check: {err}") from err
        try:
            enforce_content_free_text(norm_detail, context="CoverageSkip.detail")
        except FindingError as err:
            raise ContentLeakError(f"Intrinsic content leak in CoverageSkip.detail: {err}") from err

        if norm_check != self.check:
            object.__setattr__(self, "check", norm_check)
        if norm_detail != self.detail:
            object.__setattr__(self, "detail", norm_detail)

    def to_dict(self) -> dict[str, str]:
        """Convert CoverageSkip to dictionary."""
        return {
            "check": self.check,
            "detail": self.detail,
            "reason": self.reason,
        }

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, CoverageSkip):
            return NotImplemented
        return _skip_sort_key(self) < _skip_sort_key(other)

    def __le__(self, other: Any) -> bool:
        if not isinstance(other, CoverageSkip):
            return NotImplemented
        return _skip_sort_key(self) <= _skip_sort_key(other)

    def __gt__(self, other: Any) -> bool:
        if not isinstance(other, CoverageSkip):
            return NotImplemented
        return _skip_sort_key(self) > _skip_sort_key(other)

    def __ge__(self, other: Any) -> bool:
        if not isinstance(other, CoverageSkip):
            return NotImplemented
        return _skip_sort_key(self) >= _skip_sort_key(other)


@dataclass(frozen=True, slots=True)
class Coverage:
    """Immutable record of checks performed and skipped, binding versions (FR-047)."""

    performed: tuple[str, ...]
    skipped: tuple[CoverageSkip, ...]
    adapter: Mapping[str, str]
    profile: Mapping[str, str]

    def __post_init__(self) -> None:
        if not isinstance(self.performed, (tuple, list, set)):
            raise SchemaError(
                f"Coverage.performed must be a sequence of strings, "
                f"got {type(self.performed).__name__}"
            )
        for idx, item in enumerate(self.performed):
            if not isinstance(item, str) or not item.strip():
                raise SchemaError(
                    f"Coverage.performed[{idx}] must be a non-empty string, got {item!r}"
                )
        object.__setattr__(self, "performed", tuple(sorted(self.performed)))

        if not isinstance(self.skipped, (tuple, list, set)):
            raise SchemaError(
                f"Coverage.skipped must be a sequence of CoverageSkip, "
                f"got {type(self.skipped).__name__}"
            )
        for idx, s in enumerate(self.skipped):
            if not isinstance(s, CoverageSkip):
                raise SchemaError(
                    f"Coverage.skipped[{idx}] must be a CoverageSkip instance, "
                    f"got {type(s).__name__}"
                )
        object.__setattr__(self, "skipped", tuple(sorted(self.skipped, key=_skip_sort_key)))

        if not isinstance(self.adapter, Mapping):
            raise SchemaError(
                f"Coverage.adapter must be a Mapping, got {type(self.adapter).__name__}"
            )
        ad_dict = dict(self.adapter)
        if "id" not in ad_dict and "name" in ad_dict:
            ad_dict["id"] = ad_dict["name"]
        if "id" not in ad_dict:
            raise SchemaError("Coverage.adapter must contain 'id'")
        if "version" not in ad_dict:
            raise SchemaError("Coverage.adapter must contain 'version'")
        if ad_dict != self.adapter:
            object.__setattr__(self, "adapter", dict(sorted(ad_dict.items())))

        if not isinstance(self.profile, Mapping):
            raise SchemaError(
                f"Coverage.profile must be a Mapping, got {type(self.profile).__name__}"
            )
        pr_dict = dict(self.profile)
        if "id" not in pr_dict and "name" in pr_dict:
            pr_dict["id"] = pr_dict["name"]
        if "id" not in pr_dict:
            raise SchemaError("Coverage.profile must contain 'id'")
        if "version" not in pr_dict:
            raise SchemaError("Coverage.profile must contain 'version'")
        if pr_dict != self.profile:
            object.__setattr__(self, "profile", dict(sorted(pr_dict.items())))

    def to_dict(self) -> dict[str, Any]:
        """Convert Coverage to dictionary matching schema."""
        ad_out = {"id": self.adapter["id"], "version": self.adapter["version"]}
        if "name" in self.adapter:
            ad_out["name"] = self.adapter["name"]
        pr_out = {"id": self.profile["id"], "version": self.profile["version"]}
        if "name" in self.profile:
            pr_out["name"] = self.profile["name"]
        return {
            "adapter": dict(sorted(ad_out.items())),
            "performed": list(self.performed),
            "profile": dict(sorted(pr_out.items())),
            "skipped": [s.to_dict() for s in sorted(self.skipped, key=_skip_sort_key)],
        }


def _default_coverage() -> Coverage:
    from sesslint.profiles.builtin import ALL_RULES

    return Coverage(
        performed=ALL_RULES,
        skipped=(),
        adapter={"id": "canonical", "version": "1.0.0"},
        profile={"id": "neutral", "version": "1.0.0"},
    )


@dataclass(frozen=True, slots=True)
class Report:
    """Immutable integrity check report envelope (sesslint.report/v1).

    Encapsulates findings, derived counts, assurance level, and mandatory limitation.
    Determinism invariant: reports contain no clocks or timestamps, ensuring
    byte-identical serialization across identical findings and tool versions.
    """

    schema_version: ReportSchemaVersionLiteral
    session_id: str
    source_fingerprint: str
    tool_version: str
    findings: tuple[Finding, ...]
    counts: Counts
    assurance: Assurance
    limitation: str
    coverage: Coverage = field(default_factory=_default_coverage)

    def __post_init__(self) -> None:
        if self.schema_version != REPORT_SCHEMA_VERSION:
            raise VersionError(
                f"Report.schema_version must be {REPORT_SCHEMA_VERSION!r}, "
                f"got {self.schema_version!r}",
                version=self.schema_version,
            )
        if not isinstance(self.session_id, str) or not self.session_id.strip():
            raise SchemaError(
                f"Report.session_id must be a non-empty string, got {self.session_id!r}"
            )
        if not isinstance(self.source_fingerprint, str) or not self.source_fingerprint.strip():
            raise SchemaError(
                f"Report.source_fingerprint must be a non-empty string, "
                f"got {self.source_fingerprint!r}"
            )
        if not isinstance(self.tool_version, str) or not self.tool_version.strip():
            raise SchemaError(
                f"Report.tool_version must be a non-empty string, got {self.tool_version!r}"
            )

        if self.assurance not in VALID_ASSURANCE_LEVELS:
            raise AssuranceError(
                f"Report.assurance must be one of {sorted(VALID_ASSURANCE_LEVELS)}, "
                f"got {self.assurance!r}"
            )

        if not isinstance(self.limitation, str) or not self.limitation.strip():
            raise AssuranceError(
                f"Report.limitation is required and must be non-empty for assurance "
                f"level {self.assurance!r}"
            )

        if not isinstance(self.coverage, Coverage):
            raise SchemaError(
                f"Report.coverage must be a Coverage instance, got {type(self.coverage).__name__}"
            )

        if not isinstance(self.findings, tuple):
            raise SchemaError(
                f"Report.findings must be a tuple, got {type(self.findings).__name__}"
            )
        for idx, item in enumerate(self.findings):
            if not isinstance(item, Finding):
                raise SchemaError(
                    f"Report.findings[{idx}] must be a Finding instance, got {type(item).__name__}"
                )

        if not isinstance(self.counts, Counts):
            raise SchemaError(
                f"Report.counts must be a Counts instance, got {type(self.counts).__name__}"
            )
        if self.counts.total != len(self.findings):
            raise SchemaError(
                f"Counts.total ({self.counts.total}) does not match findings count "
                f"({len(self.findings)})"
            )

        expected_sev = {sev: 0 for sev in REQUIRED_SEVERITIES}
        expected_code_counter: Counter[str] = Counter()
        for f in self.findings:
            expected_sev[f.severity.value] += 1
            expected_code_counter[f.code] += 1
        expected_code = dict(sorted(expected_code_counter.items()))

        actual_sev = {sev: self.counts.by_severity.get(sev, 0) for sev in REQUIRED_SEVERITIES}
        if actual_sev != expected_sev:
            raise SchemaError(
                f"Counts.by_severity ({actual_sev}) does not match "
                f"findings severity distribution ({expected_sev})"
            )
        if dict(self.counts.by_code) != expected_code:
            raise SchemaError(
                f"Counts.by_code ({dict(self.counts.by_code)}) does not match "
                f"findings code distribution ({expected_code})"
            )

    def to_dict(self) -> dict[str, Any]:
        """Convert Report to schema-compliant dictionary representation."""
        return {
            "assurance": self.assurance,
            "counts": self.counts.to_dict(),
            "coverage": self.coverage.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "limitation": self.limitation,
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "source_fingerprint": self.source_fingerprint,
            "tool_version": self.tool_version,
        }


def _action_sort_key(a: RepairAction) -> tuple[str, int, str, str]:
    rec_key = (0, "") if a.record_id is None else (1, a.record_id)
    return (a.kind, rec_key[0], rec_key[1], a.detail)


@dataclass(frozen=True, slots=True)
class RepairAction:
    """Individual atomic repair operation recorded in a RepairManifest.

    All fields are content-free (no prompts, code, credentials, or session payloads).
    Implements total ordering for deterministic canonical serialization.
    """

    kind: str
    record_id: str | None = None
    detail: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or not self.kind.strip():
            raise SchemaError(f"RepairAction.kind must be a non-empty string, got {self.kind!r}")
        normalized_kind = self.kind.strip()
        try:
            enforce_content_free_text(normalized_kind, context="RepairAction.kind")
        except FindingError as err:
            raise ContentLeakError(f"Intrinsic content leak in RepairAction.kind: {err}") from err
        if normalized_kind != self.kind:
            object.__setattr__(self, "kind", normalized_kind)

        if self.record_id is not None:
            if not isinstance(self.record_id, str) or not self.record_id.strip():
                raise SchemaError(
                    f"RepairAction.record_id must be non-empty string or None, "
                    f"got {self.record_id!r}"
                )
            normalized_rec_id = self.record_id.strip()
            try:
                enforce_content_free_text(normalized_rec_id, context="RepairAction.record_id")
            except FindingError as err:
                raise ContentLeakError(
                    f"Intrinsic content leak in RepairAction.record_id: {err}"
                ) from err
            if normalized_rec_id != self.record_id:
                object.__setattr__(self, "record_id", normalized_rec_id)

        if not isinstance(self.detail, str):
            raise SchemaError(
                f"RepairAction.detail must be a string, got {type(self.detail).__name__}"
            )
        normalized_detail = self.detail.strip()
        try:
            enforce_content_free_text(normalized_detail, context="RepairAction.detail")
        except FindingError as err:
            raise ContentLeakError(f"Intrinsic content leak in RepairAction.detail: {err}") from err
        if normalized_detail != self.detail:
            object.__setattr__(self, "detail", normalized_detail)

    def to_dict(self) -> dict[str, Any]:
        """Convert RepairAction to dictionary matching schema."""
        return {
            "kind": self.kind,
            "record_id": self.record_id,
            "detail": self.detail,
        }

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, RepairAction):
            return NotImplemented
        return _action_sort_key(self) < _action_sort_key(other)

    def __le__(self, other: Any) -> bool:
        if not isinstance(other, RepairAction):
            return NotImplemented
        return _action_sort_key(self) <= _action_sort_key(other)

    def __gt__(self, other: Any) -> bool:
        if not isinstance(other, RepairAction):
            return NotImplemented
        return _action_sort_key(self) > _action_sort_key(other)

    def __ge__(self, other: Any) -> bool:
        if not isinstance(other, RepairAction):
            return NotImplemented
        return _action_sort_key(self) >= _action_sort_key(other)


@dataclass(frozen=True, slots=True)
class RevalidationSummary:
    """Embedded revalidation summary struct for RepairManifest (FR-072)."""

    assurance: Assurance
    error_count: int
    warning_count: int
    profile_id: str
    profile_version: str
    report_fingerprint: str | None = None

    def __post_init__(self) -> None:
        if self.assurance not in VALID_ASSURANCE_LEVELS:
            valid_sorted = sorted(VALID_ASSURANCE_LEVELS)
            raise AssuranceError(
                f"Invalid revalidation assurance {self.assurance!r}. Must be one of {valid_sorted}"
            )
        if (
            not isinstance(self.error_count, int)
            or isinstance(self.error_count, bool)
            or self.error_count < 0
        ):
            raise SchemaError(
                "RevalidationSummary.error_count must be non-negative integer, "
                f"got {self.error_count!r}"
            )
        if (
            not isinstance(self.warning_count, int)
            or isinstance(self.warning_count, bool)
            or self.warning_count < 0
        ):
            raise SchemaError(
                "RevalidationSummary.warning_count must be non-negative integer, "
                f"got {self.warning_count!r}"
            )
        if not isinstance(self.profile_id, str) or not self.profile_id.strip():
            raise SchemaError(
                "RevalidationSummary.profile_id must be a non-empty string, "
                f"got {self.profile_id!r}"
            )
        if not isinstance(self.profile_version, str) or not self.profile_version.strip():
            raise SchemaError(
                "RevalidationSummary.profile_version must be a non-empty string, "
                f"got {self.profile_version!r}"
            )
        if self.report_fingerprint is not None and (
            not isinstance(self.report_fingerprint, str) or not self.report_fingerprint.strip()
        ):
            raise SchemaError(
                "RevalidationSummary.report_fingerprint must be a non-empty string or None"
            )

    def to_dict(self) -> dict[str, Any]:
        """Convert RevalidationSummary to dictionary with sorted keys."""
        d: dict[str, Any] = {
            "assurance": self.assurance,
            "error_count": self.error_count,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "warning_count": self.warning_count,
        }
        if self.report_fingerprint is not None:
            d["report_fingerprint"] = self.report_fingerprint
        return d


@dataclass(frozen=True, slots=True)
class RepairManifest:
    """Immutable repair audit manifest (sesslint.repair-manifest/v1).

    Binds input/output fingerprints, repair policy, atomic actions, loss accounting,
    revalidation report reference, cryptographic idempotency key, and FR-072/FR-073 audit bindings.

    Never-Synthetic-Success Contract:
    This model explicitly does NOT contain a 'success' or 'passed' boolean field.
    SessLint structurally repairs sessions without making semantic claims about whether
    the agent or user workflow succeeded. Attaching a success boolean would falsely imply
    semantic correctness and side-effect truth (AC-009, AC-028, FR-059).
    """

    schema_version: ManifestSchemaVersionLiteral
    input_fingerprint: str
    output_fingerprint: str
    policy: Policy
    actions: tuple[RepairAction, ...]
    declared_loss: tuple[str, ...]
    revalidate_report: str | None
    idempotency_key: str
    revalidation: RevalidationSummary
    assurance_ceiling: str
    plan_fingerprint: str | None = None
    assurance: str | None = None
    recipe_versions: Mapping[str, str] = field(default_factory=dict)
    profile_version: str | None = None
    adapter_id: str | None = None
    adapter_version: str | None = None
    byte_counts: Mapping[str, int] = field(default_factory=dict)
    record_counts: Mapping[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.schema_version != MANIFEST_SCHEMA_VERSION:
            raise VersionError(
                f"RepairManifest.schema_version must be {MANIFEST_SCHEMA_VERSION!r}, "
                f"got {self.schema_version!r}",
                version=self.schema_version,
            )
        if not isinstance(self.input_fingerprint, str) or not self.input_fingerprint.strip():
            raise SchemaError(
                f"RepairManifest.input_fingerprint must be a non-empty string, "
                f"got {self.input_fingerprint!r}"
            )
        if not isinstance(self.output_fingerprint, str) or not self.output_fingerprint.strip():
            raise SchemaError(
                f"RepairManifest.output_fingerprint must be a non-empty string, "
                f"got {self.output_fingerprint!r}"
            )
        if self.policy not in VALID_POLICIES:
            raise SchemaError(
                f"RepairManifest.policy must be one of {sorted(VALID_POLICIES)}, "
                f"got {self.policy!r}"
            )
        if not isinstance(self.actions, tuple):
            raise SchemaError(
                f"RepairManifest.actions must be a tuple, got {type(self.actions).__name__}"
            )
        for idx, act in enumerate(self.actions):
            if not isinstance(act, RepairAction):
                raise SchemaError(
                    f"RepairManifest.actions[{idx}] must be a RepairAction, "
                    f"got {type(act).__name__}"
                )

        if not isinstance(self.declared_loss, tuple):
            raise SchemaError(
                f"RepairManifest.declared_loss must be a tuple, "
                f"got {type(self.declared_loss).__name__}"
            )
        for idx, loss_item in enumerate(self.declared_loss):
            if not isinstance(loss_item, str) or not loss_item.strip():
                raise SchemaError(
                    f"RepairManifest.declared_loss[{idx}] must be a non-empty string, "
                    f"got {loss_item!r}"
                )

        if self.revalidate_report is not None:
            if not isinstance(self.revalidate_report, str) or not self.revalidate_report.strip():
                raise SchemaError(
                    f"RepairManifest.revalidate_report must be a non-empty string path or None, "
                    f"got {self.revalidate_report!r}"
                )

        if not isinstance(self.idempotency_key, str) or not _SHA256_HEX_64_PATTERN.match(
            self.idempotency_key
        ):
            raise SchemaError(
                f"RepairManifest.idempotency_key must be a 64-character lowercase hex string, "
                f"got {self.idempotency_key!r}"
            )

        if not isinstance(self.revalidation, RevalidationSummary):
            raise SchemaError(
                f"RepairManifest.revalidation must be a RevalidationSummary, "
                f"got {type(self.revalidation).__name__}"
            )

        if self.assurance_ceiling not in VALID_ASSURANCE_LEVELS:
            valid_sorted = sorted(VALID_ASSURANCE_LEVELS)
            raise AssuranceError(
                f"RepairManifest.assurance_ceiling must be one of {valid_sorted}, "
                f"got {self.assurance_ceiling!r}"
            )

        if self.plan_fingerprint is not None:
            if not isinstance(self.plan_fingerprint, str) or not self.plan_fingerprint.strip():
                raise SchemaError("RepairManifest.plan_fingerprint must be a non-empty string")
        if self.assurance is not None:
            if not isinstance(self.assurance, str) or not self.assurance.strip():
                raise SchemaError("RepairManifest.assurance must be a non-empty string")
        if not isinstance(self.recipe_versions, Mapping):
            raise SchemaError("RepairManifest.recipe_versions must be a Mapping")
        if self.profile_version is not None:
            if not isinstance(self.profile_version, str) or not self.profile_version.strip():
                raise SchemaError("RepairManifest.profile_version must be a non-empty string")
        if self.adapter_id is not None:
            if not isinstance(self.adapter_id, str) or not self.adapter_id.strip():
                raise SchemaError("RepairManifest.adapter_id must be a non-empty string")
        if self.adapter_version is not None:
            if not isinstance(self.adapter_version, str) or not self.adapter_version.strip():
                raise SchemaError("RepairManifest.adapter_version must be a non-empty string")
        if not isinstance(self.byte_counts, Mapping):
            raise SchemaError("RepairManifest.byte_counts must be a Mapping")
        if not isinstance(self.record_counts, Mapping):
            raise SchemaError("RepairManifest.record_counts must be a Mapping")

    def to_dict(self) -> dict[str, Any]:
        """Convert RepairManifest to dictionary matching schema."""
        d: dict[str, Any] = {
            "actions": [a.to_dict() for a in self.actions],
            "assurance_ceiling": self.assurance_ceiling,
            "declared_loss": list(self.declared_loss),
            "idempotency_key": self.idempotency_key,
            "input_fingerprint": self.input_fingerprint,
            "output_fingerprint": self.output_fingerprint,
            "policy": self.policy,
            "revalidate_report": self.revalidate_report,
            "revalidation": self.revalidation.to_dict(),
            "schema_version": self.schema_version,
        }
        if self.plan_fingerprint is not None:
            d["plan_fingerprint"] = self.plan_fingerprint
        if self.assurance is not None:
            d["assurance"] = self.assurance
        if self.recipe_versions:
            d["recipe_versions"] = dict(sorted(self.recipe_versions.items()))
        if self.profile_version is not None:
            d["profile_version"] = self.profile_version
        if self.adapter_id is not None:
            d["adapter_id"] = self.adapter_id
        if self.adapter_version is not None:
            d["adapter_version"] = self.adapter_version
        if self.byte_counts:
            d["byte_counts"] = dict(sorted(self.byte_counts.items()))
        if self.record_counts:
            d["record_counts"] = dict(sorted(self.record_counts.items()))
        return d


def build_report(
    *,
    session_id: str,
    source_fingerprint: str,
    tool_version: str,
    findings: Iterable[Finding],
    assurance: Assurance,
    limitation: str,
    coverage: Coverage | None = None,
) -> Report:
    """Construct an immutable Report from findings, deriving counts and sorting in total order.

    Note on assurance='A0' (unreadable):
    A0 designates that zero parseable events could be safely read from the session stream.
    Callers asserting A0 must ensure this invariant is respected.

    Counts are computed purely from the sorted findings and can never be overridden
    by caller parameters.
    Limitation must be non-empty for all assurance levels (A0-A4).
    Empty limitation raises AssuranceError.
    """
    if not isinstance(session_id, str) or not session_id.strip():
        raise SchemaError(f"session_id must be a non-empty string, got {session_id!r}")
    if not isinstance(source_fingerprint, str) or not source_fingerprint.strip():
        raise SchemaError(
            f"source_fingerprint must be a non-empty string, got {source_fingerprint!r}"
        )
    if not isinstance(tool_version, str) or not tool_version.strip():
        raise SchemaError(f"tool_version must be a non-empty string, got {tool_version!r}")

    if assurance not in VALID_ASSURANCE_LEVELS:
        valid_sorted = sorted(VALID_ASSURANCE_LEVELS)
        raise AssuranceError(
            f"Invalid assurance level {assurance!r}. Must be one of {valid_sorted}"
        )

    if not isinstance(limitation, str) or not limitation.strip():
        raise AssuranceError(
            f"limitation is required and must be non-empty for assurance level {assurance!r}"
        )

    if coverage is None:
        coverage = _default_coverage()
    elif not isinstance(coverage, Coverage):
        raise SchemaError(f"coverage must be a Coverage instance, got {type(coverage).__name__}")

    sorted_findings = tuple(sort_findings(findings))

    # Compute counts in O(n) without retaining payload
    by_sev: dict[str, int] = {sev: 0 for sev in REQUIRED_SEVERITIES}
    by_code_counter: Counter[str] = Counter()

    for f in sorted_findings:
        sev_str = f.severity.value
        if sev_str in by_sev:
            by_sev[sev_str] += 1
        by_code_counter[f.code] += 1

    by_code = dict(sorted(by_code_counter.items()))
    counts = Counts(
        by_severity=by_sev,
        by_code=by_code,
        total=len(sorted_findings),
    )

    return Report(
        schema_version=REPORT_SCHEMA_VERSION,
        session_id=session_id.strip(),
        source_fingerprint=source_fingerprint.strip(),
        tool_version=tool_version.strip(),
        findings=sorted_findings,
        counts=counts,
        assurance=assurance,
        limitation=limitation.strip(),
        coverage=coverage,
    )


def compute_manifest_idempotency_key(
    *,
    input_fingerprint: str,
    policy: str,
    actions: Iterable[RepairAction],
) -> str:
    """Compute 64-character sha256 hex idempotency key for a repair plan/manifest.

    The key binds:
    - input_fingerprint
    - policy (conservative vs salvage)
    - sorted atomic repair actions

    Why 64 characters?
    Unlike 16-character intra-session finding fingerprints, manifest idempotency keys
    serve as artifact-level cryptographic digests that uniquely identify and bind state
    transformations across global session repositories, preventing collisions and verifying
    replay idempotence across runs.
    """
    if not isinstance(input_fingerprint, str) or not input_fingerprint.strip():
        raise SchemaError(
            f"input_fingerprint must be a non-empty string, got {input_fingerprint!r}"
        )
    if policy not in VALID_POLICIES:
        raise SchemaError(f"policy must be one of {sorted(VALID_POLICIES)}, got {policy!r}")

    sorted_actions = sorted(actions, key=_action_sort_key)
    canonical_payload = {
        "actions": [a.to_dict() for a in sorted_actions],
        "input_fingerprint": input_fingerprint.strip(),
        "policy": policy.strip(),
    }
    canonical_str = to_canonical_json(canonical_payload)
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


def build_manifest(
    *,
    input_fingerprint: str,
    output_fingerprint: str,
    policy: Policy,
    actions: Iterable[RepairAction] = (),
    declared_loss: Iterable[str] = (),
    revalidate_report: str | None = None,
    revalidation: RevalidationSummary | Mapping[str, Any] | None = None,
    assurance_ceiling: str | None = None,
    plan_fingerprint: str | None = None,
    assurance: str | None = None,
    recipe_versions: Mapping[str, str] | None = None,
    profile_version: str | None = None,
    adapter_id: str | None = None,
    adapter_version: str | None = None,
    byte_counts: Mapping[str, int] | None = None,
    record_counts: Mapping[str, int] | None = None,
) -> RepairManifest:
    """Construct an immutable RepairManifest, sorting actions and computing the idempotency key.

    Enforces:
    - Actions are sorted deterministically before storage and key computation.
    - Idempotency key is computed from canonical serialization of input_fingerprint,
      policy, and sorted actions.
    - Declared loss items are validated as non-empty strings.
    - Binds plan_fingerprint, assurance, versions, and byte/record counts per FR-072/FR-073.
    - Binds revalidation summary struct and bounded assurance_ceiling.
    - Never generates or accepts a 'success' or 'passed' field.
    """
    if not isinstance(input_fingerprint, str) or not input_fingerprint.strip():
        raise SchemaError(
            f"input_fingerprint must be a non-empty string, got {input_fingerprint!r}"
        )
    if not isinstance(output_fingerprint, str) or not output_fingerprint.strip():
        raise SchemaError(
            f"output_fingerprint must be a non-empty string, got {output_fingerprint!r}"
        )
    if policy not in VALID_POLICIES:
        raise SchemaError(f"policy must be one of {sorted(VALID_POLICIES)}, got {policy!r}")

    sorted_actions = tuple(sorted(actions, key=_action_sort_key))

    norm_loss: list[str] = []
    for idx, item in enumerate(declared_loss):
        if not isinstance(item, str) or not item.strip():
            raise SchemaError(f"declared_loss[{idx}] must be a non-empty string, got {item!r}")
        item_str = item.strip()
        try:
            enforce_content_free_text(item_str, context="declared_loss")
        except FindingError as err:
            raise ContentLeakError(f"Content leak in declared_loss[{idx}]: {err}") from err
        norm_loss.append(item_str)
    sorted_loss = tuple(norm_loss)

    norm_reval: str | None = None
    if revalidate_report is not None:
        if not isinstance(revalidate_report, str) or not revalidate_report.strip():
            raise SchemaError(
                f"revalidate_report must be a non-empty string path or None, "
                f"got {revalidate_report!r}"
            )
        norm_reval = revalidate_report.strip().replace("\\", "/")
        try:
            enforce_content_free_text(norm_reval, context="revalidate_report")
        except FindingError as err:
            raise ContentLeakError(f"Content leak in revalidate_report: {err}") from err

    # Normalize revalidation summary
    norm_reval_obj: RevalidationSummary
    if revalidation is None:
        norm_reval_obj = RevalidationSummary(
            assurance="A3",
            error_count=0,
            warning_count=0,
            profile_id="neutral",
            profile_version="1.0.0",
        )
    elif isinstance(revalidation, RevalidationSummary):
        norm_reval_obj = revalidation
    elif isinstance(revalidation, Mapping):
        for rf in ("assurance", "error_count", "warning_count", "profile_id", "profile_version"):
            if rf not in revalidation:
                raise SchemaError(f"revalidation missing required field '{rf}'")
        norm_reval_obj = RevalidationSummary(
            assurance=cast(Assurance, revalidation["assurance"]),
            error_count=int(revalidation["error_count"]),
            warning_count=int(revalidation["warning_count"]),
            profile_id=str(revalidation["profile_id"]),
            profile_version=str(revalidation["profile_version"]),
            report_fingerprint=(
                str(revalidation["report_fingerprint"])
                if revalidation.get("report_fingerprint") is not None
                else None
            ),
        )
    else:
        raise SchemaError(
            "revalidation must be a RevalidationSummary or Mapping, "
            f"got {type(revalidation).__name__}"
        )

    # Normalize assurance ceiling
    norm_ceiling: str
    if assurance_ceiling is None:
        from sesslint.repair.assurance import compute_assurance_ceiling

        norm_ceiling = compute_assurance_ceiling(norm_reval_obj.assurance, policy)
    else:
        if assurance_ceiling not in VALID_ASSURANCE_LEVELS:
            valid_sorted = sorted(VALID_ASSURANCE_LEVELS)
            raise AssuranceError(
                f"Invalid assurance_ceiling {assurance_ceiling!r}. Must be one of {valid_sorted}"
            )
        norm_ceiling = assurance_ceiling

    try:
        enforce_content_free_text(norm_reval_obj.profile_id, context="revalidation.profile_id")
        enforce_content_free_text(
            norm_reval_obj.profile_version, context="revalidation.profile_version"
        )
        if norm_reval_obj.report_fingerprint is not None:
            enforce_content_free_text(
                norm_reval_obj.report_fingerprint, context="revalidation.report_fingerprint"
            )
        if adapter_id is not None:
            enforce_content_free_text(adapter_id, context="adapter_id")
    except FindingError as err:
        raise ContentLeakError(f"Content leak in manifest metadata: {err}") from err

    idempotency_key = compute_manifest_idempotency_key(
        input_fingerprint=input_fingerprint.strip(),
        policy=policy,
        actions=sorted_actions,
    )

    return RepairManifest(
        schema_version=MANIFEST_SCHEMA_VERSION,
        input_fingerprint=input_fingerprint.strip(),
        output_fingerprint=output_fingerprint.strip(),
        policy=policy,
        actions=sorted_actions,
        declared_loss=sorted_loss,
        revalidate_report=norm_reval,
        idempotency_key=idempotency_key,
        revalidation=norm_reval_obj,
        assurance_ceiling=norm_ceiling,
        plan_fingerprint=plan_fingerprint.strip() if plan_fingerprint is not None else None,
        assurance=assurance.strip() if assurance is not None else None,
        recipe_versions=dict(recipe_versions) if recipe_versions is not None else {},
        profile_version=profile_version.strip() if profile_version is not None else None,
        adapter_id=adapter_id.strip() if adapter_id is not None else None,
        adapter_version=adapter_version.strip() if adapter_version is not None else None,
        byte_counts=dict(byte_counts) if byte_counts is not None else {},
        record_counts=dict(record_counts) if record_counts is not None else {},
    )


def dump_report(report: Report) -> str:
    """Serialize Report to deterministic canonical JSON string."""
    if not isinstance(report, Report):
        raise TypeError(f"Expected Report instance, got {type(report).__name__}")
    return to_canonical_json(report.to_dict())


def parse_report(obj: Mapping[str, Any] | str) -> Report:
    """Parse and validate a Report instance from a mapping or JSON string.

    Version-gated against sesslint.report/v1. Rejects unknown top-level fields (SL302).
    """
    if isinstance(obj, str):
        try:
            data = json.loads(obj)
        except json.JSONDecodeError as err:
            raise SchemaError(f"Malformed JSON in report: {err}") from err
    elif isinstance(obj, Mapping):
        data = obj
    else:
        raise SchemaError(f"Report must be a Mapping or JSON string, got {type(obj).__name__}")

    if not isinstance(data, Mapping):
        raise SchemaError(f"Report root must be a mapping, got {type(data).__name__}")

    # Check for unknown top-level fields
    for key in data:
        if key not in KNOWN_REPORT_FIELDS:
            raise UnknownFieldError(f"Unknown top-level field in report: '{key}'", field_name=key)

    # Check required fields
    for req in REQUIRED_REPORT_FIELDS:
        if req not in data:
            raise SchemaError(f"Missing required field in report: '{req}'")

    schema_version = data["schema_version"]
    if schema_version != REPORT_SCHEMA_VERSION:
        raise VersionError(
            f"Unsupported report schema version: {schema_version!r}",
            version=str(schema_version),
        )

    session_id = data["session_id"]
    if not isinstance(session_id, str) or not session_id.strip():
        raise SchemaError(f"Report.session_id must be a non-empty string, got {session_id!r}")

    source_fingerprint = data["source_fingerprint"]
    if not isinstance(source_fingerprint, str) or not source_fingerprint.strip():
        raise SchemaError(
            f"Report.source_fingerprint must be a non-empty string, got {source_fingerprint!r}"
        )

    tool_version = data["tool_version"]
    if not isinstance(tool_version, str) or not tool_version.strip():
        raise SchemaError(f"Report.tool_version must be a non-empty string, got {tool_version!r}")

    raw_findings = data["findings"]
    if not isinstance(raw_findings, (list, tuple)):
        raise SchemaError(f"findings must be a list or tuple, got {type(raw_findings).__name__}")
    parsed_findings = tuple(sort_findings(parse_finding_dict(f) for f in raw_findings))

    raw_counts = data["counts"]
    if not isinstance(raw_counts, Mapping):
        raise SchemaError(f"counts must be a mapping, got {type(raw_counts).__name__}")
    for k in raw_counts:
        if k not in ("by_severity", "by_code", "total"):
            raise UnknownFieldError(f"Unknown field in counts: '{k}'", field_name=k)
    for c_req in ("by_severity", "by_code", "total"):
        if c_req not in raw_counts:
            raise SchemaError(f"Missing required field in counts: '{c_req}'")

    raw_sev = raw_counts["by_severity"]
    if not isinstance(raw_sev, Mapping):
        raise SchemaError(f"counts.by_severity must be a mapping, got {type(raw_sev).__name__}")
    for k in raw_sev:
        if k not in REQUIRED_SEVERITIES:
            raise UnknownFieldError(f"Unknown severity in counts.by_severity: '{k}'", field_name=k)
    for s_req in REQUIRED_SEVERITIES:
        if s_req not in raw_sev:
            raise SchemaError(f"Missing required severity in counts.by_severity: '{s_req}'")

    raw_by_code = raw_counts["by_code"]
    if not isinstance(raw_by_code, Mapping):
        raise SchemaError(f"counts.by_code must be a mapping, got {type(raw_by_code).__name__}")

    raw_total = raw_counts["total"]
    if not isinstance(raw_total, int) or isinstance(raw_total, bool) or raw_total < 0:
        raise SchemaError(f"counts.total must be a non-negative integer, got {raw_total!r}")

    counts = Counts(
        by_severity=dict(raw_sev),
        by_code=dict(raw_by_code),
        total=raw_total,
    )

    assurance = data["assurance"]
    if assurance not in VALID_ASSURANCE_LEVELS:
        valid_sorted = sorted(VALID_ASSURANCE_LEVELS)
        raise AssuranceError(
            f"Invalid assurance level {assurance!r}. Must be one of {valid_sorted}"
        )

    limitation = data["limitation"]
    if not isinstance(limitation, str) or not limitation.strip():
        raise AssuranceError(f"Report limitation must be a non-empty string, got {limitation!r}")

    raw_cov = data["coverage"]
    if not isinstance(raw_cov, Mapping):
        raise SchemaError(f"Report.coverage must be a mapping, got {type(raw_cov).__name__}")
    for cov_k in raw_cov:
        if cov_k not in ("performed", "skipped", "adapter", "profile"):
            raise UnknownFieldError(f"Unknown field in coverage: '{cov_k}'", field_name=cov_k)
    for req_cov in ("performed", "skipped", "adapter", "profile"):
        if req_cov not in raw_cov:
            raise SchemaError(f"Missing required field in coverage: '{req_cov}'")

    raw_perf = raw_cov["performed"]
    if not isinstance(raw_perf, (list, tuple)):
        raise SchemaError(
            f"coverage.performed must be a list or tuple, got {type(raw_perf).__name__}"
        )
    parsed_perf: list[str] = []
    for idx, item in enumerate(raw_perf):
        if not isinstance(item, str) or not item.strip():
            raise SchemaError(f"coverage.performed[{idx}] must be a non-empty string, got {item!r}")
        parsed_perf.append(item.strip())

    raw_skipped = raw_cov["skipped"]
    if not isinstance(raw_skipped, (list, tuple)):
        raise SchemaError(
            f"coverage.skipped must be a list or tuple, got {type(raw_skipped).__name__}"
        )
    parsed_skips: list[CoverageSkip] = []
    for idx, item in enumerate(raw_skipped):
        if not isinstance(item, Mapping):
            raise SchemaError(
                f"coverage.skipped[{idx}] must be a mapping, got {type(item).__name__}"
            )
        for sk_k in item:
            if sk_k not in ("check", "reason", "detail"):
                raise UnknownFieldError(
                    f"Unknown field in coverage.skipped[{idx}]: '{sk_k}'", field_name=sk_k
                )
        if "check" not in item:
            raise SchemaError(f"coverage.skipped[{idx}] missing required field 'check'")
        if "reason" not in item:
            raise SchemaError(f"coverage.skipped[{idx}] missing required field 'reason'")
        chk = item["check"]
        if not isinstance(chk, str) or not chk.strip():
            raise SchemaError(
                f"coverage.skipped[{idx}].check must be a non-empty string, got {chk!r}"
            )
        rsn = item["reason"]
        if rsn not in VALID_COVERAGE_SKIP_REASONS:
            valid_rsns = sorted(VALID_COVERAGE_SKIP_REASONS)
            raise SchemaError(
                f"Invalid coverage skip reason '{rsn}' in skipped[{idx}]. "
                f"Must be one of {valid_rsns}"
            )
        dtl = item.get("detail", "")
        if not isinstance(dtl, str):
            raise SchemaError(
                f"coverage.skipped[{idx}].detail must be a string, got {type(dtl).__name__}"
            )
        parsed_skips.append(CoverageSkip(check=chk.strip(), reason=rsn, detail=dtl.strip()))

    raw_adapter = raw_cov["adapter"]
    if not isinstance(raw_adapter, Mapping):
        raise SchemaError(f"coverage.adapter must be a mapping, got {type(raw_adapter).__name__}")
    for k in raw_adapter:
        if k not in ("id", "name", "version"):
            raise UnknownFieldError(f"Unknown field in coverage.adapter: '{k}'", field_name=k)
    ad_id = raw_adapter.get("id") or raw_adapter.get("name")
    if not isinstance(ad_id, str) or not ad_id.strip():
        raise SchemaError("coverage.adapter must contain non-empty 'id'")
    ad_ver = raw_adapter.get("version")
    if not isinstance(ad_ver, str) or not ad_ver.strip():
        raise SchemaError("coverage.adapter must contain non-empty 'version'")
    parsed_adapter = {"id": ad_id.strip(), "version": ad_ver.strip()}
    if "name" in raw_adapter and isinstance(raw_adapter["name"], str):
        parsed_adapter["name"] = raw_adapter["name"].strip()

    raw_profile = raw_cov["profile"]
    if not isinstance(raw_profile, Mapping):
        raise SchemaError(f"coverage.profile must be a mapping, got {type(raw_profile).__name__}")
    for k in raw_profile:
        if k not in ("id", "name", "version"):
            raise UnknownFieldError(f"Unknown field in coverage.profile: '{k}'", field_name=k)
    pr_id = raw_profile.get("id") or raw_profile.get("name")
    if not isinstance(pr_id, str) or not pr_id.strip():
        raise SchemaError("coverage.profile must contain non-empty 'id'")
    pr_ver = raw_profile.get("version")
    if not isinstance(pr_ver, str) or not pr_ver.strip():
        raise SchemaError("coverage.profile must contain non-empty 'version'")
    parsed_profile = {"id": pr_id.strip(), "version": pr_ver.strip()}
    if "name" in raw_profile and isinstance(raw_profile["name"], str):
        parsed_profile["name"] = raw_profile["name"].strip()

    coverage = Coverage(
        performed=tuple(parsed_perf),
        skipped=tuple(sorted(parsed_skips, key=_skip_sort_key)),
        adapter=parsed_adapter,
        profile=parsed_profile,
    )

    return Report(
        schema_version=REPORT_SCHEMA_VERSION,
        session_id=session_id.strip(),
        source_fingerprint=source_fingerprint.strip(),
        tool_version=tool_version.strip(),
        findings=parsed_findings,
        counts=counts,
        assurance=cast(Assurance, assurance),
        limitation=limitation.strip(),
        coverage=coverage,
    )


def dump_manifest(manifest: RepairManifest) -> str:
    """Serialize RepairManifest to deterministic canonical JSON string."""
    if not isinstance(manifest, RepairManifest):
        raise TypeError(f"Expected RepairManifest instance, got {type(manifest).__name__}")
    return to_canonical_json(manifest.to_dict())


def parse_manifest(obj: Mapping[str, Any] | str) -> RepairManifest:
    """Parse and validate a RepairManifest from a mapping or JSON string.

    Version-gated against sesslint.repair-manifest/v1. Rejects unknown top-level fields (SL302)
    and synthetic success claims (FR-059).
    """
    if isinstance(obj, str):
        try:
            data = json.loads(obj)
        except json.JSONDecodeError as err:
            raise SchemaError(f"Malformed JSON in manifest: {err}") from err
    elif isinstance(obj, Mapping):
        data = obj
    else:
        raise SchemaError(f"Manifest must be a Mapping or JSON string, got {type(obj).__name__}")

    if not isinstance(data, Mapping):
        raise SchemaError(f"Manifest root must be a mapping, got {type(data).__name__}")

    # Explicit refusal of synthetic success fields
    for forbidden in ("success", "passed", "ok", "healthy"):
        if forbidden in data:
            raise SchemaError(
                f"Manifest must not contain synthetic '{forbidden}' field "
                f"(never-synthetic-success invariant)"
            )

    # Check for unknown top-level fields
    for key in data:
        if key not in KNOWN_MANIFEST_FIELDS:
            raise UnknownFieldError(
                f"Unknown top-level field in manifest: '{key}'",
                field_name=key,
            )

    # Check required fields
    for req in REQUIRED_MANIFEST_FIELDS:
        if req not in data:
            raise SchemaError(f"Missing required field in manifest: '{req}'")

    schema_version = data["schema_version"]
    if schema_version != MANIFEST_SCHEMA_VERSION:
        raise VersionError(
            f"Unsupported manifest schema version: {schema_version!r}",
            version=str(schema_version),
        )

    input_fingerprint = data["input_fingerprint"]
    if not isinstance(input_fingerprint, str) or not input_fingerprint.strip():
        raise SchemaError(
            f"RepairManifest.input_fingerprint must be a non-empty string, "
            f"got {input_fingerprint!r}"
        )

    output_fingerprint = data["output_fingerprint"]
    if not isinstance(output_fingerprint, str) or not output_fingerprint.strip():
        raise SchemaError(
            f"RepairManifest.output_fingerprint must be a non-empty string, "
            f"got {output_fingerprint!r}"
        )

    policy = data["policy"]
    if policy not in VALID_POLICIES:
        raise SchemaError(f"Invalid manifest policy: {policy!r}")

    raw_actions = data["actions"]
    if not isinstance(raw_actions, (list, tuple)):
        raise SchemaError(f"actions must be a list or tuple, got {type(raw_actions).__name__}")

    actions_list: list[RepairAction] = []
    for idx, item in enumerate(raw_actions):
        if not isinstance(item, Mapping):
            raise SchemaError(f"actions[{idx}] must be a mapping, got {type(item).__name__}")
        if "kind" not in item:
            raise SchemaError(f"actions[{idx}] missing required field 'kind'")
        for k in item:
            if k not in ("kind", "record_id", "detail"):
                raise UnknownFieldError(f"Unknown field in action[{idx}]: '{k}'", field_name=k)
        kind = item["kind"]
        if not isinstance(kind, str) or not kind.strip():
            raise SchemaError(f"actions[{idx}].kind must be a non-empty string, got {kind!r}")

        rec_id = item.get("record_id")
        if rec_id is not None and (not isinstance(rec_id, str) or not rec_id.strip()):
            raise SchemaError(
                f"actions[{idx}].record_id must be non-empty string or None, got {rec_id!r}"
            )

        detail = item.get("detail", "")
        if not isinstance(detail, str):
            raise SchemaError(
                f"actions[{idx}].detail must be a string, got {type(detail).__name__}"
            )

        actions_list.append(
            RepairAction(
                kind=kind.strip(),
                record_id=rec_id.strip() if rec_id is not None else None,
                detail=detail.strip(),
            )
        )

    sorted_actions = tuple(sorted(actions_list, key=_action_sort_key))

    raw_loss = data["declared_loss"]
    if not isinstance(raw_loss, (list, tuple)):
        raise SchemaError(f"declared_loss must be a list or tuple, got {type(raw_loss).__name__}")
    loss_list: list[str] = []
    for idx, loss_item in enumerate(raw_loss):
        if not isinstance(loss_item, str) or not loss_item.strip():
            raise SchemaError(f"declared_loss[{idx}] must be a non-empty string, got {loss_item!r}")
        loss_list.append(loss_item.strip())
    loss_tuple = tuple(loss_list)

    reval = data["revalidate_report"]
    reval_str: str | None = None
    if reval is not None:
        if not isinstance(reval, str) or not reval.strip():
            raise SchemaError(
                f"RepairManifest.revalidate_report must be a non-empty string path or None, "
                f"got {reval!r}"
            )
        reval_str = reval.strip().replace("\\", "/")

    idempotency_key = data["idempotency_key"]
    if not isinstance(idempotency_key, str) or not _SHA256_HEX_64_PATTERN.match(idempotency_key):
        raise SchemaError(
            f"RepairManifest.idempotency_key must be a 64-character lowercase hex string, "
            f"got {idempotency_key!r}"
        )

    plan_fingerprint = data.get("plan_fingerprint")
    if plan_fingerprint is not None and (
        not isinstance(plan_fingerprint, str) or not plan_fingerprint.strip()
    ):
        raise SchemaError("RepairManifest.plan_fingerprint must be a non-empty string")

    assurance = data.get("assurance")
    if assurance is not None and (not isinstance(assurance, str) or not assurance.strip()):
        raise SchemaError("RepairManifest.assurance must be a non-empty string")

    recipe_versions = data.get("recipe_versions")
    if recipe_versions is not None and not isinstance(recipe_versions, Mapping):
        raise SchemaError("RepairManifest.recipe_versions must be a mapping")

    profile_version = data.get("profile_version")
    if profile_version is not None and (
        not isinstance(profile_version, str) or not profile_version.strip()
    ):
        raise SchemaError("RepairManifest.profile_version must be a non-empty string")

    adapter_id = data.get("adapter_id")
    if adapter_id is not None and (not isinstance(adapter_id, str) or not adapter_id.strip()):
        raise SchemaError("RepairManifest.adapter_id must be a non-empty string")

    adapter_version = data.get("adapter_version")
    if adapter_version is not None and (
        not isinstance(adapter_version, str) or not adapter_version.strip()
    ):
        raise SchemaError("RepairManifest.adapter_version must be a non-empty string")

    byte_counts = data.get("byte_counts")
    if byte_counts is not None and not isinstance(byte_counts, Mapping):
        raise SchemaError("RepairManifest.byte_counts must be a mapping")

    record_counts = data.get("record_counts")
    if record_counts is not None and not isinstance(record_counts, Mapping):
        raise SchemaError("RepairManifest.record_counts must be a mapping")

    # Validate and parse revalidation summary
    raw_reval = data["revalidation"]
    if not isinstance(raw_reval, Mapping):
        raise SchemaError(
            f"RepairManifest.revalidation must be a mapping, got {type(raw_reval).__name__}"
        )
    for k in raw_reval:
        if k not in (
            "assurance",
            "error_count",
            "warning_count",
            "profile_id",
            "profile_version",
            "report_fingerprint",
        ):
            raise UnknownFieldError(
                f"Unknown field in manifest revalidation: '{k}'",
                field_name=k,
            )
    for req_rf in ("assurance", "error_count", "warning_count", "profile_id", "profile_version"):
        if req_rf not in raw_reval:
            raise SchemaError(f"Missing required field in manifest revalidation: '{req_rf}'")

    rev_assurance = raw_reval["assurance"]
    if rev_assurance not in VALID_ASSURANCE_LEVELS:
        valid_sorted = sorted(VALID_ASSURANCE_LEVELS)
        raise AssuranceError(
            f"Invalid revalidation assurance: {rev_assurance!r}. Must be one of {valid_sorted}"
        )

    rev_errors = raw_reval["error_count"]
    if not isinstance(rev_errors, int) or isinstance(rev_errors, bool) or rev_errors < 0:
        raise SchemaError(
            f"revalidation.error_count must be a non-negative integer, got {rev_errors!r}"
        )

    rev_warnings = raw_reval["warning_count"]
    if not isinstance(rev_warnings, int) or isinstance(rev_warnings, bool) or rev_warnings < 0:
        raise SchemaError(
            f"revalidation.warning_count must be a non-negative integer, got {rev_warnings!r}"
        )

    rev_prof_id = raw_reval["profile_id"]
    if not isinstance(rev_prof_id, str) or not rev_prof_id.strip():
        raise SchemaError("revalidation.profile_id must be a non-empty string")

    rev_prof_ver = raw_reval["profile_version"]
    if not isinstance(rev_prof_ver, str) or not rev_prof_ver.strip():
        raise SchemaError("revalidation.profile_version must be a non-empty string")

    rev_rfp = raw_reval.get("report_fingerprint")
    if rev_rfp is not None and (not isinstance(rev_rfp, str) or not rev_rfp.strip()):
        raise SchemaError("revalidation.report_fingerprint must be a non-empty string or None")

    parsed_reval = RevalidationSummary(
        assurance=cast(Assurance, rev_assurance),
        error_count=rev_errors,
        warning_count=rev_warnings,
        profile_id=rev_prof_id.strip(),
        profile_version=rev_prof_ver.strip(),
        report_fingerprint=rev_rfp.strip() if rev_rfp is not None else None,
    )

    assurance_ceiling = data["assurance_ceiling"]
    if assurance_ceiling not in VALID_ASSURANCE_LEVELS:
        valid_sorted = sorted(VALID_ASSURANCE_LEVELS)
        raise AssuranceError(
            f"Invalid assurance_ceiling: {assurance_ceiling!r}. Must be one of {valid_sorted}"
        )

    return RepairManifest(
        schema_version=MANIFEST_SCHEMA_VERSION,
        input_fingerprint=input_fingerprint.strip(),
        output_fingerprint=output_fingerprint.strip(),
        policy=cast(Policy, policy),
        actions=sorted_actions,
        declared_loss=loss_tuple,
        revalidate_report=reval_str,
        idempotency_key=idempotency_key,
        revalidation=parsed_reval,
        assurance_ceiling=assurance_ceiling,
        plan_fingerprint=plan_fingerprint.strip() if plan_fingerprint is not None else None,
        assurance=assurance.strip() if assurance is not None else None,
        recipe_versions=dict(recipe_versions) if recipe_versions is not None else {},
        profile_version=profile_version.strip() if profile_version is not None else None,
        adapter_id=adapter_id.strip() if adapter_id is not None else None,
        adapter_version=adapter_version.strip() if adapter_version is not None else None,
        byte_counts=dict(byte_counts) if byte_counts is not None else {},
        record_counts=dict(record_counts) if record_counts is not None else {},
    )


def enforce_content_free(
    artifact: Report | RepairManifest,
    *,
    forbidden_substrings: Collection[str] | None = (),
) -> None:
    """Enforce SessLint's content-free invariant (FR-081) on a Report or RepairManifest.

    Inspects all human-readable message, detail, and identity coordinates for:
    1. Intrinsic content leaks: control chars, emails, private keys, bearer tokens,
       API keys, credentials.
    2. Extrinsic content leaks: any substring in forbidden_substrings (such as raw
       session payload text).

    Raises:
        ContentLeakError: If any forbidden substring, credential, or PII leak is found.
        TypeError: If artifact is neither Report nor RepairManifest.
    """
    clean_substrings: list[str] = []
    if forbidden_substrings is not None:
        clean_substrings = [s.strip() for s in forbidden_substrings if s and s.strip()]

    def check_text(text: str, context: str) -> None:
        try:
            enforce_content_free_text(text, context=context)
        except FindingError as err:
            raise ContentLeakError(f"Intrinsic content leak in {context}: {err}") from err

        for sub in clean_substrings:
            if sub in text or sub.lower() in text.lower():
                raise ContentLeakError(
                    f"Forbidden payload text {sub!r} detected in {context}: {text!r}"
                )

    if isinstance(artifact, Report):
        check_text(artifact.session_id, "Report.session_id")
        check_text(artifact.source_fingerprint, "Report.source_fingerprint")
        check_text(artifact.tool_version, "Report.tool_version")
        check_text(artifact.limitation, "Report.limitation")
        for s_idx, sk in enumerate(artifact.coverage.skipped):
            check_text(sk.check, f"Report.coverage.skipped[{s_idx}].check")
            check_text(sk.detail, f"Report.coverage.skipped[{s_idx}].detail")
        for idx, f in enumerate(artifact.findings):
            check_text(f.message, f"Report.findings[{idx}].message")
            if f.message_template is not None:
                check_text(f.message_template, f"Report.findings[{idx}].message_template")
            check_text(f.source.path, f"Report.findings[{idx}].source.path")
            if f.source.record_id is not None:
                check_text(f.source.record_id, f"Report.findings[{idx}].source.record_id")
            for r_idx, rel_id in enumerate(f.related_ids):
                check_text(rel_id, f"Report.findings[{idx}].related_ids[{r_idx}]")

    elif isinstance(artifact, RepairManifest):
        check_text(artifact.input_fingerprint, "RepairManifest.input_fingerprint")
        check_text(artifact.output_fingerprint, "RepairManifest.output_fingerprint")
        if artifact.revalidate_report is not None:
            check_text(artifact.revalidate_report, "RepairManifest.revalidate_report")
        for l_idx, loss_item in enumerate(artifact.declared_loss):
            check_text(loss_item, f"RepairManifest.declared_loss[{l_idx}]")
        for a_idx, act in enumerate(artifact.actions):
            check_text(act.kind, f"RepairManifest.actions[{a_idx}].kind")
            if act.record_id is not None:
                check_text(act.record_id, f"RepairManifest.actions[{a_idx}].record_id")
            check_text(act.detail, f"RepairManifest.actions[{a_idx}].detail")
        check_text(artifact.revalidation.profile_id, "RepairManifest.revalidation.profile_id")
        check_text(
            artifact.revalidation.profile_version, "RepairManifest.revalidation.profile_version"
        )
        if artifact.revalidation.report_fingerprint is not None:
            check_text(
                artifact.revalidation.report_fingerprint,
                "RepairManifest.revalidation.report_fingerprint",
            )
        if artifact.adapter_id is not None:
            check_text(artifact.adapter_id, "RepairManifest.adapter_id")
    else:
        raise TypeError(f"Expected Report or RepairManifest, got {type(artifact).__name__}")


def get_report_schema_path() -> Path:
    """Return filesystem path to schemas/sesslint.report.v1.json."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    dev_path = repo_root / "schemas" / "sesslint.report.v1.json"
    if dev_path.is_file():
        return dev_path
    prefix_path = Path(sys.prefix) / "share" / "sesslint" / "schemas" / "sesslint.report.v1.json"
    if prefix_path.is_file():
        return prefix_path
    return dev_path


def load_report_schema() -> dict[str, Any]:
    """Load the committed JSON Schema for sesslint.report/v1 as a dict."""
    path = get_report_schema_path()
    if not path.is_file():
        raise FileNotFoundError(f"Report schema not found at {path}")
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def get_manifest_schema_path() -> Path:
    """Return filesystem path to schemas/sesslint.repair-manifest.v1.json."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    dev_path = repo_root / "schemas" / "sesslint.repair-manifest.v1.json"
    if dev_path.is_file():
        return dev_path
    prefix_path = (
        Path(sys.prefix) / "share" / "sesslint" / "schemas" / "sesslint.repair-manifest.v1.json"
    )
    if prefix_path.is_file():
        return prefix_path
    return dev_path


def load_manifest_schema() -> dict[str, Any]:
    """Load the committed JSON Schema for sesslint.repair-manifest/v1 as a dict."""
    path = get_manifest_schema_path()
    if not path.is_file():
        raise FileNotFoundError(f"Manifest schema not found at {path}")
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def apply_plan_assurance(base: str, plan: Any) -> str:
    """Apply assurance cap from a repair plan's loss characteristics."""
    return cap_assurance(base, plan)


def minimize_path(path: Path | str, *, home: Path | None = None) -> str:
    """Render a path in minimized home-relative form (e.g. ~/dir/file.jsonl).

    If path is under home directory, renders as '~/relative/path' (or '~' for home itself).
    If path is outside home directory, renders as '.._<8hex>/filename'
    where 8hex is sha1(parent)[:8].
    Non-home absolute paths are never emitted in default mode.
    """
    if isinstance(path, str):
        if path.startswith("~/") or path == "~" or path.startswith(".._"):
            return path

    p = Path(path)
    p_str = str(path).replace("\\", "/")
    is_abs = p.is_absolute() or p_str.startswith("/") or (len(p_str) > 1 and p_str[1] == ":")
    h = home if home is not None else Path.home()

    if is_abs:
        try:
            rel = p.relative_to(h)
            if rel.parts == ():
                return "~"
            return f"~/{rel.as_posix()}"
        except (ValueError, RuntimeError):
            pass

        try:
            resolved_p = p.resolve()
            resolved_h = h.resolve()
            rel = resolved_p.relative_to(resolved_h)
            if rel.parts == ():
                return "~"
            return f"~/{rel.as_posix()}"
        except (ValueError, RuntimeError):
            pass

        parent_str = str(p.parent).replace("\\", "/")
        p_hash = hashlib.sha1(parent_str.encode("utf-8")).hexdigest()[:8]
        return f".._{p_hash}/{p.name}"

    parent_str = str(p.parent).replace("\\", "/") if p.parent != Path(".") else ""
    if parent_str:
        p_hash = hashlib.sha1(parent_str.encode("utf-8")).hexdigest()[:8]
        return f".._{p_hash}/{p.name}"
    return p.name


def short_hash(identifier: str, length: int = 8) -> str:
    """Compute truncated sha256 hex digest of an identifier string."""
    return hashlib.sha256(identifier.encode("utf-8")).hexdigest()[:length]


def minimize_id(
    identifier: str,
    *,
    ordinal: int | None = None,
    include_content: bool = False,
    as_dict: bool = False,
) -> Any:
    """Minimize an event or record identifier to ordinal + short hash.

    When include_content is False:
        - string mode: f"#{ordinal}" if ordinal is not None, else short_hash(identifier, 8)
        - dict mode: {"short": short_hash(identifier, 8)} (+ "ordinal": ordinal if present)
    When include_content is True:
        - string mode: identifier
        - dict mode: {"short": short_hash(identifier, 8), "full": identifier}
          (+ "ordinal": ordinal if present)
    """
    s_hash = short_hash(identifier, 8)
    if as_dict:
        res: dict[str, Any] = {"short": s_hash}
        if ordinal is not None:
            res["ordinal"] = ordinal
        if include_content:
            res["full"] = identifier
        return res

    if include_content:
        return identifier
    if ordinal is not None:
        return f"#{ordinal}"
    return s_hash


@dataclass(frozen=True, slots=True)
class ReproMetadata:
    """Environment reproduction metadata devoid of machine or user identities."""

    cli_version: str
    schema_versions: dict[str, str]
    adapter: dict[str, str]
    profile: dict[str, str]
    detection: dict[str, Any]
    platform: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter": dict(self.adapter),
            "cli_version": self.cli_version,
            "detection": dict(self.detection),
            "platform": dict(self.platform),
            "profile": dict(self.profile),
            "schema_versions": dict(self.schema_versions),
        }


def build_repro_metadata(
    *,
    adapter_name: str = "canonical",
    adapter_version: str = "1.0",
    profile_name: str = "neutral",
    profile_version: str = "1.0",
    detection_method: str = "auto",
    detection_confidence: float | None = 1.0,
) -> ReproMetadata:
    """Build reproduction metadata without host, user, or machine identifiers."""
    from sesslint import __version__

    return ReproMetadata(
        cli_version=__version__,
        schema_versions={
            "manifest": MANIFEST_SCHEMA_VERSION,
            "report": REPORT_SCHEMA_VERSION,
            "session": "sesslint.session/v1",
        },
        adapter={"name": adapter_name, "version": adapter_version},
        profile={"name": profile_name, "version": profile_version},
        detection={"confidence": detection_confidence, "method": detection_method},
        platform={
            "os": sys.platform,
            "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        },
    )


def get_finding_remediation(f: Finding, *, home: Path | None = None) -> str:
    """Return concise content-free remediation instructions for a finding."""
    from sesslint.codes import Repairability

    min_path = minimize_path(f.source.path, home=home)
    if f.repairability == Repairability.DETERMINISTIC:
        return f"deterministic recipe available: run 'sesslint repair {min_path}'"
    if f.repairability == Repairability.LOSSY_EXPLICIT:
        return f"lossy-explicit recipe available: run 'sesslint repair {min_path} --policy salvage'"
    if f.repairability == Repairability.MANUAL:
        return "manual inspection required; automated repair refused"
    return "unsupported defect or structure; automated repair refused"


finding_report_sort_key = finding_sort_key
"""Alias to finding_sort_key ensuring reports and renderers use deterministic FR-094 order."""


def format_finding_content_free(
    f: Finding,
    *,
    include_content: bool = False,
    home: Path | None = None,
    ordinal: int | None = None,
) -> dict[str, Any]:
    """Format a finding into schema-compliant dictionary without raw payload text."""
    min_path = minimize_path(f.source.path, home=home)
    byte_val = None
    if f.evidence and isinstance(f.evidence, Mapping):
        b = f.evidence.get("byte_offset", f.evidence.get("byte"))
        if isinstance(b, int) and not isinstance(b, bool) and b >= 0:
            byte_val = b

    span_dict: dict[str, Any] = {
        "path": min_path,
        "line": f.source.line,
        "byte": byte_val,
    }

    ev_dict: dict[str, Any] = {}
    if f.evidence and isinstance(f.evidence, Mapping):
        for k, v in f.evidence.items():
            if not include_content and k in ("content", "text", "payload", "message", "prompt"):
                continue
            if isinstance(v, str) and not include_content:
                if len(v) > 16 and ("id" in k.lower() or "uuid" in k.lower()):
                    ev_dict[k] = short_hash(v, 8)
                else:
                    ev_dict[k] = v
            else:
                ev_dict[k] = v

    if ordinal is not None and "ordinal" not in ev_dict:
        ev_dict["ordinal"] = ordinal

    remediation = get_finding_remediation(f, home=home)

    res: dict[str, Any] = {
        "code": f.code,
        "evidence": ev_dict if ev_dict else None,
        "fingerprint": f.fingerprint,
        "remediation": remediation,
        "repairability": f.repairability.value,
        "severity": f.severity.value,
        "span": span_dict,
    }
    if include_content:
        res["message"] = f.message
        if f.source.record_id:
            res["record_id"] = f.source.record_id

    return res


def render_json(
    report: Report | Mapping[str, Any],
    *,
    include_content: bool = False,
    repro: ReproMetadata | dict[str, Any] | None = None,
    home: Path | None = None,
) -> str:
    """Render Report or report mapping to strictly validated, content-free JSON string.

    Enforces:
    - Root keys strictly subset of REPORT_ROOT_KEYS.
    - Default mode findings keys strictly subset of REPORT_FINDING_KEYS.
    - Default mode findings strictly forbid 'text', 'content', 'message', 'payload'.
    - Unauthorized or extra keys trigger OperationalError (fail-closed).
    - When include_content=True, sets content_warning=True and included_content=True.
    - When include_content=False, neither content_warning nor included_content is present.
    """
    if isinstance(report, Report):
        sorted_findings = sorted(report.findings, key=finding_report_sort_key)
        findings_json = [
            format_finding_content_free(
                f,
                include_content=include_content,
                home=home,
                ordinal=idx + 1,
            )
            for idx, f in enumerate(sorted_findings)
        ]
        data: dict[str, Any] = {
            "assurance": report.assurance,
            "counts": report.counts.to_dict(),
            "coverage": report.coverage.to_dict(),
            "findings": findings_json,
            "limitation": report.limitation,
            "schema_version": report.schema_version,
            "session_id": report.session_id,
            "source_fingerprint": report.source_fingerprint,
            "tool_version": report.tool_version,
        }
        if repro is not None:
            if isinstance(repro, ReproMetadata):
                data["repro"] = repro.to_dict()
            else:
                data["repro"] = dict(repro)
        if include_content:
            data["content_warning"] = True
            data["included_content"] = True
    elif isinstance(report, Mapping):
        data = dict(report)
        if include_content:
            data["content_warning"] = True
            data["included_content"] = True
    else:
        raise TypeError(f"Expected Report or Mapping, got {type(report).__name__}")

    # Fail-closed allowlist validation: Root keys
    root_keys = set(data.keys())
    if not root_keys.issubset(REPORT_ROOT_KEYS):
        extra = sorted(root_keys - REPORT_ROOT_KEYS)
        raise OperationalError(
            f"Renderer root key allowlist violation: unauthorized fields {extra}"
        )

    # Fail-closed allowlist validation: Findings keys
    findings_list = data.get("findings")
    if isinstance(findings_list, list):
        for idx, f_item in enumerate(findings_list):
            if isinstance(f_item, Mapping):
                f_keys = set(f_item.keys())
                if not include_content:
                    forbidden = f_keys.intersection(REPORT_FORBIDDEN_FINDING_KEYS)
                    if forbidden:
                        msg = (
                            f"Renderer finding[{idx}] forbidden content key violation: "
                            f"{sorted(forbidden)}"
                        )
                        raise OperationalError(msg)
                    if not f_keys.issubset(REPORT_FINDING_KEYS):
                        extra_f = sorted(f_keys - REPORT_FINDING_KEYS)
                        msg = (
                            f"Renderer finding[{idx}] key allowlist violation: "
                            f"unauthorized fields {extra_f}"
                        )
                        raise OperationalError(msg)
                else:
                    allowed_leak = (
                        REPORT_FINDING_KEYS
                        | REPORT_FORBIDDEN_FINDING_KEYS
                        | frozenset(
                            {
                                "record_id",
                                "raw_content",
                                "related_ids",
                                "schema_version",
                                "source",
                            }
                        )
                    )
                    if not f_keys.issubset(allowed_leak):
                        extra_f = sorted(f_keys - allowed_leak)
                        msg = (
                            f"Renderer finding[{idx}] key allowlist violation: "
                            f"unauthorized fields {extra_f}"
                        )
                        raise OperationalError(msg)

    return json.dumps(data, indent=2, sort_keys=True)


def render_human(
    report: Report,
    *,
    color: bool = False,
    adapter: str = "canonical",
    profile: str = "neutral",
    next_action: str | None = None,
    home: Path | None = None,
) -> str:
    """Render Report to human-readable format with summary header and ordered finding blocks."""
    from sesslint.codes import CODE_REGISTRY

    green = "\033[32m" if color else ""
    red = "\033[31m" if color else ""
    yellow = "\033[33m" if color else ""
    bold = "\033[1m" if color else ""
    reset = "\033[0m" if color else ""

    has_error = (
        report.counts.by_severity.get("error", 0) > 0
        or report.counts.by_severity.get("fatal", 0) > 0
    )
    has_warning = report.counts.by_severity.get("warning", 0) > 0
    err_cnt = report.counts.by_severity.get("error", 0) + report.counts.by_severity.get("fatal", 0)
    warn_cnt = report.counts.by_severity.get("warning", 0)

    if has_error:
        verdict = "invalid"
        verdict_colored = f"{bold}{red}Integrity check failed{reset}"
        files_summary = "H=0 I=1 U=0 R=0 S=0"
    elif has_warning:
        verdict = "healthy with warnings"
        verdict_colored = f"{bold}{yellow}Session is healthy with warnings{reset}"
        files_summary = "H=1 I=0 U=0 R=0 S=0"
    else:
        verdict = "healthy"
        verdict_colored = f"{bold}{green}Session is healthy{reset}"
        files_summary = "H=1 I=0 U=0 R=0 S=0"

    if next_action is None:
        if has_error:
            if any(f.repairability.value == "deterministic" for f in report.findings):
                p = minimize_path(report.findings[0].source.path, home=home)
                next_action = f"Run 'sesslint repair {p} --output <out>'"
            elif any(f.repairability.value == "lossy-explicit" for f in report.findings):
                p = minimize_path(report.findings[0].source.path, home=home)
                next_action = f"Run 'sesslint repair {p} --output <out> --policy salvage'"
            else:
                next_action = "Manual inspection required; automated repair refused."
        elif has_warning:
            next_action = "Review warnings; session is structurally replayable."
        else:
            next_action = "No repair needed."

    summary_meta = (
        f"verdict: {verdict} / errors: {err_cnt} / warnings: {warn_cnt} / "
        f"files: {files_summary} / profile: {profile} / adapter: {adapter}"
    )
    lines: list[str] = [
        f"[read-only] {verdict_colored} ({summary_meta})",
        f"Next Action: {next_action}",
        f"Assurance: {report.assurance} - {report.limitation}",
        f"Limitation: {report.limitation}",
        f"Source fingerprint: {report.source_fingerprint}",
    ]

    # Coverage section (FR-047)
    cov = report.coverage
    perf_str = ", ".join(cov.performed) if cov.performed else "none"
    lines.append(f"Coverage: {len(cov.performed)} checks performed ({perf_str})")
    if cov.skipped:
        skip_items = [f"{s.check} ({s.reason})" for s in cov.skipped]
        lines.append(f"  Skipped ({len(cov.skipped)}): {', '.join(skip_items)}")

    if report.findings:
        sorted_findings = sorted(report.findings, key=finding_report_sort_key)
        lines.append("")
        lines.append("Findings:")
        for _idx, f in enumerate(sorted_findings):
            title = CODE_REGISTRY[f.code].name if f.code in CODE_REGISTRY else "Integrity finding"
            min_path = minimize_path(f.source.path, home=home)
            loc_str = f"{min_path}:{f.source.line}" if f.source.line is not None else min_path
            if (
                f.evidence
                and isinstance(f.evidence, Mapping)
                and "byte_offset" in f.evidence
                and "byte_end" in f.evidence
            ):
                b_start = f.evidence["byte_offset"]
                b_end = f.evidence["byte_end"]
                if (
                    isinstance(b_start, int)
                    and not isinstance(b_start, bool)
                    and b_start >= 0
                    and isinstance(b_end, int)
                    and not isinstance(b_end, bool)
                    and b_end >= b_start
                ):
                    loc_str = f"{loc_str} (bytes {b_start}-{b_end})"
            sev_color = red if f.severity.value in ("error", "fatal") else yellow
            why_str = f.message
            fix_str = get_finding_remediation(f, home=home)

            sev_rep = f"({f.severity.value.upper()}, {f.repairability.value})"
            lines.append(f"  [{f.code}] {sev_color}{title}{reset} {sev_rep}")
            lines.append(f"    Span:        {loc_str}")
            lines.append(f"    Why:         {why_str}")
            lines.append(f"    Fix:         {fix_str}")
            lines.append(f"    Fingerprint: {f.fingerprint}")

    return "\n".join(lines)


__all__ = [
    "ASSURANCE_DESCRIPTIONS",
    "ASSURANCE_LIMITATIONS",
    "KNOWN_MANIFEST_FIELDS",
    "KNOWN_REPORT_FIELDS",
    "MANIFEST_SCHEMA_VERSION",
    "REPORT_DEFAULT_FINDING_KEYS",
    "REPORT_FINDING_KEYS",
    "REPORT_FORBIDDEN_FINDING_KEYS",
    "REPORT_ROOT_KEYS",
    "REPORT_SCHEMA_VERSION",
    "REQUIRED_MANIFEST_FIELDS",
    "REQUIRED_REPORT_FIELDS",
    "REQUIRED_SEVERITIES",
    "VALID_ASSURANCE_LEVELS",
    "VALID_COVERAGE_SKIP_REASONS",
    "VALID_POLICIES",
    "Assurance",
    "Counts",
    "Coverage",
    "CoverageSkip",
    "Policy",
    "RepairAction",
    "RepairManifest",
    "Report",
    "ReproMetadata",
    "RevalidationSummary",
    "apply_plan_assurance",
    "build_manifest",
    "build_report",
    "build_repro_metadata",
    "cap_assurance",
    "compute_assurance",
    "compute_manifest_idempotency_key",
    "dump_manifest",
    "dump_report",
    "enforce_content_free",
    "finding_report_sort_key",
    "format_finding_content_free",
    "get_finding_remediation",
    "get_manifest_schema_path",
    "get_report_schema_path",
    "load_manifest_schema",
    "load_report_schema",
    "minimize_id",
    "minimize_path",
    "parse_manifest",
    "parse_report",
    "render_human",
    "render_json",
    "short_hash",
]
