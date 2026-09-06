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
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal, cast

from sesslint.canonical import to_canonical_json
from sesslint.errors import (
    AssuranceError,
    ContentLeakError,
    FindingError,
    SchemaError,
    UnknownFieldError,
    VersionError,
)
from sesslint.finding import (
    Finding,
    enforce_content_free_text,
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
    }
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
    }
)

KNOWN_MANIFEST_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "input_fingerprint",
        "output_fingerprint",
        "policy",
        "actions",
        "declared_loss",
        "revalidate_report",
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
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "source_fingerprint": self.source_fingerprint,
            "tool_version": self.tool_version,
            "findings": [f.to_dict() for f in self.findings],
            "counts": self.counts.to_dict(),
            "assurance": self.assurance,
            "limitation": self.limitation,
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
class RepairManifest:
    """Immutable repair audit manifest (sesslint.repair-manifest/v1).

    Binds input/output fingerprints, repair policy, atomic actions, loss accounting,
    revalidation report reference, and cryptographic idempotency key.

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

    def to_dict(self) -> dict[str, Any]:
        """Convert RepairManifest to dictionary matching schema."""
        return {
            "schema_version": self.schema_version,
            "input_fingerprint": self.input_fingerprint,
            "output_fingerprint": self.output_fingerprint,
            "policy": self.policy,
            "actions": [a.to_dict() for a in self.actions],
            "declared_loss": list(self.declared_loss),
            "revalidate_report": self.revalidate_report,
            "idempotency_key": self.idempotency_key,
        }


def build_report(
    *,
    session_id: str,
    source_fingerprint: str,
    tool_version: str,
    findings: Iterable[Finding],
    assurance: Assurance,
    limitation: str,
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
) -> RepairManifest:
    """Construct an immutable RepairManifest, sorting actions and computing the idempotency key.

    Enforces:
    - Actions are sorted deterministically before storage and key computation.
    - Idempotency key is computed from canonical serialization of input_fingerprint,
      policy, and sorted actions.
    - Declared loss items are validated as non-empty strings.
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

    return Report(
        schema_version=REPORT_SCHEMA_VERSION,
        session_id=session_id.strip(),
        source_fingerprint=source_fingerprint.strip(),
        tool_version=tool_version.strip(),
        findings=parsed_findings,
        counts=counts,
        assurance=cast(Assurance, assurance),
        limitation=limitation.strip(),
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

    return RepairManifest(
        schema_version=MANIFEST_SCHEMA_VERSION,
        input_fingerprint=input_fingerprint.strip(),
        output_fingerprint=output_fingerprint.strip(),
        policy=cast(Policy, policy),
        actions=sorted_actions,
        declared_loss=loss_tuple,
        revalidate_report=reval_str,
        idempotency_key=idempotency_key,
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


__all__ = [
    "ASSURANCE_LIMITATIONS",
    "KNOWN_MANIFEST_FIELDS",
    "KNOWN_REPORT_FIELDS",
    "MANIFEST_SCHEMA_VERSION",
    "REPORT_SCHEMA_VERSION",
    "REQUIRED_MANIFEST_FIELDS",
    "REQUIRED_REPORT_FIELDS",
    "REQUIRED_SEVERITIES",
    "VALID_ASSURANCE_LEVELS",
    "VALID_POLICIES",
    "Assurance",
    "Counts",
    "Policy",
    "RepairAction",
    "RepairManifest",
    "Report",
    "apply_plan_assurance",
    "build_manifest",
    "build_report",
    "cap_assurance",
    "compute_manifest_idempotency_key",
    "dump_manifest",
    "dump_report",
    "enforce_content_free",
    "get_manifest_schema_path",
    "get_report_schema_path",
    "load_manifest_schema",
    "load_report_schema",
    "parse_manifest",
    "parse_report",
]
