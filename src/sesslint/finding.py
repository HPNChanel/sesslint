"""Finding envelope, severity/repairability taxonomies, fingerprinting, and deterministic ordering.

This module provides the frozen Finding and SourceRef models, the make_finding constructor,
total order sorting, and sha256 fingerprinting contracts.
Generic detectors, repair planning, and reports operate on these types.
"""

from __future__ import annotations

import hashlib
import json
import re
import string
import sys
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal, cast

from sesslint.codes import (
    ALL_CODES,
    CODE_REGISTRY,
    Code,
    CodeInfo,
    Repairability,
    Severity,
    get_code_info,
    is_valid_code,
)
from sesslint.context import CheckContext
from sesslint.errors import FindingError

SchemaVersionLiteral = Literal["sesslint.finding/v1"]
SCHEMA_VERSION: Final[SchemaVersionLiteral] = "sesslint.finding/v1"

ALLOWED_TEMPLATE_VARS: Final[frozenset[str]] = frozenset({"record_id", "line"})
MAX_MESSAGE_LENGTH: Final[int] = 500
TRUNCATION_MARKER: Final[str] = "... [truncated]"

SEVERITY_ORDER: Final[dict[Severity, int]] = {
    Severity.FATAL: 0,
    Severity.ERROR: 1,
    Severity.WARNING: 2,
    Severity.INFO: 3,
}

_FINGERPRINT_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{16}$")
_EMAIL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
_PRIVATE_KEY_PATTERN: Final[re.Pattern[str]] = re.compile(r"-----BEGIN [A-Z ]+KEY-----")
_BEARER_PATTERN: Final[re.Pattern[str]] = re.compile(r"\bBearer\s+[A-Za-z0-9_\-\.]{10,}\b")
_API_KEY_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b(?:sk|ghp|gho|glpat|slack_token)[_\-][A-Za-z0-9_\-]{16,}\b"
)
_CREDENTIAL_ASSIGN_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b(?:password|passwd|api_key|secret|token)\s*[:=]\s*\S+"
)
_CONTROL_CHAR_PATTERN: Final[re.Pattern[str]] = re.compile(r"[\r\n\t\x00-\x1f\x7f]")
_DANGEROUS_UNICODE_CATEGORIES: Final[frozenset[str]] = frozenset({"Cc", "Cf", "Zl", "Zp"})


def enforce_content_free_text(text: str, *, context: str = "text") -> None:
    """Validate that text does not contain control characters, line breaks, or credentials/PII.

    Enforces SessLint's content-free guarantee (FR-081) by rejecting:
    - Control characters and newlines (both ASCII and Unicode Cc, Cf, Zl, Zp categories)
    - PII patterns (email addresses)
    - Sensitive credentials (private keys, bearer tokens, API keys, password assignments)

    Raises:
        FindingError: If control characters, formatting overrides, or sensitive patterns are found.
    """
    if _CONTROL_CHAR_PATTERN.search(text):
        raise FindingError(f"Forbidden control or newline characters in {context}: {text!r}")
    if not text.isascii():
        for ch in text:
            cat = unicodedata.category(ch)
            if cat in _DANGEROUS_UNICODE_CATEGORIES:
                code_pt = f"U+{ord(ch):04X}"
                raise FindingError(
                    f"Forbidden Unicode control/formatting character {code_pt} "
                    f"in {context}: {text!r}"
                )
    if _EMAIL_PATTERN.search(text):
        raise FindingError(
            f"Forbidden content-bearing pattern (e.g., email/PII) in {context}: {text!r}"
        )
    if _PRIVATE_KEY_PATTERN.search(text):
        raise FindingError(f"Forbidden credential pattern (private key) in {context}: {text!r}")
    if _BEARER_PATTERN.search(text):
        raise FindingError(f"Forbidden credential pattern (bearer token) in {context}: {text!r}")
    if _API_KEY_PATTERN.search(text):
        raise FindingError(f"Forbidden credential pattern (API key) in {context}: {text!r}")
    if _CREDENTIAL_ASSIGN_PATTERN.search(text):
        raise FindingError(
            f"Forbidden credential pattern (credential assignment) in {context}: {text!r}"
        )


@dataclass(frozen=True, slots=True)
class SourceRef:
    """Source coordinates for a finding.

    Paths are normalized to use forward slashes ('/') and stripped to guarantee
    cross-platform deterministic hashing and ordering between Windows, Linux, and macOS
    (AC-019, AC-029).
    """

    path: str
    line: int | None = None
    record_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.path, str) or not self.path.strip():
            raise FindingError(f"SourceRef.path must be a non-empty string, got {self.path!r}")
        normalized_path = self.path.strip().replace("\\", "/")
        enforce_content_free_text(normalized_path, context="SourceRef.path")
        if normalized_path != self.path:
            object.__setattr__(self, "path", normalized_path)

        if self.line is not None:
            if not isinstance(self.line, int) or isinstance(self.line, bool) or self.line < 1:
                raise FindingError(
                    f"SourceRef.line must be a positive integer or None, got {self.line!r}"
                )

        if self.record_id is not None:
            if not isinstance(self.record_id, str) or not self.record_id.strip():
                raise FindingError(
                    f"SourceRef.record_id must be non-empty string or None, got {self.record_id!r}"
                )
            normalized_rec_id = self.record_id.strip()
            enforce_content_free_text(normalized_rec_id, context="SourceRef.record_id")
            if normalized_rec_id != self.record_id:
                object.__setattr__(self, "record_id", normalized_rec_id)


@dataclass(frozen=True, slots=True)
class Finding:
    """Immutable finding envelope capturing an integrity defect.

    Total ordering hierarchy (FR-094):
    1. path (lexicographical, forward-slash normalized)
    2. line (None sorts as -1 before line 0, then ascending integer)
    3. ordinal (stream record ordinal from evidence['record_ordinal'], None/-1 sorts before 0)
    4. severity_rank (fatal < error < warning < info)
    5. code (lexicographical)
    6. record_id (None sorts as empty string before any non-empty string, then lexicographical)
    7. fingerprint (16-character sha256 hex string)
    """

    code: str
    severity: Severity
    repairability: Repairability
    message: str
    source: SourceRef
    related_ids: tuple[str, ...]
    fingerprint: str
    schema_version: Literal["sesslint.finding/v1"] = "sesslint.finding/v1"
    message_template: str | None = None
    evidence: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.code, str) or not is_valid_code(self.code):
            valid_sorted = sorted(ALL_CODES)
            raise FindingError(
                f"Finding.code must be a registered detector code, got {self.code!r}. "
                f"Must be one of {valid_sorted}"
            )
        if not isinstance(self.severity, Severity):
            raise FindingError(f"Finding.severity must be a Severity enum, got {self.severity!r}")
        if not isinstance(self.repairability, Repairability):
            raise FindingError(
                f"Finding.repairability must be a Repairability enum, got {self.repairability!r}"
            )
        if not isinstance(self.message, str) or not self.message.strip():
            raise FindingError(
                f"Finding.message must be a non-empty string, got {type(self.message).__name__}"
            )
        if len(self.message) > MAX_MESSAGE_LENGTH:
            raise FindingError(
                f"Finding.message exceeds maximum length of {MAX_MESSAGE_LENGTH} characters "
                f"(length: {len(self.message)})"
            )
        enforce_content_free_text(self.message, context="Finding.message")

        if not isinstance(self.source, SourceRef):
            t_name = type(self.source).__name__
            raise FindingError(f"Finding.source must be a SourceRef, got {t_name}")

        if not isinstance(self.fingerprint, str) or not _FINGERPRINT_PATTERN.match(
            self.fingerprint
        ):
            raise FindingError(
                f"Finding.fingerprint must be a 16-character lowercase hex string matching "
                f"^[0-9a-f]{{16}}$, got {self.fingerprint!r}"
            )

        if self.schema_version != "sesslint.finding/v1":
            raise FindingError(
                f"Finding.schema_version must be 'sesslint.finding/v1', got {self.schema_version!r}"
            )

        if self.message_template is not None:
            if not isinstance(self.message_template, str) or not self.message_template.strip():
                t_name = type(self.message_template).__name__
                raise FindingError(
                    f"Finding.message_template must be a non-empty string or None, got {t_name}"
                )
            enforce_content_free_text(self.message_template, context="Finding.message_template")

        # Normalize related_ids to sorted unique tuple of strings
        if isinstance(self.related_ids, Iterable) and not isinstance(
            self.related_ids, (str, bytes)
        ):
            unique_raw = set(self.related_ids)
            cleaned: list[str] = []
            for x in unique_raw:
                if not isinstance(x, str) or not x.strip():
                    raise FindingError(
                        f"Finding.related_ids items must be non-empty strings, got {x!r}"
                    )
                x_str = x.strip()
                enforce_content_free_text(x_str, context="Finding.related_ids")
                cleaned.append(x_str)
            norm = tuple(sorted(cleaned))
            if norm != self.related_ids:
                object.__setattr__(self, "related_ids", norm)
        else:
            t_name = type(self.related_ids).__name__
            raise FindingError(f"Finding.related_ids must be an iterable of strings, got {t_name}")

        if self.evidence is not None:
            if not isinstance(self.evidence, Mapping):
                t_name = type(self.evidence).__name__
                raise FindingError(f"Finding.evidence must be a mapping or None, got {t_name}")
            for k, v in self.evidence.items():
                if not isinstance(k, str) or not k.strip():
                    raise FindingError("Finding.evidence keys must be non-empty strings")
                enforce_content_free_text(str(k), context=f"Finding.evidence key {k!r}")
                if isinstance(v, str):
                    enforce_content_free_text(v, context=f"Finding.evidence value for {k!r}")

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, Finding):
            return NotImplemented
        return _finding_sort_key(self) < _finding_sort_key(other)

    def __le__(self, other: Any) -> bool:
        if not isinstance(other, Finding):
            return NotImplemented
        return _finding_sort_key(self) <= _finding_sort_key(other)

    def __gt__(self, other: Any) -> bool:
        if not isinstance(other, Finding):
            return NotImplemented
        return _finding_sort_key(self) > _finding_sort_key(other)

    def __ge__(self, other: Any) -> bool:
        if not isinstance(other, Finding):
            return NotImplemented
        return _finding_sort_key(self) >= _finding_sort_key(other)

    @property
    def variant(self) -> str | None:
        """Convenience property accessing evidence['variant'] if present."""
        if self.evidence is not None and "variant" in self.evidence:
            return cast(str, self.evidence["variant"])
        return None

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to canonical dictionary representation matching schema."""
        d: dict[str, Any] = {
            "schema_version": self.schema_version,
            "code": self.code,
            "severity": self.severity.value,
            "repairability": self.repairability.value,
            "message": self.message,
            "source": {
                "path": self.source.path,
                "line": self.source.line,
                "record_id": self.source.record_id,
            },
            "related_ids": list(self.related_ids),
            "fingerprint": self.fingerprint,
        }
        if self.message_template is not None:
            d["message_template"] = self.message_template
        if self.evidence is not None:
            d["evidence"] = dict(self.evidence)
        return d


def _finding_sort_key(
    f: Finding,
) -> tuple[str, int, int, int, str, str, str, tuple[str, ...], str, str]:
    """Pure sort key ensuring deterministic total ordering of findings (FR-094).

    Total ordering hierarchy:
    1. path (lexicographical, forward-slash normalized)
    2. line (None sorts as -1 before line 0, then ascending integer)
    3. ordinal (stream record ordinal from evidence['record_ordinal'], None/-1 sorts before 0)
    4. severity_rank (fatal < error < warning < info)
    5. code (lexicographical)
    6. record_id (None sorts as empty string before any non-empty string, then lexicographical)
    7. fingerprint (16-character sha256 hex string)
    Followed by related_ids, message, repairability for strict trichotomy/totality.
    """
    norm_path = f.source.path.replace("\\", "/")
    line_val = -1 if f.source.line is None else f.source.line
    ordinal_val = -1
    if f.evidence is not None:
        raw_ordinal = f.evidence.get("record_ordinal")
        if isinstance(raw_ordinal, int) and not isinstance(raw_ordinal, bool) and raw_ordinal >= 0:
            ordinal_val = raw_ordinal
    sev_rank = SEVERITY_ORDER[f.severity]
    rec_val = "" if f.source.record_id is None else str(f.source.record_id)
    return (
        norm_path,
        line_val,
        ordinal_val,
        sev_rank,
        f.code,
        rec_val,
        f.fingerprint,
        f.related_ids,
        f.message,
        f.repairability.value,
    )


finding_sort_key = _finding_sort_key


def sort_findings(fs: Iterable[Finding]) -> list[Finding]:
    """Return a new list of findings sorted in deterministic total order (FR-094).

    Total ordering hierarchy:
    1. path (lexicographical, forward-slash normalized)
    2. line (None sorts as -1 before line 0, then ascending integer)
    3. ordinal (stream record ordinal from evidence['record_ordinal'], None/-1 sorts before 0)
    4. severity_rank (fatal < error < warning < info)
    5. code (lexicographical)
    6. record_id (None sorts as empty string before any non-empty string, then lexicographical)
    7. fingerprint (16-character sha256 hex string)
    """
    return sorted(fs, key=_finding_sort_key)


CANONICAL_EVIDENCE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "actual_seq",
        "at_index",
        "boundary_index",
        "byte_end",
        "byte_offset",
        "call_agent_id",
        "call_branch_id",
        "call_ids",
        "call_indexes",
        "call_interaction_id",
        "candidate_count",
        "caused_by",
        "classification",
        "coerced",
        "component_index",
        "component_members",
        "component_size",
        "confinement",
        "correlation_id",
        "count",
        "cycle_events",
        "cycle_length",
        "cycle_nodes",
        "cycle_parent_edges",
        "detail",
        "differing_fields",
        "event_id",
        "event_ids",
        "expected_seq",
        "field",
        "first_unsafe_index",
        "format",
        "head_count",
        "head_ids",
        "id",
        "index",
        "intervening_count",
        "intervening_kinds",
        "match_rule",
        "overflow",
        "parent_id",
        "profile",
        "reason",
        "record_ordinal",
        "rejected_decoys",
        "result_agent_id",
        "result_branch_id",
        "result_id",
        "result_ids",
        "result_indexes",
        "result_interaction_id",
        "schema",
        "scope_mismatch",
        "seq",
        "state_hash_a",
        "state_hash_b",
        "truncated",
        "use_id",
        "use_index",
        "variant",
    }
)


def _canonical_evidence_for_fingerprint(
    evidence: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Extract and normalize a content-free subset of evidence for fingerprinting (FR-046, FR-081).

    Only allowlisted structural/coordinate keys are included in the preimage to guarantee
    content-free hashing. Keys are sorted lexicographically.
    """
    if not evidence:
        return {}
    subset: dict[str, Any] = {}
    for k in sorted(evidence):
        if k in CANONICAL_EVIDENCE_KEYS:
            subset[k] = evidence[k]
    return subset


def compute_finding_fingerprint(
    *,
    code: str,
    source: SourceRef,
    adapter_id: str | None = None,
    adapter_version: str | None = None,
    profile_id: str | None = None,
    profile_version: str | None = None,
    ordinal: int | None = None,
    evidence: Mapping[str, Any] | None = None,
    # Optional parameters accepted for backward compatibility with older tests/call sites:
    severity: Severity | str | None = None,
    repairability: Repairability | str | None = None,
    message_template: str | None = None,
    related_ids: Iterable[str] = (),
    context: CheckContext | None = None,
) -> str:
    """Compute deterministic 16-character sha256 fingerprint for a finding (FR-046).

    Preimage array contract (FR-046, DEV-004):
    [
        code,
        adapter_id,
        adapter_version,
        profile_id,
        profile_version,
        path,
        line,
        ordinal,
        record_id,
        canonical_evidence_subset,
    ]
    Hashed with unified canonical_json_bytes(preimage, newline=False), 16-hex digest.
    Unavailable or omitted versions MUST be explicit "unknown" (never empty string).
    """
    ad_id: str
    ad_ver: str
    prof_id: str
    prof_ver: str

    if context is not None:
        ad_id = adapter_id.strip() if adapter_id and adapter_id.strip() else context.adapter_id
        ad_ver = (
            adapter_version.strip()
            if adapter_version and adapter_version.strip()
            else context.adapter_version
        )
        prof_id = profile_id.strip() if profile_id and profile_id.strip() else context.profile_id
        prof_ver = (
            profile_version.strip()
            if profile_version and profile_version.strip()
            else context.profile_version
        )
    else:
        ad_id = adapter_id.strip() if adapter_id and adapter_id.strip() else "unknown"
        ad_ver = (
            adapter_version.strip() if adapter_version and adapter_version.strip() else "unknown"
        )
        prof_id = profile_id.strip() if profile_id and profile_id.strip() else "unknown"
        prof_ver = (
            profile_version.strip() if profile_version and profile_version.strip() else "unknown"
        )

    norm_path = source.path.replace("\\", "/")

    ord_val = ordinal
    if ord_val is None and evidence is not None:
        raw_ord = evidence.get("record_ordinal")
        if isinstance(raw_ord, int) and not isinstance(raw_ord, bool) and raw_ord >= 0:
            ord_val = raw_ord

    ev_subset = _canonical_evidence_for_fingerprint(evidence)

    preimage: list[Any] = [
        code,
        ad_id,
        ad_ver,
        prof_id,
        prof_ver,
        norm_path,
        source.line,
        ord_val,
        source.record_id,
        ev_subset,
    ]

    from sesslint.determinism import canonical_json_bytes

    encoded = canonical_json_bytes(preimage, newline=False)
    return hashlib.sha256(encoded).hexdigest()[:16]


compute_fingerprint = compute_finding_fingerprint


def fingerprint_finding(
    f: Finding,
    *,
    without_fingerprint: bool = True,
    adapter_id: str | None = None,
    adapter_version: str | None = None,
    profile_id: str | None = None,
    profile_version: str | None = None,
    context: CheckContext | None = None,
) -> str:
    """Return or recompute the 16-character deterministic sha256 fingerprint for a finding.

    When without_fingerprint=True, recomputes from coordinates, versions, and allowlisted evidence.
    When without_fingerprint=False, returns the finding's stored fingerprint.
    """
    if not without_fingerprint:
        return f.fingerprint
    return compute_finding_fingerprint(
        code=f.code,
        source=f.source,
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        profile_id=profile_id,
        profile_version=profile_version,
        evidence=f.evidence,
        severity=f.severity,
        repairability=f.repairability,
        message_template=f.message_template if f.message_template is not None else f.message,
        related_ids=f.related_ids,
        context=context,
    )


def make_finding(
    *,
    code: str,
    severity: Severity | str | None = None,
    repairability: Repairability | str | None = None,
    message_template: str,
    template_args: Mapping[str, Any] | None = None,
    source: SourceRef,
    related_ids: Iterable[str] = (),
    evidence: Mapping[str, Any] | None = None,
    fingerprint: str | None = None,
    adapter_id: str | None = None,
    adapter_version: str | None = None,
    profile_id: str | None = None,
    profile_version: str | None = None,
    ordinal: int | None = None,
    context: CheckContext | None = None,
) -> Finding:
    """Construct, validate, and fingerprint a Finding instance.

    Validates:
    - code is present in 20-code registry.
    - severity and repairability resolve strictly to known enum variants.
    - message_template is non-empty with allow-listed placeholders: {record_id}, {line}.
    - template_args contain only allow-listed keys and pass content-free validation.
    - source is a valid SourceRef.
    - related_ids are sorted, deduplicated, and content-free.
    - fingerprint covers code, severity, repairability, template, and coordinates.
    - rendered message is capped at 500 characters and content-free.
    """
    if not isinstance(code, str) or not is_valid_code(code):
        valid_sorted = sorted(ALL_CODES)
        raise FindingError(f"Unknown finding code: {code!r}. Must be one of {valid_sorted}")

    code_info = get_code_info(code)
    sev = Severity.from_str(severity) if severity is not None else code_info.default_severity
    rep = (
        Repairability.from_str(repairability)
        if repairability is not None
        else code_info.default_repairability
    )

    if not isinstance(source, SourceRef):
        raise FindingError(f"source must be a SourceRef instance, got {type(source).__name__}")

    if not isinstance(message_template, str) or not message_template.strip():
        raise FindingError("message_template must be a non-empty string")

    enforce_content_free_text(message_template, context="message_template")

    # Validate template placeholders and format specifiers
    formatter = string.Formatter()
    try:
        parsed_fields = list(formatter.parse(message_template))
    except ValueError as err:
        raise FindingError(f"Malformed message template {message_template!r}: {err}") from err

    for _, field_name, format_spec, conversion in parsed_fields:
        if field_name is not None:
            if field_name not in ALLOWED_TEMPLATE_VARS:
                allowed_sorted = sorted(ALLOWED_TEMPLATE_VARS)
                raise FindingError(
                    f"Disallowed placeholder '{field_name}' in message template. "
                    f"Only {allowed_sorted} are allowed to prevent payload leaking."
                )
            if format_spec or conversion is not None:
                raise FindingError(
                    f"Format specifiers and conversions are disallowed in template placeholder "
                    f"'{field_name}' to prevent format-string manipulation."
                )

    args_dict: dict[str, str] = {}
    if template_args is not None:
        if not isinstance(template_args, Mapping):
            t_name = type(template_args).__name__
            raise FindingError(f"template_args must be a mapping, got {t_name}")
        for k, v in template_args.items():
            if k not in ALLOWED_TEMPLATE_VARS:
                allowed_sorted = sorted(ALLOWED_TEMPLATE_VARS)
                raise FindingError(
                    f"Disallowed template argument '{k}'. Only {allowed_sorted} are allowed."
                )
            if k == "line":
                if isinstance(v, bool) or not (
                    (isinstance(v, int) and v >= 1)
                    or (isinstance(v, str) and (v.isdigit() and int(v) >= 1 or v == "<unknown>"))
                ):
                    raise FindingError(
                        f"template_args['line'] must be positive int or digits, got {v!r}"
                    )
            elif k == "record_id":
                if not isinstance(v, str) or not v.strip():
                    raise FindingError(
                        f"template_args['record_id'] must be non-empty string, got {v!r}"
                    )
            val_str = str(v).strip()
            enforce_content_free_text(val_str, context=f"template_arg[{k}]")
            args_dict[k] = val_str

    # Build render arguments
    render_args: dict[str, str] = {}
    if "line" in args_dict:
        render_args["line"] = args_dict["line"]
    elif source.line is not None:
        render_args["line"] = str(source.line)
    else:
        render_args["line"] = "<unknown>"

    if "record_id" in args_dict:
        render_args["record_id"] = args_dict["record_id"]
    elif source.record_id is not None:
        render_args["record_id"] = source.record_id
    else:
        render_args["record_id"] = "<none>"

    rendered_message = message_template.format(**render_args)
    if len(rendered_message) > MAX_MESSAGE_LENGTH:
        cut = MAX_MESSAGE_LENGTH - len(TRUNCATION_MARKER)
        rendered_message = rendered_message[:cut] + TRUNCATION_MARKER

    enforce_content_free_text(rendered_message, context="rendered_message")

    if not isinstance(related_ids, Iterable) or isinstance(related_ids, (str, bytes)):
        raise FindingError("related_ids must be an iterable of string identifiers")
    unique_raw_items = set(related_ids)
    cleaned_related: list[str] = []
    for item in unique_raw_items:
        if not isinstance(item, str) or not item.strip():
            raise FindingError(f"related_ids items must be non-empty strings, got {item!r}")
        item_str = item.strip()
        enforce_content_free_text(item_str, context="related_ids")
        cleaned_related.append(item_str)
    norm_related_ids = tuple(sorted(cleaned_related))

    if fingerprint is not None:
        if not isinstance(fingerprint, str) or not _FINGERPRINT_PATTERN.match(fingerprint):
            raise FindingError(
                f"Finding.fingerprint must be a 16-character lowercase hex string matching "
                f"^[0-9a-f]{{16}}$, got {fingerprint!r}"
            )
        fp = fingerprint
    else:
        fp = compute_finding_fingerprint(
            code=code,
            source=source,
            adapter_id=adapter_id,
            adapter_version=adapter_version,
            profile_id=profile_id,
            profile_version=profile_version,
            ordinal=ordinal,
            evidence=evidence,
            severity=sev,
            repairability=rep,
            message_template=message_template,
            related_ids=norm_related_ids,
            context=context,
        )

    return Finding(
        code=code,
        severity=sev,
        repairability=rep,
        message=rendered_message,
        source=source,
        related_ids=norm_related_ids,
        fingerprint=fp,
        schema_version="sesslint.finding/v1",
        message_template=message_template,
        evidence=evidence,
    )


def parse_finding_dict(obj: Mapping[str, Any]) -> Finding:
    """Parse and validate a finding mapping against the canonical finding model."""
    if not isinstance(obj, Mapping):
        raise FindingError(f"Finding object must be a mapping, got {type(obj).__name__}")

    version = obj.get("schema_version")
    if version != "sesslint.finding/v1":
        raise FindingError(
            f"Unsupported finding schema_version {version!r}, expected 'sesslint.finding/v1'"
        )

    code = obj.get("code")
    if not isinstance(code, str) or not is_valid_code(code):
        raise FindingError(f"Invalid finding code in dictionary: {code!r}")

    sev_raw = obj.get("severity")
    if not isinstance(sev_raw, str):
        raise FindingError(f"Missing or non-string severity in finding dictionary: {sev_raw!r}")
    severity = Severity.from_str(sev_raw)

    rep_raw = obj.get("repairability")
    if not isinstance(rep_raw, str):
        raise FindingError(
            f"Missing or non-string repairability in finding dictionary: {rep_raw!r}"
        )
    repairability = Repairability.from_str(rep_raw)

    message: Any
    if "message" in obj:
        message = obj["message"]
    elif "remediation" in obj and isinstance(obj["remediation"], str):
        message = obj["remediation"]
    else:
        raise FindingError("Missing required field 'message' in finding dictionary")

    if not isinstance(message, str) or not message.strip():
        raise FindingError(f"Missing or non-string message in finding dictionary: {message!r}")
    if len(message) > MAX_MESSAGE_LENGTH:
        raise FindingError(
            f"Finding message in dictionary exceeds {MAX_MESSAGE_LENGTH} characters: {len(message)}"
        )

    raw_source = obj.get("source")
    if raw_source is None and "span" in obj:
        raw_source = obj["span"]
    if not isinstance(raw_source, Mapping):
        raise FindingError(f"Missing or invalid source in finding dictionary: {raw_source!r}")
    path = raw_source.get("path")
    if not isinstance(path, str) or not path.strip():
        raise FindingError(f"Missing or non-string source.path: {path!r}")
    line = raw_source.get("line")
    record_id = raw_source.get("record_id")
    source = SourceRef(path=path, line=line, record_id=record_id)

    raw_related = obj.get("related_ids", ())
    if not isinstance(raw_related, (list, tuple)):
        raise FindingError(f"related_ids must be a list or tuple, got {type(raw_related).__name__}")
    for item in raw_related:
        if not isinstance(item, str) or not item.strip():
            raise FindingError(f"related_ids elements must be non-empty strings, got {item!r}")
    related_ids = tuple(item.strip() for item in raw_related)

    fingerprint = obj.get("fingerprint")
    if not isinstance(fingerprint, str) or not _FINGERPRINT_PATTERN.match(fingerprint):
        raise FindingError(f"Missing or invalid fingerprint in finding dictionary: {fingerprint!r}")

    msg_template = obj.get("message_template")
    if msg_template is not None and (not isinstance(msg_template, str) or not msg_template.strip()):
        t_name = type(msg_template).__name__
        raise FindingError(f"message_template must be a non-empty string or None, got {t_name}")

    raw_evidence = obj.get("evidence")
    if raw_evidence is not None and not isinstance(raw_evidence, Mapping):
        raise FindingError(
            f"Finding.evidence must be a mapping or None, got {type(raw_evidence).__name__}"
        )
    evidence = dict(raw_evidence) if raw_evidence is not None else None

    return Finding(
        code=code,
        severity=severity,
        repairability=repairability,
        message=message,
        source=source,
        related_ids=related_ids,
        fingerprint=fingerprint,
        schema_version="sesslint.finding/v1",
        message_template=msg_template,
        evidence=evidence,
    )


def get_finding_schema_path() -> Path:
    """Return the filesystem path to schemas/sesslint.finding.v1.json."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    dev_path = repo_root / "schemas" / "sesslint.finding.v1.json"
    if dev_path.is_file():
        return dev_path
    prefix_path = Path(sys.prefix) / "share" / "sesslint" / "schemas" / "sesslint.finding.v1.json"
    if prefix_path.is_file():
        return prefix_path
    return dev_path


def load_finding_schema() -> dict[str, Any]:
    """Load the committed JSON Schema for sesslint.finding/v1 as a dict."""
    schema_path = get_finding_schema_path()
    if not schema_path.is_file():
        raise FileNotFoundError(f"Canonical finding schema not found at {schema_path}")
    return cast(dict[str, Any], json.loads(schema_path.read_text(encoding="utf-8")))


__all__ = [
    "ALL_CODES",
    "CODE_REGISTRY",
    "MAX_MESSAGE_LENGTH",
    "SCHEMA_VERSION",
    "SEVERITY_ORDER",
    "TRUNCATION_MARKER",
    "CANONICAL_EVIDENCE_KEYS",
    "Code",
    "CodeInfo",
    "Finding",
    "Repairability",
    "Severity",
    "SourceRef",
    "_canonical_evidence_for_fingerprint",
    "compute_finding_fingerprint",
    "compute_fingerprint",
    "enforce_content_free_text",
    "finding_sort_key",
    "fingerprint_finding",
    "get_code_info",
    "get_finding_schema_path",
    "is_valid_code",
    "load_finding_schema",
    "make_finding",
    "parse_finding_dict",
    "sort_findings",
]
