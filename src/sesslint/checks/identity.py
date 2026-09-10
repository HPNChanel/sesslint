"""Vendor-neutral detector for SL003 duplicate and conflicting event IDs.

This module implements deterministic identity checks over canonical session events:
- Groups events by event identifier (ignoring null or missing IDs).
- Identical duplicates (all members byte-equal on canonical serialization)
  are flagged with SL003 identical-duplicate (warning, deterministic).
- Conflicting duplicates (any member differs in canonical attributes)
  are flagged with SL003 conflicting-duplicate (error, manual).
- Differing fields are reported by name only to prevent content leaks.
- Enforces MAX_IDENTITY_FINDINGS cap with deterministic overflow summary.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any, Final

from sesslint.canonical import (
    PROVENANCE_FIELDS,
    SessionEvent,
    canonical_bytes,
    to_canonical_dict,
    to_canonical_json,
)
from sesslint.codes import SL003, Repairability, Severity
from sesslint.context import CheckContext
from sesslint.finding import (
    Finding,
    SourceRef,
    enforce_content_free_text,
    make_finding,
)

MAX_IDENTITY_FINDINGS: Final[int] = 1000
MAX_RECORD_INDEXES_IN_EVIDENCE: Final[int] = 32

_MISSING: Final[object] = object()

_MSG_IDENTICAL: Final[str] = (
    "Duplicate event ID detected with identical content for record {record_id}"
)
_MSG_CONFLICTING: Final[str] = (
    "Duplicate event ID detected with conflicting content for record {record_id}"
)
_MSG_OVERFLOW: Final[str] = "Identity check finding cap reached; remaining duplicate IDs truncated"


def compute_identity_fingerprint(id_: str, payload_hashes: Sequence[str]) -> str:
    """Compute deterministic 16-character sha256 fingerprint for SL003 finding.

    Formula: sha256("SL003|" + id + "|" + ",".join(sorted(payload_hashes)))[:16]
    """
    sorted_hashes = sorted(payload_hashes)
    content = f"SL003|{id_}|{','.join(sorted_hashes)}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def diff_field_names(events: Sequence[SessionEvent]) -> list[str]:
    """Compare canonical event dicts field-by-field, returning names of fields that differ.

    Returns field names only (never values or hashes) to strictly uphold SessLint's
    content-free guarantee (FR-081).
    """
    if len(events) < 2:
        return []

    dicts: list[dict[str, Any]] = [
        e.to_canonical_dict()
        if hasattr(e, "to_canonical_dict") and callable(e.to_canonical_dict)
        else to_canonical_dict(e)
        for e in events
    ]
    all_keys = set().union(*(d.keys() for d in dicts)) - PROVENANCE_FIELDS

    differing: set[str] = set()
    first_dict = dicts[0]
    for key in all_keys:
        first_present = key in first_dict
        first_val = first_dict.get(key, _MISSING)
        for other_dict in dicts[1:]:
            other_present = key in other_dict
            if (first_present != other_present) or (first_val != other_dict.get(key, _MISSING)):
                differing.add(key)
                break
    return sorted(differing)


def _cap_finding_sort_key(f: Finding) -> tuple[str, str, str]:
    """Sort key for cap_findings with fingerprint tiebreaker."""
    rec_id = f.source.record_id or ""
    if not rec_id and f.evidence and isinstance(f.evidence.get("id"), str):
        rec_id = f.evidence["id"]
    return (f.code, rec_id, f.fingerprint)


def cap_findings(
    findings: list[Finding],
    *,
    max_findings: int = MAX_IDENTITY_FINDINGS,
    source_path: str = "<canonical>",
    context: CheckContext | None = None,
) -> list[Finding]:
    """Sort and cap identity findings, appending a deterministic overflow finding if truncated."""
    sorted_findings = sorted(findings, key=_cap_finding_sort_key)

    if len(sorted_findings) <= max_findings:
        return sorted_findings

    kept = sorted_findings[:max_findings]
    total_count = len(sorted_findings)
    truncated_count = total_count - max_findings

    ctx = context if context is not None else CheckContext()
    norm_source_path = source_path.replace("\\", "/")

    overflow_finding = make_finding(
        code=SL003,
        severity=Severity.WARNING,
        repairability=Repairability.MANUAL,
        message_template=_MSG_OVERFLOW,
        source=SourceRef(path=norm_source_path, line=None, record_id=None),
        evidence={
            "cap": max_findings,
            "overflow": True,
            "total_duplicate_ids": total_count,
            "truncated_count": truncated_count,
            "variant": "overflow-summary",
        },
        adapter_id=ctx.adapter_id,
        adapter_version=ctx.adapter_version,
        profile_id=ctx.profile_id,
        profile_version=ctx.profile_version,
    )
    kept.append(overflow_finding)
    return kept


def check_identities(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    max_findings: int = MAX_IDENTITY_FINDINGS,
    context: CheckContext | None = None,
) -> list[Finding]:
    """Check a sequence of canonical session events for duplicate or conflicting IDs.

    Guarantees:
    - Pure function: no I/O, does not mutate input events list or event objects.
    - O(n) grouping by event.id; null/missing/empty IDs are explicitly ignored.
    - Groups with 2+ occurrences are classified into:
      - Identical-duplicate: all members byte-equal on canonical serialization.
        Severity: warning, Repairability: deterministic.
      - Conflicting-duplicate: any member differs.
        Severity: error, Repairability: manual.
    - Differing fields in evidence contain field names only, no values.
    - IDs processed in sorted order; indexes are ascending.
    - Output capped at max_findings + deterministic overflow marker if truncated.
    """
    if not events:
        return []

    ctx = context if context is not None else CheckContext()
    groups: dict[str, list[tuple[int, Any]]] = defaultdict(list)
    coerced_ids: set[str] = set()

    for idx, event in enumerate(events):
        raw_id = getattr(event, "id", None)
        if raw_id is None and isinstance(event, Mapping):
            raw_id = event.get("id")
        if raw_id is None:
            continue
        if isinstance(raw_id, str):
            if not raw_id.strip():
                continue
            id_str = raw_id
        else:
            id_str = str(raw_id)
            if not id_str.strip():
                continue
            coerced_ids.add(id_str)
        groups[id_str].append((idx, event))

    findings: list[Finding] = []

    for id_ in sorted(groups.keys()):
        occ = groups[id_]
        if len(occ) < 2:
            continue

        idxs = [i for i, _ in occ]
        evs = [e for _, e in occ]
        first_event = evs[0]

        canonical_hashes: list[str] = []
        for e in evs:
            if hasattr(e, "content_identity_hash") and callable(e.content_identity_hash):
                canonical_hashes.append(str(e.content_identity_hash()))
            elif hasattr(e, "to_canonical_dict") and callable(e.to_canonical_dict):
                d = dict(e.to_canonical_dict())
                for field in PROVENANCE_FIELDS:
                    d.pop(field, None)
                canonical_hashes.append(
                    hashlib.sha256(to_canonical_json(d).encode("utf-8")).hexdigest()
                )
            elif isinstance(e, Mapping):
                d = {k: v for k, v in e.items() if str(k) not in PROVENANCE_FIELDS}
                canonical_hashes.append(
                    hashlib.sha256(to_canonical_json(d).encode("utf-8")).hexdigest()
                )
            else:
                canonical_hashes.append(hashlib.sha256(canonical_bytes(e)).hexdigest())

        # Sanitize record_id for SourceRef and message
        safe_rec_id: str | None = id_ if bool(id_.strip()) else None
        if safe_rec_id is not None:
            try:
                enforce_content_free_text(safe_rec_id, context="record_id")
            except Exception:
                safe_rec_id = None

        evidence_indexes = idxs[:MAX_RECORD_INDEXES_IN_EVIDENCE]
        is_truncated = len(idxs) > MAX_RECORD_INDEXES_IN_EVIDENCE
        is_coerced = id_ in coerced_ids

        first_loc = getattr(first_event, "source_location", None)
        if first_loc is None and isinstance(first_event, Mapping):
            first_loc = first_event.get("source_location")

        resolved_path = (
            source_path if (source_path != "<canonical>" or not first_loc) else str(first_loc)
        ).replace("\\", "/")

        first_line = getattr(first_event, "source_line", None)
        if first_line is None and isinstance(first_event, Mapping):
            first_line = first_event.get("source_line")
        line_num: int | None = (
            first_line
            if (
                isinstance(first_line, int) and not isinstance(first_line, bool) and first_line >= 1
            )
            else None
        )

        source_ref = SourceRef(
            path=resolved_path,
            line=line_num,
            record_id=safe_rec_id,
        )

        if len(set(canonical_hashes)) == 1:
            # All members are byte-equal on canonical serialization
            evidence: dict[str, Any] = {
                "count": len(occ),
                "first_index": idxs[0],
                "id": safe_rec_id or "<redacted>",
                "record_indexes": evidence_indexes,
                "variant": "identical-duplicate",
            }
            if is_truncated:
                evidence["truncated"] = True
            if is_coerced:
                evidence["coerced"] = True

            findings.append(
                make_finding(
                    code=SL003,
                    severity=Severity.WARNING,
                    repairability=Repairability.DETERMINISTIC,
                    message_template=_MSG_IDENTICAL,
                    source=source_ref,
                    evidence=evidence,
                    adapter_id=ctx.adapter_id,
                    adapter_version=ctx.adapter_version,
                    profile_id=ctx.profile_id,
                    profile_version=ctx.profile_version,
                )
            )
        else:
            # Conflicting members
            diff_fields = diff_field_names(evs)
            evidence = {
                "count": len(occ),
                "differing_fields": diff_fields,
                "first_index": idxs[0],
                "id": safe_rec_id or "<redacted>",
                "record_indexes": evidence_indexes,
                "variant": "conflicting-duplicate",
            }
            if is_truncated:
                evidence["truncated"] = True
            if is_coerced:
                evidence["coerced"] = True

            findings.append(
                make_finding(
                    code=SL003,
                    severity=Severity.ERROR,
                    repairability=Repairability.MANUAL,
                    message_template=_MSG_CONFLICTING,
                    source=source_ref,
                    evidence=evidence,
                    adapter_id=ctx.adapter_id,
                    adapter_version=ctx.adapter_version,
                    profile_id=ctx.profile_id,
                    profile_version=ctx.profile_version,
                )
            )

    return cap_findings(findings, max_findings=max_findings, source_path=source_path, context=ctx)


__all__ = [
    "MAX_IDENTITY_FINDINGS",
    "MAX_RECORD_INDEXES_IN_EVIDENCE",
    "cap_findings",
    "check_identities",
    "compute_identity_fingerprint",
    "diff_field_names",
]
