"""Generic tool-pairing integrity checks part 1 (SL101, SL102, SL103, SL104).

This module implements four vendor-neutral tool-pairing rules over canonical events:
- SL101 (Orphan tool result): tool_result has no matching tool call.
  Severity: error, Repairability: manual.
  Rationale: An orphan tool result may represent unverified external state execution
  without a proven antecedent request; conservative repair cannot synthesize a call.
- SL102 (Dangling tool call): tool call has no matching tool_result.
  Severity: error, Repairability: manual.
  Rationale: A dangling tool call leaves execution state unresolved; conservative repair
  refuses to synthesize fake tool outputs.
- SL103 (Reused tool-call ID): Multiple distinct tool calls share a correlation identifier.
  Severity: error, Repairability: manual.
  Rationale: Reused call identifiers create ambiguity in request-response pairing that
  cannot be automatically disambiguated without operator choice.
- SL104 (Multiple tool results): Multiple tool_result events match a single tool call.
  Severity: error, Repairability: manual.
  Rationale: Duplicate or competing responses indicate dropped connections or race conditions
  in the upstream environment; manual selection is required.

Pairing Keys & Scope:
- Tool events are identified strictly by `kind in CALL_KINDS` or `kind in RESULT_KINDS`.
- Other event kinds (messages, checkpoints, etc.) are ignored.
- The join key is `correlation_id`.
- If `correlation_id is None`:
    - A tool call is unpairable and flagged as SL102 (dangling-call).
    - A tool result is unpairable and flagged as SL101 (orphan-result).
- An empty string `""` or whitespace correlation_id is treated as a real key.
- When a correlation identifier has both multiple calls and multiple results,
  both SL103 and SL104 fire.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Final

from sesslint.canonical import SessionEvent, compute_content_hash
from sesslint.codes import (
    SL101,
    SL102,
    SL103,
    SL104,
    Repairability,
    Severity,
)
from sesslint.finding import (
    Finding,
    SourceRef,
    enforce_content_free_text,
    make_finding,
)

MAX_PAIRING_FINDINGS: Final[int] = 500
MAX_INDEX_SAMPLE_SIZE: Final[int] = 32
MAX_PAIRING_SAMPLE_SIZE: Final[int] = MAX_INDEX_SAMPLE_SIZE

_KIND_TOOL_USE: Final[str] = "tool_use"
_KIND_TOOL_CALL: Final[str] = "tool_call"
_KIND_TOOL_RESULT: Final[str] = "tool_result"

CALL_KINDS: Final[frozenset[str]] = frozenset({_KIND_TOOL_CALL, _KIND_TOOL_USE})
RESULT_KINDS: Final[frozenset[str]] = frozenset({_KIND_TOOL_RESULT})

_MSG_SL101: Final[str] = "Orphan tool result detected for record {record_id}"
_MSG_SL102: Final[str] = "Dangling tool call detected for record {record_id}"
_MSG_SL103: Final[str] = "Reused tool-call ID detected for record {record_id}"
_MSG_SL104: Final[str] = "Multiple tool results detected for record {record_id}"
_MSG_OVERFLOW: Final[str] = "Tool pairing check finding cap reached; remaining records truncated"


def _safe_id(id_str: str | None) -> str:
    """Sanitize string for content-free enforcement, returning '<redacted>' on violation."""
    if id_str is None:
        return "<redacted>"
    try:
        enforce_content_free_text(id_str, context="id")
        return id_str
    except Exception:
        return "<redacted>"


def _source_record_id(id_str: str | None) -> str | None:
    """Return a sanitized record_id suitable for SourceRef, or None if empty/whitespace."""
    if id_str is None:
        return None
    s = str(id_str).strip()
    if not s:
        return None
    return _safe_id(id_str)


def compute_pairing_fingerprint(code: str, items: Iterable[str]) -> str:
    """Compute deterministic 16-character sha256 fingerprint for a tool-pairing finding.

    Formula: sha256(code + "|" + ",".join(sorted(items)))[:16]
    """
    sorted_items = sorted(set(str(x) for x in items))
    content = f"{code}|{','.join(sorted_items)}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def _cap_finding_sort_key(f: Finding) -> tuple[str, int, str, str]:
    """Sort key for findings: (code, is_overflow, primary_id, fingerprint)."""
    is_overflow = 1 if (f.evidence and f.evidence.get("overflow") is True) else 0
    rec_id = f.source.record_id or ""
    if not rec_id and f.evidence and isinstance(f.evidence.get("correlation_id"), str):
        rec_id = f.evidence["correlation_id"]
    return (f.code, is_overflow, rec_id, f.fingerprint)


def cap_pairing_findings(
    findings: list[Finding],
    *,
    code: str,
    max_findings: int = MAX_PAIRING_FINDINGS,
    source_path: str = "<canonical>",
) -> list[Finding]:
    """Sort findings by (code, primary_id) and cap family at max_findings with overflow finding."""
    sorted_findings = sorted(findings, key=_cap_finding_sort_key)

    if len(sorted_findings) <= max_findings:
        return sorted_findings

    kept = sorted_findings[:max_findings]
    total_count = len(sorted_findings)
    truncated_count = total_count - max_findings

    overflow_fp = hashlib.sha256(f"{code}|overflow|{max_findings}".encode()).hexdigest()[:16]
    norm_source_path = source_path.replace("\\", "/")

    overflow_finding = make_finding(
        code=code,
        severity=Severity.WARNING,
        repairability=Repairability.MANUAL,
        message_template=_MSG_OVERFLOW,
        source=SourceRef(path=norm_source_path, line=None, record_id=None),
        fingerprint=overflow_fp,
        evidence={
            "cap": max_findings,
            "overflow": True,
            "total_count": total_count,
            "truncated_count": truncated_count,
            "variant": "overflow-summary",
        },
    )
    kept.append(overflow_finding)
    return kept


def _resolve_source_coords(
    event: Any,
    default_path: str,
) -> tuple[str, int | None]:
    """Resolve normalized source path and line number for an event."""
    first_loc = getattr(event, "source_location", None)
    if first_loc is None and isinstance(event, Mapping):
        first_loc = event.get("source_location")

    resolved_path = (
        default_path if (default_path != "<canonical>" or not first_loc) else str(first_loc)
    ).replace("\\", "/")

    raw_line = getattr(event, "source_line", None)
    if raw_line is None and isinstance(event, Mapping):
        raw_line = event.get("source_line")

    line_num: int | None = (
        raw_line
        if (isinstance(raw_line, int) and not isinstance(raw_line, bool) and raw_line >= 1)
        else None
    )
    return resolved_path, line_num


class _ToolPairingIndexer:
    """Single-pass indexer partitioning tool events by correlation_id."""

    __slots__ = (
        "null_results",
        "null_uses",
        "results_by_corr",
        "source_path",
        "uses_by_corr",
    )

    def __init__(
        self,
        events: Sequence[SessionEvent],
        source_path: str = "<canonical>",
    ) -> None:
        self.source_path = source_path
        self.uses_by_corr: dict[str, list[tuple[int, Any]]] = defaultdict(list)
        self.results_by_corr: dict[str, list[tuple[int, Any]]] = defaultdict(list)
        self.null_uses: list[tuple[int, Any]] = []
        self.null_results: list[tuple[int, Any]] = []

        for idx, ev in enumerate(events):
            raw_kind = getattr(ev, "kind", None)
            if raw_kind is None and isinstance(ev, Mapping):
                raw_kind = ev.get("kind")

            if raw_kind in CALL_KINDS:
                corr = getattr(ev, "correlation_id", None)
                if corr is None and isinstance(ev, Mapping):
                    corr = ev.get("correlation_id")

                if corr is None:
                    self.null_uses.append((idx, ev))
                else:
                    self.uses_by_corr[str(corr)].append((idx, ev))

            elif raw_kind in RESULT_KINDS:
                corr = getattr(ev, "correlation_id", None)
                if corr is None and isinstance(ev, Mapping):
                    corr = ev.get("correlation_id")

                if corr is None:
                    self.null_results.append((idx, ev))
                else:
                    self.results_by_corr[str(corr)].append((idx, ev))


def check_orphans(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    max_findings: int = MAX_PAIRING_FINDINGS,
) -> list[Finding]:
    """Check for orphan tool results (SL101) matching zero tool calls.

    Guarantees:
    - Emitted per orphan result event.
    - severity: error, repairability: manual.
    - evidence: {result_id, correlation_id, index}.
    """
    indexer = _ToolPairingIndexer(events, source_path=source_path)
    findings: list[Finding] = []

    # 1. Results with defined correlation_id not present in uses
    orphan_corrs = sorted(set(indexer.results_by_corr.keys()) - set(indexer.uses_by_corr.keys()))
    for corr in orphan_corrs:
        safe_corr = _safe_id(corr)
        for idx, ev in indexer.results_by_corr[corr]:
            raw_ev_id = getattr(ev, "id", None)
            if raw_ev_id is None and isinstance(ev, Mapping):
                raw_ev_id = ev.get("id")
            ev_id_str = str(raw_ev_id) if raw_ev_id is not None else f"<result:{idx}>"
            safe_ev_id = _safe_id(ev_id_str)
            rec_id = _source_record_id(ev_id_str)

            path, line = _resolve_source_coords(ev, source_path)
            fp = compute_pairing_fingerprint(SL101, [corr, ev_id_str, str(idx)])

            findings.append(
                make_finding(
                    code=SL101,
                    severity=Severity.ERROR,
                    repairability=Repairability.MANUAL,
                    message_template=_MSG_SL101,
                    source=SourceRef(path=path, line=line, record_id=rec_id),
                    fingerprint=fp,
                    related_ids=(safe_corr,) if safe_corr != "<redacted>" else (),
                    evidence={
                        "correlation_id": safe_corr,
                        "index": idx,
                        "result_id": safe_ev_id,
                    },
                )
            )

    # 2. Results with null correlation_id
    for idx, ev in indexer.null_results:
        raw_ev_id = getattr(ev, "id", None)
        if raw_ev_id is None and isinstance(ev, Mapping):
            raw_ev_id = ev.get("id")
        ev_id_str = str(raw_ev_id) if raw_ev_id is not None else f"<result:{idx}>"
        safe_ev_id = _safe_id(ev_id_str)
        rec_id = _source_record_id(ev_id_str)

        path, line = _resolve_source_coords(ev, source_path)
        fp = compute_pairing_fingerprint(SL101, ["null", ev_id_str, str(idx)])

        findings.append(
            make_finding(
                code=SL101,
                severity=Severity.ERROR,
                repairability=Repairability.MANUAL,
                message_template=_MSG_SL101,
                source=SourceRef(path=path, line=line, record_id=rec_id),
                fingerprint=fp,
                evidence={
                    "correlation_id": None,
                    "index": idx,
                    "result_id": safe_ev_id,
                },
            )
        )

    return cap_pairing_findings(
        findings,
        code=SL101,
        max_findings=max_findings,
        source_path=source_path,
    )


def check_dangling(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    max_findings: int = MAX_PAIRING_FINDINGS,
) -> list[Finding]:
    """Check for dangling tool calls (SL102) with zero matching tool_result events.

    Guarantees:
    - Emitted per dangling tool call event.
    - severity: error, repairability: manual.
    - evidence: {correlation_id, event_id, index}.
    """
    indexer = _ToolPairingIndexer(events, source_path=source_path)
    findings: list[Finding] = []

    # 1. Uses with defined correlation_id not present in results
    dangling_corrs = sorted(set(indexer.uses_by_corr.keys()) - set(indexer.results_by_corr.keys()))
    for corr in dangling_corrs:
        safe_corr = _safe_id(corr)
        for idx, ev in indexer.uses_by_corr[corr]:
            raw_ev_id = getattr(ev, "id", None)
            if raw_ev_id is None and isinstance(ev, Mapping):
                raw_ev_id = ev.get("id")
            ev_id_str = str(raw_ev_id) if raw_ev_id is not None else f"<call:{idx}>"
            safe_ev_id = _safe_id(ev_id_str)
            rec_id = _source_record_id(ev_id_str)

            path, line = _resolve_source_coords(ev, source_path)
            fp = compute_pairing_fingerprint(SL102, [corr, ev_id_str, str(idx)])

            findings.append(
                make_finding(
                    code=SL102,
                    severity=Severity.ERROR,
                    repairability=Repairability.MANUAL,
                    message_template=_MSG_SL102,
                    source=SourceRef(path=path, line=line, record_id=rec_id),
                    fingerprint=fp,
                    related_ids=(safe_corr,) if safe_corr != "<redacted>" else (),
                    evidence={
                        "correlation_id": safe_corr,
                        "event_id": safe_ev_id,
                        "index": idx,
                    },
                )
            )

    # 2. Uses with null correlation_id
    for idx, ev in indexer.null_uses:
        raw_ev_id = getattr(ev, "id", None)
        if raw_ev_id is None and isinstance(ev, Mapping):
            raw_ev_id = ev.get("id")
        ev_id_str = str(raw_ev_id) if raw_ev_id is not None else f"<call:{idx}>"
        safe_ev_id = _safe_id(ev_id_str)
        rec_id = _source_record_id(ev_id_str)

        path, line = _resolve_source_coords(ev, source_path)
        fp = compute_pairing_fingerprint(SL102, ["null", ev_id_str, str(idx)])

        findings.append(
            make_finding(
                code=SL102,
                severity=Severity.ERROR,
                repairability=Repairability.MANUAL,
                message_template=_MSG_SL102,
                source=SourceRef(path=path, line=line, record_id=rec_id),
                fingerprint=fp,
                evidence={
                    "correlation_id": None,
                    "event_id": safe_ev_id,
                    "index": idx,
                },
            )
        )

    return cap_pairing_findings(
        findings,
        code=SL102,
        max_findings=max_findings,
        source_path=source_path,
    )


def check_reused(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    max_findings: int = MAX_PAIRING_FINDINGS,
) -> list[Finding]:
    """Check for reused tool-call IDs (SL103) where >1 tool calls share correlation_id.

    Guarantees:
    - Emitted one finding per correlation_id.
    - severity: error, repairability: manual.
    - evidence: {correlation_id, count, call_indexes[], event_ids[], call_ids[], truncated}.
    """
    indexer = _ToolPairingIndexer(events, source_path=source_path)
    findings: list[Finding] = []

    for corr in sorted(indexer.uses_by_corr.keys()):
        occ = indexer.uses_by_corr[corr]
        if len(occ) <= 1:
            continue

        call_indexes = [idx for idx, _ in occ]
        call_ids: list[str] = []
        for idx, ev in occ:
            raw_id = getattr(ev, "id", None)
            if raw_id is None and isinstance(ev, Mapping):
                raw_id = ev.get("id")
            ev_id = str(raw_id) if raw_id is not None else f"<call:{idx}>"
            call_ids.append(_safe_id(ev_id))

        safe_corr = _safe_id(corr)
        first_ev = occ[0][1]
        first_ev_id = call_ids[0] if call_ids else None
        rec_id = _source_record_id(first_ev_id)
        path, line = _resolve_source_coords(first_ev, source_path)

        fp = compute_pairing_fingerprint(SL103, [corr] + [str(i) for i in sorted(call_indexes)])

        sample_indexes = call_indexes[:MAX_INDEX_SAMPLE_SIZE]
        sample_ids = call_ids[:MAX_INDEX_SAMPLE_SIZE]
        is_truncated = len(call_indexes) > MAX_INDEX_SAMPLE_SIZE

        evidence: dict[str, Any] = {
            "call_ids": sample_ids,
            "call_indexes": sample_indexes,
            "correlation_id": safe_corr,
            "count": len(occ),
            "event_ids": sample_ids,
            "truncated": is_truncated,
        }

        findings.append(
            make_finding(
                code=SL103,
                severity=Severity.ERROR,
                repairability=Repairability.MANUAL,
                message_template=_MSG_SL103,
                source=SourceRef(
                    path=path,
                    line=line,
                    record_id=rec_id,
                ),
                fingerprint=fp,
                related_ids=tuple(call_ids[:MAX_INDEX_SAMPLE_SIZE]),
                evidence=evidence,
            )
        )

    return cap_pairing_findings(
        findings,
        code=SL103,
        max_findings=max_findings,
        source_path=source_path,
    )


def check_multi_results(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    max_findings: int = MAX_PAIRING_FINDINGS,
) -> list[Finding]:
    """Check for multiple tool results (SL104) where >1 tool_result events share correlation_id.

    Guarantees:
    - Emitted one finding per correlation_id.
    - severity: error, repairability: manual.
    - evidence: {correlation_id, count, result_indexes[], event_ids[], result_ids[], truncated}.
    """
    indexer = _ToolPairingIndexer(events, source_path=source_path)
    findings: list[Finding] = []

    for corr in sorted(indexer.results_by_corr.keys()):
        occ = indexer.results_by_corr[corr]
        if len(occ) <= 1:
            continue

        result_indexes = [idx for idx, _ in occ]
        result_ids: list[str] = []
        for idx, ev in occ:
            raw_id = getattr(ev, "id", None)
            if raw_id is None and isinstance(ev, Mapping):
                raw_id = ev.get("id")
            ev_id = str(raw_id) if raw_id is not None else f"<result:{idx}>"
            result_ids.append(_safe_id(ev_id))

        safe_corr = _safe_id(corr)
        first_ev = occ[0][1]
        first_ev_id = result_ids[0] if result_ids else None
        rec_id = _source_record_id(first_ev_id)
        path, line = _resolve_source_coords(first_ev, source_path)

        fp = compute_pairing_fingerprint(SL104, [corr] + [str(i) for i in sorted(result_indexes)])

        sample_indexes = result_indexes[:MAX_INDEX_SAMPLE_SIZE]
        sample_ids = result_ids[:MAX_INDEX_SAMPLE_SIZE]
        is_truncated = len(result_indexes) > MAX_INDEX_SAMPLE_SIZE

        evidence: dict[str, Any] = {
            "correlation_id": safe_corr,
            "count": len(occ),
            "event_ids": sample_ids,
            "result_ids": sample_ids,
            "result_indexes": sample_indexes,
            "truncated": is_truncated,
        }

        # Check if candidate results for this correlation_id have identical content fingerprints
        res_events = [events[i] for i in result_indexes if 0 <= i < len(events)]
        fps: set[str] = set()
        for e in res_events:
            p = getattr(e, "payload", None)
            if p is None and isinstance(e, Mapping):
                p = e.get("payload")
            if isinstance(p, Mapping):
                fps.add(compute_content_hash(p))
            else:
                fps.add(str(p))

        call_count = len(indexer.uses_by_corr.get(corr, []))
        rep = (
            Repairability.DETERMINISTIC
            if call_count == 1 and len(res_events) >= 2 and len(fps) == 1
            else Repairability.MANUAL
        )

        findings.append(
            make_finding(
                code=SL104,
                severity=Severity.ERROR,
                repairability=rep,
                message_template=_MSG_SL104,
                source=SourceRef(
                    path=path,
                    line=line,
                    record_id=rec_id,
                ),
                fingerprint=fp,
                related_ids=tuple(result_ids[:MAX_INDEX_SAMPLE_SIZE]),
                evidence=evidence,
            )
        )

    return cap_pairing_findings(
        findings,
        code=SL104,
        max_findings=max_findings,
        source_path=source_path,
    )


def check_tool_pairing_1(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    max_findings_per_family: int = MAX_PAIRING_FINDINGS,
) -> list[Finding]:
    """Run all part-1 tool pairing checks (SL101, SL102, SL103, SL104) over canonical events.

    Guarantees:
    - Pure function: no I/O, does not mutate input events or session objects.
    - O(n) partitioning and aggregation over tool calls and tool_result events.
    - Findings sorted deterministically by (code, is_overflow, primary_id, fingerprint).
    - Capped at max_findings_per_family per code family with overflow summary finding.
    """
    all_findings: list[Finding] = []

    all_findings.extend(
        check_orphans(
            events,
            source_path=source_path,
            max_findings=max_findings_per_family,
        )
    )
    all_findings.extend(
        check_dangling(
            events,
            source_path=source_path,
            max_findings=max_findings_per_family,
        )
    )
    all_findings.extend(
        check_reused(
            events,
            source_path=source_path,
            max_findings=max_findings_per_family,
        )
    )
    all_findings.extend(
        check_multi_results(
            events,
            source_path=source_path,
            max_findings=max_findings_per_family,
        )
    )

    return sorted(all_findings, key=_cap_finding_sort_key)


# Aliases for specification and test compatibility
check_orphan_results = check_orphans
check_sl101 = check_orphans
check_dangling_calls = check_dangling
check_sl102 = check_dangling
check_reused_ids = check_reused
check_sl103 = check_reused
check_multiple_results = check_multi_results
check_sl104 = check_multi_results

__all__ = [
    "CALL_KINDS",
    "MAX_INDEX_SAMPLE_SIZE",
    "MAX_PAIRING_FINDINGS",
    "MAX_PAIRING_SAMPLE_SIZE",
    "RESULT_KINDS",
    "cap_pairing_findings",
    "check_dangling",
    "check_dangling_calls",
    "check_multi_results",
    "check_multiple_results",
    "check_orphan_results",
    "check_orphans",
    "check_reused",
    "check_reused_ids",
    "check_sl101",
    "check_sl102",
    "check_sl103",
    "check_sl104",
    "check_tool_pairing_1",
    "compute_pairing_fingerprint",
]
