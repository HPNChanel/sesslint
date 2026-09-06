"""Generic tool-pairing integrity checks part 2 (SL105, SL106, SL107, SL108).

This module implements four vendor-neutral tool-pairing placement and order rules over
canonical events:
- SL105 (Reversed tool pairing): tool_result index precedes tool call index.
  Severity: error, Repairability: manual.
  Rationale: A response preceding its request violates session causal ordering.
- SL106 (Cross-branch tool pairing): tool call and tool result reside on different parent branches.
  Severity: error, Repairability: manual.
  Rationale: Cross-branch pairing indicates an invalid tree merge or divergent execution.
- SL107 (Non-adjacent tool pairing / gap): Unrelated events intervene between call and result.
  Severity: warning, Repairability: manual.
  Rationale: Interleaved non-tool events disrupt the request-response cycle; suppressed
  when all intervening events belong to valid concurrent tool pairs (parallel-exemption).
- SL108 (Split compaction boundary): A compaction_boundary event splits call and result.
  Severity: warning, Repairability: manual.
  Rationale: A compaction boundary between a call and its result indicates truncation or
  loss of contextual continuity.

Precedence & Clean-Pair Gate:
- Placement checks (SL105-SL108) run ONLY on clean pairs (exactly 1 call + 1 result per corr).
- Correlation IDs flagged with cardinality errors (SL103 reused or SL104 multi-result) are
  skipped here (precedence belongs to TASK-014).
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Final

from sesslint.canonical import SessionEvent
from sesslint.codes import (
    SL105,
    SL106,
    SL107,
    SL108,
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
MAX_INTERVENING_KINDS_SAMPLE: Final[int] = 16

_KIND_TOOL_USE: Final[str] = "tool_use"
_KIND_TOOL_CALL: Final[str] = "tool_call"
_KIND_TOOL_RESULT: Final[str] = "tool_result"
_KIND_COMPACTION: Final[str] = "compaction_boundary"

CALL_KINDS: Final[frozenset[str]] = frozenset({_KIND_TOOL_CALL, _KIND_TOOL_USE})
RESULT_KINDS: Final[frozenset[str]] = frozenset({_KIND_TOOL_RESULT})
TOOL_KINDS: Final[frozenset[str]] = CALL_KINDS | RESULT_KINDS
COMPACTION_KINDS: Final[frozenset[str]] = frozenset({_KIND_COMPACTION})

_MSG_SL105: Final[str] = "Reversed tool-pairing order detected for record {record_id}"
_MSG_SL106: Final[str] = "Cross-branch tool pairing detected for record {record_id}"
_MSG_SL107: Final[str] = "Non-adjacent tool pairing detected for record {record_id}"
_MSG_SL108: Final[str] = "Split compaction boundary detected for record {record_id}"
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
    """Sort key for findings: (code, is_overflow, correlation_id or primary_id, fingerprint)."""
    is_overflow = 1 if (f.evidence and f.evidence.get("overflow") is True) else 0
    primary = ""
    if f.evidence and isinstance(f.evidence.get("correlation_id"), str):
        primary = f.evidence["correlation_id"]
    elif f.source.record_id:
        primary = f.source.record_id
    return (f.code, is_overflow, primary, f.fingerprint)


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


class _DisjointSet:
    """Disjoint-set data structure with path compression and union by rank."""

    __slots__ = ("parent", "rank")

    def __init__(self) -> None:
        self.parent: dict[str, str] = {}
        self.rank: dict[str, int] = {}

    def find(self, item: str) -> str:
        if item not in self.parent:
            self.parent[item] = item
            self.rank[item] = 0
            return item
        root = item
        while root != self.parent[root]:
            root = self.parent[root]
        curr = item
        while curr != root:
            nxt = self.parent[curr]
            self.parent[curr] = root
            curr = nxt
        return root

    def union(self, a: str, b: str) -> None:
        root_a = self.find(a)
        root_b = self.find(b)
        if root_a == root_b:
            return
        rank_a = self.rank[root_a]
        rank_b = self.rank[root_b]
        if rank_a < rank_b:
            self.parent[root_a] = root_b
        elif rank_a > rank_b:
            self.parent[root_b] = root_a
        else:
            self.parent[root_b] = root_a
            self.rank[root_a] += 1


class _ToolPairing2Indexer:
    """Index canonical events, partition clean pairs, and compute parent components."""

    __slots__ = (
        "clean_corrs",
        "compaction_indices",
        "ds",
        "event_kinds",
        "events",
        "id_set",
        "results_by_corr",
        "source_path",
        "uses_by_corr",
    )

    def __init__(
        self,
        events: Sequence[SessionEvent],
        source_path: str = "<canonical>",
    ) -> None:
        self.events = events
        self.source_path = source_path
        self.uses_by_corr: dict[str, list[tuple[int, Any]]] = defaultdict(list)
        self.results_by_corr: dict[str, list[tuple[int, Any]]] = defaultdict(list)
        self.compaction_indices: list[int] = []
        self.event_kinds: list[str] = []
        self.id_set: set[str] = set()
        self.ds = _DisjointSet()

        # Pass 1: Gather IDs and kinds
        for idx, ev in enumerate(events):
            raw_kind = getattr(ev, "kind", None)
            if raw_kind is None and isinstance(ev, Mapping):
                raw_kind = ev.get("kind")
            kind_str = str(raw_kind) if raw_kind is not None else "unknown"
            self.event_kinds.append(kind_str)

            raw_id = getattr(ev, "id", None)
            if raw_id is None and isinstance(ev, Mapping):
                raw_id = ev.get("id")
            if raw_id is not None and str(raw_id).strip():
                ev_id_str = str(raw_id)
                self.id_set.add(ev_id_str)
                self.ds.find(ev_id_str)

            if kind_str in COMPACTION_KINDS:
                self.compaction_indices.append(idx)

            corr = getattr(ev, "correlation_id", None)
            if corr is None and isinstance(ev, Mapping):
                corr = ev.get("correlation_id")

            if corr is not None:
                corr_str = str(corr)
                if kind_str in CALL_KINDS:
                    self.uses_by_corr[corr_str].append((idx, ev))
                elif kind_str in RESULT_KINDS:
                    self.results_by_corr[corr_str].append((idx, ev))

        # Pass 2: Build weakly-connected parent components
        for ev in events:
            raw_id = getattr(ev, "id", None)
            if raw_id is None and isinstance(ev, Mapping):
                raw_id = ev.get("id")
            if raw_id is None or not str(raw_id).strip():
                continue
            ev_id = str(raw_id)

            raw_parent = getattr(ev, "parent_id", None)
            if raw_parent is None and isinstance(ev, Mapping):
                raw_parent = ev.get("parent_id")
            if raw_parent is not None and str(raw_parent).strip():
                parent_id = str(raw_parent)
                if parent_id in self.id_set:
                    self.ds.union(ev_id, parent_id)

        # Pass 3: Filter clean pairs (exactly 1 use and 1 result)
        common_corrs = set(self.uses_by_corr.keys()) & set(self.results_by_corr.keys())
        self.clean_corrs = sorted(
            corr
            for corr in common_corrs
            if len(self.uses_by_corr[corr]) == 1 and len(self.results_by_corr[corr]) == 1
        )

    def component(self, event_id: str | None) -> str:
        """Return canonical component root for an event ID."""
        if event_id is None or not str(event_id).strip():
            return f"<unknown:{id(event_id)}>"
        return self.ds.find(str(event_id))


def check_reversed_order(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    max_findings: int = MAX_PAIRING_FINDINGS,
) -> list[Finding]:
    """Check for reversed tool pairing (SL105) where result index precedes call index.

    Guarantees:
    - Runs only on clean pairs (1 call, 1 result).
    - Trigger: result_index < use_index.
    - severity: error, repairability: manual.
    - evidence: {correlation_id, result_index, use_index}.
    """
    indexer = _ToolPairing2Indexer(events, source_path=source_path)
    findings: list[Finding] = []

    for corr in indexer.clean_corrs:
        use_idx, use_ev = indexer.uses_by_corr[corr][0]
        res_idx, res_ev = indexer.results_by_corr[corr][0]

        if res_idx < use_idx:
            raw_use_id = getattr(use_ev, "id", None)
            if raw_use_id is None and isinstance(use_ev, Mapping):
                raw_use_id = use_ev.get("id")
            use_id_str = str(raw_use_id) if raw_use_id is not None else None

            safe_corr = _safe_id(corr)
            rec_id = _source_record_id(use_id_str)
            path, line = _resolve_source_coords(res_ev, source_path)

            fp = compute_pairing_fingerprint(SL105, [corr, str(use_idx), str(res_idx)])

            findings.append(
                make_finding(
                    code=SL105,
                    severity=Severity.ERROR,
                    repairability=Repairability.MANUAL,
                    message_template=_MSG_SL105,
                    source=SourceRef(path=path, line=line, record_id=rec_id),
                    fingerprint=fp,
                    related_ids=(safe_corr,) if safe_corr != "<redacted>" else (),
                    evidence={
                        "correlation_id": safe_corr,
                        "result_index": res_idx,
                        "use_index": use_idx,
                    },
                )
            )

    return cap_pairing_findings(
        findings,
        code=SL105,
        max_findings=max_findings,
        source_path=source_path,
    )


def check_cross_branch(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    max_findings: int = MAX_PAIRING_FINDINGS,
) -> list[Finding]:
    """Check for cross-branch tool pairing (SL106) where call and result belong to different trees.

    Guarantees:
    - Runs only on clean pairs (1 call, 1 result).
    - Trigger: component(use_id) != component(result_id).
    - severity: error, repairability: manual.
    - evidence: {correlation_id, result_id, result_index, use_id, use_index}.
    """
    indexer = _ToolPairing2Indexer(events, source_path=source_path)
    findings: list[Finding] = []

    for corr in indexer.clean_corrs:
        use_idx, use_ev = indexer.uses_by_corr[corr][0]
        res_idx, res_ev = indexer.results_by_corr[corr][0]

        raw_use_id = getattr(use_ev, "id", None)
        if raw_use_id is None and isinstance(use_ev, Mapping):
            raw_use_id = use_ev.get("id")
        use_id_str = str(raw_use_id) if raw_use_id is not None else None

        raw_res_id = getattr(res_ev, "id", None)
        if raw_res_id is None and isinstance(res_ev, Mapping):
            raw_res_id = res_ev.get("id")
        res_id_str = str(raw_res_id) if raw_res_id is not None else None

        comp_use = indexer.component(use_id_str)
        comp_res = indexer.component(res_id_str)

        if comp_use != comp_res:
            safe_corr = _safe_id(corr)
            safe_use_id = _safe_id(use_id_str)
            safe_res_id = _safe_id(res_id_str)
            rec_id = _source_record_id(use_id_str)
            path, line = _resolve_source_coords(res_ev, source_path)

            fp = compute_pairing_fingerprint(
                SL106,
                [corr, str(use_idx), str(res_idx), comp_use, comp_res],
            )

            findings.append(
                make_finding(
                    code=SL106,
                    severity=Severity.ERROR,
                    repairability=Repairability.MANUAL,
                    message_template=_MSG_SL106,
                    source=SourceRef(path=path, line=line, record_id=rec_id),
                    fingerprint=fp,
                    related_ids=(safe_res_id,) if safe_res_id != "<redacted>" else (),
                    evidence={
                        "correlation_id": safe_corr,
                        "result_id": safe_res_id,
                        "result_index": res_idx,
                        "use_id": safe_use_id,
                        "use_index": use_idx,
                    },
                )
            )

    return cap_pairing_findings(
        findings,
        code=SL106,
        max_findings=max_findings,
        source_path=source_path,
    )


def check_adjacency(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    max_findings: int = MAX_PAIRING_FINDINGS,
) -> list[Finding]:
    """Check for non-adjacent tool pairing (SL107) with parallel-exemption for concurrent tools.

    Guarantees:
    - Runs only on clean pairs (1 call, 1 result).
    - Trigger: abs(result_index - use_index) > 1 AND at least one intervening event
      is NOT a tool event.
    - Parallel-exemption: If ALL intervening events have kind in (tool_call, tool_use,
      tool_result), SL107 is suppressed to allow concurrent tool fan-out.
    - severity: warning, repairability: manual.
    - evidence: {correlation_id, intervening_count, intervening_kinds, result_index, use_index}.
    """
    indexer = _ToolPairing2Indexer(events, source_path=source_path)
    findings: list[Finding] = []

    for corr in indexer.clean_corrs:
        use_idx, use_ev = indexer.uses_by_corr[corr][0]
        res_idx, _res_ev = indexer.results_by_corr[corr][0]

        min_idx = min(use_idx, res_idx)
        max_idx = max(use_idx, res_idx)

        if max_idx - min_idx <= 1:
            continue

        intervening_kinds_slice = indexer.event_kinds[min_idx + 1 : max_idx]
        intervening_count = len(intervening_kinds_slice)

        # Parallel-exemption: Suppress SL107 iff all intervening events are tool kinds
        if all(k in TOOL_KINDS for k in intervening_kinds_slice):
            continue

        safe_corr = _safe_id(corr)
        raw_use_id = getattr(use_ev, "id", None)
        if raw_use_id is None and isinstance(use_ev, Mapping):
            raw_use_id = use_ev.get("id")
        use_id_str = str(raw_use_id) if raw_use_id is not None else None
        rec_id = _source_record_id(use_id_str)
        path, line = _resolve_source_coords(use_ev, source_path)

        unique_intervening_kinds = sorted(set(intervening_kinds_slice))

        fp = compute_pairing_fingerprint(
            SL107,
            [corr, str(use_idx), str(res_idx), str(intervening_count)],
        )

        findings.append(
            make_finding(
                code=SL107,
                severity=Severity.WARNING,
                repairability=Repairability.MANUAL,
                message_template=_MSG_SL107,
                source=SourceRef(path=path, line=line, record_id=rec_id),
                fingerprint=fp,
                related_ids=(safe_corr,) if safe_corr != "<redacted>" else (),
                evidence={
                    "correlation_id": safe_corr,
                    "intervening_count": intervening_count,
                    "intervening_kinds": unique_intervening_kinds[:MAX_INTERVENING_KINDS_SAMPLE],
                    "result_index": res_idx,
                    "use_index": use_idx,
                },
            )
        )

    return cap_pairing_findings(
        findings,
        code=SL107,
        max_findings=max_findings,
        source_path=source_path,
    )


def check_compaction_split(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    max_findings: int = MAX_PAIRING_FINDINGS,
) -> list[Finding]:
    """Check for compaction boundaries splitting a tool pair (SL108).

    Guarantees:
    - Runs only on clean pairs (1 call, 1 result).
    - Trigger: A compaction_boundary event index k exists strictly between use_idx and result_idx.
    - severity: warning, repairability: manual.
    - evidence: {boundary_index, correlation_id, result_index, use_index}.
    """
    indexer = _ToolPairing2Indexer(events, source_path=source_path)
    findings: list[Finding] = []

    for corr in indexer.clean_corrs:
        use_idx, use_ev = indexer.uses_by_corr[corr][0]
        res_idx, _res_ev = indexer.results_by_corr[corr][0]

        min_idx = min(use_idx, res_idx)
        max_idx = max(use_idx, res_idx)

        split_boundaries = [k for k in indexer.compaction_indices if min_idx < k < max_idx]
        if not split_boundaries:
            continue

        first_boundary_idx = split_boundaries[0]
        safe_corr = _safe_id(corr)
        raw_use_id = getattr(use_ev, "id", None)
        if raw_use_id is None and isinstance(use_ev, Mapping):
            raw_use_id = use_ev.get("id")
        use_id_str = str(raw_use_id) if raw_use_id is not None else None
        rec_id = _source_record_id(use_id_str)
        path, line = _resolve_source_coords(use_ev, source_path)

        fp = compute_pairing_fingerprint(
            SL108,
            [corr, str(use_idx), str(res_idx), str(first_boundary_idx)],
        )

        findings.append(
            make_finding(
                code=SL108,
                severity=Severity.WARNING,
                repairability=Repairability.MANUAL,
                message_template=_MSG_SL108,
                source=SourceRef(path=path, line=line, record_id=rec_id),
                fingerprint=fp,
                related_ids=(safe_corr,) if safe_corr != "<redacted>" else (),
                evidence={
                    "boundary_index": first_boundary_idx,
                    "correlation_id": safe_corr,
                    "result_index": res_idx,
                    "use_index": use_idx,
                },
            )
        )

    return cap_pairing_findings(
        findings,
        code=SL108,
        max_findings=max_findings,
        source_path=source_path,
    )


def check_tool_pairing_2(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    max_findings_per_family: int = MAX_PAIRING_FINDINGS,
) -> list[Finding]:
    """Run all part-2 tool pairing checks (SL105, SL106, SL107, SL108) over canonical events.

    Guarantees:
    - Pure function: no I/O, does not mutate input events or session objects.
    - Evaluates clean pairs only (precedence given to part-1 cardinality checks).
    - Enforces parallel-exemption for concurrent tool fan-out in SL107.
    - Findings sorted deterministically by (code, is_overflow, primary_id, fingerprint).
    - Capped at max_findings_per_family per code family with overflow summary finding.
    """
    all_findings: list[Finding] = []

    all_findings.extend(
        check_reversed_order(
            events,
            source_path=source_path,
            max_findings=max_findings_per_family,
        )
    )
    all_findings.extend(
        check_cross_branch(
            events,
            source_path=source_path,
            max_findings=max_findings_per_family,
        )
    )
    all_findings.extend(
        check_adjacency(
            events,
            source_path=source_path,
            max_findings=max_findings_per_family,
        )
    )
    all_findings.extend(
        check_compaction_split(
            events,
            source_path=source_path,
            max_findings=max_findings_per_family,
        )
    )

    return sorted(all_findings, key=_cap_finding_sort_key)


# Aliases for specification and test compatibility
check_sl105 = check_reversed_order
check_sl106 = check_cross_branch
check_sl107 = check_adjacency
check_sl108 = check_compaction_split

__all__ = [
    "CALL_KINDS",
    "COMPACTION_KINDS",
    "MAX_INDEX_SAMPLE_SIZE",
    "MAX_INTERVENING_KINDS_SAMPLE",
    "MAX_PAIRING_FINDINGS",
    "RESULT_KINDS",
    "TOOL_KINDS",
    "cap_pairing_findings",
    "check_adjacency",
    "check_compaction_split",
    "check_cross_branch",
    "check_reversed_order",
    "check_sl105",
    "check_sl106",
    "check_sl107",
    "check_sl108",
    "check_tool_pairing_2",
    "compute_pairing_fingerprint",
]
