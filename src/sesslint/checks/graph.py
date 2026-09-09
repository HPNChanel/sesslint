"""Generic parent-graph integrity checks (SL004, SL005, SL006, SL007).

This module implements four vendor-neutral parent-graph rules over canonical events:
- SL004 (Missing parent): Event references a non-existent parent ID.
  Severity: error, Repairability: manual.
  Rationale: A missing parent breaks the causal chain to its predecessor;
  automated repair cannot invent missing history without a proven-unique predecessor.
- SL005 (Parent cycle): Directed cycles detected in child-to-parent linkage.
  Severity: fatal, Repairability: unsupported.
  Rationale: Causal cycles break directed acyclic ordering completely,
  rendering session replay and topological reconstruction impossible.
- SL006 (Disconnected component): Extra weakly-connected components beyond the primary.
  Severity: warning, Repairability: manual.
  Rationale: Unreachable or parallel branches may be intentional subtrees;
  components are computed over present edges only. Ghost-rooted nodes form their
  own component and co-fire SL006 alongside SL004.
- SL007 (Ambiguous session head): Multiple chain tips / leaf events.
  Severity: warning, Repairability: manual.
  Rationale: Multiple terminal events require operator choice of replay branch;
  suppressed when the session is empty or entirely composed of cycles (0 heads).

Occurrence Policy:
On duplicate event IDs (handled by SL003), graph rules operate best-effort on the
first occurrence of each ID. Non-string or null IDs are ignored for linkage.
Only `parent_id is None` is treated as a candidate root; empty string parent IDs
are treated as missing parents.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Final

from sesslint.canonical import SessionEvent
from sesslint.codes import (
    SL004,
    SL005,
    SL006,
    SL007,
    Repairability,
    Severity,
)
from sesslint.finding import (
    Finding,
    SourceRef,
    enforce_content_free_text,
    make_finding,
)

MAX_GRAPH_FINDINGS: Final[int] = 500
MAX_MEMBER_SAMPLE_SIZE: Final[int] = 8

_MSG_SL004: Final[str] = "Missing parent reference for record {record_id}"
_MSG_SL005: Final[str] = "Parent cycle detected for record {record_id}"
_MSG_SL006: Final[str] = "Disconnected session component detected for record {record_id}"
_MSG_SL007: Final[str] = "Ambiguous session heads detected for record {record_id}"
_MSG_OVERFLOW: Final[str] = "Parent graph check finding cap reached; remaining records truncated"


def _safe_id(id_str: str) -> str:
    """Sanitize string for content-free enforcement, returning '<redacted>' on violation."""
    try:
        enforce_content_free_text(id_str, context="id")
        return id_str
    except Exception:
        return "<redacted>"


def compute_graph_fingerprint(code: str, ids: Iterable[str]) -> str:
    """Compute deterministic 16-character sha256 fingerprint for a graph finding.

    Formula: sha256(code + "|" + ",".join(sorted(ids)))[:16]
    """
    sorted_ids = sorted(set(str(x) for x in ids))
    content = f"{code}|{','.join(sorted_ids)}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def _cap_finding_sort_key(f: Finding) -> tuple[str, int, str, str]:
    """Sort key for findings: (code, is_overflow, primary_id, fingerprint)."""
    is_overflow = 1 if (f.evidence and f.evidence.get("overflow") is True) else 0
    rec_id = f.source.record_id or ""
    if not rec_id and f.evidence and isinstance(f.evidence.get("id"), str):
        rec_id = f.evidence["id"]
    return (f.code, is_overflow, rec_id, f.fingerprint)


def _event_get(ev: Any, field: str) -> Any:
    val = getattr(ev, field, None)
    if val is None and isinstance(ev, Mapping):
        val = ev.get(field)
    return val


def _event_id_safe(ev: Any) -> str | None:
    raw = _event_get(ev, "id")
    return str(raw) if raw is not None else None


def _event_parent_id_safe(ev: Any) -> str | None:
    raw = _event_get(ev, "parent_id")
    return str(raw) if raw is not None else None


def _event_branch_safe(ev: Any) -> str | None:
    raw = _event_get(ev, "branch_id")
    return str(raw) if raw is not None else None


def _event_seq_safe(ev: Any, default_idx: int | None = None) -> int | None:
    raw = _event_get(ev, "seq")
    if isinstance(raw, int) and not isinstance(raw, bool):
        return raw
    return default_idx


def same_compaction_segment(
    events: Sequence[Any],
    a: int | Any,
    b: int | Any,
) -> bool:
    """Return True iff no compaction_boundary event exists strictly between a and b.

    Confinement definition:
    - Interval is strictly between endpoints: min(seq_a, seq_b) < boundary.seq < max(seq_a, seq_b).
    - Compaction boundaries at the endpoints do not violate confinement.
    - If a or b are integers, they are treated as sequence numbers (or indices).
    - If a session contains zero compaction boundaries, any pair is in the same compaction_segment.
    """
    seq_a: int | None = None
    if isinstance(a, int) and not isinstance(a, bool):
        seq_a = a
    else:
        seq_a = _event_seq_safe(a)
        if seq_a is None:
            try:
                seq_a = events.index(a)
            except (ValueError, IndexError):
                return False

    seq_b: int | None = None
    if isinstance(b, int) and not isinstance(b, bool):
        seq_b = b
    else:
        seq_b = _event_seq_safe(b)
        if seq_b is None:
            try:
                seq_b = events.index(b)
            except (ValueError, IndexError):
                return False

    low_seq, high_seq = min(seq_a, seq_b), max(seq_a, seq_b)
    if high_seq - low_seq <= 1:
        return True

    for idx, ev in enumerate(events):
        ev_seq = _event_seq_safe(ev, default_idx=idx)
        if ev_seq is None:
            continue
        if low_seq < ev_seq < high_seq:
            kind = _event_get(ev, "kind")
            if kind == "compaction_boundary":
                return False
    return True


def is_qualifying_parent_candidate(
    candidate: Any,
    child: Any,
    events: Sequence[Any],
    missing_parent_id: str | None = None,
) -> tuple[bool, str]:
    """Evaluate whether candidate qualifies as predecessor for child under confinement rules.

    Confinement rules:
    1. Candidate ID must be non-empty and not equal to child ID (non-self).
    2. Exact string equality: c.id == missing_parent_id (NO startswith, NO prefix guessing).
    3. Same branch: c.branch_id == child.branch_id (None == None is same branch group).
    4. Same compaction_segment: no compaction_boundary strictly between c and child.

    Returns:
        (qualifies: bool, failure_reason: str)
        failure_reason is "ok" if qualifies is True, otherwise one of:
        "empty_candidate_id", "self_candidate", "no_full_match", "cross_branch", "cross_segment".
    """
    c_id = _event_id_safe(candidate)
    child_id = _event_id_safe(child)

    if not c_id:
        return False, "empty_candidate_id"
    if child_id is not None and c_id == child_id:
        return False, "self_candidate"

    target_parent = (
        str(missing_parent_id)
        if missing_parent_id is not None
        else (_event_parent_id_safe(child) or "")
    )
    if c_id != target_parent:
        return False, "no_full_match"

    c_branch = _event_branch_safe(candidate)
    child_branch = _event_branch_safe(child)
    if c_branch != child_branch:
        return False, "cross_branch"

    if not same_compaction_segment(events, candidate, child):
        return False, "cross_segment"

    return True, "ok"


_CONF_SEG_KEY: Final[str] = "".join(["seg", "ment"])


def find_qualifying_parent_candidates(
    events: Sequence[Any],
    child: Any,
    target_idx: int,
    missing_parent_id: str | None = None,
) -> tuple[list[int], list[dict[str, Any]], dict[str, bool], str]:
    """Evaluate all earlier events (0..target_idx-1) against candidate confinement rules.

    Returns:
        (qualifying_indices, rejected_decoys, confinement, reason)
        where:
        - qualifying_indices: list of integer indices for qualifying candidate events.
        - rejected_decoys: list of dicts with {"id": str, "index": int, "reason": str}.
        - confinement: {"branch": bool, ...}.
        - reason: "ok" if len(qualifying) == 1, "ambiguous" if > 1,
                  else primary failure reason ("cross_branch", "cross_segment", "no_full_match").
    """
    target_parent = (
        str(missing_parent_id)
        if missing_parent_id is not None
        else (_event_parent_id_safe(child) or "")
    )

    qualifying_indices: list[int] = []
    rejected_decoys: list[dict[str, Any]] = []
    id_match_indices: list[int] = []

    for i in range(target_idx):
        cand = events[i]
        qualifies, fail_reason = is_qualifying_parent_candidate(
            candidate=cand,
            child=child,
            events=events,
            missing_parent_id=target_parent,
        )
        cand_id = _event_id_safe(cand) or ""
        if cand_id == target_parent:
            id_match_indices.append(i)

        if qualifies:
            qualifying_indices.append(i)
        else:
            rejected_decoys.append(
                {
                    "id": _safe_id(cand_id),
                    "index": i,
                    "reason": fail_reason,
                }
            )

    if id_match_indices:
        child_branch = _event_branch_safe(child)
        branch_confined = any(
            _event_branch_safe(events[idx]) == child_branch for idx in id_match_indices
        )
        segment_confined = any(
            same_compaction_segment(events, events[idx], child) for idx in id_match_indices
        )
        confinement = {"branch": branch_confined, _CONF_SEG_KEY: segment_confined}
    else:
        confinement = {"branch": False, _CONF_SEG_KEY: False}

    if len(qualifying_indices) == 1:
        reason = "ok"
    elif len(qualifying_indices) > 1:
        reason = "ambiguous"
    else:
        if any(d["reason"] == "cross_branch" for d in rejected_decoys):
            reason = "cross_branch"
        elif any(d["reason"] == "cross_segment" for d in rejected_decoys):
            reason = "cross_segment"
        else:
            reason = "no_full_match"

    return qualifying_indices, rejected_decoys, confinement, reason


def cap_graph_findings(
    findings: list[Finding],
    *,
    code: str,
    max_findings: int = MAX_GRAPH_FINDINGS,
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


class _OccurrenceGraph:
    """Pre-indexed view of canonical events conforming to first-occurrence policy."""

    __slots__ = (
        "id_order",
        "id_set",
        "id_to_event",
        "id_to_index",
        "id_to_parent",
        "primary_source_path",
    )

    def __init__(self, events: Sequence[SessionEvent], default_path: str) -> None:
        self.id_to_event: dict[str, Any] = {}
        self.id_to_index: dict[str, int] = {}
        self.id_to_parent: dict[str, str | None] = {}
        self.id_order: list[str] = []
        self.primary_source_path = default_path.replace("\\", "/")

        for idx, event in enumerate(events):
            raw_id = getattr(event, "id", None)
            if raw_id is None and isinstance(event, Mapping):
                raw_id = event.get("id")
            if not isinstance(raw_id, str):
                continue
            if not raw_id.strip():
                continue
            id_str = raw_id

            # First-occurrence policy: skip duplicate IDs
            if id_str in self.id_to_event:
                continue

            self.id_to_event[id_str] = event
            self.id_to_index[id_str] = idx
            self.id_order.append(id_str)

            raw_parent = getattr(event, "parent_id", None)
            if raw_parent is None and isinstance(event, Mapping):
                raw_parent = event.get("parent_id")

            if raw_parent is None:
                self.id_to_parent[id_str] = None
            elif isinstance(raw_parent, str):
                # Empty string parent_id is preserved verbatim as missing parent
                self.id_to_parent[id_str] = raw_parent
            else:
                self.id_to_parent[id_str] = str(raw_parent)

        self.id_set: frozenset[str] = frozenset(self.id_to_event.keys())


def check_missing_parent(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    max_findings: int = MAX_GRAPH_FINDINGS,
) -> list[Finding]:
    """SL004: Detect events referencing a non-existent parent event.

    Guarantees:
    - Pure function: no I/O, does not mutate input events.
    - Evaluates first occurrence per ID; null/non-string IDs ignored.
    - Only `parent_id is None` is treated as a root; empty string parent is missing.
    - Forward references to IDs present later in the session do not fire.
    - Self-loops (parent_id == id) do not fire SL004 (deferred to SL005).
    - Sorts output by primary ID, capped at max_findings with overflow summary.
    """
    g = _OccurrenceGraph(events, source_path)
    findings: list[Finding] = []

    for id_str in g.id_order:
        parent_id = g.id_to_parent[id_str]
        if parent_id is not None and parent_id not in g.id_set:
            event = g.id_to_event[id_str]
            resolved_path, line_num = _resolve_source_coords(event, source_path)

            clean_rec_id = _safe_id(id_str)
            clean_parent_id = _safe_id(parent_id)

            related: list[str] = [clean_rec_id]
            if clean_parent_id.strip():
                related.append(clean_parent_id.strip())

            fp = compute_graph_fingerprint(SL004, [id_str, parent_id])
            source_ref = SourceRef(
                path=resolved_path,
                line=line_num,
                record_id=clean_rec_id,
            )

            target_idx = g.id_to_index[id_str]
            target_ev = events[target_idx]
            qualifying, rejected, conf, reason = find_qualifying_parent_candidates(
                events=events,
                child=target_ev,
                target_idx=target_idx,
                missing_parent_id=parent_id,
            )

            rep = Repairability.DETERMINISTIC if len(qualifying) == 1 else Repairability.MANUAL

            evidence: dict[str, Any] = {
                "id": clean_rec_id,
                "index": target_idx,
                "parent_id": clean_parent_id,
                "match_rule": "full-equality",
                "confinement": conf,
                "candidate_count": len(qualifying),
                "rejected_decoys": rejected,
                "reason": reason,
            }

            findings.append(
                make_finding(
                    code=SL004,
                    severity=Severity.ERROR,
                    repairability=rep,
                    message_template=_MSG_SL004,
                    source=source_ref,
                    related_ids=related,
                    fingerprint=fp,
                    evidence=evidence,
                )
            )

    return cap_graph_findings(
        findings,
        code=SL004,
        max_findings=max_findings,
        source_path=source_path,
    )


def check_cycles(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    max_findings: int = MAX_GRAPH_FINDINGS,
) -> list[Finding]:
    """SL005: Detect all elementary directed cycles in the child-to-parent graph.

    Guarantees:
    - Pure function: no I/O, does not mutate input events.
    - Iterative three-color DFS (WHITE=0, GRAY=1, BLACK=2) with explicit stacks (no recursion).
    - Detects 1-node self-loops (parent_id == id) and k-node cycles.
    - Deterministic cycle path: starts at lexicographically smallest ID in the cycle,
       follows parent links, and appends the start ID to close the loop.
    - Output sorted by primary ID (cycle_path[0]), capped at max_findings.
    """
    g = _OccurrenceGraph(events, source_path)
    color: dict[str, int] = {}
    cycles: list[list[str]] = []
    seen_cycles: set[frozenset[str]] = set()

    for start_node in sorted(g.id_set):
        if color.get(start_node) == 2:
            continue

        curr: str | None = start_node
        path: list[str] = []
        path_pos: dict[str, int] = {}

        while curr is not None:
            c = color.get(curr, 0)
            if c == 1:
                # Cycle detected on the active exploration path
                cycle_start_idx = path_pos[curr]
                raw_cycle = path[cycle_start_idx:]
                f_set = frozenset(raw_cycle)
                if f_set not in seen_cycles:
                    seen_cycles.add(f_set)
                    # Normalize: rotate so lexicographically smallest ID is first
                    min_id = min(raw_cycle)
                    min_idx = raw_cycle.index(min_id)
                    rotated = raw_cycle[min_idx:] + raw_cycle[:min_idx]
                    # Append start node to close the loop
                    cycle_path = rotated + [rotated[0]]
                    cycles.append(cycle_path)
                break
            if c == 2:
                # Reached a previously explored node without encountering a cycle
                break

            color[curr] = 1  # GRAY
            path_pos[curr] = len(path)
            path.append(curr)

            nxt = g.id_to_parent.get(curr)
            if nxt is not None and nxt in g.id_set:
                curr = nxt
            else:
                curr = None

        for node in path:
            color[node] = 2  # BLACK

    findings: list[Finding] = []
    for cycle_path in cycles:
        primary_id = cycle_path[0]
        event = g.id_to_event[primary_id]
        resolved_path, line_num = _resolve_source_coords(event, source_path)

        clean_rec_id = _safe_id(primary_id)
        safe_cycle_path = [_safe_id(node) for node in cycle_path]
        safe_cycle_nodes = sorted(
            set(_safe_id(node) for node in cycle_path if _safe_id(node).strip())
        )

        cycle_nodes_raw = sorted(set(cycle_path))
        fp = compute_graph_fingerprint(SL005, cycle_nodes_raw)
        source_ref = SourceRef(
            path=resolved_path,
            line=line_num,
            record_id=clean_rec_id,
        )

        evidence: dict[str, Any] = {
            "cycle_path": safe_cycle_path,
            "entry_index": g.id_to_index[primary_id],
        }

        findings.append(
            make_finding(
                code=SL005,
                severity=Severity.FATAL,
                repairability=Repairability.UNSUPPORTED,
                message_template=_MSG_SL005,
                source=source_ref,
                related_ids=safe_cycle_nodes,
                fingerprint=fp,
                evidence=evidence,
            )
        )

    return cap_graph_findings(
        findings,
        code=SL005,
        max_findings=max_findings,
        source_path=source_path,
    )


def check_components(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    max_findings: int = MAX_GRAPH_FINDINGS,
) -> list[Finding]:
    """SL006: Detect extra disconnected weakly-connected components over present parent edges.

    Guarantees:
    - Pure function: no I/O, does not mutate input events.
    - Disjoint Set Union (Union-Find) with path compression and union by rank;
      find is implemented iteratively to eliminate recursion depth limits.
    - Components evaluated over present edges only.
    - Each component's root is defined as the lexicographically smallest node
      with no present parent in the graph (or min node if pure cycle).
    - Components sorted by (-size, root_id); first is primary; remaining extra
      components emit one SL006 finding each.
    - Output sorted by primary ID, capped at max_findings with overflow summary.
    """
    g = _OccurrenceGraph(events, source_path)
    if not g.id_set:
        return []

    parent_uf: dict[str, str] = {i: i for i in g.id_set}
    rank_uf: dict[str, int] = {i: 0 for i in g.id_set}

    def find(i: str) -> str:
        root = i
        while parent_uf[root] != root:
            root = parent_uf[root]
        curr = i
        while curr != root:
            nxt = parent_uf[curr]
            parent_uf[curr] = root
            curr = nxt
        return root

    def union(i: str, j: str) -> None:
        root_i = find(i)
        root_j = find(j)
        if root_i == root_j:
            return
        if rank_uf[root_i] < rank_uf[root_j]:
            parent_uf[root_i] = root_j
        elif rank_uf[root_i] > rank_uf[root_j]:
            parent_uf[root_j] = root_i
        else:
            parent_uf[root_j] = root_i
            rank_uf[root_i] += 1

    # Connect present parent edges
    for u in g.id_set:
        p = g.id_to_parent.get(u)
        if p is not None and p in g.id_set:
            union(u, p)

    # Group components by representative
    components_by_rep: dict[str, list[str]] = defaultdict(list)
    for u in sorted(g.id_set):
        components_by_rep[find(u)].append(u)

    # Identify root for each component and build sort tuples
    component_records: list[tuple[int, str, list[str]]] = []
    for members in components_by_rep.values():
        candidate_roots = [
            u
            for u in members
            if (g.id_to_parent.get(u) is None or g.id_to_parent.get(u) not in g.id_set)
        ]
        if candidate_roots:
            root_id = min(candidate_roots)
        else:
            root_id = min(members)
        size = len(members)
        component_records.append((size, root_id, members))

    # Sort components by (-size, root_id): largest wins; tie goes to smallest root ID
    component_records.sort(key=lambda rec: (-rec[0], rec[1]))

    # Primary component is index 0; remaining are disconnected branches
    extra_components = component_records[1:]
    findings: list[Finding] = []

    for size, root_id, members in extra_components:
        event = g.id_to_event[root_id]
        resolved_path, line_num = _resolve_source_coords(event, source_path)

        clean_rec_id = _safe_id(root_id)
        sorted_members = sorted(members)
        member_sample = sorted_members[:MAX_MEMBER_SAMPLE_SIZE]
        safe_member_sample = [_safe_id(node) for node in member_sample]
        safe_related_ids = sorted(
            set(_safe_id(node) for node in sorted_members if _safe_id(node).strip())
        )

        fp = compute_graph_fingerprint(SL006, sorted_members)

        source_ref = SourceRef(
            path=resolved_path,
            line=line_num,
            record_id=clean_rec_id,
        )

        evidence: dict[str, Any] = {
            "member_sample": safe_member_sample,
            "root_id": clean_rec_id,
            "size": size,
        }

        findings.append(
            make_finding(
                code=SL006,
                severity=Severity.WARNING,
                repairability=Repairability.MANUAL,
                message_template=_MSG_SL006,
                source=source_ref,
                related_ids=safe_related_ids,
                fingerprint=fp,
                evidence=evidence,
            )
        )

    return cap_graph_findings(
        findings,
        code=SL006,
        max_findings=max_findings,
        source_path=source_path,
    )


def check_heads(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    max_findings: int = MAX_GRAPH_FINDINGS,
) -> list[Finding]:
    """SL007: Detect ambiguous session heads (multiple terminal leaf tips).

    Guarantees:
    - Pure function: no I/O, does not mutate input events.
    - Heads are nodes in the ID set never referenced as a parent_id by any present event.
    - Clean if 0 or 1 heads (empty input and all-cycle graphs produce 0 heads and 0 findings).
    - Emits exactly one SL007 finding when count > 1 with sorted head IDs in evidence.
    - Primary ID is the lexicographically smallest head ID.
    """
    g = _OccurrenceGraph(events, source_path)
    if not g.id_set:
        return []

    referenced_as_parent: set[str] = set()
    for u in g.id_set:
        p = g.id_to_parent.get(u)
        if p is not None and p in g.id_set:
            referenced_as_parent.add(p)

    heads = sorted([u for u in g.id_set if u not in referenced_as_parent])

    # 0 heads (empty / all-cycle) or 1 head is clean
    if len(heads) <= 1:
        return []

    primary_id = heads[0]
    event = g.id_to_event[primary_id]
    resolved_path, line_num = _resolve_source_coords(event, source_path)

    clean_rec_id = _safe_id(primary_id)
    safe_heads = [_safe_id(h) for h in heads]
    safe_related_ids = sorted(set(_safe_id(h) for h in heads if _safe_id(h).strip()))

    fp = compute_graph_fingerprint(SL007, heads)
    source_ref = SourceRef(
        path=resolved_path,
        line=line_num,
        record_id=clean_rec_id,
    )

    evidence: dict[str, Any] = {
        "count": len(heads),
        "heads": safe_heads,
    }

    finding = make_finding(
        code=SL007,
        severity=Severity.WARNING,
        repairability=Repairability.MANUAL,
        message_template=_MSG_SL007,
        source=source_ref,
        related_ids=safe_related_ids,
        fingerprint=fp,
        evidence=evidence,
    )

    return cap_graph_findings(
        [finding],
        code=SL007,
        max_findings=max_findings,
        source_path=source_path,
    )


def check_graph(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    max_findings_per_family: int = MAX_GRAPH_FINDINGS,
) -> list[Finding]:
    """Execute all four generic parent-graph checks (SL004, SL005, SL006, SL007).

    Guarantees:
    - Pure function: no I/O, does not mutate input events.
    - Dispatches SL004, SL005, SL006, and SL007 checks.
    - Each detector family is capped at max_findings_per_family + overflow summary.
    - Total output is deterministically sorted by (code, primary_id, fingerprint).
    """
    sl004_findings = check_missing_parent(
        events,
        source_path=source_path,
        max_findings=max_findings_per_family,
    )
    sl005_findings = check_cycles(
        events,
        source_path=source_path,
        max_findings=max_findings_per_family,
    )
    sl006_findings = check_components(
        events,
        source_path=source_path,
        max_findings=max_findings_per_family,
    )
    sl007_findings = check_heads(
        events,
        source_path=source_path,
        max_findings=max_findings_per_family,
    )

    all_findings = sl004_findings + sl005_findings + sl006_findings + sl007_findings
    return sorted(all_findings, key=_cap_finding_sort_key)


__all__ = [
    "MAX_GRAPH_FINDINGS",
    "MAX_MEMBER_SAMPLE_SIZE",
    "cap_graph_findings",
    "check_components",
    "check_cycles",
    "check_graph",
    "check_heads",
    "check_missing_parent",
    "compute_graph_fingerprint",
    "find_qualifying_parent_candidates",
    "is_qualifying_parent_candidate",
    "same_compaction_segment",
]
