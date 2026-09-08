"""Checkpoint and continuation integrity checks (SL201, SL202, SL203).

This module implements three vendor-neutral safeguard rules over canonical events:
- SL201 (Checkpoint gap): Missing preceding checkpoint upon session resumption or
  a sequence jump > 1 between consecutive checkpoints.
  Severity: error, Repairability: manual.
  Rationale: A resumed session without an establishing checkpoint lacks proof of identity.
- SL202 (Checkpoint divergence): Checkpoints sharing the same sequence number with
  divergent state hashes, or state hash mismatch.
  Severity: error, Repairability: manual.
  Rationale: Competing state hashes for the same logical step indicate split-brain branches.
- SL203 (Unsafe continuation): Tool events executing after an SL201/SL202 trigger or after
  an uncheckpointed compaction boundary.
  Severity: error, Repairability: manual.
  Rationale: Continuing to invoke tools across lost or corrupted state compounds damage;
  SL203 acts as a mandatory hard refusal gate against automated repair.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Final

from sesslint.canonical import SessionEvent
from sesslint.codes import (
    SL201,
    SL202,
    SL203,
    Repairability,
    Severity,
)
from sesslint.finding import (
    Finding,
    SourceRef,
    enforce_content_free_text,
    make_finding,
)

MAX_CHECKPOINT_FINDINGS: Final[int] = 500

_KIND_CHECKPOINT: Final[str] = "checkpoint"
_KIND_RUN_START: Final[frozenset[str]] = frozenset({"run_start", "run-start", "continuation"})
_KIND_COMPACTION: Final[str] = "compaction_boundary"
_TOOL_KINDS: Final[frozenset[str]] = frozenset({"tool_call", "tool_use", "tool_result"})

_MSG_SL201: Final[str] = "Checkpoint gap detected for record {record_id}"
_MSG_SL202: Final[str] = "Checkpoint divergence detected for record {record_id}"
_MSG_SL203: Final[str] = "Unsafe continuation across loss detected for record {record_id}"
_MSG_OVERFLOW: Final[str] = "Checkpoint check finding cap reached; remaining records truncated"


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


def compute_checkpoint_fingerprint(code: str, items: Iterable[str]) -> str:
    """Compute deterministic 16-character sha256 fingerprint for a checkpoint finding."""
    sorted_items = sorted(set(str(x) for x in items))
    content = f"{code}|{','.join(sorted_items)}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def _cap_finding_sort_key(f: Finding) -> tuple[str, int, str, str]:
    """Sort key for findings: (code, is_overflow, primary_id, fingerprint)."""
    is_overflow = 1 if (f.evidence and f.evidence.get("overflow") is True) else 0
    primary = f.source.record_id or ""
    return (f.code, is_overflow, primary, f.fingerprint)


def cap_checkpoint_findings(
    findings: list[Finding],
    *,
    code: str,
    max_findings: int = MAX_CHECKPOINT_FINDINGS,
    source_path: str = "<canonical>",
) -> list[Finding]:
    """Sort findings and cap family at max_findings with overflow finding."""
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


def _get_event_kind(event: Any) -> str | None:
    """Extract event kind string safely from SessionEvent or mapping."""
    raw_kind = getattr(event, "kind", None)
    if raw_kind is None and isinstance(event, Mapping):
        raw_kind = event.get("kind")
    return str(raw_kind) if raw_kind is not None else None


def _extract_checkpoint_fields(event: Any) -> tuple[str | None, int | None, str | None]:
    """Extract (checkpoint_id, seq, state_hash) from a checkpoint event."""
    chk_id: Any = None
    seq: Any = None
    state_hash: Any = None

    payload = getattr(event, "payload", None)
    if payload is None and isinstance(event, Mapping):
        payload = event.get("payload")

    if isinstance(payload, Mapping):
        chk_id = payload.get("checkpoint_id")
        if chk_id is None:
            chk_id = payload.get("id")
        if "seq" in payload:
            seq = payload["seq"]
        elif "checkpoint_seq" in payload:
            seq = payload["checkpoint_seq"]
        state_hash = payload.get("state_hash")
        if state_hash is None:
            state_hash = payload.get("hash")

    if chk_id is None:
        chk_id = getattr(event, "checkpoint_id", None)
        if chk_id is None and isinstance(event, Mapping):
            chk_id = event.get("checkpoint_id")

    if seq is None:
        seq = getattr(event, "seq", None)
        if seq is None and isinstance(event, Mapping):
            seq = event.get("seq")

    if state_hash is None:
        state_hash = getattr(event, "state_hash", None)
        if state_hash is None and isinstance(event, Mapping):
            state_hash = event.get("state_hash")

    chk_id_str = str(chk_id) if chk_id is not None and str(chk_id).strip() else None
    seq_val: int | None = int(seq) if isinstance(seq, int) and not isinstance(seq, bool) else None
    hash_str = str(state_hash) if state_hash is not None and str(state_hash).strip() else None
    return chk_id_str, seq_val, hash_str


def check_checkpoint_gap(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    max_findings: int = MAX_CHECKPOINT_FINDINGS,
    checkpoint_sensitivity: str = "default",
) -> list[Finding]:
    """Check for checkpoint gaps (SL201).

    Guarantees:
    - Fires when run_start/continuation appears with no preceding checkpoint.
    - Fires when consecutive checkpoints have a seq jump > 1.
    - Fires when a checkpoint has missing or empty state_hash.
    - sensitivity flag ('default' or 'high') preserved with pinned parity.
    - severity: error, repairability: manual.
    """
    findings: list[Finding] = []
    last_checkpoint_seq: int | None = None
    has_seen_checkpoint = False

    for idx, ev in enumerate(events):
        raw_kind = getattr(ev, "kind", None)
        if raw_kind is None and isinstance(ev, Mapping):
            raw_kind = ev.get("kind")
        kind_str = str(raw_kind) if raw_kind is not None else "unknown"

        raw_id = getattr(ev, "id", None)
        if raw_id is None and isinstance(ev, Mapping):
            raw_id = ev.get("id")
        ev_id = str(raw_id) if raw_id is not None else f"<event:{idx}>"
        rec_id = _source_record_id(ev_id)
        path, line = _resolve_source_coords(ev, source_path)

        # 1. Resumption without preceding checkpoint
        if kind_str in _KIND_RUN_START:
            if not has_seen_checkpoint:
                fp = compute_checkpoint_fingerprint(SL201, [str(idx), "0", "None"])
                findings.append(
                    make_finding(
                        code=SL201,
                        severity=Severity.ERROR,
                        repairability=Repairability.MANUAL,
                        message_template=_MSG_SL201,
                        source=SourceRef(path=path, line=line, record_id=rec_id),
                        fingerprint=fp,
                        evidence={
                            "at_index": idx,
                            "expected_seq": 0,
                            "found_seq": None,
                        },
                    )
                )

        # 2. Checkpoint sequence and hash checks
        elif kind_str == _KIND_CHECKPOINT:
            chk_id, seq, state_hash = _extract_checkpoint_fields(ev)
            has_seen_checkpoint = True

            # Missing or empty state_hash is gap evidence
            if not state_hash:
                fp = compute_checkpoint_fingerprint(
                    SL201, [str(idx), str(seq or 0), "missing_hash"]
                )
                findings.append(
                    make_finding(
                        code=SL201,
                        severity=Severity.ERROR,
                        repairability=Repairability.MANUAL,
                        message_template=_MSG_SL201,
                        source=SourceRef(path=path, line=line, record_id=rec_id),
                        fingerprint=fp,
                        evidence={
                            "at_index": idx,
                            "expected_seq": (
                                last_checkpoint_seq + 1 if last_checkpoint_seq is not None else 0
                            ),
                            "found_seq": seq,
                        },
                    )
                )

            # Sequence jump check
            if seq is not None:
                if last_checkpoint_seq is not None and (seq - last_checkpoint_seq) > 1:
                    expected_seq = last_checkpoint_seq + 1
                    fp = compute_checkpoint_fingerprint(
                        SL201, [str(idx), str(expected_seq), str(seq)]
                    )
                    findings.append(
                        make_finding(
                            code=SL201,
                            severity=Severity.ERROR,
                            repairability=Repairability.MANUAL,
                            message_template=_MSG_SL201,
                            source=SourceRef(path=path, line=line, record_id=rec_id),
                            fingerprint=fp,
                            evidence={
                                "at_index": idx,
                                "expected_seq": expected_seq,
                                "found_seq": seq,
                            },
                        )
                    )
                last_checkpoint_seq = seq
            elif checkpoint_sensitivity == "high":
                expected_seq = 0 if last_checkpoint_seq is None else last_checkpoint_seq + 1
                fp = compute_checkpoint_fingerprint(
                    SL201, [str(idx), str(expected_seq), "missing_seq"]
                )
                findings.append(
                    make_finding(
                        code=SL201,
                        severity=Severity.ERROR,
                        repairability=Repairability.MANUAL,
                        message_template=_MSG_SL201,
                        source=SourceRef(path=path, line=line, record_id=rec_id),
                        fingerprint=fp,
                        evidence={
                            "at_index": idx,
                            "expected_seq": expected_seq,
                            "found_seq": None,
                            "sensitivity": "high",
                        },
                    )
                )

    return cap_checkpoint_findings(
        findings,
        code=SL201,
        max_findings=max_findings,
        source_path=source_path,
    )


def check_checkpoint_divergence(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    max_findings: int = MAX_CHECKPOINT_FINDINGS,
) -> list[Finding]:
    """Check for checkpoint divergence (SL202).

    Guarantees:
    - Fires when two checkpoints with identical seq have differing state_hash.
    - Idempotent re-emission (identical seq and hash) does not fire.
    - Truncates reported hashes to 16 characters in evidence.
    - severity: error, repairability: manual.
    """
    findings: list[Finding] = []
    seen_seq_to_hash: dict[int, str] = {}

    for idx, ev in enumerate(events):
        raw_kind = getattr(ev, "kind", None)
        if raw_kind is None and isinstance(ev, Mapping):
            raw_kind = ev.get("kind")
        if raw_kind != _KIND_CHECKPOINT:
            continue

        _chk_id, seq, state_hash = _extract_checkpoint_fields(ev)
        if seq is None or state_hash is None:
            continue

        raw_id = getattr(ev, "id", None)
        if raw_id is None and isinstance(ev, Mapping):
            raw_id = ev.get("id")
        ev_id = str(raw_id) if raw_id is not None else f"<event:{idx}>"
        rec_id = _source_record_id(ev_id)
        path, line = _resolve_source_coords(ev, source_path)

        if seq in seen_seq_to_hash:
            prev_hash = seen_seq_to_hash[seq]
            if prev_hash != state_hash:
                hash_a = prev_hash[:16]
                hash_b = state_hash[:16]
                fp = compute_checkpoint_fingerprint(SL202, [str(seq), hash_a, hash_b])

                findings.append(
                    make_finding(
                        code=SL202,
                        severity=Severity.ERROR,
                        repairability=Repairability.MANUAL,
                        message_template=_MSG_SL202,
                        source=SourceRef(path=path, line=line, record_id=rec_id),
                        fingerprint=fp,
                        evidence={
                            "hash_a": hash_a,
                            "hash_b": hash_b,
                            "seq": seq,
                        },
                    )
                )
        else:
            seen_seq_to_hash[seq] = state_hash

    return cap_checkpoint_findings(
        findings,
        code=SL202,
        max_findings=max_findings,
        source_path=source_path,
    )


def check_unsafe_continuation(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    prior_sl201_findings: Sequence[Finding] | None = None,
    prior_sl202_findings: Sequence[Finding] | None = None,
) -> list[Finding]:
    """Check for unsafe continuation across loss (SL203).

    Guarantees:
    - Exactly one SL203 finding per session (cap 1).
    - Trigger index: earliest index of SL201, SL202, or compaction_boundary without checkpoint.
    - Fires only if at least one tool event occurs strictly after the trigger index.
    - severity: error, repairability: manual.
    - evidence: {caused_by: [sorted triggers], first_unsafe_index}.
    """
    # Compute SL201 and SL202 if not provided
    f201 = (
        prior_sl201_findings
        if prior_sl201_findings is not None
        else check_checkpoint_gap(events, source_path=source_path)
    )
    f202 = (
        prior_sl202_findings
        if prior_sl202_findings is not None
        else check_checkpoint_divergence(events, source_path=source_path)
    )

    triggers: list[tuple[int, str]] = []

    for f in f201:
        if f.evidence and isinstance(f.evidence.get("at_index"), int):
            triggers.append((f.evidence["at_index"], "SL201"))

    for f in f202:
        # Resolve index of divergent checkpoint
        seq = f.evidence.get("seq") if f.evidence else None
        if seq is not None:
            for idx, ev in enumerate(events):
                if getattr(ev, "kind", None) == _KIND_CHECKPOINT or (
                    isinstance(ev, Mapping) and ev.get("kind") == _KIND_CHECKPOINT
                ):
                    _, ev_seq, _ = _extract_checkpoint_fields(ev)
                    if ev_seq == seq:
                        triggers.append((idx, "SL202"))

    # Compaction boundary with no intervening checkpoint before tool event
    checkpoint_indices = [
        c_idx for c_idx, c_ev in enumerate(events) if _get_event_kind(c_ev) == _KIND_CHECKPOINT
    ]

    for idx, ev in enumerate(events):
        raw_kind = _get_event_kind(ev)
        if raw_kind == _KIND_COMPACTION:
            has_subsequent_checkpoint = any(chk > idx for chk in checkpoint_indices)
            if not has_subsequent_checkpoint:
                triggers.append((idx, "compaction"))
            else:
                next_chk = min(chk for chk in checkpoint_indices if chk > idx)
                has_tool_before_chk = any(
                    _get_event_kind(events[t_idx]) in _TOOL_KINDS
                    for t_idx in range(idx + 1, next_chk)
                )
                if has_tool_before_chk:
                    triggers.append((idx, "compaction"))

    if not triggers:
        return []

    min_trigger_idx = min(idx for idx, _ in triggers)

    # Find earliest tool event strictly after min_trigger_idx
    first_unsafe_tool: tuple[int, Any] | None = None
    for idx in range(min_trigger_idx + 1, len(events)):
        ev = events[idx]
        raw_kind = getattr(ev, "kind", None)
        if raw_kind is None and isinstance(ev, Mapping):
            raw_kind = ev.get("kind")
        if raw_kind in _TOOL_KINDS:
            first_unsafe_tool = (idx, ev)
            break

    if first_unsafe_tool is None:
        return []

    unsafe_idx, unsafe_ev = first_unsafe_tool

    # Filter causes that occurred at or before the unsafe tool index
    active_causes = sorted(set(cause for idx, cause in triggers if idx < unsafe_idx))

    raw_id = getattr(unsafe_ev, "id", None)
    if raw_id is None and isinstance(unsafe_ev, Mapping):
        raw_id = unsafe_ev.get("id")
    ev_id = str(raw_id) if raw_id is not None else f"<event:{unsafe_idx}>"
    rec_id = _source_record_id(ev_id)
    path, line = _resolve_source_coords(unsafe_ev, source_path)

    fp = compute_checkpoint_fingerprint(SL203, [str(unsafe_idx)] + active_causes)

    finding = make_finding(
        code=SL203,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template=_MSG_SL203,
        source=SourceRef(path=path, line=line, record_id=rec_id),
        fingerprint=fp,
        evidence={
            "caused_by": active_causes,
            "first_unsafe_index": unsafe_idx,
        },
    )

    return [finding]


def check_checkpoint(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    max_findings_per_family: int = MAX_CHECKPOINT_FINDINGS,
    checkpoint_sensitivity: str = "default",
) -> list[Finding]:
    """Run all checkpoint checks (SL201, SL202, SL203) over canonical events."""
    all_findings: list[Finding] = []

    f201 = check_checkpoint_gap(
        events,
        source_path=source_path,
        max_findings=max_findings_per_family,
        checkpoint_sensitivity=checkpoint_sensitivity,
    )
    all_findings.extend(f201)

    f202 = check_checkpoint_divergence(
        events,
        source_path=source_path,
        max_findings=max_findings_per_family,
    )
    all_findings.extend(f202)

    f203 = check_unsafe_continuation(
        events,
        source_path=source_path,
        prior_sl201_findings=f201,
        prior_sl202_findings=f202,
    )
    all_findings.extend(f203)

    return sorted(all_findings, key=_cap_finding_sort_key)


# Aliases for specification and test compatibility
check_sl201 = check_checkpoint_gap
check_sl202 = check_checkpoint_divergence
check_sl203 = check_unsafe_continuation

__all__ = [
    "MAX_CHECKPOINT_FINDINGS",
    "cap_checkpoint_findings",
    "check_checkpoint",
    "check_checkpoint_divergence",
    "check_checkpoint_gap",
    "check_sl201",
    "check_sl202",
    "check_sl203",
    "check_unsafe_continuation",
    "compute_checkpoint_fingerprint",
]
