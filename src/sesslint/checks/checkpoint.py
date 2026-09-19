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

Boundary Note (FR-044, DEV-011):
- SL201 and SL202 verdicts are strictly events-only (evaluating checkpoint records and
  continuation boundaries present in the canonical event stream).
- When runtime state or checkpoints are supplied by the adapter (e.g. provider run-state metadata),
  a content-free structural projection is preserved and attached to SL201/SL202 evidence
  under `run_state`.
- Full runtime ownership verdicts (validating continuation steps and terminal outputs
  against provider runtime state) require upstream provider semantics and are deferred
  to OPP-019 research.
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
    SL205,
    Repairability,
    Severity,
)
from sesslint.context import CheckContext
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
_MSG_SL205: Final[str] = "Compaction coverage gap detected for record {record_id}"
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
    context: CheckContext | None = None,
) -> list[Finding]:
    """Sort findings and cap family at max_findings with overflow finding."""
    sorted_findings = sorted(findings, key=_cap_finding_sort_key)

    if len(sorted_findings) <= max_findings:
        return sorted_findings

    kept = sorted_findings[:max_findings]
    total_count = len(sorted_findings)
    truncated_count = total_count - max_findings

    ctx = context if context is not None else CheckContext()
    norm_source_path = source_path.replace("\\", "/")

    overflow_finding = make_finding(
        code=code,
        severity=Severity.WARNING,
        repairability=Repairability.MANUAL,
        message_template=_MSG_OVERFLOW,
        source=SourceRef(path=norm_source_path, line=None, record_id=None),
        evidence={
            "cap": max_findings,
            "overflow": True,
            "total_count": total_count,
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


def _extract_run_state_projection(
    *,
    context: CheckContext | None = None,
    events: Sequence[SessionEvent] | None = None,
    run_state_projection: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Resolve content-free run_state projection from explicit param, context, or events."""
    if run_state_projection is not None:
        return dict(run_state_projection)

    candidates: list[Mapping[str, Any]] = []
    if context is not None and isinstance(context.source_metadata, Mapping):
        candidates.append(context.source_metadata)
    if events is not None:
        raw_source = getattr(events, "source", None)
        if isinstance(raw_source, Mapping) and raw_source not in candidates:
            candidates.append(raw_source)

    for source_meta in candidates:
        cached_proj = source_meta.get("run_state_projection")
        if isinstance(cached_proj, Mapping):
            if cached_proj.get("keys") or cached_proj.get("checkpoints"):
                return dict(cached_proj)

        if "keys" in source_meta and "shapes" in source_meta:
            if source_meta.get("keys") or source_meta.get("checkpoints"):
                return dict(source_meta)

    return None


def _extract_run_state_checkpoints(
    *,
    context: CheckContext | None = None,
    events: Sequence[SessionEvent] | None = None,
    run_state_projection: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Resolve and normalize list of checkpoints from run_state / source metadata / projection."""
    raw_list: Sequence[Any] | None = None
    candidates: list[Mapping[str, Any]] = []
    if context is not None and isinstance(context.source_metadata, Mapping):
        candidates.append(context.source_metadata)
    if events is not None:
        raw_source = getattr(events, "source", None)
        if isinstance(raw_source, Mapping) and raw_source not in candidates:
            candidates.append(raw_source)

    for source_meta in candidates:
        # 1. Direct "checkpoints" in source_meta
        chks = source_meta.get("checkpoints")
        if isinstance(chks, Sequence) and not isinstance(chks, (str, bytes)):
            raw_list = chks
            break
        # 2. "run_state" in source_meta
        rs = source_meta.get("run_state")
        if isinstance(rs, Mapping):
            chks = rs.get("checkpoints")
            if isinstance(chks, Sequence) and not isinstance(chks, (str, bytes)):
                raw_list = chks
                break
        # 3. "metadata" inside source_meta
        meta = source_meta.get("metadata")
        if isinstance(meta, Mapping):
            chks = meta.get("checkpoints")
            if isinstance(chks, Sequence) and not isinstance(chks, (str, bytes)):
                raw_list = chks
                break
            rs_m = meta.get("run_state")
            if isinstance(rs_m, Mapping):
                chks = rs_m.get("checkpoints")
                if isinstance(chks, Sequence) and not isinstance(chks, (str, bytes)):
                    raw_list = chks
                    break

    # Fallback to projection if no unredacted checkpoints available
    if raw_list is None and run_state_projection is not None:
        chks = run_state_projection.get("checkpoints")
        if isinstance(chks, Sequence) and not isinstance(chks, (str, bytes)):
            raw_list = chks

    if raw_list is None:
        for source_meta in candidates:
            rsp = source_meta.get("run_state_projection")
            if isinstance(rsp, Mapping):
                chks = rsp.get("checkpoints")
                if isinstance(chks, Sequence) and not isinstance(chks, (str, bytes)):
                    raw_list = chks
                    break

    if not raw_list:
        return []

    normalized: list[dict[str, Any]] = []
    for idx, item in enumerate(raw_list):
        chk_id: Any = None
        seq: Any = None
        state_hash: Any = None

        if isinstance(item, Mapping):
            raw_id = item.get("id") if item.get("id") is not None else item.get("checkpoint_id")
            chk_id = raw_id
            if "seq" in item:
                seq = item["seq"]
            elif "checkpoint_seq" in item:
                seq = item["checkpoint_seq"]
            state_hash = (
                item.get("hash")
                if item.get("hash") is not None
                else (
                    item.get("state_hash")
                    if item.get("state_hash") is not None
                    else item.get("payload_hash")
                )
            )
        elif item is not None and not isinstance(item, (str, bytes, int, float, bool)):
            raw_id = (
                getattr(item, "id", None)
                if getattr(item, "id", None) is not None
                else getattr(item, "checkpoint_id", None)
            )
            chk_id = raw_id
            seq = (
                getattr(item, "seq", None)
                if getattr(item, "seq", None) is not None
                else getattr(item, "checkpoint_seq", None)
            )
            state_hash = (
                getattr(item, "hash", None)
                if getattr(item, "hash", None) is not None
                else (
                    getattr(item, "state_hash", None)
                    if getattr(item, "state_hash", None) is not None
                    else getattr(item, "payload_hash", None)
                )
            )

        chk_id_str = (
            str(chk_id) if chk_id is not None and str(chk_id).strip() else f"chk-runstate-{idx}"
        )
        seq_val: int | None = None
        if isinstance(seq, int) and not isinstance(seq, bool):
            seq_val = seq
        elif isinstance(seq, str) and seq.strip().isdigit():
            try:
                seq_val = int(seq.strip())
            except ValueError:
                seq_val = None

        hash_str: str | None = (
            str(state_hash).strip() if state_hash is not None and str(state_hash).strip() else None
        )
        if hash_str in ("<NoneType>", "<null>", "None", "", "null"):
            hash_str = None

        normalized.append(
            {
                "hash": hash_str,
                "id": chk_id_str,
                "index": idx,
                "seq": seq_val,
            }
        )

    return normalized


def check_checkpoint_gap(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    max_findings: int = MAX_CHECKPOINT_FINDINGS,
    checkpoint_sensitivity: str = "default",
    context: CheckContext | None = None,
    run_state_projection: Mapping[str, Any] | None = None,
) -> list[Finding]:
    """Check for checkpoint gaps (SL201).

    Guarantees:
    - Fires when run_start/continuation appears with no preceding checkpoint.
    - Fires when consecutive checkpoints have a seq jump > 1.
    - Fires when a checkpoint has missing or empty state_hash.
    - Validates run-state checkpoints from source metadata / projection (FR-044).
    - sensitivity flag ('default' or 'high') preserved with pinned parity.
    - severity: error, repairability: manual.
    - Preserves and attaches content-free run_state projection when present (DEV-011).
    """
    ctx = context if context is not None else CheckContext()
    proj = _extract_run_state_projection(
        context=ctx,
        events=events,
        run_state_projection=run_state_projection,
    )
    rs_checkpoints = _extract_run_state_checkpoints(
        context=ctx,
        events=events,
        run_state_projection=run_state_projection,
    )
    findings: list[Finding] = []
    last_checkpoint_seq: int | None = None
    has_seen_checkpoint = bool(rs_checkpoints)

    # Collect all sequence numbers present in event-level checkpoints
    event_checkpoint_seqs: set[int] = set()
    for ev in events:
        raw_kind = getattr(ev, "kind", None)
        if raw_kind is None and isinstance(ev, Mapping):
            raw_kind = ev.get("kind")
        if raw_kind == _KIND_CHECKPOINT:
            _, ev_seq, _ = _extract_checkpoint_fields(ev)
            if ev_seq is not None:
                event_checkpoint_seqs.add(ev_seq)

    min_event_seq = min(event_checkpoint_seqs) if event_checkpoint_seqs else None

    # 1. Validate run-state checkpoints (FR-044)
    sorted_rs_checkpoints = sorted(
        rs_checkpoints,
        key=lambda c: (
            c["seq"] is None,
            c["seq"] if c["seq"] is not None else 0,
            c["index"],
        ),
    )
    last_rs_seq: int | None = None
    for rs_chk in sorted_rs_checkpoints:
        chk_id = rs_chk["id"]
        rec_id = _source_record_id(chk_id)
        seq = rs_chk["seq"]
        state_hash = rs_chk["hash"]
        idx = rs_chk["index"]

        is_covered_by_event = seq is not None and seq in event_checkpoint_seqs

        # Missing or empty state_hash in run-state checkpoint
        if not state_hash and not is_covered_by_event:
            evidence_nohash: dict[str, Any] = {
                "at_index": idx,
                "expected_seq": (last_rs_seq + 1 if last_rs_seq is not None else 0),
                "found_seq": seq,
                "source": "run_state",
            }
            if proj is not None:
                evidence_nohash["run_state"] = proj
            findings.append(
                make_finding(
                    code=SL201,
                    severity=Severity.ERROR,
                    repairability=Repairability.MANUAL,
                    message_template=_MSG_SL201,
                    source=SourceRef(path=source_path, line=1, record_id=rec_id),
                    evidence=evidence_nohash,
                    adapter_id=ctx.adapter_id,
                    adapter_version=ctx.adapter_version,
                    profile_id=ctx.profile_id,
                    profile_version=ctx.profile_version,
                )
            )

        # Sequence jump check within run-state
        if seq is not None:
            if not is_covered_by_event and last_rs_seq is not None and (seq - last_rs_seq) > 1:
                expected_seq = last_rs_seq + 1
                evidence_jump: dict[str, Any] = {
                    "at_index": idx,
                    "expected_seq": expected_seq,
                    "found_seq": seq,
                    "source": "run_state",
                }
                if proj is not None:
                    evidence_jump["run_state"] = proj
                findings.append(
                    make_finding(
                        code=SL201,
                        severity=Severity.ERROR,
                        repairability=Repairability.MANUAL,
                        message_template=_MSG_SL201,
                        source=SourceRef(path=source_path, line=1, record_id=rec_id),
                        evidence=evidence_jump,
                        adapter_id=ctx.adapter_id,
                        adapter_version=ctx.adapter_version,
                        profile_id=ctx.profile_id,
                        profile_version=ctx.profile_version,
                    )
                )
            last_rs_seq = seq
        elif checkpoint_sensitivity == "high":
            expected_seq = 0 if last_rs_seq is None else last_rs_seq + 1
            evidence_sens: dict[str, Any] = {
                "at_index": idx,
                "expected_seq": expected_seq,
                "found_seq": None,
                "sensitivity": "high",
                "source": "run_state",
            }
            if proj is not None:
                evidence_sens["run_state"] = proj
            findings.append(
                make_finding(
                    code=SL201,
                    severity=Severity.ERROR,
                    repairability=Repairability.MANUAL,
                    message_template=_MSG_SL201,
                    source=SourceRef(path=source_path, line=1, record_id=rec_id),
                    evidence=evidence_sens,
                    adapter_id=ctx.adapter_id,
                    adapter_version=ctx.adapter_version,
                    profile_id=ctx.profile_id,
                    profile_version=ctx.profile_version,
                )
            )

    if sorted_rs_checkpoints:
        if min_event_seq is not None:
            preceding = [
                c["seq"]
                for c in sorted_rs_checkpoints
                if c["seq"] is not None and c["seq"] < min_event_seq
            ]
            if preceding:
                last_checkpoint_seq = max(preceding)
        elif last_rs_seq is not None:
            last_checkpoint_seq = last_rs_seq

    # 2. Validate events stream
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

        # 2a. Resumption without preceding checkpoint
        if kind_str in _KIND_RUN_START:
            if not has_seen_checkpoint:
                evidence_gap: dict[str, Any] = {
                    "at_index": idx,
                    "expected_seq": 0,
                    "found_seq": None,
                }
                if proj is not None:
                    evidence_gap["run_state"] = proj
                findings.append(
                    make_finding(
                        code=SL201,
                        severity=Severity.ERROR,
                        repairability=Repairability.MANUAL,
                        message_template=_MSG_SL201,
                        source=SourceRef(path=path, line=line, record_id=rec_id),
                        evidence=evidence_gap,
                        adapter_id=ctx.adapter_id,
                        adapter_version=ctx.adapter_version,
                        profile_id=ctx.profile_id,
                        profile_version=ctx.profile_version,
                    )
                )

        # 2b. Checkpoint sequence and hash checks
        elif kind_str == _KIND_CHECKPOINT:
            chk_id, seq, state_hash = _extract_checkpoint_fields(ev)
            has_seen_checkpoint = True

            # Missing or empty state_hash is gap evidence
            if not state_hash:
                evidence_nohash_ev: dict[str, Any] = {
                    "at_index": idx,
                    "expected_seq": (
                        last_checkpoint_seq + 1 if last_checkpoint_seq is not None else 0
                    ),
                    "found_seq": seq,
                }
                if proj is not None:
                    evidence_nohash_ev["run_state"] = proj
                findings.append(
                    make_finding(
                        code=SL201,
                        severity=Severity.ERROR,
                        repairability=Repairability.MANUAL,
                        message_template=_MSG_SL201,
                        source=SourceRef(path=path, line=line, record_id=rec_id),
                        evidence=evidence_nohash_ev,
                        adapter_id=ctx.adapter_id,
                        adapter_version=ctx.adapter_version,
                        profile_id=ctx.profile_id,
                        profile_version=ctx.profile_version,
                    )
                )

            # Sequence jump check
            if seq is not None:
                if last_checkpoint_seq is not None and (seq - last_checkpoint_seq) > 1:
                    expected_seq = last_checkpoint_seq + 1
                    evidence_jump_ev: dict[str, Any] = {
                        "at_index": idx,
                        "expected_seq": expected_seq,
                        "found_seq": seq,
                    }
                    if proj is not None:
                        evidence_jump_ev["run_state"] = proj
                    findings.append(
                        make_finding(
                            code=SL201,
                            severity=Severity.ERROR,
                            repairability=Repairability.MANUAL,
                            message_template=_MSG_SL201,
                            source=SourceRef(path=path, line=line, record_id=rec_id),
                            evidence=evidence_jump_ev,
                            adapter_id=ctx.adapter_id,
                            adapter_version=ctx.adapter_version,
                            profile_id=ctx.profile_id,
                            profile_version=ctx.profile_version,
                        )
                    )
                last_checkpoint_seq = seq
            elif checkpoint_sensitivity == "high":
                expected_seq = 0 if last_checkpoint_seq is None else last_checkpoint_seq + 1
                evidence_sens_ev: dict[str, Any] = {
                    "at_index": idx,
                    "expected_seq": expected_seq,
                    "found_seq": None,
                    "sensitivity": "high",
                }
                if proj is not None:
                    evidence_sens_ev["run_state"] = proj
                findings.append(
                    make_finding(
                        code=SL201,
                        severity=Severity.ERROR,
                        repairability=Repairability.MANUAL,
                        message_template=_MSG_SL201,
                        source=SourceRef(path=path, line=line, record_id=rec_id),
                        evidence=evidence_sens_ev,
                        adapter_id=ctx.adapter_id,
                        adapter_version=ctx.adapter_version,
                        profile_id=ctx.profile_id,
                        profile_version=ctx.profile_version,
                    )
                )

    return cap_checkpoint_findings(
        findings,
        code=SL201,
        max_findings=max_findings,
        source_path=source_path,
        context=ctx,
    )


def check_checkpoint_divergence(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    max_findings: int = MAX_CHECKPOINT_FINDINGS,
    context: CheckContext | None = None,
    run_state_projection: Mapping[str, Any] | None = None,
) -> list[Finding]:
    """Check for checkpoint divergence (SL202).

    Guarantees:
    - Fires when two checkpoints with identical seq have differing state_hash.
    - Validates run-state checkpoints against each other and event checkpoints (FR-044).
    - Idempotent re-emission (identical seq and hash) does not fire.
    - Truncates reported hashes to 16 characters in evidence.
    - severity: error, repairability: manual.
    - Preserves and attaches content-free run_state projection when present (DEV-011).
    """
    ctx = context if context is not None else CheckContext()
    proj = _extract_run_state_projection(
        context=ctx,
        events=events,
        run_state_projection=run_state_projection,
    )
    rs_checkpoints = _extract_run_state_checkpoints(
        context=ctx,
        events=events,
        run_state_projection=run_state_projection,
    )
    findings: list[Finding] = []
    seen_seq_to_hash: dict[int, str] = {}

    # 1. Process run-state checkpoints (FR-044)
    sorted_rs_checkpoints = sorted(
        rs_checkpoints,
        key=lambda c: (
            c["seq"] is None,
            c["seq"] if c["seq"] is not None else 0,
            c["index"],
        ),
    )
    for rs_chk in sorted_rs_checkpoints:
        chk_id = rs_chk["id"]
        rec_id = _source_record_id(chk_id)
        seq = rs_chk["seq"]
        state_hash = rs_chk["hash"]

        if seq is None or state_hash is None:
            continue

        if seq in seen_seq_to_hash:
            prev_hash = seen_seq_to_hash[seq]
            if prev_hash != state_hash:
                hash_a = prev_hash[:16]
                hash_b = state_hash[:16]

                evidence_div_rs: dict[str, Any] = {
                    "hash_a": hash_a,
                    "hash_b": hash_b,
                    "seq": seq,
                    "source": "run_state",
                }
                if proj is not None:
                    evidence_div_rs["run_state"] = proj

                findings.append(
                    make_finding(
                        code=SL202,
                        severity=Severity.ERROR,
                        repairability=Repairability.MANUAL,
                        message_template=_MSG_SL202,
                        source=SourceRef(path=source_path, line=1, record_id=rec_id),
                        evidence=evidence_div_rs,
                        adapter_id=ctx.adapter_id,
                        adapter_version=ctx.adapter_version,
                        profile_id=ctx.profile_id,
                        profile_version=ctx.profile_version,
                    )
                )
        else:
            seen_seq_to_hash[seq] = state_hash

    # 2. Process event checkpoints
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

                evidence_div: dict[str, Any] = {
                    "hash_a": hash_a,
                    "hash_b": hash_b,
                    "seq": seq,
                }
                if proj is not None:
                    evidence_div["run_state"] = proj

                findings.append(
                    make_finding(
                        code=SL202,
                        severity=Severity.ERROR,
                        repairability=Repairability.MANUAL,
                        message_template=_MSG_SL202,
                        source=SourceRef(path=path, line=line, record_id=rec_id),
                        evidence=evidence_div,
                        adapter_id=ctx.adapter_id,
                        adapter_version=ctx.adapter_version,
                        profile_id=ctx.profile_id,
                        profile_version=ctx.profile_version,
                    )
                )
        else:
            seen_seq_to_hash[seq] = state_hash

    return cap_checkpoint_findings(
        findings,
        code=SL202,
        max_findings=max_findings,
        source_path=source_path,
        context=ctx,
    )


def check_unsafe_continuation(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    prior_sl201_findings: Sequence[Finding] | None = None,
    prior_sl202_findings: Sequence[Finding] | None = None,
    context: CheckContext | None = None,
) -> list[Finding]:
    """Check for unsafe continuation across loss (SL203).

    Guarantees:
    - Exactly one SL203 finding per session (cap 1).
    - Trigger index: earliest index of SL201, SL202, or compaction_boundary without checkpoint.
    - Fires only if at least one tool event occurs strictly after the trigger index.
    - severity: error, repairability: manual.
    - evidence: {caused_by: [sorted triggers], first_unsafe_index}.
    """
    ctx = context if context is not None else CheckContext()
    # Compute SL201 and SL202 if not provided
    f201 = (
        prior_sl201_findings
        if prior_sl201_findings is not None
        else check_checkpoint_gap(events, source_path=source_path, context=ctx)
    )
    f202 = (
        prior_sl202_findings
        if prior_sl202_findings is not None
        else check_checkpoint_divergence(events, source_path=source_path, context=ctx)
    )

    triggers: list[tuple[int, str]] = []

    for f in f201:
        if f.evidence:
            if f.evidence.get("source") == "run_state":
                triggers.append((-1, "SL201"))
            elif isinstance(f.evidence.get("at_index"), int):
                triggers.append((f.evidence["at_index"], "SL201"))

    for f in f202:
        if f.evidence and f.evidence.get("source") == "run_state":
            triggers.append((-1, "SL202"))
        else:
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

    finding = make_finding(
        code=SL203,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template=_MSG_SL203,
        source=SourceRef(path=path, line=line, record_id=rec_id),
        evidence={
            "caused_by": active_causes,
            "first_unsafe_index": unsafe_idx,
        },
        adapter_id=ctx.adapter_id,
        adapter_version=ctx.adapter_version,
        profile_id=ctx.profile_id,
        profile_version=ctx.profile_version,
    )

    return [finding]


def _coverage_pointer(event: Any) -> str | None:
    """Extract a normalized coverage pointer from ``extra_fields['coverage']``."""
    extra = getattr(event, "extra_fields", None)
    if extra is None and isinstance(event, Mapping):
        extra = event.get("extra_fields")
    if not isinstance(extra, Mapping):
        return None
    coverage = extra.get("coverage")
    if not isinstance(coverage, Mapping):
        return None
    ptr = coverage.get("covered_through_id")
    return str(ptr) if isinstance(ptr, str) and ptr.strip() else None


def check_compaction_coverage(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    max_findings: int = MAX_CHECKPOINT_FINDINGS,
    context: CheckContext | None = None,
) -> list[Finding]:
    """SL205: flag compaction boundaries whose coverage claim is unverifiable.

    For each ``compaction_boundary`` carrying a normalized coverage pointer
    (``extra_fields["coverage"]["covered_through_id"]``, populated by
    adapters from bounded vendor leaf-reference fields):

    - ``missing``: the referenced leaf id does not exist in the stream.
    - ``non_contiguous``: the leaf exists but does not precede the
      boundary, or its ancestor chain has an unresolvable/post-boundary
      link (the claimed covered span is not contiguous).

    Pointerless boundaries and ambiguous (duplicated) leaf ids are skipped
    silently — this rule never guesses coverage semantics.
    """
    ctx = context if context is not None else CheckContext()

    id_to_indices: dict[str, list[int]] = {}
    for idx, ev in enumerate(events):
        raw_id = getattr(ev, "id", None)
        if raw_id is None and isinstance(ev, Mapping):
            raw_id = ev.get("id")
        if raw_id is not None:
            id_to_indices.setdefault(str(raw_id), []).append(idx)

    findings: list[Finding] = []
    for b_idx, boundary in enumerate(events):
        if _get_event_kind(boundary) != _KIND_COMPACTION:
            continue
        covered_id = _coverage_pointer(boundary)
        if covered_id is None:
            continue  # pointerless boundary — nothing to verify

        missing = False
        non_contiguous = False

        leaf_indices = id_to_indices.get(covered_id)
        if leaf_indices is None:
            missing = True
        elif len(leaf_indices) != 1:
            continue  # duplicated leaf id — SL003 territory, fail silent
        else:
            leaf_idx = leaf_indices[0]
            if leaf_idx >= b_idx:
                non_contiguous = True  # claimed span is not strictly prior
            else:
                # Walk the leaf's ancestor chain: every link must resolve
                # to an event strictly before the boundary.
                visited: set[int] = {leaf_idx}
                cur = events[leaf_idx]
                while True:
                    raw_parent = getattr(cur, "parent_id", None)
                    if raw_parent is None and isinstance(cur, Mapping):
                        raw_parent = cur.get("parent_id")
                    if raw_parent is None:
                        break  # reached a root — chain is contiguous
                    parent_indices = id_to_indices.get(str(raw_parent))
                    if not parent_indices or len(parent_indices) != 1:
                        non_contiguous = True  # unresolvable or ambiguous link
                        break
                    p_idx = parent_indices[0]
                    if p_idx >= b_idx:
                        non_contiguous = True  # chain crosses the boundary
                        break
                    if p_idx in visited:
                        break  # cycle — SL005 territory, stop quietly
                    visited.add(p_idx)
                    cur = events[p_idx]

        if not (missing or non_contiguous):
            continue

        resolved_path, line_num = _resolve_source_coords(boundary, source_path)
        raw_bid = getattr(boundary, "id", None)
        if raw_bid is None and isinstance(boundary, Mapping):
            raw_bid = boundary.get("id")
        clean_boundary_id = _safe_id(str(raw_bid) if raw_bid is not None else None)
        clean_covered_id = _safe_id(covered_id)

        findings.append(
            make_finding(
                code=SL205,
                severity=Severity.WARNING,
                repairability=Repairability.MANUAL,
                message_template=_MSG_SL205,
                source=SourceRef(path=resolved_path, line=line_num, record_id=clean_boundary_id),
                related_ids=(clean_boundary_id, clean_covered_id),
                evidence={
                    "record_id": clean_boundary_id,
                    "boundary_id": clean_boundary_id,
                    "covered_through_id": clean_covered_id,
                    "missing": missing,
                    "non_contiguous": non_contiguous,
                    "boundary_index": b_idx,
                    "record_ordinal": b_idx,
                },
                adapter_id=ctx.adapter_id,
                adapter_version=ctx.adapter_version,
                profile_id=ctx.profile_id,
                profile_version=ctx.profile_version,
            )
        )

    return cap_checkpoint_findings(
        findings,
        code=SL205,
        max_findings=max_findings,
        source_path=source_path,
        context=ctx,
    )


def check_checkpoint(
    events: Sequence[SessionEvent],
    *,
    source_path: str = "<canonical>",
    max_findings_per_family: int = MAX_CHECKPOINT_FINDINGS,
    checkpoint_sensitivity: str = "default",
    context: CheckContext | None = None,
    run_state_projection: Mapping[str, Any] | None = None,
) -> list[Finding]:
    """Run all checkpoint checks (SL201, SL202, SL203) over canonical events."""
    ctx = context if context is not None else CheckContext()
    proj = _extract_run_state_projection(
        context=ctx,
        events=events,
        run_state_projection=run_state_projection,
    )
    all_findings: list[Finding] = []

    f201 = check_checkpoint_gap(
        events,
        source_path=source_path,
        max_findings=max_findings_per_family,
        checkpoint_sensitivity=checkpoint_sensitivity,
        context=ctx,
        run_state_projection=proj,
    )
    all_findings.extend(f201)

    f202 = check_checkpoint_divergence(
        events,
        source_path=source_path,
        max_findings=max_findings_per_family,
        context=ctx,
        run_state_projection=proj,
    )
    all_findings.extend(f202)

    f203 = check_unsafe_continuation(
        events,
        source_path=source_path,
        prior_sl201_findings=f201,
        prior_sl202_findings=f202,
        context=ctx,
    )
    all_findings.extend(f203)

    f205 = check_compaction_coverage(
        events,
        source_path=source_path,
        max_findings=max_findings_per_family,
        context=ctx,
    )
    all_findings.extend(f205)

    return sorted(all_findings, key=_cap_finding_sort_key)


# Aliases for specification and test compatibility
check_sl201 = check_checkpoint_gap
check_sl202 = check_checkpoint_divergence
check_sl203 = check_unsafe_continuation
check_sl205 = check_compaction_coverage

__all__ = [
    "MAX_CHECKPOINT_FINDINGS",
    "cap_checkpoint_findings",
    "check_checkpoint",
    "check_checkpoint_divergence",
    "check_checkpoint_gap",
    "check_compaction_coverage",
    "check_sl201",
    "check_sl202",
    "check_sl203",
    "check_sl205",
    "check_unsafe_continuation",
    "compute_checkpoint_fingerprint",
]
