"""Codex CLI/Desktop ``rollout-*.jsonl`` session adapter (DW-T-12).

This module ingests Codex rollout session files — newline-delimited JSON
records written by the Codex CLI/Desktop agent runtime — into the canonical
session event graph (sesslint.session/v1).

Observed rollout envelope (every record):

    {"timestamp": <RFC3339>, "type": <envelope_type>, "ordinal": <int>,
     "payload": {...}}

Envelope ``type`` values seen in the wild: ``session_meta`` (header-like
metadata), ``response_item`` (conversation items), ``event_msg`` (lifecycle
signals), ``turn_context`` (per-turn run context), ``world_state``,
``inter_agent_communication_metadata``, ``token_usage_record`` (token usage
metadata), and ``compacted`` (window compaction).

``response_item`` payloads carry their own ``type``: ``message``,
``agent_message``, ``reasoning``, ``function_call``, ``custom_tool_call``,
``tool_search_call``, ``function_call_output``, ``custom_tool_call_output``,
``tool_search_output``.

Guarantees:
- Zero live-store mutation: JSONL read-only ingestion; refuses SQLite magic
  via the shared detection gate.
- call_id pairing preserved in ``correlation_id`` for tool calls and results.
- ``compacted`` records map to canonical ``compaction_boundary`` events so
  post-compaction corruption analysis sees the same boundary structure other
  adapters expose.
- Run-metadata records (``event_msg``, ``turn_context``, ``world_state``,
  ``session_meta``, ``inter_agent_communication_metadata``,
  ``token_usage_record``) are kept as ``system``/``opaque`` events — preserved
  in DAG position without pretending to be conversational content (unknown
  noncritical records may be kept opaque, FR-021).
- Unknown envelope types and unknown ``response_item`` payload types route to
  SL302 with bounded discriminator evidence; missing/unsupported explicit
  format-version markers (``rollout_version``/``format_version``/
  ``schema_version``/``export_version``) fail closed with SL301. The rollout
  format carries no version field in the wild — ``cli_version`` in
  ``session_meta`` is an application version and is recorded as evidence only,
  never version-gated.
- Enforces strict hostile-input bounds (max_file_bytes, max_line_bytes,
  max_depth, max_records) with SL001/SL002 terminal-torn distinction.
- Deterministic: identical bytes produce identical event IDs, hashes, and
  finding fingerprints.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, BinaryIO, Final

from sesslint.adapters.drift import DriftTracker
from sesslint.adapters.links import extract_links
from sesslint.adapters.openai_agents import (
    EventList,
    SourceMetadata,
    normalize_version,
)
from sesslint.adapters.safe_value import safe_discriminator, safe_type_value
from sesslint.adapters.synthetic import (
    SyntheticIdCollisionGuard,
    synthetic_event_id,
)
from sesslint.canonical import (
    MUTATING_TOOL_NAMES,
    READ_ONLY_TOOL_NAMES,
    ActorLiteral,
    KindLiteral,
    Session,
    SessionEvent,
    SessionHeader,
    canonical_bytes,
    compute_content_hash,
)
from sesslint.checks.hygiene import SecretScanTracker
from sesslint.codes import SL001, SL002, SL301, SL302, Repairability, Severity
from sesslint.errors import MaxRecordsExceededError
from sesslint.finding import Finding, SourceRef, make_finding, sort_findings
from sesslint.io import (
    _STRICT_JSON_DECODER,
    DEFAULT_READER_LIMITS,
    MalformedTailTracker,
    ReaderLimits,
    _RawLine,
    check_nesting_depth,
    decode_json_dupaware,
    dup_key_findings,
    extract_record_id,
)

CanonicalEvent = SessionEvent

SQLITE_MAGIC: Final[bytes] = b"SQLite format 3\x00"

# Explicit rollout format-version markers. The format carries no version field
# in the wild; these are honored when present so a future versioned rollout
# fails closed instead of being silently misinterpreted.
SUPPORTED_CODEX_ROLLOUT_VERSIONS: Final[frozenset[str]] = frozenset(
    {
        "1",
        "1.0",
        "1.0.0",
        "codex-rollout-v1",
    }
)

# Envelope-level types that carry run/telemetry metadata rather than
# conversational content. Mapped to system/opaque so they keep DAG position
# without participating in identity/parentage/pairing semantics (FR-021).
ENVELOPE_OPAQUE_TYPES: Final[frozenset[str]] = frozenset(
    {
        "session_meta",
        "event_msg",
        "turn_context",
        "world_state",
        "inter_agent_communication_metadata",
        "token_usage_record",
    }
)

# Envelope families the rollout writer persists as thread history — the
# durable record sequence the paginated resume path replays (SL206,
# detector-depth T-03). ``session_meta`` is the durable thread header;
# ``response_item`` carries conversation items; ``compacted`` is a durable
# history rewrite. The remaining ENVELOPE_OPAQUE_TYPES families
# (``event_msg``, ``turn_context``, ``world_state``,
# ``inter_agent_communication_metadata``, ``token_usage_record``) are
# per-run telemetry — present in the file but not part of the durable
# prefix. Unknown envelope types fail closed as non-durable.
DURABLE_ENVELOPE_TYPES: Final[frozenset[str]] = frozenset(
    {
        "session_meta",
        "response_item",
        "compacted",
    }
)

# response_item payload types → canonical (actor, kind). "message" is
# role-disambiguated below (developer→system like openai adapter semantics).
RESPONSE_ITEM_TYPE_MAP: Final[dict[str, tuple[ActorLiteral, KindLiteral]]] = {
    "message": ("assistant", "message"),
    "agent_message": ("assistant", "message"),
    "reasoning": ("assistant", "opaque"),
    "function_call": ("assistant", "tool_call"),
    "custom_tool_call": ("assistant", "tool_call"),
    "tool_search_call": ("assistant", "tool_call"),
    "function_call_output": ("tool", "tool_result"),
    "custom_tool_call_output": ("tool", "tool_result"),
    "tool_search_output": ("tool", "tool_result"),
}

# Envelope keys observed in rollout records.
KNOWN_ENVELOPE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "timestamp",
        "ts",
        "created_at",
        "type",
        "ordinal",
        "payload",
        "rollout_version",
        "format_version",
        "schema_version",
        "export_version",
        "version",
    }
)

# Payload keys observed across known payload types. Additional keys on the
# critical path that are absent here route to SL302.
KNOWN_PAYLOAD_KEYS: Final[frozenset[str]] = frozenset(
    {
        "type",
        "id",
        "role",
        "phase",
        "content",
        "author",
        "recipient",
        "name",
        "namespace",
        "arguments",
        "args",
        "input",
        "output",
        "call_id",
        "tool_call_id",
        "status",
        "summary",
        "encrypted_content",
        "internal_chat_message_metadata_passthrough",
        # session_meta
        "session_id",
        "cli_version",
        "model_provider",
        "originator",
        "source",
        "thread_source",
        "history_mode",
        "context_window",
        "base_instructions",
        "cwd",
        "timestamp",
        "git",
        "agent_nickname",
        "agent_path",
        "agent_role",
        "forked_from_id",
        "multi_agent_version",
        "parent_thread_id",
        "subagent_history_start_ordinal",
        # turn_context / world_state
        "turn_id",
        "approval_policy",
        "approvals_reviewer",
        "collaboration_mode",
        "comp_hash",
        "current_date",
        "effort",
        "model",
        "permission_profile",
        "personality",
        "realtime_active",
        "sandbox_policy",
        "timezone",
        "workspace_roots",
        "full",
        "state",
        # event_msg payloads
        "started_at",
        "started_at_ms",
        "completed_at",
        "completed_at_ms",
        "duration_ms",
        "reason",
        "last_agent_message",
        "time_to_first_token_ms",
        "collaboration_mode_kind",
        "model_context_window",
        "thread_id",
        "item",
        "info",
        "rate_limits",
        "thread_settings",
        # compacted
        "message",
        "first_window_id",
        "previous_window_id",
        "window_id",
        "window_number",
        "replacement_history",
        # inter_agent_communication_metadata
        "trigger_turn",
        # version markers honored when present
        "rollout_version",
        "format_version",
        "schema_version",
        "export_version",
        "version",
        "is_error",
        "error",
        "result",
        "metadata",
        # token_usage_record
        "response_id",
        "root_turn_id",
        "thread_token_usage",
        "turn_token_usage",
        "usage",
        # tool_search_call / tool_search_output
        "execution",
        "tools",
    }
)

# Critical keys participating in identity, pairing, or continuation.
CRITICAL_KEYS: Final[frozenset[str]] = frozenset(
    {
        "type",
        "parent_id",
        "prev_id",
        "call_id",
        "tool_call_id",
        "unknown_critical_field",
    }
)

_TIMESTAMP_ISO_REGEX: Final[re.Pattern[str]] = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$"
)


def _safe_type_value(val: Any) -> str:
    """Return safe type and size descriptor without leaking field content (FR-081, FR-082)."""
    return safe_type_value(val)


def detect_codex_rollout(first_bytes: bytes, filename: str) -> float:
    """Return heuristic confidence in [0.0, 1.0] that input is a Codex rollout JSONL.

    Inspects the file extension plus early bytes for the rollout envelope
    signature: ``"type": "session_meta"`` / ``"response_item"`` records with
    ``"payload"`` + ``"ordinal"`` fields, and Codex-specific payload types such
    as ``custom_tool_call`` / ``function_call_output``. A ``rollout-*.jsonl``
    filename is a strong supporting signal.
    """
    fn_lower = filename.lower()
    if not (fn_lower.endswith(".jsonl") or fn_lower.endswith(".json")):
        return 0.0

    if not first_bytes:
        return 0.0

    if first_bytes.startswith(SQLITE_MAGIC):
        return 0.0

    data = first_bytes
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]

    decoded = data[:4096].decode("utf-8", errors="replace")

    signals = 0
    if '"session_meta"' in decoded:
        signals += 4
    if '"response_item"' in decoded:
        signals += 4
    if '"ordinal"' in decoded and '"payload"' in decoded:
        signals += 2
    if '"turn_context"' in decoded or '"world_state"' in decoded:
        signals += 2
    if '"event_msg"' in decoded:
        signals += 1
    if '"custom_tool_call"' in decoded or '"function_call_output"' in decoded:
        signals += 2
    if '"compacted"' in decoded:
        signals += 1
    if fn_lower.startswith("rollout-"):
        signals += 2

    if signals >= 6:
        return 1.0
    if signals >= 3:
        return 0.8
    if signals >= 1:
        return 0.3
    return 0.0


def _normalize_timestamp(raw_ts: Any) -> str:
    """Ensure timestamp conforms to RFC3339, else a fixed epoch (deterministic)."""
    if isinstance(raw_ts, str) and raw_ts.strip():
        val = raw_ts.strip()
        if _TIMESTAMP_ISO_REGEX.match(val):
            return val
    return "1970-01-01T00:00:00Z"


def _check_version(
    version_candidate: Any,
    *,
    path_str: str,
    line_number: int,
    rec_id: str | None,
    findings: list[Finding],
    source_metadata: SourceMetadata,
    seen_version_sl301: bool,
    byte_offset: int | None = None,
    byte_end: int | None = None,
    record_ordinal: int | None = None,
    guard: SyntheticIdCollisionGuard | None = None,
) -> bool:
    """Evaluate an explicit rollout format-version marker, emitting SL301 if unsupported."""
    if version_candidate is None:
        return seen_version_sl301

    if rec_id is not None:
        rec_id_str = rec_id
    else:
        ord_val = record_ordinal if record_ordinal is not None else 0
        p_len = (
            (byte_end - byte_offset) if (byte_offset is not None and byte_end is not None) else 0
        )
        rec_id_str = synthetic_event_id(
            adapter="codex_rollout",
            ordinal=ord_val,
            source_hint=path_str,
            payload_len=p_len,
        )
        if guard is not None:
            guard.register_synthetic(rec_id_str)

    coord_ev: dict[str, Any] = {}
    if byte_offset is not None:
        coord_ev["byte_offset"] = byte_offset
    if byte_end is not None:
        coord_ev["byte_end"] = byte_end
    if record_ordinal is not None:
        coord_ev["record_ordinal"] = record_ordinal

    if isinstance(version_candidate, (str, int, float)):
        version_raw = str(version_candidate).strip()
        source_metadata.version_raw = version_raw
        version_norm = normalize_version(version_raw)
        if version_norm not in SUPPORTED_CODEX_ROLLOUT_VERSIONS and not seen_version_sl301:
            source = SourceRef(path=path_str, line=line_number, record_id=rec_id_str)
            safe_v, _ = safe_discriminator(version_raw)
            findings.append(
                make_finding(
                    code=SL301,
                    severity=Severity.ERROR,
                    repairability=Repairability.UNSUPPORTED,
                    message_template=(
                        "Unsupported format version on line {line} for record {record_id}"
                    ),
                    source=source,
                    evidence={
                        "version_raw": safe_v,
                        "supported_set": tuple(sorted(SUPPORTED_CODEX_ROLLOUT_VERSIONS)),
                        **coord_ev,
                    },
                )
            )
            return True
    elif not seen_version_sl301:
        source = SourceRef(path=path_str, line=line_number, record_id=rec_id_str)
        findings.append(
            make_finding(
                code=SL301,
                severity=Severity.ERROR,
                repairability=Repairability.UNSUPPORTED,
                message_template=(
                    "Unsupported format version on line {line} for record {record_id}"
                ),
                source=source,
                evidence={
                    "version_raw": "<invalid_version_type>",
                    "supported_set": tuple(sorted(SUPPORTED_CODEX_ROLLOUT_VERSIONS)),
                    **coord_ev,
                },
            )
        )
        return True
    return seen_version_sl301


def _emit_sl302(
    *,
    path_str: str,
    line_number: int,
    rec_id: str,
    field_path: str,
    type_value: Any,
    coord_ev: dict[str, Any],
    findings: list[Finding],
) -> None:
    """Emit a bounded SL302 unknown-critical-record finding."""
    safe_val, truncated = safe_discriminator(type_value)
    evidence: dict[str, Any] = {
        "field_path": field_path,
        "type_value": safe_val,
        "record_id": rec_id,
        **coord_ev,
    }
    if truncated:
        evidence["type_truncated"] = True
    findings.append(
        make_finding(
            code=SL302,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message_template="Unknown critical record on line {line} for record {record_id}",
            source=SourceRef(path=path_str, line=line_number, record_id=rec_id),
            evidence=evidence,
        )
    )


def _tool_input_payload(raw_input: Any) -> Any:
    """Normalize a tool input/arguments field to a canonical input payload."""
    if raw_input is None:
        return {}
    if isinstance(raw_input, str):
        try:
            parsed = _STRICT_JSON_DECODER.decode(raw_input)
            if isinstance(parsed, Mapping):
                return dict(parsed)
            return {"value": parsed}
        except Exception:
            return {"value": raw_input}
    if isinstance(raw_input, Mapping):
        return dict(raw_input)
    return {"value": raw_input}


def _version_field_name(envelope: Any, payload: Any) -> str:
    """Return the bounded key path that supplied the version candidate.

    Mirrors the ``or``-chain in ``_process_rollout_record``: envelope keys
    first (including ``version``), then payload keys.
    """
    for _k in (
        "rollout_version",
        "format_version",
        "schema_version",
        "export_version",
        "version",
    ):
        if envelope.get(_k):
            return _k
    if isinstance(payload, Mapping):
        for _k in (
            "rollout_version",
            "format_version",
            "schema_version",
            "export_version",
        ):
            if payload.get(_k):
                return f"payload.{_k}"
    return "version"


def _process_rollout_record(
    envelope: dict[str, Any],
    *,
    line_number: int,
    path_str: str,
    events: list[SessionEvent],
    findings: list[Finding],
    source_metadata: SourceMetadata,
    seen_version_sl301: bool,
    byte_offset: int | None = None,
    byte_end: int | None = None,
    record_ordinal: int | None = None,
    guard: SyntheticIdCollisionGuard | None = None,
    last_event_id: str | None = None,
    last_envelope_ordinal: int | None = None,
    gap_after_drop: bool = False,
    drift: DriftTracker | None = None,
) -> tuple[bool, int | None]:
    """Canonicalize one rollout envelope record into a SessionEvent.

    Rollout records carry no explicit parent linkage; the envelope ``ordinal``
    is the stream sequence. Parentage is mapped linearly: an event's parent is
    the previously emitted event only when continuity is provable (no dropped
    line in between, and envelope ordinals are consecutive when present). A
    torn/lost record therefore surfaces as an honest new root (SL006/SL007)
    instead of a fabricated link.

    Returns ``(seen_version_sl301, envelope_ordinal)``.
    """
    seq_index = len(events)
    try:
        p_len = len(canonical_bytes(envelope))
    except Exception:
        p_len = 0

    coord_ev: dict[str, Any] = {}
    if byte_offset is not None:
        coord_ev["byte_offset"] = byte_offset
    if byte_end is not None:
        coord_ev["byte_end"] = byte_end
    if record_ordinal is not None:
        coord_ev["record_ordinal"] = record_ordinal

    env_type = envelope.get("type")
    payload = envelope.get("payload")

    # Resolve event identity: payload.id when present, else synthetic.
    payload_id: Any = payload.get("id") if isinstance(payload, Mapping) else None
    if payload_id is not None and str(payload_id).strip():
        rec_id_str = str(payload_id).strip()
        original_id: str | None = rec_id_str
        if guard is not None:
            guard.register_real(rec_id_str)
    else:
        rec_id_str = synthetic_event_id(
            adapter="codex_rollout",
            ordinal=record_ordinal if record_ordinal is not None else seq_index,
            source_hint=path_str,
            payload_len=p_len,
        )
        original_id = None
        if guard is not None:
            guard.register_synthetic(rec_id_str)

    # Schema-drift tracking (SL304): foreign envelope ``type`` signatures.
    if drift is not None:
        drift.observe_signature(
            env_type,
            line=line_number,
            record_id=rec_id_str,
            record_ordinal=record_ordinal,
            byte_offset=byte_offset,
            byte_end=byte_end,
        )

    # Explicit format-version markers (envelope or payload level).
    version_candidate = (
        envelope.get("rollout_version")
        or envelope.get("format_version")
        or envelope.get("schema_version")
        or envelope.get("export_version")
        or envelope.get("version")
    )
    if version_candidate is None and isinstance(payload, Mapping):
        version_candidate = (
            payload.get("rollout_version")
            or payload.get("format_version")
            or payload.get("schema_version")
            or payload.get("export_version")
        )
    seen_version_sl301 = _check_version(
        version_candidate,
        path_str=path_str,
        line_number=line_number,
        rec_id=rec_id_str,
        findings=findings,
        source_metadata=source_metadata,
        seen_version_sl301=seen_version_sl301,
        byte_offset=byte_offset,
        byte_end=byte_end,
        record_ordinal=record_ordinal,
        guard=guard,
    )

    if drift is not None:
        if seen_version_sl301:
            drift.note_unsupported_version()
        elif isinstance(version_candidate, (str, int, float)):
            _ver_norm = normalize_version(str(version_candidate).strip())
            drift.observe_version(
                _ver_norm,
                supported=_ver_norm in SUPPORTED_CODEX_ROLLOUT_VERSIONS,
                field=_version_field_name(envelope, payload),
                line=line_number,
                record_id=rec_id_str,
                record_ordinal=record_ordinal,
                byte_offset=byte_offset,
                byte_end=byte_end,
            )

    actor: ActorLiteral = "system"
    kind: KindLiteral = "unknown"
    correlation_id: str | None = None
    execution_state: Any = None
    side_effects: str | None = None
    out_payload: dict[str, Any] = {}
    event_extra: dict[str, Any] = {}

    # SL206 markers (detector-depth T-03): normalized durability + ordinal +
    # envelope family so the durable-prefix check never re-derives vendor
    # semantics. Type-specific claims (item_type, encrypted_content presence,
    # inherited-prefix ordinal) are attached inside the branches below.
    env_ord_raw = envelope.get("ordinal")
    codex_extra: dict[str, Any] = {
        "durable": isinstance(env_type, str) and env_type in DURABLE_ENVELOPE_TYPES,
        "ordinal": (
            env_ord_raw
            if isinstance(env_ord_raw, int) and not isinstance(env_ord_raw, bool)
            else None
        ),
        "envelope_type": env_type if isinstance(env_type, str) else None,
    }

    # Declared cross-file resume pointers (bounded structural ids only —
    # scan-layer SL401 resolves them; per-file processing never does).
    if isinstance(payload, Mapping):
        links_meta = source_metadata.get("links")
        if isinstance(links_meta, list):
            extract_links(payload, links=links_meta, record_id=rec_id_str, line=line_number)

    # Bounded per-record byte size for the SL011 distribution check.
    if byte_offset is not None and byte_end is not None and byte_end >= byte_offset:
        sizes_meta = source_metadata.get("record_sizes")
        if isinstance(sizes_meta, list):
            sizes_meta.append(byte_end - byte_offset)

    if env_type == "response_item":
        if not isinstance(payload, Mapping):
            _emit_sl302(
                path_str=path_str,
                line_number=line_number,
                rec_id=rec_id_str,
                field_path="payload",
                type_value=payload,
                coord_ev=coord_ev,
                findings=findings,
            )
            out_payload = {"type": "<invalid>"}
        else:
            item_type = payload.get("type")
            if isinstance(item_type, str):
                codex_extra["item_type"] = item_type
                if item_type == "reasoning":
                    # SL206 resume-projection marker (#19661): field
                    # presence only — never the encrypted value.
                    codex_extra["has_encrypted_content"] = "encrypted_content" in payload
                    # SL305 replay-vocabulary marker (#36551): official
                    # reasoning items carry content=null or no content key;
                    # a non-null value (array of reasoning_text parts) is a
                    # third-party provider shape. Shape class only — never
                    # the content value.
                    if "content" not in payload:
                        codex_extra["reasoning_content_shape"] = "absent"
                    elif payload["content"] is None:
                        codex_extra["reasoning_content_shape"] = "null"
                    elif isinstance(payload["content"], list):
                        codex_extra["reasoning_content_shape"] = "array"
                    else:
                        codex_extra["reasoning_content_shape"] = "other"
            if isinstance(item_type, str) and item_type in RESPONSE_ITEM_TYPE_MAP:
                actor, kind = RESPONSE_ITEM_TYPE_MAP[item_type]
            else:
                _emit_sl302(
                    path_str=path_str,
                    line_number=line_number,
                    rec_id=rec_id_str,
                    field_path="type",
                    type_value=item_type,
                    coord_ev=coord_ev,
                    findings=findings,
                )
                out_payload = {"type": str(item_type) if item_type is not None else "<missing>"}

            if kind == "message":
                role = payload.get("role")
                if item_type == "agent_message":
                    actor = "assistant"
                elif role == "user":
                    actor = "user"
                elif role == "assistant":
                    actor = "assistant"
                elif role == "developer":
                    actor = "system"
                elif role is not None:
                    actor = "system"
                out_payload = {"content": payload.get("content"), "role": actor}
                if payload.get("phase") is not None:
                    out_payload["phase"] = payload.get("phase")
                if item_type == "agent_message":
                    if payload.get("author") is not None:
                        out_payload["author"] = str(payload.get("author"))
                    if payload.get("recipient") is not None:
                        out_payload["recipient"] = str(payload.get("recipient"))
            elif kind == "tool_call":
                raw_call_id = (
                    payload.get("call_id")
                    if payload.get("call_id") is not None
                    else payload.get("tool_call_id")
                )
                call_id = str(raw_call_id) if raw_call_id is not None else rec_id_str
                correlation_id = call_id
                tool_name = str(payload.get("name") or "")
                raw_input = (
                    payload.get("arguments")
                    if payload.get("arguments") is not None
                    else (
                        payload.get("args")
                        if payload.get("args") is not None
                        else payload.get("input")
                    )
                )
                out_payload = {
                    "call_id": call_id,
                    "input": _tool_input_payload(raw_input),
                    "name": tool_name,
                    "tool_name": tool_name,
                    "tool_use_id": call_id,
                }
                if payload.get("status") is not None:
                    status = str(payload.get("status"))
                    execution_state = (
                        "success"
                        if status == "completed"
                        else ("failure" if status == "failed" else "unknown")
                    )
                t_name = tool_name.lower()
                if t_name in READ_ONLY_TOOL_NAMES:
                    side_effects = "none"
                elif t_name in MUTATING_TOOL_NAMES:
                    side_effects = "possible"
                else:
                    side_effects = "unknown"
            elif kind == "tool_result":
                raw_call_id = (
                    payload.get("call_id")
                    if payload.get("call_id") is not None
                    else payload.get("tool_call_id")
                )
                call_id = str(raw_call_id) if raw_call_id is not None else ""
                correlation_id = call_id or None
                raw_output = (
                    payload.get("output")
                    if payload.get("output") is not None
                    else (
                        payload.get("content")
                        if payload.get("content") is not None
                        else (
                            payload.get("result")
                            if payload.get("result") is not None
                            else payload.get("tools")
                        )
                    )
                )
                is_err = bool(
                    payload.get("is_error")
                    if payload.get("is_error") is not None
                    else (payload.get("error") if payload.get("error") is not None else False)
                )
                out_payload = {
                    "call_id": call_id,
                    "content": raw_output if raw_output is not None else "",
                    "is_error": is_err,
                    "tool_use_id": call_id,
                }
                execution_state = "failure" if is_err else "success"
                side_effects = "none"
            elif kind == "opaque":
                # e.g. reasoning — preserve position, no content projection.
                out_payload = {"type": str(item_type)}
    elif env_type == "compacted":
        actor, kind = "system", "compaction_boundary"
        if isinstance(payload, Mapping):
            raw_summary = (
                payload.get("message")
                if payload.get("message") is not None
                else payload.get("summary")
            )
            out_payload = {
                "summary": str(raw_summary) if raw_summary is not None else "",
            }
            for key in ("window_id", "window_number", "first_window_id", "previous_window_id"):
                if payload.get(key) is not None:
                    out_payload[key] = payload.get(key)
        else:
            out_payload = {"summary": ""}
    elif isinstance(env_type, str) and env_type in ENVELOPE_OPAQUE_TYPES:
        actor, kind = "system", "opaque"
        out_payload = {"type": env_type}
        if env_type == "token_usage_record" and isinstance(payload, Mapping):
            # SL204 canonical slot (adapter-neutral): numeric counters only —
            # ``turn_token_usage``/``usage`` is this record's contribution,
            # ``thread_token_usage`` is the cumulative running-total marker.
            usage_slot: dict[str, Any] = {}
            contribution_raw = payload.get("turn_token_usage")
            if contribution_raw is None:
                contribution_raw = payload.get("usage")
            cumulative_raw = payload.get("thread_token_usage")
            if isinstance(contribution_raw, Mapping):
                usage_slot["contribution"] = {
                    str(k): v
                    for k, v in contribution_raw.items()
                    if isinstance(v, int) and not isinstance(v, bool)
                }
            if isinstance(cumulative_raw, Mapping):
                usage_slot["cumulative"] = {
                    str(k): v
                    for k, v in cumulative_raw.items()
                    if isinstance(v, int) and not isinstance(v, bool)
                }
            if usage_slot:
                event_extra["usage"] = usage_slot
        if env_type == "session_meta":
            # Record minimized metadata for the session envelope — identifiers
            # and versions only, never content fields like cwd/instructions.
            if isinstance(payload, Mapping):
                meta: dict[str, Any] = {}
                for key in ("session_id", "cli_version", "model_provider", "originator"):
                    if payload.get(key) is not None:
                        meta[key] = payload.get(key)
                source_metadata.session_meta = meta
                if payload.get("session_id") is not None:
                    out_payload["session_id"] = str(payload.get("session_id"))
                _shso = payload.get("subagent_history_start_ordinal")
                if isinstance(_shso, int) and not isinstance(_shso, bool):
                    # SL206: declared inherited-prefix ordinal the file's
                    # durable sequence must cover (#40747 signature).
                    codex_extra["subagent_history_start_ordinal"] = _shso
        elif env_type == "turn_context" and isinstance(payload, Mapping):
            if payload.get("turn_id") is not None:
                out_payload["turn_id"] = str(payload.get("turn_id"))
        elif env_type == "event_msg" and isinstance(payload, Mapping):
            if payload.get("type") is not None:
                out_payload["subtype"] = str(payload.get("type"))
            if payload.get("turn_id") is not None:
                out_payload["turn_id"] = str(payload.get("turn_id"))
    else:
        # Unknown or missing envelope type -> SL302 unknown critical record.
        _emit_sl302(
            path_str=path_str,
            line_number=line_number,
            rec_id=rec_id_str,
            field_path="type",
            type_value=env_type,
            coord_ev=coord_ev,
            findings=findings,
        )
        actor, kind = "system", "unknown"
        out_payload = {"type": str(env_type) if env_type is not None else "<missing>"}

    # Check for unknown critical fields on critical paths (envelope + payload).
    for key in sorted(envelope.keys()):
        unknown_critical = (
            key in CRITICAL_KEYS
            or key.startswith("critical_")
            or key.startswith("unknown_critical")
        )
        if key not in KNOWN_ENVELOPE_KEYS and unknown_critical:
            _emit_sl302(
                path_str=path_str,
                line_number=line_number,
                rec_id=rec_id_str,
                field_path=key,
                type_value=envelope[key],
                coord_ev=coord_ev,
                findings=findings,
            )
            break
    if isinstance(payload, Mapping):
        for key in sorted(payload.keys()):
            unknown_critical = (
                key in CRITICAL_KEYS
                or key.startswith("critical_")
                or key.startswith("unknown_critical")
            )
            if key not in KNOWN_PAYLOAD_KEYS and unknown_critical:
                _emit_sl302(
                    path_str=path_str,
                    line_number=line_number,
                    rec_id=rec_id_str,
                    field_path=key,
                    type_value=payload[key],
                    coord_ev=coord_ev,
                    findings=findings,
                )
                break

    event_extra["codex"] = codex_extra

    cur_envelope_ordinal = envelope.get("ordinal")
    contiguous = (
        last_event_id is not None
        and not gap_after_drop
        and (
            last_envelope_ordinal is None
            or not isinstance(cur_envelope_ordinal, int)
            or isinstance(cur_envelope_ordinal, bool)
            or cur_envelope_ordinal == last_envelope_ordinal + 1
        )
    )
    parent_id = last_event_id if contiguous else None

    ts = _normalize_timestamp(
        envelope.get("timestamp")
        if envelope.get("timestamp") is not None
        else (envelope.get("ts") if envelope.get("ts") is not None else envelope.get("created_at"))
    )
    content_hash = compute_content_hash(out_payload)

    event = SessionEvent(
        id=rec_id_str,
        parent_id=parent_id,
        seq=seq_index,
        ts=ts,
        actor=actor,
        kind=kind,
        payload=out_payload,
        content_hash=content_hash,
        correlation_id=correlation_id,
        source_line=line_number,
        source_record_hash=f"sha256:{hashlib.sha256(canonical_bytes(envelope)).hexdigest()}",
        original_id=original_id,
        source_adapter="codex-rollout",
        source_location=None,
        execution_state=execution_state,
        side_effects=side_effects,
        extra_fields=event_extra,
    )
    events.append(event)
    if guard is not None:
        guard.check_event(event)
    env_ord_out = envelope.get("ordinal")
    if not isinstance(env_ord_out, int) or isinstance(env_ord_out, bool):
        env_ord_out = None
    return seen_version_sl301, env_ord_out


def _process_jsonl_line(
    raw: _RawLine,
    *,
    is_terminal: bool,
    path_str: str,
    limits: ReaderLimits,
    events: list[SessionEvent],
    findings: list[Finding],
    source_metadata: SourceMetadata,
    seen_version_sl301: bool,
    guard: SyntheticIdCollisionGuard | None = None,
    last_event_id: str | None = None,
    last_envelope_ordinal: int | None = None,
    gap_after_drop: bool = False,
    drift: DriftTracker | None = None,
    secret_tracker: SecretScanTracker | None = None,
) -> tuple[bool, bool, int | None]:
    """Process a single rollout JSONL line, emitting SessionEvent or SL001/SL002.

    Returns ``(seen_version_sl301, emitted, envelope_ordinal)`` where
    ``emitted`` is True when a canonical event was appended for this line and
    ``envelope_ordinal`` is the record's envelope ``ordinal`` (or None).
    """
    # SL009: scan the persisted raw bytes for secret shapes before any
    # validation rejects the record — malformed lines still carry secrets.
    if secret_tracker is not None:
        secret_tracker.feed(
            raw.raw_bytes,
            line_number=raw.line_number,
            byte_offset=raw.byte_offset,
            byte_end=raw.byte_end,
            record_ordinal=raw.record_ordinal,
        )

    code = SL002 if is_terminal else SL001
    coord_evidence: dict[str, Any] = {
        "byte_offset": raw.byte_offset,
        "byte_end": raw.byte_end,
        "record_ordinal": raw.record_ordinal,
    }

    if raw.truncated_limit:
        rec_id = extract_record_id(raw.raw_bytes.decode("utf-8", errors="replace"))
        findings.append(
            make_finding(
                code=code,
                message_template=(
                    "Line {line} exceeds maximum line byte limit [detail: LIMIT] "
                    "for record {record_id}"
                ),
                source=SourceRef(path=path_str, line=raw.line_number, record_id=rec_id),
                evidence=coord_evidence,
            )
        )
        return seen_version_sl301, False, None

    if b"\x00" in raw.raw_bytes:
        rec_id = extract_record_id(raw.raw_bytes.decode("utf-8", errors="replace"))
        findings.append(
            make_finding(
                code=code,
                message_template="Forbidden NUL byte on line {line} for record {record_id}",
                source=SourceRef(path=path_str, line=raw.line_number, record_id=rec_id),
                evidence=coord_evidence,
            )
        )
        return seen_version_sl301, False, None

    to_decode = raw.raw_bytes
    if raw.line_number == 1 and to_decode.startswith(b"\xef\xbb\xbf"):
        to_decode = to_decode[3:]

    try:
        decoded_text = to_decode.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError:
        rec_id = extract_record_id(raw.raw_bytes.decode("utf-8", errors="replace"))
        findings.append(
            make_finding(
                code=code,
                message_template=(
                    "Invalid UTF-8 encoding on line {line} [detail: ENCODING] "
                    "for record {record_id}"
                ),
                source=SourceRef(path=path_str, line=raw.line_number, record_id=rec_id),
                evidence=coord_evidence,
            )
        )
        return seen_version_sl301, False, None

    try:
        obj, dup_keys, dups_truncated = decode_json_dupaware(
            decoded_text, critical_keys=CRITICAL_KEYS
        )
    except RecursionError:
        rec_id = extract_record_id(decoded_text)
        findings.append(
            make_finding(
                code=code,
                message_template=(
                    "Nesting depth exceeds maximum limit on line {line} [detail: LIMIT] "
                    "for record {record_id}"
                ),
                source=SourceRef(path=path_str, line=raw.line_number, record_id=rec_id),
                evidence=coord_evidence,
            )
        )
        return seen_version_sl301, False, None
    except (json.JSONDecodeError, ValueError):
        rec_id = extract_record_id(decoded_text)
        msg_template = (
            "Torn terminal record on line {line} for record {record_id}"
            if is_terminal
            else "Malformed record on line {line} for record {record_id}"
        )
        findings.append(
            make_finding(
                code=code,
                message_template=msg_template,
                source=SourceRef(path=path_str, line=raw.line_number, record_id=rec_id),
                evidence=coord_evidence,
            )
        )
        return seen_version_sl301, False, None

    if dup_keys:
        findings.extend(
            dup_key_findings(
                dup_keys,
                truncated=dups_truncated,
                path_str=path_str,
                line=raw.line_number,
                record_id=extract_record_id(decoded_text, obj),
                record_ordinal=raw.record_ordinal,
            )
        )

    if not isinstance(obj, dict):
        msg_template = (
            "Torn terminal record on line {line} for record {record_id}"
            if is_terminal
            else "Malformed record on line {line} for record {record_id}"
        )
        findings.append(
            make_finding(
                code=code,
                message_template=msg_template,
                source=SourceRef(path=path_str, line=raw.line_number, record_id=None),
                evidence=coord_evidence,
            )
        )
        return seen_version_sl301, False, None

    if not check_nesting_depth(obj, limits.max_depth):
        rec_id = extract_record_id(decoded_text, obj)
        findings.append(
            make_finding(
                code=code,
                message_template=(
                    "Nesting depth exceeds maximum limit on line {line} [detail: LIMIT] "
                    "for record {record_id}"
                ),
                source=SourceRef(path=path_str, line=raw.line_number, record_id=rec_id),
                evidence=coord_evidence,
            )
        )
        return seen_version_sl301, False, None

    latch, env_ord = _process_rollout_record(
        obj,
        line_number=raw.line_number,
        path_str=path_str,
        events=events,
        findings=findings,
        source_metadata=source_metadata,
        seen_version_sl301=seen_version_sl301,
        byte_offset=raw.byte_offset,
        byte_end=raw.byte_end,
        record_ordinal=raw.record_ordinal,
        guard=guard,
        last_event_id=last_event_id,
        last_envelope_ordinal=last_envelope_ordinal,
        gap_after_drop=gap_after_drop,
        drift=drift,
    )
    return latch, True, env_ord


def load_codex_rollout(
    path: Path | str | BinaryIO | bytes,
    *,
    limits: ReaderLimits | None = None,
) -> tuple[EventList, list[Finding]]:
    """Ingest a Codex rollout-*.jsonl session file.

    Guarantees:
    - Never mutates input files; refuses live SQLite databases (SL001 fatal).
    - Preserves call_id pairing in correlation_id for tool calls and results.
    - Maps ``compacted`` to compaction_boundary; keeps run-metadata records as opaque.
    - Evaluates explicit format-version markers (SL301) and unknown records (SL302).
    - Delivers deterministic canonical events for identical bytes.
    """
    effective_limits = limits if limits is not None else DEFAULT_READER_LIMITS

    path_str: str
    stream: BinaryIO
    is_owned_file = False

    if isinstance(path, bytes):
        stream = io.BytesIO(path)
        path_str = "<bytes>"
    elif isinstance(path, (str, os.PathLike, Path)):
        path_obj = Path(path)
        path_str = str(path_obj).replace("\\", "/")
        if not path_obj.exists():
            raise FileNotFoundError(f"Session file not found: {path_obj}")
        if path_obj.is_dir():
            raise IsADirectoryError(f"Expected session file, got directory: {path_obj}")

        try:
            if path_obj.is_file():
                file_size = path_obj.stat().st_size
                if file_size > effective_limits.max_file_bytes:
                    finding = make_finding(
                        code=SL001,
                        severity=Severity.ERROR,
                        repairability=Repairability.MANUAL,
                        message_template="File size exceeds maximum limit [detail: LIMIT]",
                        source=SourceRef(path=path_str, line=1, record_id=None),
                        evidence={
                            "reason": "size_limit_exceeded",
                            "limit": effective_limits.max_file_bytes,
                        },
                    )
                    return EventList([], source=SourceMetadata()), [finding]
        except OSError:
            pass

        stream = open(path_obj, "rb")
        is_owned_file = True
    else:
        stream = path
        path_str = getattr(path, "name", "<stream>")
        path_str = str(path_str).replace("\\", "/")

    try:
        first_16 = stream.read(16)
        if first_16.startswith(SQLITE_MAGIC):
            finding = make_finding(
                code=SL001,
                severity=Severity.FATAL,
                repairability=Repairability.UNSUPPORTED,
                message_template=(
                    "Refused live SQLite database; SessLint requires exported items or "
                    "checkpoints [detail: refused_live_db]"
                ),
                source=SourceRef(path=path_str, line=1, record_id=None),
                evidence={"reason": "refused_live_db"},
            )
            return EventList([], source=SourceMetadata(format="refused_live_db")), [finding]

        max_bytes = effective_limits.max_file_bytes
        to_read = max(0, max_bytes - len(first_16) + 1)
        stream_remainder = stream.read(to_read)
        full_bytes = first_16 + stream_remainder

        if len(full_bytes) > max_bytes:
            finding = make_finding(
                code=SL001,
                severity=Severity.ERROR,
                repairability=Repairability.MANUAL,
                message_template="File size exceeds maximum limit [detail: LIMIT]",
                source=SourceRef(path=path_str, line=1, record_id=None),
                evidence={"reason": "size_limit_exceeded", "limit": max_bytes},
            )
            return EventList([], source=SourceMetadata()), [finding]

        events: list[SessionEvent] = []
        findings: list[Finding] = []
        source_metadata = SourceMetadata(format="codex-rollout", checkpoints=[])
        source_metadata["links"] = []
        source_metadata["record_sizes"] = []
        guard = SyntheticIdCollisionGuard()
        seen_version_sl301 = False
        drift = DriftTracker("codex-rollout")
        secret_tracker = SecretScanTracker()
        last_event_id: str | None = None
        last_envelope_ordinal: int | None = None
        gap_after_drop = False

        data = full_bytes
        current_offset = 0
        line_number = 0
        record_count = 0
        total_len = len(data)
        pending_raw: _RawLine | None = None
        tail_tracker = MalformedTailTracker()

        while current_offset < total_len:
            line_number += 1
            nl_pos = data.find(b"\n", current_offset)
            if nl_pos == -1:
                line_chunk = data[current_offset:]
                line_end = total_len
            else:
                line_end = nl_pos + 1
                line_chunk = data[current_offset:line_end]

            line_start = current_offset
            current_offset = line_end

            truncated = len(line_chunk) > effective_limits.max_line_bytes
            if not line_chunk.strip() and not truncated:
                continue

            record_count += 1
            record_bytes = line_chunk
            rec_byte_end = line_end
            if truncated:
                record_bytes = line_chunk[: effective_limits.max_line_bytes + 1]
                rec_byte_end = line_start + len(record_bytes)

            current_raw = _RawLine(
                line_number=line_number,
                raw_bytes=record_bytes,
                truncated_limit=truncated,
                byte_offset=line_start,
                byte_end=rec_byte_end,
                record_ordinal=record_count,
            )

            if pending_raw is not None:
                if (
                    effective_limits.max_records is not None
                    and pending_raw.record_ordinal > effective_limits.max_records
                ):
                    raise MaxRecordsExceededError(
                        f"Record count {pending_raw.record_ordinal} exceeds limit of "
                        f"{effective_limits.max_records}"
                    )
                prev_len = len(events)
                prev_findings = len(findings)
                seen_version_sl301, emitted, env_ord = _process_jsonl_line(
                    pending_raw,
                    is_terminal=False,
                    path_str=path_str,
                    limits=effective_limits,
                    events=events,
                    findings=findings,
                    source_metadata=source_metadata,
                    seen_version_sl301=seen_version_sl301,
                    guard=guard,
                    last_event_id=last_event_id,
                    last_envelope_ordinal=last_envelope_ordinal,
                    gap_after_drop=gap_after_drop,
                    drift=drift,
                    secret_tracker=secret_tracker,
                )
                tail_tracker.note_produced(events[prev_len:], findings[prev_findings:])
                if emitted and len(events) > prev_len:
                    last_event_id = events[-1].id
                    last_envelope_ordinal = env_ord
                    gap_after_drop = False
                else:
                    gap_after_drop = True

            pending_raw = current_raw

        torn_tail_offset: int | None = None
        if pending_raw is not None:
            if (
                effective_limits.max_records is not None
                and pending_raw.record_ordinal > effective_limits.max_records
            ):
                raise MaxRecordsExceededError(
                    f"Record count {pending_raw.record_ordinal} exceeds limit of "
                    f"{effective_limits.max_records}"
                )
            prev_len = len(events)
            prev_findings = len(findings)
            seen_version_sl301, _emitted, _ord = _process_jsonl_line(
                pending_raw,
                is_terminal=True,
                path_str=path_str,
                limits=effective_limits,
                events=events,
                findings=findings,
                source_metadata=source_metadata,
                seen_version_sl301=seen_version_sl301,
                guard=guard,
                last_event_id=last_event_id,
                last_envelope_ordinal=last_envelope_ordinal,
                gap_after_drop=gap_after_drop,
                drift=drift,
                secret_tracker=secret_tracker,
            )
            new_findings = findings[prev_findings:]
            tail_tracker.note_produced(events[prev_len:], new_findings)
            if any(f.code == SL002 for f in new_findings):
                torn_tail_offset = pending_raw.byte_offset
            _ = prev_len  # terminal line ends the stream; lineage state unused

        tail_tracker.finalize(total_bytes=total_len, torn_tail_offset=torn_tail_offset)

        guard.assert_no_collision()
        findings.extend(drift.into_findings(path_str=path_str))
        findings.extend(secret_tracker.into_findings(path_str=path_str))
        return EventList(events, source=source_metadata), sort_findings(findings)
    finally:
        if is_owned_file:
            stream.close()


def load_codex_rollout_session(
    path: Path | str | BinaryIO | bytes,
    *,
    limits: ReaderLimits | None = None,
) -> tuple[Session, list[Finding]]:
    """Stream a Codex rollout file and wrap canonical events in a Session envelope."""
    events, findings = load_codex_rollout(path, limits=limits)
    first_ts = events[0].ts if events else "1970-01-01T00:00:00Z"
    meta = getattr(events, "source", None)
    session_id = "codex-rollout-session"
    if isinstance(meta, Mapping):
        sm = meta.get("session_meta")
        if isinstance(sm, Mapping) and sm.get("session_id"):
            session_id = str(sm["session_id"])
    header = SessionHeader(
        schema_version="sesslint.session/v1",
        session_id=session_id,
        created_at=first_ts,
        source=events.source,
    )
    return Session(header=header, events=tuple(events)), findings


__all__ = [
    "CRITICAL_KEYS",
    "CanonicalEvent",
    "ENVELOPE_OPAQUE_TYPES",
    "KNOWN_ENVELOPE_KEYS",
    "KNOWN_PAYLOAD_KEYS",
    "RESPONSE_ITEM_TYPE_MAP",
    "SQLITE_MAGIC",
    "SUPPORTED_CODEX_ROLLOUT_VERSIONS",
    "detect_codex_rollout",
    "load_codex_rollout",
    "load_codex_rollout_session",
]
