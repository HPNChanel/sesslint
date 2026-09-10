"""SessLint Canonical Session Format v1 (sesslint.session/v1) adapter.

This module implements the canonical-format adapter for SessLint (TASK-010).
It strictly validates and reads/writes `sesslint.session/v1` documents
byte-deterministically, serving as the interchange + golden-test backbone
and the repair pipeline's revalidation input.

Guarantees:
- Read: strict validation ladder (size, NUL, encoding, JSON, schema, version, per-event keys).
- Write: byte-deterministic canonical JSON with minimal separators and trailing newline.
- Round-trip: `read(write(events)) == events` and `write(read(bytes)) == bytes`.
- Version handling: version != 1 produces SL301 (unsupported-version), parsing best-effort.
- Critical unknown fields: unknown critical keys produce SL302; decorative keys ignored.
- Schema errors: invalid/missing schema or required keys produce SL001 without exception escape.
- Preserves duplicate event IDs verbatim without modification or de-duplication.
- Pure serialization: dump_canonical injects no nondeterminism, timestamps, or synthetic UUIDs.
"""

from __future__ import annotations

import io
import json
import os
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, BinaryIO, Final, Literal, cast

from sesslint.canonical import (
    KNOWN_HEADER_FIELDS,
    MUTATING_TOOL_NAMES,
    READ_ONLY_TOOL_NAMES,
    VALID_ACTORS,
    VALID_KINDS,
    VALID_SIDE_EFFECTS,
    ActorLiteral,
    KindLiteral,
    Session,
    SessionEvent,
    SessionHeader,
    _normalize_for_canonical_json,
    _validate_rfc3339_utc,
)
from sesslint.codes import SL001, SL002, SL301, SL302, Repairability, Severity
from sesslint.errors import MaxRecordsExceededError, SchemaError
from sesslint.finding import (
    Finding,
    SourceRef,
    enforce_content_free_text,
    make_finding,
    sort_findings,
)
from sesslint.io import (
    _STRICT_JSON_DECODER,
    DEFAULT_READER_LIMITS,
    ReaderLimits,
    _validate_stream_coordinates,
    check_nesting_depth,
)

# CanonicalEvent alias for specification conformance
CanonicalEvent = SessionEvent

# Supported canonical session format versions
SUPPORTED_CANONICAL_VERSIONS: Final[frozenset[str]] = frozenset({"1", "1.0", "1.0.0"})

# Known top-level document keys in sesslint.session/v1
KNOWN_TOP_KEYS: Final[frozenset[str]] = frozenset(
    {
        "created_at",
        "events",
        "header",
        "metadata",
        "schema",
        "schema_version",
        "session_id",
        "source",
        "title",
        "version",
    }
)

# Known event keys in sesslint.session/v1
KNOWN_EVENT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "actor",
        "agent_id",
        "branch_id",
        "content_hash",
        "correlation_id",
        "execution_state",
        "id",
        "interaction_id",
        "kind",
        "original_id",
        "parent_id",
        "payload",
        "seq",
        "side_effects",
        "source_adapter",
        "source_line",
        "source_location",
        "source_record_hash",
        "ts",
    }
)

# Critical fields that participate in DAG, identity, pairing, or checkpoints
CRITICAL_KEYS: Final[frozenset[str]] = frozenset(
    {
        "call_id",
        "checkpoint",
        "checkpoints",
        "correlation_id",
        "critical_checkpoint",
        "critical_graph",
        "critical_ordering",
        "id",
        "kind",
        "linkage_override",
        "parent_id",
        "prev_id",
        "replay_barrier",
        "tool_call_id",
        "tool_use_id",
        "type",
        "unknown_critical",
        "unknown_critical_field",
    }
)

# Critical top-level document fields
CRITICAL_TOP_KEYS: Final[frozenset[str]] = frozenset(
    {
        "checkpoints",
        "critical_checkpoint",
        "critical_graph",
        "critical_ordering",
        "linkage_override",
        "replay_barrier",
        "unknown_critical",
        "unknown_critical_field",
    }
)

# Per-event required keys per specification
REQUIRED_EVENT_KEYS: Final[tuple[str, ...]] = ("id", "parent_id", "kind", "ts")

# Regex to detect sesslint.session/v1 schema declarations
_CANONICAL_SCHEMA_PATTERN: Final[re.Pattern[str]] = re.compile(
    r'"(?:schema|schema_version)"\s*:\s*"sesslint\.session/v1"'
)

# Message templates for standard findings
_MSG_MISSING_REQ_EVENT: Final[str] = (
    "Missing required event field on line {line} for record {record_id}"
)
_MSG_INVALID_TS: Final[str] = "Invalid timestamp on line {line} for record {record_id}"
_MSG_INVALID_PARENT_ID: Final[str] = "Invalid parent_id on line {line} for record {record_id}"
_MSG_INVALID_PAYLOAD: Final[str] = "Invalid payload type on line {line} for record {record_id}"
_MSG_INVALID_SEQ: Final[str] = "Invalid sequence number on line {line} for record {record_id}"


class SourceMetadata(dict[str, Any]):
    """Dynamic source metadata dictionary supporting dot-attribute access."""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError:
            if name == "checkpoints":
                return []
            raise AttributeError(f"SourceMetadata has no attribute {name!r}") from None

    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value


class EventList(list[SessionEvent]):
    """Extended event list carrying preserved source metadata."""

    source: SourceMetadata

    def __init__(
        self,
        iterable: Sequence[SessionEvent] = (),
        *,
        source: SourceMetadata | None = None,
    ) -> None:
        super().__init__(iterable)
        self.source = source if source is not None else SourceMetadata()


def normalize_version(version: str) -> str:
    """Normalize a raw version string by stripping whitespace and leading 'v'/'V'."""
    cleaned = version.strip().lower()
    if cleaned.startswith("v") and len(cleaned) > 1 and cleaned[1].isdigit():
        return cleaned[1:]
    return cleaned


def detect_canonical(first_bytes: bytes, filename: str) -> float:
    """Return heuristic confidence in range [0.0, 1.0] that input is canonical session format.

    Parses first bytes without I/O:
    - 1.0 if '"schema": "sesslint.session/v1"' or '"schema_version": "sesslint.session/v1"' found.
    - 0.6 if '"sesslint.session"' substring found anywhere.
    - 0.0 otherwise.
    """
    if not first_bytes:
        return 0.0

    data = first_bytes
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]

    decoded = data[:65536].decode("utf-8", errors="replace")

    if _CANONICAL_SCHEMA_PATTERN.search(decoded):
        return 1.0

    if "sesslint.session" in decoded:
        return 0.6

    return 0.0


def event_to_dict(event: Any) -> dict[str, Any]:
    """Serialize a canonical SessionEvent dataclass or mapping to a normalized JSON dictionary.

    Guarantees:
    - Calls event.to_dict() if present.
    - 'parent_id: null' is preserved when parent_id is None.
    - Other optional None fields are omitted.
    - Extra fields (e.g. experimental_*) are hoisted to top-level.
    """
    if hasattr(event, "to_dict") and callable(event.to_dict):
        res = event.to_dict()
        if isinstance(res, dict):
            return res
    return cast(dict[str, Any], _normalize_for_canonical_json(event))


def _safe_type_value(val: Any) -> str:
    """Return safe type and size descriptor without leaking field content (FR-081, FR-082)."""
    t_name = type(val).__name__
    if isinstance(val, (str, bytes, list, dict, set, tuple)):
        return f"<{t_name}:len={len(val)}>"
    return f"<{t_name}>"


def dump_canonical(
    events: Sequence[CanonicalEvent] | Session,
    source: Mapping[str, Any] | str | None = None,
    *,
    format: Literal["jsonl", "json"] = "jsonl",
) -> bytes:
    """Serialize canonical events and source metadata into deterministic JSON / JSONL bytes.

    Guarantees:
    - Default format is 'jsonl' (Line 1: Header, Lines 2+: Events), matching the canonical
      streaming architecture.
    - Format 'json' emits a single-document JSON object with 'events', 'schema_version',
      'session_id', 'created_at'.
    - Accepts either a Sequence[CanonicalEvent] or a Session dataclass envelope.
    - Keys are sorted lexicographically (sort_keys=True).
    - Minimal separators without whitespace (',', ':').
    - Trailing newline appended.
    - Strict determinism: no timestamps, run counters, or random UUIDs injected.
    - Preserves source checkpoints verbatim.
    """
    events_seq: Sequence[CanonicalEvent]
    source_dict: dict[str, Any] = {}
    schema_version: str = "sesslint.session/v1"
    title: str | None = None
    version: int | None = 1
    metadata: dict[str, Any] | None = None

    if isinstance(events, Session):
        events_seq = events.events
        session_id = events.header.session_id
        created_at = events.header.created_at
        schema_version = events.header.schema_version
        title = events.header.title
        version = events.header.version if events.header.version is not None else 1
        if events.header.metadata:
            metadata = dict(events.header.metadata)
        if source is not None:
            if isinstance(source, (SourceMetadata, Mapping)):
                source_dict = dict(source)
            else:
                source_dict = {"value": str(source)}
        elif events.header.source is not None:
            raw_src = events.header.source
            source_dict = (
                dict(raw_src) if isinstance(raw_src, Mapping) else {"format": str(raw_src)}
            )
        for k in ("session_id", "created_at", "schema_version", "title", "version", "metadata"):
            source_dict.pop(k, None)
    else:
        events_seq = events
        first_ts = (
            events_seq[0].ts
            if events_seq and hasattr(events_seq[0], "ts") and isinstance(events_seq[0].ts, str)
            else "2026-09-05T12:00:00Z"
        )
        session_id = "canonical-session"
        created_at = first_ts

        if source is not None:
            if isinstance(source, (SourceMetadata, Mapping)):
                source_dict = dict(source)
            else:
                source_dict = {"value": str(source)}
        elif hasattr(events, "source") and events.source is not None:
            raw_src = events.source
            source_dict = dict(raw_src) if isinstance(raw_src, Mapping) else {}

        # Extract known header fields if provided in source_dict
        if "session_id" in source_dict and source_dict["session_id"] is not None:
            session_id = str(source_dict.pop("session_id"))
        if "created_at" in source_dict and source_dict["created_at"] is not None:
            created_at = str(source_dict.pop("created_at"))
        if "schema_version" in source_dict and source_dict["schema_version"] is not None:
            schema_version = str(source_dict.pop("schema_version"))
        if "title" in source_dict:
            title = source_dict.pop("title")
        if "version" in source_dict:
            version = source_dict.pop("version")
        if "metadata" in source_dict and isinstance(source_dict["metadata"], Mapping):
            metadata = dict(source_dict.pop("metadata"))

    if format == "json":
        doc: dict[str, Any] = {
            "created_at": created_at,
            "events": [event_to_dict(ev) for ev in events_seq],
            "schema_version": schema_version,
            "session_id": session_id,
            "source": source_dict,
            "version": version if version is not None else 1,
        }
        if title is not None:
            doc["title"] = title
        if metadata is not None:
            doc["metadata"] = metadata
        serialized = json.dumps(
            doc,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        return serialized.encode("utf-8") + b"\n"

    # Default: JSONL Stream (Line 1: Header, Lines 2+: Events)
    header_obj: dict[str, Any] = {
        "created_at": created_at,
        "schema_version": schema_version,
        "session_id": session_id,
    }
    if title is not None:
        header_obj["title"] = title
    if metadata is not None:
        header_obj["metadata"] = metadata
    if source_dict:
        header_obj["source"] = source_dict
    if version is not None:
        header_obj["version"] = version

    hdr_line = json.dumps(
        header_obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    lines = [hdr_line]
    for ev in events_seq:
        lines.append(
            json.dumps(
                event_to_dict(ev),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
        )
    return "\n".join(lines).encode("utf-8") + b"\n"


def _safe_rec_id(val: Any) -> str | None:
    """Return sanitized record_id string for SourceRef, or None if invalid/control-chars."""
    if not isinstance(val, str):
        return None
    stripped = val.strip()
    if not stripped or stripped != val:
        return None
    try:
        enforce_content_free_text(stripped, context="record_id")
        return stripped
    except Exception:
        return None


def _safe_evidence_val(val: Any) -> str | None:
    """Return sanitized evidence string free of control characters."""
    if val is None:
        return None
    s = str(val)
    try:
        enforce_content_free_text(s, context="evidence")
        return s
    except Exception:
        return "<sanitized_control_chars>"


def _parse_canonical_event_record(
    ev_raw: dict[str, Any],
    idx: int,
    line_num: int,
    path_str: str,
    add_finding: Any,
    *,
    byte_offset: int | None = None,
    byte_end: int | None = None,
    record_ordinal: int | None = None,
) -> SessionEvent:
    """Parse and validate a single canonical event record, emitting findings as needed."""

    def _ev_dict(base: dict[str, Any]) -> dict[str, Any]:
        if byte_offset is not None and byte_end is not None and record_ordinal is not None:
            _validate_stream_coordinates(byte_offset, byte_end, record_ordinal)
            return {
                "byte_offset": byte_offset,
                "byte_end": byte_end,
                "record_ordinal": record_ordinal,
                **base,
            }
        return base

    raw_id = ev_raw.get("id")
    has_id_key = "id" in ev_raw
    rec_id_str: str | None = _safe_rec_id(raw_id)
    is_valid_id = isinstance(raw_id, str) and rec_id_str is not None and raw_id == rec_id_str
    rec_id: str = rec_id_str if rec_id_str is not None else f"<missing:{idx}>"

    if not has_id_key:
        add_finding(
            make_finding(
                code=SL001,
                severity=Severity.ERROR,
                repairability=Repairability.MANUAL,
                message_template=_MSG_MISSING_REQ_EVENT,
                source=SourceRef(path=path_str, line=line_num, record_id=None),
                related_ids=("id",),
                evidence=_ev_dict(
                    {
                        "reason": "missing_id_key",
                        "field": "id",
                        "record_id": None,
                    }
                ),
            )
        )
    elif not is_valid_id:
        add_finding(
            make_finding(
                code=SL001,
                severity=Severity.ERROR,
                repairability=Repairability.MANUAL,
                message_template="Invalid event id on line {line} for record {record_id}",
                source=SourceRef(path=path_str, line=line_num, record_id=rec_id_str),
                related_ids=("id",),
                evidence=_ev_dict(
                    {
                        "reason": "invalid_id",
                        "field": "id",
                        "record_id": _safe_evidence_val(raw_id),
                    }
                ),
            )
        )

    # Per-event required keys check: parent_id, kind, ts
    if "parent_id" not in ev_raw:
        add_finding(
            make_finding(
                code=SL001,
                severity=Severity.ERROR,
                repairability=Repairability.MANUAL,
                message_template=_MSG_MISSING_REQ_EVENT,
                source=SourceRef(path=path_str, line=line_num, record_id=rec_id_str),
                related_ids=("parent_id",),
                evidence=_ev_dict(
                    {
                        "reason": "missing_parent_id_key",
                        "field": "parent_id",
                        "record_id": rec_id_str,
                    }
                ),
            )
        )
    else:
        raw_parent = ev_raw["parent_id"]
        if raw_parent is not None and (not isinstance(raw_parent, str) or not raw_parent.strip()):
            add_finding(
                make_finding(
                    code=SL001,
                    severity=Severity.ERROR,
                    repairability=Repairability.MANUAL,
                    message_template=_MSG_INVALID_PARENT_ID,
                    source=SourceRef(path=path_str, line=line_num, record_id=rec_id_str),
                    related_ids=("parent_id",),
                    evidence=_ev_dict(
                        {
                            "reason": "invalid_parent_id",
                            "field": "parent_id",
                            "record_id": rec_id_str,
                        }
                    ),
                )
            )

    if "kind" not in ev_raw:
        add_finding(
            make_finding(
                code=SL001,
                severity=Severity.ERROR,
                repairability=Repairability.MANUAL,
                message_template=_MSG_MISSING_REQ_EVENT,
                source=SourceRef(path=path_str, line=line_num, record_id=rec_id_str),
                related_ids=("kind",),
                evidence=_ev_dict(
                    {
                        "reason": "missing_kind_key",
                        "field": "kind",
                        "record_id": rec_id_str,
                    }
                ),
            )
        )
    elif ev_raw["kind"] not in VALID_KINDS:
        add_finding(
            make_finding(
                code=SL001,
                severity=Severity.ERROR,
                repairability=Repairability.MANUAL,
                message_template="Invalid kind on line {line} for record {record_id}",
                source=SourceRef(path=path_str, line=line_num, record_id=rec_id_str),
                related_ids=("kind",),
                evidence=_ev_dict(
                    {
                        "reason": "invalid_kind",
                        "kind": str(ev_raw["kind"]),
                        "record_id": rec_id_str,
                    }
                ),
            )
        )

    if "ts" not in ev_raw:
        add_finding(
            make_finding(
                code=SL001,
                severity=Severity.ERROR,
                repairability=Repairability.MANUAL,
                message_template=_MSG_MISSING_REQ_EVENT,
                source=SourceRef(path=path_str, line=line_num, record_id=rec_id_str),
                related_ids=("ts",),
                evidence=_ev_dict(
                    {
                        "reason": "missing_ts_key",
                        "field": "ts",
                        "record_id": rec_id_str,
                    }
                ),
            )
        )
    else:
        raw_ts = ev_raw["ts"]
        if not isinstance(raw_ts, str):
            add_finding(
                make_finding(
                    code=SL001,
                    severity=Severity.ERROR,
                    repairability=Repairability.MANUAL,
                    message_template=_MSG_INVALID_TS,
                    source=SourceRef(path=path_str, line=line_num, record_id=rec_id_str),
                    related_ids=("ts",),
                    evidence=_ev_dict(
                        {
                            "reason": "invalid_timestamp",
                            "ts": str(raw_ts),
                            "record_id": rec_id_str,
                        }
                    ),
                )
            )
        else:
            try:
                _validate_rfc3339_utc(raw_ts, "ts")
            except SchemaError:
                add_finding(
                    make_finding(
                        code=SL001,
                        severity=Severity.ERROR,
                        repairability=Repairability.MANUAL,
                        message_template=_MSG_INVALID_TS,
                        source=SourceRef(path=path_str, line=line_num, record_id=rec_id_str),
                        related_ids=("ts",),
                        evidence=_ev_dict(
                            {
                                "reason": "invalid_timestamp",
                                "ts": str(raw_ts),
                                "record_id": rec_id_str,
                            }
                        ),
                    )
                )

    # Validate actor (default to 'user' or 'system' if missing)
    raw_actor = ev_raw.get("actor")
    if "actor" not in ev_raw:
        actor: ActorLiteral = "user"
    elif raw_actor in VALID_ACTORS:
        actor = cast(ActorLiteral, raw_actor)
    else:
        actor = "system"
        add_finding(
            make_finding(
                code=SL001,
                severity=Severity.ERROR,
                repairability=Repairability.MANUAL,
                message_template="Invalid actor on line {line} for record {record_id}",
                source=SourceRef(path=path_str, line=line_num, record_id=rec_id_str),
                evidence=_ev_dict({"reason": "invalid_actor", "actor": str(raw_actor)}),
            )
        )

    # Validate kind
    raw_kind = ev_raw.get("kind")
    if raw_kind in VALID_KINDS:
        kind = cast(KindLiteral, raw_kind)
    else:
        kind = "unknown"

    # Validate timestamp format
    raw_ts = ev_raw.get("ts")
    ts = raw_ts if isinstance(raw_ts, str) else "1970-01-01T00:00:00Z"

    # Check unknown critical fields on event (SL302)
    has_emitted_event_sl302 = False
    extra_fields: dict[str, Any] = {}
    for k, v in ev_raw.items():
        if k not in KNOWN_EVENT_KEYS:
            if k in CRITICAL_KEYS or k.startswith("critical_") or k.startswith("unknown_critical"):
                if not has_emitted_event_sl302:
                    safe_tv = _safe_type_value(v)
                    add_finding(
                        make_finding(
                            code=SL302,
                            severity=Severity.ERROR,
                            repairability=Repairability.MANUAL,
                            message_template=(
                                "Unknown critical record on line {line} for record {record_id}"
                            ),
                            source=SourceRef(path=path_str, line=line_num, record_id=rec_id_str),
                            evidence=_ev_dict(
                                {
                                    "field_path": k,
                                    "type_value": safe_tv,
                                    "record_id": rec_id_str,
                                }
                            ),
                        )
                    )
                    has_emitted_event_sl302 = True
            extra_fields[k] = v

    # Validate payload
    if "payload" in ev_raw and not isinstance(ev_raw["payload"], Mapping):
        add_finding(
            make_finding(
                code=SL001,
                severity=Severity.ERROR,
                repairability=Repairability.MANUAL,
                message_template=_MSG_INVALID_PAYLOAD,
                source=SourceRef(path=path_str, line=line_num, record_id=rec_id_str),
                related_ids=("payload",),
                evidence=_ev_dict(
                    {
                        "reason": "invalid_payload_type",
                        "type": type(ev_raw["payload"]).__name__,
                        "record_id": rec_id_str,
                    }
                ),
            )
        )
    raw_payload = ev_raw.get("payload")
    payload: dict[str, Any] = dict(raw_payload) if isinstance(raw_payload, Mapping) else {}
    content_hash = str(ev_raw["content_hash"]) if ev_raw.get("content_hash") is not None else None

    # Extract parent_id and correlation_id
    raw_parent = ev_raw.get("parent_id")
    parent_id = (
        str(raw_parent)
        if (raw_parent is not None and isinstance(raw_parent, str) and raw_parent.strip())
        else None
    )
    correlation_id = (
        str(ev_raw["correlation_id"]) if ev_raw.get("correlation_id") is not None else None
    )

    # Extract sequence number
    if "seq" in ev_raw:
        seq_val = ev_raw["seq"]
        if not isinstance(seq_val, int) or isinstance(seq_val, bool) or seq_val < 0:
            add_finding(
                make_finding(
                    code=SL001,
                    severity=Severity.ERROR,
                    repairability=Repairability.MANUAL,
                    message_template=_MSG_INVALID_SEQ,
                    source=SourceRef(path=path_str, line=line_num, record_id=rec_id_str),
                    related_ids=("seq",),
                    evidence=_ev_dict(
                        {
                            "reason": "invalid_seq",
                            "seq": str(seq_val),
                            "record_id": rec_id_str,
                        }
                    ),
                )
            )
            seq = idx
        else:
            seq = seq_val
    else:
        seq = idx

    # Extract source_line if explicitly present
    source_line_val = ev_raw.get("source_line")
    source_line = (
        int(source_line_val)
        if isinstance(source_line_val, int) and not isinstance(source_line_val, bool)
        else None
    )

    raw_se = ev_raw.get("side_effects")
    side_effects: str | None = None
    if isinstance(raw_se, str) and raw_se in VALID_SIDE_EFFECTS:
        side_effects = raw_se
    elif isinstance(payload, Mapping) and payload.get("side_effects") in VALID_SIDE_EFFECTS:
        side_effects = str(payload["side_effects"])
    elif kind == "tool_result":
        side_effects = "none"
    elif kind in ("tool_call", "tool_use"):
        tool_name = ""
        if isinstance(payload, Mapping):
            tool_name = str(payload.get("name") or payload.get("tool_name") or "").lower()
        if not tool_name and "name" in ev_raw:
            tool_name = str(ev_raw.get("name") or "").lower()
        if tool_name in READ_ONLY_TOOL_NAMES:
            side_effects = "none"
        elif tool_name in MUTATING_TOOL_NAMES:
            side_effects = "possible"
        else:
            side_effects = "unknown"

    return SessionEvent(
        id=rec_id,
        parent_id=parent_id,
        seq=seq,
        ts=ts,
        actor=actor,
        kind=kind,
        payload=payload,
        content_hash=content_hash,
        correlation_id=correlation_id,
        branch_id=ev_raw.get("branch_id"),
        interaction_id=ev_raw.get("interaction_id"),
        agent_id=ev_raw.get("agent_id"),
        execution_state=ev_raw.get("execution_state"),
        source_line=source_line,
        source_record_hash=ev_raw.get("source_record_hash"),
        original_id=ev_raw.get("original_id"),
        source_adapter=ev_raw.get("source_adapter"),
        source_location=ev_raw.get("source_location"),
        side_effects=side_effects,
        extra_fields=extra_fields,
    )


def load_canonical(
    path: Path | str | BinaryIO | bytes,
    *,
    limits: ReaderLimits | None = None,
) -> tuple[EventList, list[Finding]]:
    """Strictly load and validate a canonical session document (sesslint.session/v1).

    Guarantees:
    - Enforces reader limits (max_file_bytes, max_depth, max_records).
    - Rejects malformed JSON, invalid UTF-8, and forbidden NUL bytes with SL001.
    - Rejects missing schema, version, or events keys with SL001.
    - Validates schema name: wrong schema -> SL001 (not SL301).
    - Validates version: version != 1 -> SL301 (events still parsed best-effort).
    - Flags unknown critical fields with SL302; ignores decorative unknown fields.
    - Checks per-event required keys (id, parent_id, kind, ts) with SL001.
    - Preserves duplicate IDs verbatim (later judged by SL003).
    - Returns deterministically sorted findings and EventList carrying source metadata.
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

        # Size gate check
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

    findings: list[Finding] = []
    seen_fingerprints: set[str] = set()
    max_event_findings: Final[int] = 1000

    def add_finding(f: Finding) -> None:
        if f.fingerprint not in seen_fingerprints:
            seen_fingerprints.add(f.fingerprint)
            if len(findings) < max_event_findings:
                findings.append(f)

    source_metadata = SourceMetadata(format="canonical")

    try:
        data = stream.read(effective_limits.max_file_bytes + 1)
        raw_data = data
        if len(data) > effective_limits.max_file_bytes:
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
            return EventList([], source=source_metadata), [finding]

        if b"\x00" in data:
            finding = make_finding(
                code=SL001,
                severity=Severity.ERROR,
                repairability=Repairability.MANUAL,
                message_template="Forbidden NUL byte on line {line} for record {record_id}",
                source=SourceRef(path=path_str, line=1, record_id=None),
                evidence={"reason": "forbidden_nul_byte"},
            )
            return EventList([], source=source_metadata), [finding]

        if data.startswith(b"\xef\xbb\xbf"):
            data = data[3:]

        stripped_data = data.strip()
        if not stripped_data:
            finding = make_finding(
                code=SL001,
                severity=Severity.ERROR,
                repairability=Repairability.MANUAL,
                message_template="Session input is empty [detail: EMPTY]",
                source=SourceRef(path=path_str, line=1, record_id=None),
                evidence={"reason": "empty_input"},
            )
            return EventList([], source=source_metadata), [finding]

        # Check if single-document JSON
        is_single_doc = False
        doc: Any = None
        try:
            decoded_text = stripped_data.decode("utf-8", errors="strict")
            doc = _STRICT_JSON_DECODER.decode(decoded_text)
            if isinstance(doc, dict) and "events" in doc:
                is_single_doc = True
            elif (
                isinstance(doc, dict)
                and ("schema" in doc or "version" in doc)
                and ("schema_version" not in doc and "session_id" not in doc)
            ):
                # Malformed single-doc missing 'events'
                is_single_doc = True
            elif not isinstance(doc, dict):
                # Valid JSON value that is not an object (e.g. array, integer, string)
                is_single_doc = True
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            is_single_doc = False

        if is_single_doc:
            # Document must be a JSON object
            if not isinstance(doc, dict):
                finding = make_finding(
                    code=SL001,
                    severity=Severity.ERROR,
                    repairability=Repairability.MANUAL,
                    message_template="Canonical document must be a JSON object on line {line}",
                    source=SourceRef(path=path_str, line=1, record_id=None),
                    evidence={"reason": "invalid_document_type"},
                )
                return EventList([], source=source_metadata), [finding]

            # Nesting depth check
            if not check_nesting_depth(doc, effective_limits.max_depth):
                finding = make_finding(
                    code=SL001,
                    severity=Severity.ERROR,
                    repairability=Repairability.MANUAL,
                    message_template=(
                        "Nesting depth exceeds maximum limit on line {line} [detail: LIMIT] "
                        "for record {record_id}"
                    ),
                    source=SourceRef(path=path_str, line=1, record_id=None),
                    evidence={"reason": "depth_exceeded"},
                )
                return EventList([], source=source_metadata), [finding]

            # Required top-level keys check
            missing_top_keys: list[str] = []
            schema_candidate = doc.get("schema") or doc.get("schema_version")
            if "schema" not in doc and "schema_version" not in doc:
                missing_top_keys.append("schema")
            elif "schema" in doc and "schema_version" not in doc:
                if "version" not in doc:
                    missing_top_keys.append("version")

            if "events" not in doc:
                missing_top_keys.append("events")

            if missing_top_keys:
                for missing_key in missing_top_keys:
                    add_finding(
                        make_finding(
                            code=SL001,
                            severity=Severity.ERROR,
                            repairability=Repairability.MANUAL,
                            message_template="Missing required field on line {line}",
                            source=SourceRef(path=path_str, line=1, record_id=None),
                            evidence={"reason": f"missing_{missing_key}_key", "field": missing_key},
                        )
                    )
                return EventList([], source=source_metadata), sort_findings(findings)

            # Validate schema name (wrong schema -> SL001, not SL301)
            if schema_candidate != "sesslint.session/v1":
                add_finding(
                    make_finding(
                        code=SL001,
                        severity=Severity.ERROR,
                        repairability=Repairability.MANUAL,
                        message_template="Unsupported or invalid schema on line {line}",
                        source=SourceRef(path=path_str, line=1, record_id=None),
                        evidence={"reason": "invalid_schema", "schema": str(schema_candidate)},
                    )
                )
                return EventList([], source=source_metadata), sort_findings(findings)

            # Validate version (version != 1 -> SL301, events still parsed best-effort)
            raw_version = doc.get("version")
            norm_ver = normalize_version(str(raw_version)) if raw_version is not None else ""
            if (
                raw_version is not None
                and raw_version != 1
                and norm_ver not in SUPPORTED_CANONICAL_VERSIONS
            ):
                add_finding(
                    make_finding(
                        code=SL301,
                        severity=Severity.ERROR,
                        repairability=Repairability.UNSUPPORTED,
                        message_template="Unsupported canonical format version on line {line}",
                        source=SourceRef(path=path_str, line=1, record_id=None),
                        evidence={
                            "version_raw": str(raw_version),
                            "supported_set": tuple(sorted(SUPPORTED_CANONICAL_VERSIONS)),
                        },
                    )
                )

            # Ingest document identity and metadata
            if "session_id" in doc and isinstance(doc["session_id"], str):
                source_metadata["session_id"] = doc["session_id"]
            if "created_at" in doc and isinstance(doc["created_at"], str):
                source_metadata["created_at"] = doc["created_at"]
            if "title" in doc and isinstance(doc["title"], str):
                source_metadata["title"] = doc["title"]
            if "metadata" in doc and isinstance(doc["metadata"], dict):
                source_metadata["metadata"] = dict(doc["metadata"])

            # Ingest source metadata and checkpoints
            raw_source = doc.get("source")
            if isinstance(raw_source, dict):
                source_metadata.update(raw_source)
                if "checkpoints" in raw_source and isinstance(raw_source["checkpoints"], list):
                    source_metadata["checkpoints"] = list(raw_source["checkpoints"])
            elif isinstance(raw_source, str):
                source_metadata["format"] = raw_source
            elif raw_source is not None:
                add_finding(
                    make_finding(
                        code=SL001,
                        severity=Severity.ERROR,
                        repairability=Repairability.MANUAL,
                        message_template="Invalid source metadata type on line {line}",
                        source=SourceRef(path=path_str, line=1, record_id=None),
                        evidence={
                            "reason": "invalid_source_type",
                            "type": type(raw_source).__name__,
                        },
                    )
                )

            # Check unknown top-level keys for critical indicators (SL302)
            has_emitted_top_sl302 = False
            for key in sorted(doc.keys()):
                if key not in KNOWN_TOP_KEYS:
                    if (
                        key in CRITICAL_TOP_KEYS
                        or key.startswith("critical_")
                        or key.startswith("unknown_critical")
                    ):
                        if not has_emitted_top_sl302:
                            add_finding(
                                make_finding(
                                    code=SL302,
                                    severity=Severity.ERROR,
                                    repairability=Repairability.MANUAL,
                                    message_template="Unknown critical record on line {line}",
                                    source=SourceRef(path=path_str, line=1, record_id=None),
                                    evidence={
                                        "field_path": key,
                                        "type_value": _safe_type_value(doc[key]),
                                    },
                                )
                            )
                            has_emitted_top_sl302 = True

            # Validate events array
            raw_events = doc.get("events")
            if not isinstance(raw_events, list):
                add_finding(
                    make_finding(
                        code=SL001,
                        severity=Severity.ERROR,
                        repairability=Repairability.MANUAL,
                        message_template="Field 'events' must be a list on line {line}",
                        source=SourceRef(path=path_str, line=1, record_id=None),
                        evidence={"reason": "invalid_events_type"},
                    )
                )
                return EventList([], source=source_metadata), sort_findings(findings)

            if (
                effective_limits.max_records is not None
                and len(raw_events) > effective_limits.max_records
            ):
                raise MaxRecordsExceededError(
                    f"Record count {len(raw_events)} exceeds limit of "
                    f"{effective_limits.max_records}"
                )

            # Parse each canonical event
            events: list[SessionEvent] = []
            for idx, ev_raw in enumerate(raw_events):
                line_num = idx + 1
                if not isinstance(ev_raw, dict):
                    add_finding(
                        make_finding(
                            code=SL001,
                            severity=Severity.ERROR,
                            repairability=Repairability.MANUAL,
                            message_template="Event record on line {line} must be an object",
                            source=SourceRef(path=path_str, line=line_num, record_id=None),
                            evidence={"reason": "event_not_dict"},
                        )
                    )
                    continue

                event = _parse_canonical_event_record(
                    ev_raw=ev_raw,
                    idx=idx,
                    line_num=line_num,
                    path_str=path_str,
                    add_finding=add_finding,
                )
                events.append(event)

            return EventList(events, source=source_metadata), sort_findings(findings)

        # ---------------------------------------------------------------------
        # JSONL Stream Parsing (Line 1: Header, Lines 2+: Events)
        # ---------------------------------------------------------------------
        lines_info: list[tuple[int, bytes, int, int]] = []
        curr_offset = 0
        raw_len = len(raw_data)
        line_no = 0

        while curr_offset < raw_len:
            line_no += 1
            nl_pos = raw_data.find(b"\n", curr_offset)
            if nl_pos == -1:
                chunk = raw_data[curr_offset:]
                end_pos = raw_len
            else:
                end_pos = nl_pos + 1
                chunk = raw_data[curr_offset:end_pos]

            start_pos = curr_offset
            curr_offset = end_pos

            if not chunk.strip():
                continue

            lines_info.append((line_no, chunk, start_pos, end_pos))

        if not lines_info:
            finding = make_finding(
                code=SL001,
                severity=Severity.ERROR,
                repairability=Repairability.MANUAL,
                message_template="Session input is empty [detail: EMPTY]",
                source=SourceRef(path=path_str, line=1, record_id=None),
                evidence={"reason": "empty_input"},
            )
            return EventList([], source=source_metadata), [finding]

        # Line 1: Header
        hdr_line_no, hdr_chunk, hdr_byte_offset, hdr_byte_end = lines_info[0]
        hdr_ordinal = 1
        _validate_stream_coordinates(hdr_byte_offset, hdr_byte_end, hdr_ordinal)
        hdr_coord_ev: dict[str, Any] = {
            "byte_offset": hdr_byte_offset,
            "byte_end": hdr_byte_end,
            "record_ordinal": hdr_ordinal,
        }

        hdr_decode = hdr_chunk
        if hdr_line_no == 1 and hdr_decode.startswith(b"\xef\xbb\xbf"):
            hdr_decode = hdr_decode[3:]

        try:
            hdr_str = hdr_decode.decode("utf-8", errors="strict").strip()
            hdr_doc = _STRICT_JSON_DECODER.decode(hdr_str)
        except UnicodeDecodeError as err:
            finding = make_finding(
                code=SL001,
                severity=Severity.ERROR,
                repairability=Repairability.MANUAL,
                message_template="Invalid UTF-8 encoding on line {line} for record {record_id}",
                source=SourceRef(path=path_str, line=hdr_line_no, record_id=None),
                evidence={**hdr_coord_ev, "reason": "invalid_utf8", "detail": str(err)},
            )
            return EventList([], source=source_metadata), [finding]
        except (json.JSONDecodeError, ValueError) as err:
            finding = make_finding(
                code=SL001,
                severity=Severity.ERROR,
                repairability=Repairability.MANUAL,
                message_template="Malformed record on line {line} for record {record_id}",
                source=SourceRef(path=path_str, line=hdr_line_no, record_id=None),
                evidence={**hdr_coord_ev, "reason": "malformed_json", "detail": str(err)},
            )
            return EventList([], source=source_metadata), [finding]

        if not isinstance(hdr_doc, dict):
            finding = make_finding(
                code=SL001,
                severity=Severity.ERROR,
                repairability=Repairability.MANUAL,
                message_template="Canonical document must be a JSON object on line {line}",
                source=SourceRef(path=path_str, line=hdr_line_no, record_id=None),
                evidence={**hdr_coord_ev, "reason": "invalid_document_type"},
            )
            return EventList([], source=source_metadata), [finding]

        if not check_nesting_depth(hdr_doc, effective_limits.max_depth):
            finding = make_finding(
                code=SL001,
                severity=Severity.ERROR,
                repairability=Repairability.MANUAL,
                message_template=(
                    "Nesting depth exceeds maximum limit on line {line} [detail: LIMIT] "
                    "for record {record_id}"
                ),
                source=SourceRef(path=path_str, line=hdr_line_no, record_id=None),
                evidence={**hdr_coord_ev, "reason": "depth_exceeded"},
            )
            return EventList([], source=source_metadata), [finding]

        schema_candidate = hdr_doc.get("schema_version") or hdr_doc.get("schema")
        if not schema_candidate:
            add_finding(
                make_finding(
                    code=SL001,
                    severity=Severity.ERROR,
                    repairability=Repairability.MANUAL,
                    message_template="Missing required field on line {line}",
                    source=SourceRef(path=path_str, line=hdr_line_no, record_id=None),
                    evidence={
                        **hdr_coord_ev,
                        "reason": "missing_schema_version_key",
                        "field": "schema_version",
                    },
                )
            )
            return EventList([], source=source_metadata), sort_findings(findings)

        if schema_candidate != "sesslint.session/v1":
            add_finding(
                make_finding(
                    code=SL001,
                    severity=Severity.ERROR,
                    repairability=Repairability.MANUAL,
                    message_template="Unsupported or invalid schema on line {line}",
                    source=SourceRef(path=path_str, line=hdr_line_no, record_id=None),
                    evidence={
                        **hdr_coord_ev,
                        "reason": "invalid_schema",
                        "schema": str(schema_candidate),
                    },
                )
            )
            return EventList([], source=source_metadata), sort_findings(findings)

        raw_version = hdr_doc.get("version")
        norm_ver = normalize_version(str(raw_version)) if raw_version is not None else ""
        if (
            raw_version is not None
            and raw_version != 1
            and norm_ver not in SUPPORTED_CANONICAL_VERSIONS
        ):
            add_finding(
                make_finding(
                    code=SL301,
                    severity=Severity.ERROR,
                    repairability=Repairability.UNSUPPORTED,
                    message_template="Unsupported canonical format version on line {line}",
                    source=SourceRef(path=path_str, line=hdr_line_no, record_id=None),
                    evidence={
                        **hdr_coord_ev,
                        "version_raw": str(raw_version),
                        "supported_set": tuple(sorted(SUPPORTED_CANONICAL_VERSIONS)),
                    },
                )
            )

        # Ingest header metadata
        if "session_id" in hdr_doc and isinstance(hdr_doc["session_id"], str):
            source_metadata["session_id"] = hdr_doc["session_id"]
        if "created_at" in hdr_doc and isinstance(hdr_doc["created_at"], str):
            source_metadata["created_at"] = hdr_doc["created_at"]
        if "title" in hdr_doc and isinstance(hdr_doc["title"], str):
            source_metadata["title"] = hdr_doc["title"]
        if "metadata" in hdr_doc and isinstance(hdr_doc["metadata"], dict):
            source_metadata["metadata"] = dict(hdr_doc["metadata"])
        source_metadata["schema_version"] = "sesslint.session/v1"

        raw_source = hdr_doc.get("source")
        if isinstance(raw_source, dict):
            source_metadata.update(raw_source)
            if "checkpoints" in raw_source and isinstance(raw_source["checkpoints"], list):
                source_metadata["checkpoints"] = list(raw_source["checkpoints"])
        elif isinstance(raw_source, str):
            source_metadata["format"] = raw_source

        # Check unknown critical keys on header (SL302)
        has_emitted_hdr_sl302 = False
        for key in sorted(hdr_doc.keys()):
            if key not in KNOWN_HEADER_FIELDS and key not in KNOWN_TOP_KEYS:
                if (
                    key in CRITICAL_TOP_KEYS
                    or key in CRITICAL_KEYS
                    or key.startswith("critical_")
                    or key.startswith("unknown_critical")
                ):
                    if not has_emitted_hdr_sl302:
                        add_finding(
                            make_finding(
                                code=SL302,
                                severity=Severity.ERROR,
                                repairability=Repairability.MANUAL,
                                message_template="Unknown critical record on line {line}",
                                source=SourceRef(path=path_str, line=hdr_line_no, record_id=None),
                                evidence={
                                    **hdr_coord_ev,
                                    "field_path": key,
                                    "type_value": _safe_type_value(hdr_doc[key]),
                                },
                            )
                        )
                        has_emitted_hdr_sl302 = True

        # Lines 2+: Events
        event_lines = lines_info[1:]
        if (
            effective_limits.max_records is not None
            and len(event_lines) > effective_limits.max_records
        ):
            raise MaxRecordsExceededError(
                f"Record count {len(event_lines)} exceeds limit of {effective_limits.max_records}"
            )

        events_stream: list[SessionEvent] = []
        for ev_idx, (line_no, ev_chunk, ev_byte_offset, ev_byte_end) in enumerate(event_lines):
            is_terminal = ev_idx == len(event_lines) - 1
            ev_ordinal = ev_idx + 2
            _validate_stream_coordinates(ev_byte_offset, ev_byte_end, ev_ordinal)
            ev_coord_ev: dict[str, Any] = {
                "byte_offset": ev_byte_offset,
                "byte_end": ev_byte_end,
                "record_ordinal": ev_ordinal,
            }
            try:
                ev_str = ev_chunk.decode("utf-8", errors="strict").strip()
                ev_raw = _STRICT_JSON_DECODER.decode(ev_str)
            except UnicodeDecodeError as err:
                code = SL002 if is_terminal else SL001
                rep = Repairability.DETERMINISTIC if is_terminal else Repairability.MANUAL
                msg = (
                    "Torn terminal record on line {line} for record {record_id}"
                    if is_terminal
                    else "Invalid UTF-8 encoding on line {line} for record {record_id}"
                )
                add_finding(
                    make_finding(
                        code=code,
                        severity=Severity.ERROR,
                        repairability=rep,
                        message_template=msg,
                        source=SourceRef(path=path_str, line=line_no, record_id=None),
                        evidence={
                            **ev_coord_ev,
                            "reason": "invalid_utf8",
                            "detail": str(err),
                        },
                    )
                )
                continue
            except (json.JSONDecodeError, ValueError) as err:
                code = SL002 if is_terminal else SL001
                rep = Repairability.DETERMINISTIC if is_terminal else Repairability.MANUAL
                msg = (
                    "Torn terminal record on line {line} for record {record_id}"
                    if is_terminal
                    else "Malformed record on line {line} for record {record_id}"
                )
                add_finding(
                    make_finding(
                        code=code,
                        severity=Severity.ERROR,
                        repairability=rep,
                        message_template=msg,
                        source=SourceRef(path=path_str, line=line_no, record_id=None),
                        evidence={
                            **ev_coord_ev,
                            "reason": "malformed_json",
                            "detail": str(err),
                        },
                    )
                )
                continue

            if not isinstance(ev_raw, dict):
                code = SL002 if is_terminal else SL001
                rep = Repairability.DETERMINISTIC if is_terminal else Repairability.MANUAL
                msg = (
                    "Torn terminal record on line {line} for record {record_id}"
                    if is_terminal
                    else "Event record on line {line} must be an object"
                )
                add_finding(
                    make_finding(
                        code=code,
                        severity=Severity.ERROR,
                        repairability=rep,
                        message_template=msg,
                        source=SourceRef(path=path_str, line=line_no, record_id=None),
                        evidence={
                            **ev_coord_ev,
                            "reason": "event_not_dict",
                        },
                    )
                )
                continue

            if not check_nesting_depth(ev_raw, effective_limits.max_depth):
                add_finding(
                    make_finding(
                        code=SL001,
                        severity=Severity.ERROR,
                        repairability=Repairability.MANUAL,
                        message_template=(
                            "Nesting depth exceeds maximum limit on line {line} [detail: LIMIT] "
                            "for record {record_id}"
                        ),
                        source=SourceRef(path=path_str, line=line_no, record_id=None),
                        evidence={
                            **ev_coord_ev,
                            "reason": "depth_exceeded",
                        },
                    )
                )
                continue

            event = _parse_canonical_event_record(
                ev_raw=ev_raw,
                idx=ev_idx,
                line_num=line_no,
                path_str=path_str,
                add_finding=add_finding,
                byte_offset=ev_byte_offset,
                byte_end=ev_byte_end,
                record_ordinal=ev_ordinal,
            )
            events_stream.append(event)

        return EventList(events_stream, source=source_metadata), sort_findings(findings)

    finally:
        if is_owned_file:
            stream.close()


def load_canonical_session(
    path: Path | str | BinaryIO | bytes,
    *,
    limits: ReaderLimits | None = None,
) -> tuple[Session, list[Finding]]:
    """Stream a canonical session file and wrap canonical events in a Session envelope."""
    events, findings = load_canonical(path, limits=limits)
    first_ts = events[0].ts if events else "1970-01-01T00:00:00Z"
    session_id = events.source.get("session_id") or "canonical-session"
    created_at = events.source.get("created_at") or first_ts
    title = events.source.get("title")
    metadata = (
        dict(events.source.get("metadata", {}))
        if isinstance(events.source.get("metadata"), Mapping)
        else {}
    )
    header = SessionHeader(
        schema_version="sesslint.session/v1",
        session_id=str(session_id),
        created_at=str(created_at),
        title=str(title) if title is not None else None,
        metadata=metadata,
        source=events.source,
        version=1,
    )
    return Session(header=header, events=tuple(events)), findings


__all__ = [
    "CRITICAL_KEYS",
    "CRITICAL_TOP_KEYS",
    "CanonicalEvent",
    "EventList",
    "KNOWN_EVENT_KEYS",
    "KNOWN_TOP_KEYS",
    "REQUIRED_EVENT_KEYS",
    "SUPPORTED_CANONICAL_VERSIONS",
    "SourceMetadata",
    "detect_canonical",
    "dump_canonical",
    "event_to_dict",
    "load_canonical",
    "load_canonical_session",
    "normalize_version",
]
