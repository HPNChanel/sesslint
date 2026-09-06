"""Canonical session model, serialization helpers, and validation rules.

This module defines the vendor-neutral canonical session event graph
for SessLint. Generic detectors, repair planning, and reporting operate
on these types without depending on vendor-specific formats.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final, Literal, cast

from sesslint.errors import SchemaError, UnknownFieldError, VersionError

SchemaVersionLiteral = Literal["sesslint.session/v1"]
SCHEMA_VERSION: Final[SchemaVersionLiteral] = "sesslint.session/v1"
MAX_NON_STREAMING_BYTES: Final[int] = 100 * 1024 * 1024  # 100 MB
MAX_PAYLOAD_DEPTH: Final[int] = 100
ActorLiteral = Literal["user", "assistant", "tool", "system"]
KindLiteral = Literal[
    "message",
    "tool_call",
    "tool_result",
    "approval",
    "checkpoint",
    "compaction_boundary",
    "handoff",
    "subagent_boundary",
    "error",
    "opaque",
    "unknown",
]
ExecutionStateLiteral = Literal["success", "failure", "pending", "aborted", "unknown"]

VALID_ACTORS: Final[frozenset[str]] = frozenset({"user", "assistant", "tool", "system"})
VALID_KINDS: Final[frozenset[str]] = frozenset(
    {
        "message",
        "tool_call",
        "tool_result",
        "approval",
        "checkpoint",
        "compaction_boundary",
        "handoff",
        "subagent_boundary",
        "error",
        "opaque",
        "unknown",
    }
)
VALID_EXECUTION_STATES: Final[frozenset[str]] = frozenset(
    {"success", "failure", "pending", "aborted", "unknown"}
)

REQUIRED_HEADER_FIELDS: Final[frozenset[str]] = frozenset(
    {"schema_version", "session_id", "created_at"}
)
KNOWN_HEADER_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "created_at",
        "metadata",
        "schema_version",
        "session_id",
        "source",
        "title",
        "version",
    }
)

REQUIRED_EVENT_FIELDS: Final[frozenset[str]] = frozenset(
    {"id", "parent_id", "seq", "ts", "actor", "kind", "payload"}
)
KNOWN_EVENT_FIELDS: Final[frozenset[str]] = frozenset(
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
        "source_adapter",
        "source_line",
        "source_location",
        "source_record_hash",
        "ts",
    }
)

_RFC3339_UTC_REGEX: Final[re.Pattern[str]] = re.compile(
    r"^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"
    r"T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?"
    r"(?:Z|[+-]00(?::?00)?)$"
)


def _validate_rfc3339_utc(ts: str, field_name: str) -> None:
    """Validate that timestamp conforms to RFC3339 UTC format and valid calendar date."""
    if not isinstance(ts, str) or not _RFC3339_UTC_REGEX.match(ts):
        raise SchemaError(
            f"Field '{field_name}' must be an RFC3339 UTC timestamp string, got {ts!r}"
        )
    try:
        normalized_ts = ts.replace("Z", "+00:00")
        datetime.fromisoformat(normalized_ts)
    except ValueError as err:
        raise SchemaError(
            f"Field '{field_name}' contains invalid calendar date/time: {ts!r}"
        ) from err


def _validate_depth(val: Any, current_depth: int = 0, seen: set[int] | None = None) -> None:
    """Recursively guard against hostile payload nesting depth and cyclic references."""
    if current_depth > MAX_PAYLOAD_DEPTH:
        raise SchemaError(
            f"Payload nesting depth {current_depth} exceeds limit of {MAX_PAYLOAD_DEPTH}"
        )
    if seen is None:
        seen = set()

    if isinstance(val, (Mapping, list, tuple)):
        obj_id = id(val)
        if obj_id in seen:
            raise SchemaError("Cyclic reference detected in payload")
        seen.add(obj_id)
        try:
            if isinstance(val, Mapping):
                for sub_val in val.values():
                    _validate_depth(sub_val, current_depth + 1, seen)
            else:
                for item in val:
                    _validate_depth(item, current_depth + 1, seen)
        finally:
            seen.remove(obj_id)


@dataclass(frozen=True, slots=True)
class SessionHeader:
    """Header record defining session identity and schema version."""

    schema_version: SchemaVersionLiteral
    session_id: str
    created_at: str
    title: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    source: Mapping[str, Any] | str | None = None
    version: int | None = None
    extra_fields: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SessionEvent:
    """Canonical event record in a session graph."""

    id: str
    parent_id: str | None
    seq: int
    ts: str
    actor: ActorLiteral
    kind: KindLiteral
    payload: Mapping[str, Any] = field(default_factory=dict)
    content_hash: str | None = None
    correlation_id: str | None = None
    branch_id: str | None = None
    interaction_id: str | None = None
    agent_id: str | None = None
    execution_state: ExecutionStateLiteral | None = None
    source_line: int | None = None
    source_record_hash: str | None = None
    original_id: str | None = None
    source_adapter: str | None = None
    source_location: str | None = None
    extra_fields: Mapping[str, Any] = field(default_factory=dict)

    def to_canonical_dict(self) -> dict[str, Any]:
        """Return normalized canonical dictionary for this event."""
        return to_canonical_dict(self)

    def to_canonical_bytes(self) -> bytes:
        """Return canonical UTF-8 bytes for this event."""
        return canonical_bytes(self)

    def canonical_hash(self) -> str:
        """Compute SHA-256 hex digest of this event's canonical bytes."""
        return hashlib.sha256(self.to_canonical_bytes()).hexdigest()

    def payload_hash(self) -> str:
        """Return content_hash or compute SHA-256 of payload canonical bytes."""
        return self.content_hash or compute_content_hash(self.payload)


CanonicalEvent = SessionEvent


@dataclass(frozen=True, slots=True)
class Session:
    """Canonical session artifact composed of a header and ordered events."""

    header: SessionHeader
    events: tuple[SessionEvent, ...] = ()
    extra_fields: Mapping[str, Any] = field(default_factory=dict)


def compute_content_hash(payload: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 hash of payload canonical bytes."""
    digest = hashlib.sha256(canonical_bytes(payload)).hexdigest()
    return f"sha256:{digest}"


def _normalize_for_canonical_json(obj: Any, seen: set[int] | None = None) -> Any:
    """Normalize objects to plain JSON types with sorted keys and minimal representation."""
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            raise SchemaError(f"Float value {obj!r} is not valid in canonical JSON (RFC 8785)")
        return obj

    if seen is None:
        seen = set()

    if is_dataclass(obj) and not isinstance(obj, type):
        obj_id = id(obj)
        if obj_id in seen:
            raise SchemaError("Cyclic reference detected during canonical serialization")
        seen.add(obj_id)
        try:
            result: dict[str, Any] = {}
            for f in fields(obj):
                val = getattr(obj, f.name)
                if f.name == "extra_fields":
                    if isinstance(val, Mapping):
                        for k, v in val.items():
                            key_str = str(k)
                            if key_str not in result:
                                result[key_str] = _normalize_for_canonical_json(v, seen)
                    continue
                # parent_id is required and must be present even when null
                if val is None and f.name != "parent_id":
                    continue
                # Omit optional metadata in header when empty
                if f.name == "metadata" and isinstance(val, Mapping) and not val:
                    continue
                result[f.name] = _normalize_for_canonical_json(val, seen)
            return result
        finally:
            seen.remove(obj_id)

    if isinstance(obj, Mapping):
        obj_id = id(obj)
        if obj_id in seen:
            raise SchemaError("Cyclic reference detected during canonical serialization")
        seen.add(obj_id)
        try:
            return {str(k): _normalize_for_canonical_json(v, seen) for k, v in obj.items()}
        finally:
            seen.remove(obj_id)

    if isinstance(obj, (list, tuple)):
        obj_id = id(obj)
        if obj_id in seen:
            raise SchemaError("Cyclic reference detected during canonical serialization")
        seen.add(obj_id)
        try:
            return [_normalize_for_canonical_json(item, seen) for item in obj]
        finally:
            seen.remove(obj_id)

    if isinstance(obj, (str, int, bool)) or obj is None:
        return obj

    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def to_canonical_json(obj: Any) -> str:
    """Serialize an object or dataclass to deterministic canonical JSON string.

    Guarantees:
    - Keys are sorted lexicographically.
    - Compact separators without whitespace (',', ':').
    - Non-ASCII characters preserved directly as UTF-8 (ensure_ascii=False).
    - Dataclass extra fields (experimental_*) hoisted to top level.
    - Strict RFC 8785 compliance (rejects out-of-range floats like NaN/Inf and cyclic structures).
    """
    try:
        normalized = _normalize_for_canonical_json(obj)
        return json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except RecursionError as err:
        raise SchemaError("Object nesting depth exceeded during canonical serialization") from err
    except ValueError as err:
        raise SchemaError(f"Canonical serialization error: {err}") from err


def canonical_bytes(obj: Any) -> bytes:
    """Serialize an object to canonical UTF-8 bytes."""
    return to_canonical_json(obj).encode("utf-8")


def to_canonical_dict(obj: Any) -> dict[str, Any]:
    """Convert an object or dataclass to a normalized dictionary for canonical inspection."""
    normalized = _normalize_for_canonical_json(obj)
    if isinstance(normalized, dict):
        return cast(dict[str, Any], normalized)
    raise TypeError(f"Expected dict from canonical normalization, got {type(normalized).__name__}")


def parse_session_header(obj: Mapping[str, Any]) -> SessionHeader:
    """Parse and validate a session header mapping."""
    if not isinstance(obj, Mapping):
        raise SchemaError(f"Session header must be a mapping, got {type(obj).__name__}")

    # Check schema_version first
    if "schema_version" not in obj:
        raise SchemaError("Missing required field 'schema_version' in session header")
    version_val = obj["schema_version"]
    if not isinstance(version_val, str):
        raise SchemaError(f"Field 'schema_version' must be a string, got {version_val!r}")
    if version_val != SCHEMA_VERSION:
        raise VersionError(
            f"Unsupported schema version '{version_val}', expected '{SCHEMA_VERSION}'",
            version=version_val,
        )

    # Check remaining required header keys
    for req_key in REQUIRED_HEADER_FIELDS:
        if req_key not in obj:
            raise SchemaError(f"Missing required header field '{req_key}'")

    session_id = obj["session_id"]
    if not isinstance(session_id, str) or not session_id.strip():
        raise SchemaError(f"Field 'session_id' must be a non-empty string, got {session_id!r}")

    created_at = obj["created_at"]
    _validate_rfc3339_utc(created_at, "created_at")

    # Validate unknown and optional keys
    extra_fields: dict[str, Any] = {}
    for key, value in obj.items():
        if key not in KNOWN_HEADER_FIELDS:
            if key.startswith("experimental_"):
                extra_fields[key] = value
            else:
                raise UnknownFieldError(
                    f"Unknown field '{key}' in session header",
                    field_name=key,
                )

    title = obj.get("title")
    if title is not None and not isinstance(title, str):
        raise SchemaError(f"Field 'title' must be a string or None, got {title!r}")

    raw_metadata = obj.get("metadata", {})
    if not isinstance(raw_metadata, Mapping):
        raise SchemaError(f"Field 'metadata' must be a mapping, got {type(raw_metadata).__name__}")
    _validate_depth(raw_metadata)

    source = obj.get("source")
    if source is not None and not isinstance(source, (Mapping, str)):
        raise SchemaError(
            f"Field 'source' must be a mapping or string, got {type(source).__name__}"
        )
    if isinstance(source, Mapping):
        _validate_depth(source)

    version = obj.get("version")
    if version is not None and (not isinstance(version, int) or isinstance(version, bool)):
        raise SchemaError(f"Field 'version' must be an integer, got {version!r}")

    return SessionHeader(
        schema_version=SCHEMA_VERSION,
        session_id=session_id,
        created_at=created_at,
        title=title,
        metadata=dict(raw_metadata),
        source=dict(source) if isinstance(source, Mapping) else source,
        version=version,
        extra_fields=extra_fields,
    )


def parse_session_event(obj: Mapping[str, Any], seen_ids: set[str] | None = None) -> SessionEvent:
    """Parse and validate a single canonical session event record."""
    if not isinstance(obj, Mapping):
        raise SchemaError(f"Session event must be a mapping, got {type(obj).__name__}")

    # Check required fields
    for req_key in REQUIRED_EVENT_FIELDS:
        if req_key not in obj:
            raise SchemaError(f"Missing required event field '{req_key}'")

    # Check unknown fields
    extra_fields: dict[str, Any] = {}
    for key, value in obj.items():
        if key not in KNOWN_EVENT_FIELDS:
            if key.startswith("experimental_"):
                extra_fields[key] = value
            else:
                raise UnknownFieldError(
                    f"Unknown top-level field in event: '{key}'",
                    field_name=key,
                )

    # Validate id
    event_id = obj["id"]
    if not isinstance(event_id, str) or not event_id.strip():
        raise SchemaError(f"Event 'id' must be a non-empty string, got {event_id!r}")
    if seen_ids is not None:
        if event_id in seen_ids:
            raise SchemaError(f"Duplicate event ID detected: '{event_id}'")
        seen_ids.add(event_id)

    # Validate parent_id
    parent_id = obj["parent_id"]
    if parent_id is not None:
        if not isinstance(parent_id, str) or not parent_id.strip():
            raise SchemaError(f"Field 'parent_id' must be a string or None, got {parent_id!r}")
        if parent_id == event_id:
            raise SchemaError(f"Event '{event_id}' has self-referencing parent_id")

    # Validate seq
    seq = obj["seq"]
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise SchemaError(f"Field 'seq' must be a non-negative integer, got {seq!r}")

    # Validate ts
    ts = obj["ts"]
    _validate_rfc3339_utc(ts, "ts")

    # Validate actor
    actor = obj["actor"]
    if actor not in VALID_ACTORS:
        raise SchemaError(f"Invalid actor '{actor}', expected one of {sorted(VALID_ACTORS)}")

    # Validate kind
    kind = obj["kind"]
    if kind not in VALID_KINDS:
        raise SchemaError(f"Invalid kind '{kind}', expected one of {sorted(VALID_KINDS)}")

    # Validate payload (content-opaque, but checked for depth and cycles)
    payload = obj["payload"]
    if not isinstance(payload, Mapping):
        raise SchemaError(f"Field 'payload' must be a mapping, got {type(payload).__name__}")
    _validate_depth(payload)

    # Validate optional fields
    content_hash = obj.get("content_hash")
    if content_hash is not None and not isinstance(content_hash, str):
        raise SchemaError(f"Field 'content_hash' must be a string or None, got {content_hash!r}")

    correlation_id = obj.get("correlation_id")
    if correlation_id is not None and not isinstance(correlation_id, str):
        raise SchemaError(
            f"Field 'correlation_id' must be a string or None, got {correlation_id!r}"
        )

    branch_id = obj.get("branch_id")
    if branch_id is not None and not isinstance(branch_id, str):
        raise SchemaError(f"Field 'branch_id' must be a string or None, got {branch_id!r}")

    interaction_id = obj.get("interaction_id")
    if interaction_id is not None and not isinstance(interaction_id, str):
        raise SchemaError(
            f"Field 'interaction_id' must be a string or None, got {interaction_id!r}"
        )

    agent_id = obj.get("agent_id")
    if agent_id is not None and not isinstance(agent_id, str):
        raise SchemaError(f"Field 'agent_id' must be a string or None, got {agent_id!r}")

    execution_state = obj.get("execution_state")
    if execution_state is not None and execution_state not in VALID_EXECUTION_STATES:
        raise SchemaError(
            f"Invalid execution_state '{execution_state}', expected one of "
            f"{sorted(VALID_EXECUTION_STATES)}"
        )

    source_line = obj.get("source_line")
    if source_line is not None and (
        not isinstance(source_line, int) or isinstance(source_line, bool) or source_line < 1
    ):
        raise SchemaError(f"Field 'source_line' must be a positive integer, got {source_line!r}")

    source_record_hash = obj.get("source_record_hash")
    if source_record_hash is not None and not isinstance(source_record_hash, str):
        raise SchemaError(
            f"Field 'source_record_hash' must be a string or None, got {source_record_hash!r}"
        )

    original_id = obj.get("original_id")
    if original_id is not None and not isinstance(original_id, str):
        raise SchemaError(f"Field 'original_id' must be a string or None, got {original_id!r}")

    source_adapter = obj.get("source_adapter")
    if source_adapter is not None and not isinstance(source_adapter, str):
        raise SchemaError(
            f"Field 'source_adapter' must be a string or None, got {source_adapter!r}"
        )

    source_location = obj.get("source_location")
    if source_location is not None and not isinstance(source_location, str):
        raise SchemaError(
            f"Field 'source_location' must be a string or None, got {source_location!r}"
        )

    return SessionEvent(
        id=event_id,
        parent_id=parent_id,
        seq=seq,
        ts=ts,
        actor=cast(ActorLiteral, actor),
        kind=cast(KindLiteral, kind),
        payload=dict(payload),
        content_hash=content_hash,
        correlation_id=correlation_id,
        branch_id=branch_id,
        interaction_id=interaction_id,
        agent_id=agent_id,
        execution_state=cast(ExecutionStateLiteral | None, execution_state),
        source_line=source_line,
        source_record_hash=source_record_hash,
        original_id=original_id,
        source_adapter=source_adapter,
        source_location=source_location,
        extra_fields=extra_fields,
    )


def parse_session(obj: Mapping[str, Any]) -> Session:
    """Parse a full session structure from a mapping.

    Accepts either framed mapping `{"header": {...}, "events": [...]}`
    or flat session dictionary `{"schema_version": ..., "session_id": ..., "events": [...]}`.
    """
    if not isinstance(obj, Mapping):
        raise SchemaError(f"Session object must be a mapping, got {type(obj).__name__}")

    if "events" not in obj:
        raise SchemaError("Missing required field 'events' in session")

    raw_events = obj["events"]
    if not isinstance(raw_events, (list, tuple)):
        raise SchemaError(
            f"Field 'events' must be a list or tuple, got {type(raw_events).__name__}"
        )

    header_input: Mapping[str, Any]
    extra_fields: dict[str, Any] = {}
    if "header" in obj:
        for key, val in obj.items():
            if key not in ("header", "events"):
                if key.startswith("experimental_"):
                    extra_fields[key] = val
                else:
                    raise UnknownFieldError(
                        f"Unknown top-level field in session: '{key}'",
                        field_name=key,
                    )
        raw_header = obj["header"]
        if not isinstance(raw_header, Mapping):
            raise SchemaError(f"Field 'header' must be a mapping, got {type(raw_header).__name__}")
        header_input = raw_header
    else:
        header_input = {k: v for k, v in obj.items() if k != "events"}

    header = parse_session_header(header_input)

    seen_ids: set[str] = set()
    events: list[SessionEvent] = []
    for event_obj in raw_events:
        events.append(parse_session_event(event_obj, seen_ids=seen_ids))

    return Session(header=header, events=tuple(events), extra_fields=extra_fields)


def parse_session_lines(lines: Iterable[str]) -> Session:
    """Parse line-delimited session (JSONL) with header on line 1 and events below."""
    header: SessionHeader | None = None
    seen_ids: set[str] = set()
    events: list[SessionEvent] = []

    for line_idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        if header is None:
            try:
                header_obj = json.loads(stripped)
            except json.JSONDecodeError as err:
                raise SchemaError(
                    f"Malformed JSON on header line (line {line_idx}): {err}"
                ) from err
            header = parse_session_header(header_obj)
        else:
            try:
                event_obj = json.loads(stripped)
            except json.JSONDecodeError as err:
                raise SchemaError(f"Malformed JSON on event line {line_idx}: {err}") from err
            events.append(parse_session_event(event_obj, seen_ids=seen_ids))

    if header is None:
        raise SchemaError("Session stream contains no records")

    return Session(header=header, events=tuple(events))


def load_session_file(path: str | Path) -> Session:
    """Load and validate a canonical session file (.json or .jsonl).

    Rejects files larger than 100 MB, directing caller to streaming reader.
    Normalizes CRLF and UTF-8-BOM encodings.
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"Session file not found: {file_path}")

    file_size = file_path.stat().st_size
    if file_size > MAX_NON_STREAMING_BYTES:
        raise SchemaError(
            f"File size {file_size} bytes exceeds maximum non-streaming limit "
            f"({MAX_NON_STREAMING_BYTES} bytes); use streaming reader (TASK-005)"
        )

    try:
        text = file_path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as err:
        raise SchemaError(f"File encoding is not valid UTF-8: {err}") from err

    stripped = text.strip()
    if not stripped:
        raise SchemaError(f"Session file is empty: {file_path}")

    # If file contains a single JSON object containing "events"
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
            if isinstance(data, Mapping) and "events" in data:
                return parse_session(data)
        except json.JSONDecodeError:
            # Fall back to line-by-line parsing if not a single document
            pass

    return parse_session_lines(text.splitlines())


def dump_session(session: Session) -> str:
    """Serialize a session to canonical JSONL framing (header line 1 + event per line)."""
    header_json = to_canonical_json(session.header)
    if not session.events:
        return header_json + "\n"
    event_lines = [to_canonical_json(ev) for ev in session.events]
    return header_json + "\n" + "\n".join(event_lines) + "\n"


def dump_session_file(session: Session, path: str | Path) -> None:
    """Write canonical session to file using UTF-8 encoding."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(dump_session(session), encoding="utf-8")


def get_session_schema_path() -> Path:
    """Return the filesystem path to schemas/sesslint.session.v1.json."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    dev_path = repo_root / "schemas" / "sesslint.session.v1.json"
    if dev_path.is_file():
        return dev_path
    prefix_path = Path(sys.prefix) / "share" / "sesslint" / "schemas" / "sesslint.session.v1.json"
    if prefix_path.is_file():
        return prefix_path
    return dev_path


def load_session_schema() -> dict[str, Any]:
    """Load the committed JSON Schema for sesslint.session/v1 as a dict."""
    schema_path = get_session_schema_path()
    if not schema_path.is_file():
        raise FileNotFoundError(f"Canonical session schema not found at {schema_path}")
    return cast(dict[str, Any], json.loads(schema_path.read_text(encoding="utf-8")))
