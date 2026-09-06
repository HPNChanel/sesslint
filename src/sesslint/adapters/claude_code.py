"""Claude Code JSONL session adapter with version evidence and unknown record handling.

This module implements the Claude Code JSONL adapter for SessLint (TASK-008). It converts
Claude Code session JSONL artifacts into the canonical event graph (sesslint.session/v1),
extracts version evidence for detector SL301 without guessing, and routes unknown or
critical record fields to detector SL302 while preserving graph integrity.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, BinaryIO, Final

from sesslint.canonical import (
    ActorLiteral,
    KindLiteral,
    Session,
    SessionEvent,
    SessionHeader,
    canonical_bytes,
    compute_content_hash,
)
from sesslint.codes import SL001, SL002, SL301, SL302, Repairability, Severity
from sesslint.errors import FileTooLargeError, MaxRecordsExceededError
from sesslint.finding import Finding, SourceRef, make_finding, sort_findings
from sesslint.io import (
    _CHUNK_DRAIN_SIZE,
    _STRICT_JSON_DECODER,
    DEFAULT_READER_LIMITS,
    ReaderLimits,
    _RawLine,
    check_nesting_depth,
    extract_record_id,
)

# CanonicalEvent alias for compatibility with task specification
CanonicalEvent = SessionEvent

# Set of supported Claude Code versions (documented as explicit static data)
SUPPORTED_CLAUDE_VERSIONS: Final[frozenset[str]] = frozenset(
    {"1", "1.0", "1.0.0", "0.1", "0.1.0", "claude-code-v1"}
)

# Critical fields that participate in causal DAG, pairing, or session identity
CRITICAL_KEYS: Final[frozenset[str]] = frozenset(
    {
        "type",
        "parentId",
        "parent_id",
        "toolUseId",
        "tool_use_id",
        "tool_call_id",
        "unknown_critical_field",
    }
)

# Explicit mapping from Claude Code record types to canonical (actor, kind) pairs
TYPE_MAP: Final[dict[str, tuple[ActorLiteral, KindLiteral]]] = {
    "user_message": ("user", "message"),
    "user": ("user", "message"),
    "assistant_message": ("assistant", "message"),
    "assistant": ("assistant", "message"),
    "tool_use": ("assistant", "tool_call"),
    "tool_result": ("tool", "tool_result"),
    "system": ("system", "message"),
    "summary": ("system", "message"),
    "compaction": ("system", "compaction_boundary"),
    "compaction_boundary": ("system", "compaction_boundary"),
}

# Known Claude Code record keys used to distinguish standard fields from unknown fields
KNOWN_RECORD_KEYS: Final[frozenset[str]] = frozenset(
    {
        "id",
        "uuid",
        "record_id",
        "message_id",
        "parentId",
        "parent_id",
        "type",
        "timestamp",
        "ts",
        "created_at",
        "message",
        "role",
        "content",
        "text",
        "toolUse",
        "tool_use",
        "toolUseId",
        "tool_use_id",
        "tool_call_id",
        "name",
        "tool_name",
        "input",
        "args",
        "arguments",
        "toolResult",
        "tool_result",
        "output",
        "result",
        "is_error",
        "error",
        "version",
        "agentVersion",
        "schemaVersion",
        "appVersion",
        "claude_code_version",
        "sessionId",
        "session_id",
        "summary",
        "compaction",
        # Recognized decorative / non-critical metadata keys to ignore without SL302
        "theme",
        "extra_debug",
        "cost",
        "tokens",
        "model",
        "metadata",
        "prompt_tokens",
        "completion_tokens",
        "cwd",
        "git_branch",
        "duration_ms",
        "user",
    }
)

_TIMESTAMP_ISO_REGEX: Final[re.Pattern[str]] = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$"
)


def normalize_version(version: str) -> str:
    """Normalize a raw version string by stripping whitespace and leading 'v'/'V'.

    Examples:
        >>> normalize_version("1.0.0")
        '1.0.0'
        >>> normalize_version("v1.0.0")
        '1.0.0'
        >>> normalize_version("  V0.1.0  ")
        '0.1.0'
    """
    cleaned = version.strip().lower()
    if cleaned.startswith("v") and len(cleaned) > 1 and cleaned[1].isdigit():
        return cleaned[1:]
    return cleaned


def detect_claude_code(first_bytes: bytes, filename: str) -> float:
    """Return heuristic confidence in range [0.0, 1.0] that input is Claude Code JSONL.

    Inspects file extension and first non-empty lines for Claude-specific signatures
    such as 'type' matching TYPE_MAP, 'sessionId', 'toolUseId', or 'agentVersion'.
    """
    fn_lower = filename.lower()
    if not (fn_lower.endswith(".jsonl") or fn_lower.endswith(".json")):
        return 0.0

    if not first_bytes:
        return 0.0

    data = first_bytes
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]

    lines = [line.strip() for line in data.split(b"\n") if line.strip()]
    if not lines:
        return 0.0

    parsed_records = 0
    claude_signals = 0

    for raw_line in lines[:5]:
        try:
            decoded = raw_line.decode("utf-8", errors="replace")
            obj = json.loads(decoded)
        except Exception:
            continue

        if not isinstance(obj, dict):
            continue

        parsed_records += 1

        rec_type = obj.get("type")
        if isinstance(rec_type, str) and rec_type in TYPE_MAP:
            claude_signals += 2

        if "sessionId" in obj or "session_id" in obj:
            claude_signals += 1

        if "toolUseId" in obj or "tool_use_id" in obj:
            claude_signals += 2

        if "parentId" in obj:
            claude_signals += 1

        if "agentVersion" in obj or "claude_code_version" in obj:
            claude_signals += 2

    if parsed_records == 0:
        return 0.0

    if claude_signals >= 3:
        return 1.0
    if claude_signals >= 1:
        return 0.8
    if parsed_records > 0 and fn_lower.endswith(".jsonl"):
        return 0.2
    return 0.0


def _normalize_timestamp(raw_ts: Any) -> str:
    """Ensure timestamp conforms to RFC3339 UTC string format."""
    if isinstance(raw_ts, str) and raw_ts.strip():
        val = raw_ts.strip()
        if _TIMESTAMP_ISO_REGEX.match(val):
            if not val.endswith("Z") and "+" not in val and "-" not in val[10:]:
                return f"{val}Z"
            return val
    return "1970-01-01T00:00:00Z"


def _build_payload(
    obj: dict[str, Any],
    actor: ActorLiteral,
    kind: KindLiteral,
    rec_id: str,
    raw_type: Any,
) -> dict[str, Any]:
    """Construct content-structured payload based on canonical kind."""
    if kind == "tool_call":
        tool_name = str(obj.get("name") or obj.get("tool_name") or "")
        tool_use_id = str(obj.get("toolUseId") or obj.get("tool_use_id") or rec_id)
        raw_input = obj.get("input") or obj.get("args") or obj.get("arguments") or {}
        input_payload = raw_input if isinstance(raw_input, Mapping) else {"value": raw_input}
        return {
            "name": tool_name,
            "tool_name": tool_name,
            "tool_use_id": tool_use_id,
            "input": input_payload,
        }

    if kind == "tool_result":
        tool_use_id = str(obj.get("toolUseId") or obj.get("tool_use_id") or "")
        content = obj.get("content") or obj.get("output") or obj.get("result") or ""
        is_err = bool(obj.get("is_error") or obj.get("error") or False)
        return {
            "tool_use_id": tool_use_id,
            "content": content,
            "is_error": is_err,
        }

    if kind == "compaction_boundary":
        summary = str(obj.get("summary") or obj.get("content") or "")
        return {"summary": summary}

    if kind == "unknown":
        return {"type": str(raw_type) if raw_type is not None else "<missing>"}

    # Default message payload
    msg_content = obj.get("message") or obj.get("content") or obj.get("text") or ""
    return {"role": actor, "content": msg_content}


def load_claude_code(
    path: Path | str | BinaryIO,
    *,
    limits: ReaderLimits | None = None,
) -> tuple[list[SessionEvent], list[Finding]]:
    """Stream and canonicalize a Claude Code JSONL session file.

    Guarantees:
    - Enforces ReaderLimits (max_line_bytes, max_records, max_depth, max_file_bytes).
    - Preserves streaming lookahead: mid-stream malformed line -> SL001, torn tail -> SL002.
    - Unsupported format version -> SL301 (with version evidence).
    - Unknown critical record type or field -> SL302 (with field evidence, kind="unknown").
    - Unknown non-critical fields -> silently ignored (no spurious findings).
    - Returns deterministically sorted findings and canonical events in source order.

    Raises:
        FileTooLargeError: If file exceeds limits.max_file_bytes.
        MaxRecordsExceededError: If record count exceeds limits.max_records.
        FileNotFoundError: If path does not exist.
    """
    effective_limits = limits if limits is not None else DEFAULT_READER_LIMITS

    path_str: str
    stream: BinaryIO
    is_owned_file = False

    if isinstance(path, (str, os.PathLike, Path)):
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
                    raise FileTooLargeError(
                        f"File size {file_size} bytes exceeds maximum limit "
                        f"({effective_limits.max_file_bytes} bytes)"
                    )
        except OSError:
            pass
        stream = open(path_obj, "rb")
        is_owned_file = True
    else:
        stream = path
        path_str = getattr(path, "name", "<stream>")
        path_str = str(path_str).replace("\\", "/")

    events: list[SessionEvent] = []
    findings: list[Finding] = []
    seen_version_sl301 = False

    try:
        line_number = 0
        total_bytes_read = 0
        record_count = 0
        pending_raw: _RawLine | None = None

        while True:
            line_number += 1
            chunk = stream.readline(effective_limits.max_line_bytes + 1)
            if not chunk:
                break

            total_bytes_read += len(chunk)
            if total_bytes_read > effective_limits.max_file_bytes:
                raise FileTooLargeError(
                    f"Stream exceeded maximum file size limit "
                    f"({effective_limits.max_file_bytes} bytes)"
                )

            # Strip UTF-8 BOM on first line
            if line_number == 1 and chunk.startswith(b"\xef\xbb\xbf"):
                chunk = chunk[3:]

            truncated = False
            if len(chunk) > effective_limits.max_line_bytes:
                truncated = True
                if not chunk.endswith(b"\n"):
                    while True:
                        drain = stream.readline(_CHUNK_DRAIN_SIZE)
                        if not drain:
                            break
                        total_bytes_read += len(drain)
                        if total_bytes_read > effective_limits.max_file_bytes:
                            raise FileTooLargeError(
                                f"Stream exceeded maximum file size limit "
                                f"({effective_limits.max_file_bytes} bytes)"
                            )
                        if drain.endswith(b"\n"):
                            break

            if not chunk.strip() and not truncated:
                continue

            current_raw = _RawLine(
                line_number=line_number,
                raw_bytes=chunk,
                truncated_limit=truncated,
            )

            if pending_raw is not None:
                record_count += 1
                if (
                    effective_limits.max_records is not None
                    and record_count > effective_limits.max_records
                ):
                    raise MaxRecordsExceededError(
                        f"Record count {record_count} exceeds limit of "
                        f"{effective_limits.max_records}"
                    )

                _process_claude_line(
                    pending_raw,
                    is_terminal=False,
                    path_str=path_str,
                    limits=effective_limits,
                    events=events,
                    findings=findings,
                    seen_version_sl301=seen_version_sl301,
                )

            pending_raw = current_raw

        # Handle final terminal record (EOF reached)
        if pending_raw is not None:
            record_count += 1
            if (
                effective_limits.max_records is not None
                and record_count > effective_limits.max_records
            ):
                raise MaxRecordsExceededError(
                    f"Record count {record_count} exceeds limit of {effective_limits.max_records}"
                )

            _process_claude_line(
                pending_raw,
                is_terminal=True,
                path_str=path_str,
                limits=effective_limits,
                events=events,
                findings=findings,
                seen_version_sl301=seen_version_sl301,
            )

        return events, sort_findings(findings)

    finally:
        if is_owned_file:
            stream.close()


def _process_claude_line(
    raw: _RawLine,
    *,
    is_terminal: bool,
    path_str: str,
    limits: ReaderLimits,
    events: list[SessionEvent],
    findings: list[Finding],
    seen_version_sl301: bool,
) -> None:
    """Process a single physical line, emitting either SessionEvent or syntax/integrity findings."""
    code = SL002 if is_terminal else SL001

    # 1. Line length limit check
    if raw.truncated_limit:
        rec_id = extract_record_id(raw.raw_bytes.decode("utf-8", errors="replace"))
        source = SourceRef(path=path_str, line=raw.line_number, record_id=rec_id)
        msg_template = (
            "Line {line} exceeds maximum line byte limit [detail: LIMIT] for record {record_id}"
        )
        findings.append(make_finding(code=code, message_template=msg_template, source=source))
        return

    # 2. Check for NUL bytes
    if b"\x00" in raw.raw_bytes:
        rec_id = extract_record_id(raw.raw_bytes.decode("utf-8", errors="replace"))
        source = SourceRef(path=path_str, line=raw.line_number, record_id=rec_id)
        msg_template = "Forbidden NUL byte on line {line} for record {record_id}"
        findings.append(make_finding(code=code, message_template=msg_template, source=source))
        return

    # 3. UTF-8 decode
    try:
        decoded_text = raw.raw_bytes.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError:
        rec_id = extract_record_id(raw.raw_bytes.decode("utf-8", errors="replace"))
        source = SourceRef(path=path_str, line=raw.line_number, record_id=rec_id)
        msg_template = (
            "Invalid UTF-8 encoding on line {line} [detail: ENCODING] for record {record_id}"
        )
        findings.append(make_finding(code=code, message_template=msg_template, source=source))
        return

    # 4. Strict JSON decode
    try:
        obj = _STRICT_JSON_DECODER.decode(decoded_text)
    except RecursionError:
        rec_id = extract_record_id(decoded_text)
        source = SourceRef(path=path_str, line=raw.line_number, record_id=rec_id)
        msg_template = (
            "Nesting depth exceeds maximum limit on line {line} [detail: LIMIT] "
            "for record {record_id}"
        )
        findings.append(make_finding(code=code, message_template=msg_template, source=source))
        return
    except (json.JSONDecodeError, ValueError):
        rec_id = extract_record_id(decoded_text)
        source = SourceRef(path=path_str, line=raw.line_number, record_id=rec_id)
        msg_template = (
            "Torn terminal record on line {line} for record {record_id}"
            if is_terminal
            else "Malformed record on line {line} for record {record_id}"
        )
        findings.append(make_finding(code=code, message_template=msg_template, source=source))
        return

    # 5. Check object is dictionary
    if not isinstance(obj, dict):
        rec_id = None
        source = SourceRef(path=path_str, line=raw.line_number, record_id=rec_id)
        msg_template = (
            "Torn terminal record on line {line} for record {record_id}"
            if is_terminal
            else "Malformed record on line {line} for record {record_id}"
        )
        findings.append(make_finding(code=code, message_template=msg_template, source=source))
        return

    # 6. Check nesting depth
    if not check_nesting_depth(obj, limits.max_depth):
        rec_id = extract_record_id(decoded_text, obj)
        source = SourceRef(path=path_str, line=raw.line_number, record_id=rec_id)
        msg_template = (
            "Nesting depth exceeds maximum limit on line {line} [detail: LIMIT] "
            "for record {record_id}"
        )
        findings.append(make_finding(code=code, message_template=msg_template, source=source))
        return

    # 7. Extract event identity and lineage coordinates
    raw_id = obj.get("id") or obj.get("uuid") or obj.get("record_id") or obj.get("message_id")
    seq_index = len(events)
    rec_id_str = (
        str(raw_id).strip() if raw_id is not None and str(raw_id).strip() else f"rec_{seq_index}"
    )
    original_id = str(raw_id).strip() if raw_id is not None and str(raw_id).strip() else None

    raw_parent = obj.get("parentId") or obj.get("parent_id")
    parent_id = (
        str(raw_parent).strip() if raw_parent is not None and str(raw_parent).strip() else None
    )

    # 8. Version recognition and SL301 evaluation
    version_candidate = (
        obj.get("version")
        or obj.get("agentVersion")
        or obj.get("schemaVersion")
        or obj.get("appVersion")
        or obj.get("claude_code_version")
    )
    if version_candidate is not None:
        if isinstance(version_candidate, (str, int, float)):
            version_raw = str(version_candidate).strip()
            version_norm = normalize_version(version_raw)
            if version_norm not in SUPPORTED_CLAUDE_VERSIONS and not seen_version_sl301:
                source = SourceRef(path=path_str, line=raw.line_number, record_id=rec_id_str)
                finding_sl301 = make_finding(
                    code=SL301,
                    severity=Severity.ERROR,
                    repairability=Repairability.UNSUPPORTED,
                    message_template=(
                        "Unsupported format version on line {line} for record {record_id}"
                    ),
                    source=source,
                    evidence={
                        "version_raw": version_raw,
                        "supported_set": tuple(sorted(SUPPORTED_CLAUDE_VERSIONS)),
                    },
                )
                findings.append(finding_sl301)
        else:
            # Type confusion on version field (e.g. dict or list)
            if not seen_version_sl301:
                source = SourceRef(path=path_str, line=raw.line_number, record_id=rec_id_str)
                finding_sl301 = make_finding(
                    code=SL301,
                    severity=Severity.ERROR,
                    repairability=Repairability.UNSUPPORTED,
                    message_template=(
                        "Unsupported format version on line {line} for record {record_id}"
                    ),
                    source=source,
                    evidence={
                        "version_raw": "<invalid_version_type>",
                        "supported_set": tuple(sorted(SUPPORTED_CLAUDE_VERSIONS)),
                    },
                )
                findings.append(finding_sl301)

    # 9. Type canonicalization and SL302 evaluation
    raw_type = obj.get("type")
    has_emitted_sl302 = False

    if isinstance(raw_type, str) and raw_type in TYPE_MAP:
        actor, kind = TYPE_MAP[raw_type]
    else:
        actor = "system"
        kind = "unknown"
        type_val = str(raw_type) if raw_type is not None else "<missing>"
        source = SourceRef(path=path_str, line=raw.line_number, record_id=rec_id_str)
        finding_sl302 = make_finding(
            code=SL302,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message_template="Unknown critical record on line {line} for record {record_id}",
            source=source,
            evidence={
                "field_path": "type",
                "type_value": type_val,
                "record_id": rec_id_str,
            },
        )
        findings.append(finding_sl302)
        has_emitted_sl302 = True

    # 10. Check for unknown critical fields on critical path (one SL302 max per record)
    if not has_emitted_sl302:
        for key in sorted(obj.keys()):
            if key not in KNOWN_RECORD_KEYS and (
                key in CRITICAL_KEYS
                or key.startswith("critical_")
                or key.startswith("unknown_critical")
            ):
                source = SourceRef(path=path_str, line=raw.line_number, record_id=rec_id_str)
                finding_sl302 = make_finding(
                    code=SL302,
                    severity=Severity.ERROR,
                    repairability=Repairability.MANUAL,
                    message_template=(
                        "Unknown critical record on line {line} for record {record_id}"
                    ),
                    source=source,
                    evidence={
                        "field_path": key,
                        "type_value": str(obj[key]),
                        "record_id": rec_id_str,
                    },
                )
                findings.append(finding_sl302)
                break

    # 11. Timestamp and payload canonicalization
    ts = _normalize_timestamp(obj.get("timestamp") or obj.get("ts") or obj.get("created_at"))
    payload = _build_payload(obj, actor, kind, rec_id_str, raw_type)
    content_hash = compute_content_hash(payload)

    execution_state: Any = None
    if kind == "tool_result":
        execution_state = "failure" if obj.get("is_error") or obj.get("error") else "success"

    correlation_id: str | None = None
    if kind in ("tool_call", "tool_result"):
        raw_call_id = (
            obj.get("toolUseId")
            or obj.get("tool_use_id")
            or obj.get("call_id")
            or obj.get("correlation_id")
        )
        if raw_call_id is not None and str(raw_call_id).strip():
            correlation_id = str(raw_call_id).strip()
        elif kind == "tool_call":
            correlation_id = rec_id_str

    event = SessionEvent(
        id=rec_id_str,
        parent_id=parent_id,
        seq=seq_index,
        ts=ts,
        actor=actor,
        kind=kind,
        payload=payload,
        content_hash=content_hash,
        correlation_id=correlation_id,
        source_line=raw.line_number,
        source_record_hash=f"sha256:{hashlib.sha256(canonical_bytes(obj)).hexdigest()}",
        original_id=original_id,
        source_adapter="claude-code-jsonl",
        source_location=f"{Path(path_str).name}:{raw.line_number}",
        execution_state=execution_state,
    )
    events.append(event)


def load_claude_code_session(
    path: Path | str | BinaryIO,
    *,
    limits: ReaderLimits | None = None,
) -> tuple[Session, list[Finding]]:
    """Stream a Claude Code JSONL file and wrap canonical events in a Session envelope."""
    events, findings = load_claude_code(path, limits=limits)
    first_ts = events[0].ts if events else "1970-01-01T00:00:00Z"
    header = SessionHeader(
        schema_version="sesslint.session/v1",
        session_id="claude-session",
        created_at=first_ts,
        source={"format": "claude-code-jsonl"},
    )
    return Session(header=header, events=tuple(events)), findings


__all__ = [
    "CRITICAL_KEYS",
    "CanonicalEvent",
    "KNOWN_RECORD_KEYS",
    "SUPPORTED_CLAUDE_VERSIONS",
    "TYPE_MAP",
    "detect_claude_code",
    "load_claude_code",
    "load_claude_code_session",
    "normalize_version",
]
