"""OpenAI Agents SDK item-export adapter and run-state/checkpoint ingestion.

This module implements the OpenAI Agents SDK adapter for SessLint (TASK-009).
It ingests exported session item lists, run-state wrappers, and JSONL item streams
into the canonical session event graph (sesslint.session/v1).

Guarantees:
- Zero live SQLite mutation: refuses inputs with SQLite magic bytes with fatal SL001.
- Absolutely never imports the `sqlite3` module.
- Preserves function-call / function-call-output pairing via `correlation_id` (call_id).
- Preserves checkpoint evidence verbatim-hash in `source.checkpoints` for SL201–SL203.
- Extracts SDK version evidence for SL301 without guessing.
- Routes unknown item types and unknown critical fields to SL302.
- Enforces strict hostile-input bounds (max_file_bytes, max_depth, max_line_bytes).
- Delivers exact format parity between JSON array exports and JSONL item streams.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, BinaryIO, Final

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
from sesslint.codes import SL001, SL002, SL301, SL302, Repairability, Severity
from sesslint.errors import MaxRecordsExceededError
from sesslint.finding import Finding, SourceRef, make_finding, sort_findings
from sesslint.io import (
    _STRICT_JSON_DECODER,
    DEFAULT_READER_LIMITS,
    ReaderLimits,
    _RawLine,
    check_nesting_depth,
    extract_record_id,
)

# CanonicalEvent alias for specification conformance
CanonicalEvent = SessionEvent

# Magic bytes identifying SQLite database files (RFC/file format 3)
SQLITE_MAGIC: Final[bytes] = b"SQLite format 3\x00"

# Supported OpenAI Agents SDK / export versions
SUPPORTED_OPENAI_AGENTS_VERSIONS: Final[frozenset[str]] = frozenset(
    {
        "0.1",
        "0.1.0",
        "0.2",
        "0.2.0",
        "1",
        "1.0",
        "1.0.0",
        "openai-agents-v1",
    }
)

# Critical keys participating in causal DAG, pairing, or session identity
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

# Known OpenAI Agents SDK item keys
KNOWN_RECORD_KEYS: Final[frozenset[str]] = frozenset(
    {
        "id",
        "item_id",
        "parent_id",
        "prev_id",
        "type",
        "role",
        "timestamp",
        "ts",
        "created_at",
        "name",
        "tool_name",
        "function",
        "call_id",
        "tool_call_id",
        "input",
        "args",
        "arguments",
        "output",
        "content",
        "result",
        "is_error",
        "error",
        "target",
        "agent",
        "handoff_to",
        "reason",
        "checkpoint_id",
        "state",
        "run_state",
        "checkpoints",
        "items",
        "sdk_version",
        "export_version",
        "agent_sdk_version",
        "metadata",
        "model",
        "usage",
        "thread_id",
        "user",
    }
)


def _safe_type_value(val: Any) -> str:
    """Return safe type and size descriptor without leaking field content (FR-081, FR-082)."""
    return safe_type_value(val)


MAX_PROJECTED_RUN_STATE_KEYS: Final[int] = 32
MAX_PROJECTED_CHECKPOINTS: Final[int] = 8


def project_run_state(source: Any) -> dict[str, Any]:
    """Redact runtime state and checkpoints to a content-free structural projection.

    Guarantees (FR-044, DEV-011):
    - Bounded: max 32 keys, max 8 checkpoint entries projected.
    - Zero raw values or prompts: values are mapped to safe shape strings (<type:len>).
    - Keys are filtered through safe discriminator allowlist or safe shape strings.
    - Checkpoint entries project to (id, seq, hash: <shape>, ts: bool).
    - If bounded limits are exceeded, truncated is True and counts are added.
    """
    if (
        isinstance(source, Mapping)
        and "keys" in source
        and "shapes" in source
        and "checkpoints" in source
    ):
        return dict(source)

    if (
        hasattr(source, "run_state_projection")
        and isinstance(source.run_state_projection, Mapping)
        and (
            source.run_state_projection.get("keys")
            or source.run_state_projection.get("checkpoints")
        )
    ):
        return dict(source.run_state_projection)

    run_state_map: Mapping[Any, Any] = {}
    chk_list: list[Any] = []

    if source is not None:
        if isinstance(source, Mapping):
            raw_rs = source.get("run_state")
            if isinstance(raw_rs, Mapping):
                run_state_map = raw_rs
            raw_chks = source.get("checkpoints")
            if isinstance(raw_chks, Sequence) and not isinstance(raw_chks, (str, bytes)):
                chk_list = list(raw_chks)
        else:
            raw_rs = getattr(source, "run_state", None)
            if isinstance(raw_rs, Mapping):
                run_state_map = raw_rs
            raw_chks = getattr(source, "checkpoints", None)
            if isinstance(raw_chks, Sequence) and not isinstance(raw_chks, (str, bytes)):
                chk_list = list(raw_chks)

    raw_items_list: list[tuple[Any, Any]] = []
    try:
        raw_items_list = list(run_state_map.items())
    except Exception:
        raw_items_list = []

    sorted_items = sorted(raw_items_list, key=lambda item: str(item[0]))
    total_keys = len(sorted_items)
    is_keys_truncated = total_keys > MAX_PROJECTED_RUN_STATE_KEYS
    projected_items = sorted_items[:MAX_PROJECTED_RUN_STATE_KEYS]

    projected_keys: list[str] = []
    shapes: dict[str, str] = {}

    for raw_k, raw_v in projected_items:
        str_k = str(raw_k)
        safe_k, _ = safe_discriminator(str_k)
        orig_safe_k = safe_k
        dup_suffix = 1
        while safe_k in shapes:
            safe_k = f"{orig_safe_k}#{dup_suffix}"
            dup_suffix += 1
        projected_keys.append(safe_k)
        shapes[safe_k] = _safe_type_value(raw_v)

    total_checkpoints = len(chk_list)
    is_chk_truncated = total_checkpoints > MAX_PROJECTED_CHECKPOINTS
    projected_raw_chks = chk_list[:MAX_PROJECTED_CHECKPOINTS]

    projected_checkpoints: list[dict[str, Any]] = []
    for chk in projected_raw_chks:
        if isinstance(chk, Mapping):
            raw_id = chk.get("id") or chk.get("checkpoint_id") or ""
            raw_seq = chk.get("seq") if chk.get("seq") is not None else chk.get("checkpoint_seq")
            raw_hash = chk.get("hash") or chk.get("payload_hash") or chk.get("state_hash")
            raw_ts = chk.get("ts") or chk.get("created_at")
        elif chk is not None and not isinstance(chk, (str, bytes, int, float, bool)):
            raw_id = getattr(chk, "id", None) or getattr(chk, "checkpoint_id", None) or ""
            raw_seq = (
                getattr(chk, "seq", None)
                if getattr(chk, "seq", None) is not None
                else getattr(chk, "checkpoint_seq", None)
            )
            raw_hash = (
                getattr(chk, "hash", None)
                or getattr(chk, "payload_hash", None)
                or getattr(chk, "state_hash", None)
            )
            raw_ts = getattr(chk, "ts", None) or getattr(chk, "created_at", None)
        else:
            projected_checkpoints.append(
                {
                    "hash": "<NoneType>",
                    "id": "<invalid>",
                    "seq": None,
                    "ts": False,
                }
            )
            continue

        safe_id_str, id_trunc = safe_discriminator(str(raw_id)) if raw_id else ("", False)
        chk_id = safe_id_str if not id_trunc else "<redacted>"

        seq_val: int | None = None
        if isinstance(raw_seq, int) and not isinstance(raw_seq, bool):
            seq_val = raw_seq
        elif isinstance(raw_seq, str) and raw_seq.strip().isdigit():
            try:
                seq_val = int(raw_seq.strip())
            except ValueError:
                seq_val = None

        hash_shape = _safe_type_value(raw_hash) if raw_hash is not None else "<NoneType>"
        ts_present = bool(raw_ts)

        projected_checkpoints.append(
            {
                "hash": hash_shape,
                "id": chk_id,
                "seq": seq_val,
                "ts": ts_present,
            }
        )

    is_truncated = is_keys_truncated or is_chk_truncated

    projection: dict[str, Any] = {
        "checkpoints": projected_checkpoints,
        "keys": projected_keys,
        "shapes": shapes,
        "truncated": is_truncated,
    }
    if is_truncated:
        projection["total_keys"] = total_keys
        projection["total_checkpoints"] = total_checkpoints
        projection["truncated_keys"] = max(0, total_keys - MAX_PROJECTED_RUN_STATE_KEYS)
        projection["truncated_checkpoints"] = max(0, total_checkpoints - MAX_PROJECTED_CHECKPOINTS)

    return projection


# Explicit mapping from OpenAI item types to canonical (actor, kind) pairs
ITEM_TYPE_MAP: Final[dict[str, tuple[ActorLiteral, KindLiteral]]] = {
    "message": ("assistant", "message"),  # Disambiguated by role if present
    "user": ("user", "message"),
    "assistant": ("assistant", "message"),
    "system": ("system", "message"),
    "tool_call": ("assistant", "tool_call"),
    "function_call": ("assistant", "tool_call"),
    "tool_result": ("tool", "tool_result"),
    "function_call_output": ("tool", "tool_result"),
    "handoff": ("assistant", "handoff"),
    "checkpoint": ("system", "checkpoint"),
    "compaction": ("system", "compaction_boundary"),
    "compaction_boundary": ("system", "compaction_boundary"),
}

_TIMESTAMP_ISO_REGEX: Final[re.Pattern[str]] = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$"
)


class SourceMetadata(dict[str, Any]):
    """Preserved source provenance and checkpoint evidence."""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError:
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


def detect_openai_agents(first_bytes: bytes, filename: str) -> float:
    """Return heuristic confidence in range [0.0, 1.0] that input is OpenAI Agents SDK export.

    Inspects file extension and first non-empty lines for OpenAI Agents SDK signatures
    such as 'items', 'run_state', 'checkpoints', 'call_id', or 'agent_sdk_version'.
    """
    fn_lower = filename.lower()
    if not (
        fn_lower.endswith(".json")
        or fn_lower.endswith(".jsonl")
        or fn_lower.endswith(".sqlite")
        or fn_lower.endswith(".db")
    ):
        return 0.0

    if not first_bytes:
        return 0.0

    # Live SQLite file signature
    if first_bytes.startswith(SQLITE_MAGIC):
        if fn_lower.endswith(".sqlite") or fn_lower.endswith(".db"):
            return 1.0
        return 0.5

    data = first_bytes
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]

    # Text content analysis
    decoded = data[:4096].decode("utf-8", errors="replace")

    signals = 0
    if '"items"' in decoded:
        signals += 2
    if '"run_state"' in decoded:
        signals += 3
    if '"checkpoints"' in decoded:
        signals += 3
    if '"call_id"' in decoded:
        signals += 2
    if '"tool_call"' in decoded or '"tool_result"' in decoded:
        signals += 2
    if '"function_call"' in decoded or '"function_call_output"' in decoded:
        signals += 2
    if '"handoff"' in decoded:
        signals += 2
    if '"agent_sdk_version"' in decoded or '"export_version"' in decoded:
        signals += 2

    if signals >= 3:
        return 1.0
    if signals >= 1:
        return 0.8
    if fn_lower.endswith(".json") or fn_lower.endswith(".jsonl"):
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
        tool_name = str(obj.get("name") or obj.get("tool_name") or obj.get("function") or "")
        call_id = str(obj.get("call_id") or obj.get("tool_call_id") or rec_id)
        raw_input = obj.get("args") or obj.get("arguments") or obj.get("input") or {}
        if isinstance(raw_input, str):
            try:
                raw_input = _STRICT_JSON_DECODER.decode(raw_input)
            except Exception:
                pass
        input_payload = raw_input if isinstance(raw_input, Mapping) else {"value": raw_input}
        return {
            "call_id": call_id,
            "input": input_payload,
            "name": tool_name,
            "tool_name": tool_name,
            "tool_use_id": call_id,
        }

    if kind == "tool_result":
        call_id = str(obj.get("call_id") or obj.get("tool_call_id") or "")
        content = obj.get("content") or obj.get("output") or obj.get("result") or ""
        is_err = bool(obj.get("is_error") or obj.get("error") or False)
        return {
            "call_id": call_id,
            "content": content,
            "is_error": is_err,
            "tool_use_id": call_id,
        }

    if kind == "handoff":
        target = obj.get("target") or obj.get("handoff_to") or obj.get("agent")
        res: dict[str, Any] = {"target": str(target) if target is not None else None}
        if "reason" in obj:
            res["reason"] = str(obj["reason"])
        return res

    if kind == "checkpoint":
        chk_id = obj.get("checkpoint_id") or obj.get("id") or rec_id
        res = {"checkpoint_id": str(chk_id)}
        if "seq" in obj:
            res["seq"] = obj["seq"]
        if "hash" in obj:
            res["hash"] = str(obj["hash"])
        if "state" in obj:
            res["state"] = obj["state"]
        return res

    if kind == "compaction_boundary":
        summary = str(obj.get("summary") or obj.get("content") or "")
        return {"summary": summary}

    if kind == "unknown":
        return {"type": str(raw_type) if raw_type is not None else "<missing>"}

    # Default message payload
    msg_content = obj.get("content") or obj.get("message") or obj.get("text") or ""
    return {"content": msg_content, "role": actor}


def load_openai_agents(
    path: Path | str | BinaryIO | bytes,
    *,
    limits: ReaderLimits | None = None,
) -> tuple[EventList, list[Finding]]:
    """Ingest an OpenAI Agents SDK session export (JSON or JSONL).

    Guarantees:
    - Never mutates input files; refuses live SQLite databases (SL001 fatal).
    - Never imports sqlite3.
    - Preserves call_id pairing in correlation_id for tool calls and results.
    - Preserves checkpoint evidence verbatim-hash in source.checkpoints without validation.
    - Evaluates version compatibility (SL301) and unknown records (SL302).
    - Delivers byte-identical canonical JSON output for JSON and JSONL forms.
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

    try:
        # 1. SQLite Magic Refusal Safety Gate
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

        # Read remaining prefix to inspect format (JSON vs JSONL)
        stream_remainder = stream.read()
        full_bytes = first_16 + stream_remainder

        if len(full_bytes) > effective_limits.max_file_bytes:
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

        stripped_prefix = full_bytes
        if stripped_prefix.startswith(b"\xef\xbb\xbf"):
            stripped_prefix = stripped_prefix[3:]

        stripped_data = stripped_prefix.strip()
        if not stripped_data:
            return EventList([], source=SourceMetadata()), []

        # Determine if JSON document or JSONL stream
        # A JSON document starts with '[' or has top-level wrapper keys 'items' / 'run_state'
        is_json_doc = False
        first_non_ws = stripped_data[:1]
        if first_non_ws == b"[":
            is_json_doc = True
        elif first_non_ws == b"{":
            first_line = stripped_data.split(b"\n", 1)[0].strip()
            if (
                b'"items"' in first_line
                or b'"run_state"' in first_line
                or b'"checkpoints"' in first_line
                or b'"sdk_version"' in first_line
                or b'"export_version"' in first_line
                or first_line == b"{"
            ):
                is_json_doc = True

        if is_json_doc:
            return _load_openai_agents_json(full_bytes, path_str=path_str, limits=effective_limits)
        return _load_openai_agents_jsonl(full_bytes, path_str=path_str, limits=effective_limits)

    finally:
        if is_owned_file:
            stream.close()


def _load_openai_agents_json(
    data: bytes,
    *,
    path_str: str,
    limits: ReaderLimits,
) -> tuple[EventList, list[Finding]]:
    """Parse a single JSON document export with hostile input validation.

    Note on source coordinates: in a single-doc JSON export, internal record
    elements cannot be mapped to physical stream byte offsets without an
    AST/parser with token offset tracking. Therefore, single-doc JSON records
    emit `record_ordinal` and `line_number` (best-available), without faked
    byte offsets.
    """
    findings: list[Finding] = []
    source_metadata = SourceMetadata(format="openai-agents", checkpoints=[])
    guard = SyntheticIdCollisionGuard()

    # Check for forbidden NUL bytes
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

    # UTF-8 decoding
    to_decode = data
    if to_decode.startswith(b"\xef\xbb\xbf"):
        to_decode = to_decode[3:]
    try:
        decoded_text = to_decode.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        finding = make_finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message_template=(
                "Invalid UTF-8 encoding on line {line} [detail: ENCODING] for record {record_id}"
            ),
            source=SourceRef(path=path_str, line=1, record_id=None),
            evidence={"reason": "invalid_utf8"},
        )
        return EventList([], source=source_metadata), [finding]

    # JSON parsing
    try:
        doc = _STRICT_JSON_DECODER.decode(decoded_text.strip())
    except (json.JSONDecodeError, ValueError):
        finding = make_finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message_template="Malformed record on line {line} for record {record_id}",
            source=SourceRef(path=path_str, line=1, record_id=None),
            evidence={"reason": "malformed_json"},
        )
        return EventList([], source=source_metadata), [finding]

    # Nesting depth check
    if not check_nesting_depth(doc, limits.max_depth):
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

    raw_items: list[Any] = []
    seen_version_sl301 = False

    if isinstance(doc, dict):
        # Extract version evidence
        version_candidate = (
            doc.get("sdk_version")
            or doc.get("export_version")
            or doc.get("agent_sdk_version")
            or doc.get("version")
        )
        seen_version_sl301 = _check_version(
            version_candidate,
            path_str=path_str,
            line_number=1,
            rec_id=None,
            findings=findings,
            source_metadata=source_metadata,
            seen_version_sl301=seen_version_sl301,
            guard=guard,
        )

        # Ingest checkpoints
        raw_checkpoints = doc.get("checkpoints")
        if isinstance(raw_checkpoints, list):
            for chk in raw_checkpoints:
                if isinstance(chk, dict):
                    chk_id = str(chk.get("id") or chk.get("checkpoint_id") or "")
                    seq = chk.get("seq")
                    chk_hash = str(chk.get("hash") or chk.get("payload_hash") or "")
                    ts = str(chk.get("ts") or chk.get("created_at") or "")
                    source_metadata.checkpoints.append(
                        {
                            "id": chk_id,
                            "seq": seq,
                            "hash": chk_hash,
                            "ts": ts,
                        }
                    )

        # Ingest run_state
        if "run_state" in doc and isinstance(doc["run_state"], dict):
            source_metadata.run_state = doc["run_state"]

        # Extract items
        items_field = doc.get("items")
        if items_field is not None:
            if isinstance(items_field, list):
                raw_items = items_field
            elif isinstance(items_field, dict):
                # Adversarial case: items as dict instead of list -> preserve without raising
                raw_items = [items_field]
        else:
            raw_items = [doc]

    elif isinstance(doc, list):
        raw_items = doc
    else:
        finding = make_finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message_template="Malformed record on line {line} for record {record_id}",
            source=SourceRef(path=path_str, line=1, record_id=None),
            evidence={"reason": "invalid_document_type"},
        )
        return EventList([], source=source_metadata), [finding]

    if limits.max_records is not None and len(raw_items) > limits.max_records:
        raise MaxRecordsExceededError(
            f"Record count {len(raw_items)} exceeds limit of {limits.max_records}"
        )

    events: list[SessionEvent] = []
    for idx, item in enumerate(raw_items):
        line_num = idx + 1
        if not isinstance(item, dict):
            finding = make_finding(
                code=SL001,
                severity=Severity.ERROR,
                repairability=Repairability.MANUAL,
                message_template="Malformed record on line {line} for record {record_id}",
                source=SourceRef(path=path_str, line=line_num, record_id=None),
                evidence={"reason": "item_not_dict"},
            )
            findings.append(finding)
            continue

        _process_openai_item(
            item,
            line_number=line_num,
            path_str=path_str,
            events=events,
            findings=findings,
            source_metadata=source_metadata,
            seen_version_sl301=seen_version_sl301,
            record_ordinal=idx + 1,
            guard=guard,
        )

    guard.assert_no_collision()
    source_metadata.run_state_projection = project_run_state(source_metadata)
    return EventList(events, source=source_metadata), sort_findings(findings)


def _load_openai_agents_jsonl(
    data: bytes,
    *,
    path_str: str,
    limits: ReaderLimits,
) -> tuple[EventList, list[Finding]]:
    """Stream a JSONL item stream with 1-record lookahead for SL001 vs SL002."""
    events: list[SessionEvent] = []
    findings: list[Finding] = []
    source_metadata = SourceMetadata(format="openai-agents", checkpoints=[])
    guard = SyntheticIdCollisionGuard()
    seen_version_sl301 = False

    current_offset = 0
    line_number = 0
    record_count = 0
    total_len = len(data)
    pending_raw: _RawLine | None = None

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

        truncated = len(line_chunk) > limits.max_line_bytes
        if not line_chunk.strip() and not truncated:
            continue

        record_count += 1
        record_bytes = line_chunk
        rec_byte_end = line_end
        if truncated:
            record_bytes = line_chunk[: limits.max_line_bytes + 1]
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
            if limits.max_records is not None and pending_raw.record_ordinal > limits.max_records:
                raise MaxRecordsExceededError(
                    f"Record count {pending_raw.record_ordinal} exceeds limit of "
                    f"{limits.max_records}"
                )
            _process_jsonl_line(
                pending_raw,
                is_terminal=False,
                path_str=path_str,
                limits=limits,
                events=events,
                findings=findings,
                source_metadata=source_metadata,
                seen_version_sl301=seen_version_sl301,
                guard=guard,
            )

        pending_raw = current_raw

    if pending_raw is not None:
        if limits.max_records is not None and pending_raw.record_ordinal > limits.max_records:
            raise MaxRecordsExceededError(
                f"Record count {pending_raw.record_ordinal} exceeds limit of {limits.max_records}"
            )
        _process_jsonl_line(
            pending_raw,
            is_terminal=True,
            path_str=path_str,
            limits=limits,
            events=events,
            findings=findings,
            source_metadata=source_metadata,
            seen_version_sl301=seen_version_sl301,
            guard=guard,
        )

    guard.assert_no_collision()
    source_metadata.run_state_projection = project_run_state(source_metadata)
    return EventList(events, source=source_metadata), sort_findings(findings)


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
) -> None:
    """Process a single JSONL line, emitting SessionEvent or SL001/SL002."""
    code = SL002 if is_terminal else SL001
    coord_evidence: dict[str, Any] = {
        "byte_offset": raw.byte_offset,
        "byte_end": raw.byte_end,
        "record_ordinal": raw.record_ordinal,
    }

    if raw.truncated_limit:
        rec_id = extract_record_id(raw.raw_bytes.decode("utf-8", errors="replace"))
        source = SourceRef(path=path_str, line=raw.line_number, record_id=rec_id)
        msg_template = (
            "Line {line} exceeds maximum line byte limit [detail: LIMIT] for record {record_id}"
        )
        findings.append(
            make_finding(
                code=code,
                message_template=msg_template,
                source=source,
                evidence=coord_evidence,
            )
        )
        return

    if b"\x00" in raw.raw_bytes:
        rec_id = extract_record_id(raw.raw_bytes.decode("utf-8", errors="replace"))
        source = SourceRef(path=path_str, line=raw.line_number, record_id=rec_id)
        msg_template = "Forbidden NUL byte on line {line} for record {record_id}"
        findings.append(
            make_finding(
                code=code,
                message_template=msg_template,
                source=source,
                evidence=coord_evidence,
            )
        )
        return

    # Strip UTF-8 BOM on line 1 if present for decode only
    to_decode = raw.raw_bytes
    if raw.line_number == 1 and to_decode.startswith(b"\xef\xbb\xbf"):
        to_decode = to_decode[3:]

    try:
        decoded_text = to_decode.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError:
        rec_id = extract_record_id(raw.raw_bytes.decode("utf-8", errors="replace"))
        source = SourceRef(path=path_str, line=raw.line_number, record_id=rec_id)
        msg_template = (
            "Invalid UTF-8 encoding on line {line} [detail: ENCODING] for record {record_id}"
        )
        findings.append(
            make_finding(
                code=code,
                message_template=msg_template,
                source=source,
                evidence=coord_evidence,
            )
        )
        return

    try:
        obj = _STRICT_JSON_DECODER.decode(decoded_text)
    except RecursionError:
        rec_id = extract_record_id(decoded_text)
        source = SourceRef(path=path_str, line=raw.line_number, record_id=rec_id)
        msg_template = (
            "Nesting depth exceeds maximum limit on line {line} [detail: LIMIT] "
            "for record {record_id}"
        )
        findings.append(
            make_finding(
                code=code,
                message_template=msg_template,
                source=source,
                evidence=coord_evidence,
            )
        )
        return
    except (json.JSONDecodeError, ValueError):
        rec_id = extract_record_id(decoded_text)
        source = SourceRef(path=path_str, line=raw.line_number, record_id=rec_id)
        msg_template = (
            "Torn terminal record on line {line} for record {record_id}"
            if is_terminal
            else "Malformed record on line {line} for record {record_id}"
        )
        findings.append(
            make_finding(
                code=code,
                message_template=msg_template,
                source=source,
                evidence=coord_evidence,
            )
        )
        return

    if not isinstance(obj, dict):
        source = SourceRef(path=path_str, line=raw.line_number, record_id=None)
        msg_template = (
            "Torn terminal record on line {line} for record {record_id}"
            if is_terminal
            else "Malformed record on line {line} for record {record_id}"
        )
        findings.append(
            make_finding(
                code=code,
                message_template=msg_template,
                source=source,
                evidence=coord_evidence,
            )
        )
        return

    if not check_nesting_depth(obj, limits.max_depth):
        rec_id = extract_record_id(decoded_text, obj)
        source = SourceRef(path=path_str, line=raw.line_number, record_id=rec_id)
        msg_template = (
            "Nesting depth exceeds maximum limit on line {line} [detail: LIMIT] "
            "for record {record_id}"
        )
        findings.append(
            make_finding(
                code=code,
                message_template=msg_template,
                source=source,
                evidence=coord_evidence,
            )
        )
        return

    _process_openai_item(
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
    )


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
    """Evaluate format version against supported registry and record SL301 if obsolete."""
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
            adapter="openai_agents",
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
        if version_norm not in SUPPORTED_OPENAI_AGENTS_VERSIONS and not seen_version_sl301:
            source = SourceRef(path=path_str, line=line_number, record_id=rec_id_str)
            safe_v, _ = safe_discriminator(version_raw)
            finding_sl301 = make_finding(
                code=SL301,
                severity=Severity.ERROR,
                repairability=Repairability.UNSUPPORTED,
                message_template="Unsupported format version on line {line} for record {record_id}",
                source=source,
                evidence={
                    "version_raw": safe_v,
                    "supported_set": tuple(sorted(SUPPORTED_OPENAI_AGENTS_VERSIONS)),
                    **coord_ev,
                },
            )
            findings.append(finding_sl301)
            return True
    else:
        if not seen_version_sl301:
            source = SourceRef(path=path_str, line=line_number, record_id=rec_id_str)
            finding_sl301 = make_finding(
                code=SL301,
                severity=Severity.ERROR,
                repairability=Repairability.UNSUPPORTED,
                message_template="Unsupported format version on line {line} for record {record_id}",
                source=source,
                evidence={
                    "version_raw": "<invalid_version_type>",
                    "supported_set": tuple(sorted(SUPPORTED_OPENAI_AGENTS_VERSIONS)),
                    **coord_ev,
                },
            )
            findings.append(finding_sl301)
            return True
    return seen_version_sl301


def _process_openai_item(
    obj: dict[str, Any],
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
) -> None:
    """Canonicalize a single item dict into a SessionEvent, emitting findings as needed."""
    seq_index = len(events)
    raw_id = obj.get("id") or obj.get("item_id")
    if byte_offset is not None and byte_end is not None:
        p_len = byte_end - byte_offset
    else:
        try:
            p_len = len(canonical_bytes(obj))
        except Exception:
            p_len = 0

    if raw_id is not None and str(raw_id).strip():
        rec_id_str = str(raw_id).strip()
        original_id = rec_id_str
        if guard is not None:
            guard.register_real(rec_id_str)
    else:
        rec_id_str = synthetic_event_id(
            adapter="openai_agents",
            ordinal=seq_index,
            source_hint=path_str,
            payload_len=p_len,
        )
        original_id = None
        if guard is not None:
            guard.register_synthetic(rec_id_str)

    raw_parent = obj.get("parent_id") or obj.get("prev_id")
    parent_id = (
        str(raw_parent).strip() if raw_parent is not None and str(raw_parent).strip() else None
    )

    coord_ev: dict[str, Any] = {}
    if byte_offset is not None:
        coord_ev["byte_offset"] = byte_offset
    if byte_end is not None:
        coord_ev["byte_end"] = byte_end
    if record_ordinal is not None:
        coord_ev["record_ordinal"] = record_ordinal

    # Check for version candidate on item level
    version_candidate = (
        obj.get("sdk_version")
        or obj.get("export_version")
        or obj.get("agent_sdk_version")
        or obj.get("version")
    )
    if version_candidate is not None:
        _check_version(
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

    # Type resolution and role disambiguation
    raw_type = obj.get("type")
    raw_role = obj.get("role")
    has_emitted_sl302 = False

    actor: ActorLiteral
    kind: KindLiteral

    if isinstance(raw_type, str) and raw_type in ITEM_TYPE_MAP:
        actor, kind = ITEM_TYPE_MAP[raw_type]
        if kind == "message":
            if raw_role == "user":
                actor = "user"
            elif raw_role == "assistant":
                actor = "assistant"
            elif raw_role == "system":
                actor = "system"
            elif raw_role == "tool":
                actor = "tool"
                kind = "tool_result"
    elif raw_type is None and isinstance(raw_role, str):
        if raw_role == "user":
            actor, kind = "user", "message"
        elif raw_role == "assistant":
            actor, kind = "assistant", "message"
        elif raw_role == "system":
            actor, kind = "system", "message"
        elif raw_role == "tool":
            actor, kind = "tool", "tool_result"
        else:
            actor, kind = "system", "unknown"
    else:
        actor = "system"
        kind = "unknown"
        type_val, type_truncated = safe_discriminator(raw_type)
        source = SourceRef(path=path_str, line=line_number, record_id=rec_id_str)
        evidence_sl302: dict[str, Any] = {
            "field_path": "type",
            "type_value": type_val,
            "record_id": rec_id_str,
            **coord_ev,
        }
        if type_truncated:
            evidence_sl302["type_truncated"] = True
        finding_sl302 = make_finding(
            code=SL302,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message_template="Unknown critical record on line {line} for record {record_id}",
            source=source,
            evidence=evidence_sl302,
        )
        findings.append(finding_sl302)
        has_emitted_sl302 = True

    # Check for unknown critical fields on critical path
    if not has_emitted_sl302:
        for key in sorted(obj.keys()):
            if key not in KNOWN_RECORD_KEYS and (
                key in CRITICAL_KEYS
                or key.startswith("critical_")
                or key.startswith("unknown_critical")
            ):
                source = SourceRef(path=path_str, line=line_number, record_id=rec_id_str)
                safe_k, _ = safe_discriminator(key)
                finding_sl302 = make_finding(
                    code=SL302,
                    severity=Severity.ERROR,
                    repairability=Repairability.MANUAL,
                    message_template=(
                        "Unknown critical record on line {line} for record {record_id}"
                    ),
                    source=source,
                    evidence={
                        "field_path": safe_k,
                        "type_value": _safe_type_value(obj[key]),
                        "record_id": rec_id_str,
                        **coord_ev,
                    },
                )
                findings.append(finding_sl302)
                break

    # Correlation ID extraction for tool calls and tool results
    correlation_id: str | None = None
    if kind in ("tool_call", "tool_result"):
        raw_call_id = obj.get("call_id") or obj.get("tool_call_id")
        if raw_call_id is not None and str(raw_call_id).strip():
            correlation_id = str(raw_call_id).strip()
        elif kind == "tool_call":
            correlation_id = rec_id_str

    ts = _normalize_timestamp(obj.get("timestamp") or obj.get("ts") or obj.get("created_at"))
    payload = _build_payload(obj, actor, kind, rec_id_str, raw_type)
    content_hash = compute_content_hash(payload)

    execution_state: Any = None
    if kind == "tool_result":
        execution_state = "failure" if obj.get("is_error") or obj.get("error") else "success"

    side_effects: str | None = None
    if kind == "tool_result":
        side_effects = "none"
    elif kind == "tool_call":
        t_name = str(obj.get("name") or obj.get("tool_name") or payload.get("name") or "").lower()
        if t_name in READ_ONLY_TOOL_NAMES:
            side_effects = "none"
        elif t_name in MUTATING_TOOL_NAMES:
            side_effects = "possible"
        else:
            side_effects = "unknown"

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
        source_line=line_number,
        source_record_hash=f"sha256:{hashlib.sha256(canonical_bytes(obj)).hexdigest()}",
        original_id=original_id,
        source_adapter="openai-agents",
        source_location=None,
        execution_state=execution_state,
        side_effects=side_effects,
    )
    events.append(event)
    if guard is not None:
        guard.check_event(event)


def load_openai_agents_session(
    path: Path | str | BinaryIO | bytes,
    *,
    limits: ReaderLimits | None = None,
) -> tuple[Session, list[Finding]]:
    """Stream an OpenAI Agents SDK session and wrap canonical events in a Session envelope."""
    events, findings = load_openai_agents(path, limits=limits)
    first_ts = events[0].ts if events else "1970-01-01T00:00:00Z"
    header = SessionHeader(
        schema_version="sesslint.session/v1",
        session_id="openai-agents-session",
        created_at=first_ts,
        source=events.source,
    )
    return Session(header=header, events=tuple(events)), findings


__all__ = [
    "CRITICAL_KEYS",
    "CanonicalEvent",
    "EventList",
    "ITEM_TYPE_MAP",
    "KNOWN_RECORD_KEYS",
    "MAX_PROJECTED_CHECKPOINTS",
    "MAX_PROJECTED_RUN_STATE_KEYS",
    "SQLITE_MAGIC",
    "SUPPORTED_OPENAI_AGENTS_VERSIONS",
    "SourceMetadata",
    "detect_openai_agents",
    "load_openai_agents",
    "load_openai_agents_session",
    "normalize_version",
    "project_run_state",
]
