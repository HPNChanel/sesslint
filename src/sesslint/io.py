"""Streaming JSONL reader with hostile-input limits, source coordinates, and SL001/SL002 detectors.

This module provides bounded-memory, length-guarded streaming over canonical session JSONL
artifacts without whole-file loads, enforcing DoS-resistant limits (FR-011, FR-013, FR-014,
FR-015, FR-016, FR-017).
"""

from __future__ import annotations

import json
import math
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Final

from sesslint.canonical import (
    SessionEvent,
    SessionHeader,
    parse_session_event,
    parse_session_header,
)
from sesslint.codes import SL001, SL002
from sesslint.errors import (
    FileTooLargeError,
    FindingError,
    HeaderMissingError,
    MaxRecordsExceededError,
    SchemaError,
    SesslintError,
)
from sesslint.finding import Finding, SourceRef, enforce_content_free_text, make_finding

DEFAULT_MAX_LINE_BYTES: Final[int] = 1_000_000
DEFAULT_MAX_DEPTH: Final[int] = 100
DEFAULT_MAX_FILE_BYTES: Final[int] = 100 * 1024 * 1024  # 100 MB
_RECORD_ID_REGEX: Final[re.Pattern[str]] = re.compile(r'"id"\s*:\s*"([^"]{1,200})"')
_CHUNK_DRAIN_SIZE: Final[int] = 65536


@dataclass(frozen=True, slots=True)
class ReaderLimits:
    """Configurable hostile-input limits for streaming JSONL parser (FR-013).

    Guarantees bounded CPU and RSS resources when ingesting untrusted session files:
    - max_line_bytes: Cap on physical JSON line size in bytes (DoS / giant-line defense).
    - max_depth: Cap on nesting depth of JSON structures (stack overflow defense).
    - max_file_bytes: Cap on total artifact size before aborting.
    - max_records: Optional cap on total records processed.
    """

    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES
    max_depth: int = DEFAULT_MAX_DEPTH
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_records: int | None = None

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_line_bytes, bool)
            or not isinstance(self.max_line_bytes, int)
            or self.max_line_bytes < 1
        ):
            raise ValueError(
                f"max_line_bytes must be a positive integer, got {self.max_line_bytes!r}"
            )
        if (
            isinstance(self.max_depth, bool)
            or not isinstance(self.max_depth, int)
            or self.max_depth < 1
        ):
            raise ValueError(f"max_depth must be a positive integer, got {self.max_depth!r}")
        if (
            isinstance(self.max_file_bytes, bool)
            or not isinstance(self.max_file_bytes, int)
            or self.max_file_bytes < 1
        ):
            raise ValueError(
                f"max_file_bytes must be a positive integer, got {self.max_file_bytes!r}"
            )
        if self.max_records is not None:
            if (
                isinstance(self.max_records, bool)
                or not isinstance(self.max_records, int)
                or self.max_records < 1
            ):
                raise ValueError(
                    f"max_records must be a positive integer or None, got {self.max_records!r}"
                )


DEFAULT_READER_LIMITS: Final[ReaderLimits] = ReaderLimits()


def _reject_constant(val: str) -> None:
    """Reject non-standard numeric constants (NaN, Infinity, -Infinity) per RFC 8785."""
    raise ValueError(f"Out-of-range or non-standard numeric constant: {val}")


def _strict_parse_float(val: str) -> float:
    """Strictly parse floating-point numbers, rejecting out-of-range overflows."""
    result = float(val)
    if math.isnan(result) or math.isinf(result):
        raise ValueError(f"Out-of-range float: {val}")
    return result


_STRICT_JSON_DECODER: Final[json.JSONDecoder] = json.JSONDecoder(
    parse_constant=_reject_constant,
    parse_float=_strict_parse_float,
)


def check_nesting_depth(obj: Any, max_depth: int) -> bool:
    """Iteratively verify that object nesting depth does not exceed max_depth.

    Uses an explicit iterative stack to guarantee zero risk of hitting Python's
    internal recursion limits or crashing the interpreter.
    """
    if not isinstance(obj, (dict, list, tuple)):
        return True

    stack: list[tuple[Any, int]] = [(obj, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            return False
        next_depth = depth + 1
        if isinstance(current, dict):
            for v in current.values():
                if isinstance(v, (dict, list, tuple)):
                    stack.append((v, next_depth))
        elif isinstance(current, (list, tuple)):
            for item in current:
                if isinstance(item, (dict, list, tuple)):
                    stack.append((item, next_depth))
    return True


def extract_record_id(raw_text: str | None, obj: Any | None = None) -> str | None:
    """Extract event record identifier best-effort from parsed dict or raw text.

    Ensures that any extracted candidate passes SessLint's content-free text
    validation before being exposed in SourceRef coordinates (FR-015, FR-081).
    """
    if isinstance(obj, dict):
        rec_id = obj.get("id")
        if isinstance(rec_id, str):
            candidate = rec_id.strip()
            if candidate:
                if len(candidate) > 200:
                    candidate = candidate[:200]
                try:
                    enforce_content_free_text(candidate, context="extracted record_id")
                    return candidate
                except FindingError:
                    return None

    if raw_text is not None:
        match = _RECORD_ID_REGEX.search(raw_text)
        if match:
            candidate = match.group(1).strip()
            if candidate:
                if len(candidate) > 200:
                    candidate = candidate[:200]
                try:
                    enforce_content_free_text(candidate, context="extracted record_id")
                    return candidate
                except FindingError:
                    return None

    return None


def _validate_stream_coordinates(byte_offset: int, byte_end: int, record_ordinal: int) -> None:
    """Validate physical stream coordinate invariants (fail-closed, DEV-006)."""
    if isinstance(byte_offset, bool) or not isinstance(byte_offset, int) or byte_offset < 0:
        raise ValueError(f"Invalid byte_offset: {byte_offset!r} (must be integer >= 0)")
    if isinstance(byte_end, bool) or not isinstance(byte_end, int) or byte_end < byte_offset:
        raise ValueError(
            f"Invalid byte_end: {byte_end!r} (must be integer >= byte_offset={byte_offset})"
        )
    if (
        isinstance(record_ordinal, bool)
        or not isinstance(record_ordinal, int)
        or record_ordinal < 1
    ):
        raise ValueError(f"Invalid record_ordinal: {record_ordinal!r} (must be integer >= 1)")


@dataclass(slots=True)
class _RawLine:
    """Internal container for a non-empty physical line read with length guards and coordinates."""

    line_number: int
    raw_bytes: bytes
    truncated_limit: bool
    byte_offset: int = 0
    byte_end: int = 0
    record_ordinal: int = 1

    def __post_init__(self) -> None:
        _validate_stream_coordinates(self.byte_offset, self.byte_end, self.record_ordinal)


def _process_line(
    raw: _RawLine,
    *,
    is_terminal: bool,
    path_str: str,
    limits: ReaderLimits,
    is_first_record: bool,
) -> SessionEvent | Finding | None:
    """Process a single non-empty physical line, enforcing hostile-input validation.

    Returns:
    - SessionEvent if valid event record.
    - None if valid session header on first non-empty line (headers are consumed).
    - Finding(SL002) if terminal line has any error (incomplete append or terminal defect).
    - Finding(SL001) if nonterminal line has any error (malformed record).
    """
    code = SL002 if is_terminal else SL001
    coord_evidence: dict[str, Any] = {
        "byte_offset": raw.byte_offset,
        "byte_end": raw.byte_end,
        "record_ordinal": raw.record_ordinal,
    }

    # 1. Check if line length exceeded max_line_bytes
    if raw.truncated_limit:
        rec_id = extract_record_id(raw.raw_bytes.decode("utf-8", errors="replace"))
        source = SourceRef(path=path_str, line=raw.line_number, record_id=rec_id)
        msg_template = (
            "Line {line} exceeds maximum line byte limit [detail: LIMIT] for record {record_id}"
        )
        return make_finding(
            code=code,
            message_template=msg_template,
            source=source,
            evidence=coord_evidence,
        )

    # 2. Check for NUL bytes in record
    if b"\x00" in raw.raw_bytes:
        rec_id = extract_record_id(raw.raw_bytes.decode("utf-8", errors="replace"))
        source = SourceRef(path=path_str, line=raw.line_number, record_id=rec_id)
        msg_template = "Forbidden NUL byte on line {line} for record {record_id}"
        return make_finding(
            code=code,
            message_template=msg_template,
            source=source,
            evidence=coord_evidence,
        )

    # 3. Check UTF-8 decoding (strip BOM on line 1 if present for decode only)
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
        return make_finding(
            code=code,
            message_template=msg_template,
            source=source,
            evidence=coord_evidence,
        )

    # 4. Strict JSON decoding (rejects NaN, Infinity, 1e999, and maps recursion depth overflow)
    try:
        obj = _STRICT_JSON_DECODER.decode(decoded_text)
    except RecursionError:
        rec_id = extract_record_id(decoded_text)
        source = SourceRef(path=path_str, line=raw.line_number, record_id=rec_id)
        msg_template = (
            "Nesting depth exceeds maximum limit on line {line} [detail: LIMIT] "
            "for record {record_id}"
        )
        return make_finding(
            code=code,
            message_template=msg_template,
            source=source,
            evidence=coord_evidence,
        )
    except (json.JSONDecodeError, ValueError):
        rec_id = extract_record_id(decoded_text)
        source = SourceRef(path=path_str, line=raw.line_number, record_id=rec_id)
        msg_template = (
            "Torn terminal record on line {line} for record {record_id}"
            if is_terminal
            else "Malformed record on line {line} for record {record_id}"
        )
        return make_finding(
            code=code,
            message_template=msg_template,
            source=source,
            evidence=coord_evidence,
        )

    # 5. Check mapping structure
    if not isinstance(obj, dict):
        rec_id = None
        source = SourceRef(path=path_str, line=raw.line_number, record_id=rec_id)
        msg_template = (
            "Torn terminal record on line {line} for record {record_id}"
            if is_terminal
            else "Malformed record on line {line} for record {record_id}"
        )
        return make_finding(
            code=code,
            message_template=msg_template,
            source=source,
            evidence=coord_evidence,
        )

    # 6. Check nesting depth limit
    if not check_nesting_depth(obj, limits.max_depth):
        rec_id = extract_record_id(decoded_text, obj)
        source = SourceRef(path=path_str, line=raw.line_number, record_id=rec_id)
        msg_template = (
            "Nesting depth exceeds maximum limit on line {line} [detail: LIMIT] "
            "for record {record_id}"
        )
        return make_finding(
            code=code,
            message_template=msg_template,
            source=source,
            evidence=coord_evidence,
        )

    # 7. Check if first non-empty record is session header
    if is_first_record and ("schema_version" in obj or "session_id" in obj):
        try:
            parse_session_header(obj)
            return None
        except (SchemaError, SesslintError):
            rec_id = extract_record_id(decoded_text, obj)
            source = SourceRef(path=path_str, line=raw.line_number, record_id=rec_id)
            msg_template = (
                "Torn terminal record on line {line} for record {record_id}"
                if is_terminal
                else "Malformed record on line {line} for record {record_id}"
            )
            return make_finding(
                code=code,
                message_template=msg_template,
                source=source,
                evidence=coord_evidence,
            )

    # 8. Event record validation (TASK-002 model)
    try:
        event = parse_session_event(obj, seen_ids=None)
        return event
    except (SchemaError, SesslintError):
        rec_id = extract_record_id(decoded_text, obj)
        source = SourceRef(path=path_str, line=raw.line_number, record_id=rec_id)
        msg_template = (
            "Torn terminal record on line {line} for record {record_id}"
            if is_terminal
            else "Malformed record on line {line} for record {record_id}"
        )
        return make_finding(
            code=code,
            message_template=msg_template,
            source=source,
            evidence=coord_evidence,
        )


def read_header(
    path: str | os.PathLike[str] | Path | BinaryIO,
    *,
    limits: ReaderLimits = DEFAULT_READER_LIMITS,
) -> SessionHeader:
    """Read and validate session header from the first non-empty line of a stream or file.

    Fast, version-gated probe that verifies session identity without loading later records.
    Enforces file size, line byte, and nesting depth limits.

    Raises:
        HeaderMissingError: If file is 0 bytes or contains no non-empty lines.
        FileTooLargeError: If file size exceeds limits.max_file_bytes.
        SchemaError: If header line violates canonical schema or version.
        FileNotFoundError: If path does not exist.
    """
    path_str: str
    stream: BinaryIO
    is_owned_file = False

    if isinstance(path, (str, os.PathLike)):
        path_obj = Path(path)
        path_str = str(path_obj).replace("\\", "/")
        if not path_obj.exists():
            raise FileNotFoundError(f"Session file not found: {path_obj}")
        if path_obj.is_dir():
            raise IsADirectoryError(f"Expected session file, got directory: {path_obj}")
        try:
            if path_obj.is_file():
                file_size = path_obj.stat().st_size
                if file_size > limits.max_file_bytes:
                    raise FileTooLargeError(
                        f"File size {file_size} bytes exceeds maximum limit "
                        f"({limits.max_file_bytes} bytes); split file into smaller sessions"
                    )
        except OSError:
            pass
        stream = open(path_obj, "rb")
        is_owned_file = True
    else:
        stream = path
        path_str = getattr(path, "name", "<stream>")
        path_str = str(path_str).replace("\\", "/")

    try:
        line_number = 0
        total_bytes_read = 0

        while True:
            line_number += 1
            chunk = stream.readline(limits.max_line_bytes + 1)
            if not chunk:
                break

            total_bytes_read += len(chunk)
            if total_bytes_read > limits.max_file_bytes:
                raise FileTooLargeError(
                    f"Stream exceeded maximum file size limit ({limits.max_file_bytes} bytes); "
                    f"split file into smaller sessions"
                )

            # Strip UTF-8 BOM on first read
            if line_number == 1 and chunk.startswith(b"\xef\xbb\xbf"):
                chunk = chunk[3:]

            if len(chunk) > limits.max_line_bytes:
                raise SchemaError(
                    f"Header line {line_number} exceeds maximum line byte limit "
                    f"({limits.max_line_bytes} bytes)"
                )

            stripped = chunk.strip()
            if not stripped:
                continue

            if b"\x00" in chunk:
                raise SchemaError(f"Forbidden NUL byte in header line {line_number}")

            try:
                decoded = chunk.decode("utf-8", errors="strict").strip()
            except UnicodeDecodeError as err:
                raise SchemaError(f"Invalid UTF-8 encoding in header line {line_number}") from err

            try:
                obj = _STRICT_JSON_DECODER.decode(decoded)
            except RecursionError as err:
                raise SchemaError(
                    f"Header nesting depth exceeds recursion limit on line {line_number}"
                ) from err
            except (json.JSONDecodeError, ValueError) as err:
                raise SchemaError(
                    f"Malformed JSON on header line (line {line_number}): {err}"
                ) from err

            if not isinstance(obj, dict):
                raise SchemaError(
                    f"Session header must be a mapping, got {type(obj).__name__} "
                    f"on line {line_number}"
                )

            if "schema_version" not in obj and "session_id" not in obj:
                raise HeaderMissingError(
                    f"First record is not a session header "
                    f"(missing schema_version/session_id): {path_str}"
                )

            if not check_nesting_depth(obj, limits.max_depth):
                raise SchemaError(
                    f"Header nesting depth exceeds limit of {limits.max_depth} "
                    f"on line {line_number}"
                )

            return parse_session_header(obj)

        raise HeaderMissingError(f"Session file is empty or contains no header: {path_str}")
    finally:
        if is_owned_file:
            stream.close()


def iter_events(
    path: str | os.PathLike[str] | Path | BinaryIO,
    *,
    limits: ReaderLimits | None = None,
) -> Iterator[SessionEvent | Finding]:
    """Stream a canonical session JSONL file line-by-line with hostile-input limits.

    Yields:
    - SessionEvent: Valid session events in document order.
    - Finding(SL001): Malformed nonterminal records (skip-and-continue).
    - Finding(SL002): Torn terminal record on the last non-empty line (deterministic suffix drop).

    Invariants:
    - Bounded RSS: At most two lines in memory at any time (1-record lookahead).
    - Exact coordinates: 1-based physical line numbers (blanks counted but skipped).
    - Tail-only SL002: Only the final non-empty line can produce SL002; mid-file broken lines
      produce SL001.
    - Content-free: Yielded findings never leak raw payloads, credentials, or control characters.
    - Safe execution: Never evaluates payload content (FR-012).

    Raises:
        HeaderMissingError: If the file is 0 bytes or contains only whitespace.
        FileTooLargeError: If file size exceeds limits.max_file_bytes.
        MaxRecordsExceededError: If record count exceeds limits.max_records.
        FileNotFoundError: If path does not exist.
    """
    effective_limits = limits if limits is not None else DEFAULT_READER_LIMITS
    path_str: str
    stream: BinaryIO
    is_owned_file = False

    if isinstance(path, (str, os.PathLike)):
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
                        f"({effective_limits.max_file_bytes} bytes); "
                        f"split file into smaller sessions"
                    )
        except OSError:
            pass
        stream = open(path_obj, "rb")
        is_owned_file = True
    else:
        stream = path
        path_str = getattr(path, "name", "<stream>")
        path_str = str(path_str).replace("\\", "/")

    try:
        line_number = 0
        total_bytes_read = 0
        record_count = 0
        pending_raw: _RawLine | None = None
        has_any_records = False

        while True:
            line_start_offset = total_bytes_read
            chunk = stream.readline(effective_limits.max_line_bytes + 1)
            if not chunk:
                break

            line_number += 1
            total_bytes_read += len(chunk)
            if total_bytes_read > effective_limits.max_file_bytes:
                raise FileTooLargeError(
                    f"Stream exceeded maximum file size limit "
                    f"({effective_limits.max_file_bytes} bytes); "
                    f"split file into smaller sessions"
                )

            truncated = False
            if len(chunk) > effective_limits.max_line_bytes:
                truncated = True
                # Drain remainder of runaway line without unbounded buffering
                if not chunk.endswith(b"\n"):
                    while True:
                        drain = stream.readline(_CHUNK_DRAIN_SIZE)
                        if not drain:
                            break
                        total_bytes_read += len(drain)
                        if total_bytes_read > effective_limits.max_file_bytes:
                            raise FileTooLargeError(
                                f"Stream exceeded maximum file size limit "
                                f"({effective_limits.max_file_bytes} bytes); "
                                f"split file into smaller sessions"
                            )
                        if drain.endswith(b"\n"):
                            break

            # Blank lines count towards physical line coordinates but are skipped
            # (unless line length exceeded max_line_bytes, which must be reported)
            if not chunk.strip() and not truncated:
                continue

            record_count += 1
            line_end_offset = line_start_offset + len(chunk)
            current_raw = _RawLine(
                line_number=line_number,
                raw_bytes=chunk,
                truncated_limit=truncated,
                byte_offset=line_start_offset,
                byte_end=line_end_offset,
                record_ordinal=record_count,
            )

            # If we had a previous non-empty line, it is definitively NONTERMINAL
            if pending_raw is not None:
                has_any_records = True
                is_first = pending_raw.record_ordinal == 1
                if (
                    effective_limits.max_records is not None
                    and pending_raw.record_ordinal > effective_limits.max_records
                ):
                    raise MaxRecordsExceededError(
                        f"Record count {pending_raw.record_ordinal} exceeds limit of "
                        f"{effective_limits.max_records}"
                    )

                item = _process_line(
                    pending_raw,
                    is_terminal=False,
                    path_str=path_str,
                    limits=effective_limits,
                    is_first_record=is_first,
                )
                if item is not None:
                    yield item

            pending_raw = current_raw

        # EOF reached: pending_raw is the final non-empty record in the stream (TERMINAL)
        if pending_raw is not None:
            has_any_records = True
            is_first = pending_raw.record_ordinal == 1
            if (
                effective_limits.max_records is not None
                and pending_raw.record_ordinal > effective_limits.max_records
            ):
                raise MaxRecordsExceededError(
                    f"Record count {pending_raw.record_ordinal} exceeds limit of "
                    f"{effective_limits.max_records}"
                )

            item = _process_line(
                pending_raw,
                is_terminal=True,
                path_str=path_str,
                limits=effective_limits,
                is_first_record=is_first,
            )
            if item is not None:
                yield item

        if not has_any_records:
            raise HeaderMissingError(f"Session file contains no records: {path_str}")

    finally:
        if is_owned_file:
            stream.close()
