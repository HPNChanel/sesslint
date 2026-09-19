"""Streaming JSONL reader with hostile-input limits, source coordinates, and SL001/SL002 detectors.

This module provides bounded-memory, length-guarded streaming over canonical session JSONL
artifacts without whole-file loads, enforcing DoS-resistant limits (FR-011, FR-013, FR-014,
FR-015, FR-016, FR-017).
"""

from __future__ import annotations

import codecs
import hashlib
import io
import json
import math
import mmap
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Final, Literal

from sesslint.canonical import (
    SessionEvent,
    SessionHeader,
    parse_session_event,
    parse_session_header,
)
from sesslint.codes import SL001, SL002, SL303, Repairability, Severity
from sesslint.errors import (
    FileTooLargeError,
    FindingError,
    HeaderMissingError,
    MaxRecordsExceededError,
    SchemaError,
    SesslintError,
)
from sesslint.finding import Finding, SourceRef, enforce_content_free_text, make_finding

# 8 MiB per-line bound: real vendor records (e.g. Codex custom_tool_call_output
# carrying tool output) legitimately reach ~1.5 MB, so the hostile-input line
# cap must clear that while still bounding giant-line DoS well under the
# 100 MB whole-file cap.
DEFAULT_MAX_LINE_BYTES: Final[int] = 8 * 1024 * 1024
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

_PROBE_CHUNK_BYTES: Final[int] = 1024 * 1024  # 1 MiB

EncodingProbe = Literal["nul", "utf8"]


def probe_stream_encoding(stream: BinaryIO) -> EncodingProbe | None:
    """Probe a byte stream for NUL bytes or non-UTF-8 content in bounded chunks.

    Same semantics as ``probe_text_encoding``: ``None`` when the stream decodes
    cleanly as UTF-8 with no NUL bytes, ``"nul"`` on a NUL byte, ``"utf8"`` on
    an undecodable sequence. Reads the stream once, front to back — callers
    pass a fresh or rewound stream.
    """
    decoder = codecs.getincrementaldecoder("utf-8")()
    while True:
        chunk = stream.read(_PROBE_CHUNK_BYTES)
        if not chunk:
            break
        if b"\x00" in chunk:
            return "nul"
        try:
            decoder.decode(chunk)
        except UnicodeDecodeError:
            return "utf8"
    try:
        decoder.decode(b"", final=True)
    except UnicodeDecodeError:
        return "utf8"
    return None


def probe_text_encoding(path: Path) -> EncodingProbe | None:
    """Probe a file for NUL bytes or non-UTF-8 content in bounded chunks (DW-T-11).

    Returns ``None`` when the file decodes cleanly as UTF-8 with no NUL bytes,
    ``"nul"`` when a NUL byte is found, or ``"utf8"`` when an undecodable
    sequence is found. Semantics match a whole-file read: any violation —
    head or tail — is reported. OSError propagates to the caller so it can be
    mapped into the standard I/O finding path.
    """
    with path.open("rb") as fh:
        return probe_stream_encoding(fh)


def probe_bytes_encoding(data: bytes) -> EncodingProbe | None:
    """Probe an in-memory byte buffer with the same semantics as
    ``probe_text_encoding`` — the stdin/virtual-source path (ux T-06)."""
    return probe_stream_encoding(io.BytesIO(data))


def sha256_file_bytes(path: Path, *, chunk_bytes: int = _PROBE_CHUNK_BYTES) -> str:
    """Return the SHA-256 hex digest of a file's bytes, read in bounded chunks.

    Content-hash is the correctness floor for the incremental scan cache
    (perf-scale T-02): never relies on mtime. OSError propagates so callers
    can map it into the standard I/O finding path or a cache miss.
    """
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_bytes)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


_MMAP_MIN_BYTES: Final[int] = 4 * 1024 * 1024  # 4 MiB (perf-scale T-03)
_MMAP_MIN_LINE_BYTES: Final[int] = 65536  # 64 KiB avg line to engage mmap
_MMAP_SNIFF_BYTES: Final[int] = 65536  # head sample for the line-size gate


class _MMapLineSource:
    """``readline()``-compatible byte source backed by a read-only mmap view.

    ``mmap.readline`` is unbounded in stdlib, so line iteration is
    re-implemented with ``find`` + slice: the scan happens inside the mapped
    pages without intermediate copies, and the returned bytes are sliced at
    the caller's size cap — identical bounded semantics to
    ``BufferedReader.readline(limit)``. Lifecycle is tied to the owning file
    object; nothing outside ``io.py`` sees the mapping.
    """

    __slots__ = ("_fh", "_mm", "_pos")

    def __init__(self, fh: BinaryIO, mm: mmap.mmap) -> None:
        self._fh = fh
        self._mm = mm
        self._pos = 0

    def readline(self, size: int = -1) -> bytes:
        """Return bytes up to and including the next newline, capped at ``size``.

        Mirrors ``io.BufferedReader.readline``: at EOF returns ``b""``; a
        positive cap may split a long line across consecutive calls.
        """
        if self._pos >= len(self._mm):
            return b""
        try:
            nl = self._mm.find(b"\n", self._pos)
        except (ValueError, OSError):
            return b""
        end = len(self._mm) if nl < 0 else nl + 1
        if size is not None and size >= 0:
            end = min(end, self._pos + size)
        try:
            chunk = self._mm[self._pos : end]
        except (ValueError, IndexError, OSError):
            # Mutating/shrinking source: treat as EOF; the source-mutation
            # fingerprint check reports it, matching buffered semantics.
            self._pos = len(self._mm)
            return b""
        self._pos = end
        return chunk

    def close(self) -> None:
        """Close the mapping then the backing file object."""
        try:
            self._mm.close()
        finally:
            self._fh.close()

    def __enter__(self) -> _MMapLineSource:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _open_byte_source(path: Path) -> BinaryIO | _MMapLineSource:
    """Open a line-iterating byte source — mmap only where it wins.

    mmap pays off when lines are large enough that per-line copy overhead
    dominates the buffered reader's C-level dispatch (perf-scale T-03):
    multi-MB Codex rollout records read ~30% faster through the mapping,
    while ~1 KiB lines are ~18% slower (Python-level ``find``+slice per
    line). Gate: file size ≥ ``_MMAP_MIN_BYTES`` AND average line length
    in a ``_MMAP_SNIFF_BYTES`` head sample ≥ ``_MMAP_MIN_LINE_BYTES``.
    Anything else — small files, pipes, empty files, platforms where
    mapping fails — falls back to the buffered reader. Both paths expose
    ``readline(limit)`` and ``close()`` with identical bounded semantics.
    """
    fh = open(path, "rb")
    try:
        if path.stat().st_size >= _MMAP_MIN_BYTES:
            try:
                head = fh.read(_MMAP_SNIFF_BYTES)
                fh.seek(0)
                avg_line = len(head) // (head.count(b"\n") + 1) if head else 0
                if avg_line >= _MMAP_MIN_LINE_BYTES:
                    mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
                    return _MMapLineSource(fh, mm)
            except (OSError, ValueError, BufferError):
                fh.seek(0)
    except OSError:
        pass
    return fh


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


_MAX_DUP_KEYS_PER_RECORD: Final[int] = 16


@dataclass(frozen=True, slots=True)
class DuplicateKey:
    """One duplicated JSON object key found while decoding a record (SL303).

    ``key_path`` is a schema position (``$.a.b[0].id``), never a value — safe
    for content-free evidence. ``occurrence_count`` totals the appearances of
    the key at that position; ``critical`` marks membership in the decoding
    adapter's CRITICAL_KEYS set.
    """

    key_path: str
    occurrence_count: int
    critical: bool


def decode_json_dupaware(
    text: str,
    *,
    critical_keys: frozenset[str] | None = None,
    max_dup_keys: int = _MAX_DUP_KEYS_PER_RECORD,
) -> tuple[Any, tuple[DuplicateKey, ...], bool]:
    """Strict-decode ``text`` while collecting duplicated object-key positions.

    Parses with the same strictness as ``_STRICT_JSON_DECODER`` (rejects NaN,
    Infinity, out-of-range floats, recursion-depth overflow) plus an
    ``object_pairs_hook`` that records keys appearing more than once inside a
    single object — RFC 8259 permits duplicates but parsers disagree on the
    winning value, which is a first-class integrity signal (SL303).

    Returns ``(obj, dups, truncated)``: ``dups`` holds up to ``max_dup_keys``
    entries in document order; ``truncated`` is True when further duplicates
    existed beyond the cap. When no duplicates exist the post-parse path walk
    is skipped entirely, so clean records only pay for the pairs hook.
    """
    # id(decoded dict) -> duplicated (key, count) entries for that object.
    # Every hooked object remains reachable from the decoded root for the
    # duration of the post-parse walk, so ids cannot be recycled meanwhile.
    marked: dict[int, tuple[tuple[str, int], ...]] = {}

    def _hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj = dict(pairs)
        if len(obj) != len(pairs):
            counts: dict[str, int] = {}
            for key, _val in pairs:
                counts[key] = counts.get(key, 0) + 1
            marked[id(obj)] = tuple((k, n) for k, n in counts.items() if n > 1)
        return obj

    obj = json.loads(
        text,
        parse_constant=_reject_constant,
        parse_float=_strict_parse_float,
        object_pairs_hook=_hook,
    )
    if not marked:
        return obj, (), False

    crit = critical_keys if critical_keys is not None else frozenset()
    dups: list[DuplicateKey] = []
    truncated = False
    stack: list[tuple[Any, str]] = [(obj, "$")]
    remaining = len(marked)
    while stack and remaining:
        node, path = stack.pop()
        if isinstance(node, dict):
            node_dups = marked.get(id(node))
            if node_dups is not None:
                remaining -= 1
                for key, count in node_dups:
                    if len(dups) >= max_dup_keys:
                        truncated = True
                        break
                    dups.append(
                        DuplicateKey(
                            key_path=f"{path}.{key}",
                            occurrence_count=count,
                            critical=key in crit,
                        )
                    )
                if truncated:
                    break
            for key in reversed(list(node.keys())):
                stack.append((node[key], f"{path}.{key}"))
        elif isinstance(node, list):
            for idx in range(len(node) - 1, -1, -1):
                stack.append((node[idx], f"{path}[{idx}]"))
    if remaining:
        truncated = True
    return obj, tuple(dups), truncated


def dup_key_findings(
    dups: tuple[DuplicateKey, ...],
    *,
    truncated: bool = False,
    path_str: str,
    line: int | None = None,
    record_id: str | None = None,
    record_ordinal: int | None = None,
) -> list[Finding]:
    """Build SL303 findings for decoded duplicate-key positions.

    One finding per duplicated key path: ``error`` when the key participates
    in identity/parentage/pairing (the adapter's CRITICAL_KEYS), ``warning``
    otherwise. Evidence stays content-free — key paths and counts only, never
    the duplicated values.
    """
    findings: list[Finding] = []
    for dup in dups:
        evidence: dict[str, Any] = {
            "key_path": dup.key_path,
            "occurrence_count": dup.occurrence_count,
            "critical": dup.critical,
        }
        if record_ordinal is not None:
            evidence["record_index"] = record_ordinal
        if truncated:
            evidence["truncated"] = True
        findings.append(
            make_finding(
                code=SL303,
                severity=Severity.ERROR if dup.critical else Severity.WARNING,
                repairability=Repairability.MANUAL,
                message_template=("Duplicate JSON key on line {line} for record {record_id}"),
                source=SourceRef(path=path_str, line=line, record_id=record_id),
                evidence=evidence,
            )
        )
    return findings


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
    dup_sink: list[Finding] | None = None,
    critical_keys: frozenset[str] | None = None,
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
        obj, dup_keys, dups_truncated = decode_json_dupaware(
            decoded_text, critical_keys=critical_keys
        )
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

    if dup_sink is not None and dup_keys:
        rec_id = extract_record_id(decoded_text, obj)
        dup_sink.extend(
            dup_key_findings(
                dup_keys,
                truncated=dups_truncated,
                path_str=path_str,
                line=raw.line_number,
                record_id=rec_id,
                record_ordinal=raw.record_ordinal,
            )
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
    dup_sink: list[Finding] | None = None,
    critical_keys: frozenset[str] | None = None,
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
    stream: BinaryIO | _MMapLineSource
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
        stream = _open_byte_source(path_obj)
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
                obj, dup_keys, dups_truncated = decode_json_dupaware(
                    decoded, critical_keys=critical_keys
                )
            except RecursionError as err:
                raise SchemaError(
                    f"Header nesting depth exceeds recursion limit on line {line_number}"
                ) from err
            except (json.JSONDecodeError, ValueError) as err:
                raise SchemaError(
                    f"Malformed JSON on header line (line {line_number}): {err}"
                ) from err

            if dup_sink is not None and dup_keys:
                dup_sink.extend(
                    dup_key_findings(
                        dup_keys,
                        truncated=dups_truncated,
                        path_str=path_str,
                        line=line_number,
                        record_id=extract_record_id(decoded, obj),
                    )
                )

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
    critical_keys: frozenset[str] | None = None,
) -> Iterator[SessionEvent | Finding]:
    """Stream a canonical session JSONL file line-by-line with hostile-input limits.

    Args:
        path: Session file path or binary stream.
        limits: Optional reader limits for bounded streaming.
        critical_keys: Optional adapter field-name set; duplicated keys in this
            set escalate their SL303 finding from warning to error.

    Yields:
    - SessionEvent: Valid session events in document order.
    - Finding(SL001): Malformed nonterminal records (skip-and-continue).
    - Finding(SL002): Torn terminal record on the last non-empty line (deterministic suffix drop).
    - Finding(SL303): Duplicated JSON object keys within a decoded record.

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
    stream: BinaryIO | _MMapLineSource
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
        stream = _open_byte_source(path_obj)
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

                dup_sink: list[Finding] = []
                item = _process_line(
                    pending_raw,
                    is_terminal=False,
                    path_str=path_str,
                    limits=effective_limits,
                    is_first_record=is_first,
                    dup_sink=dup_sink,
                    critical_keys=critical_keys,
                )
                if item is not None:
                    yield item
                yield from dup_sink

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

            dup_sink = []
            item = _process_line(
                pending_raw,
                is_terminal=True,
                path_str=path_str,
                limits=effective_limits,
                is_first_record=is_first,
                dup_sink=dup_sink,
                critical_keys=critical_keys,
            )
            if item is not None:
                yield item
            yield from dup_sink

        if not has_any_records:
            raise HeaderMissingError(f"Session file contains no records: {path_str}")

    finally:
        if is_owned_file:
            stream.close()
