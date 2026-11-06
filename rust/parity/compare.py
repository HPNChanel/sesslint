#!/usr/bin/env python3
"""Byte-exact parity comparator for one Python/Rust capture pair (RX-P1.3c).

Stdlib only. ``compare`` is the importable entry. Running this file with no
arguments is a missing-input failure, not a pass. The acceptance check is
``python rust/parity/compare.py --self-check``.

Stdout bytes and process exit codes are compared exactly. Stderr is compared
line by line (split only on ``\\n``, separators kept). A line whose body is a
progress NDJSON object drops the time fields named below, then the remaining
bytes are compared. Any other line, including non-JSON text, is compared raw.

On a byte mismatch the report carries the reference offset and at most 64
bytes of compared context. Nothing else from the captures is printed.
"""

from __future__ import annotations

import io
import json
import sys
from dataclasses import dataclass
from typing import Final

# Time fields removed from each progress-NDJSON object before that line is
# compared. Closed list. Pinned emitter is ProgressEvent.to_dict via
# ndjson_progress_cb (src/sesslint/progress.py, src/sesslint/cli/_progress.py):
# keys on the wire are only completed, item, phase, and total. None of those
# are clocks, so no key is dropped. The verbose line ``debug: elapsed …`` is
# not JSON and stays raw; it is not in this list.
# Removed fields:
#   (none)
REMOVED_TIME_FIELDS: Final[tuple[str, ...]] = ()

_PROGRESS_KEYS: Final[frozenset[str]] = frozenset({"completed", "item", "phase", "total"})
_CONTEXT_LIMIT: Final[int] = 64
_WS: Final[frozenset[int]] = frozenset(b" \t\r\n")


@dataclass(frozen=True, slots=True)
class Capture:
    """One side of a parity capture. ``None`` means the input is missing."""

    stdout: bytes | None
    stderr: bytes | None
    exit_code: int | None


@dataclass(frozen=True, slots=True)
class Diff:
    """First failure only, in the order input, exit, stdout, stderr."""

    equal: bool
    channel: str
    offset: int | None
    context: bytes
    missing: str
    left_exit: int | None
    right_exit: int | None


def compare(left: Capture, right: Capture) -> Diff:
    """Return the first mismatch. Missing or ill-typed input is not a match."""
    missing = _input_error(left, right)
    if missing is not None:
        return _missing(missing)
    assert type(left.exit_code) is int
    assert type(right.exit_code) is int
    assert type(left.stdout) is bytes
    assert type(right.stdout) is bytes
    assert type(left.stderr) is bytes
    assert type(right.stderr) is bytes
    if left.exit_code != right.exit_code:
        return _exit_mismatch(left.exit_code, right.exit_code)
    stdout = _diff_bytes("stdout", left.stdout, right.stdout, None)
    if stdout is not None:
        return stdout
    left_err, left_map = _normalize_stderr(left.stderr)
    right_err, _right_map = _normalize_stderr(right.stderr)
    return _diff_bytes("stderr", left_err, right_err, left_map) or _ok()


def status_code(diff: Diff) -> int:
    """0 match, 1 mismatch, 2 missing input."""
    if diff.equal:
        return 0
    if diff.channel == "input":
        return 2
    return 1


def format_diff(diff: Diff) -> str:
    """Render ``diff`` as LF key=value lines. Context is at most 64 bytes."""
    lines = [f"equal={'true' if diff.equal else 'false'}"]
    if diff.equal:
        return "\n".join(lines) + "\n"
    lines.append(f"channel={diff.channel}")
    if diff.channel == "input":
        lines.append(f"missing={diff.missing}")
    elif diff.channel == "exit":
        lines.append(f"left_exit={diff.left_exit}")
        lines.append(f"right_exit={diff.right_exit}")
    else:
        context = diff.context[:_CONTEXT_LIMIT]
        if diff.offset is None:
            lines.append("offset=absent")
        else:
            lines.append(f"offset={diff.offset}")
        lines.append(f"context_len={len(context)}")
        lines.append(f"context_hex={context.hex()}")
    return "\n".join(lines) + "\n"


def _ok() -> Diff:
    return Diff(True, "", None, b"", "", None, None)


def _missing(name: str) -> Diff:
    return Diff(False, "input", None, b"", name, None, None)


def _exit_mismatch(left: int, right: int) -> Diff:
    return Diff(False, "exit", None, b"", "", left, right)


def _byte_mismatch(channel: str, offset: int, context: bytes) -> Diff:
    return Diff(False, channel, offset, context[:_CONTEXT_LIMIT], "", None, None)


def _input_error(left: Capture, right: Capture) -> str | None:
    checked = (
        ("left_exit", left.exit_code, "exit"),
        ("right_exit", right.exit_code, "exit"),
        ("left_stdout", left.stdout, "bytes"),
        ("right_stdout", right.stdout, "bytes"),
        ("left_stderr", left.stderr, "bytes"),
        ("right_stderr", right.stderr, "bytes"),
    )
    for name, value, kind in checked:
        if kind == "exit":
            if type(value) is not int:
                return name
        elif type(value) is not bytes:
            return name
    return None


def _diff_bytes(
    channel: str,
    left: bytes,
    right: bytes,
    left_map: list[int] | None,
) -> Diff | None:
    found = _first_diff(left, right)
    if found is None:
        return None
    if found < len(left):
        context = left[found : found + _CONTEXT_LIMIT]
        offset = left_map[found] if left_map is not None else found
    else:
        context = right[found : found + _CONTEXT_LIMIT]
        if left_map is None:
            offset = found
        elif left_map:
            offset = left_map[-1] + 1
        else:
            offset = 0
    return _byte_mismatch(channel, offset, context)


def _first_diff(left: bytes, right: bytes) -> int | None:
    limit = min(len(left), len(right))
    start = 0
    step = 4096
    while start < limit:
        end = min(start + step, limit)
        if left[start:end] != right[start:end]:
            for index in range(start, end):
                if left[index] != right[index]:
                    return index
        start = end
    if len(left) != len(right):
        return limit
    return None


def _normalize_stderr(
    data: bytes, time_fields: tuple[str, ...] = REMOVED_TIME_FIELDS
) -> tuple[bytes, list[int]]:
    out = bytearray()
    mapping: list[int] = []
    for start, piece in _pieces(data):
        if piece.endswith(b"\n"):
            body = piece[:-1]
            separator = b"\n"
        else:
            body = piece
            separator = b""
        norm, body_map = _normalize_body(body, time_fields)
        if len(body_map) != len(norm):
            norm = body
            body_map = list(range(len(body)))
        for index, bite in enumerate(norm):
            out.append(bite)
            mapping.append(start + body_map[index])
        base = start + len(body)
        for index, bite in enumerate(separator):
            out.append(bite)
            mapping.append(base + index)
    return bytes(out), mapping


def _pieces(data: bytes) -> list[tuple[int, bytes]]:
    pieces: list[tuple[int, bytes]] = []
    start = 0
    for index, bite in enumerate(data):
        if bite == 0x0A:
            pieces.append((start, data[start : index + 1]))
            start = index + 1
    if start < len(data):
        pieces.append((start, data[start:]))
    return pieces


def _normalize_body(body: bytes, time_fields: tuple[str, ...]) -> tuple[bytes, list[int]]:
    identity = (body, list(range(len(body))))
    try:
        obj = _load_progress(body, time_fields)
        if obj is None:
            return identity
        present = tuple(key for key in time_fields if key in obj)
        if not present:
            return identity
        excised = _excise_keys(body, present)
    except RecursionError:
        return identity
    if excised is None:
        return identity
    return excised


def _load_progress(body: bytes, time_fields: tuple[str, ...]) -> dict[str, object] | None:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return None
    if not isinstance(value, dict):
        return None
    obj: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            return None
        obj[key] = item
    allowed = _PROGRESS_KEYS | set(time_fields)
    if not set(obj) <= allowed:
        return None
    phase = obj.get("phase")
    completed = obj.get("completed")
    if not isinstance(phase, str) or type(completed) is not int:
        return None
    if "total" in obj and type(obj["total"]) is not int:
        return None
    if "item" in obj and not isinstance(obj["item"], str):
        return None
    for key in time_fields:
        if key in obj and not _time_value_ok(obj[key]):
            return None
    return obj


def _time_value_ok(value: object) -> bool:
    if value is None or type(value) in (int, float, str):
        return True
    return False


def _excise_keys(body: bytes, names: tuple[str, ...]) -> tuple[bytes, list[int]] | None:
    """Drop top-level keys in ``names`` without reordering the bytes kept."""
    members = _Cursor(body).parse_object_members()
    if members is None:
        return None
    drop = set(names)
    kept = [index for index, (key, _start, _end) in enumerate(members) if key not in drop]
    out = bytearray()
    mapping: list[int] = []

    def take(start: int, end: int) -> None:
        for pos in range(start, end):
            out.append(body[pos])
            mapping.append(pos)

    if not kept:
        opened = body.find(0x7B)
        closed = body.rfind(0x7D)
        if opened < 0 or closed < opened:
            return None
        take(opened, opened + 1)
        take(closed, closed + 1)
    else:
        take(0, members[0][1])
        for nth, index in enumerate(kept):
            if nth > 0:
                prev = kept[nth - 1]
                take(members[prev][2], members[prev + 1][1])
            take(members[index][1], members[index][2])
        take(members[-1][2], len(body))
    if any(mapping[index] >= mapping[index + 1] for index in range(len(mapping) - 1)):
        return None
    if len(mapping) != len(out):
        return None
    return bytes(out), mapping


class _Cursor:
    """Byte-offset JSON scanner for one progress object."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.i = 0
        self.n = len(data)

    def peek(self) -> int | None:
        if self.i >= self.n:
            return None
        return self.data[self.i]

    def skip_ws(self) -> None:
        while self.i < self.n and self.data[self.i] in _WS:
            self.i += 1

    def parse_object_members(self) -> list[tuple[str, int, int]] | None:
        self.skip_ws()
        if self.peek() != 0x7B:
            return None
        self.i += 1
        members: list[tuple[str, int, int]] = []
        self.skip_ws()
        if self.peek() == 0x7D:
            self.i += 1
            self.skip_ws()
            if self.i != self.n:
                return None
            return members
        while True:
            self.skip_ws()
            key_start = self.i
            if not self.skip_string():
                return None
            key = _decode_json_string(self.data[key_start : self.i])
            if key is None:
                return None
            self.skip_ws()
            if self.peek() != 0x3A:
                return None
            self.i += 1
            if not self.skip_value():
                return None
            members.append((key, key_start, self.i))
            self.skip_ws()
            mark = self.peek()
            if mark == 0x2C:
                self.i += 1
                continue
            if mark == 0x7D:
                self.i += 1
                self.skip_ws()
                if self.i != self.n:
                    return None
                return members
            return None

    def skip_value(self) -> bool:
        self.skip_ws()
        mark = self.peek()
        if mark is None:
            return False
        if mark == 0x22:
            return self.skip_string()
        if mark == 0x7B:
            return self.skip_object()
        if mark == 0x5B:
            return self.skip_array()
        if mark == 0x74:
            return self._literal(b"true")
        if mark == 0x66:
            return self._literal(b"false")
        if mark == 0x6E:
            return self._literal(b"null")
        if mark == 0x2D or 48 <= mark <= 57:
            return self.skip_number()
        return False

    def skip_object(self) -> bool:
        if self.peek() != 0x7B:
            return False
        self.i += 1
        self.skip_ws()
        if self.peek() == 0x7D:
            self.i += 1
            return True
        while True:
            if not self.skip_string():
                return False
            self.skip_ws()
            if self.peek() != 0x3A:
                return False
            self.i += 1
            if not self.skip_value():
                return False
            self.skip_ws()
            mark = self.peek()
            if mark == 0x2C:
                self.i += 1
                self.skip_ws()
                continue
            if mark == 0x7D:
                self.i += 1
                return True
            return False

    def skip_array(self) -> bool:
        if self.peek() != 0x5B:
            return False
        self.i += 1
        self.skip_ws()
        if self.peek() == 0x5D:
            self.i += 1
            return True
        while True:
            if not self.skip_value():
                return False
            self.skip_ws()
            mark = self.peek()
            if mark == 0x2C:
                self.i += 1
                self.skip_ws()
                continue
            if mark == 0x5D:
                self.i += 1
                return True
            return False

    def skip_string(self) -> bool:
        if self.peek() != 0x22:
            return False
        self.i += 1
        while self.i < self.n:
            mark = self.data[self.i]
            if mark == 0x22:
                self.i += 1
                return True
            if mark == 0x5C:
                return self._escape() and self.skip_string_rest()
            if mark < 0x20:
                return False
            self.i += 1
        return False

    def skip_string_rest(self) -> bool:
        while self.i < self.n:
            mark = self.data[self.i]
            if mark == 0x22:
                self.i += 1
                return True
            if mark == 0x5C:
                if not self._escape():
                    return False
                continue
            if mark < 0x20:
                return False
            self.i += 1
        return False

    def _escape(self) -> bool:
        if self.i + 1 >= self.n or self.data[self.i] != 0x5C:
            return False
        esc = self.data[self.i + 1]
        if esc != 0x75:
            if esc not in b'"\\/bfnrt':
                return False
            self.i += 2
            return True
        if self.i + 6 > self.n:
            return False
        hexpart = self.data[self.i + 2 : self.i + 6]
        if not all(chr(bite) in "0123456789abcdefABCDEF" for bite in hexpart):
            return False
        self.i += 6
        return True

    def _literal(self, text: bytes) -> bool:
        end = self.i + len(text)
        if self.data[self.i : end] != text:
            return False
        self.i = end
        return True

    def skip_number(self) -> bool:
        start = self.i
        if self.peek() == 0x2D:
            self.i += 1
        if self.peek() is None or not (48 <= (self.peek() or 0) <= 57):
            return False
        if self.data[self.i] == 48:
            self.i += 1
        else:
            while self.i < self.n and 48 <= self.data[self.i] <= 57:
                self.i += 1
        if self.i < self.n and self.data[self.i] == 0x2E:
            self.i += 1
            frac = self.i
            while self.i < self.n and 48 <= self.data[self.i] <= 57:
                self.i += 1
            if self.i == frac:
                return False
        if self.i < self.n and self.data[self.i] in (0x65, 0x45):
            self.i += 1
            if self.i < self.n and self.data[self.i] in (0x2B, 0x2D):
                self.i += 1
            exp = self.i
            while self.i < self.n and 48 <= self.data[self.i] <= 57:
                self.i += 1
            if self.i == exp:
                return False
        return self.i > start


def _decode_json_string(token: bytes) -> str | None:
    try:
        value = json.loads(token.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, str):
        return None
    return value


def _capture(stdout: bytes, stderr: bytes, exit_code: int) -> Capture:
    return Capture(stdout, stderr, exit_code)


def _self_check() -> int:
    failures: list[str] = []
    flip_at = 17
    payload = bytes((32 + (index % 90)) for index in range(flip_at + 80))
    flipped = bytearray(payload)
    flipped[flip_at] ^= 0x01
    same = _capture(payload, b"", 0)
    changed = _capture(bytes(flipped), b"", 0)
    diff = compare(same, changed)
    rendered = format_diff(diff)
    _expect(status_code(diff) == 1, "flip_status", failures)
    _expect(diff.channel == "stdout", "flip_channel", failures)
    _expect(diff.offset == flip_at, "flip_offset", failures)
    _expect(diff.context == payload[flip_at : flip_at + _CONTEXT_LIMIT], "flip_context", failures)
    _expect(len(diff.context) == _CONTEXT_LIMIT, "flip_context_len", failures)
    _expect(_report_offset(rendered) == flip_at, "flip_report_offset", failures)
    _expect(_report_context_len(rendered) == _CONTEXT_LIMIT, "flip_report_context", failures)
    _expect(rendered.count("context_hex=") == 1, "flip_one_context", failures)

    _expect(status_code(compare(same, same)) == 0, "identical", failures)

    absent = compare(Capture(None, b"", 0), same)
    _expect(status_code(absent) == 2 and not absent.equal, "missing_stdout", failures)
    _expect(
        absent.channel == "input" and absent.missing == "left_stdout",
        "missing_name",
        failures,
    )
    missing_err = compare(_capture(b"", b"", 0), Capture(b"", None, 0))
    _expect(
        status_code(missing_err) == 2 and missing_err.missing == "right_stderr",
        "missing_stderr",
        failures,
    )
    bool_exit = compare(Capture(b"", b"", True), _capture(b"", b"", 1))
    _expect(
        bool_exit.channel == "input" and bool_exit.missing == "left_exit",
        "bool_exit",
        failures,
    )
    no_args, no_args_text = _run_main([])
    _expect(no_args == 2, "argv_missing", failures)
    _expect(
        no_args_text == "equal=false\nchannel=input\nmissing=argv\n",
        "argv_text",
        failures,
    )

    exit_and_stdout = compare(_capture(b"a", b"", 0), _capture(b"b", b"", 1))
    _expect(exit_and_stdout.channel == "exit", "exit_before_stdout", failures)
    both_streams = compare(_capture(b"a", b"x", 0), _capture(b"b", b"y", 0))
    _expect(
        both_streams.channel == "stdout" and both_streams.offset == 0,
        "stdout_before_stderr",
        failures,
    )

    line = b'{"completed": 1, "phase": "scan"}\n'
    second = b'{"completed": 2, "phase": "scan"}\n'
    stderr_left = line + second
    stderr_right = bytearray(stderr_left)
    stderr_at = len(line) + second.index(b"scan")
    stderr_right[stderr_at] ^= 0x01
    stderr_diff = compare(
        _capture(b"", stderr_left, 0),
        _capture(b"", bytes(stderr_right), 0),
    )
    _expect(stderr_diff.channel == "stderr", "stderr_channel", failures)
    _expect(stderr_diff.offset == stderr_at, "stderr_offset", failures)
    _expect(
        stderr_diff.context == stderr_left[stderr_at : stderr_at + _CONTEXT_LIMIT],
        "stderr_context",
        failures,
    )

    raw_left = line + b"debug: elapsed 1.00s\n"
    raw_right = line + b"debug: elapsed 2.00s\n"
    raw_diff = compare(_capture(b"", raw_left, 0), _capture(b"", raw_right, 0))
    raw_at = next(
        index
        for index, pair in enumerate(zip(raw_left, raw_right, strict=True))
        if pair[0] != pair[1]
    )
    _expect(raw_diff.offset == raw_at, "raw_elapsed_not_stripped", failures)

    array_left = b"[1, 2, 3]\n"
    array_right = bytearray(array_left)
    array_right[1] ^= 0x01
    array_diff = compare(_capture(b"", array_left, 0), _capture(b"", bytes(array_right), 0))
    _expect(array_diff.offset == 1, "json_array_raw", failures)

    with_clock = b'{"completed": 1, "elapsed_ms": 5, "phase": "scan"}\n'
    without_clock = b'{"completed": 1, "phase": "scan"}\n'
    clock_diff = compare(
        _capture(b"", with_clock, 0),
        _capture(b"", without_clock, 0),
    )
    _expect(
        not clock_diff.equal and clock_diff.channel == "stderr",
        "unnamed_clock_not_dropped",
        failures,
    )
    lf_line = b'{"completed": 1, "phase": "scan"}\n'
    crlf_line = b'{"completed": 1, "phase": "scan"}\r\n'
    crlf_diff = compare(_capture(b"", lf_line, 0), _capture(b"", crlf_line, 0))
    _expect(
        not crlf_diff.equal and crlf_diff.offset == lf_line.index(b"\n"),
        "crlf_not_equal",
        failures,
    )

    _expect(_excise_samples(), "excise", failures)

    if failures:
        sys.stdout.write("self_check=fail\n")
        for name in failures:
            sys.stdout.write(f"failed={name}\n")
        return 1
    sys.stdout.write(f"removed_time_fields={_removed_field_text()}\n")
    sys.stdout.write("case=flip\n")
    sys.stdout.write(rendered)
    sys.stdout.write("self_check=pass\n")
    sys.stdout.write(f"flipped_offset={flip_at}\n")
    sys.stdout.write(f"reported_offset={diff.offset}\n")
    sys.stdout.write(f"mismatch_exit={status_code(diff)}\n")
    return 0


def _removed_field_text() -> str:
    if not REMOVED_TIME_FIELDS:
        return "(none)"
    return ",".join(REMOVED_TIME_FIELDS)


def _report_offset(rendered: str) -> int | None:
    for line in rendered.split("\n"):
        if line.startswith("offset="):
            return int(line.removeprefix("offset="))
    return None


def _report_context_len(rendered: str) -> int | None:
    for line in rendered.split("\n"):
        if line.startswith("context_len="):
            return int(line.removeprefix("context_len="))
        if line.startswith("context_hex="):
            return len(bytes.fromhex(line.removeprefix("context_hex=")))
    return None


def _expect(cond: bool, name: str, failures: list[str]) -> None:
    if not cond:
        failures.append(name)


def _run_main(argv: list[str]) -> tuple[int, str]:
    sink = io.StringIO()
    previous = sys.stdout
    sys.stdout = sink
    try:
        code = main(argv)
    finally:
        sys.stdout = previous
    return code, sink.getvalue()


def _excise_samples() -> bool:
    names = ("elapsed_ms",)
    samples = (
        b'{"completed": 1, "elapsed_ms": 42, "phase": "scan"}',
        b'{"elapsed_ms": 42, "completed": 1, "phase": "scan"}',
        b'{"completed": 1, "phase": "scan", "elapsed_ms": 42}',
        b'{"elapsed_ms": 1, "ts": 2, "completed": 1, "phase": "scan"}',
        b'{"completed": 1, "elapsed_ms": 4, "item": "a\\"b,}", "phase": "scan"}',
        b'{"elapsed_ms": 9}',
    )
    for body in samples:
        norm, mapping = _normalize_for_sample(body, names)
        if norm is None or mapping is None:
            return False
        if len(mapping) != len(norm):
            return False
        if any(norm[index] != body[mapping[index]] for index in range(len(norm))):
            return False
        loaded = json.loads(norm)
        original = json.loads(body)
        if not isinstance(original, dict) or not isinstance(loaded, dict):
            return False
        for key in names:
            original.pop(key, None)
        if loaded != original:
            return False
    kept_body = b'{"completed": 1, "item": "elapsed_ms", "phase": "scan"}'
    kept_norm, kept_map = _normalize_body(kept_body, names)
    if kept_norm != kept_body or kept_map != list(range(len(kept_body))):
        return False
    left = b'{"completed": 1, "elapsed_ms": 5, "phase": "scan"}\n'
    right = b'{"completed": 1, "elapsed_ms": 9, "phase": "scan"}\n'
    left_norm, _left_map = _normalize_stderr(left, names)
    right_norm, _right_map = _normalize_stderr(right, names)
    if left_norm != right_norm:
        return False
    plain = b'{"completed": 1, "phase": "scan"}'
    plain_norm, plain_map = _normalize_body(plain, REMOVED_TIME_FIELDS)
    if plain_norm != plain or plain_map != list(range(len(plain))):
        return False
    both = ("elapsed_ms", "ts")
    paired = b'{"completed": 1, "elapsed_ms": 1, "phase": "scan", "ts": 2}'
    paired_norm, paired_map = _normalize_body(paired, both)
    if any(paired_norm[index] != paired[paired_map[index]] for index in range(len(paired_norm))):
        return False
    return json.loads(paired_norm) == {"completed": 1, "phase": "scan"}


def _normalize_for_sample(
    body: bytes, names: tuple[str, ...]
) -> tuple[bytes, list[int]] | tuple[None, None]:
    if _load_progress(body, names) is None:
        excised = _excise_keys(body, names)
        if excised is None:
            return None, None
        return excised
    return _normalize_body(body, names)


def self_check() -> int:
    try:
        return _self_check()
    except Exception:
        sys.stdout.write("self_check=fail\nfailed=exception\n")
        return 1


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--self-check"]:
        return self_check()
    sys.stdout.write("equal=false\nchannel=input\nmissing=argv\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
