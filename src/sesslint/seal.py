"""Tamper-evident hash-chain ledger for SessLint verdicts (evidence-assurance T-01).

``sesslint check|verify|repair --seal LEDGER`` appends one JSON line binding
that invocation's outcome — file hash, verdict, code counts, report hash —
into a SHA-256 chain: each line carries ``prev_sha256`` pointing at the
previous line's ``entry_sha256``. ``sesslint seal --verify LEDGER`` re-walks
the chain and reports the first divergence (edited, dropped, reordered, or
truncated lines). The ledger is self-verifying — no keys, server, or trusted
clock; stdlib ``hashlib`` + the canonical JSON codec only.

Honesty boundary (DEMAND non-goal 19): a seal ledger is a **tamper-evident
record of SessLint verdicts** — never an audit artifact, compliance claim,
or proof about session semantics. ``sealed_at`` is self-reported wall-clock
time carried *inside* the hashed line; it has no trust anchor, and the
deterministic check/verify/repair outputs are unaffected by it.

Ledger rules:

- ``seq`` starts at 1 and strictly increments; ``prev_sha256`` is
  ``"GENESIS"`` on the first line, else the previous ``entry_sha256``.
- ``entry_sha256`` = SHA-256 over the canonical JSON of every other field.
- Appending re-verifies the existing chain first — a divergent ledger is
  never extended (rotate via ``genesis_of`` instead).
- Lines are content-free: hashes, verdict, per-code counts, minimized
  path (omittable via ``--seal-no-path``), self-reported time.
- Appends are serialized by an exclusive OS lock on the sidecar
  ``<LEDGER>.lock`` (``msvcrt.locking`` / ``fcntl.flock``, bounded wait):
  concurrent ``--seal`` runs can never mint duplicate ``seq`` values (B26).
  The kernel drops the lock when its holder exits, so a crashed run never
  leaves a stale lock; the empty sidecar file itself is inert.
- Lines are split on LF only (canonical JSON may carry raw U+2028 / U+0085
  inside string values), and an append first terminates a final line that
  lacks its LF so two entries are never glued together (B26).
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import sys
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, cast

from sesslint._canonical_codec import canonical_json_bytes
from sesslint.errors import SesslintError

StrPath = str | os.PathLike[str]

SEAL_SCHEMA_ID: Final[str] = "sesslint.seal-ledger/v1"
GENESIS: Final[str] = "GENESIS"
SEAL_TOOLS: Final[frozenset[str]] = frozenset({"check", "verify", "repair"})

_HEX64: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}")
_SEALED_AT: Final[re.Pattern[str]] = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")

# Divergence kinds emitted by verify_ledger — a closed vocabulary so JSON
# consumers can switch on it.
DIVERGENCE_KINDS: Final[frozenset[str]] = frozenset(
    {"malformed-line", "bad-schema", "seq-gap", "chain-break", "hash-mismatch"}
)

_CHUNK: Final[int] = 1024 * 1024

# Append serialization (B26): sidecar lock file + bounded wait. The wait uses
# the monotonic clock only for the deadline — no clock value reaches output.
LOCK_SUFFIX: Final[str] = ".lock"
LOCK_TIMEOUT_SECONDS: Final[float] = 30.0
_LOCK_POLL_SECONDS: Final[float] = 0.05


class SealError(Exception):
    """Ledger file is unreadable, malformed, or chain-divergent."""


def sha256_bytes(data: bytes) -> str:
    """SHA-256 hex digest of in-memory bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: StrPath) -> str:
    """Streaming SHA-256 hex digest of a file's bytes (1 MiB chunks)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _entry_hash(entry: Mapping[str, Any]) -> str:
    """SHA-256 over the canonical JSON of every field except ``entry_sha256``."""
    preimage = {k: v for k, v in entry.items() if k != "entry_sha256"}
    return hashlib.sha256(canonical_json_bytes(preimage)).hexdigest()


def build_entry(
    *,
    seq: int,
    prev_sha256: str,
    file_sha256: str,
    path: str | None,
    tool: str,
    verdict: str,
    codes: Mapping[str, int],
    report_sha256: str,
    genesis_of: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build one ledger line (``entry_sha256`` included) after validating
    every field against the closed vocabulary. ``now`` defaults to the
    self-reported wall clock; tests inject a fixed value for determinism."""
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        raise SealError(f"seq must be a positive integer, got {seq!r}")
    if prev_sha256 != GENESIS and not _HEX64.fullmatch(prev_sha256):
        raise SealError("prev_sha256 must be 'GENESIS' or a sha256 hex digest")
    if not _HEX64.fullmatch(file_sha256):
        raise SealError("file_sha256 must be a sha256 hex digest")
    if tool not in SEAL_TOOLS:
        raise SealError(f"tool must be one of {sorted(SEAL_TOOLS)}, got {tool!r}")
    if not isinstance(verdict, str) or not verdict:
        raise SealError("verdict must be a non-empty string")
    norm_codes: dict[str, int] = {}
    for code, count in codes.items():
        if not isinstance(code, str) or not isinstance(count, int) or count < 0:
            raise SealError(f"codes must map code strings to non-negative ints: {code!r}")
        norm_codes[code] = count
    if not _HEX64.fullmatch(report_sha256):
        raise SealError("report_sha256 must be a sha256 hex digest")
    if genesis_of is not None and not _HEX64.fullmatch(genesis_of):
        raise SealError("genesis_of must be a sha256 hex digest")
    if path is not None and not isinstance(path, str):
        raise SealError("path must be a string or None")

    sealed_at = (now or datetime.now(UTC)).isoformat(timespec="seconds").replace("+00:00", "Z")

    entry: dict[str, Any] = {
        "schema": SEAL_SCHEMA_ID,
        "seq": seq,
        "prev_sha256": prev_sha256,
        "file_sha256": file_sha256,
        "tool": tool,
        "verdict": verdict,
        "codes": norm_codes,
        "report_sha256": report_sha256,
        "sealed_at": sealed_at,
    }
    if path is not None:
        entry["path"] = path
    if genesis_of is not None:
        entry["genesis_of"] = genesis_of
    try:
        entry["entry_sha256"] = _entry_hash(entry)
    except (SesslintError, ValueError, RecursionError) as err:
        # e.g. a path carrying lone surrogates (undecodable filename bytes).
        raise SealError("entry fields cannot be serialized as canonical JSON") from err
    return entry


def _read_ledger_text(path: Path) -> str:
    """Read a ledger file as UTF-8 text.

    Raises ``SealError`` on a missing/unreadable/non-UTF8 file — append
    never silently extends an unreadable ledger.
    """
    try:
        raw = path.read_bytes()
    except OSError as err:
        raise SealError(f"cannot read ledger {path}: {err}") from err
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as err:
        raise SealError(f"ledger {path} is not UTF-8: {err}") from err


def _split_ledger_lines(text: str) -> list[tuple[int, str]]:
    """Split ledger text into non-blank ``(line_number, raw_text)`` pairs.

    Splits on LF only: ``str.splitlines`` would also break on U+2028, U+2029,
    U+0085 and other separators that canonical JSON (``ensure_ascii`` off)
    emits raw inside string values such as ``path`` (B26).
    """
    return [(i, line) for i, line in enumerate(text.split("\n"), start=1) if line.strip()]


def _iter_lines(path: Path) -> list[tuple[int, str]]:
    """Read a ledger file into ``(line_number, raw_text)`` pairs (see
    ``_read_ledger_text`` for the fail-closed read contract)."""
    return _split_ledger_lines(_read_ledger_text(path))


def _validate_entry_shape(entry: Any) -> str | None:
    """Return a divergence kind when a parsed line fails shape checks, else
    None. Field-level validation only — chain linkage is verified by the
    caller which has sequence context."""
    if not isinstance(entry, dict):
        return "malformed-line"
    if entry.get("schema") != SEAL_SCHEMA_ID:
        return "bad-schema"
    seq = entry.get("seq")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        return "malformed-line"
    prev = entry.get("prev_sha256")
    if not isinstance(prev, str) or (prev != GENESIS and not _HEX64.fullmatch(prev)):
        return "malformed-line"
    for key in ("file_sha256", "report_sha256", "entry_sha256"):
        val = entry.get(key)
        if not isinstance(val, str) or not _HEX64.fullmatch(val):
            return "malformed-line"
    if entry.get("tool") not in SEAL_TOOLS:
        return "malformed-line"
    if not isinstance(entry.get("verdict"), str) or not entry["verdict"]:
        return "malformed-line"
    codes = entry.get("codes")
    if not isinstance(codes, dict) or any(
        not isinstance(k, str) or not isinstance(v, int) or v < 0 for k, v in codes.items()
    ):
        return "malformed-line"
    sealed_at = entry.get("sealed_at")
    if not isinstance(sealed_at, str) or not _SEALED_AT.fullmatch(sealed_at):
        return "malformed-line"
    if "path" in entry and not isinstance(entry["path"], str):
        return "malformed-line"
    if "genesis_of" in entry and (
        not isinstance(entry["genesis_of"], str) or not _HEX64.fullmatch(entry["genesis_of"])
    ):
        return "malformed-line"
    return None


def verify_lines(lines: list[tuple[int, str]]) -> dict[str, Any] | None:
    """Walk parsed ledger lines; return the first divergence as
    ``{kind, line, seq?, detail}`` or None when the chain is intact.

    Detection covers: unparseable/tampered fields (``malformed-line``),
    foreign documents (``bad-schema``), dropped or reordered lines
    (``seq-gap``), a ``prev_sha256`` that no longer binds to the previous
    entry (``chain-break``), and edited content (``hash-mismatch``).
    """
    prev_hash = GENESIS
    expected_seq = 1
    for line_no, raw in lines:
        try:
            entry: Any = json.loads(raw)
        except RecursionError:
            # Hostile nesting must surface as divergence, never a traceback (B26).
            return {
                "kind": "malformed-line",
                "line": line_no,
                "detail": "line nesting exceeds parser limits",
            }
        except ValueError:
            # JSONDecodeError, oversized integer literals, and decode errors
            # are all ValueError subclasses (B26).
            return {
                "kind": "malformed-line",
                "line": line_no,
                "detail": "line is not valid JSON (edit or truncation)",
            }
        shape = _validate_entry_shape(entry)
        if shape is not None:
            return {
                "kind": shape,
                "line": line_no,
                "detail": (
                    "document is not a sesslint.seal-ledger/v1 entry"
                    if shape == "bad-schema"
                    else "entry fields are malformed or missing"
                ),
            }
        seq = entry["seq"]
        if seq != expected_seq:
            return {
                "kind": "seq-gap",
                "line": line_no,
                "seq": seq,
                "detail": f"expected seq {expected_seq}, found {seq} (line drop or reorder)",
            }
        if entry["prev_sha256"] != prev_hash:
            return {
                "kind": "chain-break",
                "line": line_no,
                "seq": seq,
                "detail": "prev_sha256 does not bind to the previous entry hash",
            }
        try:
            recomputed = _entry_hash(entry)
        except (SesslintError, ValueError, RecursionError):
            # Extra fields that cannot be canonicalized (NaN, lone surrogates,
            # hostile nesting) can never hash-verify (B26).
            return {
                "kind": "malformed-line",
                "line": line_no,
                "seq": seq,
                "detail": "entry fields cannot be canonicalized",
            }
        if entry["entry_sha256"] != recomputed:
            return {
                "kind": "hash-mismatch",
                "line": line_no,
                "seq": seq,
                "detail": "entry_sha256 does not match the entry contents (line edited)",
            }
        prev_hash = entry["entry_sha256"]
        expected_seq += 1
    return None


def verify_ledger(path: StrPath) -> tuple[int, dict[str, Any] | None]:
    """Verify a ledger file end to end.

    Returns ``(entries_verified, divergence)`` — ``divergence`` is None when
    the chain is intact. Raises ``SealError`` when the file itself is
    missing or unreadable (a usage error, distinct from chain data
    divergence).
    """
    p = Path(path)
    if not p.is_file():
        raise SealError(f"ledger not found: {p}")
    lines = _iter_lines(p)
    divergence = verify_lines(lines)
    if divergence is None:
        return len(lines), None
    # Entries verified = lines walked cleanly before the divergence point.
    verified = sum(1 for line_no, _ in lines if line_no < divergence["line"])
    return verified, divergence


def append_seal(
    ledger: StrPath,
    *,
    tool: str,
    file_sha256: str,
    path: str | None,
    verdict: str,
    codes: Mapping[str, int],
    report_sha256: str,
    genesis_of: str | None = None,
    now: datetime | None = None,
    lock_timeout: float = LOCK_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Append one sealed line to ``ledger`` after re-verifying the chain.

    Fail-closed: a divergent existing ledger raises ``SealError`` and is
    never extended — rotate to a new ledger bound via ``genesis_of``
    (allowed only on an empty/absent ledger). The append is a single
    write + fsync; the parent directory is synced on POSIX.

    The read → verify → append sequence runs under an exclusive lock on
    ``<ledger>.lock`` (B26): concurrent appenders serialize instead of both
    claiming the same ``seq``. ``lock_timeout`` bounds the wait; expiry
    raises ``SealError`` and nothing is written.
    """
    p = Path(ledger)
    parent = p.parent
    if not parent.exists():
        raise SealError(f"ledger directory does not exist: {parent}")
    with _ledger_lock(p, timeout=lock_timeout):
        seq = 1
        prev = GENESIS
        terminate_tail = False
        if p.exists():
            text = _read_ledger_text(p)
            lines = _split_ledger_lines(text)
            divergence = verify_lines(lines)
            if divergence is not None:
                raise SealError(
                    f"ledger {p} is divergent at line {divergence['line']} "
                    f"({divergence['kind']}: {divergence['detail']}) — refusing to extend"
                )
            if lines:
                last = json.loads(lines[-1][1])
                seq = int(last["seq"]) + 1
                prev = str(last["entry_sha256"])
            # A verified final line missing its LF would otherwise fuse with
            # the appended entry into one unparseable line (B26).
            terminate_tail = bool(text) and not text.endswith("\n")
        if genesis_of is not None and seq != 1:
            raise SealError("genesis_of binds only a ledger's first line (seq 1)")

        entry = build_entry(
            seq=seq,
            prev_sha256=prev,
            file_sha256=file_sha256,
            path=path,
            tool=tool,
            verdict=verdict,
            codes=codes,
            report_sha256=report_sha256,
            genesis_of=genesis_of,
            now=now,
        )
        line = canonical_json_bytes(entry, newline=True)
        if terminate_tail:
            line = b"\n" + line
        try:
            with open(p, "ab") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
            _sync_dir(parent)
        except OSError as err:
            raise SealError(f"cannot append to ledger {p}: {err}") from err
    return entry


def lock_path_for(ledger: StrPath) -> Path:
    """Sidecar lock file that serializes appends to ``ledger`` (B26)."""
    p = Path(ledger)
    return p.with_name(p.name + LOCK_SUFFIX)


if sys.platform == "win32":
    import msvcrt

    def _try_lock(fd: int) -> bool:
        """Non-blocking exclusive lock on byte 0 of ``fd``; False on contention."""
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError as err:
            if err.errno in (errno.EACCES, errno.EDEADLK):
                return False
            raise
        return True

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _try_lock(fd: int) -> bool:
        """Non-blocking exclusive ``flock`` on ``fd``; False on contention."""
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        return True

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


@contextmanager
def _ledger_lock(ledger: Path, *, timeout: float) -> Iterator[None]:
    """Hold the exclusive append lock for ``ledger`` (B26).

    The lock is an OS lock on a persistent sidecar file, never the file's
    existence: the kernel releases it when the holder exits or crashes, so
    there is no stale-lock state to clean up or guess about. Waiting is
    bounded by ``timeout`` (monotonic clock, never reported); expiry or a
    filesystem that cannot lock raises ``SealError`` — fail closed, never an
    unserialized append.
    """
    lock_p = lock_path_for(ledger)
    try:
        fd = os.open(str(lock_p), os.O_RDWR | os.O_CREAT, 0o644)
    except OSError as err:
        raise SealError(f"cannot open ledger lock {lock_p}: {err}") from err
    try:
        deadline = time.monotonic() + max(timeout, 0.0)
        while True:
            try:
                acquired = _try_lock(fd)
            except OSError as err:
                raise SealError(f"cannot lock ledger {ledger}: {err}") from err
            if acquired:
                break
            if time.monotonic() >= deadline:
                raise SealError(
                    f"ledger {ledger} is locked by another sesslint process "
                    f"(waited {timeout:g}s) — nothing appended"
                )
            time.sleep(_LOCK_POLL_SECONDS)
        try:
            yield
        finally:
            try:
                _unlock(fd)
            except OSError:
                pass  # closing the descriptor releases the lock regardless
    finally:
        os.close(fd)


def _sync_dir(path: Path) -> None:
    """Best-effort parent directory fsync (no-op on Windows)."""
    if os.name == "nt":
        return
    try:
        fd = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def get_seal_schema_path() -> Path:
    """Return filesystem path to schemas/sesslint.seal-ledger.v1.json."""
    from sesslint._resources import schema_path

    development_path = (
        Path(__file__).resolve().parent.parent.parent / "schemas" / "sesslint.seal-ledger.v1.json"
    )
    return schema_path("sesslint.seal-ledger.v1.json", development_path)


def load_seal_schema() -> dict[str, Any]:
    """Load the committed JSON Schema for sesslint.seal-ledger/v1 as a dict."""
    path = get_seal_schema_path()
    if not path.is_file():
        raise FileNotFoundError(f"Seal-ledger schema not found at {path}")
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


__all__ = [
    "DIVERGENCE_KINDS",
    "GENESIS",
    "LOCK_SUFFIX",
    "LOCK_TIMEOUT_SECONDS",
    "SEAL_SCHEMA_ID",
    "SEAL_TOOLS",
    "SealError",
    "append_seal",
    "build_entry",
    "get_seal_schema_path",
    "load_seal_schema",
    "lock_path_for",
    "sha256_bytes",
    "sha256_file",
    "verify_ledger",
    "verify_lines",
]
