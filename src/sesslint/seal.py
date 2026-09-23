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
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, cast

from sesslint._canonical_codec import canonical_json_bytes

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
    entry["entry_sha256"] = _entry_hash(entry)
    return entry


def _iter_lines(path: Path) -> list[tuple[int, str]]:
    """Read a ledger file into ``(line_number, raw_text)`` pairs.

    Raises ``SealError`` on a missing/unreadable/non-UTF8 file — append
    never silently extends an unreadable ledger.
    """
    try:
        raw = path.read_bytes()
    except OSError as err:
        raise SealError(f"cannot read ledger {path}: {err}") from err
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as err:
        raise SealError(f"ledger {path} is not UTF-8: {err}") from err
    return [(i, line) for i, line in enumerate(text.splitlines(), start=1) if line.strip()]


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
        except json.JSONDecodeError:
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
        if entry["entry_sha256"] != _entry_hash(entry):
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
) -> dict[str, Any]:
    """Append one sealed line to ``ledger`` after re-verifying the chain.

    Fail-closed: a divergent existing ledger raises ``SealError`` and is
    never extended — rotate to a new ledger bound via ``genesis_of``
    (allowed only on an empty/absent ledger). The append is a single
    write + fsync; the parent directory is synced on POSIX.
    """
    p = Path(ledger)
    seq = 1
    prev = GENESIS
    if p.exists():
        lines = _iter_lines(p)
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
    try:
        parent = p.parent
        if not parent.exists():
            raise SealError(f"ledger directory does not exist: {parent}")
        with open(p, "ab") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())
        _sync_dir(parent)
    except SealError:
        raise
    except OSError as err:
        raise SealError(f"cannot append to ledger {p}: {err}") from err
    return entry


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
    repo_root = Path(__file__).resolve().parent.parent.parent
    dev_path = repo_root / "schemas" / "sesslint.seal-ledger.v1.json"
    if dev_path.is_file():
        return dev_path
    prefix_path = (
        Path(sys.prefix) / "share" / "sesslint" / "schemas" / "sesslint.seal-ledger.v1.json"
    )
    if prefix_path.is_file():
        return prefix_path
    return dev_path


def load_seal_schema() -> dict[str, Any]:
    """Load the committed JSON Schema for sesslint.seal-ledger/v1 as a dict."""
    path = get_seal_schema_path()
    if not path.is_file():
        raise FileNotFoundError(f"Seal-ledger schema not found at {path}")
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


__all__ = [
    "DIVERGENCE_KINDS",
    "GENESIS",
    "SEAL_SCHEMA_ID",
    "SEAL_TOOLS",
    "SealError",
    "append_seal",
    "build_entry",
    "get_seal_schema_path",
    "load_seal_schema",
    "sha256_bytes",
    "sha256_file",
    "verify_ledger",
    "verify_lines",
]
