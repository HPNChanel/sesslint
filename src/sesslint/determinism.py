"""Determinism utilities, canonical serialization, and stable ordering (TASK-026).

This module provides pure, side-effect-free helpers ensuring byte-identical repeatability
across runs and environments, independent of PYTHONHASHSEED, OS platform, or locale.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from typing import Any

from sesslint.canonical import to_canonical_json
from sesslint.finding import Finding, finding_sort_key


def canonical_json_bytes(obj: Any, *, newline: bool = True) -> bytes:
    """Serialize an object or dictionary to deterministic canonical UTF-8 JSON bytes.

    Unifies canonical JSON serialization across SessLint into a single primitive.
    Guarantees:
    - Keys are sorted lexicographically (sort_keys=True)
    - Compact separators without whitespace (",", ":")
    - Non-ASCII characters preserved directly as UTF-8 (ensure_ascii=False)
    - Strict RFC 8785 compliance (rejects out-of-range floats like NaN/Inf and cyclic structures)

    Two domains are explicitly supported:
    1. Serialization / file writing domain (newline=True, default): terminates
       strictly with LF (b"\n").
    2. Hash domain (newline=False): produces compact bytes without trailing newline
       for cryptographic fingerprinting and hashing (findings, plans).
    """
    target = obj.to_dict() if hasattr(obj, "to_dict") and callable(obj.to_dict) else obj
    raw_str = to_canonical_json(target)
    raw_bytes = raw_str.encode("utf-8")
    if newline:
        return raw_bytes + b"\n"
    return raw_bytes


def stable_sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Sort an iterable of findings in deterministic FR-094 order.

    Total ordering hierarchy:
    1. path (lexicographical, forward-slash normalized)
    2. line (None sorts as -1 before line 0, then ascending integer)
    3. ordinal (stream record ordinal from evidence['record_ordinal'], None/-1 sorts before 0)
    4. severity_rank (fatal < error < warning < info)
    5. code (lexicographical)
    6. record_id (None sorts as empty string before any non-empty string, then lexicographical)
    7. fingerprint (16-character sha256 hex string)
    """
    return sorted(findings, key=finding_sort_key)


def repeat_hash(data: bytes | str | Any) -> str:
    """Compute deterministic SHA-256 hex digest of data, text, or report structures."""
    if isinstance(data, bytes):
        raw_bytes = data
    elif isinstance(data, str):
        raw_bytes = data.encode("utf-8")
    else:
        raw_bytes = canonical_json_bytes(data)

    return hashlib.sha256(raw_bytes).hexdigest()


__all__ = [
    "canonical_json_bytes",
    "finding_sort_key",
    "repeat_hash",
    "stable_sort_findings",
]
