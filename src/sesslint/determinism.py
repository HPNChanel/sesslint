"""Determinism utilities, canonical serialization, and stable ordering (TASK-026).

This module provides pure, side-effect-free helpers ensuring byte-identical repeatability
across runs and environments, independent of PYTHONHASHSEED, OS platform, or locale.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from typing import Any

from sesslint.finding import Finding, finding_sort_key


def canonical_json_bytes(obj: Any) -> bytes:
    """Serialize an object or dictionary to deterministic canonical UTF-8 JSON bytes.

    Encodes with sorted keys, compact separators (",", ":"), unescaped UTF-8 characters,
    and a terminating newline byte (b"\\n").
    """
    if hasattr(obj, "to_dict") and callable(obj.to_dict):
        raw = obj.to_dict()
    elif isinstance(obj, Mapping):
        raw = dict(obj)
    else:
        raw = obj

    return (
        json.dumps(
            raw,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        + b"\n"
    )


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
