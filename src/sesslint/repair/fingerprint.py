"""Deterministic fingerprinting for repair plans (TASK-018).

This module implements deterministic cryptographic plan fingerprinting.
Any field reordering, key permutation, or round-trip serialization produces
an identical 64-character SHA-256 hex digest.

Guarantees:
- Zero I/O, zero file writes.
- Canonical JSON serialization with sorted keys and compact separators.
- Excludes the 'fingerprint' field itself to avoid self-referential hashing.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from sesslint.determinism import canonical_json_bytes


def compute_plan_fingerprint(plan_data: Mapping[str, Any]) -> str:
    """Compute a deterministic 64-character SHA-256 fingerprint for a repair plan dictionary.

    The 'fingerprint' key is excluded from the input dictionary if present.
    Uses the unified canonical JSON primitive in the hash domain
    (newline=False, ensure_ascii=False).
    """
    cleaned: dict[str, Any] = {k: v for k, v in plan_data.items() if k != "fingerprint"}
    encoded = canonical_json_bytes(cleaned, newline=False)
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "canonical_json_bytes",
    "compute_plan_fingerprint",
]
