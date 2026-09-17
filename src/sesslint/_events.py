"""Shared canonical-event field accessors and converters (DW-T-10).

Single authoritative implementation of the ``_event_*`` helpers previously
duplicated across ``repair/planner.py``, ``policy/abstention.py``,
``repair/recipes_*.py``, ``repair/preconditions.py``, and ``repair/executor.py``.
All copies were verified byte-for-byte identical before consolidation, except
``_copy_events_as_dicts``: the recipe modules tolerate unconvertible events via
a ``dict(ev)`` fallback, while the executor intentionally fails closed — both
semantics are preserved here as ``_copy_events_as_dicts`` (tolerant) and
``_copy_events_as_dicts_strict`` (no fallback).

Private module: not part of the public API surface.
"""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Mapping, Sequence
from typing import Any

from sesslint.canonical import to_canonical_dict
from sesslint.determinism import canonical_json_bytes


def _event_kind(ev: Any) -> str | None:
    k = getattr(ev, "kind", None)
    if k is None and isinstance(ev, Mapping):
        k = ev.get("kind")
    return str(k) if k is not None else None


def _event_id(ev: Any) -> str | None:
    i = getattr(ev, "id", None)
    if i is None and isinstance(ev, Mapping):
        i = ev.get("id")
    return str(i) if i is not None else None


def _event_parent_id(ev: Any) -> str | None:
    p = getattr(ev, "parent_id", None)
    if p is None and isinstance(ev, Mapping):
        p = ev.get("parent_id")
    return str(p) if p is not None else None


def _event_corr_id(ev: Any) -> str | None:
    c = getattr(ev, "correlation_id", None)
    if c is None and isinstance(ev, Mapping):
        c = ev.get("correlation_id")
    return str(c) if c is not None else None


def _event_content_fingerprint(ev: Any) -> str:
    ch = getattr(ev, "content_hash", None)
    if ch is None and isinstance(ev, Mapping):
        ch = ev.get("content_hash")
    if isinstance(ch, str) and ch:
        return ch
    if hasattr(ev, "payload_hash"):
        return str(ev.payload_hash())
    payload = getattr(ev, "payload", None)
    if payload is None and isinstance(ev, Mapping):
        payload = ev.get("payload")
    if isinstance(payload, Mapping):
        return hashlib.sha256(canonical_json_bytes(payload, newline=False)).hexdigest()
    if hasattr(ev, "to_canonical_bytes"):
        return hashlib.sha256(ev.to_canonical_bytes()).hexdigest()
    if isinstance(ev, Mapping):
        return hashlib.sha256(canonical_json_bytes(ev, newline=False)).hexdigest()
    return hashlib.sha256(str(ev).encode("utf-8")).hexdigest()


def _event_canonical_hash(ev: Any) -> str:
    if hasattr(ev, "canonical_hash"):
        return str(ev.canonical_hash())
    if hasattr(ev, "to_canonical_bytes"):
        return hashlib.sha256(ev.to_canonical_bytes()).hexdigest()
    if isinstance(ev, Mapping):
        return hashlib.sha256(canonical_json_bytes(ev, newline=False)).hexdigest()
    return hashlib.sha256(str(ev).encode("utf-8")).hexdigest()


def _to_event_dict(ev: Any) -> dict[str, Any]:
    if hasattr(ev, "to_canonical_dict"):
        return copy.deepcopy(ev.to_canonical_dict())
    if isinstance(ev, Mapping):
        return copy.deepcopy(dict(ev))
    try:
        return copy.deepcopy(to_canonical_dict(ev))
    except Exception:
        return copy.deepcopy(dict(ev))


def _copy_events_as_dicts(events: Sequence[Any]) -> list[dict[str, Any]]:
    return [_to_event_dict(e) for e in events]


def _copy_events_as_dicts_strict(events: Sequence[Any]) -> list[dict[str, Any]]:
    """Executor semantics: deep-copy events with NO ``dict(ev)`` fallback.

    Events that cannot be canonically converted raise — the executor fails
    closed rather than repairing a partial projection (DW-T-10).
    """
    result: list[dict[str, Any]] = []
    for ev in events:
        if hasattr(ev, "to_canonical_dict"):
            result.append(copy.deepcopy(ev.to_canonical_dict()))
        elif isinstance(ev, Mapping):
            result.append(copy.deepcopy(dict(ev)))
        else:
            result.append(copy.deepcopy(to_canonical_dict(ev)))
    return result
