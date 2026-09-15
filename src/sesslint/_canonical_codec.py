"""Canonical serialization and cryptographic hashing codec seam (T-01 / S1).

This module unifies all canonical serialization and identity hashing behind a single
narrow, strictly-typed protocol interface. It allows pluggable acceleration
(e.g., pure Python or optional native extension) with guaranteed fail-closed fallback
and byte-level determinism conforming to RFC 8785 (JSON Canonicalization Scheme).
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from typing import TYPE_CHECKING, Any, Final, Protocol, runtime_checkable

from sesslint.errors import SchemaError

if TYPE_CHECKING:
    from sesslint.canonical import SessionEvent

CODEC_INTERFACE_VERSION: Final[str] = "1.0.0"

_PROVENANCE_FIELD_NAMES: Final[frozenset[str]] = frozenset(
    {"source_line", "source_location", "source_record_hash"}
)


@runtime_checkable
class CanonicalCodec(Protocol):
    """Strict protocol contract for canonical serialization and hashing implementations."""

    @property
    def codec_name(self) -> str:
        """Name of the active codec engine."""
        ...

    @property
    def codec_version(self) -> str:
        """Version of the codec implementation."""
        ...

    def canonical_json_bytes(self, obj: Any, *, newline: bool = False) -> bytes:
        """Serialize an object or mapping to RFC 8785 canonical UTF-8 JSON bytes."""
        ...

    def content_identity_bytes(self, event: SessionEvent) -> bytes:
        """Serialize a SessionEvent to canonical UTF-8 bytes excluding provenance fields."""
        ...

    def content_identity_hash(self, event: SessionEvent) -> str:
        """Compute the SHA-256 hex digest of a SessionEvent's content identity bytes."""
        ...

    def payload_content_hash(self, payload: Mapping[str, Any]) -> str:
        """Compute the deterministic SHA-256 hex digest of a payload mapping."""
        ...

    def plan_fingerprint(
        self,
        plan_data: Mapping[str, Any],
        *,
        policy: str | None = None,
    ) -> str:
        """Compute the deterministic 64-character SHA-256 fingerprint of a repair plan."""
        ...


class PurePythonCanonicalCodec:
    """Pure-Python reference implementation of the CanonicalCodec protocol."""

    codec_name: Final[str] = "pure_python"
    codec_version: Final[str] = CODEC_INTERFACE_VERSION

    def canonical_json_bytes(self, obj: Any, *, newline: bool = False) -> bytes:
        """Serialize an object to RFC 8785 canonical UTF-8 JSON bytes."""
        target = obj.to_dict() if hasattr(obj, "to_dict") and callable(obj.to_dict) else obj
        try:
            normalized = self._normalize(target)
            encoded = json.dumps(
                normalized,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except RecursionError as err:
            raise SchemaError(
                "Object nesting depth exceeded during canonical serialization"
            ) from err
        except SchemaError:
            raise
        except (TypeError, ValueError) as err:
            raise SchemaError(f"Canonical serialization error: {err}") from err

        if newline:
            return encoded + b"\n"
        return encoded

    def content_identity_bytes(self, event: SessionEvent) -> bytes:
        """Serialize SessionEvent to canonical bytes excluding provenance fields."""
        d = event.to_canonical_dict()
        if any(f in d for f in _PROVENANCE_FIELD_NAMES):
            d = {k: v for k, v in d.items() if k not in _PROVENANCE_FIELD_NAMES}
        try:
            return json.dumps(
                d,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except RecursionError as err:
            raise SchemaError(
                "Object nesting depth exceeded during canonical serialization"
            ) from err
        except (TypeError, ValueError) as err:
            raise SchemaError(f"Canonical serialization error: {err}") from err

    def content_identity_hash(self, event: SessionEvent) -> str:
        """Compute SHA-256 hex digest of event content identity bytes."""
        return hashlib.sha256(self.content_identity_bytes(event)).hexdigest()

    def payload_content_hash(self, payload: Mapping[str, Any]) -> str:
        """Compute deterministic 'sha256:<hex>' digest of payload canonical bytes."""
        digest = hashlib.sha256(self.canonical_json_bytes(payload, newline=False)).hexdigest()
        return f"sha256:{digest}"

    def plan_fingerprint(
        self,
        plan_data: Mapping[str, Any],
        *,
        policy: str | None = None,
    ) -> str:
        """Compute deterministic 64-character SHA-256 fingerprint for a repair plan."""
        cleaned: dict[str, Any] = {k: v for k, v in plan_data.items() if k != "fingerprint"}
        if policy is not None and "policy" not in cleaned:
            cleaned["policy"] = policy
        raw_bytes = self.canonical_json_bytes(cleaned, newline=False)
        return hashlib.sha256(raw_bytes).hexdigest()

    def _normalize(self, obj: Any, seen: set[int] | None = None) -> Any:
        """Normalize objects to plain JSON types with sorted keys and minimal representation."""
        obj_type = type(obj)

        # Fast path 1: JSON primitives
        if obj_type is str or obj_type is int or obj_type is bool or obj is None:
            return obj

        if obj_type is float:
            if math.isnan(obj) or math.isinf(obj):
                raise SchemaError(f"Float value {obj!r} is not valid in canonical JSON (RFC 8785)")
            return obj

        # Fast path 2: SessionEvent
        from sesslint.canonical import SessionEvent

        if obj_type is SessionEvent:
            obj_id = id(obj)
            if seen is not None and obj_id in seen:
                raise SchemaError("Cyclic reference detected during canonical serialization")
            if seen is None:
                seen = set()
            seen.add(obj_id)
            try:
                ev_dict: dict[str, Any] = {
                    "actor": obj.actor,
                    "id": obj.id,
                    "kind": obj.kind,
                    "parent_id": obj.parent_id,
                    "payload": self._normalize(obj.payload, seen),
                    "seq": obj.seq,
                    "ts": obj.ts,
                }
                if obj.content_hash is not None:
                    ev_dict["content_hash"] = obj.content_hash
                if obj.correlation_id is not None:
                    ev_dict["correlation_id"] = obj.correlation_id
                if obj.branch_id is not None:
                    ev_dict["branch_id"] = obj.branch_id
                if obj.interaction_id is not None:
                    ev_dict["interaction_id"] = obj.interaction_id
                if obj.agent_id is not None:
                    ev_dict["agent_id"] = obj.agent_id
                if obj.execution_state is not None:
                    ev_dict["execution_state"] = obj.execution_state
                if obj.source_line is not None:
                    ev_dict["source_line"] = obj.source_line
                if obj.source_record_hash is not None:
                    ev_dict["source_record_hash"] = obj.source_record_hash
                if obj.original_id is not None:
                    ev_dict["original_id"] = obj.original_id
                if obj.source_adapter is not None:
                    ev_dict["source_adapter"] = obj.source_adapter
                if obj.source_location is not None:
                    ev_dict["source_location"] = obj.source_location
                if obj.side_effects is not None:
                    ev_dict["side_effects"] = obj.side_effects
                if obj.extra_fields:
                    if isinstance(obj.extra_fields, Mapping):
                        for k, v in obj.extra_fields.items():
                            if not isinstance(k, str):
                                raise SchemaError(
                                    f"Non-string dictionary key rejected under RFC 8785: {k!r}"
                                )
                            if k not in ev_dict:
                                ev_dict[k] = self._normalize(v, seen)
                return ev_dict
            finally:
                seen.remove(obj_id)

        # Fast path 3: Concrete dict
        if obj_type is dict:
            obj_id = id(obj)
            if seen is not None and obj_id in seen:
                raise SchemaError("Cyclic reference detected during canonical serialization")
            if seen is None:
                seen = set()
            seen.add(obj_id)
            try:
                norm_map: dict[str, Any] = {}
                for k, v in obj.items():
                    if type(k) is not str and not isinstance(k, str):
                        raise SchemaError(
                            f"Non-string dictionary key rejected under RFC 8785: {k!r}"
                        )
                    norm_map[k] = self._normalize(v, seen)
                return norm_map
            finally:
                seen.remove(obj_id)

        # Fast path 4: Concrete list
        if obj_type is list:
            obj_id = id(obj)
            if seen is not None and obj_id in seen:
                raise SchemaError("Cyclic reference detected during canonical serialization")
            if seen is None:
                seen = set()
            seen.add(obj_id)
            try:
                return [self._normalize(item, seen) for item in obj]
            finally:
                seen.remove(obj_id)

        # Generic path for other dataclasses, Mappings, and Sequences
        if seen is None:
            seen = set()

        if is_dataclass(obj) and not isinstance(obj, type):
            obj_id = id(obj)
            if obj_id in seen:
                raise SchemaError("Cyclic reference detected during canonical serialization")
            seen.add(obj_id)
            try:
                result: dict[str, Any] = {}
                for f in fields(obj):
                    val = getattr(obj, f.name)
                    if f.name == "extra_fields":
                        if isinstance(val, Mapping):
                            for k, v in val.items():
                                if not isinstance(k, str):
                                    raise SchemaError(
                                        f"Non-string dictionary key rejected under RFC 8785: {k!r}"
                                    )
                                if k not in result:
                                    result[k] = self._normalize(v, seen)
                        continue
                    if val is None and f.name != "parent_id":
                        continue
                    if f.name == "metadata" and isinstance(val, Mapping) and not val:
                        continue
                    result[f.name] = self._normalize(val, seen)
                return result
            finally:
                seen.remove(obj_id)

        if isinstance(obj, Mapping):
            obj_id = id(obj)
            if obj_id in seen:
                raise SchemaError("Cyclic reference detected during canonical serialization")
            seen.add(obj_id)
            try:
                gen_map: dict[str, Any] = {}
                for k, v in obj.items():
                    if not isinstance(k, str):
                        raise SchemaError(
                            f"Non-string dictionary key rejected under RFC 8785: {k!r}"
                        )
                    gen_map[k] = self._normalize(v, seen)
                return gen_map
            finally:
                seen.remove(obj_id)

        if isinstance(obj, (list, tuple)):
            obj_id = id(obj)
            if obj_id in seen:
                raise SchemaError("Cyclic reference detected during canonical serialization")
            seen.add(obj_id)
            try:
                return [self._normalize(item, seen) for item in obj]
            finally:
                seen.remove(obj_id)

        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _resolve_active_codec() -> CanonicalCodec:
    """Resolve the active canonical codec with fail-closed pure-Python fallback."""
    import os

    if os.environ.get("SESSLINT_DISABLE_ACCEL", "").strip() in ("1", "true", "yes"):
        return PurePythonCanonicalCodec()

    try:
        import sesslint._accel as _accel  # type: ignore[import-untyped]

        if getattr(_accel, "CODEC_INTERFACE_VERSION", None) == CODEC_INTERFACE_VERSION:
            native_factory = getattr(_accel, "NativeCanonicalCodec", None)
            if callable(native_factory):
                codec_instance = native_factory()
                if isinstance(codec_instance, CanonicalCodec):
                    return codec_instance
    except Exception:
        pass

    return PurePythonCanonicalCodec()


_ACTIVE_CODEC: CanonicalCodec = _resolve_active_codec()
_DEFAULT_PURE_CODEC: Final[PurePythonCanonicalCodec] = PurePythonCanonicalCodec()


def get_active_codec() -> CanonicalCodec:
    """Return the currently active CanonicalCodec instance."""
    return _ACTIVE_CODEC


def set_active_codec(codec: CanonicalCodec) -> None:
    """Explicitly set the active CanonicalCodec (for testing / benchmarking)."""
    global _ACTIVE_CODEC
    _ACTIVE_CODEC = codec


def normalize_canonical(obj: Any, seen: set[int] | None = None) -> Any:
    """Normalize objects to plain JSON types with sorted keys using pure-Python fast path."""
    return _DEFAULT_PURE_CODEC._normalize(obj, seen=seen)


def canonical_json_bytes(obj: Any, *, newline: bool = False) -> bytes:
    """Serialize an object to RFC 8785 canonical UTF-8 JSON bytes."""
    return _ACTIVE_CODEC.canonical_json_bytes(obj, newline=newline)


def content_identity_bytes(event: SessionEvent) -> bytes:
    """Serialize a SessionEvent to canonical bytes excluding provenance fields."""
    return _ACTIVE_CODEC.content_identity_bytes(event)


def content_identity_hash(event: SessionEvent) -> str:
    """Compute the SHA-256 hex digest of a SessionEvent's content identity bytes."""
    return _ACTIVE_CODEC.content_identity_hash(event)


def payload_content_hash(payload: Mapping[str, Any]) -> str:
    """Compute the deterministic SHA-256 hex digest of a payload mapping."""
    return _ACTIVE_CODEC.payload_content_hash(payload)


def plan_fingerprint(
    plan_data: Mapping[str, Any],
    *,
    policy: str | None = None,
) -> str:
    """Compute the deterministic 64-character SHA-256 fingerprint of a repair plan."""
    return _ACTIVE_CODEC.plan_fingerprint(plan_data, policy=policy)


__all__ = [
    "CODEC_INTERFACE_VERSION",
    "CanonicalCodec",
    "PurePythonCanonicalCodec",
    "canonical_json_bytes",
    "content_identity_bytes",
    "content_identity_hash",
    "get_active_codec",
    "normalize_canonical",
    "payload_content_hash",
    "plan_fingerprint",
    "set_active_codec",
]
