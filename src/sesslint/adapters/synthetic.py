"""Collision-proof synthetic event ID generation and collision guard.

Reserved namespace format:
    sesslint:synthetic:<adapter>:<ordinal>:<8-hex-hash>

Where:
    <adapter>: Adapter identifier (e.g. 'claude_code', 'openai_agents')
    <ordinal>: Sequence ordinal of the event within the session (non-negative integer)
    <8-hex-hash>: First 8 hex characters of SHA-256 over:
                  `{source_hint}:{ordinal}:{payload_len}`
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Final

from sesslint.errors import AdapterError

if TYPE_CHECKING:
    from sesslint.canonical import SessionEvent

SYNTHETIC_ID_PREFIX: Final[str] = "sesslint:synthetic:"


def synthetic_event_id(
    adapter: str,
    ordinal: int,
    *,
    source_hint: str = "",
    payload_len: int = 0,
) -> str:
    """Generate a collision-resistant synthetic event ID in the reserved sesslint namespace.

    Format: `sesslint:synthetic:<adapter>:<ordinal>:<8-hex-hash>`
    Where `<8-hex-hash>` is the first 8 hex digits of SHA-256 over:
    `{source_hint}:{ordinal}:{payload_len}`.

    Args:
        adapter: Adapter identifier (e.g. 'claude_code', 'openai_agents').
        ordinal: Zero- or one-based sequence ordinal of the event within the session.
        source_hint: Path or stream identifier for the input data source.
        payload_len: Length in bytes of the record/payload.

    Returns:
        A deterministic synthetic event ID string.
    """
    hasher = hashlib.sha256()
    hasher.update(source_hint.encode("utf-8", errors="replace"))
    hasher.update(b":")
    hasher.update(str(ordinal).encode("utf-8"))
    hasher.update(b":")
    hasher.update(str(payload_len).encode("utf-8"))
    digest = hasher.hexdigest()[:8]
    return f"{SYNTHETIC_ID_PREFIX}{adapter}:{ordinal}:{digest}"


def is_synthetic_id(event_id: str) -> bool:
    """Return True if the given event ID is in the sesslint synthetic namespace."""
    return event_id.startswith(SYNTHETIC_ID_PREFIX)


class SyntheticIdCollisionGuard:
    """Tracks real versus synthetic IDs per session load to prevent cross-namespace collisions.

    If any synthetic event ID matches a real (vendor-supplied) event ID in the same session,
    the guard fails closed by raising an `AdapterError`.
    """

    def __init__(self) -> None:
        self._seen_real_ids: set[str] = set()
        self._seen_synthetic_ids: set[str] = set()

    @property
    def seen_real_ids(self) -> frozenset[str]:
        """Return the set of real event IDs seen in the current load."""
        return frozenset(self._seen_real_ids)

    @property
    def seen_synthetic_ids(self) -> frozenset[str]:
        """Return the set of synthetic event IDs generated in the current load."""
        return frozenset(self._seen_synthetic_ids)

    def register_real(self, real_id: str) -> str:
        """Register a vendor-provided real ID, ensuring no collision with synthetic IDs.

        Args:
            real_id: The real ID extracted from the record.

        Returns:
            The registered real ID.

        Raises:
            AdapterError: If real_id matches any previously generated synthetic ID.
        """
        if real_id in self._seen_synthetic_ids:
            raise AdapterError(
                f"Synthetic ID collision: real ID {real_id!r} collides with a previously "
                f"generated synthetic ID"
            )
        self._seen_real_ids.add(real_id)
        return real_id

    def register_synthetic(self, synthetic_id: str) -> str:
        """Register a generated synthetic ID, ensuring no collision with real IDs.

        Args:
            synthetic_id: The generated synthetic ID.

        Returns:
            The registered synthetic ID.

        Raises:
            AdapterError: If synthetic_id matches any previously seen real ID.
        """
        if synthetic_id in self._seen_real_ids:
            raise AdapterError(
                f"Synthetic ID collision: synthetic ID {synthetic_id!r} collides with a "
                f"previously seen real ID"
            )
        self._seen_synthetic_ids.add(synthetic_id)
        return synthetic_id

    def register(self, event_id: str, *, is_synthetic: bool) -> str:
        """Register an event ID as either real or synthetic.

        Args:
            event_id: The event ID to register.
            is_synthetic: True if the ID was synthetically generated; False if vendor-provided.

        Returns:
            The registered event ID.
        """
        if is_synthetic:
            return self.register_synthetic(event_id)
        return self.register_real(event_id)

    def check_event(self, event: SessionEvent, *, is_synthetic: bool | None = None) -> None:
        """Check and register an event with the collision guard.

        Args:
            event: The SessionEvent instance to validate.
            is_synthetic: Explicit flag indicating whether event ID is synthetic.
                          If None, defaults to `event.original_id is None`.
        """
        synthetic_flag = (event.original_id is None) if is_synthetic is None else is_synthetic
        self.register(event.id, is_synthetic=synthetic_flag)

    def assert_no_collision(self) -> None:
        """Assert that no real ID equals any synthetic ID in this load.

        Raises:
            AdapterError: If any ID exists in both the real and synthetic sets.
        """
        collision = self._seen_real_ids & self._seen_synthetic_ids
        if collision:
            colliding = sorted(collision)[0]
            raise AdapterError(
                f"Synthetic ID collision: ID {colliding!r} exists in both real and synthetic "
                f"namespaces"
            )


__all__ = [
    "SYNTHETIC_ID_PREFIX",
    "SyntheticIdCollisionGuard",
    "is_synthetic_id",
    "synthetic_event_id",
]
