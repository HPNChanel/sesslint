"""Structured progress events and cooperative cancellation for long-running
operations (DW-T-13).

Long-running API calls (directory scans, single-file checks, repair) accept an
optional ``progress_cb`` callback receiving frozen :class:`ProgressEvent`
records and an optional :class:`CancellationToken` checked at existing loop
boundaries.

Contract (FR-081 applies to progress too):

- Events carry counters and coordinates only — a phase name, completed/total
  counts, and an optional basename or step identifier. Record content is never
  emitted.
- Progress emission never affects output bytes or finding order; events are
  emitted in a deterministic sequence for a deterministic input.
- Cancellation is cooperative: :meth:`CancellationToken.throw_if_cancelled`
  raises :class:`OperationCancelled`, which propagates through the same
  cleanup paths as ``KeyboardInterrupt`` (no partial outputs, source
  immutable). CLI exit semantics are unchanged — a cancelled CLI operation
  still exits 130 via the existing interrupt handling.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ProgressEvent:
    """A single structured progress emission.

    Attributes:
        phase: Stable phase identifier, e.g. ``"scan"``, ``"check:load"``,
            ``"repair:execute"``.
        completed: Units of work finished within ``phase`` (1-based count of
            completed items; phase-start emissions use the count completed so
            far).
        total: Total units for ``phase`` when known upfront, else ``None``.
        item: Optional current-item coordinate — a basename or step
            identifier only, never a full path or record content.
    """

    phase: str
    completed: int
    total: int | None = None
    item: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a deterministic dict form (sorted keys, JSON-safe values)."""
        d: dict[str, Any] = {"phase": self.phase, "completed": self.completed}
        if self.total is not None:
            d["total"] = self.total
        if self.item is not None:
            d["item"] = self.item
        return d


class OperationCancelled(Exception):
    """Raised at cooperative cancellation boundaries when the token is set.

    Propagates like ``KeyboardInterrupt`` with respect to cleanup guarantees:
    callers must not leave partial outputs behind.
    """


class CancellationToken:
    """Cooperative cancellation token checked at loop boundaries.

    Thread-safe: ``cancel()`` may be called from any thread (e.g. a UI
    callback) while the operation runs on another.
    """

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        """Request cancellation; the next boundary check raises."""
        self._event.set()

    @property
    def is_cancelled(self) -> bool:
        """True after :meth:`cancel` has been called."""
        return self._event.is_set()

    def throw_if_cancelled(self) -> None:
        """Raise :class:`OperationCancelled` if cancellation was requested."""
        if self._event.is_set():
            raise OperationCancelled("operation cancelled")


ProgressCallback = Callable[[ProgressEvent], None]


def emit(cb: ProgressCallback | None, event: ProgressEvent) -> None:
    """Invoke ``cb`` with ``event`` when a callback is attached.

    Centralized so call sites stay uniform; a ``None`` callback is the
    zero-cost default path.
    """
    if cb is not None:
        cb(event)


def check_token(token: CancellationToken | None) -> None:
    """Raise :class:`OperationCancelled` when ``token`` is set and cancelled."""
    if token is not None:
        token.throw_if_cancelled()


__all__ = [
    "CancellationToken",
    "OperationCancelled",
    "ProgressCallback",
    "ProgressEvent",
    "check_token",
    "emit",
]
