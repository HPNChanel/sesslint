"""Independent reference reconstruction check for A4 assurance (T-14, AC-027).

A4 (reference-loader equivalent) requires more than a clean profile replay: an
independent reconstruction of the canonical events must agree with the primary
parse. This module implements that check honestly and narrowly:

- Operates on canonical events, so it is adapter-agnostic.
- Returns False fast on any error/fatal/warning finding (also bounding cost on
  the hostile/bench path, where findings are always present).
- Reconstructs via serialize (dump_canonical) -> reparse (load_canonical) and
  compares event count plus the multiset of per-event content-identity hashes.
- Fails closed: any exception, empty input, or non-event input yields False.
- Scale-bounded: inputs above MAX_REFERENCE_EVENTS skip the loader (A3 max),
  protecting the 250k-record bench budget (AC-023).

The check depends on the documented adapter round-trip invariant
(read(write(events)) == events). If round-trip ever diverges, A4 is withheld
(A3 max) rather than over-claimed.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from typing import Any, Final

from sesslint.adapters.canonical import dump_canonical, load_canonical
from sesslint.canonical import SessionEvent
from sesslint.codes import Severity
from sesslint.finding import Finding

MAX_REFERENCE_EVENTS: Final[int] = 50000

_BLOCKING_SEVERITIES: tuple[Severity, ...] = (
    Severity.ERROR,
    Severity.FATAL,
    Severity.WARNING,
)


def _identity_multiset(events: Sequence[Any]) -> Counter[str] | None:
    """Return multiset of content-identity hashes, or None if not comparable."""
    identities: list[str] = []
    for ev in events:
        if not isinstance(ev, SessionEvent):
            return None
        try:
            identities.append(ev.content_identity_hash())
        except Exception:
            return None
    return Counter(identities)


def reference_equivalent(events: Sequence[Any] | None) -> bool:
    """Return True when independent reconstruction agrees with the input events.

    Fails closed (False) on empty input, non-event input, any exception, or
    any count/identity divergence between input and reconstruction.
    """
    if events is None or len(events) == 0:
        return False
    if len(events) > MAX_REFERENCE_EVENTS:
        return False
    try:
        data = dump_canonical(events, None)
        reparsed, reparse_findings = load_canonical(data)
    except Exception:
        return False
    if len(reparsed) != len(events):
        return False
    if any(f.severity in _BLOCKING_SEVERITIES for f in reparse_findings):
        return False
    # Dedup fast path: if reconstructed events directly match original events,
    # then their content identities are guaranteed identical without rehashing.
    try:
        if list(events) == list(reparsed):
            return True
    except Exception:
        pass
    try:
        original = _identity_multiset(events)
        rebuilt = _identity_multiset(reparsed)
    except Exception:
        return False
    if original is None or rebuilt is None or original != rebuilt:
        return False
    # Verify sequential ordering to prevent out-of-order/shuffled reconstructions
    try:
        orig_seq = [ev.content_identity_hash() for ev in events if isinstance(ev, SessionEvent)]
        rebuilt_seq = [
            ev.content_identity_hash() for ev in reparsed if isinstance(ev, SessionEvent)
        ]
        if orig_seq != rebuilt_seq:
            return False
    except Exception:
        return False
    return True


def reference_equivalent_if_clean(
    events: Sequence[Any] | None, findings: Sequence[Finding]
) -> bool:
    """Return True only for clean inputs whose reconstruction agrees.

    Short-circuits to False (without running the loader) when any finding has
    error, fatal, or warning severity.
    """
    if any(f.severity in _BLOCKING_SEVERITIES for f in findings):
        return False
    return reference_equivalent(events)


__all__ = [
    "MAX_REFERENCE_EVENTS",
    "reference_equivalent",
    "reference_equivalent_if_clean",
]
