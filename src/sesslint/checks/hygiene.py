"""Persisted-secret-shape detector (SL009, transcript-hygiene pack T-01).

Scans raw persisted record bytes — during the same streaming pass the
adapters already perform — for well-known secret token shapes. Detection is
family-based and deliberately precision-weighted: only documented token
formats fire, and no generic entropy heuristic is used.

Content-free contract:
- The matched secret value is never stored, logged, or emitted — not in
  findings, reports, stderr, or exception paths.
- Findings carry only the family label, record coordinates, an occurrence
  count, and SHA-256 digests of the full matched byte spans.
- ``SECRET_FAMILY_SET_VERSION`` versions the family registry: adding or
  tightening a family bumps the set version so evidence stays
  self-describing across releases.

The tracker aggregates one finding per (record, family) pair — a record
carrying three AWS keys produces a single ``aws-access-key`` finding with
``occurrence_count: 3`` and three digests. Output is capped at
``MAX_SECRET_FINDINGS_PER_FILE`` findings per file and
``MAX_DIGESTS_PER_FINDING`` digests per finding; totals in
``occurrence_count`` stay exact and suppressed output is marked with
``truncated`` / ``overflow`` evidence.

Rotation-verification note: ``match_sha256`` digests of low-entropy
families (notably ``generic-credential-assignment`` values) are brute-force
searchable; the hash proves *whether the same bytes still persist* after
remediation — it is not proof the value was secret, and deleting the file
never rotates the credential.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Final

from sesslint._secret_families import (
    SECRET_FAMILIES,
    SECRET_FAMILY_IDS,
    SECRET_FAMILY_SET_VERSION,
    iter_family_spans,
)
from sesslint.codes import SL009
from sesslint.finding import (
    Finding,
    Repairability,
    Severity,
    SourceRef,
    make_finding,
)

MAX_SECRET_FINDINGS_PER_FILE: Final[int] = 64
MAX_DIGESTS_PER_FINDING: Final[int] = 16

# Family registry lives in ``sesslint._secret_families`` — the single source
# of truth shared with discriminator redaction in ``adapters/safe_value.py``
# (B14). Each entry carries the exact pattern, its ``value_group`` (the whole
# match for vendor prefixes; the assigned value for
# ``generic-credential-assignment``/``bearer-token``/Azure, so ``token: X``
# and ``token=X`` digest the same credential), necessary literal anchors, and
# gate data. Ordered data, not a dict, so iteration order is contract.
#
# Vendor-prefix families anchor at a token boundary — a real credential
# starts at a boundary, while ``...Gsk-X``, ``xghp_y`` inside longer
# base64url/random blobs are substring noise (on a real 9GB corpus every one
# of 910 ``sk-``-shape hits was mid-token — zero boundary starts). The
# boundary is JSON-escape aware (B24): ``\n``/``\t``/``\u000a`` before a
# token in raw JSON bytes count as separators.

# Back-compat view: (family_id, reference_pattern, value_group) tuples.
_SECRET_FAMILIES: Final[tuple[tuple[str, re.Pattern[bytes], int], ...]] = tuple(
    (f.family_id, f.pattern, f.value_group) for f in SECRET_FAMILIES
)

# Bytes IGNORECASE folds ASCII only. The generic pattern's value character
# class is case-independent, so matching a lowered shadow preserves every
# span. Slice values from the original bytes below to preserve secret digests.
# Keeping the original pattern above makes the equivalence testable (T-10).
_GENERIC_ASSIGNMENT_LOWER: Final[re.Pattern[bytes]] = next(
    f.scan_pattern for f in SECRET_FAMILIES if f.family_id == "generic-credential-assignment"
)

# Necessary literals, never sufficient matches (T-10). Avoid running every
# negative-lookbehind regex across a giant record merely because one family
# made the window gate positive. The exact family regex remains authoritative.
_FAMILY_LITERALS: Final[dict[str, tuple[bytes, ...]]] = {
    f.family_id: f.anchors for f in SECRET_FAMILIES if f.anchors
}

# --- Gate layer ------------------------------------------------------------
# Per-line regex scanning does not meet the perf contract (~75-190us/line on
# the 250k-record/100MB bench). feed() therefore buffers records into a
# bounded window and gates each window once with C-speed primitives: literal
# ``in`` anchors, a few narrow regexes for families whose literal alone is
# too common in random blobs (telegram's ``:``+35 tail, ``npm_``/``hf_``/
# slack shapes), and a find-loop keyword check on lowered bytes. A miss
# skips all regex work for the whole window; a hit re-scans the window's
# records through the same superset checks per line and then the exact
# family patterns. The gate is a strict superset of every family pattern —
# each family match necessarily contains one of its gate literals, matches
# its gate pattern, or is a keyword..separator assignment — so detection
# results are identical; only the scan order changes. Gate data comes from
# the shared family table (``gate_literals`` / ``gate_pattern``).
_GATE_WINDOW_BYTES: Final[int] = 65_536

_GATE_LITERALS: Final[tuple[bytes, ...]] = tuple(
    dict.fromkeys(lit for f in SECRET_FAMILIES for lit in f.gate_literals)
)
_GATE_PATTERNS: Final[tuple[re.Pattern[bytes], ...]] = tuple(
    f.gate_pattern for f in SECRET_FAMILIES if f.gate_pattern is not None
)

# telegram-bot-token family: ``\d{8,10}:[A-Za-z0-9_-]{35}`` — every match
# contains ``:`` followed by 35 token-alphabet chars; that alone is the
# superset gate (the digits-prefix check stays in the family pattern). It is
# also the per-record prefilter for this anchorless family.
_GATE_TOKEN_TAIL: Final[re.Pattern[bytes]] = next(
    f.gate_pattern
    for f in SECRET_FAMILIES
    if f.family_id == "telegram-bot-token" and f.gate_pattern is not None
)

# Keyword roots for generic-credential-assignment, on lowered bytes. The
# family's keyword alternatives each contain one of these roots
# (``api_key``/``access_key``/``private_key`` contain ``key``,
# ``client_secret`` contains ``secret``, ``auth_token`` contains ``token``).
_GATE_KEYWORDS: Final[tuple[bytes, ...]] = (
    b"password",
    b"passwd",
    b"key",
    b"secret",
    b"token",
)

# Bytes allowed between a keyword and the ``:``/``=`` separator — superset of
# the family's ``(?:\\?["\'.-])*\s*`` middle (quotes, dots, dashes,
# backslashes, whitespace).
_GATE_KW_MID: Final[bytes] = b"\"'.-\\ \t\r\n"
_GATE_KW_SEP: Final[bytes] = b":="


def _kw_assignment_present(lowered: bytes) -> bool:
    """Find-loop superset of the generic-assignment keyword+separator shape.

    For each keyword occurrence, skip the allowed middle bytes; a ``:`` or
    ``=`` immediately after counts as a candidate. Overmatching is safe —
    the exact family pattern arbitrates.
    """
    n = len(lowered)
    for kw in _GATE_KEYWORDS:
        i = lowered.find(kw)
        while i != -1:
            j = i + len(kw)
            while j < n and lowered[j] in _GATE_KW_MID:
                j += 1
            if j < n and lowered[j] in _GATE_KW_SEP:
                return True
            i = lowered.find(kw, i + 1)
    return False


def _gate_maybe_contains_secret(data: bytes) -> bool:
    """Superset gate over a byte window: never misses a family match."""
    for anchor in _GATE_LITERALS:
        if anchor in data:
            return True
    for gate in _GATE_PATTERNS:
        if gate.search(data) is not None:
            return True
    return _kw_assignment_present(data.lower())


def _line_gate_maybe_contains_secret(raw: bytes) -> bool:
    """Per-line superset gate used only inside hit windows."""
    for anchor in _GATE_LITERALS:
        if anchor in raw:
            return True
    for gate in _GATE_PATTERNS:
        if gate.search(raw) is not None:
            return True
    return _kw_assignment_present(raw.lower())


@dataclass(slots=True)
class _HitAgg:
    """Per-(record, family) aggregation: count, distinct digests, max length."""

    count: int = 0
    digests: set[str] = field(default_factory=set)
    max_len: int = 0


# Aggregation key: (record_ordinal, line_number, byte_offset, byte_end, family)
_HitKey = tuple[int | None, int | None, int | None, int | None, str]


class SecretScanTracker:
    """Accumulate SL009 secret-shape hits for one file scan.

    Adapters feed every persisted record's raw bytes through :meth:`feed`
    during the normal streaming pass — before JSON validation — so malformed,
    truncated, and unknown-type records are scanned too. ``feed_blob``
    covers single-document formats where per-record byte spans do not exist.

    Records are buffered into a bounded pending window (``_GATE_WINDOW_BYTES``)
    and screened once per window by a strict-superset gate; only windows that
    pass the gate have their records scanned against the family patterns.
    No matched bytes are retained: only the family id, a SHA-256 digest of
    the matched span, its length, and the record coordinates survive.
    """

    def __init__(self) -> None:
        self._hits: dict[_HitKey, _HitAgg] = {}
        self._pending: list[
            tuple[bytes | memoryview, int | None, int | None, int | None, int | None]
        ] = []
        self._pending_bytes = 0

    def feed(
        self,
        raw_bytes: bytes | memoryview,
        *,
        line_number: int | None,
        byte_offset: int | None,
        byte_end: int | None,
        record_ordinal: int | None,
    ) -> None:
        """Buffer one record's raw bytes for gated scanning.

        Called for every non-empty physical record — including records the
        adapter later rejects — so secrets in malformed lines are still
        surfaced. Cheap: an append plus a counter per record; the gate and
        family regexes run at window flush, not per line. ``memoryview``
        spans are accepted zero-copy and only materialized to bytes when a
        window actually passes the superset gate (T-10).
        """
        if not raw_bytes:
            return
        self._pending.append((raw_bytes, line_number, byte_offset, byte_end, record_ordinal))
        self._pending_bytes += len(raw_bytes)
        if self._pending_bytes >= _GATE_WINDOW_BYTES:
            self._flush_pending()

    def _flush_pending(self) -> None:
        """Gate the buffered window; family-scan its records only on a hit."""
        if not self._pending:
            return
        if _gate_maybe_contains_secret(b"".join(item[0] for item in self._pending)):
            for raw, line_number, byte_offset, byte_end, record_ordinal in self._pending:
                # bytes ``in``/lower() semantics need a materialized copy;
                # memoryview silently misses multi-byte literals otherwise.
                raw_b = raw.tobytes() if type(raw) is memoryview else raw
                if _line_gate_maybe_contains_secret(raw_b):
                    self._scan_record(
                        raw_b,
                        line_number=line_number,
                        byte_offset=byte_offset,
                        byte_end=byte_end,
                        record_ordinal=record_ordinal,
                    )
        self._pending.clear()
        self._pending_bytes = 0

    def _scan_record(
        self,
        raw_bytes: bytes,
        *,
        line_number: int | None,
        byte_offset: int | None,
        byte_end: int | None,
        record_ordinal: int | None,
    ) -> None:
        """Run the exact family patterns over one record's raw bytes.

        ``iter_family_spans`` applies the JSON-escape-aware token boundary
        (B24), co-occurrence markers, and placeholder/value vetoes; casefold
        families match an ASCII-lowered shadow while spans slice the original
        bytes, so digests stay case-sensitive (T-10).
        """
        for family in SECRET_FAMILIES:
            family_id = family.family_id
            anchors = _FAMILY_LITERALS.get(family_id)
            if anchors is not None and not any(anchor in raw_bytes for anchor in anchors):
                continue
            if family_id == "telegram-bot-token" and _GATE_TOKEN_TAIL.search(raw_bytes) is None:
                continue
            for value_start, value_end in iter_family_spans(family, raw_bytes):
                secret_bytes = raw_bytes[value_start:value_end]
                key: _HitKey = (
                    record_ordinal,
                    line_number,
                    byte_offset,
                    byte_end,
                    family_id,
                )
                agg = self._hits.get(key)
                if agg is None:
                    agg = _HitAgg()
                    self._hits[key] = agg
                agg.count += 1
                agg.digests.add(hashlib.sha256(secret_bytes).hexdigest())
                if len(secret_bytes) > agg.max_len:
                    agg.max_len = len(secret_bytes)

    def feed_blob(self, data: bytes) -> None:
        """Scan a whole-document byte blob line-by-line.

        Single-document formats (a JSON export object) cannot map internal
        elements to physical byte offsets without an offset-tracking parser;
        physical line numbers and byte offsets are still exact, while
        ``record_ordinal`` is reported as absent for these records.
        """
        offset = 0
        line_number = 0
        total = len(data)
        while offset < total:
            line_number += 1
            nl = data.find(b"\n", offset)
            end = total if nl == -1 else nl + 1
            self.feed(
                data[offset:end],
                line_number=line_number,
                byte_offset=offset,
                byte_end=end,
                record_ordinal=None,
            )
            offset = end

    def into_findings(self, *, path_str: str) -> list[Finding]:
        """Materialize aggregated hits as SL009 findings (pure, idempotent).

        Flushes any pending window first. Emits at most
        ``MAX_SECRET_FINDINGS_PER_FILE`` findings ordered by
        (line, ordinal, family); when more would exist the final emitted
        finding carries ``truncated: true`` plus ``overflow`` = the count of
        suppressed (record, family) findings.
        """
        self._flush_pending()
        if not self._hits:
            return []
        ordered = sorted(
            self._hits.items(),
            key=lambda kv: (
                kv[0][1] if kv[0][1] is not None else -1,
                kv[0][0] if kv[0][0] is not None else -1,
                kv[0][4],
            ),
        )
        suppressed = max(0, len(ordered) - MAX_SECRET_FINDINGS_PER_FILE)
        emitted = ordered[:MAX_SECRET_FINDINGS_PER_FILE]
        out: list[Finding] = []
        for idx, ((ordinal, line, byte_off, byte_end, family), agg) in enumerate(emitted):
            evidence: dict[str, Any] = {
                "secret_family": family,
                "occurrence_count": agg.count,
                "match_sha256": sorted(agg.digests)[:MAX_DIGESTS_PER_FINDING],
                "match_len": agg.max_len,
                "secret_family_set": SECRET_FAMILY_SET_VERSION,
            }
            if ordinal is not None:
                evidence["record_ordinal"] = ordinal
            if byte_off is not None:
                evidence["byte_offset"] = byte_off
            if byte_end is not None:
                evidence["byte_end"] = byte_end
            if len(agg.digests) > MAX_DIGESTS_PER_FINDING or (
                suppressed and idx == len(emitted) - 1
            ):
                evidence["truncated"] = True
            if suppressed and idx == len(emitted) - 1:
                evidence["overflow"] = suppressed
            out.append(
                make_finding(
                    code=SL009,
                    severity=Severity.WARNING,
                    repairability=Repairability.MANUAL,
                    message_template=("Persisted secret-shaped material in record on line {line}"),
                    source=SourceRef(path=path_str, line=line, record_id=None),
                    evidence=evidence,
                )
            )
        return out


__all__ = [
    "MAX_DIGESTS_PER_FINDING",
    "MAX_SECRET_FINDINGS_PER_FILE",
    "SECRET_FAMILY_IDS",
    "SECRET_FAMILY_SET_VERSION",
    "SecretScanTracker",
]
