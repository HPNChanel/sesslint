"""Record-size outlier check — SL011 (checks-rules T-07).

Flags the single largest record when its byte size is an extreme outlier
within the file's own distribution: fires only when
``record_bytes > max(median * K, FLOOR)`` (K=20, floor=256 KiB). Legitimate
big lines exist (vendor rollouts reach ~1.5 MiB), so this is a *relative*
check — absolute limits already live in the reader line cap.

Adapters publish per-record byte sizes on ``source_metadata["record_sizes"]``
(one int per record line, in stream order — bounded, content-free). Files
with fewer than ``SIZE_MIN_RECORDS`` records are skipped by the runner
(distribution meaningless); missing/short size data yields no finding.

At most one finding per file — the largest outlier only, bounded noise by
design. Determinism: integer median via sorted selection, size/ratio from
the file's own data — no wall clock, no randomness.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Final

from sesslint.canonical import SessionEvent
from sesslint.codes import SL011, Repairability, Severity
from sesslint.context import CheckContext
from sesslint.finding import Finding, SourceRef, make_finding

SIZE_MIN_RECORDS: Final[int] = 8
SIZE_RATIO_K: Final[int] = 20
SIZE_FLOOR_BYTES: Final[int] = 256 * 1024


def check_size_anomaly(
    events: Sequence[SessionEvent],
    *,
    source_path: str,
    context: CheckContext | None = None,
) -> list[Finding]:
    """Emit at most one SL011 for the largest record-size outlier.

    ``events`` is unused beyond presence — the metric is the adapter's
    ``record_sizes`` stream (line byte lengths), reached via ``context``.
    """
    meta = context.source_metadata if context is not None else None
    raw_sizes = meta.get("record_sizes") if isinstance(meta, Mapping) else None
    sizes: list[int] = []
    if isinstance(raw_sizes, list):
        sizes = [s for s in raw_sizes if isinstance(s, int) and not isinstance(s, bool) and s >= 0]
    if len(sizes) < SIZE_MIN_RECORDS:
        return []

    ordered = sorted(sizes)
    median = ordered[len(ordered) // 2]  # upper median — conservative threshold
    threshold = max(median * SIZE_RATIO_K, SIZE_FLOOR_BYTES)
    largest = max(sizes)
    if largest <= threshold:
        return []

    record_index = sizes.index(largest)
    return [
        make_finding(
            code=SL011,
            severity=Severity.INFO,
            repairability=Repairability.MANUAL,
            message_template="Record is a byte-size outlier within this file",
            source=SourceRef(path=source_path),
            evidence={
                "file_median_bytes": median,
                "ratio": round(largest / median, 3) if median else None,
                "record_bytes": largest,
                "record_index": record_index,
            },
        )
    ]


check_sl011 = check_size_anomaly

__all__ = [
    "SIZE_FLOOR_BYTES",
    "SIZE_MIN_RECORDS",
    "SIZE_RATIO_K",
    "check_size_anomaly",
    "check_sl011",
]
