"""Vendor write-back: project a canonical repair onto source lines.

SessLint never reconstructs a vendor record (that would be invention). Instead it
keeps-or-drops WHOLE physical source lines verbatim — every surviving record is
byte-identical to the source — then the caller proves validity by re-loading the
emitted artifact through its adapter and re-running the checks.

The physical line is the atomic unit because one vendor line can expand into
several canonical events (e.g. a single record carrying a text block plus N
tool-use blocks all share one ``source_line``). A line is kept only when
every canonical event derived from it survives the repair unchanged.

Fail-closed refusal conditions (``VendorProjectionRefused``):

- ``R1`` synthesized-event — an output event has ``source_line is None``; there is
  no vendor record to write it back to.
- ``R2`` partial-line — a source line survives partially (some of its canonical
  events kept, some dropped); emitting it would require an intra-line field edit.
- ``R3`` rewritten-field — a surviving event's ``content_identity_hash`` differs
  from the source event's (a recipe rewrote a field such as ``parent_id``).
- ``R4`` source-drift — the re-read source line's recomputed record hash does not
  equal the stored ``source_record_hash`` (the file changed between plan & write).
- ``R5`` reorder-required — the required output line order is not a subsequence of
  the source order; expressing it would need a reorder.
- ``R6`` adapter-unsupported — the artifact is not a per-line record stream (e.g.
  a single-document JSON export, whose ``source_line`` is best-available,
  not a true physical record boundary).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from sesslint.adapters.detect import (
    FORMAT_CLAUDE_CODE,
    FORMAT_CODEX_ROLLOUT,
    FORMAT_OPENAI_AGENTS,
)
from sesslint.canonical import canonical_bytes
from sesslint.repair.errors import VendorProjectionRefused

if TYPE_CHECKING:
    from sesslint.canonical import SessionEvent


# Formats for which line-verbatim write-back is provably expressible.
WRITEBACK_FORMATS: Final[frozenset[str]] = frozenset(
    {FORMAT_CLAUDE_CODE, FORMAT_OPENAI_AGENTS, FORMAT_CODEX_ROLLOUT}
)


@dataclass(frozen=True, slots=True)
class ProjectionSummary:
    """Content-free accounting of a vendor write-back projection."""

    retained_lines: int
    dropped_lines: int
    emitted_sha256: str
    emit_format: str

    def to_dict(self) -> dict[str, object]:
        """Serialize the projection summary for the repair manifest."""
        return {
            "dropped_lines": self.dropped_lines,
            "emit_format": self.emit_format,
            "emitted_sha256": self.emitted_sha256,
            "retained_lines": self.retained_lines,
        }


def _line_number(event: SessionEvent) -> int | None:
    """Return the 1-based physical source line for an event, or None."""
    line = getattr(event, "source_line", None)
    if line is None and isinstance(event, Mapping):
        line = event.get("source_line")
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        return None
    return line


def _identity(event: SessionEvent) -> str:
    """Return the content-identity hash for an event (provenance excluded)."""
    fn = getattr(event, "content_identity_hash", None)
    if callable(fn):
        return str(fn())
    return ""


def emit_vendor_bytes(
    source_bytes: bytes,
    source_events: Sequence[SessionEvent],
    output_events: Sequence[SessionEvent],
    emit_format: str,
    *,
    drop_lines: frozenset[int] | None = None,
) -> tuple[bytes, ProjectionSummary]:
    """Project a canonical repair back onto verbatim vendor source lines.

    Args:
        source_bytes: Raw bytes of the original vendor source file.
        source_events: Canonical events produced by the vendor adapter for the
            source file (carry ``source_line``/``source_record_hash``).
        output_events: The repaired canonical event sequence.
        emit_format: Target vendor format id (a member of
            ``WRITEBACK_FORMATS``).
        drop_lines: Physical source lines the repair plan explicitly discards
            even though they produced no canonical events (e.g. the torn
            terminal record targeted by ``torn-terminal-record-discard``).
            Lines without events that are NOT in this set are kept verbatim —
            uninterpreted content is never silently dropped.

    Returns:
        ``(emitted_bytes, ProjectionSummary)`` — the emitted artifact and a
        content-free accounting for the manifest.

    Raises:
        VendorProjectionRefused: On any refusal condition R1-R6.
    """
    if emit_format not in WRITEBACK_FORMATS:
        raise VendorProjectionRefused(
            f"Write-back is not supported for format '{emit_format}'. "
            "Use '--emit canonical' to produce a canonical repaired artifact.",
            reason="R6",
        )

    # R6: a single-document JSON export is not a per-line record stream; its
    # `source_line` coordinates do not denote physical record boundaries.
    try:
        json.loads(source_bytes)
    except (ValueError, TypeError):
        pass  # multi-record stream (JSONL) — expected
    else:
        raise VendorProjectionRefused(
            "Write-back requires a per-line record stream (JSONL); a "
            "single-document JSON export has no physical record boundaries. "
            "Use '--emit canonical' to produce a canonical repaired artifact.",
            reason="R6",
        )

    lines = source_bytes.splitlines(keepends=True) if source_bytes else []
    drop_lines = drop_lines or frozenset()

    # Index each event-bearing source line -> [(event_id, identity)] in order.
    line_events: dict[int, list[tuple[str, str]]] = {}
    line_record_hash: dict[int, str] = {}
    for ev in source_events:
        ln = _line_number(ev)
        if ln is None:
            continue
        line_events.setdefault(ln, []).append((str(getattr(ev, "id", "")), _identity(ev)))
        rh = getattr(ev, "source_record_hash", None)
        if rh is None and isinstance(ev, Mapping):
            rh = ev.get("source_record_hash")
        if isinstance(rh, str):
            line_record_hash.setdefault(ln, rh)

    # Group output events by their source line, preserving output order.
    out_by_line: dict[int, list[tuple[str, str]]] = {}
    out_order: list[int] = []
    seen_lines: set[int] = set()
    for ev in output_events:
        ln = _line_number(ev)
        if ln is None:
            raise VendorProjectionRefused(
                "Repaired output contains a synthesized event with no source "
                "line; cannot project to vendor format. Use '--emit canonical'.",
                reason="R1",
            )
        out_by_line.setdefault(ln, []).append((str(getattr(ev, "id", "")), _identity(ev)))
        if ln not in seen_lines:
            seen_lines.add(ln)
            out_order.append(ln)

    # R5: a verbatim projection can only emit lines in increasing source order.
    # out_order holds each touched line in first-appearance order; if it is not
    # strictly increasing, the repair required a cross-line reorder.
    if out_order != sorted(out_order):
        raise VendorProjectionRefused(
            "Repair requires reordering source lines; cannot express as a "
            "verbatim vendor projection. Use '--emit canonical'.",
            reason="R5",
        )

    emitted_lines: list[bytes] = []
    retained = 0
    dropped = 0

    for idx, raw in enumerate(lines):
        ln = idx + 1
        src_evs = line_events.get(ln)
        out_evs = out_by_line.get(ln)

        if not src_evs:
            # Line produced no canonical events (blank/padding, uninterpreted
            # non-critical record, or a torn/malformed record). Keep it verbatim
            # unless the plan explicitly discarded it — never silently drop
            # content the event model does not represent.
            if ln in drop_lines:
                dropped += 1
                continue
            emitted_lines.append(raw)
            retained += 1
            continue

        if out_evs is None:
            # Every event derived from this line was dropped by the repair.
            dropped += 1
            continue

        # The line must survive whole: every canonical event derived from the
        # source line must be present and unchanged in the output.
        if len(out_evs) != len(src_evs):
            raise VendorProjectionRefused(
                f"Source line {ln} survives partially "
                f"({len(out_evs)}/{len(src_evs)} events); emitting it would "
                "require an intra-line field edit. Use '--emit canonical'.",
                reason="R2",
            )
        for (out_id, out_idn), (src_id, src_idn) in zip(out_evs, src_evs, strict=True):
            if out_id != src_id or out_idn != src_idn:
                raise VendorProjectionRefused(
                    f"A surviving event on source line {ln} was rewritten by a "
                    "recipe (content identity changed); cannot emit the line "
                    "verbatim. Use '--emit canonical'.",
                    reason="R3",
                )

        # R4: the re-read line must still hash to its stored record hash. The
        # stored hash was computed over the parsed JSON object (not raw bytes),
        # so re-parse the line before hashing.
        expected = line_record_hash.get(ln)
        if expected:
            try:
                parsed = json.loads(raw)
            except (ValueError, TypeError) as err:
                raise VendorProjectionRefused(
                    f"Source line {ln} no longer parses as a single JSON record "
                    "(source drifted). Re-run repair on a stable source.",
                    reason="R4",
                ) from err
            recomputed = f"sha256:{hashlib.sha256(canonical_bytes(parsed)).hexdigest()}"
            if recomputed != expected:
                raise VendorProjectionRefused(
                    f"Source line {ln} changed between planning and write "
                    "(record hash drift). Re-run repair on a stable source.",
                    reason="R4",
                )

        emitted_lines.append(raw)
        retained += 1

    emitted = b"".join(emitted_lines)
    summary = ProjectionSummary(
        retained_lines=retained,
        dropped_lines=dropped,
        emitted_sha256=hashlib.sha256(emitted).hexdigest(),
        emit_format=emit_format,
    )
    return emitted, summary


__all__ = [
    "ProjectionSummary",
    "VendorProjectionRefused",
    "WRITEBACK_FORMATS",
    "emit_vendor_bytes",
]
