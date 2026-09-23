# Recipe: torn-record-excision

## Overview

- **Recipe Name**: `torn-record-excision`
- **Handles Codes**: `SL001`
- **Lossy**: `true`
- **Salvage Only**: `true`

Drops exactly one nonterminal malformed record — a physical line that failed
parsing and produced no canonical event — when the operator explicitly opts in
via `--policy salvage --acknowledge-side-effects`. The excision is realized at
write-back: canonical re-serialization omits the line because it never became
an event, and vendor write-back removes the physical line via the step's
finding fingerprint. Every parsed event is preserved verbatim; nothing about
the malformed bytes is interpreted, guessed, or synthesized.

## Preconditions

`salvage_policy`, `acknowledge_side_effects`, `sl001_excisable`

`sl001_excisable` requires the finding to be `SL001` anchored to a real
physical record: a positive source line plus integer `byte_offset`/`byte_end`/
`record_ordinal` coordinates. Stream-level refusals (`reason:
size_limit_exceeded`) are never excisable — there is no droppable line. When
the reader extracted a record id from the malformed bytes and any parsed
event's `parent_id` equals it, the precondition refuses (excision would orphan
a provable dependent); such sessions need manual intervention or branch
handling. Any failure blocks planning with
`precondition-failed:sl001_excisable`; the apply-time transform re-validates
the same anchors and dependents and refuses via `PreconditionFailed`.

## Risk

High: the torn record's contents are unrecoverable by definition. It may hold
the sole evidence of an external action, a checkpoint, or causal links that
other records depend on. The recipe never proves the record was unimportant —
it trades fidelity for a parseable continuation artifact under explicit
operator acknowledgement.

## Evidence

The `SL001` finding carries the record's stream coordinates (line, byte span,
record ordinal) and, when recoverable, a best-effort record id. The plan step
copies those anchors into its params so the dropped record remains
identifiable by location and finding fingerprint in the plan and manifest —
never by content.

## Non-Proof Statement

Excision proves nothing about what the record contained or whether dependent
state exists beyond the parsed stream. Output assurance is capped at
structural validity; sessions whose parsed events reference the torn record
still fail post-repair revalidation (`SL004` missing parent) and the executor
refuses rather than emit an inconsistent artifact.

## Loss Behavior

Exactly one record is omitted (loss class `torn-record`, count 1 per step).
The loss is a *record* loss, not an event loss: `total_kept` counts the
parsed event list only. No events, payloads, or ordering are synthesized; the
source artifact is never modified.

## Tested Fixture

- Path: `tests/repair/test_sl001_excision.py` (synthetic torn-line sessions
  built inline; no committed payload fixtures required)
