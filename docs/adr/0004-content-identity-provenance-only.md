# ADR-0004: Content identity excludes provenance fields only — `seq` participates

- Status: accepted
- Date: 2026-09-19

## Context

Repair verification and reparse comparison need an equality notion that
ignores where a record *came from* (line numbers, raw-record digests)
while still detecting any change to what the record *says*. The open
question is which fields count as content versus provenance — in
particular whether `seq` (sequence ordinal) is identity or metadata.

## Decision

`content_identity_hash()` excludes exactly the provenance set
`{source_line, source_location, source_record_hash}` — and nothing else.
`seq` is authored data: two sessions differing only in declared sequence
numbers are NOT content-identical, so `seq` participates in the hash.
Legitimate renumbering is expressed through the `seq-renumber` repair
recipe, never through silent identity stripping.

## Consequences

- Repair verification detects any semantic drift — including sequence
  rewrites — as a fingerprint change.
- Duplicate-detection identity (`SL003`) compares content identity, so
  provenance-only differences cannot manufacture or mask duplicates.
- The exclusion set is closed: adding a field to
  `_PROVENANCE_FIELD_NAMES` is an ADR-level change.

## Alternatives rejected

- *Exclude `seq` from content identity* — rejected: makes declared-order
  corruption invisible to verify/diff; renumbering must be an explicit,
  auditable repair act.
- *Exclude all adapter-injected fields* — rejected: `original_id` and
  `source_adapter` are load-bearing for cross-format comparison.

## Evidence

- `src/sesslint/_canonical_codec.py:_PROVENANCE_FIELD_NAMES` — the
  three-field exclusion set.
- `src/sesslint/canonical.py:SessionEvent.content_identity_hash`,
  `src/sesslint/reference.py`, `src/sesslint/diff.py` — consumers.
- `tests/test_canonical_codec.py` — hashing semantics.
- `docs/SPEC.md` §6 — normative statement.
