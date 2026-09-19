# Recipe: identical-duplicate-drop

## Overview

- **Recipe Name**: `identical-duplicate-drop`
- **Handles Codes**: `SL003` (identical-duplicate class only)
- **Lossy**: `false`
- **Salvage Only**: `false`

## Preconditions

`no_sl203`, `sl003_identical_duplicate`

The `sl003_identical_duplicate` precondition is fail-closed on class: the
finding evidence must carry `variant == "identical-duplicate"` plus a
`record_indexes` list of at least two in-bounds integer positions.
Conflicting-duplicate findings never reach this recipe — they stay
`manual`/blocked, and the recipe re-verifies the variant at apply time as
defense-in-depth against crafted plans.

## Risk

Zero risk for byte-identical duplicate occurrences: the recipe keeps the
earliest canonical position and drops only later occurrences whose kind,
event id, and content fingerprint re-verify equal to the kept event. Any
drift (kind mismatch, content drift, id drift, out-of-bounds index,
boundary kind) fails closed with `PreconditionFailed`.

## Evidence

`SL003` identical-duplicate finding: multiple events share one event id
with byte-identical canonical content (`seq` and provenance fields
excluded). `record_indexes` lists every occurrence; the first is kept.

## Non-Proof Statement

Does not prove semantic deduplication intent of the emitting agent, only
byte-level identity of the removed records within the session log.

## Loss Behavior

Drops redundant identical copies (count = `len(record_indexes) - 1`);
children of a different-id dropped event are relinked to the kept id.
Content loss is nil — dropped bytes are byte-identical to the kept event.

## Tested Fixture

- Path: `fixtures/repair/t04_identical_duplicate_drop/source.jsonl`
