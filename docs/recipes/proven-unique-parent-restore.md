# Recipe: proven-unique-parent-restore

## Overview

- **Recipe Name**: `proven-unique-parent-restore`
- **Handles Codes**: `SL004`
- **Lossy**: `false`
- **Salvage Only**: `false`

## Preconditions
 
`no_sl203`, `unique_parent_candidate` (enforces full string equality, same branch, and same compaction segment confinement; rejects prefix matches)

## Risk

Re-attaching a disconnected child to an unintended parent if ancestry was non-linear or ambiguous. Mitigated by strict full-equality matching and branch/segment confinement (zero prefix guessing).

## Evidence

The missing parent candidate is uniquely identified by exact string equality (`c.id == parent_id`), same-branch confinement (`c.branch_id == child.branch_id`), and same-compaction-segment confinement without intervening `compaction_boundary` events.

## Non-Proof Statement

Does not prove semantic intention of the original agent turn, only exact topological uniqueness within the confined branch and compaction segment.

## Loss Behavior

Updates the child parent_id pointer to the proven unique predecessor (lossless).

## Tested Fixture

- Path: `fixtures/repair/recipe_parent_restore.json`
