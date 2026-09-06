# Recipe: proven-unique-parent-restore

## Overview

- **Recipe Name**: `proven-unique-parent-restore`
- **Handles Codes**: `SL004`
- **Lossy**: `false`
- **Salvage Only**: `false`

## Preconditions

`no_sl203`, `unique_parent_candidate`

## Risk

Re-attaching a disconnected child to an unintended parent if ancestry was non-linear.

## Evidence

The missing parent candidate is uniquely identified by unambiguous lineage traversal without competing candidates.

## Non-Proof Statement

Does not prove causal intention of the original agent turn, only topological uniqueness in DAG reconstruction.

## Loss Behavior

Updates the child parent_id pointer to the proven unique predecessor (lossless).

## Tested Fixture

- Path: `fixtures/repair/recipe_parent_restore.json`
