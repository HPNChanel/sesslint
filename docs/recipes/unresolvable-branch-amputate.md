# Recipe: unresolvable-branch-amputate

## Overview

- **Recipe Name**: `unresolvable-branch-amputate`
- **Handles Codes**: `SL005`, `SL006`
- **Lossy**: `true`
- **Salvage Only**: `true`

## Preconditions

`salvage_policy`, `branch_has_no_checkpoint`

## Risk

Irreversible loss of conversation branches and any decisions recorded within the pruned subtrees.

## Evidence

The branch contains parent cycles or disconnected components with no durable checkpoints.

## Non-Proof Statement

Does not prove that the amputated branch was intended to be discarded by the user.

## Loss Behavior

Prunes the unresolvable branch nodes from the session DAG (lossy, salvage only).

## Tested Fixture

- Path: `fixtures/repair/salvage_branch.json`
