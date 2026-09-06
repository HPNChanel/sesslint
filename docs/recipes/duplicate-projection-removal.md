# Recipe: duplicate-projection-removal

## Overview

- **Recipe Name**: `duplicate-projection-removal`
- **Handles Codes**: `SL104`
- **Lossy**: `false`
- **Salvage Only**: `false`

## Preconditions

`no_sl203`, `duplicate_projection_identical`

## Risk

Removing duplicate tool results could lose delivery attempt metadata.

## Evidence

Multiple tool result events correlate to the same tool call and contain identical output payloads.

## Non-Proof Statement

Does not prove that the external tool was only invoked once; only proves logged results are identical.

## Loss Behavior

Discards redundant identical tool result projections (lossless).

## Tested Fixture

- Path: `fixtures/repair/recipe_projection_removal.json`
