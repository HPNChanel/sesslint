# Recipe: identical-duplicate-collapse

## Overview

- **Recipe Name**: `identical-duplicate-collapse`
- **Handles Codes**: `SL003`
- **Lossy**: `false`
- **Salvage Only**: `false`

## Preconditions

`no_sl203`, `adjacent_identical_duplicate`

## Risk

Zero risk for byte-identical duplicate events; potential loss of timestamp ordering nuance.

## Evidence

Adjacent events possess identical event IDs and byte-identical JSON payloads.

## Non-Proof Statement

Does not prove semantic idempotency of downstream consumers, only byte-level identity within session log.

## Loss Behavior

Collapses redundant duplicate event copies into a single canonical event record (lossless).

## Tested Fixture

- Path: `fixtures/repair/recipe_duplicate_collapse.json`
