# Recipe: compaction-projection-reunion

## Overview

- **Recipe Name**: `compaction-projection-reunion`
- **Handles Codes**: `SL108`
- **Lossy**: `false`
- **Salvage Only**: `false`

## Preconditions

`no_sl203`, `single_boundary_split`

## Risk

Recombining context across compaction boundaries might exceed target LLM token context limits.

## Evidence

A compaction marker split a single tool call from its matching tool result across an atomic turn boundary.

## Non-Proof Statement

Does not prove that the underlying LLM would have retained both records in active working memory.

## Loss Behavior

Reunites the split pair on the active side of the compaction boundary (lossless).

## Tested Fixture

- Path: `fixtures/repair/recipe_reunion.json`
