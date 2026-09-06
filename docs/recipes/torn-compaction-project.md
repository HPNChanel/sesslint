# Recipe: torn-compaction-project

## Overview

- **Recipe Name**: `torn-compaction-project`
- **Handles Codes**: `SL108`
- **Lossy**: `true`
- **Salvage Only**: `true`

## Preconditions

`salvage_policy`, `sl108_present`

## Risk

Loss of compaction historical summary or tool result pairing context.

## Evidence

A compaction boundary is torn or incomplete with SL108 present, leaving half of a tool pair stranded.

## Non-Proof Statement

Does not prove the complete conversation state can be accurately reconstructed without the severed turn.

## Loss Behavior

Projects the surviving half of the compaction context and discards orphaned fragments (lossy, salvage only).

## Tested Fixture

- Path: `fixtures/repair/salvage_project.json`
