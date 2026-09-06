# Recipe: terminal-suffix-discard

## Overview

- **Recipe Name**: `terminal-suffix-discard`
- **Handles Codes**: `SL005`, `SL203`
- **Lossy**: `true`
- **Salvage Only**: `false`

## Preconditions

`no_prior_safe_tool_after_cut`

## Risk

Loss of incomplete trailing event data if the trailing record contained partially accepted user intent.

## Evidence

The trailing line is incomplete or torn, and no subsequent events or safe tool results exist beyond the cut point.

## Non-Proof Statement

Does not prove that the discarded fragment had no external side effects if executed asynchronously.

## Loss Behavior

Discards the torn trailing bytes up to the last clean newline boundary.

## Tested Fixture

- Path: `fixtures/repair/recipe_suffix_discard.json`
