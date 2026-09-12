# Recipe: terminal-suffix-discard

## Overview

- **Recipe Name**: `terminal-suffix-discard`
- **Handles Codes**: `SL005`
- **Lossy**: `true`
- **Salvage Only**: `true`

## Preconditions

`no_prior_safe_tool_after_cut`

## Risk

Loss of trailing events forming or following a cycle if the discarded turns contained valid agent reasoning or user intent.

## Evidence

A causal parent cycle or trailing loop exists at the tail of the session stream, and no durable checkpoints or safe tool results exist beyond the cut point.

## Non-Proof Statement

Does not prove that the discarded turns had no external side effects or that omitted conversational context is unneeded.

## Loss Behavior

Discards all trailing events after the cut point to eliminate the cycle (lossy, salvage only).

## Tested Fixture

- Path: `fixtures/repair/recipe_suffix_discard.json`
