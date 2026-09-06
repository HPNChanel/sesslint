# Recipe: side-effect-unknown-truncate

## Overview

- **Recipe Name**: `side-effect-unknown-truncate`
- **Handles Codes**: `SL102`
- **Lossy**: `true`
- **Salvage Only**: `true`

## Preconditions

`salvage_policy`, `acknowledge_side_effects`

## Risk

Severe: unconfirmed external actions may have executed in the real world without durable logging in the session.

## Evidence

A dangling tool call exists without result, and operator has explicitly acknowledged unknown side-effect risk.

## Non-Proof Statement

Explicitly makes no semantic safety or side-effect safety claims. External side effects remain unverified.

## Loss Behavior

Truncates the session history before the unconfirmed side-effecting call (lossy, salvage only).

## Tested Fixture

- Path: `fixtures/repair/salvage_truncate.json`
