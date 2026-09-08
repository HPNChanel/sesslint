# Recipe: torn-terminal-record-discard

## Overview

- **Recipe Name**: `torn-terminal-record-discard`
- **Handles Codes**: `SL002`
- **Lossy**: `false`
- **Salvage Only**: `false`

## Preconditions

`no_sl203`, `torn_terminal_record`

## Risk

Low; only truncates incomplete or malformed terminal record suffixes that cannot be parsed.

## Evidence

Terminal record is incomplete, unparseable, or truncated before clean line termination.

## Non-Proof Statement

Does not recover lost terminal data, only truncates invalid trailing suffix.

## Loss Behavior

Discards incomplete terminal record suffix safely while preserving all valid preceding events.

## Tested Fixture

- Path: `fixtures/hostile/torn_final.jsonl`
