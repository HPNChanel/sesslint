# Recipe: orphan-result-drop

## Overview

- **Recipe Name**: `orphan-result-drop`
- **Handles Codes**: `SL101`
- **Lossy**: `true`
- **Salvage Only**: `true`

Drops exactly one orphan `tool_result` record — a result whose correlation
identifier matches no tool call in the session — when the operator explicitly
opts in via `--policy salvage --acknowledge-side-effects`.

## Preconditions

`salvage_policy`, `acknowledge_side_effects`, `sl101_orphan_present`

`sl101_orphan_present` requires the finding to be `SL101` and its target to
resolve to an event that is verifiably an orphan: it must be a `tool_result`,
must have no matching call for its correlation identifier, and must have no
dependent child events (dropping a referenced parent would create missing
parents). Any failure blocks planning with
`precondition-failed:sl101_orphan_present`; the apply-time transform re-validates
the same conditions and refuses via `PreconditionFailed`.

## Risk

High: an orphan result may be the sole durable evidence that an external action
executed. Dropping it trades fidelity for a provider-acceptable continuation
artifact and can erase the only record of a completed side effect.

## Evidence

The finding's `SL101` evidence identifies the orphan record by index, source
record id, and correlation identifier; the plan step carries the target index
and correlation parameter so the omitted record remains identifiable by hash
and location in the plan and manifest.

## Non-Proof Statement

Dropping the record proves nothing about whether the underlying action
executed; semantic equivalence is not claimed, external side effects remain
unverified, and output assurance is capped at structural validity.

## Loss Behavior

Exactly one record is omitted (loss class `orphan-result`, count 1). No calls,
results, approvals, or execution states are synthesized; the source artifact is
never modified.

## Tested Fixture

- Path: `fixtures/checks/sl101_orphan.json`
