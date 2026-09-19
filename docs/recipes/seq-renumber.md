# Recipe: seq-renumber

## Overview

- **Recipe Name**: `seq-renumber`
- **Handles Codes**: — (planner-synthesized normalizing step; never
  matches a finding directly)
- **Lossy**: `false`
- **Salvage Only**: `false`

## Preconditions

None (registered with an empty precondition set). The planner appends
this step itself — after all drop-class steps — only when the input
format is canonical, because canonical input always emits canonical
output (vendor emit is refused for canonical sources). Vendor inputs are
skipped: vendor write-back keeps source lines verbatim and `seq` lives
inside canonical events only.

## Risk

None structural: `seq` is a positional ordinal excluded from content
identity, and the canonical loader already normalizes it to list
position. Renumbering only makes the emitted bytes match what any
SessLint load would observe — a fixed point (applying twice converges).

## Evidence

One or more drop-class plan steps on canonical input. Emitted streams
would otherwise carry `seq` gaps where records were removed; downstream
consumers that assume contiguous ordinals benefit from normalization.

## Non-Proof Statement

Does not prove that downstream consumers require contiguous `seq`;
canonical spec treats `seq` as an ordinal, not as evidence. Renumber is
normalization, not corruption repair.

## Loss Behavior

Lossless: only `seq` ordinals are rewritten; no events or fields are
removed. Declared loss accounting stays zero.

## Tested Fixture

- Path: `fixtures/repair/t04_seq_renumber/source.jsonl`
