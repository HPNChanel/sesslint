# SessLint Repair Recipe Catalog

This directory documents the 8 deterministic repair recipes provided by SessLint.

## Classification

Recipes are strictly partitioned into two categories:

1. **Conservative Recipes**:
   - `identical-duplicate-collapse`
   - `proven-unique-parent-restore`
   - `compaction-projection-reunion`
   - `duplicate-projection-removal`
   - `terminal-suffix-discard`
   - Invariant: Conservative repairs never perform lossy amputation of unconfirmed actions, never synthesize arbitrary results, and fail closed if side effects are unknown (`SL203`).

2. **Salvage Recipes** (Explicit `--policy salvage` required):
   - `unresolvable-branch-amputate`
   - `torn-compaction-project`
   - `side-effect-unknown-truncate`
   - Invariant: Salvage recipes perform bounded, operator-acknowledged truncation or projection on otherwise unresolvable transcripts.

## Core Non-Proof Disclaimer

SessLint repair recipes perform structural and topological repairs on session logs. They **explicitly do not make semantic safety or external side-effect safety claims**.
