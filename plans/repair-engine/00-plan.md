# SessLint Repair-Engine Plan (00)

- Status: done
- Language: English
- Created: 2026-09-08
- Authority: execution plan for repair workflow extensions. All work here is
  subordinate to fail-closed semantics: anything not provably safe refuses.
- Companion docs: `src/sesslint/repair/` (planner, executor, recipes,
  refusals), `docs/recipes/`, `schemas/` (`sesslint.plan/v1`).

## Goal

Turn repair from a single-shot command into an auditable workflow: export a
plan for review, apply a reviewed plan later, preview structural effects
before write, and batch deterministic repairs across a scan — without
weakening any refusal gate.

## Verified Facts

1. `sesslint.plan/v1` schema exists (`demand-wedge-plan/T-09`); the manifest
   already carries plan fingerprints, policy, and declared loss.
2. Today a plan is computed and executed inside one invocation — no way to
   inspect the plan JSON, hand it to a reviewer, or replay it later.
3. Multiple-orphan repair now resolves identity-first (field-test A6 fix);
   that machinery makes plan portability feasible (targets are anchored by
   identity, not just position).
4. Salvage repair reports declared loss; batch operation must never widen
   loss silently — per-file manifests are the audit trail.
5. Recipe coverage gaps remain: no `seq`-renumber normalization recipe, no
   identical-duplicate consolidation recipe (SL003 identical class is
   deterministic-repairable but unhandled).

## Constraints And Non-Goals

- Plan application re-verifies the plan fingerprint against the live source;
  any drift → refuse (fail-closed, no "best effort").
- Batch mode repairs only `deterministic`-class findings; `manual`,
  `salvage-only`, and SL203-blocked files are skipped with explicit reasons.
- No new write surfaces beyond the existing atomic write-back path; no
  in-place mutation without manifest.
- Preview diff is content-free: event ids/kinds/positions only, never
  payload bytes.

## Task Index

| ID | Title | Priority | Depends on |
| --- | --- | --- | --- |
| T-01 | Plan export/apply split (`--plan-out` / `--apply-plan`) | P1 | `sesslint.plan/v1` schema (done) |
| T-02 | Batch repair driven by scan report | P2 | T-01 |
| T-03 | Structural diff preview (`--preview`) | P2 | — |
| T-04 | New recipes: `seq-renumber`, `identical-duplicate-drop` | P1 | — |

## Validation

Per task: full gates; adversarial tests (stale plan → refuse; shifted source
→ refuse; ambiguous target → refuse); `verify` round-trip on every new
workflow path.
