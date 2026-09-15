## Goal

Execute the next phase of SessLint in strict dependency order: prove the tree green (Phase 0), ship five core features (Phase 1a), close MVP acceptance (Phase 1b), and run the bounded demand campaign (Phase 2). This file is the index and ordering authority; per-function detail lives in `T-01`–`T-15`.

## Success Criteria

- `next-phase-plan/` holds `00-plan.md` + `T-01`–`T-15`, each self-contained, executed in the order below.
- New capabilities shipped: scan-report JSON schema, `sesslint export` (vendor→canonical repair enablement), shell completion, A4 reference loader, AC-025 test-matrix gate.
- Full gates green with recorded logs; AC triage complete; release hygiene done; campaign memo recorded.
- No history rewrite; no release from an unverified tree.

## Context And Current Facts

- All 23 `agent_tasks` items closed and spot-verified by code inspection (see prior review).
- Gaps: no full-suite gate evidence; bench 250k numbers stale; A4 reserved while README implies attainability; status-only task files; vendor sessions are repair dead-ends (RVW-019 canonical-only refusal); CLI stabilized so completion is unblocked (`DEMAND.md:439`); scan JSON has no published schema; AC-025 matrix unenforced.
- Binding constraints (`DEMAND.md`): offline, zero runtime deps, no telemetry, content-free diagnostics, determinism, source immutability, solo-maintainer scope; alpha gate + kill/pivot bounds; fixture provenance gate; perf disclosure rule.

## Constraints And Non-goals

- Still out of scope: dashboard/fleet/SaaS, LLM-guessed repairs, new vendor adapters, watch/daemon mode, in-place mutation, synthesized "success" results (either policy).
- Note: this plan expands scope before the alpha gate at the maintainer's explicit direction (five features below). The gate still guards *further* expansion and release positioning.
- One function per task file; same-file tasks serialize; minimal diffs; executor protocol from `agent_tasks/00-README.md` applies (claim → reproduce → minimal diff → gates → done-note + appended logs).

## Key Decisions

1. **Verify-then-build.** Phase 0 (T-01–T-04) runs before any feature work; features build only on a green tree.
2. **Feature order is dependency-driven:** schema (no deps) → export (adds CLI surface) → completion (covers new surface) → reference loader (decides A4 attainability) → matrix gate (covers everything incl. new tests).
3. **Export is repair-enablement, not migration.** Single artifact → canonical file, atomic write, lossiness disclosed, refused inputs fail closed. No bulk/directory mode.
4. **Reference loader is structural and honest.** Independent serialize→reparse→projection-compare; A4 only when clean *and* reconstruction agrees. Canonical-event based, adapter-agnostic.
5. **T-06 scrub follows the loader.** With A4 attainable via loader, the scrub narrows to copy accuracy instead of unattainability.

## Execution Order (binding)

| Order | Task | Function | Phase | Depends on |
|------:|------|----------|-------|------------|
| 1 | `T-01-gates-matrix.md` | Full gates matrix + logs | 0 | — |
| 2 | `T-02-full-scale-bench.md` | 250k bench or disclosure | 0 | — |
| 3 | `T-04-note-backfill.md` | Backfill notes, close P1-07 | 0 | — |
| 4 | `T-03-ac-triage.md` | AC-001–030 evidence triage | 0 | T-01, T-02 |
| 5 | `T-11-scan-schema.md` | Scan-report JSON schema | 1a | T-01 |
| 6 | `T-12-export.md` | `sesslint export` + `api.export_file` | 1a | T-01 |
| 7 | `T-13-completion.md` | bash/zsh/fish completion | 1a | T-12 |
| 8 | `T-14-reference-loader.md` | Reference loader + A4 path | 1a | T-01 |
| 9 | `T-15-test-matrix.md` | AC-025 matrix gate | 1a | T-11–T-14 |
| 10 | `T-05x-<slug>.md` | One file per Phase 0/1a failure | 1b | as found |
| 11 | `T-06-a4-scrub.md` | A4 copy-accuracy scrub (revised) | 1b | T-14 |
| 12 | `T-07-release-hygiene.md` | Badge, sha256sums, notes | 1b | T-05, T-15 |
| 13 | `T-08-dogfood.md` | Dogfood incl. new features | 1b | T-05, T-15 |
| 14 | `T-09-demand-campaign.md` | DV-001–007 campaign | 2 | Phase 1b green |
| 15 | `T-10-kill-pivot-review.md` | Decision memo at bound | 2 | T-09 |

Parallel-safe batches: {T-01, T-02, T-04} → {T-03} → {T-11, T-12} → {T-13, T-14} → {T-15} → {T-05*} → {T-06} → {T-07, T-08} → {T-09} → {T-10}. T-13 needs T-12's CLI surface; T-06 needs T-14's A4 verdict; T-15 runs after all code lands.

## Validation Summary

Each T-file carries its own commands. Phase gates: Phase 0 needs F-01 logs + triage table; Phase 1a needs per-feature tests green + full matrix re-green after each; Phase 1b needs scrub proof + hygiene checklist + dogfood log; Phase 2 needs campaign log + memo. Highest risk: full suite never shown green (T-01); second: stale bench numbers (T-02).

## Risks

- Red suite after the wave → absorbed by T-05 fan-out; nothing released yet.
- Bench breach → mandatory disclosure, never fixture-shrinking.
- Campaign miss → stop/narrow/pivot is success per `DEMAND.md`.
- Feature scope creep → this file's 15 tasks are closed; new asks become new T-files, never silent expansion.

## Open Questions

1. Which machine runs T-01/T-02 (shell, Python 3.11+, ideally second OS)?
2. Who owns T-09, and does the six-week clock start at Phase 1b green?
3. Reference-class machine for T-02, or CI `workflow_dispatch` as reference?
