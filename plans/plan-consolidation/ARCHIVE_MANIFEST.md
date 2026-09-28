# Archive Manifest — frozen planning generations

- Freeze date: 2026-09-25
- Authority: `plans/plan-consolidation/00-plan.md`, task T-01
- Rule: files below are read-only history. Changes must be appended
  supersession notes citing evidence — never status flips or content
  rewrites (post-alpha T-01 model).

## Frozen packs (all counts verified 2026-09-25)

| # | Pack | Files | Final state |
| --- | --- | --- | --- |
| F-01 | `docs/implementation/` | 4 top-level + `tasks/` TASK-001…028 (28) | MVP foundation, done |
| F-02 | `agent_tasks/` | `00-README.md` + 22 task files (P0-01…10, P1-01…08, P2-01…04) | 20 done + 2 verified-already-fixed |
| F-03 | `20260908-01a0817f-next-development/` | 7 top-level + `tasks/` DEV-001…016 (16) | bridge pack, done |
| F-04 | `next-phase-plan/` | `00-plan.md` + 21 T-files (T-01…T-15, T-05a…f) | done (T-09/T-10 carry supersession notes) |
| F-05 | `post-alpha-hardening-plan/` (except T-10 + ledgers) | `00-plan.md` + 12 done T-files (T-00…T-09a) | done; T-10 stays live (planned) |
| F-06 | `demand-wedge-plan/` | `00-plan.md` + `MARKET_EVIDENCE.md` + `desktop-companion-spec.md` + T-01…T-14 (14) | all done; desktop BUILD decision stays live |
| F-07 | `native-accel-plan/` | `00-plan.md` + `T-01-canonical-codec.md` | S0+S1 done; S2 deferred / S3 paper-only stay live |
| F-08 | `plans/` prior 14 packs | 87 files (14 × `00-plan.md` + 72 T-files + 1 MEMO) | all done except adapters T-04…T-09 (live, DV-gated) |
| F-09 | `docs/reviews/final-mvp-review/` | 12 review files | APPROVED_FOR_ALPHA, done |

`plans/` prior-pack detail (all statuses verified `done` unless noted):

| Pack | Files |
| --- | --- |
| `adapters-coverage/` | `00-plan.md` + T-01…T-09 (T-01…T-03 done; T-04…T-09 **live, DV-gated**) |
| `agent-hooks/` | `00-plan.md` + T-01…T-03 |
| `checks-rules/` | `00-plan.md` + T-01…T-07 |
| `detector-depth/` | `00-plan.md` + T-01…T-05 |
| `docs-spec/` | `00-plan.md` + T-01…T-05 |
| `evidence-assurance/` | `00-plan.md` + `MEMO-provider-drift.md` + T-01…T-02 |
| `index-reconciliation/` | `00-plan.md` + T-01…T-05 |
| `integrations/` | `00-plan.md` + T-01…T-05 |
| `perf-scale/` | `00-plan.md` + T-01…T-04 |
| `qa-infra/` | `00-plan.md` + T-01…T-05 |
| `release-dist/` | `00-plan.md` + T-01…T-06 |
| `repair-engine/` | `00-plan.md` + T-01…T-04 |
| `transcript-hygiene/` | `00-plan.md` + T-01…T-03 |
| `ux-reporting/` | `00-plan.md` + T-01…T-09 |

## Stays live (not frozen)

- `post-alpha-hardening-plan/T-10-campaign-closeout-kill-pivot.md`
  (planned) + `CAMPAIGN_LEDGER.md` + `EVIDENCE_LEDGER.md`
- `plans/adapters-coverage/` T-04…T-09 (DV-gated)
- `demand-wedge-plan/desktop-companion-spec.md` BUILD decision
  (spec done; build DV-gated)
- `native-accel-plan/` S2/S3 gateway
- Tracked living truth: `DEMAND.md`, `CHANGELOG.md` — plus
  `plans/plan-consolidation/` task files
- Local-only working mirrors (gitignored, never normative):
  `ROADMAP.md`, `STRATEGY.md`

## Reverification for 0.4.1 — 2026-09-26

OBSERVED: the 14 prior `plans/` packs still contain 87 Markdown files.
F-01 is 4 + 28; F-02 is 23; F-03 is 7 + 16; F-04 is 22;
F-06 is 17; F-07 is 2. F-09 is 12 files (11 Markdown and FINDINGS.json).
F-05 contains 16 Markdown files including its live task and two ledgers;
the frozen subset and live exceptions above remain unchanged.
The archive is historical evidence, not a source for new release status.
