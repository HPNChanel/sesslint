# T-01: Evidence ledger reconciliation

- Status: in-progress
- Phase: 0
- Priority: P0
- Type: documentation / evidence correctness
- Depends on: —
- Code behavior change: none

## Goal

Reconcile the current plan/task narrative with the actual source contracts and measured evidence before any new code work proceeds. This task prevents later release decisions from inheriting already-known false-green or stale claims.

## Known Reconciliation Items

1. Correct the rule-family descriptions in `next-phase-plan/T-03-ac-triage.md`:
   - `SL003`: identity.
   - `SL004`–`SL007`: graph.
   - `SL101`–`SL108`: tool pairing.
   - `SL201`–`SL203`: checkpoint / continuation safety.
2. Correct `next-phase-plan/T-08-dogfood.md` from “8 manifest checks” to the verifier’s actual 7 audit checks unless the verifier contract is intentionally changed later.
3. Reclassify `next-phase-plan/T-09-demand-campaign.md` from `done` to an active campaign state while external metrics remain unmet.
4. Reclassify `next-phase-plan/T-10-kill-pivot-review.md` as an interim memo, not a completed bounded review.
5. Do not count repository-owned synthetic/challenger fixtures as “external contributed fixtures”.
6. Do not count internal dogfood repair cycles as external user work-recovery evidence.
7. Reconcile T-02 performance evidence with the actual `bench/PERF_NOTES.md` contents; the current note file is stale relative to the 15.430s / 785.52MB measurement.
8. Record that the current working tree is dirty/untracked and therefore is not yet a release provenance point.

## Steps

1. Build a one-row-per-claim reconciliation table with:
   - claim,
   - original task/file,
   - source/test/measurement evidence,
   - corrected status,
   - corrective owner task.
2. Patch only factual/status text; do not rewrite historical command logs.
3. Add an explicit note to historical plans that `post-alpha-hardening-plan/00-plan.md` is the next operational authority.
4. Verify all referenced code families against `src/sesslint/checks/__init__.py` and rule registry.
5. Verify verifier check count against `src/sesslint/verify.py`.
6. Verify campaign metrics are external before incrementing any DV counter.

## Acceptance

- Zero known false-green status remains.
- T-03 family descriptions match source.
- T-08 verifier count matches source.
- T-09 is not `done` while any required external metric is still pending.
- T-10 is not a final closeout before the declared bound elapses.
- Internal fixtures/dogfood are explicitly labeled internal evidence.
- A reconciliation table points every remaining defect to T-02–T-10.

## Validation

```bash
pytest -q tests/test_codes.py tests/test_coverage_matrix.py tests/test_verify.py
```

No source-code change is required by this task.

## Out of Scope

- Fixing threshold plumbing.
- Fixing manifest/profile reconstruction.
- Performance optimization.
- Starting or fabricating external campaign evidence.
