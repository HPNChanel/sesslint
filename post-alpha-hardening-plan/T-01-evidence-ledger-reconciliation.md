# T-01: Evidence ledger reconciliation

- Status: planned
- Phase: 1
- Priority: P0 — evidence correctness
- Type: documentation / evidence correctness (no production-code behavior change)
- Depends on: T-00
- Primary targets:
  - `post-alpha-hardening-plan/EVIDENCE_LEDGER.md` (execution deliverable — does not exist yet)
  - `next-phase-plan/T-03-ac-triage.md` (append-only supersession note)
  - `next-phase-plan/T-08-dogfood.md` (append-only supersession note)
  - `next-phase-plan/T-09-demand-campaign.md` (append-only supersession note)
  - `next-phase-plan/T-10-kill-pivot-review.md` (append-only supersession note)
  - `README.md` (wording corrections only)
  - `bench/PERF_NOTES.md` (factual alignment; deep contract repair is T-05)
  - `DEMAND.md` (status/provenance annotations only)

## Goal

Reconcile the plan/task narrative with actual source contracts and measured evidence before any corrective code work proceeds, so no later release or campaign decision inherits a known false-green or stale claim.

## Verified Problem / Current Evidence

The following discrepancies were verified against source during planning:

1. `next-phase-plan/T-03-ac-triage.md` labels rule families incorrectly in criterion summaries. Verified source mapping: `SL003` identity; `SL004`–`SL007` graph; `SL101`–`SL108` tool pairing; `SL201`–`SL203` checkpoint/continuation safety.
2. `next-phase-plan/T-08-dogfood.md` says "8 manifest checks" while `src/sesslint/verify.py` currently exposes 7 audit checks.
3. `bench/PERF_NOTES.md` still claims PASS / `~65–190MB`; the latest recorded run is `15.430s` / `785.52MB` against `15.0s` / `512MB` budgets — a dual breach, not a pass.
4. No release provenance exists: no local/remote tags, no GitHub Releases, PyPI `sesslint` 404, and the working tree was dirty — no clean-SHA release evidence can be cited anywhere.
5. `next-phase-plan/T-09-demand-campaign.md` is marked done while external demand metrics are unmet; `next-phase-plan/T-10-kill-pivot-review.md` is marked done although it is an interim memo and its 6-week/outreach bound never elapsed.
6. Internal/synthetic fixtures and internal dogfood repair cycles have been counted as external demand evidence in campaign tracking.
7. Test counts cited in plan/task notes are stale relative to the current suite.
8. `README.md` wording implies a previous `0.1.0` release exists; none does.

## Required Design / Decisions

1. **Append-only / superseding.** Never rewrite, delete, or reorder historical command logs or task narrative. Every correction is an appended supersession note or a ledger row pointing at the original text.
2. **Central artifact.** Create `post-alpha-hardening-plan/EVIDENCE_LEDGER.md` as the single reconciliation table: one row per claim with columns `claim | original location | contradicting evidence | corrected state | owning corrective task`.
3. **Corrected states are exact.** Historical logs retained; supersession notes appended; campaign state `not-started` until publication is proven; no release-ready claim without a clean commit SHA; internal evidence explicitly labeled internal.
4. **Authority pointer.** Each touched historical file gets an appended note that `post-alpha-hardening-plan/00-plan.md` is the current operational authority.
5. `EVIDENCE_LEDGER.md` is an **execution deliverable** of this task — it does not exist at planning time and must not be referenced elsewhere as an existing file.

## Ordered Implementation Steps

1. Verify each reconciliation item against source (`src/sesslint/checks/` registry for rule families; `src/sesslint/verify.py` for check count; benchmark log values; `git tag --list` / `gh release list` / PyPI endpoint for release absence; current `pytest -q` tail for test counts).
2. Create `EVIDENCE_LEDGER.md` with the schema above and one row per verified claim, including rows that require no correction (marked "confirmed accurate") where they were audited.
3. Append supersession notes to the four `next-phase-plan` files listed above — correction text only, original content untouched.
4. Correct `README.md` wording so it no longer implies a prior `0.1.0` release (e.g., "first public release" / "unreleased" phrasing).
5. Update `bench/PERF_NOTES.md` headline status to reflect the measured breach (full disclosure-contract repair remains T-05).
6. Annotate `DEMAND.md`/campaign notes: campaign state `not-started`; internal fixtures and dogfood labeled internal evidence, never DV increments.
7. Re-run the validation commands; record outputs in the ledger.

## Test Matrix

| Check | Method |
|---|---|
| Rule-family labels match source | Compare ledger rows to `src/sesslint/checks/` registry |
| Verify check count = 7 | Inspect `src/sesslint/verify.py`; confirm note matches |
| Benchmark claims match latest run | `python bench/perf_250k.py --records 250000 --time-budget 15.0 --mem-budget 512.0` output vs. notes (breach expected until T-06) |
| Release absence claim holds | `git tag --list`, `gh release list`, PyPI `sesslint` endpoint |
| Test count accuracy | `pytest -q` tail counts vs. ledger |
| No internal evidence counted externally | Audit every DV-adjacent claim in ledger |

## Validation Commands

```bash
pytest -q tests/test_codes.py tests/test_coverage_matrix.py tests/test_verify.py
pytest -q
git tag --list
gh release list
```

## Acceptance Criteria

- `post-alpha-hardening-plan/EVIDENCE_LEDGER.md` exists with one row per audited claim and no known false-green claim unrecorded.
- Rule-family labels, verify-check count, benchmark values, test counts, and release-status wording in corrected docs match source/measurement exactly.
- Premature T-09/T-10 statuses are superseded: campaign `not-started`; T-10 predecessor labeled interim memo.
- Internal fixtures/dogfood are explicitly labeled internal and excluded from DV counters.
- `README.md` no longer implies a previous `0.1.0` release.
- No historical log line was edited, deleted, or reordered.

## Evidence To Record

- The ledger file itself, with the verification command outputs that justify each corrected state.
- List of files touched and confirmation each change was append-only/correction-only.

## Rollback / Stop Conditions

- Stop if a "correction" would require rewriting history rather than superseding it — escalate to the maintainer instead.
- If audit uncovers a false claim with no owning corrective task, add the row and flag it for plan amendment rather than silently fixing scope.
- Reverting this task means removing the appended notes and the ledger — never restoring edited originals.

## Risks

- Over-correction: a note that disputes a claim must cite reproducible evidence, not opinion.
- Rechecks are cheap; drift between ledger creation and T-08 is re-audited at the clean-tree gate.

## Out of Scope

- Threshold plumbing, manifest binding, repro metadata, benchmark semantics, memory work (T-02–T-06).
- Creating `CAMPAIGN_LEDGER.md` or campaign state machinery (T-07).
- Release-channel or publication work (T-07a, T-09, T-09a).
- Starting or fabricating external campaign evidence.
