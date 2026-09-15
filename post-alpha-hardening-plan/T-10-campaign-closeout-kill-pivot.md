# T-10: Campaign closeout and final kill/pivot review

- Status: planned
- Phase: 7
- Priority: P1 product decision
- Type: decision / campaign closeout
- Depends on: T-09a + later of six elapsed weeks or 30 targeted outreach attempts
- Primary targets:
  - `post-alpha-hardening-plan/CAMPAIGN_LEDGER.md` (input + final state)
  - `DEMAND.md` (final DV evaluation)
  - This task's closeout memo (output)

## Goal

Replace the historical interim "proceed" memo with a final, evidence-based decision taken only after the campaign's real bound closes — using exclusively admissible external demand evidence.

## Verified Problem / Current Evidence

`next-phase-plan/T-10-kill-pivot-review.md` was marked done while being an interim memo, and its bound never elapsed. No release exists yet, so the campaign clock cannot have started; this task is unreachable until T-09a publishes `v0.1.0` and the bound later closes.

## Preconditions

- T-09a completed: `v0.1.0` verified published on both GitHub Release and PyPI; campaign state `active-campaign` with a recorded start timestamp.
- Bound closed: the **later** of six elapsed weeks since campaign start **or** 30 targeted non-spam outreach attempts is reached. Both dates/numbers are explicit in `CAMPAIGN_LEDGER.md`.
- DV metrics computed only from admissible external evidence per T-07 — no internal fixtures, dogfood, or outreach activity counted as demand.

## Required Evidence

For every DV-001..DV-007 criterion, a review-table row recording: target; actual; pass/fail; evidence references; confidence/limitations; external-vs-internal classification (must be external to count). Also record: unique external users completing real checks; contributed fixtures across distinct runtimes; testimonials/diagnosis confirmations; external integrations/adoptions; real work-recovery events; false-positive/false-validated incidents; organizational/commercial inquiries; and the outreach-attempt count.

## Decision Outcomes

Exactly one:

1. `PROCEED` — evidence supports continued independent product development.
2. `NARROW` — retain SessLint but reduce scope to the strongest validated workflow.
3. `PIVOT-UPSTREAM` — contribute adapters/checks into upstream ecosystems instead of maintaining the full product.
4. `STOP` — archive active product development while preserving released artifacts and documentation.

The chosen outcome transitions the campaign state to the matching `closed-proceed` / `closed-narrow` / `closed-pivot` / `closed-stop`.

## Validation Commands

No engineering test substitutes for elapsed external evidence. Validation is the ledger audit: every counted row traces to an external, anonymized, consented source; the bound-close timestamp is verified against the T-09a publication record.

## Acceptance Criteria

- Bound actually elapsed (later-of rule) and recorded with dates/counts.
- Complete review table; every counted DV row is external and traceable.
- Exactly one explicit outcome chosen; matching `closed-*` campaign state recorded.
- Follow-up work plan or archive plan created.
- The historical interim memo is clearly labeled interim; it was never the closeout.

## Evidence To Record

- Closeout memo: bound-close evidence, review table, outcome, rationale, follow-up/archive plan.
- Final campaign state in `CAMPAIGN_LEDGER.md`.

## Rollback / Stop Conditions

- Bound not elapsed → task stays `blocked`; there is no early closeout.
- Any DV row found to rest on internal evidence → recompute before deciding.
- Thresholds may be changed **only before** reading the final result and only with documented rationale — no post-hoc threshold tuning. If a threshold change is needed mid-review, stop and record it before evaluating.

## Risks

- Pressure to close early on thin evidence; the later-of bound and external-only rules are the defense.
- Sparse external data is itself a legitimate outcome (`STOP`/`PIVOT-UPSTREAM` are valid results, not failures of process).

## Out of Scope

- Extending the campaign indefinitely to avoid a negative decision.
- Inventing testimonials/adoption or relabeling internal evidence as external.
- Changing technical integrity requirements based on weak demand.
- Any new release work implied by the decision (a `PROCEED`/`NARROW` outcome seeds a new plan, not this one).
