# T-10: Campaign closeout and final kill/pivot review

- Status: planned
- Phase: 5
- Priority: P1 product decision
- Depends on: T-09 and campaign bound elapsed
- Earliest execution: six weeks after the actual public-alpha campaign start date, unless the declared outreach bound is reached later and the governing spec requires both.

## Goal

Replace the current interim “proceed” memo with a final evidence-based decision after the campaign’s real bound closes.

## Preconditions

- T-09 public-alpha release actually occurred.
- Campaign ledger has explicit start and close dates.
- Required outreach/activity bound is complete.
- DV metrics are computed only from admissible external evidence per T-07.

## Review Table

For every DV criterion record:

- target;
- actual;
- pass/fail;
- evidence references;
- confidence/limitations;
- whether the metric is external or internal.

Also record:

- number of unique external users who completed real checks;
- number of genuine contributed fixtures and distinct external runtimes/sources;
- testimonials/diagnosis confirmations;
- external integrations/adoptions;
- real work-recovery events;
- false-positive / false-validated incidents;
- organization/commercial inquiries.

## Decision Outcomes

Exactly one:

1. `PROCEED`: evidence supports continued independent product development.
2. `NARROW`: retain SessLint but reduce scope to the strongest validated workflow.
3. `PIVOT-UPSTREAM`: contribute adapters/checks into upstream ecosystems instead of maintaining the full product.
4. `STOP`: archive active product development while preserving released artifacts and documentation.

## Kill/Pivot Rule

Use the thresholds defined in the governing demand specification. If the historical threshold is changed, the change must be made **before** reading the final result and documented with rationale; no post-hoc threshold tuning.

## Acceptance

- Bound elapsed.
- Ledger complete.
- No internal evidence counted as external.
- One explicit outcome chosen.
- Follow-up work plan or archive plan created.
- Historical interim memo is clearly labeled interim.

## Out of Scope

- Extending the campaign indefinitely to avoid a negative decision.
- Inventing testimonials/adoption.
- Changing technical integrity requirements based on weak demand.
