# T-07: Demand campaign state machine and evidence rules

- Status: planned
- Phase: 3
- Priority: P0 governance
- Depends on: T-01
- Primary targets:
  - `DEMAND.md`
  - `next-phase-plan/T-09-demand-campaign.md`
  - `next-phase-plan/T-10-kill-pivot-review.md`
  - new campaign ledger if needed

## Problem

The current campaign task is labeled done although multiple external metrics are still in progress. Some internal fixture/dogfood evidence is being used as if it satisfied external demand metrics.

That makes the product decision process non-auditable.

## State Model

Campaign status must be one of:

- `not-started`
- `active-campaign`
- `bound-complete`
- `closed-proceed`
- `closed-narrow`
- `closed-pivot`
- `closed-stop`

Starting a campaign is not completion.

## Evidence Rules

An external metric increments only when evidence is genuinely external to the repository’s own synthetic/internal validation.

Required ledger fields:

- date;
- DV id;
- anonymized external actor/org ID;
- evidence type;
- artifact/link/reference or private evidence note;
- consent/provenance status where relevant;
- metric delta;
- reviewer note.

Examples:

- Repository-owned synthetic fixtures: useful engineering evidence, **not** DV-002 external contribution.
- Internal dogfood repair: product validation, **not** DV-005 external work recovery.
- Scheduled outreach: activity count, **not** external usage/testimonial/adoption.
- A prepared GitHub Action: integration capability, **not** DV-004 adoption.

## Clock Rule

The six-week / 30-outreach bound starts from an actual recorded public-alpha release/tag date, not from plan preparation.

Both start and close dates must be explicit.

## Steps

1. Reclassify current T-09 as active, not done.
2. Reclassify current T-10 as interim recommendation.
3. Separate engineering evidence from external demand evidence.
4. Create/update the demand ledger.
5. Define each DV numerator/denominator unambiguously.
6. Record outreach activity separately from success metrics.
7. Prevent final kill/pivot closeout until bound conditions are actually met.

## Acceptance

- No internal event is counted as external demand.
- Every passed DV metric has traceable external evidence.
- Campaign remains `active-campaign` until the bound closes.
- T-10 final decision is reserved for T-10 of this hardening plan.

## Validation

Manual evidence audit plus any existing provenance tests:

```bash
pytest -q tests/test_fixture_provenance.py tests/accept/test_offline.py
```

## Out of Scope

- Inventing external users/testimonials.
- Changing product behavior to manufacture demand.
