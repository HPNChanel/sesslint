# T-07: Demand campaign state machine and evidence rules

- Status: planned
- Phase: 2
- Priority: P0 governance
- Type: governance / documentation + state machinery
- Depends on: T-01
- Primary targets:
  - `post-alpha-hardening-plan/CAMPAIGN_LEDGER.md` (execution deliverable — does not exist yet)
  - `DEMAND.md` (status/provenance annotations)
  - `next-phase-plan/T-09-demand-campaign.md` (supersession note)
  - `next-phase-plan/T-10-kill-pivot-review.md` (supersession note)

## Goal

Reset campaign governance to a truthful pre-release state: an auditable ledger with anonymized external-evidence rules, precise DV-001..DV-007 numerators/denominators, separate outreach counters, and a state machine that cannot run ahead of a verified release.

## Verified Problem / Current Evidence

`next-phase-plan/T-09-demand-campaign.md` is marked done while external metrics are unmet; `T-10-kill-pivot-review.md` is marked done although it is an interim memo and the bound never elapsed. Internal/synthetic fixtures and internal dogfood have been counted as external demand evidence. No release exists (verified baseline: no tags, no GitHub Releases, PyPI 404), so the campaign state is `not-started`.

## Required Design / Decisions

1. **Ledger:** create `post-alpha-hardening-plan/CAMPAIGN_LEDGER.md` — an execution deliverable, not an existing file. It is the single campaign-state and external-evidence record.
2. **Campaign states** (campaign only — never a task `Status`): `not-started` → `active-campaign` → `bound-complete` → `closed-proceed` / `closed-narrow` / `closed-pivot` / `closed-stop`. Initial state: **`not-started`**.
3. **Transition rule:** the only valid transition out of `not-started` is triggered by T-09a verifying **both** release channels (GitHub Release + PyPI) for `v0.1.0`. The bound clock starts from the verified publication date.
4. **Anonymized ledger fields** per external-evidence row: date; DV id; anonymized external actor/org ID (no names, emails, hostnames, or identifying session content); evidence type; artifact/link/reference or private-evidence note; consent/provenance status; metric delta; reviewer note.
5. **Outreach counters are separate** from demand metrics: a targeted outreach attempt increments the activity counter, never a DV numerator.
6. **DV numerators/denominators** (from `DEMAND.md`, made precise):

   | DV | Numerator | Denominator / threshold |
   |---|---|---|
   | DV-001 | Unique external actors who completed ≥1 real `sesslint check` on their own artifact | ≥10; installs, stars, and CI-only runs do not count |
   | DV-002 | Corrupted fixtures contributed by external parties, counted per independent runtime | ≥5 fixtures spanning ≥3 distinct runtimes |
   | DV-003 | Framework maintainers or support engineers confirming reduced diagnosis time or improved bug reports | ≥2 |
   | DV-004 | External repositories adopting a SessLint fixture, CI check, adapter, or report format | ≥1 |
   | DV-005 | External users who recovered useful work from a repaired copy while retaining the original | ≥3 |
   | DV-006 | Known outputs labeled validated that the matching supported reference loader rejects | must remain 0 (any occurrence fails the metric) |
   | DV-007 | Organizations agreeing to discuss paid support, a private adapter, or self-hosted fleet scanning | ≥1 |

7. **Not admissible as external evidence:** repository-owned synthetic/challenger fixtures (engineering evidence only); internal dogfood repair cycles (product validation, not DV-005); scheduled outreach (activity only); a prepared GitHub Action (capability, not DV-004 adoption).

## Ordered Implementation Steps

1. Create `CAMPAIGN_LEDGER.md` with the state field (`not-started`), the DV table above, empty external-evidence and outreach tables, and explicit start/close date fields (empty until publication).
2. Append supersession notes to `next-phase-plan/T-09` (campaign not done; state `not-started`) and `next-phase-plan/T-10` (interim memo, not a final closeout).
3. Annotate `DEMAND.md` campaign status to match.
4. Move any evidence previously counted as external into the internal/engineering category with a ledger note.
5. Wire the transition gate: ledger may only enter `active-campaign` citing the T-09a publication record (tag, both channel URLs, hashes).

## Required Evidence / Decision Outcomes

| Item | Required state |
|---|---|
| Campaign state | `not-started` until T-09a verifies both channels |
| DV rows | zero or only rows with admissible anonymized external evidence |
| Outreach counter | tracked separately; target bound = 30 targeted attempts |
| Clock | start = verified publication date; close = later of six elapsed weeks or 30 targeted attempts |

## Validation Commands

```bash
pytest -q tests/test_fixture_provenance.py tests/accept/test_offline.py
```

Plus manual evidence audit: every ledger row traced to an external, anonymized source.

## Acceptance Criteria

- `CAMPAIGN_LEDGER.md` exists with state `not-started` and the precise DV-001..DV-007 definitions.
- No internal event is counted as external demand; prior misclassifications are corrected in the ledger.
- Outreach counters exist separately from DV numerators.
- The transition to `active-campaign` is defined exclusively via T-09a dual-channel verification.
- Historical statuses are superseded, not rewritten.

## Evidence To Record

- The ledger file, initial state, and the supersession notes.
- Audit trail showing reclassified internal evidence.

## Rollback / Stop Conditions

- Stop if any DV numerator would require non-anonymized or identifying data — record the refusal instead.
- Any attempt to enter `active-campaign` without a T-09a publication record is invalid; the ledger stays `not-started`.

## Risks

- Calendar-bound: the campaign cannot be accelerated; planning must not imply otherwise.
- Anonymization vs. auditability tension: private-evidence notes may hold identifying detail outside the ledger under consent/provenance status; the ledger itself stays anonymized.

## Out of Scope

- Inventing external users/testimonials; manufacturing demand.
- The publication itself (T-09a) and the closeout decision (T-10).
- Changing product behavior to produce demand.
