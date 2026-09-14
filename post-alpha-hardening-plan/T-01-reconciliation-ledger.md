# T-01 Reconciliation Ledger

This ledger is the operational evidence table required by `T-01-evidence-ledger-reconciliation.md`.

It does not rewrite historical command logs. It records the corrective interpretation that `post-alpha-hardening-plan/00-plan.md` is the current operational authority.

| Claim / historical statement | Original task / file | Evidence checked | Corrected status | Corrective owner |
|---|---|---|---|---|
| Rule-family mapping used by AC triage is accurate | `next-phase-plan/T-03-ac-triage.md` | Source contract requires `SL003` identity; `SL004`–`SL007` graph; `SL101`–`SL108` tool pairing; `SL201`–`SL203` checkpoint / continuation safety | stale factual text; must be corrected without rewriting historical logs | T-01 |
| Verifier performs 8 manifest audit checks | `next-phase-plan/T-08-dogfood.md` | Current verifier contract has 7 audit checks | false count; must read 7 unless verifier contract changes in a later approved task | T-01 / T-03 |
| Demand campaign task is complete | `next-phase-plan/T-09-demand-campaign.md` | Required external metrics are still in progress; repository fixtures/dogfood are internal engineering evidence | `active-campaign`, not `done` | T-07 |
| Kill/pivot review is final | `next-phase-plan/T-10-kill-pivot-review.md` | Six-week / outreach bound has not closed from an actual public-alpha start date | interim recommendation only | T-07 / T-10 |
| Repository-owned synthetic/challenger fixtures count as external contributions | demand evidence | Provenance is repository-owned/internal | internal engineering evidence only; DV external numerator unchanged | T-07 |
| Internal dogfood repair counts as external work recovery | demand evidence | Repair was performed inside the project/dogfood loop | internal product-validation evidence only | T-07 |
| 250k reference benchmark is green / bounded-memory | `bench/PERF_NOTES.md` and historical task evidence | Latest recorded reference run: 250,000 records (~99.45 MB), streaming parse 4.109 s, check 11.321 s, total 15.430 s, peak RSS 785.52 MB; budgets 15.0 s / 512 MB | dual performance breach; disclosure cannot convert the gate to PASS | T-05 / T-06 |
| Current working tree is valid release provenance | release evidence | Working tree was observed dirty/untracked | not a release provenance point; T-08 must run from an identified clean tree | T-08 |
| Effective detection thresholds already govern auto-detection | profile / API / detector flow | Effective config is resolved but detector still uses pinned defaults in the known corrective baseline | correctness defect remains open | T-02 |
| No-plan verify reconstructs the manifest-bound profile correctly | verify reconstruction | Profile identity is bound under `revalidation.profile_id`; historical fallback reads the wrong location | correctness defect remains open | T-03 |
| JSON repro metadata always reflects actual detection evidence | CLI/report path | Historical path hard-codes `detection_confidence=1.0` | provenance defect remains open | T-04 |

## Working state

- T-01 is `in-progress` until the historical plan files themselves are patched and the focused validation command passes.
- T-02, T-03, T-04, T-05 and T-07 are eligible to proceed after T-01 evidence reconciliation.
- T-06 depends on T-05.
- T-08 serializes after T-02 through T-07 and requires a clean identified tree.
- T-09 cannot be GO while any normative T-08 gate, including the performance contract, is failing.
- T-10 cannot execute before the real campaign bound closes.

## Evidence discipline

- Internal fixtures, dogfood, synthetic data, prepared integrations, and scheduled outreach are not external demand evidence.
- Unknown reference-host details must remain `unknown/not captured`; no platform information may be invented.
- A benchmark breach remains a failed performance gate even when accurately disclosed.
