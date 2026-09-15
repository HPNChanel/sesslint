# CAMPAIGN_LEDGER — Demand-Validation Campaign State & External Evidence

Single authoritative record for campaign state and admissible external demand evidence.
Governed by `post-alpha-hardening-plan/T-07-demand-campaign-state-machine.md`; closeout owned by `T-10-campaign-closeout.md`.

## Campaign State

- **State:** `not-started`
- **Start date (verified publication):** _empty — set only by T-09a publication record_
- **Close date (bound end):** _empty — later of six elapsed weeks from start or 30 completed targeted outreach attempts_
- **Publication record (required before activation):** _empty — must cite tag + GitHub Release URL + PyPI URL + artifact hashes verified identical across both channels_

## State Machine

```
not-started ──(T-09a verifies BOTH channels: GitHub Release + PyPI for v0.1.0)──▶ active-campaign
active-campaign ──(bound closes: later of 6 weeks or 30 targeted outreach attempts)──▶ bound-complete
bound-complete ──(T-10 records exactly one outcome)──▶ closed-proceed | closed-narrow | closed-pivot | closed-stop
```

- The only valid transition out of `not-started` cites the T-09a publication record above. Any other activation attempt is invalid; the state stays `not-started`.
- The bound clock starts from the verified publication date, never earlier.

## DV-001..DV-007 Definitions (precise numerators/denominators)

| DV | Numerator | Denominator / threshold | Current value |
|---|---|---|---|
| DV-001 | Unique external actors who completed ≥1 real `sesslint check` on their own artifact | ≥10; installs, stars, and CI-only runs do not count | 0 |
| DV-002 | Corrupted fixtures contributed by external parties, counted per independent runtime | ≥5 fixtures spanning ≥3 distinct runtimes | 0 |
| DV-003 | Framework maintainers or support engineers confirming reduced diagnosis time or improved bug reports | ≥2 | 0 |
| DV-004 | External repositories adopting a SessLint fixture, CI check, adapter, or report format | ≥1 | 0 |
| DV-005 | External users who recovered useful work from a repaired copy while retaining the original | ≥3 | 0 |
| DV-006 | Known outputs labeled validated that the matching supported reference loader rejects | must remain 0 (any occurrence fails the metric) | 0 |
| DV-007 | Organizations agreeing to discuss paid support, a private adapter, or self-hosted fleet scanning | ≥1 | 0 |

## External Evidence Log

Anonymized rows only — no names, emails, hostnames, or identifying session content.
Fields per row: date | DV id | anonymized external actor/org ID | evidence type | artifact/link/reference or private-evidence note | consent/provenance status | metric delta | reviewer note.

| date | DV id | actor/org ID | evidence type | artifact/reference | consent/provenance | metric delta | reviewer note |
|---|---|---|---|---|---|---|---|
| _(empty)_ | | | | | | | |

## Outreach Activity Log (separate from demand metrics)

Targeted outreach increments the activity counter only — never a DV numerator. Target bound: 30 attempts.

| date | channel | anonymized target ID | attempt type | outcome | reviewer note |
|---|---|---|---|---|---|
| _(empty)_ | | | | | |

- **Targeted outreach attempts completed:** 0 / 30

## Not Admissible as External Evidence

- Repository-owned synthetic/challenger fixtures — engineering evidence only (never DV-002).
- Internal dogfood repair cycles — product validation (never DV-005).
- Scheduled/prepared outreach — activity only (never a DV numerator).
- A prepared GitHub Action or published schema — capability (never DV-004 adoption).
- Installs, stars, downloads, CI-only runs — distribution signals (never DV-001).

## Reclassification Audit Trail

Internal items previously counted as external demand evidence (corrected 2026-09-15; see `EVIDENCE_LEDGER.md` rows `L-04`, `L-06`, `L-12`):

| prior claim | prior DV row | reclassified as | note |
|---|---|---|---|
| 19 hostile/challenger fixtures across 3 runtimes | DV-002 "PASS" | internal engineering evidence | fixtures are repository-owned; validated by `tests/test_fixture_provenance.py` |
| internal dogfood repair cycle on canonical/vendor logs | DV-005 | internal product validation | no external user involved |
| prepared GitHub Action dogfood workflow | DV-004 | capability, not adoption | no external repository adopted it |
| `reference_equivalent_if_clean` + A4 gating | DV-006 "PASS" | engineered property | DV-006 counts external divergent labels, currently 0 |
| outreach list prepared | DV-003/DV-007 | activity, not evidence | zero external confirmations or inquiries |
