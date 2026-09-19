# ADR-0007: Synthetic fixtures only — no real transcripts, ever

- Status: accepted
- Date: 2026-09-19 (retroactive record of a standing invariant)

## Context

Real session transcripts contain user data. Committing them — even
"anonymized" — creates permanent, unremovable exposure in git history
and turns the test corpus into a privacy liability.

## Decision

Every file under `fixtures/` MUST be synthetic: generated or handcrafted
with placeholder identifiers and reproducible seeds. Every fixture
directory MUST carry `PROVENANCE.json` with `contains_real_data: false`.
Real-world corruption *shapes* are re-authored synthetically from
observed structure (names, types, classes of damage) — content is never
copied. `true` is never acceptable; there is no `consented` fixture in
this repository today.

## Consequences

- Field findings enter the corpus as *shape families*
  (`fixtures/corpus/`), not as captured transcripts — the FIXTURES.md §4
  regression rule.
- Real-tree observations may record only names and counts (the
  `docs/VENDOR_DRIFT.md` evidence-hygiene rule).
- Any PR containing real session data is rejected outright and the
  history treated as contaminated.

## Alternatives rejected

- *Anonymized real transcripts* — rejected: anonymization of free-text
  agent sessions is not provable; the risk is permanent.
- *Encrypted real fixtures* — rejected: still ships user data; key
  handling adds a secret-management burden for zero analytic gain.

## Evidence

- `FIXTURES.md` — provenance policy and schema.
- `tests/test_fixture_provenance.py` — CI gate over every fixture dir.
- `fixtures/corpus/` — shape families re-authored from the field test.
- `docs/VENDOR_DRIFT.md` — names-and-counts-only evidence hygiene.
