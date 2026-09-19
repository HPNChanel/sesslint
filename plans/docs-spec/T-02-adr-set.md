# T-02: ADR set (`docs/adr/`)

- Status: done
- Phase: docs
- Priority: P2
- Type: documentation (architecture decision records)
- Depends on: —
- Primary targets:
  - `docs/adr/0001-*.md` … `docs/adr/NNNN-*.md` (new dir)
  - `docs/adr/README.md` (index + template)
  - `CONTRIBUTING.md` (when to write an ADR)
  - `CHANGELOG.md`

## Goal

Record the decisions tests pin but nothing explains: why fail-closed is
permanent, why forward references are legal, why seq is excluded from
identity, why vendor heuristics live only in adapters — so future
changes argue with reasons, not just code.

## Verified Problem / Current Evidence

- Multiple behaviors look like bugs until you know the decision
  (field test flagged forward-refs as a gap — it is pinned-intentional;
  SL203 permanent refusal reads as missing functionality).
- `agent_tasks` convention is task-scoped; no decision-scoped record
  exists.

## Required Design / Decisions

1. `docs/adr/` with numbered ADRs, minimal template (Status / Context /
   Decision / Consequences / Alternatives rejected). Initial set:
   - 0001 zero-runtime-dependency posture
   - 0002 fail-closed repair (SL203 permanence)
   - 0003 forward parent references are legal
   - 0004 `seq` excluded from content identity (duplicate detection)
   - 0005 vendor heuristics confined to adapters (vendor-neutral core)
   - 0006 content-free findings by default
   - 0007 synthetic fixtures only (no real transcripts, ever)
   - 0008 deterministic output as a hard contract
2. ADRs record decisions *already made* with evidence citations
   (test/file) — they are history, not proposals.
3. `docs/adr/README.md`: index table + when-to-write rules (any
   invariant-touching decision gets an ADR before merge).
4. Status vocabulary: accepted / superseded-by-NNNN — no "proposed"
   parking lots (proposals live in task files, not ADRs).

## Ordered Implementation Steps

1. Create `docs/adr/` + README + template.
2. Write the 8 seed ADRs citing pinning tests/files.
3. CONTRIBUTING pointer; CHANGELOG Added (docs note).

## Required Tests / Validation Commands

```bash
ls docs/adr/ && grep -l "Status" docs/adr/*.md
uv run pytest -q tests/ -k docs
```

## Acceptance Criteria

- 8 ADRs exist, each citing the test/code that pins its decision;
  index complete; CONTRIBUTING names when ADRs are required.

## Rollback / Stop Conditions

- None — documentation.

## Risks

- ADR write-skew (decisions change, ADR doesn't) → superseded-status
  convention + the docs-drift test pattern keeps citations honest.

## Out of Scope

- Retroactive ADRs for every past decision (seed set covers the
  load-bearing ones; others written as they're touched); RFC process.

## Implementation Notes (done)

- `docs/adr/` created: README.md (index + when-to-write rules +
  accepted/superseded status vocabulary, "proposed" explicitly banned),
  TEMPLATE.md, and eight seed ADRs 0001–0008, each with Status / Context /
  Decision / Consequences / Alternatives rejected / Evidence sections.
- **Plan correction documented**: the plan's ADR-0004 premise ("seq
  excluded from content identity") was factually wrong — verified during
  T-01 that `_PROVENANCE_FIELD_NAMES` = {source_line, source_location,
  source_record_hash} only. ADR-0004 records the true decision: identity
  excludes provenance fields only; `seq` participates (renumbering is an
  explicit `seq-renumber` repair act, never silent identity stripping).
- `tests/test_adr_docs.py` (7 tests): seed-set presence, required
  sections + valid status per ADR, no proposed-parking, every file
  citation resolves on disk, index completeness, template exists.
- CONTRIBUTING "when to write an ADR" pointer; docs/README index row;
  CHANGELOG Added.
