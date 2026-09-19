# T-05: Real-shape corpus expansion (failure-spawner)

- Status: done
- Phase: qa
- Priority: P1
- Type: test corpus work
- Depends on: —
- Primary targets:
  - `fixtures/` (new synthetic families)
  - `tests/conformance/` (rows)
  - `next-phase-plan/T-05-failure-spawner.md` (existing generator base)
  - `FIXTURES.md` (provenance notes)
  - `CHANGELOG.md`

## Goal

Grow the synthetic corruption corpus to mirror every real-world shape
the field test actually saw — so the next "real data" surprise is
caught by fixtures instead of a user's broken session.

## Verified Problem / Current Evidence

- Field test found the corpus gap directly: fixtures lacked
  `token_usage_record`, Claude 2.x version strings, `summary`/
  `isSidechain` records, >1 MiB lines — ~2000 green tests still missed
  every real-data blocker.
- `next-phase-plan/T-05` already built a failure-spawner generator —
  this extends its families.

## Required Design / Decisions

1. New fixture families (all synthetic, `PROVENANCE.json` with
   `contains_real_data: false`; shapes re-authored from observed
   *structure*, never copied content):
   - codex-telemetry: `token_usage_record`, `world_state`,
     `inter_agent_communication_metadata`, `item_completed`,
     `tool_search_call`/`tool_search_output` envelopes;
   - claude-2x: `version:"2.x.y"` markers, `summary` records,
     `isSidechain:true` subtrees, queue-operation records;
   - big-lines: legit ~1–2 MiB `custom_tool_call_output`-shape lines
     (clean + corrupted variants);
   - compaction-chains: compaction boundary + post-boundary tool calls
     (SL203-shape) + coverage-pointer variants (for checks-rules T-04);
   - mixed-integrity: files combining 2+ corruption classes (the real
     world doesn't corrupt one thing at a time).
2. Each family ships happy + corrupted + hostile variants with
   `EXPECTATIONS.json` rows.
3. Regression rule (documented in FIXTURES.md): every future real-data
   finding becomes a synthetic fixture family before the fix lands —
   the field-test protocol, codified.
4. Generation stays deterministic (spawner seeded); byte-exact
   fixtures committed.

## Ordered Implementation Steps

1. Extend the failure-spawner generator with the five families.
2. Generate + commit fixtures with provenance.
3. Conformance rows + expectation entries.
4. Run real-tree spot-check to confirm coverage now spans observed
   shapes (counts only, uncommitted note).
5. CHANGELOG Added (test-corpus note).

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/conformance/ tests/
uv run pytest -q && uv run ruff check src tests
```

## Acceptance Criteria

- All five families present with expectations; a synthetic session
  exercising the field-test's real shapes produces the expected
  findings; zero real-data content in the tree (provenance audit).

## Rollback / Stop Conditions

- Stop if any generated shape can't be confirmed against the adapter's
  own type tables — mark it `unverified` in provenance rather than
  guessing.

## Risks

- Fixture ossification → the drift-watch protocol
  (adapters-coverage/T-03) feeds new shapes here continuously.

## Out of Scope

- Real transcripts in any form; generative/property fixtures (that is
  fuzz T-01's domain — these are pinned, byte-exact cases).

## Implementation Notes (done)

- `fixtures/corpus/` — five synthetic families, each with
  `PROVENANCE.json` (`contains_real_data: false`) + `EXPECTATIONS.json`
  (exact code-set + assurance + exit + repairable):
  - `codex-telemetry` (3 files): the full observed drift set absorbs
    cleanly (A3) — token_count, task_started/complete, item_completed,
    turn_aborted, thread_settings_applied, `metadata` envelope key,
    world_state, token_usage_record, inter_agent_communication_metadata.
    Note: several shapes the plan listed are already in adapter tables
    (ENVELOPE_OPAQUE_TYPES/RESPONSE_ITEM_TYPE_MAP) — the family now
    regression-guards them.
  - `claude-2x` (4): semver 2.x app versions + isSidechain clean;
    `queue-operation` fails closed SL302 (+SL006/SL007).
  - `big-lines` (2): ~1.5 MiB single-line output clean; torn tail SL002.
  - `compaction-chains` (3): SL203 unsafe-continuation shapes —
    post-boundary pair, cross-boundary continuation, coverage-pointer
    gap (expectations measured, not guessed: SL101/SL102/SL203, SL102).
  - `mixed-integrity` (2): compound corruption — SL003+SL004+SL006+SL007
    and SL003+SL101+SL102 in single files.
- `tests/test_corpus_families.py` (12 tests): exact code-SET equality
  (stronger than hostile corpus' subset), assurance, CLI exit parity,
  provenance per family, no orphan fixture files.
- `FIXTURES.md` §4 codifies the real-shape regression rule.
- Expectations were *measured* via `api.check_file`, never guessed.
