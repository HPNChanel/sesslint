# T-04: New recipes — `seq-renumber` + `identical-duplicate-drop`

- Status: done
- Phase: repair
- Priority: P1
- Type: feature (deterministic repair recipes)
- Depends on: —
- Primary targets:
  - `src/sesslint/repair/recipes_conservative.py` (new recipes)
  - `src/sesslint/repair/registry.py` (recipe registration)
  - `src/sesslint/repair/planner.py` (finding→recipe mapping)
  - `docs/recipes/seq-renumber.md`, `docs/recipes/identical-duplicate-drop.md`
  - `tests/repair/`, `fixtures/`, conformance rows
  - `CHANGELOG.md`

## Goal

Two deterministic recipes closing known repairability gaps: renumbering
`seq` after drop-steps so emitted canonical streams stay positionally
coherent, and consolidating `identical-duplicate` SL003 findings (warning
class) that currently have no recipe.

## Verified Problem / Current Evidence

- Field-test A6 made SL003 classify identical duplicates as warning +
  `deterministic` — but no recipe consumes that class; repair still
  reports it unhandled or relies on manual.
- Drop recipes (orphan-result-drop, torn-terminal-discard) remove events;
  emitted canonical files keep original `seq` values with gaps — valid
  per current spec but a candidate normalization for downstream loaders
  that assume contiguous ordinals (verify spec first — see stop
  condition).

## Required Design / Decisions

1. `identical-duplicate-drop` (SL003, identical class only): keep the
   *first* occurrence by canonical position; drop later identicals.
   Conflicting-duplicate class stays `manual` — recipe must refuse any
   SL003 finding classified conflicting (fail-closed check inside the
   recipe, not just the planner mapping).
2. `seq-renumber` (canonical adapter only): after all drop steps,
   renumber `seq` to `0..n-1` preserving order. This is a *normalizing*
   recipe: it runs only when (a) ≥1 drop step executed AND (b) output
   format is canonical (vendor write-back keeps vendor lines verbatim —
   seq lives inside canonical events only).
3. Recipe metadata: `deterministic`, `loss: none` for seq-renumber;
   `loss: declared` for identical-duplicate-drop (dropped bytes are
   declared loss — duplicates are redundant but loss accounting stays
   honest).
4. `sesslint.plan/v1` step kinds gain the two recipe ids; plan fingerprint
   covers them automatically (params included).
5. Idempotence: applying the recipe set twice converges (verify's
   idempotence check must pass — drop-all-identicals is a fixed point;
   renumber is a fixed point).

## Ordered Implementation Steps

1. `recipes_conservative.py`: implement both recipes with refusal guards
   (conflicting SL003 → refuse; non-canonical emit for seq-renumber →
   skip-with-note).
2. `registry.py` + planner mapping; `docs/recipes/*.md` per AGENTS.md
   recipe-doc gate.
3. Fixtures + conformance rows: identical-dup canonical + vendor cases;
   drop+renumber sequence on multi-orphan fixture.
4. Tests: end-to-end repair + `verify` round-trip on both; idempotence;
   conflicting-dup still blocks.
5. CHANGELOG Added.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/repair/ tests/conformance/
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- SL003 identical-duplicate findings repair deterministically and verify
  clean; conflicting duplicates remain manual/refused.
- Drop+renumber output validates against the canonical schema with
  contiguous seq and passes `verify` audits.

## Rollback / Stop Conditions

- **Spec check first**: if the canonical spec (or a consumer) treats
  `seq` gaps as meaningful evidence, seq-renumber must not renumber —
  demote it to an opt-in `--normalize-seq` flag or drop the recipe.
- Stop if identical-dup classification cannot distinguish
  identical-vs-conflicting at recipe time (evidence must carry the class).

## Risks

- Renumbering changes event bytes → `content_identity_hash` excludes
  `seq` (A6 fix), so audits must still pass — verify explicitly in tests.

## Out of Scope

- Conflicting-duplicate merge heuristics (manual forever); cross-file
  dedupe; seq-rewrite on vendor formats.
