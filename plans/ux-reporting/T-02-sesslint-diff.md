# T-02: `sesslint diff` structural comparator

- Status: done
- Phase: ux
- Priority: P1
- Type: feature (new command; read-only)
- Depends on: —
- Primary targets:
  - `src/sesslint/cli.py` (`diff` subcommand)
  - `src/sesslint/api.py` (`diff_sessions(a, b)`)
  - `src/sesslint/diff.py` (new module)
  - `tests/`, `README.md`, `CHANGELOG.md`

## Goal

`sesslint diff A B` answers "what structurally changed between these two
session files" — event identity alignment, not text diff — for
before/after comparisons (vendor update, pre/post compaction, repair
output vs source sanity review).

## Verified Problem / Current Evidence

- Users today `diff` raw JSONL: line-level noise (reordered keys,
  reserialized floats) hides structural change.
- Canonical events already expose `content_identity_hash`, ids, parents,
  kinds, seq — the alignment primitives exist (`canonical.py`).

## Required Design / Decisions

1. `sesslint diff A.jsonl B.jsonl [--format human|json]`; both inputs go
   through normal detection+adapter parse; undetectable → structured
   error (SL001/SL302 semantics reused).
2. Alignment: primary key = event id; fallback alignment for id-less
   (synthetic-id) events = `(kind, parent_id, content_identity_hash)`
   sequence match — documented, deterministic.
3. Delta categories (content-free): `added`, `removed`, `kind-changed`,
   `parent-relinked`, `seq-reordered`, `content-changed` (identity hash
   differs — payload itself never shown).
4. Output: human = grouped sections with counts + bounded id lists; JSON =
   `{schema: "sesslint.diff/v1", a: <minimized path>, b: ..., deltas:
   [...]}` — new schema file `schemas/sesslint.diff.schema.json`.
5. Exit codes: `0` identical structure, `1` differences found, `2` usage/
   input error — consistent with `check` semantics.
6. Deterministic: deltas sorted by (category, target index in B, id);
   identical inputs → identical bytes.

## Ordered Implementation Steps

1. `diff.py`: parse via `adapters.load`, build id index, emit delta list
   (frozen dataclasses).
2. `api.diff_sessions()` + CLI wiring + exit codes.
3. `schemas/sesslint.diff.schema.json` + schema test.
4. Tests: identical files → exit 0; synthetic mutations (drop event,
   swap order, change parent) → exact expected deltas; vendor file vs
   canonical export of itself → only expected projection deltas.
5. Docs + CHANGELOG.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/ && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- `diff` on a file vs itself → zero deltas, exit 0.
- Every synthetic mutation class yields exactly its category, and JSON
  validates against `sesslint.diff.schema.json`.
- No payload strings anywhere in output (privacy test).

## Rollback / Stop Conditions

- Stop if synthetic-id alignment cannot be made deterministic — restrict
  v1 to real-id events and mark id-less spans `unaligned` honestly.

## Risks

- Vendor adapters normalize differently across versions → pin adapter
  version into the diff doc header so results are interpretable.

## Out of Scope

- Word/payload-level diffs; three-way merge; applying diffs as patches.

## Implementation Notes (landed)

- `src/sesslint/diff.py`: `diff_events` (pure two-pass aligner) +
  `diff_sessions` (detect+load via `resolve_format`/`load_events_for_format`),
  frozen `Delta`/`SessionDiff`, `DiffInputError` (CLI maps to exit 2).
- Alignment: pass 1 pairs by `event.id` (duplicate ids pop earliest);
  pass 2 fallback multiset on `(kind, parent_id, content_identity_hash)`;
  leftovers emit `removed`/`added`. Per-pair compares emit
  `kind-changed`/`parent-relinked`/`content-changed` (hash[:16] detail only);
  `seq-reordered` flags pairs whose B index regresses below running max.
- Sort: (category order, a_index, b_index, event_id) — deterministic.
- CLI `sesslint diff A B`: `--format` (both), `--format-a`/`--format-b`,
  `--output-format human|json`, `--json`; exit 0 identical / 1 diffs / 2
  input error. Read-only.
- `api.diff_sessions` exported (library-CLI parity); JSON wire shape
  `sesslint.diff/v1` + `schemas/sesslint.diff.v1.json` +
  `get_diff_schema_path`/`load_diff_schema` (scan.py convention).
- Circular-import fix: `minimize_path` imported lazily inside functions
  (diff -> report -> repair -> checks.runner -> report).
- tests/cli/test_diff.py: 18 tests (all delta categories, schema
  conformance, determinism, privacy no-payload, exit codes, DiffInputError).
- README: command matrix (nine->ten) + `#### sesslint diff` section +
  schema table row, all `next release`-marked. CHANGELOG entry.
- `PINNED_COMMANDS` in test_completion.py += "diff" (auto-completes in
  generated shells).
- Gates: ruff/format/mypy clean; full suite green; release-refs OK.
