# T-09: Baseline v2 path-normalized fingerprints

- Status: done (2026-04-05)
- Phase: ux
- Priority: P1
- Type: fix/feature (baseline format v2 + migration)
- Depends on: —
- Primary targets:
  - `src/sesslint/baseline.py` (v2 fingerprint + loader/writer)
  - `src/sesslint/cli.py` (`baseline --upgrade`)
  - `schemas/` (`sesslint.baseline/v2`)
  - `tests/test_baseline*.py`, `fixtures/`
  - `README.md`, `CHANGELOG.md`

## Goal

Baseline matching survives path spelling differences — moved cwd, absolute
vs relative invocation, checkout renames — by keying fingerprints on
finding identity rather than literal path text.

## Verified Problem / Current Evidence

- Field-test debt: baseline fingerprints are path-spelling sensitive;
  renaming a directory or invoking with a different cwd silently breaks
  matching and re-surfaces baselined findings.
- `baseline.py` exists (Wave A5): load/filter/write; suppression happens
  before counts/verdicts.

## Required Design / Decisions

1. Fingerprint v2 = `sha256(rule_code | finding_fingerprint_core)` where
   the core excludes the path string entirely — matching keyed on
   (rule, event-identity evidence: record ids/indexes/structural anchors
   already in the fingerprint) plus a *file role* key:
   `basename + parent-dir basename` (portable across relocations).
2. Matching order per finding: exact v2 key → legacy v1 key (backward
   compat, read-only) → unmatched. v1 files still load; `--write-baseline`
   always emits v2.
3. `sesslint baseline --upgrade FILE`: rewrites a v1 baseline as v2 with a
   deterministic recompute pass over the referenced file when available;
   entries whose source file is absent carry `migrated: "unverified"` —
   honest state, still matchable.
4. Ambiguity guard: if two different findings share one v2 key, the entry
   matches neither — fail-closed, logged as `baseline-ambiguous` skip.
5. Schema `sesslint.baseline/v2` documents `version`, entries
   `{key, code, file_role, created_by}`; prose in README explains what a
   fingerprint does *not* bind (path spelling) and what it still binds
   (finding identity, rule set version).
6. Deterministic: v2 computation is pure over finding+path; sorted output.

## Ordered Implementation Steps

1. `baseline.py`: v2 key computation + dual-version loader + `upgrade()`.
2. CLI: `--upgrade` on `baseline`; scan/check keep `--baseline` semantics.
3. Schema + fixtures: v1 and v2 baselines, rename/cwd-variation tests
   (same file invoked via relative vs absolute path matches identically).
4. Migration tests: v1→v2 upgrade preserves matching; ambiguous-key case
   suppresses nothing.
5. Docs + CHANGELOG (breaking note: v2 write format).

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/ -k baseline
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- Same file checked via `rel/path.jsonl`, `C:\abs\path.jsonl`, and after
  parent-dir rename matches the same v2 baseline entry in all three cases.
- v1 baselines keep working unchanged; `--write-baseline` emits v2;
  `--upgrade` output is deterministic.

## Implementation Notes (done)

- `baseline.py` rewritten: `file_role()` = `parent-basename/basename`
  (relative spellings absolutized lexically against cwd — no FS access;
  `<stdin>`-style virtual paths stay literal). `compute_v2_key()` hashes
  `[code, file_role, line, ordinal, record_id, ev_subset]` — adapter/profile
  deliberately absent so entries name finding identity, not invocation.
- `load_baseline` is dual-version (v1 fingerprints ∪ v2 entry keys → one
  opaque frozenset; zero signature changes downstream). `filter_findings`
  matches v1 fingerprint then v2 key, with the ambiguity guard: a v2 key
  owned by ≥2 distinct v1 fingerprints suppresses nothing.
- `write_baseline`/`dump_baseline` now take `Iterable[Finding]` and emit
  v2 (`code`/`file_role`/`key`/`created_by` per entry, sorted by key).
- New `sesslint baseline` subcommand: `--upgrade FILE [--source PATH]
  [--output PATH] [--format] [--profile]` — file source re-checks via
  `check_file`, directory source via `scan_path`; verified entries get real
  v2 keys, leftovers migrate `unverified` (still matchable via v1 leg).
- Acceptance interpretation: "parent-dir rename" = ancestor/checkout-root
  rename (immediate-parent rename is the documented residual ambiguity —
  file_role binds basename+parent by design). Verified: abs write → rel
  bare invoke suppresses; scan baseline written at root A suppresses the
  relocated copy at `elsewhere/deep/A`; immediate-parent rename does NOT
  match.
- Side fix: `check_release_refs.py` flag coverage now applies to `.md`
  only — CI yml legitimately invokes other tools (`pip install --upgrade`)
  whose flags collide with new sesslint flags.
- Validation: `uv run pytest -q tests/ -k baseline` (25 pass), full suite
  green, ruff/format/mypy clean, `check_release_refs.py` OK. New schema
  `schemas/sesslint.baseline.v2.json`; README Baselines section rewritten;
  `baseline` auto-joins shell completions via the live parser.

## Rollback / Stop Conditions

- Stop if v2 keys cannot be made collision-safe under rename — fall back
  to v1 semantics + documented limitation, never widen matching silently.

## Risks

- Over-normalization could let a baseline match a different file's
  identical finding → `file_role` (basename+parent) is the deliberate
  middle ground; document residual ambiguity.

## Out of Scope

- Fuzzy/content-similarity matching; baseline sharing across machines
  (file_role is intentionally local-portable, not global).
