# DEV-012 -- Documentation synchronization sweep

## Task Metadata

- Task ID: DEV-012
- Title: Synchronize all prose to the NDP-001 code truth
- Program: NDP-001 "Trustworthy Alpha"
- Milestone: M2 (runs LAST in M2)
- Status: `complete`
- Recommended Gemini effort: low
- Dependencies: DEV-002, DEV-003, DEV-004, DEV-005, DEV-006, DEV-007, DEV-008, DEV-009, DEV-010, DEV-011
- Blocks: (none; M3 entry needs M2 green incl. this task)
- Related opportunity IDs: OPP-015
- Risk level: low
- Compatibility classification: INTERNAL_ONLY (docs)
- `CONTRIBUTOR_FRIENDLY = YES`

## Repository Baseline

Known drift (pre-NDP-001): README recipe catalog lists `terminal-suffix-discard` as
conservative SL002 (code: salvage SL005) and omits `torn-terminal-record-discard`;
counts say 5+3 vs actual 5+4; `docs/recipes/README.md` says 8 recipes; RELEASING.md
checklist says 8; traceability header says "all planned"; CONTRIBUTING clone URL is a
placeholder org. NDP-001 behavior changes (DEV-002..011) add: order rule, fingerprint
preimage + value break, coverage block, byte offsets, synthetic-id namespace, SL302
shape rule, manifest fields, CLI surface decisions, run-state evidence.

## Objective

Every user-facing prose statement about behavior matches the M2 code; a docs-vs-code test
locks the recipe catalog; release-note deltas for the behavioral breaks are written.

## User / Maintainer Value

Docs are the contract users read; drift here is where false expectations (and false bug
reports) come from. This task converts M2's code truth into readable truth.

## Why Now

Runs last in M2 so it captures all M2 behavior changes in one pass.

## Scope

- Fix: README (recipe catalog + counts + command matrix + ordering/fingerprint/coverage
  statements), docs/recipes/README.md, RELEASING.md checklist, traceability header,
  CONTRIBUTING clone URL (HPNChanel/sesslint) + gate table if changed, docs/codes/README.md
  fingerprint paragraph, SL201/202 boundary consistency (from DEV-011), manifest field docs.
- Add/extend a test that locks README's recipe list + counts to the registry
  (extend `tests/test_registry_docs.py` pattern; keep it robust to formatting).
- Write `docs/NDP-001-NOTES.md`?? NO -- do not add planning artifacts to the repo.
  Instead: behavioral-break notes go in the completion report AND in the user-facing
  docs where they belong (README compatibility notes). No new repo doc files except where
  an existing doc requires a new section.
- Verify every CLI example in README/CONTRIBUTING/RELEASING by EXECUTING it verbatim.

## Out of Scope

- No code behavior changes (docs + docs-tests only). Broken behavior found during doc
  verification -> report, do not fix (fix belongs to the owning task; reopen it).
- No ADAPTER_GUIDE (DEV-016), no bundle docs (DEV-014), no action docs (DEV-015).

## Existing Architecture to Reuse

- `tests/test_registry_docs.py` + `tests/test_rule_docs.py` patterns; recipe registry;
  report schema; `--help` outputs as the CLI truth source.

## Files Expected to Change

```text
CREATE: (none)
MODIFY: README.md
        docs/recipes/README.md
        RELEASING.md
        CONTRIBUTING.md
        docs/implementation/REQUIREMENTS_TRACEABILITY.md (header only)
        docs/codes/README.md (only if stale re fingerprints)
        tests/test_registry_docs.py (extend to README catalog lock)
DELETE: (none)
```

## Public API / Schema Impact

None (docs only).

## Detailed Design

- Recipe-lock test: parse the registry (names + conservative/salvage partition + handled
  codes) and assert README's catalog section + recipes/README list contain exactly that set
  (normalize markdown bullets; fail with a diff-style message naming the missing/extra).
- Compatibility-notes section in README: enumerate NDP-001 behavioral breaks with old/new
  rule each (finding order, fingerprint values, plan fingerprint values, evidence additions,
  CLI flag removals, manifest additions, SL004 narrowing). Wording must let a 0.1.0 user
  predict 0.2.0 output diffs.
- Example verification: extract fenced `sesslint ...` commands from touched docs and run
  each; record results in the completion report. Fix doc (not code) on mismatch, unless
  mismatch reveals a product bug -> report + stop that item.

## Implementation Steps

1. Inventory every prose claim touched by DEV-002..011 (read their completion reports).
2. Fix recipe catalogs + counts + checklists + header + clone URL.
3. Write compatibility notes; extend the registry-docs lock test.
4. Execute every CLI example verbatim; fix docs; report product bugs (don't fix).
5. Run docs tests + full suite + gates.

## Required Tests

- Extended catalog-lock test (registry == README == recipes/README).
- No new product tests. Example-execution evidence in the completion report.

## Regression Risks

- Over-strict doc parsing (brittle test). Mitigate: normalize whitespace/case; assert on
  recipe NAMES + partition, not prose.

## Safety / Trust Invariants

- Docs must never over-claim: every behavior statement traceable to code/test.

## Performance Constraints

- None.

## Verification Commands

```bash
uv run pytest tests/test_registry_docs.py tests/test_rule_docs.py tests/test_license.py tests/test_fixture_provenance.py -q
uv run ruff check src tests && uv run ruff format --check src tests && uv run mypy --strict src/sesslint
uv run pytest -q
```

## Acceptance Criteria

1. Zero known drift items remain (each pre-existing item + each M2 change addressed).
2. Catalog-lock test fails if a recipe is added/renamed/moved without doc sync (prove by
   temporary mutation in a scratch checkout? NO -- prove by code review of the test's
   assertion scope + a negative unit test with synthetic registry input).
3. Every fenced CLI example in touched docs executed with recorded results.
4. Full suite + static gates green.

## Failure Conditions

- Do NOT claim completion if any example was not executed, if the lock test can pass with
  a stale catalog, or if a found product bug was fixed inside this task.
- Do NOT add planning/task artifacts to the repo.

## Completion Checklist

- [x] All drift items fixed + compatibility notes written
- [x] Catalog-lock test extended + proven
- [x] Examples executed + evidence recorded
- [x] Full suite + gates green

## Gemini Executor Directive

Implement ONLY DEV-012. Read the DEV-002..011 completion reports first so every behavior
change is captured. Docs + docs-tests only; if you find a product bug, report it and move
on -- do not fix it here. Do not implement subsequent tasks. Run every verification
command. Do not claim completion while any example is unexecuted or any gate fails.
