# T-02: Scoped mutation testing (mutmut)

- Status: done
- Phase: qa
- Priority: P3
- Type: test infrastructure (dev-dep only)
- Depends on: —
- Primary targets:
  - `pyproject.toml` (`dev` extra: `mutmut` pin)
  - `mutmut_config` (setup.cfg/pyproject section)
  - `scripts/mutation_run.sh`-equivalent doc or `docs/` note
  - `CHANGELOG.md` (dev-facing)

## Goal

Measure whether the test suite would actually catch defects: run mutmut
scoped to the highest-risk modules (`checks/`, `repair/planner.py`,
`repair/executor.py`, `io.py`) on an opt-in, time-bounded basis — never
a blocking full-tree gate.

## Verified Problem / Current Evidence

- ~2000 green tests prove the suite passes, not that it *detects*;
  mutation score is the standard measure of detection power, and the
  checks/repair modules are where a surviving mutant would hurt most.
- `mutmut` is a dev-only tool — runtime stays zero-dep by construction.

## Required Design / Decisions

1. Scope explicitly: `src/sesslint/checks/`, `repair/planner.py`,
   `repair/executor.py`, `io.py` — not the whole tree (full-tree runs
   are multi-hour; scoped runs stay CI-optional).
2. `mutmut` pinned in `dev` extra (or separate `mutation` extra —
   prefer separate to keep `uv sync --extra dev` light); config in
   `pyproject.toml` `[tool.mutmut]` or `setup.cfg` per current mutmut
   version's convention.
3. Execution mode: manual + scheduled CI job (weekly/nightly
   `workflow_dispatch` or cron, `continue-on-error` reporting as an
   informational artifact — not a PR gate).
4. Triage protocol documented: surviving mutants classified
   {equivalent, test-gap, acceptable-risk}; test-gap mutants become real
   test tasks (one task file per cluster).
5. Baseline: first run establishes the per-module survival rate; the
   task note records it; improvement is directional, not a fixed %
   target.

## Ordered Implementation Steps

1. Add `mutation` extra + mutmut config scoped to the four modules.
2. First full scoped run on the maintainer's box; record survival stats
   in the task note.
3. Triage top survivors → file test-gap tasks.
4. Optional weekly CI job (informational).
5. CHANGELOG (dev-facing).

## Required Tests / Validation Commands

```bash
uv sync --extra dev --extra mutation
uv run mutmut run --paths-to-mutate src/sesslint/checks/ src/sesslint/io.py
uv run mutmut results
```

## Acceptance Criteria

- Scoped run completes; survival report recorded; ≥3 test-gap tasks
  filed from surviving mutants (or an honest note that survivors are
  equivalent mutations).

## Rollback / Stop Conditions

- Stop if mutmut runtime is unusably slow even scoped (>2h for the four
  modules) — reduce to `checks/` only or drop to manual-only.

## Risks

- Equivalent-mutant noise is the known cost → triage protocol exists to
  keep signal high; no % score is quoted as a quality claim anywhere.

## Out of Scope

- PR-blocking mutation gates; cosmic-ray/other frameworks (mutmut is
  the mature pytest-native option); mutating tests themselves.

## Implementation Notes (done)

- `mutation` extra: `mutmut>=3.8,<4` (locked 3.8.0 in uv.lock).
- `[tool.mutmut]`: `source_paths=["src/"]` (full copy keeps
  `import sesslint` intact in mutants/) + `only_mutate` restricted to
  `sesslint/checks/*`, `repair/planner.py`, `repair/executor.py`, `io.py`;
  `pytest_add_cli_args_test_selection=["tests/"]` — mutmut's own
  relevance filter only runs tests reaching the mutated function.
- **POSIX-only discovered**: mutmut 3 requires `os.fork`; the maintainer
  box is Windows without WSL, so no local run is possible. The weekly
  `mutation.yml` workflow (ubuntu, cron + workflow_dispatch, never a PR
  trigger, `contents: read`, 120-min cap) becomes the primary run path;
  artifacts (`mutmut-results.txt`, junit, `mutants/`) uploaded for triage.
- Triage protocol + baseline-pending note in `docs/MUTATION_TESTING.md`.
- Remaining manual step: first POSIX run establishes survival stats;
  ≥3 test-gap tasks or an honest equivalent-mutant note afterwards.
