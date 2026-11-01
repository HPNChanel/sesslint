# Mutation Testing (qa-infra T-02)

Scoped [mutmut](https://github.com/boxed/mutmut) runs that measure whether the
test suite *detects* defects, not just passes. Informational only — never a
PR gate, never a blocking CI check.

## Hard requirement: POSIX only

mutmut 3 needs `os.fork`. It **cannot run on native Windows** — use WSL,
Linux, macOS, or the weekly CI workflow. Do not attempt `mutmut run` on a
Windows host; it will fail before mutating anything.

## Scope

`[tool.mutmut]` in `pyproject.toml` copies the full `src/` tree (so
`import sesslint` stays intact inside `mutants/`) and restricts mutations via
`only_mutate` to the highest-risk modules:

- `src/sesslint/checks/*` — detector logic
- `src/sesslint/repair/*` — repair planning, preconditions, recipes, executor
- `src/sesslint/outcome/*` — outcome contract
- `src/sesslint/io.py` — byte-level reading

Notes on the config (all learned the hard way):

- `only_mutate` is `fnmatch`ed against the path **with** the `src/` prefix.
  `sesslint/checks/*` matches nothing and silently yields zero mutants.
- Tests run with the `mutants/` tree as cwd, so everything they read from the
  repo root is listed in `also_copy` (`fixtures/`, `docs/`, `schemas/`,
  `man/`, and a few root files).
- Test selection is limited to `tests/{checks,repair,io,engine,outcome}/`
  (the same dirs as the CI baseline plus `outcome`). The whole `tests/` tree
  takes ~50 min for the stats phase alone, and includes tests that spawn
  `python -m sesslint` from another cwd, which cannot work in `mutants/`.
- One test is deselected via `pytest_add_cli_args` (mutmut runs pytest twice
  in one process; Hypothesis rejects the class-based test). It still runs in
  the normal `pytest` suite.

Measured on a 4-core runner: 18,860 mutants; mutant generation ~7 min, stats
~8 min, mutant testing ~60 min — plan for 75-90 min in total (the last few
hundred slow/timeout mutants dominate the tail).
Full-tree runs are explicitly out of scope.

## Run

```bash
uv sync --extra dev --extra mutation
uv run pytest -q tests/checks/ tests/repair/ tests/io/ tests/engine/  # baseline must pass
uv run mutmut run          # incremental; Ctrl-C and re-run resumes
uv run mutmut results      # survival report
uv run mutmut run 'sesslint.repair.preconditions.*'   # re-test one module
uv run mutmut browse       # interactive triage
```

`mutants/` is generated output — never commit it. When you change
`[tool.mutmut]`, delete `mutants/` first.

The CI workflow `.github/workflows/mutation.yml` runs the same scope weekly
(Sunday 03:00 UTC) and on `workflow_dispatch`, uploading `mutmut-results.txt`,
`mutmut-junit.xml`, and the `mutants/` tree as artifacts. It is scheduled-only
— no `pull_request` trigger, no required status.

## Triage protocol

For each surviving mutant, classify exactly one of:

| Class | Meaning | Action |
| ----- | ------- | ------ |
| `equivalent` | Mutant is semantically identical (e.g. `x is None` → `x == None` where equal) | Note and ignore; optionally comment `pragma: no mutate` upstream |
| `test-gap` | Mutant changes behavior and no test detects it | File a task; add the minimal regression test |
| `acceptable-risk` | Behavior change is real but harmless for this tool (e.g. cosmetic ordering in a non-output path) | Record rationale in this doc's triage log |

**Never** quote a mutation-score percentage as a quality claim — the score is
a triage queue, not a badge.

## Baseline

The first completed scoped run establishes per-module survival rates in the
internal task note (qa-infra T-02). Until a POSIX runner
completes it, the baseline is **pending** — the maintainer's box is Windows
without WSL, so the weekly CI job is the expected first real run.
