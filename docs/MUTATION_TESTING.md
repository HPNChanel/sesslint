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
`import sesslint` stays intact inside `mutants/`) but restricts mutations via
`only_mutate` to the highest-risk modules:

- `sesslint/checks/*` — detector logic
- `sesslint/repair/planner.py` — repair planning / fail-closed decisions
- `sesslint/repair/executor.py` — repair application
- `sesslint/io.py` — byte-level reading

Full-tree runs take hours and are explicitly out of scope.

## Run

```bash
uv sync --extra dev --extra mutation
uv run pytest -q tests/checks/ tests/repair/ tests/io/ tests/engine/  # baseline must pass
uv run mutmut run          # incremental; Ctrl-C and re-run resumes
uv run mutmut results      # survival report
uv run mutmut browse       # interactive triage
```

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
task note (`plans/qa-infra/T-02-mutation-testing.md`). Until a POSIX runner
completes it, the baseline is **pending** — the maintainer's box is Windows
without WSL, so the weekly CI job is the expected first real run.
