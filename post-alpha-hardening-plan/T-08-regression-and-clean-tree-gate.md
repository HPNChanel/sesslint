# T-08: Full regression and clean-tree release gate

- Status: planned
- Phase: 3
- Priority: P0 release
- Depends on: T-02, T-03, T-04, T-05, T-06, T-07
- Code behavior change: none unless a gate reveals a new defect

## Goal

Produce one reproducible release-candidate evidence set from an identified source tree after all corrective tasks land.

## Precondition

Before running release evidence:

```bash
git status --porcelain
```

must be empty.

Record:

```bash
git rev-parse HEAD
git tag --points-at HEAD
python --version
```

If the bridge/runner cannot execute Git commands, the maintainer must provide the evidence; do not infer cleanliness from task prose.

## Gate Matrix

### Static / type

```bash
ruff check .
ruff format --check .
mypy --strict src/
```

### Full tests

```bash
pytest -q
pytest -q tests/accept/test_offline.py tests/accept/test_kill.py
```

Record exact passed/skipped counts.

### Focused corrective regressions

```bash
pytest -q tests/adapters/test_detect.py tests/test_profiles.py tests/test_api_surface.py
pytest -q tests/test_verify.py tests/test_verify_challenger.py tests/test_e2e_cycle.py
pytest -q tests/test_report.py tests/cli/test_check.py
pytest -q tests/test_bench_smoke.py
```

### Performance

```bash
python bench/perf_250k.py --records 250000 --time-budget 15.0 --mem-budget 512.0
```

If this is non-zero, release readiness is blocked unless T-06 has explicitly changed the normative budget/spec through an approved decision.

### Build / offline smoke

```bash
python -m build --sdist --wheel
```

Then verify clean-environment install according to `RELEASING.md`, including `--no-index` / offline smoke requirements.

### Artifact integrity

Generate SHA-256 for every release artifact from the same clean tree.

## Acceptance

- Identified commit SHA.
- Clean tree before build.
- Full functional gates green.
- Corrective regression tests green.
- Performance gate meets the current normative contract.
- Wheel/sdist build and offline smoke green.
- Artifact hashes recorded.
- Documentation claims match measured evidence.

## Failure Rule

Any discovered defect spawns a new `T-08x-<slug>.md` and blocks T-09. Do not edit acceptance criteria downward to absorb a failure.

## Out of Scope

- Public release/tagging itself.
- Campaign closeout.
