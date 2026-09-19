# T-03: Coverage ratchet gate in CI

- Status: done
- Phase: qa
- Priority: P2
- Type: test infrastructure (dev-dep only)
- Depends on: —
- Primary targets:
  - `pyproject.toml` (`dev` extra: `coverage`; `[tool.coverage]` config)
  - `.github/workflows/ci.yml` (coverage job)
  - `tests/COVERAGE_FLOOR` (ratchet file) or pyproject threshold
  - `CONTRIBUTING.md` (coverage expectation note)
  - `CHANGELOG.md` (dev-facing)

## Goal

CI reports line+branch coverage on `src/sesslint` and fails if coverage
drops below the committed floor — a ratchet that may only tighten, so
new code can't silently ship untested.

## Verified Problem / Current Evidence

- No coverage measurement exists anywhere; field-test remediation added
  code paths whose test coverage is asserted by review, not measurement.
- `coverage.py` is the standard dev-dep; pytest integration via
  `pytest-cov` (also dev-only).

## Required Design / Decisions

1. `pytest --cov=sesslint --cov-branch --cov-report=term-missing
   --cov-fail-under=<floor>` in a dedicated CI job (not merged into the
   main test job — keeps failure signals separate).
2. Floor mechanics: committed floor value (start = measured baseline,
   e.g. whatever the first run reports minus 1%); PRs may not lower it;
   raising it is encouraged via a `COVERAGE_FLOOR` bump in the PR that
   improved coverage.
3. Scope: `src/sesslint` only; tests/bench/scripts excluded; omit
   `if TYPE_CHECKING`/`__main__`/`raise NotImplementedError` pragmas per
   standard coverage config.
4. Report artifacts: HTML+XML uploaded as CI artifacts (codecov
   optional — free for OSS; decide yes/no in task, default no to avoid
   external dependency creep).
5. Honest floor: initial floor = measured value, not an aspirational
   90% — the ratchet improves it organically.

## Ordered Implementation Steps

1. Add `coverage`/`pytest-cov` to dev extra + config (`pyproject.toml`
   `[tool.coverage.*]`).
2. Measure baseline locally; commit `COVERAGE_FLOOR` (or pyproject
   `fail_under`) at baseline−1%.
3. CI job wiring + artifact upload.
4. CONTRIBUTING note; CHANGELOG (dev-facing).

## Required Tests / Validation Commands

```bash
uv run pytest --cov=sesslint --cov-branch --cov-report=term-missing -q
uv run pytest --cov=sesslint --cov-fail-under=<floor> -q
```

## Acceptance Criteria

- Coverage job runs green at the floor; a PR removing a covered test
  demonstrably fails the gate (proven once with a seeded change,
  reverted).

## Rollback / Stop Conditions

- Stop if coverage flakiness appears (order-dependent tests) — fix the
  test, not the floor; floor only moves by deliberate commit.

## Risks

- Coverage-as-target gaming → floor is a ratchet (tripwire), never
  quoted as a quality metric in docs/README.

## Out of Scope

- Mutation score gates (T-02 is informational); coverage of tests/
  bench/; external coverage services (optional, off by default).

## Implementation Notes (done)

- `pytest-cov` was already in `dev`; `[tool.coverage]` run/report config
  already had `source`, `branch`, `exclude_also` pragmas.
- Baseline measured locally: **87%** total (14484 stmts, 6404 branches);
  `fail_under = 86` committed in `[tool.coverage.report]` — pyproject as
  the single floor source (no separate COVERAGE_FLOOR file needed).
- New `coverage` job in `ci.yml` (separate from `test` job — distinct
  failure signal): `pytest --cov=sesslint --cov-branch --cov-report=
  term+html+xml`, artifacts uploaded `if: always()` (30-day retention).
- Gate proven: `--cov-fail-under=88` seeded run fails (exit 1), and
  partial-suite runs now correctly fail under the committed floor;
  full suite sits at 87% ≥ 86.
- CONTRIBUTING §Verification Gates documents the ratchet as a
  tripwire, never a quality metric.
