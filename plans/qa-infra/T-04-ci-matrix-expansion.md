# T-04: CI matrix expansion (py3.13 + ARM)

- Status: done
- Phase: qa
- Priority: P2
- Type: infrastructure (CI)
- Depends on: —
- Primary targets:
  - `.github/workflows/ci.yml` (matrix)
  - `pyproject.toml` (classifiers if claiming 3.13)
  - `README.md` (supported-versions note)
  - `CHANGELOG.md`

## Goal

CI covers Python 3.13 and an ARM runner so the platform claims stay
honest as the ecosystem moves — free for public repos.

## Verified Problem / Current Evidence

- Current matrix: linux/win/mac × py3.11/3.12 (per native-accel plan
  notes). Python 3.13 is released and gaining share; ARM runners
  (`ubuntu-24.04-arm`) are now available to public repos at no cost.
- `pyproject.toml` requires `>=3.11` — 3.13 is inside the declared
  range but untested.

## Required Design / Decisions

1. Add `3.13` to the matrix across the three OSes (or at minimum
   ubuntu+windows — decide by job-time cost; full expansion preferred).
2. Add one `ubuntu-24.04-arm` leg at the highest py version — catches
   arch-specific assumptions (mmap T-03 later, file locking, path
   semantics).
3. If any test is flaky on the new legs: fix the test/code, don't pin
   exclusion — exclusions documented only for platform-impossible
   cases.
4. `pyproject.toml` classifiers updated once 3.13 is green (don't claim
   before evidence).
5. Keep job count sane: matrix legs run in parallel; total wall time
   should not grow materially.

## Ordered Implementation Steps

1. Edit `ci.yml` matrix; push; triage any failures (likely candidates:
   pathlib behaviors, hypothesis profiles, timing-sensitive tests).
2. Classifier + README support table update after green.
3. CHANGELOG Added (dev-facing).

## Required Tests / Validation Commands

```bash
gh run list --workflow ci.yml  # after push
uv run pytest -q  # local sanity on 3.13 env if available
```

## Acceptance Criteria

- New legs green on main; classifiers match tested versions; no
  exclusions without a documented platform-impossible reason.

## Rollback / Stop Conditions

- Stop if a runner leg is consistently capacity-starved (queueing >
  acceptable) — reduce to one ARM leg.

## Risks

- ARM runner availability/queue variance → single ARM leg keeps blast
  radius small.

## Out of Scope

- PyPy/microPython support; python 3.14 pre-releases; self-hosted
  runners.

## Implementation Notes (done)

- Matrix already covered py3.11–3.14 × {ubuntu,windows,macos} with
  matching classifiers — the py3.13 goal pre-existed.
- Added one `ubuntu-24.04-arm` leg at py3.14 via matrix `include:`
  (single leg bounds job count; catches arch-specific assumptions:
  mmap, locking, path semantics).
- Pin test `test_ci_matrix_covers_declared_python_and_arm`: full
  declared range in matrix + exactly one ARM leg at newest py
  (importorskip on optional PyYAML).
- Remaining manual step: green run evidence on main after push —
  no exclusions expected; any flaky leg gets fixed, not excluded.
