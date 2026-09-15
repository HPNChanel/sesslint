# T-08: Full regression and clean-tree release gate

- Status: planned
- Phase: 4
- Priority: P0 release
- Type: gate / release evidence
- Depends on: T-02, T-03, T-04, T-06, T-07, T-07a
- Primary targets:
  - The completed working tree, then the clean identified commit
  - `dist/` artifacts, `RELEASING.md`, `.github/workflows/release.yml` (validation only)
  - This task's Evidence To Record section

## Goal

Produce one reproducible release-candidate evidence set: first prove the completed working tree passes all gates, then land the hardening changes in a maintainer-approved commit, then rerun every release-critical check from that clean, identified commit SHA.

## Verified Problem / Current Evidence

Prior evidence was generated on dirty trees, so no release provenance exists. After T-00's baseline plus the corrective tasks, the tree again contains uncommitted changes; release evidence must be regenerated from a clean identified commit to be meaningful.

## Required Design / Decisions

Sequence is binding:

1. **Gates on the completed working tree** — run the full gate matrix on the post-hardening tree.
2. **Review** — maintainer reviews the hardening diff.
3. **Maintainer-approved commit** — land the changes (explicit paths; no `git add .`).
4. **Require clean tree and record SHA** — `git status --porcelain` must be empty; record `git rev-parse HEAD`. This SHA is the **candidate SHA**.
5. **Rerun release gates from that clean SHA** — all release-critical checks below execute against the identified commit, not the pre-commit tree.
6. **Reproducible-build epoch and tooling (must match T-07a):** `SOURCE_DATE_EPOCH` is the candidate commit's timestamp — `git show -s --format=%ct <candidate SHA>` — the same value the release workflow computes from the tagged SHA. Both isolated builds use identical pinned tooling (`build`, `hatchling`) at the vetted versions recorded in `RELEASING.md`.
7. **Evidence model (resolves the clean-tree recursion):** raw final-gate evidence — command outputs, logs, hashes, CI run IDs — is captured into immutable CI/workflow artifacts and logs keyed to the candidate SHA. Task-file/ledger evidence updates referencing that SHA may be committed afterward as a separate docs commit; they do not change the tested release target. T-09 binds the candidate SHA; T-09a tags exactly it from a clean isolated checkout.
8. **Multi-OS CI authorization:** observing `ci.yml` on the candidate SHA requires pushing the candidate branch — a remote side effect needing separate explicit maintainer authorization. If authorization is not granted, T-08 records the gap and is **blocked**; local runs are never substituted for observed CI.

## Ordered Implementation Steps

1. Confirm all dependency tasks are `done`; record their evidence pointers.
2. Run the gate matrix on the working tree; fix-forward or spawn T-08x blockers for failures.
3. Maintainer diff review; create the approved hardening commit.
4. Verify `git status --porcelain` empty; record `git rev-parse HEAD` and `git tag --points-at HEAD`.
5. From the clean SHA, rerun: static/type gates; full, focused, and acceptance tests; fresh-process reference performance; two isolated same-epoch builds (commit-derived `SOURCE_DATE_EPOCH`, pinned tooling) with byte-identical hash comparison; wheel AND sdist offline install smoke; artifact hashing; release-workflow validation.
6. With separate explicit maintainer authorization, push the candidate branch and confirm observed multi-OS `ci.yml` status on Python 3.11 and 3.12; without authorization, record the gap and block.
7. Record the complete evidence bundle into immutable CI/workflow artifacts and logs keyed to the candidate SHA.

## Test Matrix

| Gate | Command / check |
|---|---|
| Lint | `ruff check .` |
| Format | `ruff format --check .` |
| Types | `mypy --strict src/` |
| Full suite | `pytest -q` — record exact passed/skipped counts |
| Acceptance | `pytest -q tests/accept/test_offline.py tests/accept/test_kill.py` |
| Focused regressions | `pytest -q tests/adapters/test_detect.py tests/test_profiles.py tests/test_api_surface.py tests/test_bundle.py tests/test_verify.py tests/test_verify_challenger.py tests/test_e2e_cycle.py tests/test_manifest.py tests/test_report.py tests/cli/test_check.py tests/test_bench_smoke.py tests/test_ci_configs.py` |
| Reference performance | `python bench/perf_250k.py --records 250000 --time-budget 15.0 --mem-budget 512.0` — fresh-process normative metric per T-06 |
| Reproducible build | `python -m build --sdist --wheel` twice in isolated dirs with `SOURCE_DATE_EPOCH` = `git show -s --format=%ct <candidate SHA>` and identical pinned tooling; SHA-256 outputs must be byte-identical |
| Offline wheel smoke | Fresh venv, `pip install --no-index` of the wheel, no network; run `sesslint version --json` (assert structured version) and a smoke `sesslint check` |
| Offline sdist smoke | Fresh venv with either the pinned build backend preseeded + `pip install --no-index --no-build-isolation`, or a local wheelhouse supplying build requirements; then `sesslint version --json` and smoke `sesslint check` — `--no-index` alone cannot build an sdist offline |
| Artifact hashes | SHA-256 for wheel and sdist, recorded into `sha256sums.txt` (which lists distributions only — it does not hash itself); also hash the checksum file separately as evidence |
| Workflow validation | `tests/test_ci_configs.py` + `actionlint` (or equivalent) on `release.yml` |
| Multi-OS CI | Observed green `ci.yml` runs on the candidate SHA for Python 3.11 and 3.12 across the CI matrix OSes — requires the authorized branch push (design 8) |

## Validation Commands

```bash
git status --porcelain
git rev-parse HEAD
git tag --points-at HEAD
ruff check .
ruff format --check .
mypy --strict src/
pytest -q
pytest -q tests/accept/test_offline.py tests/accept/test_kill.py
python bench/perf_250k.py --records 250000 --time-budget 15.0 --mem-budget 512.0
python -m build --sdist --wheel
```

## Acceptance Criteria

- Identified clean candidate SHA; `git status --porcelain` empty at build time.
- Every gate in the matrix passes from that SHA; counts recorded exactly.
- Two isolated builds with the commit-derived `SOURCE_DATE_EPOCH` and pinned tooling are byte-identical.
- Wheel installs offline in a clean venv; sdist installs offline via preseeded pinned backend + `--no-build-isolation` or a local wheelhouse; both smoke-pass `sesslint version --json` and `sesslint check`.
- `sha256sums.txt` lists the wheel and sdist (no self-hash); workflow validation green; multi-OS 3.11/3.12 CI observed green via authorized branch push — or the gap is recorded and T-08 stays blocked.
- Raw evidence lives in immutable artifacts/logs keyed to the candidate SHA; later docs commits referencing it do not move the tested target.
- Documentation claims match measured evidence (per the T-01 ledger).
- If any gate fails: a scoped `T-08x-<slug>.md` blocker task is spawned, release is blocked, and no acceptance criterion is relaxed to absorb the failure.

## Evidence To Record

- Candidate SHA, `git status --porcelain` output, `git tag --points-at HEAD` output, Python version.
- Exact passed/skipped test counts per suite.
- Fresh-process 250k benchmark values and budgets.
- Both build SHA-256 sets proving byte identity; `SOURCE_DATE_EPOCH` (candidate-commit-derived) and pinned tooling versions.
- Offline smoke logs for wheel and sdist, including the sdist offline-build mechanism used.
- Workflow validation results and CI run links/IDs (or the recorded authorization gap).
- The immutable artifact/log locations keyed to the candidate SHA.

## Rollback / Stop Conditions

- Any gate failure → spawn T-08x and stop; T-09 may not start.
- If the clean-SHA rerun disagrees with the working-tree run, the discrepancy is a defect — investigate before proceeding.
- Never commit release artifacts, tags, or version bumps beyond the maintainer-approved hardening commit.

## Risks

- Environment differences between working-tree and clean-SHA runs (e.g., caches) can mask failures; the second run exists to catch this.
- Multi-OS CI observation requires an authorized branch push; without it T-08 blocks rather than substituting local runs.

## Out of Scope

- Creating the tag, the GitHub Release, or the PyPI upload (T-09a only).
- The go/no-go decision itself (T-09).
- Campaign transitions (T-07/T-09a/T-10 own those).
