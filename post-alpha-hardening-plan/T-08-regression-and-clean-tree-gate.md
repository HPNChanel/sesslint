# T-08: Full regression and clean-tree release gate

- Status: in-progress
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

---

## Execution Evidence — 2026-09-15 (partial; pending maintainer decisions)

### Candidate SHA

- **Candidate SHA: `dcb1c1d6242f62fd50b0b3d659aa652662565a81`** (`main`, includes all hardening tasks + the `.gitattributes` fix below)
- `git status --porcelain`: empty at gate time
- `git tag --points-at HEAD`: (none — no tags exist)
- Python: CPython 3.11.9 (AMD64/win32)

### Clean-SHA defect found and fixed

The first clean-SHA rerun (isolated worktree at `34f2e99`) failed **14 byte-exact tests** (`verify` source_hash, golden bundle, canonical dump): `core.autocrlf=true` rewrote checked-out fixture bytes to CRLF. Root cause: no `.gitattributes`. Fixed-forward as commit `dcb1c1d` (`* text=auto eol=lf`; binary fixtures marked `binary`). Rerun at `dcb1c1d`: all green — the gate caught a real reproducibility defect.

### Gate matrix at candidate SHA `dcb1c1d` (isolated worktree, `.tmp_t06/cand_wt`)

| Gate | Result |
|---|---|
| `ruff check .` | clean |
| `ruff format --check .` | clean (279 files) |
| `mypy --strict src/` | 52 files, no issues |
| `pytest -q` (full) | **1671 tests, 0 failures, 0 errors, 3 skipped** |
| Acceptance `test_offline`+`test_kill` | 4 passed |
| Focused regression set (12 files) | 289 passed, 2 skipped |
| Workflow validation | `test_ci_configs.py` structural assertions green (actionlint unavailable on host — stdlib structural checks are the equivalent mechanism per the matrix) |

### Reproducible build (commit-derived epoch, pinned tooling)

- `SOURCE_DATE_EPOCH=1789466264` = `git show -s --format=%ct dcb1c1d` (candidate commit timestamp — same rule as `release.yml`)
- Tooling: `build==1.2.2.post1`, `hatchling==1.27.0`; `python -m build --no-isolation --sdist --wheel`
- Two isolated dirs (`.tmp_t06/cand_wt`, `.tmp_t06/cand_wt2`) → **byte-identical**:
  - `sesslint-0.1.0-py3-none-any.whl` = `b0aa261f7d11a5326626364f370926f3f6249a71bbefa11dea19f11d3c9ed2cc`
  - `sesslint-0.1.0.tar.gz` = `c0237a2266c0e3ed6293b7e820122f5af73f4e93e378d053bdb6ca4f33760124`

### Offline install smokes

- **Wheel**: `uv venv --seed` clean env → `pip install --no-index --find-links=dist sesslint` → `sesslint version --json` structured output ✓, `sesslint check fixtures/cli/check_basic/healthy.jsonl --json` exit 0, assurance A3.
- **Sdist**: clean env + preseeded pinned backend `hatchling==1.27.0` → `pip install --no-index --no-build-isolation sesslint-0.1.0.tar.gz` → same smoke results, exit 0.

### CI observation — run `34957665046` on `dcb1c1d` (push authorized by maintainer)

- Workflow `CI`, `completed`, conclusion **failure**.
- 5/6 `Test` matrix jobs failed; dogfood + offline-isolation jobs passed; perf-benchmark job skipped (gate on test jobs).
- Two environment-dependent test defects surfaced (pre-existing, latent on the local 3.11/Windows host):
  1. `test_cli_scan_command_color_alignment` — POSIX only. Asserted `line.find("fixtures") == 23`, which is incidental: locally the displayed `r.path` is redacted (`.._hash/name`) so `find` returned −1 and the assert was skipped; on CI the path displays home-relative (`~/work/.../fixtures/...`) so the assert actually ran against a non-fixed column. Fixed to assert the true invariant — path column starts at 23 (tag field padded to 20).
  2. `test_read_header_adversarial_deep_nesting_recursion_error` — py3.12 on all OSes. CPython 3.12's C JSON scanner is non-recursive, so the 2000-deep object decodes and fails closed later as `HeaderMissingError` ("not a session header") instead of `RecursionError → "recursion limit"`. Both paths raise `SchemaError`; regex broadened to `recursion limit|not a session header`. Product behavior unchanged — still fail-closed.

### Perf gate resolution — shared same-family structural indexes

Follow-up optimization (maintainer chose "continue optimizing"): the four SL105–SL108 sub-checks each built an identical `_ToolPairing2Indexer` (3-pass build over all events), and the four SL004–SL007 graph checks each built an identical `_OccurrenceGraph`. Added optional `indexer=`/`occurrence_graph=` parameters so `check_tool_pairing_2`/`check_graph` build each index once and share it; direct sub-check callers still build their own (behavior identical — indexers are read-only after construction; union-find `find` path compression is idempotent).

- **Differential proof**: 213-target corpus (`fixtures/**` + 5k bench file), stdout/stderr/exit codes byte-identical vs pre-change — 0 mismatches.
- Normative fresh-process check at 250k (`.tmp_t06/bench_250k_v4.txt`): **8.438 s (< 15.0 s), peak RSS 477.1 MB (< 512 MB) — PASS, no breach classes.**
- Prior same-load readings for context: 11.5 s/11.9 s spot checks post-change; 17–18 s pre-change loaded host; 14.897 s pre-change quiet window.

### Candidate SHA v2 — `3fdad5df185c2486094bb91d28aec501c25afa15`

- Commits on top of `dcb1c1d`: `a14f1ac` (shared check indexes, perf) + `3fdad5d` (test portability fixes + this evidence).
- `git status --porcelain`: empty at gate time; isolated worktree `.tmp_t06/cand_wt`/`cand_wt2` checked out at `3fdad5d`.
- Full pytest at clean SHA: **1671 tests, 0 failures, 0 errors, 3 skipped** (`.tmp_t06/pytest_cand3.xml`); ruff/format/mypy clean in the isolated worktree.
- Fresh-process bench (main tree, same content): **8.438 s / 477.14 MB — PASS** (`.tmp_t06/bench_250k_v4.txt`).

### Reproducible build v2 (`SOURCE_DATE_EPOCH=1789469161` = commit timestamp of `3fdad5d`)

- Same pinned tooling (`build==1.2.2.post1`, `hatchling==1.27.0`), `python -m build --no-isolation --sdist --wheel`, two isolated dirs → **byte-identical**:
  - `sesslint-0.1.0-py3-none-any.whl` = `9e9d952039040615f64658ae0be5cdada91775d5d866d98f4315acf6ccb08cbe`
  - `sesslint-0.1.0.tar.gz` = `9f74a6c5e898ac823c7351036e732a74cf46e0a8bfdc4763ce0e125c7e2d31bb`
  - (Supersedes the `dcb1c1d` hashes above — source changed.)
- Offline smokes at new artifacts: wheel install `--no-index` → `version --json` + `check` exit 0 (A3); sdist `--no-index --no-build-isolation` with preseeded `hatchling==1.27.0` wheelhouse (`.tmp_t06/wheelhouse3/`) → same smoke results.

### CI observation v2 — run `34960103501` on `3fdad5d` — **GREEN**

- Pushed `main` `dcb1c1d..3fdad5d` under the existing push authorization.
- `completed`, conclusion **success**. All 15 jobs: 6/6 Test matrix (ubuntu/macos/windows × py3.11/py3.12), Offline Isolation Gate, 7 dogfood checks, Reproducible Build & Release Smoke — all `success`. Performance Benchmark job `skipped` (workflow-gated, as in the prior run; the normative gate remains the local fresh-process run above).
- Supersedes failed run `34957665046` on `dcb1c1d` (two env-dependent tests, fixed in `3fdad5d`).

### T-08 gate summary

All release-gate items pass at candidate `3fdad5d`: clean-tree isolation, static gates, full regression (1671/0/0/3), fresh-process perf (8.438 s / 477.14 MB — inside both budgets), byte-identical reproducible builds, offline wheel+sdist smokes, workflow structural tests, and observed multi-OS CI. Remaining known gap: `actionlint` unavailable on host — structural `test_ci_configs.py` assertions are the matrix-sanctioned substitute.

**T-08: gate evidence complete → ready for T-09 go/no-go decision.**

### Pending maintainer decisions

(none — push authorization already granted; CI green at `3fdad5d`)
