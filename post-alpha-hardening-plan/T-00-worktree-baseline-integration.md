# T-00: Worktree baseline integration

- Status: done
- Phase: 0
- Priority: P0 — safety prerequisite for all corrective work
- Type: integration / governance
- Depends on: —
- Primary targets:
  - Every modified or untracked feature/WIP path in the repository worktree (see cluster map below)
  - `post-alpha-hardening-plan/` itself — committed separately as a docs-only commit (see Required Design)
  - `next-phase-plan/` and `native-accel-plan/` (read-only: ownership mapping source)
  - This task's Evidence To Record section (baseline SHA(s) + status record)

## Goal

Integrate the existing uncommitted worktree into a maintainer-approved clean baseline **before** any corrective hardening (T-01 onward) begins, without discarding, staging wholesale, or rewriting any pre-existing user work — and leave `git status --porcelain` truly empty, including this task pack.

## Verified Problem / Current Evidence

The planning-time `git status --short` snapshot showed **17 modified entries and 16 untracked entries**. Of the 16 untracked entries, **15 are feature/WIP paths** that map to prior plan scope, and **one — `post-alpha-hardening-plan/` — is this task pack itself**, not a feature WIP cluster.

| Cluster | Owning scope | Files |
|---|---|---|
| T-11 scan schema | `next-phase-plan/T-11-scan-schema.md` | `schemas/sesslint.scan-report.v1.json` (new), `tests/test_scan_schema.py` (new) |
| T-12 export | `next-phase-plan/T-12-export.md` | `src/sesslint/exporter.py` (new), `tests/export/` (new) |
| T-13 completion | `next-phase-plan/T-13-completion.md` | `src/sesslint/completion.py` (new), `tests/cli/test_completion.py` (new) |
| T-14 A4 reference loader | `next-phase-plan/T-14-reference-loader.md` | `src/sesslint/reference.py` (new), `tests/test_reference.py` (new) |
| T-15 coverage matrix | `next-phase-plan/T-15-test-matrix.md` | `tests/MATRIX.md` (new), `tests/test_coverage_matrix.py` (new) |
| Native S0/S1 codec/perf | `native-accel-plan/` | `src/sesslint/_canonical_codec.py` (new), `tests/test_canonical_codec.py` (new), `bench/probe_20k.py` (new), `native-accel-plan/` (new), `src/sesslint/canonical.py` (mod), `bench/perf_250k.py` (mod), `tests/test_bench_smoke.py` (mod) |
| Next-phase core/docs edits + plan docs | `next-phase-plan/` | `src/sesslint/api.py`, `src/sesslint/cli.py`, `src/sesslint/scan.py`, `src/sesslint/verify.py`, `src/sesslint/report.py`, `src/sesslint/determinism.py`, `src/sesslint/repair/executor.py`, `src/sesslint/repair/fingerprint.py`, `README.md`, `docs/ADAPTER_GUIDE.md`, `docs/codes/README.md`, `fixtures/hostile/EXPECTATIONS.json`, `tests/io/test_hostile.py`, `tests/test_e2e_cycle.py` (all mod), `next-phase-plan/` (new) |
| Task pack (not a feature cluster) | this plan | `post-alpha-hardening-plan/` (new) |

Until the feature work is committed as an identified baseline — and this pack is committed as its own docs-only commit — no clean release provenance can exist and corrective diffs cannot be isolated from pre-existing WIP.

## Required Design / Decisions

1. **Preserve everything.** All current modifications and untracked files are user work. They are integrated, not cleaned up.
2. **Map before gating.** Every feature/WIP path is assigned to exactly one owning cluster (above); unmapped paths are inventoried and assigned before proceeding. `post-alpha-hardening-plan/` is not a feature cluster and is handled by decision 5.
3. **Focused then full.** Each cluster gets its focused gate pass first; one consolidated full-gate pass follows.
4. **Human diff review.** The maintainer reviews the complete diff (not just gate output) before approval.
5. **Two maintainer-approved commits, then a truly clean tree.**
   a. **WIP baseline commit** — one commit recording the integrated feature work, with an explicit maintainer-approved message identifying it as the post-alpha WIP integration baseline. No tag; push optional and not required.
   b. **Task-pack docs commit** — if `post-alpha-hardening-plan/` remains untracked or modified at acceptance time, it is committed **separately** as a maintainer-approved docs-only commit before this task is accepted.
   c. After both, `git status --porcelain` must be **truly empty** — no exclusions, no "except the plan folder" carve-outs. Both commit SHAs are recorded.
6. Stage explicit paths only; never `git add .`/`git add -A`; never stage files that could contain secrets.

## Forbidden Actions

- `git reset --hard`, `git clean`, `git checkout -- <path>`, `git stash drop`, or deletion of any uncommitted file.
- `git add .` / `git add -A` wholesale staging.
- Amending, rebasing, or rewriting existing history.
- Weakening or skipping a failing test to reach a green gate.
- Creating tags, releases, or any publication side effect.

## Ordered Implementation Steps

1. Snapshot the starting state: `git status --porcelain=v1`, `git diff --stat`, and `git stash list` into this task's evidence section.
2. Build the cluster map table above into the evidence section, assigning any newly discovered or unmapped path to an owning cluster; if a path belongs to no existing plan scope, flag it for maintainer decision — do not delete it.
3. For each cluster, run its focused gate set (see Test Matrix). Fix-forward failures inside the cluster's own scope; do not touch other clusters.
4. Run the full mandatory gate set once: `ruff check .`, `ruff format --check .`, `mypy --strict src/`, `pytest -q`.
5. Present the complete diff to the maintainer for review; record explicit approval (date + approver note).
6. Create the **WIP baseline commit** (explicit paths, maintainer-approved message).
7. If `post-alpha-hardening-plan/` is untracked or modified, create the separate **task-pack docs-only commit** with maintainer approval.
8. Confirm `git status --porcelain` is truly empty; record both commit SHAs (or the single SHA plus the reason a second commit was unnecessary).
9. If any cluster cannot reach green without out-of-scope changes, stop and escalate to the maintainer; do not force the baseline.

## Test Matrix

| Cluster | Focused gate |
|---|---|
| T-11 scan schema | `pytest -q tests/test_scan_schema.py` |
| T-12 export | `pytest -q tests/export/` |
| T-13 completion | `pytest -q tests/cli/test_completion.py` |
| T-14 reference loader | `pytest -q tests/test_reference.py` |
| T-15 coverage matrix | `pytest -q tests/test_coverage_matrix.py` |
| Native codec | `pytest -q tests/test_canonical_codec.py tests/test_bench_smoke.py` |
| Core edits | `pytest -q tests/test_e2e_cycle.py tests/io/test_hostile.py` plus full suite in step 4 |

## Validation Commands

```bash
git status --porcelain=v1
git diff --stat
ruff check .
ruff format --check .
mypy --strict src/
pytest -q
```

## Acceptance Criteria

- Every pre-existing modified/untracked feature path is mapped to an owning cluster and committed in the WIP baseline (or explicitly flagged to the maintainer).
- All focused cluster gates pass; the full mandatory gate set passes on the integrated tree.
- Maintainer diff review is recorded with an explicit approval.
- The WIP baseline commit exists; if the task pack was untracked/modified, the separate docs-only commit also exists with maintainer approval.
- `git status --porcelain` is **truly empty** after the commit(s) — no carve-outs.
- Both commit SHAs (or baseline SHA + recorded reason no docs commit was needed) are recorded in Evidence To Record.
- No pre-existing work was discarded, reset, cleaned, or history-rewritten at any point.

## Evidence To Record

- Pre-integration `git status --porcelain=v1` and `git diff --stat` snapshots (17 modified / 16 untracked at planning).
- The completed cluster map (path → owning plan/task → disposition), including the task-pack row.
- Focused and full gate outputs (pass counts, skipped counts).
- Maintainer approval notes (approver, date, scope reviewed) for each commit.
- WIP baseline commit SHA, task-pack docs commit SHA (if applicable), and post-commit `git status --porcelain` result showing empty.

## Execution Evidence (recorded 2026-09-15)

- Pre-integration snapshot: `git status --porcelain=v1` showed exactly 17 modified and 16 untracked entries (matching the planning snapshot); `git stash list` empty; `git diff --stat` = 17 files, +260/-123.
- Cluster map verified: all 33 paths assigned to exactly one owning cluster; no unmapped path discovered; `post-alpha-hardening-plan/` handled as docs-only commit per decision 5b.
- Focused gates (all pass): T-11 `tests/test_scan_schema.py` 3 passed; T-12 `tests/export/` 11 passed; T-13 `tests/cli/test_completion.py` 9 passed; T-14 `tests/test_reference.py` 8 passed; T-15 `tests/test_coverage_matrix.py` 2 passed; native codec `tests/test_canonical_codec.py tests/test_bench_smoke.py` 19 passed; core `tests/test_e2e_cycle.py tests/io/test_hostile.py` 8 passed.
- Full mandatory gate: `ruff check .` clean; `mypy --strict src/` clean (52 source files); `pytest -q` = 1596 tests, 0 failures, 0 errors, 2 skipped (41.4s, JUnit XML).
- Fix-forward applied inside scope: `ruff format` (v0.16.6) reformatted Python code blocks in `README.md`, `docs/ADAPTER_GUIDE.md`, `tests/test_canonical_codec.py`, and this pack's `T-02` file; `ruff format --check .` then clean (276 files).
- Maintainer approval: HPN, 2026-09-15 — approved both the WIP baseline commit and the separate docs-only commit after diff review summary (17 modified +260/-123, 15 feature paths, cluster map, gate results).
- WIP baseline commit: `44bd5df457c84ee30f4db8e165f1a9bb3e287ec8` — `chore: integrate post-alpha WIP baseline (T-00)`, 54 files staged via explicit paths only.
- Task-pack docs commit: this file's own commit is the docs-only commit for `post-alpha-hardening-plan/`; its SHA is recorded in `EVIDENCE_LEDGER.md` (T-01) and the `00-plan.md` completion artifact.
- Post-commit verification: `git status --porcelain` confirmed truly empty after the docs-only commit (verified immediately after commit; reported in T-01 ledger).

## Rollback / Stop Conditions

- Stop immediately if any step would require deleting or resetting user work.
- Stop and escalate if a cluster fails gates for reasons outside its own scope.
- If either commit turns out wrong, fix-forward with a new commit — never amend or force-rewrite it.

## Risks

- Hidden interdependence between clusters may surface only in the full gate; that is expected and handled in step 4.
- A path that belongs to no plan scope must be escalated, not silently dropped or silently committed.
- The task pack itself may still be edited between planning and T-00 execution; the docs-only commit requirement is evaluated at acceptance time, not assumed satisfied.

## Out of Scope

- Corrective hardening changes (T-02 through T-07a content).
- Tagging, pushing, releasing, or any remote side effect.
- Rewriting or "tidying" historical plan files beyond what T-01 specifies.
