# SessLint Post-Alpha Hardening Plan (00)

- Status: active governing plan
- Language: English
- Release target: `v0.1.0`
- Release channels: GitHub Release and PyPI
- Authority: this file is the single binding execution authority for post-alpha hardening. Historical `next-phase-plan/` and `native-accel-plan/` files remain evidence of what was believed or executed at the time; they are not rewritten.

## Goal

Turn the current feature-complete alpha tree into a truthfully evidenced, reproducible, release-ready tree by (a) safely integrating the existing uncommitted worktree as an explicit baseline, (b) closing verified correctness, audit-metadata, performance-contract, and campaign-governance gaps, and (c) gating a `v0.1.0` public-alpha release to GitHub and PyPI before any demand-campaign closeout.

## Verified Facts

Established by direct source/task inspection and release-endpoint checks during planning (2026-09-15):

1. `next-phase-plan/` is functionally closed and `native-accel-plan/` completed S0/S1 with S2 deferred, but the working tree still contains substantial **uncommitted** user work. The current WIP clusters are:
   - T-11 scan schema: `schemas/sesslint.scan-report.v1.json`, `tests/test_scan_schema.py`.
   - T-12 export: `src/sesslint/exporter.py`, `tests/export/`.
   - T-13 shell completion: `src/sesslint/completion.py`, `tests/cli/test_completion.py`.
   - T-14 A4 reference loader: `src/sesslint/reference.py`, `tests/test_reference.py`.
   - T-15 coverage matrix: `tests/MATRIX.md`, `tests/test_coverage_matrix.py`.
   - Native S0/S1 codec/perf: `src/sesslint/_canonical_codec.py`, `tests/test_canonical_codec.py`, `bench/probe_20k.py`, plus edits to `src/sesslint/canonical.py`, `bench/perf_250k.py`, `tests/test_bench_smoke.py`.
   - Cross-cutting edits to `src/sesslint/api.py`, `src/sesslint/cli.py`, `src/sesslint/scan.py`, `src/sesslint/verify.py`, `src/sesslint/report.py`, `src/sesslint/determinism.py`, `src/sesslint/repair/executor.py`, `src/sesslint/repair/fingerprint.py`, `README.md`, `docs/ADAPTER_GUIDE.md`, `docs/codes/README.md`, `fixtures/hostile/EXPECTATIONS.json`, `tests/io/test_hostile.py`, `tests/test_e2e_cycle.py`.
   None of this may be discarded; it is user work.
2. Verified release baseline: there are **no local or remote Git tags**, `gh release list` returns **no GitHub Releases**, and the PyPI JSON endpoint for `sesslint` returned **404** during planning. No `v0.1.0` (or any other) release has ever been published, so the demand campaign is `not-started`, not active.
3. Detection threshold overrides are resolved by `resolve_effective_config()`, but `detect_format()` and `resolve_format()` still arbitrate with the module constants `CONFIDENCE_MIN = 0.55` and `MARGIN_MIN = 0.15`. CLI/profile threshold overrides are validated and serialized but are not demonstrably applied to auto-detection.
4. `verify.py` reconstructs a missing plan using `manifest_dict.get("profile", "neutral")` (two sites), while the v1 manifest model has no root `profile` field and already requires `revalidation.profile_id` and `revalidation.profile_version`. Non-neutral no-plan verification therefore needs an explicit binding fix.
5. `check --json` builds reproduction metadata with `detection_confidence=1.0` even for auto detection, does not bind adapter/profile versions from `report.coverage`, and lacks the non-identifying architecture required by FR-088.
6. The latest recorded 250k benchmark is approximately `15.430s` total and `785.52MB` peak RSS against `15.0s` / `512MB` budgets, while `bench/PERF_NOTES.md` still contains older "PASS" / `~65–190MB` claims. `verify_disclosure_recorded()` checks headings only, not whether the current breach is actually disclosed. This 15.430s/785.52MB figure is not yet a trustworthy measurement of only the CLI check path; it may include fixture-generation and streaming-sample contamination.
7. `bench/perf_250k.py` prose says "PASS or successfully disclosed shortfall" may return 0, while the implementation correctly returns non-zero on any budget breach.
8. Plan evidence has drifted: incorrect rule-family labels in `next-phase-plan/T-03-ac-triage.md`; "8 manifest checks" in `next-phase-plan/T-08-dogfood.md` vs. the verifier's actual 7 checks; premature `done` statuses on `next-phase-plan/T-09-demand-campaign.md` and `T-10-kill-pivot-review.md`; internal fixtures/dogfood counted as external demand; stale test counts; README wording implying a previous `0.1.0` release; absent release provenance (no clean-SHA release evidence exists).
9. The default runtime constraints remain binding: Python 3.11+, zero runtime dependencies, offline operation, no telemetry, deterministic output, content-free diagnostics, source immutability, and no in-place repair.

## User-Approved Decisions

- Complete this existing `post-alpha-hardening-plan/` folder; do not create a competing roadmap.
- Documentation language: English.
- Ordering: hardening first, then release.
- Release version: `v0.1.0` (first-ever release; PyPI name `sesslint` was unclaimed at planning time but must be rechecked immediately before publication because a pending Trusted Publisher does not reserve the name).
- Release channels: **both** a public GitHub Release and PyPI.
- Git tagging, pushing, GitHub Release publication, and PyPI publication are real external side effects and require a fresh, explicit maintainer authorization at execution time (T-09a); nothing in this plan performs them implicitly.

## Success Criteria

This plan is complete only when all of the following hold:

- All current WIP is mapped to its owning plan scope, passes focused and full gates, survives maintainer diff review, and is committed as a maintainer-approved WIP baseline — with this task pack committed separately as a docs-only commit if still untracked/modified — leaving `git status --porcelain` truly empty before corrective hardening begins.
- Detection threshold overrides materially affect arbitration and are proven by behavior tests.
- No-plan verification preserves the exact profile identity and version used to create the repair artifact, including non-neutral profiles.
- Reproduction metadata never invents confidence/version/identity values and carries the FR-088 architecture field.
- Performance documentation matches the latest reference measurement exactly; a budget breach remains a failing gate even when disclosed.
- The 250k memory question has a fresh-process, phase-level measurement and either peak RSS is within the stated budget on the reference host, or the maintainer explicitly revises the budget/spec with rationale and corresponding docs/tests.
- Historical plan/task evidence is reconciled append-only; no known false-green claim remains.
- Demand metrics distinguish internal validation from genuine external evidence; the campaign state is `not-started` until both release channels are verified published.
- Release-channel preparation (tag-gated workflow, Trusted Publisher, `RELEASING.md`, CI-config tests, metadata audit) is complete before the final clean-tree gate.
- Release-candidate evidence is generated from a clean, identified Git commit.
- A dated `GO-READY-TO-PUBLISH` or `NO-GO-BLOCKED` decision is recorded; on GO plus fresh maintainer approval, `v0.1.0` is published to GitHub Release and PyPI with identical verified artifact hashes.
- The final campaign closeout decision occurs only after its declared bound actually closes and uses only admissible external evidence.

## Constraints and Non-Goals

- No history rewrite; evidence correction is append-only/superseding.
- No weakening tests merely to make a gate pass; acceptance criteria are never relaxed to absorb a failure.
- No benchmark fixture shrinking, skipped rule families, or silent redefinition of RSS/time budgets.
- No new runtime dependency unless a separate explicit plan changes the zero-dependency guarantee.
- No semantic "success" inference in reports/manifests.
- No release artifact built from an unidentified or dirty source tree.
- No publication side effect (tag, push, GitHub Release, PyPI upload) without the explicit maintainer authorization recorded in T-09a.
- Backward compatibility for existing `sesslint.repair-manifest/v1` artifacts is preserved; no duplicate root profile ID and no legacy fallback for manifests lacking `revalidation` metadata.
- Native acceleration remains deferred; this plan addresses correctness and memory/evidence before revisiting native code.
- No fabrication of external demand evidence; internal fixtures and dogfood are never counted as external.

## Binding Task Table and Order

| Order | Task file | Phase | Function | Depends on |
|---:|---|---|---|---|
| 1 | `T-00-worktree-baseline-integration.md` | 0 | Preserve, map, gate, review, and commit the current WIP as the approved baseline | — |
| 2 | `T-01-evidence-ledger-reconciliation.md` | 1 | Reconcile plan/task evidence append-only; create `EVIDENCE_LEDGER.md` | T-00 |
| 3 | `T-02-detection-threshold-plumbing.md` | 2 | Make effective thresholds control detection everywhere | T-01 |
| 4 | `T-03-manifest-profile-binding.md` | 2 | Bind profile identity/version for no-plan verify, audit, idempotence | T-01 |
| 5 | `T-04-repro-metadata-fidelity.md` | 2 | Measured repro metadata incl. FR-088 architecture | T-01 |
| 6 | `T-05-performance-contract-repair.md` | 2 | Repair benchmark exit/disclosure contract and notes | T-01 |
| 7 | `T-07-demand-campaign-state-machine.md` | 2 | Truthful pre-release campaign state and `CAMPAIGN_LEDGER.md` | T-01 |
| 8 | `T-06-memory-budget-investigation.md` | 3 | Fresh-process FR-095 measurement and gated optimization | T-05 |
| 9 | `T-07a-release-channel-preparation.md` | 3 | Tag-gated release workflow, Trusted Publisher, `RELEASING.md` | T-07 |
| 10 | `T-08-regression-and-clean-tree-gate.md` | 4 | Commit hardening, then rerun all release gates from the clean SHA | T-02, T-03, T-04, T-06, T-07, T-07a |
| 11 | `T-09-public-alpha-release-gate.md` | 5 | Dated `GO-READY-TO-PUBLISH` / `NO-GO-BLOCKED` decision | T-08 |
| 12 | `T-09a-public-alpha-publication.md` | 6 | Authorized `v0.1.0` publication to GitHub + PyPI; campaign activation | T-09 (GO-READY-TO-PUBLISH only) |
| 13 | `T-10-campaign-closeout-kill-pivot.md` | 7 | Final bounded demand decision | T-09a + later of six elapsed weeks or 30 targeted outreach attempts |

Binding dependency DAG:

```text
T-00 -> T-01
T-01 -> {T-02, T-03, T-04, T-05, T-07}
T-05 -> T-06
T-07 -> T-07a
{T-02, T-03, T-04, T-06, T-07, T-07a} -> T-08
T-08 -> T-09
T-09 (GO-READY-TO-PUBLISH only) -> T-09a
T-09a + later of six elapsed weeks or 30 targeted outreach attempts -> T-10
```

## Parallel-Safe Groups

- After T-01 completes: `{T-02, T-03, T-04, T-05, T-07}` may proceed in parallel (disjoint primary targets).
- T-06 may start as soon as T-05 completes; T-07a may start as soon as T-07 completes. T-06 and T-07a are parallel-safe with each other and with any still-running Phase-2 task.
- T-08 serializes: it requires all of T-02, T-03, T-04, T-06, T-07, and T-07a done.
- T-09, T-09a, and T-10 are strictly sequential; T-09a additionally requires a fresh maintainer authorization, and T-10 additionally requires the campaign bound to close.

## Mandatory Gates

Unless a task explicitly adds more commands, every code-changing task must run:

```bash
ruff check .
ruff format --check .
mypy --strict src/
pytest -q
```

Release-candidate gates (T-08, rerun from the clean identified commit) additionally require:

```bash
pytest -q tests/accept/test_offline.py tests/accept/test_kill.py
python bench/perf_250k.py --records 250000 --time-budget 15.0 --mem-budget 512.0
python -m build --sdist --wheel   # twice, isolated, SOURCE_DATE_EPOCH = candidate-commit timestamp, byte-identical
```

plus wheel **and** sdist offline install smoke, SHA-256 artifact hashes, release-workflow validation, and observed multi-OS CI status on Python 3.11 and 3.12.

A performance budget breach is a **failed performance gate** even when disclosure is correct. Disclosure makes the failure honest; it never converts failure into success.

## State Model

Two distinct state vocabularies are used; they must not be conflated.

**Task states** (the `Status:` field of each task file):

- `planned`: not started.
- `in-progress`: implementation/evidence collection underway.
- `blocked`: cannot continue until a named prerequisite is resolved.
- `done`: all acceptance criteria and mandatory gates for the task have passed.
- `deferred-with-evidence`: intentionally not executed because a documented gateway was not met.

No task may use `done` to mean "tracking started", "baseline prepared", "outreach scheduled", or "interim recommendation written".

**Campaign states** (recorded in `CAMPAIGN_LEDGER.md` and demand-facing docs; never a task `Status`):

- `not-started`: no verified public release exists; the campaign clock has not begun. **Current state.**
- `active-campaign`: external evidence collection underway; set only after T-09a verifies both release channels.
- `bound-complete`: the bound (later of six elapsed weeks or 30 targeted outreach attempts) has closed; ready for T-10.
- `closed-proceed`, `closed-narrow`, `closed-pivot`, `closed-stop`: terminal T-10 outcomes.

A task is never `active-campaign`, and the campaign is never `done`.

## Evidence Artifacts

| Artifact | Path | Produced by | Exists now? |
|---|---|---|---|
| Evidence ledger | `post-alpha-hardening-plan/EVIDENCE_LEDGER.md` | T-01 | No — execution deliverable |
| Campaign ledger | `post-alpha-hardening-plan/CAMPAIGN_LEDGER.md` | T-07 | No — execution deliverable |
| Release workflow | `.github/workflows/release.yml` | T-07a | No — execution deliverable |
| Release runbook | `RELEASING.md` (repo root) | T-07a | Exists — extended |
| CI config tests | `tests/test_ci_configs.py` | T-07a | Exists — extended |
| Baseline record | T-00 evidence section | T-00 | No — SHA + status recorded at execution |
| Release-candidate bundle | T-08 evidence section + completion table below | T-08 | No — execution deliverable |
| Decision memo | T-09 evidence section | T-09 | No — execution deliverable |
| Publication record | T-09a evidence section | T-09a | No — execution deliverable |
| Closeout memo | T-10 evidence section | T-10 | No — execution deliverable |

Paths listed as deliverables do not exist yet and must not be cited as existing facts.

## Release and Campaign Transition Model

1. T-08 produces the release-candidate evidence set from a clean, identified **candidate commit SHA**; raw gate evidence lives in immutable CI/workflow artifacts keyed to that SHA, and later evidence-doc commits do not move the tested target.
2. T-09 evaluates that evidence and records exactly one of `GO-READY-TO-PUBLISH` or `NO-GO-BLOCKED`. A GO decision alone **neither publishes nor starts the campaign**.
3. T-09a, only after a GO and a fresh explicit maintainer approval, creates/pushes tag `v0.1.0` pointing at the exact candidate SHA and runs the tag-gated workflow from a clean isolated checkout — never from uncommitted or later docs state.
4. The release workflow is a fixed four-job DAG: `build` (one immutable artifact set, `SOURCE_DATE_EPOCH` = tagged commit timestamp, SHA-256 manifest) → `github-draft` (staged draft release + assets) → `pypi-publish` (protected `pypi` environment, Trusted Publisher/OIDC, distributions only) → `github-promote` (promotes the existing draft only after PyPI success).
5. The campaign transitions `not-started` → `active-campaign` **only after both channels are verified published** with identical artifact hashes; the six-week/30-outreach bound starts from the verified publication date.
6. T-10 executes at the later of six elapsed weeks or 30 targeted outreach attempts and records exactly one of `PROCEED`, `NARROW`, `PIVOT-UPSTREAM`, `STOP`.

GitHub and PyPI cannot be published atomically: the workflow stages the GitHub Release as a draft and retains one immutable artifact set so a failed channel is retried with identical bytes; an already-published `v0.1.0` is never rebuilt or re-uploaded.

## Rollback and Stop Rules

- Every code task remains independently revertible. If a corrective change creates behavior drift outside its declared contract, revert that task rather than weakening the existing invariant suite.
- Any T-08 gate failure spawns a scoped `T-08x-<slug>.md` blocker task and blocks T-09; acceptance criteria are never relaxed to absorb a failure.
- T-09a stops on missing authentication, Trusted Publisher/environment misconfiguration, package-name or version collision, artifact-hash mismatch, absent explicit maintainer approval, or a release workflow not tied to the clean T-08 commit.
- T-00 forbids `git reset --hard`, `git clean`, `git checkout --`, `git stash drop`, or any deletion of uncommitted work.
- Demand tasks cannot be closed early: no engineering test, synthetic fixture, scheduled outreach, or internal dogfood substitutes for elapsed external evidence.

## Risks

- The working tree contains substantial user work; destructive cleanup would be unrecoverable. T-00 exists to eliminate this risk before hardening.
- Historical logs contain false-green claims; T-01 keeps corrections append-only so provenance is preserved.
- The 15.430s/785.52MB result may be measurement contamination rather than live check memory; T-06 requires fresh-process evidence before optimizing or revising budgets.
- A pending PyPI Trusted Publisher does not reserve the `sesslint` name; availability is rechecked immediately before the authorized release.
- Two-channel release is non-atomic; the retained immutable artifact set and draft-first GitHub Release bound the blast radius of a partial failure.
- Demand tasks span real calendar time; the closeout cannot be accelerated by engineering work.

## Completion Artifact

At completion, append a final evidence table to this file containing:

- Git commit SHA used for final gates, the T-00 baseline SHA, and the task-pack docs commit SHA (if a separate docs commit was needed).
- `git status --porcelain` result (must be empty for the release build).
- Exact test counts and skipped count.
- Exact 250k benchmark values from the fresh-process reference run.
- Artifact SHA-256 values and the fixed `SOURCE_DATE_EPOCH`.
- T-09 decision, T-09a publication identifiers (tag, GitHub Release URL, PyPI URL, workflow run ID), campaign state, and later the T-10 closeout decision.
