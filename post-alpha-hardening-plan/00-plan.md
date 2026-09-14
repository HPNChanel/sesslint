# SessLint Post-Alpha Hardening Plan

## Goal

Turn the current feature-complete alpha tree into a truthfully evidenced, reproducible, release-ready tree by closing the remaining correctness, audit-metadata, performance-contract, and campaign-governance gaps.

This plan is the next operational authority after `next-phase-plan/` and `native-accel-plan/`. It does **not** rewrite historical task notes. Historical files remain evidence of what was believed/executed at the time; this plan owns reconciliation and corrective work discovered afterward.

## Current Verified Facts

The following facts were established by direct source/task inspection on 2026-09-14:

1. `next-phase-plan/` is functionally closed, and `native-accel-plan/` completed S0/S1 with S2 deferred.
2. The working tree is not release-clean: a substantial set of source, test, docs, schema, benchmark, and plan files are modified or untracked.
3. Detection threshold overrides are resolved by `resolve_effective_config()`, but `resolve_format()` / `detect_format()` still arbitrate with module constants (`0.55` / `0.15`). Therefore CLI/library threshold overrides are validated but are not demonstrably applied to auto-detection.
4. `verify.py` reconstructs a missing plan using `manifest_dict.get("profile", "neutral")`, while the manifest model does not expose a root `profile` field. The manifest already carries `revalidation.profile_id`; non-neutral no-plan verification therefore needs an explicit binding fix and regression coverage.
5. CLI JSON check output builds repro metadata with `detection_confidence=1.0` even for auto detection, and does not bind adapter/profile versions from report coverage.
6. The latest recorded 250k benchmark is approximately `15.430s` total and `785.52MB` peak RSS against `15.0s / 512MB` budgets, while `bench/PERF_NOTES.md` still contains older “PASS” / `~65-190MB` claims. The current disclosure presence checker only checks for headings, not whether the current breach is actually disclosed.
7. `bench/perf_250k.py` documents “PASS or successfully disclosed shortfall” in its function docstring, but the implementation correctly returns non-zero on any budget breach. The contract text must be aligned with behavior.
8. Plan evidence has drift:
   - T-03 labels graph/tool/checkpoint code families incorrectly in criterion summaries.
   - T-08 says “all 8 manifest checks” while the verifier currently exposes 7 checks.
   - T-09 is marked done while several demand metrics are explicitly still in progress.
   - T-10 is marked done although it is an interim memo and its 6-week / outreach bound has not elapsed.
   - Internal/synthetic fixture evidence must not be counted as external contribution/adoption evidence.
9. The default runtime constraints remain binding: Python 3.11+, zero runtime dependencies, offline operation, no telemetry, deterministic output, content-free diagnostics, source immutability, and no in-place repair.

## Success Criteria

This plan is complete only when all of the following hold:

- Detection threshold overrides materially affect arbitration and are proven by behavior tests.
- No-plan verification preserves the exact profile identity used to create the repair artifact, including non-neutral profiles.
- Reproduction metadata never invents confidence/version values.
- Performance documentation matches the latest benchmark exactly; a budget breach remains a failing gate even when disclosed.
- The 250k memory spike has a measured phase-level explanation and either:
  - peak RSS is reduced to the stated budget on the reference host, or
  - the maintainer explicitly revises the budget/spec with rationale and corresponding docs/tests.
- Historical plan/task evidence is reconciled without rewriting execution history.
- Demand metrics distinguish internal validation from genuine external evidence.
- Release candidate evidence is generated from a clean, identified Git tree.
- The final kill/pivot decision occurs only after its declared bound actually closes.

## Constraints

- No history rewrite.
- No weakening tests merely to make a gate pass.
- No benchmark fixture shrinking to satisfy budgets.
- No new runtime dependency unless a separate explicit plan changes the zero-dependency guarantee.
- No semantic “success” inference in reports/manifests.
- No release artifact built from an unidentified or dirty source tree.
- Backward compatibility for existing `sesslint.repair-manifest/v1` artifacts must be preserved unless a schema-version migration is explicitly approved.
- Native acceleration remains deferred; this plan addresses correctness and memory/evidence before revisiting native code.

## Phases and Binding Order

| Order | Task | Phase | Function | Depends on |
|---:|---|---|---|---|
| 1 | `T-01-evidence-ledger-reconciliation.md` | 0 | Reconcile task/plan evidence and statuses | — |
| 2 | `T-02-detection-threshold-plumbing.md` | 1 | Make effective thresholds control detection | T-01 |
| 3 | `T-03-manifest-profile-binding.md` | 1 | Fix non-neutral no-plan verify reconstruction | T-01 |
| 4 | `T-04-repro-metadata-fidelity.md` | 1 | Remove invented repro metadata | T-01 |
| 5 | `T-05-performance-contract-repair.md` | 2 | Repair benchmark/disclosure contract | T-01 |
| 6 | `T-06-memory-budget-investigation.md` | 2 | Explain/reduce 250k RSS breach | T-05 |
| 7 | `T-07-demand-campaign-state-machine.md` | 3 | Make demand evidence/status truthful | T-01 |
| 8 | `T-08-regression-and-clean-tree-gate.md` | 3 | Full functional/release gates on identified tree | T-02–T-07 |
| 9 | `T-09-public-alpha-release-gate.md` | 4 | Go/no-go public-alpha release | T-08 |
| 10 | `T-10-campaign-closeout-kill-pivot.md` | 5 | Final bounded demand decision | T-09 + bound elapsed |

Parallel-safe after T-01: `{T-02, T-03, T-04, T-05, T-07}`.  
T-06 depends on T-05.  
T-08 serializes after all corrective work.

## Mandatory Gate Set

Unless a task explicitly adds more commands, code-changing tasks must run:

```bash
ruff check .
ruff format --check .
mypy --strict src/
pytest -q
```

Release-candidate gates additionally require:

```bash
pytest -q tests/accept/test_offline.py tests/accept/test_kill.py
python bench/perf_250k.py --records 250000 --time-budget 15.0 --mem-budget 512.0
python -m build --sdist --wheel
```

A performance budget breach is a **failed performance gate** even when disclosure is correct. Disclosure makes the failure honest; it does not convert failure into success.

## State Model

Task status vocabulary for this plan:

- `planned`: not started.
- `in-progress`: implementation/evidence collection underway.
- `blocked`: cannot continue until a named prerequisite is resolved.
- `done`: all acceptance criteria and mandatory gates for the task have passed.
- `deferred-with-evidence`: intentionally not executed because a documented gateway was not met.
- `active-campaign`: long-running external evidence collection; explicitly not done.

No task may use `done` to mean “tracking started”, “baseline prepared”, “outreach scheduled”, or “interim recommendation written”.

## Rollback Rule

Every code task must remain independently revertible. If a corrective change creates behavior drift outside its declared contract, revert that task rather than weakening the existing invariant suite.

## Completion Artifact

At completion, append a final evidence table to this file containing:

- Git commit SHA used for final gates.
- `git status --porcelain` result (must be empty for release build).
- exact test counts and skipped count.
- exact 250k benchmark values.
- artifact SHA-256 values.
- public-alpha decision and, later, campaign closeout decision.
