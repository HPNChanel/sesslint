# T-06: 250k memory-budget investigation and recovery

- Status: planned
- Phase: 3
- Priority: P1 performance
- Type: investigation / gated optimization
- Depends on: T-05
- Primary targets:
  - `bench/perf_250k.py` (measurement structure)
  - `bench/probe_20k.py` or a new focused memory probe
  - Check/adapter/rule-engine surfaces identified by profiling
  - Focused performance/differential tests

## Goal

Produce a trustworthy fresh-process measurement of the real `sesslint check` path's time and peak RSS at 250k records; explain the ~785.52MB observation; and, if the clean measurement still breaches, reduce peak RSS below the 512MB budget using only behavior-preserving changes.

## Verified Problem / Current Evidence

The recorded 15.430s total / 785.52MB peak RSS figure comes from `bench/perf_250k.py`, whose process lifetime includes fixture generation and auxiliary `iter_events` streaming passes (~lines 144, 155) in addition to the check itself. That number is therefore **not yet a trustworthy measurement of only the CLI check path** — it may reflect allocator high-water contamination from the generator and streaming sample rather than live check memory.

## Required Design / Decisions

1. **Normative FR-095 metric** = wall time and peak RSS of the real `sesslint check` path executed in a **fresh child process** (spawn the CLI on the pre-generated fixture; measure the child's RSS, e.g., via `resource`/`psutil`-free OS facilities or a subprocess peak-RSS probe consistent with existing bench tooling).
2. **Fixture generation and auxiliary `iter_events` throughput are separate metrics** — reported alongside, never summed into or contaminating the normative check time/RSS.
3. **Profile before optimizing.** No optimization work begins until phase-level measurements identify the dominant consumer.
4. **Contamination outcome:** if the clean child-process check is within budget, close this task as *measurement contamination* and fix the harness/reporting — not the product.
5. **If genuinely over budget:** only behavior-preserving changes are permitted — remove duplicate in-memory copies, consolidate structural indexes, free phase-local structures earlier, use compact immutable coordinates where output is unchanged. Every change requires **differential output tests** (byte-identical reports/manifests before vs. after on representative fixtures).
6. **Explicitly not permitted:** native extension work, fixture shrinking, skipping rules/checks, or silent budget revision. Budget changes require the explicit maintainer decision below.

## Ordered Implementation Steps

1. Modify/extend the benchmark so the check phase runs in a fresh child process; report check time + child peak RSS as the normative result, and generation/streaming as separate auxiliary metrics.
2. Capture phase-level measurements: baseline RSS; post-generation; post-streaming-sample; post-`iter_events`; pre/post adapter load; per check family where feasible; post-report. Capture `tracemalloc` around the **full check path**, not only the streaming sample.
3. Answer the investigation questions in Evidence To Record.
4. Decision point:
   - In budget → close as measurement contamination; update `PERF_NOTES.md`/contract wording accordingly.
   - Over budget → profile adapter materialization and rule-family indexes; implement only behavior-preserving reductions; prove each with differential output tests; re-measure.
5. If still over budget after justified optimization, stop and escalate: the maintainer explicitly chooses (A) continue optimization, or (B) revise the published budget/spec with rationale and update every dependent AC/release statement. Disclosure alone does not make this task `done`.

## Test Matrix

| Case | Expected |
|---|---|
| Fresh-process check at 250k | Normative time/RSS reported for the child only |
| Auxiliary metrics | Generation and `iter_events` throughput reported separately; never summed into check time |
| Differential output | For each optimization: byte-identical report/manifest output on representative fixtures |
| Behavior preservation | No rule family skipped; no output field dropped; determinism tests green |
| Functional correctness | Full suite passes after each optimization |

## Validation Commands

```bash
python bench/probe_20k.py
python bench/perf_250k.py --records 250000 --time-budget 15.0 --mem-budget 512.0
ruff check .
ruff format --check .
mypy --strict src/
pytest -q
```

## Acceptance Criteria

- Normative FR-095 numbers come from a fresh-process check of the real CLI path; auxiliary metrics are separated.
- Phase-level measurement table exists and identifies the dominant memory consumer.
- Either: clean child-process result ≤15.0s and <512MB on the reference host (closed as contamination, harness fixed); or measured-below-budget result after behavior-preserving optimization proven by differential tests; or the task remains `blocked` pending the explicit maintainer budget decision — it is never closed by disclosure.

## Evidence To Record

- Fresh-process measurement table (per-phase RSS + wall time; child peak RSS).
- Investigation answers: canonical event retention? duplicate adapter representations? overlapping graph/tool/checkpoint maps? retained payload dicts? A4/reference scale-gating confirmed? allocator high-water vs. live memory? generator/profiler contamination?
- Per-optimization diffs with differential-test evidence.
- The maintainer's explicit decision if option (B) is taken.

## Rollback / Stop Conditions

- Stop optimization at the first differential-test failure; revert that change.
- Stop and escalate before any budget/spec revision — that decision is the maintainer's, recorded in this task's evidence.
- Revert the task if a measurement change makes the benchmark incomparable to the documented reference contract.

## Risks

- Fresh-process measurement may itself vary across hosts; record host details or `unknown/not captured` honestly.
- Per-family RSS attribution may be infeasible at fine granularity; coarse phases are acceptable if they identify the dominant phase.

## Out of Scope

- Native extension work.
- Changing functional results for performance; dropping payload needed for output identity.
- Fixture shrinking, skipped checks/rule families, lower record counts, silent RSS redefinition.
- Provider/network replay.
