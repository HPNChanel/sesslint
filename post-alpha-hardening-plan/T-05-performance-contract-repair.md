# T-05: Performance contract and disclosure repair

- Status: planned
- Phase: 2
- Priority: P0 evidence integrity
- Type: code + documentation / benchmark contract
- Depends on: T-01
- Primary targets:
  - `bench/perf_250k.py` (`run_benchmark`, `verify_disclosure_recorded`, docstrings, current-run output)
  - `bench/PERF_NOTES.md`
  - `tests/test_bench_smoke.py`
  - Release-note / plan evidence referencing the benchmark

## Goal

Make the benchmark contract honest and evidence-aware by cleanly separating two different things: the **current run's own disclosure output** and the **dated reference baseline** recorded in `PERF_NOTES.md`. A budget breach is always non-zero regardless of disclosure.

## Verified Problem / Current Evidence

Latest recorded reference run: 250,000 records / ~99.45MB input; streaming parse 4.109s; check 11.321s; total 15.430s; peak RSS 785.52MB — against budgets of 15.0s and 512MB. `bench/PERF_NOTES.md` still carries older "PASS" / `~65–190MB` claims. `verify_disclosure_recorded(reasons)` (~line 112) only checks that two headings exist, so stale text satisfies the gate — and any design that requires static notes to match a just-finished run's fluctuating values is unsatisfiable. `run_benchmark`'s docstring (~line 121) claims a disclosed shortfall may return 0 while the implementation correctly returns 1 on any breach.

## Required Design / Decisions

1. **Disclosure never turns a breach into a pass.** Functional failure, time breach, and memory breach are each non-zero outcomes. Disclosure is mandatory context, not a waiver.
2. **Current-run disclosure = the benchmark's own output/log.** `run_benchmark` always prints the measured values, budgets, derived breach classes, and run context before returning non-zero. The run discloses itself; no static file is claimed to document it.
3. **`PERF_NOTES.md` = one dated latest reference baseline.** It records a selected reference run — run ID/date, host or `unknown/not captured`, record count/input size, measured time and peak RSS, budgets, derived breach classes, and a status consistent with those numbers. It is **not** proof that an arbitrary just-finished run was documented.
4. **Rename/redefine the validator** as a reference-disclosure validator (name may be `verify_reference_disclosure_recorded`). It validates that the **latest reference block** in `PERF_NOTES.md` is complete and internally consistent — run ID/date, host status, records/input size, measured values, budgets, breach classes derived from those values, matching status. It must **not** compare a future run's fluctuating values to static notes, and must not claim the notes describe that future run.
5. **Refresh protocol:** execute and capture a selected reference run (a breach/non-zero exit is expected and valid), update the `PERF_NOTES.md` reference block from that captured output, then run the static validator and tests.
6. Align `run_benchmark`/module docstrings and exit-semantics prose with actual behavior: breach → non-zero.
7. Ensure release notes and plan evidence quote the same dated reference baseline; clearly date older numbers so they cannot be read as the latest result.

## Ordered Implementation Steps

1. Make `run_benchmark` print complete current-run disclosure (values, budgets, breach classes, context) before returning non-zero.
2. Rewrite `verify_disclosure_recorded` → `verify_reference_disclosure_recorded` validating the latest reference block's completeness/consistency per decision 4.
3. Execute one reference run, capture output, and update `PERF_NOTES.md` to a `BREACH — DISCLOSED` dated reference block built from it; demote/date older numbers.
4. Align docstrings and exit-semantics prose.
5. Reconcile release-note and plan evidence to quote the same dated reference baseline.
6. Add the test cases below; run focused then full gates.

## Test Matrix

| Case | Expected |
|---|---|
| Reference block missing fields (no run ID/date, host, records/size, values, budgets) | Validation fails |
| Stale reference block (values disagreeing with recorded status) | Validation fails |
| Partial breach classes (e.g., memory breach recorded but only time disclosed) | Validation fails |
| Status-vs-values mismatch (status PASS while values breach) | Validation fails |
| Missing date/host | Validation fails; host may only be the honest `unknown/not captured` |
| Benchmark current-run output | Contains measured values, budgets, breach classes, and run context on a breaching run |
| Functional error | Non-zero; disclosure can never excuse it |
| Budget breach with complete current-run output + valid reference block | Still non-zero |

No test may require the static reference block's values to equal a fresh run's measured values.

## Validation Commands

```bash
pytest -q tests/test_bench_smoke.py
python bench/perf_250k.py --records 250000 --time-budget 15.0 --mem-budget 512.0
ruff check .
ruff format --check .
mypy --strict src/
pytest -q
```

The benchmark command may legitimately exit non-zero until T-06 closes the gap; that result must be recorded as a breach, never relabeled green.

## Acceptance Criteria

- Current-run disclosure is self-contained in the benchmark output; `PERF_NOTES.md` holds exactly one dated, internally consistent latest reference baseline.
- The reference validator rejects missing/stale/partial/inconsistent reference blocks.
- Benchmark, task log, `PERF_NOTES.md`, and release notes describe the same dated reference result and the same pass/fail semantics.
- Docstrings and exit semantics agree.
- Full gates green (validation tests; the reference benchmark itself may still breach and is recorded honestly).

## Evidence To Record

- The captured reference-run output used to build the `PERF_NOTES.md` block (run ID/date, host, values, budgets, breach classes).
- Before/after validator and docstring excerpts.
- Test names covering each matrix row.

## Rollback / Stop Conditions

- If making the contract honest requires changing the budgets, stop — budget changes belong to T-06's explicit maintainer decision path.
- Never restore heading-only checking or a static-vs-current value comparison.

## Risks

- Other docs may quote the stale numbers; the T-01 ledger is the cross-check that all were reconciled.
- The stricter reference validator may surface previously-green stale blocks elsewhere; those become ledger rows, not silent fixes.

## Out of Scope

- Lowering or revising budgets (T-06 decision path only).
- Shrinking the fixture or changing what the benchmark measures.
- Memory optimization itself (T-06).
- Native acceleration.
