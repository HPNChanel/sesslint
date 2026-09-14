# T-05: Performance contract and disclosure repair

- Status: planned
- Phase: 2
- Priority: P0 evidence integrity
- Depends on: T-01
- Primary targets:
  - `bench/perf_250k.py`
  - `bench/PERF_NOTES.md`
  - `tests/test_bench_smoke.py`
  - release-note evidence

## Problem

The latest task log records approximately:

- 250,000 records / ~99.45MB
- streaming parse: 4.109s
- check: 11.321s
- total: 15.430s
- peak RSS: 785.52MB

against budgets of 15.0s and 512MB.

However `bench/PERF_NOTES.md` still contains older “PASS”, `~65–190MB`, and bounded-memory claims. `verify_disclosure_recorded()` merely checks for two headings, so stale text satisfies the disclosure-presence gate.

There is also a contract mismatch: `run_benchmark()` documentation says a disclosed shortfall may return 0, while implementation returns 1 for any budget breach. The implementation’s fail-gate behavior is the correct policy.

## Required Changes

1. Make the benchmark contract explicit:
   - functional failure => exit 1;
   - performance budget breach => exit 1;
   - disclosure is mandatory context, not a pass waiver.
2. Update function/module prose to match actual exit semantics.
3. Replace heading-only disclosure verification with evidence-aware verification:
   - current time breach class must be explicitly documented;
   - current memory breach class must be explicitly documented;
   - notes must include the measured values/reference run identifier.
4. Update `PERF_NOTES.md` with the latest actual measurement and mark it `BREACH — DISCLOSED`, not PASS.
5. Remove or clearly date older typical numbers so they cannot be read as the latest reference result.
6. Ensure release notes and plan evidence quote the same reference measurement.
7. Record reference host details where available; if unavailable, say `unknown/not captured` instead of inventing a platform.

## Tests

- Stale headings without matching breach details fail disclosure validation.
- Time-only breach requires time disclosure.
- Memory-only breach requires memory disclosure.
- Dual breach requires both.
- Functional error can never be excused by disclosure.
- Performance breach remains non-zero even with correct disclosure.

## Acceptance

The benchmark, task log, performance notes, and release notes all describe the same latest reference result and the same pass/fail semantics.

## Validation

```bash
pytest -q tests/test_bench_smoke.py
python bench/perf_250k.py --records 250000 --time-budget 15.0 --mem-budget 512.0
```

Expected result may still be non-zero until T-06 closes the budget gap. That is valid and must not be relabeled green.

## Out of Scope

- Lowering budgets.
- Shrinking the fixture.
- Native acceleration.
