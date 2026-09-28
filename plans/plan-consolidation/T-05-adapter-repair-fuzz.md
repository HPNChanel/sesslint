# T-05 — Public adapter and plan fuzzing

- Status: done
- Priority: P1
- Depends on: T-02, T-03
- Authority: approved 0.4.1 implementation, 2026-09-26

## Requirement

Fuzz four adapter shapes and plan load/apply with bounded synthetic data. Permit only documented domain errors, preserve sources and refuse without repaired outputs.

## Implementation and acceptance evidence

tests/fuzz/test_fuzz_adapter_shapes.py and test_fuzz_plans.py found malformed-container and unsupported-profile crashes. Runtime validation fixes have minimized regressions in tests/repair/test_plan_input_regressions.py. Full separate fuzz gate is mandatory.

Full local and external acceptance status is recorded in [delivery evidence](../../docs/DELIVERY_0.4.1.md).
Do not equate prepared checks with executed checks. Preserve API/schema v1, exit codes,
offline stdlib runtime, content-free outputs and conservative refusal.

OBSERVED acceptance: full suite 3,209 passed / 1 platform skip, coverage 87.67%,
17 separate fuzz tests, Ruff/mypy and the unchanged benchmark pass.
See DELIVERY_0.4.1.md and the bound delivery receipts for exact scope.
