# T-02 — Actual 34-code detection goldens

- Status: done
- Priority: P0
- Depends on: T-01
- Authority: approved 0.4.1 implementation, 2026-09-26

## Requirement

Correct baseline: nine old reader goldens cover only SL001/SL002. Keep reader mode and original fixture bytes; add check_file and scan modes.

## Implementation and acceptance evidence

tests/harness/conformance.py runs real public detection. 34 detector golden files assert every registered code, including SL401/SL402. tests/test_harness.py enforces the observed code set and deterministic results. Full gate evidence is recorded in docs/DELIVERY_0.4.1.md.

Full local and external acceptance status is recorded in [delivery evidence](../../docs/DELIVERY_0.4.1.md).
Do not equate prepared checks with executed checks. Preserve API/schema v1, exit codes,
offline stdlib runtime, content-free outputs and conservative refusal.

OBSERVED acceptance: full suite 3,209 passed / 1 platform skip, coverage 87.67%,
17 separate fuzz tests, Ruff/mypy and the unchanged benchmark pass.
See DELIVERY_0.4.1.md and the bound delivery receipts for exact scope.
