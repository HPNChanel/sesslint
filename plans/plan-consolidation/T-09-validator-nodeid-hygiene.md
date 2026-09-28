# T-09 — Schema and matrix drift checks

- Status: done
- Priority: P1
- Depends on: T-06, T-07
- Authority: approved 0.4.1 implementation, 2026-09-26

## Requirement

Use jsonschema only in dev to validate emitted schemas and compare malformed-plan rejection with stdlib runtime. Retain existing node-ID/documentation drift gates.

## Implementation and acceptance evidence

tests/utils/schema.py adds Draft 2020-12 validation to report/scan/plan/bundle tests. tests/test_plan_schema_parity.py checks schema validity and rejection parity. Runtime dependencies remain empty and existing manual validators add their tighter constraints.

Full local and external acceptance status is recorded in [delivery evidence](../../docs/DELIVERY_0.4.1.md).
Do not equate prepared checks with executed checks. Preserve API/schema v1, exit codes,
offline stdlib runtime, content-free outputs and conservative refusal.

OBSERVED acceptance: full suite 3,209 passed / 1 platform skip, coverage 87.67%,
17 separate fuzz tests, Ruff/mypy and the unchanged benchmark pass.
See DELIVERY_0.4.1.md and the bound delivery receipts for exact scope.
