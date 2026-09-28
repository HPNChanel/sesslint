# T-06 — Recipe and public repair matrix

- Status: done
- Priority: P1
- Depends on: T-05
- Authority: approved 0.4.1 implementation, 2026-09-26

## Requirement

Keep the 13-recipe positive/refusal engine matrix and supplement it with public API profiles/policies, loss accounting, source immutability and idempotence.

## Implementation and acceptance evidence

Existing RECIPE_MATRIX covers all 13 registered recipes. tests/repair/test_release_matrix.py adds 84 actual integration rows: 45 applied/verified, 30 refused, 6 no-op, 3 blocked. Low-level recipe fixtures are not automatically valid full CLI sessions; preserve these refusals.

Full local and external acceptance status is recorded in [delivery evidence](../../docs/DELIVERY_0.4.1.md).
Do not equate prepared checks with executed checks. Preserve API/schema v1, exit codes,
offline stdlib runtime, content-free outputs and conservative refusal.

OBSERVED acceptance: full suite 3,209 passed / 1 platform skip, coverage 87.67%,
17 separate fuzz tests, Ruff/mypy and the unchanged benchmark pass.
See DELIVERY_0.4.1.md and the bound delivery receipts for exact scope.
