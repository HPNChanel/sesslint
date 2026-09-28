# T-07 — Fixture navigation and runnable guidance

- Status: done
- Priority: P1
- Depends on: T-02, T-03, T-06
- Authority: approved 0.4.1 implementation, 2026-09-26

## Requirement

Provide a provenance-based fixture index, actual detector golden paths and user walkthrough. Distinguish both matrices.

## Implementation and acceptance evidence

scripts/fixture_index.py generates fixtures/INDEX.md; tests/test_fixture_index.py prevents drift. docs/MATRIX.md describes adapter/profile compatibility; tests/MATRIX.md is the detector/recipe node-ID mirror. docs/STARTER_KIT.md provides PowerShell/POSIX synthetic examples.

Full local and external acceptance status is recorded in [delivery evidence](../../docs/DELIVERY_0.4.1.md).
Do not equate prepared checks with executed checks. Preserve API/schema v1, exit codes,
offline stdlib runtime, content-free outputs and conservative refusal.

OBSERVED acceptance: full suite 3,209 passed / 1 platform skip, coverage 87.67%,
17 separate fuzz tests, Ruff/mypy and the unchanged benchmark pass.
See DELIVERY_0.4.1.md and the bound delivery receipts for exact scope.
