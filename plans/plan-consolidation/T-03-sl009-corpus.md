# T-03 — Synthetic secret family corpus

- Status: done
- Priority: P0
- Depends on: T-01, T-10
- Authority: approved 0.4.1 implementation, 2026-09-26

## Requirement

Label all 14 families with positive, near-miss, placeholder, truncated and malformed cases. Exercise scanner bounds and prevent value leakage through reports/errors.

## Implementation and acceptance evidence

70 labeled cases plus scan-window and finding-cap boundaries in tests/checks/test_secret_corpus.py. Differential prefilter checks use the authoritative regex path. This measures synthetic labels only, never real-data precision/recall.

Full local and external acceptance status is recorded in [delivery evidence](../../docs/DELIVERY_0.4.1.md).
Do not equate prepared checks with executed checks. Preserve API/schema v1, exit codes,
offline stdlib runtime, content-free outputs and conservative refusal.

OBSERVED acceptance: full suite 3,209 passed / 1 platform skip, coverage 87.67%,
17 separate fuzz tests, Ruff/mypy and the unchanged benchmark pass.
See DELIVERY_0.4.1.md and the bound delivery receipts for exact scope.
