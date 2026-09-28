# T-01 — Archive manifest and protected baseline

- Status: done
- Priority: P0
- Depends on: none
- Authority: approved 0.4.1 implementation, 2026-09-26

## Requirement

Reverify the nine historical generations and preserve every frozen file and unrelated edit.

## Implementation and acceptance evidence

ARCHIVE_MANIFEST.md count reverification; BASELINE.json binds the starting commit and 370 original fixture hashes. Final diff and hash audit must show no changes to frozen packs or original fixtures.

Full local and external acceptance status is recorded in [delivery evidence](../../docs/DELIVERY_0.4.1.md).
Do not equate prepared checks with executed checks. Preserve API/schema v1, exit codes,
offline stdlib runtime, content-free outputs and conservative refusal.

OBSERVED acceptance: full suite 3,209 passed / 1 platform skip, coverage 87.67%,
17 separate fuzz tests, Ruff/mypy and the unchanged benchmark pass.
See DELIVERY_0.4.1.md and the bound delivery receipts for exact scope.
