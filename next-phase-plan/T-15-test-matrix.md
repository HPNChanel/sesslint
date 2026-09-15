# T-15: AC-025 test-matrix gate

- Status: done
- Implemented-By: main-session (2026-09-13)
- Implement-Note: `tests/test_coverage_matrix.py` (29×4 curated mapping, collect-only verified at runtime) + `tests/MATRIX.md` written and verified. Both matrix tests pass, full suite green.
- Phase: 1a (order 9)
- Depends on: T-11–T-14 (covers the final tree)
- Targets: `tests/test_coverage_matrix.py` (new; auto-enforced by the existing full-suite CI run)
- Design: AC-025 demands positive/negative/boundary/malformed-input tests per reason code and recipe, enforced in CI. Only docs gates exist today. The test holds an explicit mapping (code/recipe → required test node-id substrings across the four quadrants, `tests/MATRIX.md` as the human-readable mirror) and verifies each against `pytest --collect-only -q` output via subprocess (offline-safe). Codes come from `CODE_REGISTRY` (no hardcoded list to drift); recipes from the recipe registry.

## Steps

1. Inventory existing tests per code/recipe quadrant; write the mapping + mirror doc.
2. Implement the gate test: collect-only, match substrings, fail listing missing quadrant coverage.
3. Fill genuine gaps found (new tests, following existing style) — no weakening to pass.
4. Run gates: `ruff check .`, `ruff format --check .`, `mypy --strict src/`, full `pytest -q`.

## Acceptance

Gate passes on a tree where every code/recipe has all four quadrants; deleting any mapped test fails the gate (spot-check 2 deletions, then restore).

## Out of scope

Docs-gate changes; coverage-percentage tooling (quadrant presence, not %).
