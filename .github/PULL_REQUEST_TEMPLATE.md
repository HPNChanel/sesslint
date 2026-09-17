<!--
=============================================================================
CRITICAL SECURITY & PRIVACY NOTICE:
NEVER include real session transcripts, secrets, or personal data in this PR —
not in code, tests, fixtures, or descriptions. Use synthetic fixtures only.
=============================================================================
-->

## Summary

<!-- What does this change do and why? Link any related issues. -->

## Scope Check

- [ ] This change respects the project perimeter (no SaaS, telemetry, network
      calls, LLM heuristics, or live-store mutation — see CONTRIBUTING.md).
- [ ] `src/sesslint` still has **zero** third-party runtime dependencies.

## Verification Gates

All gates must be green locally before review:

- [ ] `ruff check src tests` and `ruff format --check src tests` pass.
- [ ] `mypy --strict src/sesslint` passes.
- [ ] `pytest -q` passes (including conformance, fuzz, and offline gates).
- [ ] New behavior is covered by tests; fixtures are synthetic and carry a
      `PROVENANCE.json` with `contains_real_data: false`.

## Documentation

- [ ] Reason-code docs in `docs/codes/` updated for any detection-logic change
      (`pytest -q tests/test_rule_docs.py` passes).
- [ ] Repair-recipe docs in `docs/recipes/` updated for any recipe change
      (`pytest -q tests/test_registry_docs.py` passes).
- [ ] `CHANGELOG.md` `Unreleased` section updated for user-visible changes.

## Risk & Rollback

<!-- Anything reviewers should scrutinize? How is the change rolled back? -->
