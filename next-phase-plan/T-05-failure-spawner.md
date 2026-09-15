# T-05: Failure-fix spawner (rule, not a single file)

- Status: done
- Phase: 1b (order 10)
- Depends on: T-01–T-03, T-11–T-15 findings

## Spawned & Resolved Records

1. `T-05a-completion-py311-compat.md`: Python 3.11 nested f-string quotes syntax compatibility.
2. `T-05b-coverage-matrix-subprocess-q.md`: Subprocess -q omitted test node IDs in coverage matrix.
3. `T-05c-reference-severity-mapping.md`: Reference loader test severity code mapping.
4. `T-05d-verify-a4-gating.md`: A4 assurance gating in verify.py and vendor formats.
5. `T-05e-hostile-a4-expectations.md`: Clean canonical expectations update to A4.
6. `T-05f-no-eval-importlib-policy.md`: Disallow importlib pattern in src/ under no-eval security policy.

## Acceptance

All 6 spawned failure records documented, minimal fixes applied, and full gates re-greened. Completed.
