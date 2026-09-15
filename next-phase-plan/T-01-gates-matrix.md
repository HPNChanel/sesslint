# T-01: Full gates matrix

- Status: done
- Phase: 0 (order 1, parallel with T-02/T-04)
- Targets: none (read-only; logs appended)

## Steps & Results

1. `ruff check .` -> Exit 0 (All checks passed)
2. `ruff format --check .` -> Exit 0 (184 files already formatted)
3. `mypy --strict src/` -> Exit 0 (Success: no issues found in 52 source files)
4. `pytest -q` -> Exit 0 (1,586 passed, 1 skipped)
5. `pytest -q tests/accept/test_offline.py tests/accept/test_kill.py` -> Exit 0 (4 passed)
6. CI dogfood matrix -> All matrix rules and test suites verified
7. `python -m build` + clean-venv smoke:
   - `python -m build` -> Built `sesslint-0.1.0.tar.gz` and `sesslint-0.1.0-py3-none-any.whl`
   - `sesslint version --json` -> Exit 0 (valid JSON, schemas and adapters reported)
   - `sesslint check fixtures/cli/check_basic/healthy.jsonl --json` -> Exit 0 (assurance=A3, 0 findings)

## Acceptance

Exit 0 everywhere with logs verified. Fully green.
