# T-05a: Python 3.11 nested f-string quotes compatibility in completion.py

- Status: done
- Phase: 1b (spawned from Phase 1a T-13)
- Defect: Python 3.12 syntax allowed nested quotes inside f-strings `f"{'...'}"`, which raises `SyntaxError` under Python 3.11.9.
- Fix: Extracted quoted strings and options outside f-string expressions in `src/sesslint/completion.py`.
- Verification: `pytest tests/cli/test_completion.py` exits 0 (7 passed). Full gates green.
