# T-05b: Subprocess -q omitted test node IDs in coverage matrix

- Status: done
- Phase: 1b (spawned from Phase 1a T-15)
- Defect: `pytest -q --collect-only` in `test_coverage_matrix.py` emitted file counts without individual `::test_name` node IDs, causing matrix matching to fail.
- Fix: Removed `-q` argument in subprocess call in `tests/test_coverage_matrix.py` so full node IDs are captured.
- Verification: `pytest tests/test_coverage_matrix.py` exits 0 (2 passed, all 1,571 node IDs parsed). Full gates green.
