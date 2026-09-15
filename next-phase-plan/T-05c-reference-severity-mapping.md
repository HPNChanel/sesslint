# T-05c: Reference loader test severity code mapping

- Status: done
- Phase: 1b (spawned from Phase 1a T-14)
- Defect: `test_flag_cannot_launder_errors_or_warnings` used `SL001` which triggers `A0`, masking whether the reference loader was blocked specifically by severity gating.
- Fix: Updated test finding to use `SL101` (Severity.ERROR, which maps to A1), verifying loader gating honestly.
- Verification: `pytest tests/test_reference.py` exits 0 (6 passed). Full gates green.
