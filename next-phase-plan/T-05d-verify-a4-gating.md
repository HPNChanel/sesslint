# T-05d: A4 assurance gating in verify.py and vendor formats

- Status: done
- Phase: 1b (spawned from Phase 1a T-14)
- Defect: `verify.py` invoked `reference_equivalent_if_clean` unconditionally, causing verification failure when artifacts had vendor format or scale ceiling capping them at A3.
- Fix: Gated A4 reference evaluation in `src/sesslint/verify.py` to run only when manifest assurance is A4; restricted `api.py` reference loader to canonical format.
- Verification: `pytest tests/test_verify.py tests/test_verify_challenger.py` exits 0 (66 passed). Full gates green.
