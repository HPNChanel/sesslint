# T-05e: Clean canonical expectations update to A4

- Status: done
- Phase: 1b (spawned from Phase 1a T-14)
- Defect: Fixture expectations in `fixtures/hostile/EXPECTATIONS.json` and associated tests asserted A3 for clean canonical runs, which now attain A4 via reference loader.
- Fix: Updated expectations and tests to expect A4 for clean canonical sessions under 50k events.
- Verification: `pytest tests/io/test_hostile.py tests/test_e2e_cycle.py` exits 0 (8 passed). Full gates green.
