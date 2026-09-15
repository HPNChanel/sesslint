# T-06: A4 copy-accuracy scrub (revised for T-14)

- Status: done
- Phase: 1b (order 11)
- Depends on: T-14 (reference loader decides A4 attainability)
- Targets: docs + CLI strings only (no behavior change)

## Steps & Audit Results

1. Confirmed T-14's A4 verdict: A4 is honestly attainable via `reference_equivalent_if_clean` on clean canonical sessions under 50,000 events whose serialize→reparse reconstruction matches.
2. Audited README/docs/CLI for A4 claims:
   - `README.md:13`: Updated badge from `assurance-A0--A4_certified` to `assurance-A0--A4_taxonomy`.
   - `README.md:772`: Updated A4 taxonomy description to: `Reconstructed via reference loader on clean canonical sessions (<50k events)`.
   - `docs/codes/README.md`: Verified Section 3 accurately describes A4 attainment via independent reconstruction.
3. Final status:
   - `AC-027`: **PASS** (covered by `tests/test_reference.py`).
   - `DV-006`: Documented and aligned with implementation.

## Acceptance

All user-facing A4 mentions are strictly loader-conditional. Completed.
