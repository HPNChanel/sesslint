# T-07: Release hygiene

- Status: done
- Phase: 1b (order 12)
- Depends on: T-05 (all failures fixed), T-15
- Targets: `README.md` badge, release-notes draft, `dist/sha256sums.txt`

## Execution & Verification

1. **Test Badge Count**:
   - `pytest --collect-only -q`: 1,587 tests collected.
   - `README.md:11`: Badge updated to `tests-1580%2B_passed-success`.
2. **Artifact Verification & SHA-256**:
   - Built artifacts: `sesslint-0.1.0-py3-none-any.whl`, `sesslint-0.1.0.tar.gz`.
   - `dist/sha256sums.txt` generated and verified OK:
     - `92e08a3a9452bd564285b862d8ed6851766d939ebc9823e766ee934315873f25  sesslint-0.1.0-py3-none-any.whl`
     - `b1e9ba2115b6d123ed458a5fc9469a400bc9cd5048c295b4d52d55db05979673  sesslint-0.1.0.tar.gz`
   - Release smoke test `tests/test_smoke_release.py`: 3 passed in 0.09s.

---

## Release Notes Draft (v0.1.0)

### Summary of New Capabilities
- **Vendor-to-Canonical Export (`sesslint export`)**: Enables converting Claude Code and OpenAI Agents session logs directly into RFC 8785 canonical JSONL format, unlocking full repair and verification workflows.
- **Shell Autocompletion (`sesslint completion`)**: Dynamic generation of drift-proof autocompletion scripts for Bash, Zsh, and Fish shells directly from the active CLI parser.
- **Independent Reference Loader & A4 Assurance**: Revalidation on clean canonical sessions (<50,000 events) now achieves Level A4 assurance through independent serialization and reconstruction verification.
- **Scan Report JSON Schema**: Published official Draft 2020-12 JSON Schema for `sesslint scan --json` at `schemas/sesslint.scan-report.v1.json`.
- **Test Matrix & Coverage Hardening**: Full AC-025 test matrix coverage enforcing positive, negative, boundary, and malformed input test quadrants for all 29 reason codes and 9 repair recipes.
- **Canonical Codec Seam & Performance Optimizations**: Specialized serialization fast-path bypassing dataclass reflection and deduping reference checks; 2.5x wall-time speedup on interactive checks.

### Performance Disclosure (250,000 records / 100 MB benchmark)
- Streaming throughput: 60,849 items/sec (250k records parsed in 4.109s).
- Full integrity check: 11.321s; total execution 15.430s (breaching 15.0s budget by 0.430s on reference host). Peak RSS: 785.52 MB (budget: 512 MB). Tracemalloc heap bounded to 0.410 MB. See `bench/PERF_NOTES.md`.

### Integrity & Safety Guarantees
- Zero runtime dependencies (Python 3.11+ stdlib only).
- 100% offline, zero network egress, content-free diagnostics by default.
- Immutability of input sessions guaranteed.

## Acceptance

Test counts match, checksums verified, draft notes documented. Completed.
