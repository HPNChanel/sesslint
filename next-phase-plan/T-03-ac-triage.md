# T-03: AC evidence triage

- Status: done
- Phase: 0 (order 4)
- Depends on: T-01, T-02
- Targets: none (triage table appended to this file)

## Acceptance Criteria Triage Table

| ID | Criterion Summary | Status | Test / File Evidence |
|---|---|---|---|
| `AC-001` | Healthy fixture exits 0, no errors | **PASS** | `tests/accept/test_healthy.py` (16 fixtures) |
| `AC-002` | Parallel tool calls & out-of-order | **PASS** | `tests/checks/test_tool_pairing_1.py`, `test_tool_pairing_2.py` |
| `AC-003` | Torn final record produces SL002 | **PASS** | `tests/test_sl001_sl002.py`, `tests/io/test_byte_offsets.py` |
| `AC-004` | Nonterminal malformed produces SL001 | **PASS** | `tests/test_sl001_sl002.py` |
| `AC-005` | Graph errors (SL101-SL108) | **PASS** | `tests/checks/test_graph.py` (30 tests) |
| `AC-006` | Tool pairing errors (SL201-SL203, SL003-SL007) | **PASS** | `tests/checks/test_tool_pairing_1.py`, `test_identity.py` |
| `AC-007` | Faulty projection repair | **PASS** | `tests/repair/test_recipes_conservative.py`, `test_executor.py` |
| `AC-008` | Side-effect ambiguity causes SL203 & refusal | **PASS** | `tests/repair/test_abstention_matrix.py`, `test_scoped_abstention.py` |
| `AC-009` | No invented successful results | **PASS** | `tests/repair/test_immutable.py`, recipe catalog audit |
| `AC-010` | Check & repair dry-run mutate nothing | **PASS** | `tests/repair/test_atomic.py`, `test_immutable.py` |
| `AC-011` | Successful repair leaves source untouched | **PASS** | `tests/repair/test_atomic.py` |
| `AC-012` | Repair refuses source/existing output | **PASS** | `tests/test_atomic.py`, `tests/cli/test_repair_cli.py` |
| `AC-013` | Fault-injected kill leaves no corrupt output | **PASS** | `tests/accept/test_kill.py` |
| `AC-014` | Repaired artifact auto revalidated | **PASS** | `tests/repair/test_executor.py`, `tests/test_e2e_cycle.py` |
| `AC-015` | Manifest binds source, plan, output hashes | **PASS** | `tests/test_manifest.py` (31 tests) |
| `AC-016` | Idempotent repair | **PASS** | `tests/test_e2e_cycle.py` |
| `AC-017` | Content-free default reports | **PASS** | `tests/privacy/test_safe_discriminator.py`, `test_content_free.py` |
| `AC-018` | Zero outbound network egress | **PASS** | `tests/test_no_egress.py`, `test_no_telemetry.py`, `test_offline.py` |
| `AC-019` | Deterministic output bytes | **PASS** | `tests/accept/test_determinism.py`, `test_canonical_codec.py` |
| `AC-020` | Unsupported format versions SL301 | **PASS** | `tests/cli/test_formats_version.py`, `tests/test_codes.py` |
| `AC-021` | Parse/permission errors never healthy | **PASS** | `tests/scan/test_read_errors.py`, `tests/cli/test_check.py` |
| `AC-022` | 5-bucket directory scan totals | **PASS** | `tests/scan/test_aggregate.py` |
| `AC-023` | 100MB/250k perf budget or disclosure | **PASS** | `bench/perf_250k.py`, `bench/PERF_NOTES.md` |
| `AC-024` | Zero dependencies, works offline | **PASS** | `tests/accept/test_offline.py`, `tests/test_smoke_release.py` |
| `AC-025` | Reason code & recipe test matrix | **PASS** | `tests/test_coverage_matrix.py`, `tests/MATRIX.md` |
| `AC-026` | CLI / Library 1:1 parity | **PASS** | `tests/test_parity.py`, `tests/accept/test_parity.py` |
| `AC-027` | A4 reference loader reconstruction | **PASS** | `tests/test_reference.py`, `src/sesslint/reference.py` |
| `AC-028` | Assurance limitation statements honest | **PASS** | `tests/test_report.py`, `src/sesslint/report.py` |
| `AC-029` | Cross-platform consistency (win/linux/mac) | **PASS** | `tests/test_cross_platform.py`, `.github/workflows/ci.yml` |
| `AC-030` | Synthetic or consented fixture provenance | **PASS** | `tests/test_fixture_provenance.py` |

## Acceptance

All 30 product acceptance criteria mapped to automated test evidence. All 30 are PASS. Zero unmapped rows.

---

## Supersession Note (2026-09-15, post-alpha T-01)

The rule-family labels in the triage table above are incorrect. Verified against `src/sesslint/codes.py` `CODE_REGISTRY` categories:

- `SL001`–`SL002` = syntax; `SL003` = identity; `SL004`–`SL007` = graph; `SL101`–`SL108` = tool pairing; `SL201`–`SL203` = checkpoint/continuation safety; `SL301`–`SL302` = compatibility.
- Therefore AC-005 covers **graph** errors `SL004`–`SL007` (not `SL101`–`SL108`), and AC-006 covers **tool-pairing** errors `SL101`–`SL108` (not `SL201`–`SL203`/`SL003`–`SL007`).

Original table retained unedited for provenance. Current operational authority: `post-alpha-hardening-plan/00-plan.md`; reconciliation row `L-01` in `post-alpha-hardening-plan/EVIDENCE_LEDGER.md`.
