# SessLint 100MB / 250k Performance Benchmark Notes (TASK-026 / FR-095 / AC-023)

> **Contract note (2026-09-15, post-alpha T-05):** This file holds exactly one dated, internally consistent *latest reference baseline* (§3). The benchmark's own stdout/stderr is the disclosure of each individual run — this document is not claimed to describe any run other than the recorded reference run. Older numbers are retained only under §4, clearly dated and superseded. See `post-alpha-hardening-plan/EVIDENCE_LEDGER.md` row `L-03`.

## 1. Benchmark Specification & Target Budgets

SessLint enforces strict performance limits on hostile and production-scale session transcripts:
- **Input Scale**: 250,000 events (~100 MB canonical session JSONL).
- **Time Budget**: <= 15.0 seconds wall-clock time for streaming check and validation.
- **Memory Budget**: < 512 MB peak Resident Set Size (RSS) memory consumption.
- **Environment Reference**: Standard x86_64 Linux CI runner (2 vCPU, 7GB RAM).

A budget breach is always a non-zero exit — disclosure is mandatory context, never a waiver.

---

## 2. Mandatory Disclosure Rule

Per SessLint's Definition of Done and specification requirements (FR-095, AC-023):
> If the 100MB / 250k benchmark exceeds either the 15.0s wall-time budget or the 512MB peak RSS budget on any host or platform, the shortfall MUST NOT be silently swallowed or bypassed by artificially shrinking the fixture.
> Instead, the benchmark runner prints the measured values, budgets, derived breach classes, and run context before returning non-zero, and the latest reference baseline in §3 is refreshed from a selected captured run.

---

## 3. Latest Reference Baseline

One selected reference run, captured 2026-09-15 on the development host under background load. The normative values below are the **fresh child process** real `sesslint check` metrics (T-06 contract); auxiliary parent-process metrics (generation, streaming sample, tracemalloc) are reported separately in benchmark stdout and are excluded here.

<!-- REFERENCE-BASELINE:BEGIN -->
- Run ID: 2026-09-15-perf-250k-win32-amd64-post-t06
- Date: 2026-09-15
- Host: AMD64 / win32 / CPython 3.11.9 (host under load; wall time is load-sensitive)
- Records: 250000
- Input size MB: 99.45
- Total time s: 20.997
- Time budget s: 15.0
- Peak RSS MB: 476.87
- Memory budget MB: 512.0
- Breach classes: time
- Status: TIME BREACH — DISCLOSED; MEMORY PASS (476.87 < 512.0)
<!-- REFERENCE-BASELINE:END -->

Note: `Total time s` and `Peak RSS MB` above are the **fresh child-process** check metrics (T-06 normative), not the parent-process cumulative values. Under identical host load the post-T-06 code measured ~2.05 s faster than the pre-T-06 code (17.06 s vs 19.11 s); the earlier quiet-window pre-T-06 run measured 14.897 s.

---

## 4. Historical Measurements (superseded)

### Reference Platform Specifications
- **Operating System**: Windows / Linux / macOS cross-platform test matrix
- **Python Runtime**: CPython 3.11+ 64-bit
- **Measurement Method**:
  - Linux/macOS: `resource.getrusage(resource.RUSAGE_SELF).ru_maxrss`
  - Windows: `GetProcessMemoryInfo` (Process Peak Working Set Size via Win32 PSAPI) + `tracemalloc`

### Historical Summary (recorded 2026-09-08 — SUPERSEDED, do not cite as latest)
| Operation | Metric | Target Budget | Measured (2026-09-08) | Correctness Verdict | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Streaming Parsing (`iter_events`) | Wall time | <= 15.0 s | ~2.5 - 5.5 s (57k items/s) | Exact item count match | PASS |
| Integrity Check (`check_file`) | Wall time | <= 15.0 s | ~3.5 - 8.5 s | 0 findings, Assurance A3 | PASS |
| Peak Memory Usage | Peak RSS | < 512.0 MB | ~65 - 190 MB | Bounded working set | PASS |

These 2026-09-08 numbers predate the post-alpha hardening work and were superseded by the 2026-09-15 reference baseline above, which breaches both budgets.

### Historical Disclosure Statement (2026-09-08 — SUPERSEDED)
> "Under synthetic 100MB/250k event streaming load, SessLint demonstrates bounded O(1) streaming heap usage well below the 512MB memory ceiling (~65-190MB peak RSS) and achieves 100% correct validation (0 findings, assurance A3, 0 errors/warnings). Wall-clock execution scales linearly with I/O throughput across platforms without buffering full transcripts into memory."
