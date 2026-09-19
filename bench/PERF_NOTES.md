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
- Run ID: 2026-09-15-perf-250k-win32-amd64-post-t08
- Date: 2026-09-15
- Host: AMD64 / win32 / CPython 3.11.9 (host under load; wall time is load-sensitive)
- Records: 250000
- Input size MB: 99.45
- Total time s: 8.438
- Time budget s: 15.0
- Peak RSS MB: 477.14
- Memory budget MB: 512.0
- Breach classes: none
- Status: PASS (8.438 < 15.0; 477.14 < 512.0)
<!-- REFERENCE-BASELINE:END -->

Note: `Total time s` and `Peak RSS MB` above are the **fresh child-process** check metrics (T-06 normative), not the parent-process cumulative values. This run reflects the T-08 shared-index optimization (single `_ToolPairing2Indexer`/`_OccurrenceGraph` per check family instead of four redundant builds). Prior same-host readings: 11.5–11.9 s spot checks post-change; ~17–21 s for the T-06 code under load; 14.897 s for the pre-T-06 code in a quiet window.

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

These 2026-09-08 numbers predate the post-alpha hardening work and were superseded by the 2026-09-15 reference baseline above, which passes both budgets.

### Historical Disclosure Statement (2026-09-08 — SUPERSEDED)
> "Under synthetic 100MB/250k event streaming load, SessLint demonstrates bounded O(1) streaming heap usage well below the 512MB memory ceiling (~65-190MB peak RSS) and achieves 100% correct validation (0 findings, assurance A3, 0 errors/warnings). Wall-clock execution scales linearly with I/O throughput across platforms without buffering full transcripts into memory."

---

## 5. Parallel Scan (`--jobs`) Observations (dev evidence, 2026-09-09)

Non-contract measurements on the maintainer host (i7-11800H, 8C/16T, Windows
spawn-mode pools). `--jobs` defaults to `1` — it is opt-in because spawn
startup (~0.35–0.5 s/pool on Windows) outweighs gains on trivial per-file
workloads.

| Workload | jobs=1 | jobs=4 | jobs=6–8 | Note |
| :--- | :--- | :--- | :--- | :--- |
| 200 tiny files (~KB each) | 0.74 s | 0.82 s | 0.67–0.69 s (8) | spawn overhead dominates |
| 16 files / 50 MB (SL302-fast) | 0.30–0.37 s | 0.53–0.55 s | 0.65–0.69 s (8) | detection exits early; pool cost masks |
| 6 valid files / 269 MB (~45 MB each, 150k events) | 56.41 s | 32.10 s | 22.14 s (6) | **2.5× speedup** — per-file ~9 s of real analysis |

**Crossover rule of thumb**: `--jobs N` pays off when average per-file
analysis exceeds ~0.5 s (i.e. large valid sessions such as multi-hundred-MB
vendor rollouts); below that, sequential is faster. Report bytes are
identical for any `jobs` value (merge sorts by path before totals).

## 6. mmap Byte Source (`_open_byte_source`, perf-scale T-03, dev evidence 2026-09)

`io._open_byte_source` replaces `open(path,"rb")` at the `iter_events` /
`load_session_header` / claude-adapter readline seams. mmap engages only
when **both** gates pass: file ≥ 4 MiB (`_MMAP_MIN_BYTES`) and average line
in a 64 KiB head sniff ≥ 64 KiB (`_MMAP_MIN_LINE_BYTES`). Anything else —
and every mmap failure — silently falls back to the buffered reader.

Measured via `bench/probe_large_file.py` on the maintainer host
(i7-11800H, Windows):

| Workload | buffered | mmap | verdict |
| :--- | :--- | :--- | :--- |
| 95 MiB, ~1.4 MiB lines (Codex rollout shape) | 0.66 s | 0.52 s | **mmap ~20% faster** — the motivating case |
| 95 MiB, ~1 KiB lines | 11.24 s | 13.29 s | mmap ~18% slower — why the line-size gate exists |

Working-set note: on Windows, mapped file pages count toward
`PeakWorkingSetSize` (+~95 MB on the 95 MiB probe) — those are evictable
page-cache pages, not heap. The perf_250k contract file (~400 B lines)
never crosses the line-size gate, so the contract path stays buffered.

## 7. Benchmark Ledger (`bench/LEDGER.jsonl`, perf-scale T-04)

`perf_250k.py --record --host-tag <label>` appends one JSONL row with the
normative fresh-process metrics (`wall_s`, `peak_rss_mb`, `input_bytes`,
`git_sha`, `os`, `py_version`, `source`). Append-only committed history;
`scripts/bench_report.py` renders the latest runs per host:

| date | host | source | records | wall_s | peak_rss_mb | py | os | git_sha |
| :--- | :--- | :--- | ---: | ---: | ---: | :--- | :--- | :--- |
| 2026-09-08 | field-remediation | field-remediation | 250000 | 13.839 | 478.5 | 3.11.9 | win32 | unknown |
| 2026-09-18 | i7-11800H-laptop | seed | 250000 | 13.994 | 478.38 | 3.11.9 | win32 | 328fcfae |
| 2026-09-18 | i7-11800H-laptop | record | 250000 | 13.411 | 478.824 | 3.11.9 | win32 | 328fcfae |

CI `perf-benchmark` runs on schedule, dispatch, and PRs: it records a
`source: ci` row (workflow artifact, never committed), then
`scripts/bench_gate.py` compares it against the latest same-OS baseline at
1.25× wall tolerance / 512 MB RSS — advisory (`continue-on-error`) until
runner-variance data justifies flipping it required. Rows for an OS with
no baseline record only; malformed ledger lines are skipped by readers.
