# SessLint Perf-Scale Plan (00)

- Status: done
- Language: English
- Created: 2026-09-08
- Authority: execution plan for throughput/memory work beyond
  `native-accel-plan/`. Complements, never replaces, that pack: native-accel
  owns the canonical-codec CPU seam; this pack owns I/O, scheduling across
  files, and perf governance.
- Companion docs: `native-accel-plan/00-plan.md`, `bench/PERF_NOTES.md`,
  `AGENTS.md` (required gates).

## Goal

Make SessLint fast enough that "scan my whole session directory" is a
sub-minute habit on real hardware (reference: 12 GB `~/.codex/sessions`,
i7-11800H 8C/16T), while keeping byte-identical output, the 15 s / 512 MB
`perf_250k` contract, and zero runtime dependencies (stdlib only —
`multiprocessing`, `mmap`, `sqlite3` permitted).

## Verified Facts

1. Single-file check is ~8,650 rec/s pure Python; codec normalization is ~55%
   of CPU (native-accel S0/S1 territory — not duplicated here).
2. `scan` is single-threaded today; on 16-thread hosts the wall time of large
   trees is bounded by one core.
3. `perf_250k` peak RSS measured 478.5 MB against a 512 MB budget — headroom
   is thin and must be defended (`post-alpha-hardening-plan/T-06` related).
4. No incremental layer exists: re-running `scan` on an unchanged tree costs
   the same as the first run.
5. Determinism contract: findings and JSON bytes identical across runs —
   any parallelism must merge deterministically (sort keys, not completion
   order).

## Constraints And Non-Goals

- Output bytes identical whether parallel/incremental paths are on or off
  (opt-in flags, default behavior unchanged).
- No new runtime deps; `sqlite3`/`mmap`/`multiprocessing` are stdlib.
- No caching of findings across runs unless keyed by content hash plus
  ruleset fingerprint — stale findings are a correctness bug.
- Not a GPU task: the engine is deterministic CPU work; GPU-class hardware
  is irrelevant here by design.

## Task Index

| ID | Title | Priority | Depends on |
| --- | --- | --- | --- |
| T-01 | Parallel scan workers (`--jobs`) with deterministic merge | P1 | — |
| T-02 | Incremental check cache (`--incremental`, sqlite3) | P2 | — |
| T-03 | mmap reader for large files in `io.py` | P2 | — |
| T-04 | Benchmark ledger + CI perf-regression gate | P1 | — |

## Validation

Per task: full gates (`ruff`, `ruff format --check`, `mypy --strict`,
`pytest -q`, `pytest tests/fuzz/`, `python bench/perf_250k.py`) plus the
task's focused perf evidence appended to `bench/PERF_NOTES.md`.
