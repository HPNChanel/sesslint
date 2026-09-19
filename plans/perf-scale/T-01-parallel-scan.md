# T-01: Parallel scan workers (`--jobs`)

- Status: done (2026-09) — `scan --jobs N` via `ProcessPoolExecutor`;
  byte-identical output vs `--jobs 1` proven in tests + bench notes
  (`bench/PERF_NOTES.md` §5); 14 tests in `tests/scan/test_parallel.py`
- Phase: perf
- Priority: P1
- Type: feature (read-only; deterministic merge)
- Depends on: —
- Primary targets:
  - `src/sesslint/scan.py` (worker pool, merge)
  - `src/sesslint/cli.py` (`scan --jobs N`)
  - `src/sesslint/progress.py` (aggregated progress events)
  - `tests/scan/`, `tests/cli/`, `tests/test_determinism*.py`
  - `README.md`, `CHANGELOG.md`

## Goal

`scan` uses `multiprocessing` workers on multi-file inputs so a 16-thread
host scans large trees at near-linear speedup, with output byte-identical
to sequential mode.

## Verified Problem / Current Evidence

- `_scan_single_file` loop in `scan.py` is sequential; a 12 GB real
  `~/.codex/sessions` tree is single-core bound.
- Reference hardware: i7-11800H (8C/16T). Field test scanned 60 files
  serially; wall time scales with file count, not CPU.
- Scan results are already structured (`FileResult`) and sorted in report
  assembly — the merge seam exists.

## Required Design / Decisions

1. `--jobs N` (default `1` = today's exact behavior; `0`/`auto` =
   `os.cpu_count()`). Only active for multi-path/directory scans;
   single-file input ignores it with a stderr note.
2. `concurrent.futures.ProcessPoolExecutor` over the resolved file list;
   each worker runs existing `check`/`_scan_single_file` logic and returns
   a serialized `FileResult` (JSON round-trip, not pickle — see constraint).
3. Parent process merges results sorted by normalized path — never by
   completion order. Aggregate counts/verdicts computed after merge.
4. Progress: workers emit counters only (completed/total per file); the
   parent emits ordered `ProgressEvent`s keyed by path, preserving the
   deterministic-event contract (FR-081).
5. Worker serialization: stdlib `json` payloads only (no `pickle` anywhere
   in `src/`); `FileResult` gains `to_dict`/`from_dict` if missing.
6. Cancellation token checked between completed futures; cancel stops
   dispatch of queued files deterministically.
7. Scan caps (`DEFAULT_MAX_FILES`, byte caps) are enforced by the parent on
   the resolved list before dispatch — workers cannot multiply limits.

## Ordered Implementation Steps

1. `FileResult` (de)serialization helpers + round-trip tests.
2. `scan.py`: split `scan_paths` into `resolve_files` + `run_scan(files,
   jobs)`; sequential path stays the default branch.
3. CLI `--jobs` wiring + help ("parallel workers; output identical").
4. Determinism test: `scan dir --jobs 8` JSON bytes == `--jobs 1` bytes.
5. Bench note in `PERF_NOTES.md` on the maintainer's real tree (dev-only
   evidence; nothing committed).
6. CHANGELOG Added.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/scan/ tests/cli/
uv run pytest -q  # determinism suite included
uv run python bench/perf_250k.py
```

## Acceptance Criteria

- `--jobs N` produces byte-identical JSON/SARIF vs `--jobs 1` on the same
  tree, across repeated runs.
- Windows spawn mode works (guarded `if __name__ == "__main__"` semantics
  in worker entry; no unguarded module-level executor).
- Memory stays inside the 512 MB contract for the bench workload.

## Rollback / Stop Conditions

- Stop if deterministic merge cannot be proven byte-identical on the
  synthetic corpus — ship sequential-only.
- Stop if worker serialization requires `pickle` (invariant violation);
  redesign as pure-JSON payloads.

## Risks

- Process spawn overhead dominates small trees → keep default `--jobs 1`,
  document `--jobs auto` for large trees.
- Frozen `FileResult` may contain non-JSON types → normalize at the
  serialization seam, not by weakening the dataclass.

## Out of Scope

- Threading for single-file check internals; native-accel S0–S3; any
  per-finding cache (that is T-02).
