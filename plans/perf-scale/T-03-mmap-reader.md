# T-03: mmap reader for large files

- Status: done (2026-09) — `_open_byte_source` + `_MMapLineSource` in
  `io.py`, wired at `iter_events` / `load_session_header` / claude-adapter
  readline seams. Dual gate (file ≥4 MiB AND avg line ≥64 KiB) added after
  probe showed mmap 18% slower on ~1 KiB lines but ~20% faster on ~1.5 MiB
  lines (`bench/probe_large_file.py`, `bench/PERF_NOTES.md` §6). 39
  equivalence tests in `tests/io/test_mmap_source.py`.
- Phase: perf
- Priority: P2
- Type: performance (internal; behavior-neutral)
- Depends on: —
- Primary targets:
  - `src/sesslint/io.py` (`iter_events` byte source)
  - `bench/` (large-file probe)
  - `tests/io/`
  - `CHANGELOG.md`

## Goal

Large single files (multi-MB Codex `rollout-*.jsonl`, 8 MiB-line records)
read via `mmap` to cut copy overhead and page-cache pressure, with
byte-exact semantics vs the current buffered reader.

## Verified Problem / Current Evidence

- `io.py` reads via buffered binary I/O; each line crosses kernel→user
  boundaries with intermediate copies. Real Codex lines reach ~1.5 MiB
  (field test); 100 MB files allocate proportional buffers.
- Peak RSS already at 478.5/512 MB on `perf_250k` — allocation pressure
  is the constrained axis, not CPU alone.

## Required Design / Decisions

1. `mmap.mmap(fileno, 0, access=mmap.ACCESS_READ)` only for regular files
   above a threshold (proposal: 4 MiB); fallback to buffered reads for
   pipes, empty files, stdin, and platforms where mmap fails — identical
   semantics either way.
2. Line iteration on the mapped view must honor every existing bound:
   `DEFAULT_MAX_LINE_BYTES` (8 MiB), `DEFAULT_MAX_FILE_BYTES`,
   `DEFAULT_MAX_DEPTH`, NUL/UTF-8 probe behavior — mmap is a byte source,
   not a policy change.
3. Lifecycle: mapping closed before parse results leave `io.py`; never
   exposed to checks/repair (internal reader detail).
4. Failure modes: `OSError`/`ValueError` on mmap → buffered fallback,
   silently (no finding changes, no warnings — behavior-neutral).
5. Source-immutability guard unchanged: `source.py` fingerprinting still
   detects mid-read modification; mmap of a mutating file is read-consistent
   enough for detection semantics (verify at test level).

## Ordered Implementation Steps

1. `io.py`: `_open_byte_source(path)` returning an iterator over lines —
   mmap or buffered; single seam, both paths share bounds code.
2. Equivalence tests: every hostile fixture passes identically through
   both paths (parametrized force-mmap / force-buffered).
3. Bench: new `bench/probe_large_file.py` measuring wall+RSS on a 100 MB
   file before/after; append numbers to `PERF_NOTES.md`.
4. CHANGELOG Changed (performance note only — no behavior change).

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/io/ tests/accept/
uv run pytest -q && uv run python bench/perf_250k.py
```

## Acceptance Criteria

- Parametrized byte-source tests prove identical findings/bytes on every
  existing fixture.
- RSS on the 100 MB probe measurably lower or equal; perf_250k stays in
  budget.

## Rollback / Stop Conditions

- Stop if any fixture produces different findings or output bytes between
  mmap and buffered paths — semantics bug, revert.

## Risks

- Windows file-locking semantics on mapped files (delete/rename while
  mapped) → keep mappings short-lived; tests on Windows CI cover it.
- 32-bit Python address-space limits → threshold keeps small files off
  mmap anyway; oversized-map failure falls back.

## Out of Scope

- Changing any reader bound; async I/O; memory-mapping output/write paths.
