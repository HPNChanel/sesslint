# T-03: `sesslint stats` aggregate statistics

- Status: done
- Phase: ux
- Priority: P2
- Type: feature (new command; read-only)
- Depends on: —
- Primary targets:
  - `src/sesslint/cli.py` (`stats` subcommand)
  - `src/sesslint/api.py` (`stats_paths()`)
  - `src/sesslint/stats.py` (new module)
  - `tests/`, `README.md`, `CHANGELOG.md`

## Goal

`sesslint stats <path|--agent>` produces content-free aggregate statistics
over session files: how many events, of which kinds, how much tool
activity, how many compactions — fleet-level visibility without reading
transcripts.

## Verified Problem / Current Evidence

- No way to answer "how big/what shape is my session corpus" without
  parsing files externally.
- Scan already walks directories + detects adapters; stats reuses the
  same pipeline read-only.

## Required Design / Decisions

1. `sesslint stats PATH... [--agent claude|codex|all] [--format human|json]`
   — composes with discovery (`demand-wedge T-05` behavior).
2. Metrics (all content-free): file count by verdict+adapter; event count
   total and per `kind`; tool-call count per tool *name-hash* (truncated
   sha256 of name — never the name); message count per role; compaction
   boundary count; checkpoint count; per-file byte/event percentiles
   (p50/p95/max).
3. JSON doc `{schema: "sesslint.stats/v1", ...}` — new schema file;
   sorted keys; deterministic.
4. Bounds: same file limits as scan; stats never materializes payloads —
   counters only.
5. Exit code 0 always on successful aggregation; 2 on usage error.

## Ordered Implementation Steps

1. `stats.py`: streaming counters over `iter_events`-equivalent adapter
   path (reuse `scan` detection; skip unreadable files into `skipped`
   bucket).
2. `api.stats_paths()` + CLI.
3. Schema + tests: synthetic tree → exact expected counters; determinism
   replay; privacy test (no tool names, no paths beyond minimized).
4. Docs + CHANGELOG.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/ tests/privacy/
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- On a synthetic tree with known composition, every counter matches
  expected values exactly; repeated runs byte-identical.
- Output contains zero payload values and zero raw tool names.

## Rollback / Stop Conditions

- Stop if tool-name hashing cannot avoid leaking short/guessable names —
  fall back to counts-only (drop per-tool breakdown).

## Risks

- Hash-dictionary attacks on short tool names → prefer total counts if
  privacy review objects; document the choice either way.

## Out of Scope

- Token/cost accounting (needs payload semantics — see checks-rules T-03
  for integrity-side usage checks); time-series storage; dashboards.

## Implementation Notes (landed)

- `src/sesslint/stats.py`: `stats_paths` (walk + detect + load counters),
  frozen `SessionStats`, `sesslint.stats/v1` wire + schema accessors
  (scan.py convention). `minimize_path` and `scan` constants lazy-imported
  (same circular-import guard as diff).
- Counters: files processed/undetected/unreadable (bad members bucket, never
  raise), `by_adapter`, events total + `by_kind` + `by_actor`,
  `tool_calls_total` + `by_tool_hash` (sha256(name)[:16] — raw names never
  emitted), compaction boundaries, checkpoints, `file_bytes` and
  `events_per_file` nearest-rank p50/p95/max/total.
- Deterministic: sorted keys everywhere, tool table top-100 by
  (count desc, hash asc), fixed percentile ranks, no timestamps.
- Directory walk mirrors scan's iterative sorted scandir + built-in
  exclusions (.git/.hg/.svn dirs, sesslint.toml names) and the
  DEFAULT_MAX_FILES/DEFAULT_MAX_BYTES budgets.
- CLI `sesslint stats PATH... [-r] [--agent claude|codex|all] [--format]
  [--output-format|--json]`; `--agent` composes `discover_session_roots`
  (conflicts with explicit paths -> exit 2); exit 0 aggregate / 2 usage.
- `api.stats_paths` exported (library-CLI parity).
- tests/cli/test_stats.py: 12 tests (exact counters on fixture corpus,
  tool-hash privacy, dir walk, error paths, determinism, schema
  conformance, no-payload).
- README: matrix (ten->eleven) + `#### sesslint stats` section + schema
  row, `next release`-marked; CHANGELOG entry; PINNED_COMMANDS += stats.
- Gates: ruff/format/mypy clean; full suite green; release-refs OK.
