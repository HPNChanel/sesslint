# T-02: Incremental check cache (`--incremental`)

- Status: done (2026-09) — `scan --incremental`/`--cache-dir` +
  `SESSLINT_CACHE_DIR`; sqlite `cache_v1` keyed on (path, analysis_fp)
  validated by SHA-256 of file bytes; `"cache": "hit"` markers in
  JSON/human output; unreadable verdicts never stored; corrupt DB →
  uncached scan; 22 tests in `tests/scan/test_incremental.py`
- Phase: perf
- Priority: P2
- Type: feature (opt-in; deterministic; content-free)
- Depends on: —
- Primary targets:
  - `src/sesslint/scan.py` (cache lookup before per-file check)
  - `src/sesslint/cli.py` (`scan --incremental`, `--cache-dir`)
  - `src/sesslint/cache.py` (new module, sqlite3)
  - `tests/scan/`, `tests/privacy/`
  - `README.md`, `CHANGELOG.md`

## Goal

Re-running `scan` on an unchanged session tree skips re-analysis of files
whose content is provably identical, cutting repeat-scan time to
file-hash cost only.

## Verified Problem / Current Evidence

- Repeat scans of a mostly-static session directory re-pay full analysis;
  agent sessions are append-heavy, so most files are unchanged between
  runs (daily `scan --agent all` habit case).
- No cache layer exists anywhere in `src/sesslint`.

## Required Design / Decisions

1. Opt-in only: `scan --incremental`. Default behavior byte-for-byte
   unchanged; cache never alters findings, verdicts, ordering, or coverage.
2. Cache store: `sqlite3` (stdlib) at `%LOCALAPPDATA%/sesslint/cache.db`
   (Windows) / `$XDG_CACHE_HOME/sesslint/cache.db` / `~/.cache/sesslint/`;
   `--cache-dir` overrides. Directory created lazily; never inside scanned
   agent dirs.
3. Cache key: `(adapter_id, profile_fingerprint, ruleset_fingerprint,
   engine_version, sha256(file_bytes))`. Any config/profile/rule/version
   change invalidates naturally via the key — no TTL.
4. Cached value: serialized `FileResult` minus timestamps/progress;
   replayed results must produce identical report bytes (replay path and
   compute path converge on one serializer).
5. Hashing cost bound: files hashed with the same bounded reader used by
   `probe_text_encoding` (chunked); unreadable/oversized files are never
   cached (negative results are not cached — fail-closed re-runs).
6. Cache corruption is non-fatal: any sqlite error → treat as empty cache;
   never block a scan on cache health. `sesslint doctor` (ux-reporting
   T-04) may report cache stats later — not required here.
7. Privacy: the cache stores no payload content — only the FileResult
   shape (codes/fingerprints already content-free) + file hash. Documented
   in README privacy section.

## Ordered Implementation Steps

1. `src/sesslint/cache.py`: open/create schema `v1`, `get(key)`,
   `put(key, result)`, `ruleset_fingerprint()` helper (adapter id +
   profile + select/ignore + rule registry version).
2. `scan.py`: between resolve_files and per-file check, lookup → skip or
   compute+store; mark replayed entries in coverage metadata
   (`cache: "hit"` flag inside FileResult metadata, report-visible).
3. CLI flags + help text; env override `SESSLINT_CACHE_DIR` documented.
4. Tests: unchanged tree second run produces identical report bytes with
   cache hits; modified file re-analyzed; corrupted db tolerated.
5. CHANGELOG Added.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/scan/ tests/privacy/ tests/cli/
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- Second `--incremental` run on unchanged tree reports identical bytes and
  marks cache hits; a one-byte file change re-analyzes only that file.
- `--select`/`--ignore`/profile change invalidates via key, not TTL.
- No writes to scanned directories; cache location documented; sqlite
  failure degrades to uncached scan.

## Rollback / Stop Conditions

- Stop if any path lets a cached result diverge from a fresh computation
  on identical input — that is a determinism breach.

## Risks

- `mtime` shortcuts tempt stale hits → never key on mtime, only content
  hash (hash cost is the accepted floor).
- sqlite on Windows file locking → single-writer per process; treat lock
  errors as empty cache.

## Out of Scope

- Cross-machine/shared caches; caching findings for `--include-content`
  runs (excluded by design — content mode bypasses cache entirely).
