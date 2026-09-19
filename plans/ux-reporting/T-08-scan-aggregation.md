# T-08: Scan aggregation views (by-code, top-N)

- Status: done (2026-04-05)
- Phase: ux
- Priority: P1
- Type: feature (report presentation)
- Depends on: —
- Primary targets:
  - `src/sesslint/report.py` (scan summary renderer)
  - `src/sesslint/scan.py` (aggregate computation)
  - `src/sesslint/cli.py` (`--top N`, `--group-by` flags)
  - `tests/scan/`, `tests/report/`
  - `README.md`, `CHANGELOG.md`

## Goal

On multi-file scans, surface "what matters": findings grouped by rule code
with counts, and the top-N worst files — instead of a flat per-file table
users must eyeball.

## Verified Problem / Current Evidence

- Real-tree scans produce hundreds of file rows; the field test's own
  real-data run needed manual triage to see "9× SL203 caused by
  compaction" as a pattern.
- JSON report already carries all findings; aggregation is presentation
  plus a small summary object — no detection change.

## Required Design / Decisions

1. Human output gains a summary block after the per-file table:
   `by_code` rows (code, severity, total findings, files affected —
   sorted by severity rank then count desc then code) and `worst_files`
   top-N (default 10) ranked by error-count then warning-count then path.
2. JSON gains `summary: {by_code: [...], worst_files: [...]}` inside the
   existing scan document — additive field, schema version unchanged
   unless the schema requires bump (check `sesslint.scan/v1` rules;
   additive optional field = no bump).
3. Flags: `--top N` (0 disables worst-files), `--group-by code|none`
   (extensible later); defaults keep current output plus summary.
4. Deterministic: all sorts explicit; ties broken by minimized path/code.
5. Content-free: aggregates contain codes/counts/paths only — same as
   existing report fields.

## Ordered Implementation Steps

1. `scan.py`: pure `aggregate_scan(results) -> ScanSummary` (frozen
   dataclasses; by_code rows, worst_files rows).
2. `report.py`: human renderer block + JSON `summary` field.
3. CLI flags wiring.
4. Tests: synthetic multi-file scan → exact summary object; ordering
   stability; `--top 0`/`--group-by none` behaviors; privacy test.
5. Docs + CHANGELOG.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/scan/ tests/report/
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- On a fixture tree with known findings, `by_code` and `worst_files`
  match hand-computed expectations exactly; repeated runs byte-identical.
- JSON schema validates the new `summary` object; older consumers ignore
  it safely.

## Implementation Notes (done)

- `scan.py`: `ByCodeRow`/`WorstFileRow`/`ScanSummary` frozen dataclasses +
  pure `aggregate_scan(files, top=10, group_by="code")`. `ScanReport`
  gained an optional `summary` field emitted only when attached — API
  scans (`check_dir`, `scan_path`, `scan_bytes`) remain summary-free;
  aggregation is a CLI-layer presentation concern.
- `cli.py`: `--top N` (default 10; negative rejected with exit 2) and
  `--group-by code|none` on the scan parser; summary attached once at the
  emit convergence point so `--agent`, `-` (stdin), and path scans all get
  it. `format_scan_report_human` appends the block after the file table.
- Schema check: `sesslint.scan-report/v1` has no top-level
  `additionalProperties: false`, so `summary` is additive-legal — no
  version bump (verified against `load_scan_schema()`).
- Smoke on `fixtures/scan/mixed`: by_code shows SL001/SL101/SL301/SL302
  (error) before SL006/SL007 (warning); worst files rank invalid.jsonl
  (1e/2w) first; `--group-by none`, `--top 0`, and `--top -1` (exit 2)
  behave per spec; `--json` runs byte-identical across repeats.
- Validation run: `uv run pytest -q tests/scan/ tests/report/` (155 pass),
  ruff check/format clean, `mypy --strict` clean (63 files),
  `scripts/check_release_refs.py` OK.

## Rollback / Stop Conditions

- Stop if additive JSON field breaks the published scan schema contract —
  bump schema version properly instead.

## Risks

- "Worst files" ranking could leak via path ordering → paths already
  minimized; no additional exposure.

## Out of Scope

- Interactive TUI; trend/history comparison across scans (needs the
  bench-ledger-style store — not planned).
