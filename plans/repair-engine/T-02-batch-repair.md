# T-02: Batch repair driven by scan report

- Status: done (2026-09-19)
- Phase: repair
- Priority: P2
- Type: feature (repair workflow)
- Depends on: T-01 (plan export gives per-file audit trail)
- Primary targets:
  - `src/sesslint/cli.py` (`repair --from-scan` / `--batch` mode)
  - `src/sesslint/api.py` (`repair_many()`)
  - `src/sesslint/scan.py` (report→file-list adapter)
  - `tests/repair/`, `tests/cli/`
  - `README.md`, `CHANGELOG.md`

## Goal

Repair an entire tree of deterministic-fixable files in one audited pass:
`sesslint scan dir --json > r.json && sesslint repair --from-scan r.json
--output-dir out/ --manifest-dir manifests/` — each file gets its own
manifest; nothing silently widens loss.

## Verified Problem / Current Evidence

- Real trees carry many independently-corrupted files (field test: 9/15
  Codex files flagged). Per-file CLI repair is one command per file.
- Scan JSON already lists per-file verdicts + codes — the driver input
  exists.

## Required Design / Decisions

1. Input: a `sesslint.scan/v1` JSON report (`--from-scan`) or a directory
   (`--batch DIR` running scan internally); explicit file list
   (`--files`) also accepted.
2. Eligibility filter (fail-closed, non-overridable): a file is attempted
   only if every blocking finding is `deterministic`-repairable and no
   SL203/manual/unknown findings exist; ineligible files are reported
   with code+reason, never attempted.
3. Per-file outputs: `--output-dir` mirrors input relative structure with
   `.repaired.jsonl` suffix preserved names; `--manifest-dir` gets one
   manifest per file named `<sha8-of-path>.manifest.json` — deterministic
   naming, no collisions.
4. Salvage policy applies per file exactly as single repair; `--policy`
   propagates; a file whose plan computes declared loss writes it in its
   manifest and in the batch summary.
5. Batch summary (stdout/`--json`): counts {attempted, repaired, refused,
   skipped}, per-file rows {minimized path, outcome, codes}, never
   payloads. Exit code: 0 all attempted succeeded; 1 any refusal/
   ineligible (partial success is honest); 2 usage error.
6. Deterministic: files processed in sorted-path order; summary rows
   sorted; no wall-clock fields.
7. Atomicity per file is unchanged (existing atomic write path); batch
   has no cross-file transaction — partial results are valid results.

## Ordered Implementation Steps

1. `api.repair_many(files, opts)` orchestrating per-file `repair()` with
   eligibility prefilter on scan findings.
2. CLI: `--from-scan`/`--batch`/`--files` + output/manifest dir flags;
   single-file behavior untouched.
3. Tests: synthetic tree with deterministic+manual+SL203 mix → exactly
   the deterministic subset repaired, rest reported with reasons; output
   dir structure; manifest count; determinism replay.
4. Docs + CHANGELOG.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/repair/ tests/cli/ tests/scan/
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- Mixed-eligibility tree: only deterministic files repaired (verifiable
  via `verify` per manifest); every skipped file lists blocking codes.
- Repeated runs produce identical output tree bytes and summary bytes.

## Rollback / Stop Conditions

- Stop if eligibility cannot reuse existing repairability classification
  verbatim — never introduce a second, looser eligibility notion.

## Risks

- Users expecting "fix everything" → summary must name why files were
  skipped (codes+reasons), keeping refusals informative.

## Out of Scope

- Parallel repair (perf-scale T-01 pattern could apply later); repairing
  into original locations (batch always writes to `--output-dir`; in-place
  batch is deliberately not offered).
