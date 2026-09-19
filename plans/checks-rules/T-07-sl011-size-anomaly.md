# T-07: SL011 record size anomaly

- Status: done (implemented 2026-09-19)
- Implementation:
  - `src/sesslint/checks/size.py` — `check_size_anomaly`; fires at most once
    per file when the largest record exceeds `max(median × 20, 256 KiB)` of
    the file's own distribution. Severity `info`, repairability `manual`.
  - Adapters publish `source_metadata["record_sizes"]` (one int per physical
    record, stream order) — claude (5-tuple internal loader → `EventList`),
    codex, openai, canonical. No second payload pass.
  - Runner: new `size` family; `<8 records` → `adapter-not-applicable`
    coverage skip (family + rule), family discarded from `performed`.
  - `adapters/canonical.py`: `_INTERNAL_SOURCE_KEYS` strips `record_sizes`/
    `links` on load-merge and dump — canonical wire bytes stay schema-clean
    (round-trip byte-exactness preserved).
  - Registry 27 codes; schemas ×3, profiles, refusal rationale, golden
    bundle, matrix, README, CHANGELOG.
- Verified: outlier→1 INFO (`record_index`/`record_bytes`/`file_median_bytes`/
  `ratio`); uniform→clean; <8→coverage skip; `--select`/`--ignore` gated;
  full suite green, ruff/format/mypy clean, perf PASS 12.648s/15s,
  release-refs OK.
- Phase: checks
- Priority: P3
- Type: feature (new detector; info severity)
- Depends on: —
- Primary targets:
  - `src/sesslint/codes.py` (SL011)
  - `src/sesslint/io.py` or `checks/` (byte-size evidence already at parse)
  - `docs/codes/SL011.md`
  - `fixtures/` + conformance rows + `tests/`
  - `CHANGELOG.md`

## Goal

Flag records whose byte size is an extreme outlier within their file —
the content-free tripwire for "a giant blob got spliced into this
session" (embedded dumps, base64 payloads, accidental log captures).

## Verified Problem / Current Evidence

- Field test: real Codex `custom_tool_call_output` lines legitimately
  reach ~1.5 MiB (cap raised to 8 MiB) — legitimate big lines exist, so
  this must be a *relative* outlier check, never an absolute threshold
  (the line cap already handles absolute limits).
- A spliced/injected blob is structurally suspicious even when
  well-formed JSON — size is a content-free proxy.

## Required Design / Decisions

1. Metric: record byte-length vs the file's own distribution. Fire when a
   record exceeds `max(median*K, absolute_floor)` — proposal K=20,
   floor=256 KiB (tunable constants in `io.py` limits family).
2. Severity `info` (lowest; never fails `--fail-on warning` defaults),
   repairability `none`.
3. Evidence: `{record_index, record_bytes, file_median_bytes, ratio}` —
   numbers only.
4. Files with <8 records skip the check (distribution meaningless) —
   coverage `not-applicable` skip.
5. One finding per file max (report the largest outlier only — bounded
   noise by design).
6. Deterministic: median/ratio computed on the file's own record sizes —
   integer math, sorted selection.

## Ordered Implementation Steps

1. Record-size collection in the parse path (line byte lengths are
   already available at `io.py` level — thread through, no re-read).
2. `codes.py` SL011 + emission logic.
3. `docs/codes/SL011.md` + fixtures (uniform file control, one-outlier
   file, small-file skip, legit-large-codex-shape file stays clean via
   floor+ratio design).
4. Tests + tuning evidence: run over the maintainer's real tree
   (dev-only, uncommitted) to confirm legit files don't trip.
5. CHANGELOG Added.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/checks/ tests/io/
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- Fixture with one 2 MiB record among ~1 KiB records → exactly one SL011
  with correct ratio; uniform and small files produce none; real-shape
  codex file with typical ~1.5 MiB outputs does not fire (ratio-based,
  not absolute).

## Rollback / Stop Conditions

- Stop if real-corpus tuning shows the rule fires on >1% of clean files —
  raise floor/K or drop; an info rule that cries wolf is worse than none.

## Risks

- Mixed-workload files (many small + many large) have bimodal medians →
  the `max(median*K, floor)` formula is deliberately conservative;
  document residual false-positive profile.

## Out of Scope

- Content entropy analysis (payload inspection — out permanently);
  compression-ratio tricks; per-record-type thresholds (v1 is global).
