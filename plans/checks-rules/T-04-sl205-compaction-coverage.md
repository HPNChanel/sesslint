# T-04: SL205 compaction coverage gap

- Status: done (implemented 2026-09-19)
- Phase: checks
- Priority: P2
- Type: feature (new detector)
- Depends on: —
- Primary targets:
  - `src/sesslint/codes.py` (SL205)
  - `src/sesslint/checks/checkpoint.py` (compaction-aware logic)
  - `docs/codes/SL205.md`
  - `fixtures/` + conformance rows + `tests/checks/`
  - `CHANGELOG.md`

## Goal

Flag compaction boundaries whose summary does not cover the span it
claims to replace — torn compaction projections that leave the ledger
silently shorter than the summary asserts (complement to SL108's torn
projection and SL203's unsafe continuation).

## Verified Problem / Current Evidence

- Real sessions: 9/15 sampled Codex files hit SL203 (post-compaction
  unauditable tool calls) — compaction is where integrity gets subtle.
- Claude `summary` records carry a `leafUuid`/covered-span pointer;
  whether the claimed span actually exists and is contiguous is
  unchecked today.
- SL108 covers *torn projection* shape; nothing validates *coverage
  semantics* (does the boundary reference real, contiguous prior events?).

## Required Design / Decisions

1. Check: for each `compaction_boundary` event carrying a coverage
   pointer (adapter-normalized `covered_through_id`/`leaf` reference):
   the referenced event must exist, precede the boundary, and every
   covered event must be reachable in the same branch — else SL205.
2. Missing/uncheckable pointers → not a finding (fail-silent where
   semantics are unknowable; coverage note in rule doc). This rule never
   guesses coverage.
3. Severity `warning`, repairability `manual`.
4. Evidence: `{boundary_id, covered_through_id, missing: bool,
   non_contiguous: bool}` — structural facts only.
5. Interaction: SL203 remains the hard gate for repair; SL205 is
   detection-only diagnostics and must not alter plan gating.

## Ordered Implementation Steps

1. Adapter normalization: expose coverage pointer in canonical
   `extra_fields` for claude `summary` and codex `compacted` records
   (bounded field names only).
2. `checks/checkpoint.py`: coverage validation per boundary event.
3. `codes.py` SL205 + `docs/codes/SL205.md` + fixtures (valid coverage,
   missing leaf, non-contiguous span, pointerless boundary control).
4. Tests + determinism + CHANGELOG.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/checks/ tests/conformance/
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- Fixture with a summary pointing at a nonexistent leaf → exactly one
  SL205; valid-coverage fixtures stay clean; pointerless boundaries
  produce no findings.

## Rollback / Stop Conditions

- Stop if coverage-pointer semantics differ too much across vendors to
  normalize safely — ship only for the adapter(s) with verified pointer
  semantics and mark others `not-applicable` in coverage.

## Risks

- Vendor compaction internals are opaque → conservative interpretation:
  only fire on definable violations (missing target, proven
  non-contiguity), never on "suspicious" coverage.

## Out of Scope

- Summary quality/semantic adequacy (unmeasurable without content
  analysis — permanently out); repairing coverage pointers.

## Implementation Notes (2026-09-19)

- `checks/checkpoint.py`: `_coverage_pointer` reads
  `extra_fields["coverage"]["covered_through_id"]`; `check_compaction_coverage`
  builds an id→index map and flags a boundary when the pointer target is
  absent (`missing: true`), sits at/after the boundary, or is unreachable on
  the boundary's parent chain (`non_contiguous: true`). Pointerless
  boundaries skip. `check_sl205` alias exported.
- Claude adapter normalizes bounded `leafUuid` / coverage fields into
  `extra_fields["coverage"]["covered_through_id"]` on summary/compaction
  records. Codex `compacted` records have no verified event pointer →
  pointerless → skipped (documented in `docs/codes/SL205.md`).
- Runner checkpoint family now `{SL201, SL202, SL203, SL205}`; SL205 in
  `ALL_RULES` for all builtin profiles; refusal rationale added
  (detection-only; SL203 remains the repair hard gate — plan gating
  unchanged).
- Fixtures: `sl205_valid_coverage`, `sl205_missing_leaf`,
  `sl205_noncontig`, `sl205_pointerless` under `fixtures/checks/` (covered
  by directory `PROVENANCE.json`).
- `tests/checks/test_compaction_coverage.py`: 15 tests (missing target,
  target-at/after-boundary, non-contiguous branch, pointerless skip,
  valid coverage, gating, determinism, evidence shape).
- Registry now 24 codes; schema enums, profile snapshots, golden bundle,
  coverage matrix, README/docs index, CHANGELOG updated.
- Vendor-free gate: checks-layer docstrings scrubbed of vendor names
  (`test_vendor_free`); field names referenced generically.

## Verification (2026-09-19)

- `uv run pytest -q` — full suite green (incl. conformance + fuzz).
- `uv run ruff check src tests`, `ruff format --check`, `mypy --strict` —
  clean.
- `uv run python bench/perf_250k.py` — PASS: 11.916s / 15.0s budget,
  476.4 MB / 512 MB peak RSS.
- `uv run python scripts/check_release_refs.py` — OK.
- No CRLF artifacts; `git diff --check` clean (pre-existing DEMAND.md
  hard-break whitespace unrelated).
