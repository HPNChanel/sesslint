# T-03: SL204 token-usage arithmetic inconsistency

- Status: done (2026-09-19)
- Phase: checks
- Priority: P2
- Type: feature (new detector)
- Depends on: codex adapter (done)
- Primary targets:
  - `src/sesslint/codes.py` (SL204)
  - `src/sesslint/checks/checkpoint.py` or new `checks/accounting.py`
  - `docs/codes/SL204.md`
  - `fixtures/` (synthetic codex-shape usage records) + conformance rows
  - `CHANGELOG.md`

## Goal

Flag sessions whose token-usage accounting cannot be consistent —
cumulative `token_usage_record` totals that contradict the sum of
per-event usage fields — a corruption signature after truncation,
splicing, or partial compaction.

## Verified Problem / Current Evidence

- Real Codex files carry `token_usage_record` envelopes with `usage` /
  `turn_token_usage` payload keys (inventoried in Wave B field test).
- After torn writes or compaction, per-event usage entries and the
  running totals can diverge — currently no check reconciles them.
- This is a numeric invariant check — deterministic, content-free
  (numbers only, never text).

## Required Design / Decisions

1. Canonical surface: adapters normalize usage fields into
   `SessionEvent.extra_fields["usage"]` (or a dedicated slot — decide at
   impl; adapter-neutral shape required since core stays vendor-neutral).
2. Rule: within one session, cumulative usage records must equal the sum
   of contributions since the previous cumulative marker (or stream
   start). Tolerance: exact integer equality; any mismatch fires.
3. Compaction interaction: a `compaction_boundary` resets the accounting
   baseline — post-boundary sums start fresh (document; mirrors SL203
   semantics that post-compaction history is a new audit epoch).
4. Severity `warning`, repairability `none` (accounting evidence; never
   auto-edited).
5. Evidence: `{record_id, expected_total, observed_total,
   window_start_index, window_end_index}` — integers only.
6. Files lacking usage records are unaffected (no coverage noise — the
   rule reports as `not-applicable` skip via coverage).

## Ordered Implementation Steps

1. Decide canonical usage slot; codex adapter populates it (claude/openai
   may map equivalents if present — per-adapter note in doc).
2. `checks/accounting.py`: windowed sum check with boundary reset.
3. `codes.py` SL204 + `docs/codes/SL204.md` + fixtures (consistent,
   torn-mid-window, post-compaction fresh-window, missing-fields).
4. Tests + CHANGELOG.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/checks/ tests/conformance/
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- Synthetic codex-shape file with doctored cumulative total yields one
  SL204 with correct expected/observed numbers; consistent files stay
  clean; post-compaction window resets verified.

## Rollback / Stop Conditions

- Stop if usage payload shapes vary too much across real files to define
  one canonical slot — scope the rule to the exact keys observed in the
  shape inventory (adapters-coverage T-01) and document coverage.

## Risks

- Vendor semantics of "cumulative" may not be per-session → shape
  inventory evidence is required before finalizing the window rule;
  fallback is pairwise delta sanity (non-decreasing totals) which is
  still worth a warning.

## Out of Scope

- Cost/pricing computation; cross-session accounting; repairing usage
  fields.

## Implementation Notes (2026-09-19)

- Canonical slot: `SessionEvent.extra_fields["usage"]` with
  `contribution` / `cumulative` counter dicts. Codex adapter maps
  `turn_token_usage`/`usage` → contribution and `thread_token_usage` →
  cumulative on `token_usage_record` envelopes; other adapters add
  mappings as shapes are observed.
- `checks/accounting.py`: windowed reconciliation — marker counters must
  equal baseline + window contributions (the marker's own contribution
  included). `compaction_boundary` resets the epoch; the first
  post-boundary marker sets the baseline unchecked. Non-negative ints
  only (bool/float/negative skipped per key).
- `Repairability.MANUAL` chosen over plan's "none" (enum has no `none`;
  manual = accounting evidence, never auto-edited). Refusal rationale in
  `repair/refusals.py`.
- New `accounting` family in `checks/runner.py`; SL204 in registry (23
  codes), `ALL_RULES`, all three schemas' `code` enums, profile
  snapshots, coverage matrix + MATRIX.md, README tables, golden bundle
  regenerated.
- Fixtures `sl204_usage_{consistent,divergent,postcompact}.jsonl`
  (codex-rollout shape); tests `tests/checks/test_accounting.py`
  (14 tests incl. boundary epoch, non-int counter skip, gating).
- Gates: ruff/format/mypy clean; full suite green; coverage matrix +
  rule-docs gates pass.
