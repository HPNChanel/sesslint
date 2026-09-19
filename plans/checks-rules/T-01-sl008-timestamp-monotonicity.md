# T-01: SL008 non-monotonic timestamp

- Status: done (2026-07-25)
- Phase: checks
- Priority: P1
- Type: feature (new detector)
- Depends on: —
- Primary targets:
  - `src/sesslint/codes.py` (SL008 registry entry)
  - `src/sesslint/checks/graph.py` or new `checks/ordering.py`
  - `docs/codes/SL008.md`
  - `fixtures/` + conformance rows + `tests/checks/`
  - `CHANGELOG.md`

## Goal

Flag events whose `ts` goes backwards within a causal chain — the
ordering violation that is actually a corruption signal (unlike forward
*positional* references, which are legal by design).

## Verified Problem / Current Evidence

- Field test explicitly confirmed forward parent references are legal
  (`test_adversarial_forward_reference`) — the remaining ordering signal
  is timestamp monotonicity, currently unchecked.
- Append-only ledgers with clock metadata: `ts` regressions occur on
  clock changes, hand-edits, or spliced records — worth a warning, not an
  error (clock skew is legitimate).

## Required Design / Decisions

1. Scope: compare `ts` between an event and its parent (causal edge), not
   global file order (sidechains legitimately interleave). Per-branch
   monotonicity only.
2. Severity `warning`, repairability `manual` — clock drift and vendor
   timestamp semantics make auto-fix unjustifiable.
3. Evidence (content-free): `{record_id, parent_id, ts_delta_ms,
   child_index, parent_index}` — deltas as numbers, never raw payload.
4. Tolerance: exact-equality OK; any negative delta fires (no epsilon —
   deterministic; document that vendors emitting equal/retro timestamps
   will warn, tunable later only with evidence).
5. Events lacking `ts` or parents lacking `ts` are skipped silently
   (coverage note in rule doc), not findings.
6. Vendor-neutral: operates on canonical `SessionEvent.ts`; adapter
   normalization decides whether ts exists.

## Ordered Implementation Steps

1. `codes.py`: SL008 entry (title, severity, repairability, family).
2. `checks/ordering.py` (new) or graph.py addition: walk parent edges,
   emit findings.
3. `docs/codes/SL008.md` + fixtures (synthetic ts-regression,
   legit-forward-ref control, missing-ts control).
4. Tests: unit cases + `--select`/`--ignore` gating + check/scan
   consistency + determinism.
5. CHANGELOG Added.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/checks/ tests/conformance/
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- A synthetic file with one ts-regression edge yields exactly one SL008
  warning with correct ids/delta; forward-ref fixture stays clean
  (regression guard for the pinned behavior).

## Rollback / Stop Conditions

- Stop if canonical `ts` is not reliably populated across adapters —
  gate the rule to adapters declaring ts support via adapter metadata.

## Risks

- Vendor ts granularity (seconds vs ms) creates false warnings on equal
  values → equality is allowed by design; document.

## Out of Scope

- Wall-clock plausibility (future timestamps); cross-file ordering;
  auto-repair of ts.

## Implementation Notes

- `src/sesslint/checks/ordering.py` (new `ordering` family): walks unique
  parent edges via graph helpers; fires on any negative parent→child ts
  delta, equality allowed. Skips missing parents (SL004), duplicated
  parent ids (SL003), the adapter epoch sentinel `1970-01-01T00:00:00Z`,
  and unparseable or naive/aware-mixed values.
- Evidence: `{record_id, parent_id, ts_delta_ms, child_index,
  parent_index}` — content-free per plan.
- Wired in `checks/runner.py`; `SL008` added to `codes.py` registry and
  `profiles/builtin.py` `ALL_RULES` (all three built-in profiles).
- Refusal rationale registered in `repair/refusals.py` (Non-goal #13);
  golden bundle + profile snapshot fixtures regenerated for the new code.
- Docs `docs/codes/SL008.md`; fixture
  `fixtures/checks/sl008_ts_regression.json`; tests in
  `tests/checks/test_ts_ordering.py` (renamed to avoid basename collision
  with `tests/engine/test_ordering.py`); MATRIX.md + coverage rows;
  report/scan/bundle schema `code` enums updated.
- Public helper `check_timestamp_order` exported for parity with other
  check families.
- During this task the T-09 `baseline` CLI subcommand (lost to a stale
  edit) was restored in `cli.py` and `--write-baseline` call sites were
  fixed to pass `Finding` objects with a versioned `created_by`.
- Gates: `ruff check`, `ruff format --check`, `mypy --strict` clean;
  full suite 2201 passed / 4 skipped.
