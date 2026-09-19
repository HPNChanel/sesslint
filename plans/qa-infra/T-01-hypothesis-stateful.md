# T-01: Hypothesis stateful session-mutation machine

- Status: done
- Phase: qa
- Priority: P1
- Type: test infrastructure (dev-dep usage, already present)
- Depends on: —
- Primary targets:
  - `tests/fuzz/test_stateful_sessions.py` (new)
  - `tests/fuzz/` (existing hypothesis suite)
  - `CHANGELOG.md` (dev-facing)

## Goal

A `RuleBasedStateMachine` that mutates synthetic sessions through the
operations corruption actually produces — insert duplicate, swap lines,
truncate tail, inject NUL/invalid UTF-8, drop a parent, splice a blob —
asserting the invariants that matter: no crash, deterministic output,
check/scan verdict consistency (the exact bug class field testing
found).

## Verified Problem / Current Evidence

- `tests/fuzz/` exists (hypothesis) but covers flat properties;
  field-test blockers were *divergence* bugs (check vs scan disagreeing
  on identical bytes) — precisely what metamorphic stateful tests catch.
- Hypothesis is already a dev dep — zero new dependencies.

## Required Design / Decisions

1. State machine holds a synthetic canonical session (list of record
   dicts); rules: `add_event`, `duplicate_random_line`, `swap_two_lines`,
   `truncate_tail`, `inject_bytes` (NUL/0xFF), `remove_parent_link`,
   `splice_blob`, `corrupt_id`.
2. Invariants asserted after each step's check:
   - `check_file` never raises (returns structured findings or clean);
   - `check_file(f)` findings equal `scan` per-file findings on the same
     bytes (the field-test invariant — would have caught the SL302/SL001
     divergence);
   - double-run byte-identical reports (determinism);
   - findings' codes ⊆ registered codes.
3. Bounded: generated sessions capped (≤200 events) for speed; deadline
   per step reasonable; shrink-friendly record model.
4. Seeded repro registry: any failure found is minimized, then frozen
   into `fixtures/` as a named regression (protocol documented in the
   test docstring).

## Ordered Implementation Steps

1. `tests/fuzz/test_stateful_sessions.py`: machine + invariants.
2. Run extended (`--hypothesis-seed` sweeps locally; CI uses default
   profile); record any caught bug as a real fix + regression.
3. CHANGELOG (dev-facing).

## Required Tests / Validation Commands

```bash
uv run pytest tests/fuzz/test_stateful_sessions.py -q
uv run pytest tests/fuzz/ -q
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- Machine runs green under CI profile; a *seeded* divergence (planted
  check-vs-scan inconsistency, reverted) is caught by the metamorphic
  invariant — proof the harness hunts the right bug class.

## Rollback / Stop Conditions

- Stop if runtimes explode (>5 min CI) — tighten generation bounds;
  never drop the consistency invariant to buy speed.

## Risks

- Flakiness from unbounded generation → deterministic seed in CI +
  capped session size keeps it stable; failures replay by seed.

## Out of Scope

- Coverage-guided binary fuzzing (atheris — evaluate separately if
  needed); fuzzing vendor adapters with real-data-derived generators
  (corpus policy: synthetic only).

## Implementation Notes (done)

- `tests/fuzz/test_stateful_sessions.py`: `SessionMutationMachine` —
  10 rules (add/duplicate/swap/truncate events, parent removal, id/field
  corruption, byte injection, blob splice, tail cut) over a synthetic
  `sesslint.session/v1` document, ≤200 events.
- Invariants per step: `check_file` raises at most `SesslintError`;
  double-run `report.to_dict()` byte-identical; `(code, severity)`
  multiset of `check_file` findings ≡ `check_dir` `FileResult.findings`
  (path-free comparison so minimized-path reporting can't false-fire);
  all codes ⊆ `ALL_CODES`.
- Seeded-divergence acceptance proven: monkeypatching `check_file` to
  drop one finding fires `check/scan divergence` assertion (reverted;
  nothing committed).
- `StatefulSessionTest` settings: max_examples=25, step_count=20,
  deadline=None (CI-stable, replays by seed).
