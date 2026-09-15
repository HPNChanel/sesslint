# T-14: A4 reference loader

- Status: done
- Implemented-By: main-session (2026-09-13)
- Implement-Note: `reference.py` (incl. 50k scale bound) + 3 call sites + `tests/test_reference.py` + codes README note written and verified. All 6 reference tests pass, full suite green.
- Phase: 1a (order 8)
- Depends on: T-01 green
- Targets: `src/sesslint/reference.py` (new), `src/sesslint/report.py` (`reference_equivalent` param), `src/sesslint/api.py` + `repair/executor.py` + `src/sesslint/verify.py` (3 call sites), `tests/test_reference.py` (new), `docs/codes/README.md` (A4 note)
- Design: demanded by AC-027, missing today (A4 reserved). Independent reconstruction check, adapter-agnostic (operates on canonical events): fast False on any error/warning finding; else `dump_canonical` → reparse → compare event count + content-identity multiset + structural projection equality. `compute_assurance(..., reference_equivalent=False)` stays backward-compatible; A4 only when clean AND loader agrees. Loader cost is bounded: skipped unless findings are clean, and skipped above MAX_REFERENCE_EVENTS (50k) so the 250k bench path keeps its budget (large clean files cap at A3).

## Steps

1. Implement `reference.reference_equivalent_if_clean(events, findings) -> bool` (pure, offline, no I/O).
2. Add keyword param + A4 branch in `compute_assurance`; thread through the 3 call sites.
3. Tests: clean canonical fixture → A4; warning fixture → A2 (unchanged); error fixture → A1 (unchanged); serializer/parser disagreement (crafted) → capped at A3; loader never runs on findings (perf guard asserted via flag/counter).
4. Docs: A4 section note (attainable = clean + loader-agreeing).
5. Run gates: `ruff check .`, `ruff format --check .`, `mypy --strict src/`, full `pytest -q`.

## Acceptance

A4 attainable and honestly scoped; no behavior change for non-clean inputs; bench path unaffected (loader skipped on findings).

## Out of scope

Provider-backed replay (never — offline product); README rewording (T-06).
