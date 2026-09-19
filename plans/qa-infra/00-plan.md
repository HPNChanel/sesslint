# SessLint QA-Infra Plan (00)

- Status: done
- Language: English
- Created: 2026-09-08
- Authority: execution plan for test/QA infrastructure. Everything here is
  dev-side only — dev extras, CI jobs, scripts; zero impact on runtime
  dependencies.
- Companion docs: `tests/` layout, `AGENTS.md` required gates,
  `next-phase-plan/T-05-failure-spawner.md`, `.github/workflows/ci.yml`.

## Goal

Raise the confidence ceiling per commit: stateful fuzzing that hunts
verdict-divergence bugs (the class the field test actually found), mutation
testing to measure whether tests would catch real defects, a coverage
ratchet, a wider CI matrix, and a growing synthetic corruption corpus
mirroring real vendor shapes.

## Verified Facts

1. `tests/fuzz/` already runs Hypothesis — but as flat property tests, not
   stateful session-mutation machines; the check-vs-scan divergence bug
   (field test) is exactly what stateful + metamorphic tests catch.
2. No coverage gate exists — a new code path can ship untested silently.
3. No mutation testing exists — test suite strength is unmeasured.
4. CI matrix is linux/win/mac × py3.11/3.12; py3.13 and ARM runners are
   free additions for public repos.
5. Field test found the corpus gap directly: fixtures lacked
   `token_usage_record`, Claude 2.x, `summary`/`isSidechain`, >1 MiB lines
   — ~2000 green tests still missed every real-data blocker.

## Constraints And Non-Goals

- Dev extras only (`mutmut`, `coverage`, `hypothesis` extensions); runtime
  stays stdlib-only.
- Mutation runs are scoped + time-bounded (checks/, repair/planner) — never
  a blocking full-tree gate.
- Corpus stays synthetic with `PROVENANCE.json`; real shapes are
  re-authored as synthetic equivalents, never copied.
- Coverage gate is a ratchet (may only tighten), not a vanity target.

## Task Index

| ID | Title | Priority | Depends on |
| --- | --- | --- | --- |
| T-01 | Hypothesis stateful session-mutation machine | P1 | — |
| T-02 | Scoped mutation testing (mutmut) | P3 | — |
| T-03 | Coverage ratchet gate in CI | P2 | — |
| T-04 | CI matrix: py3.13 + ARM runner | P2 | — |
| T-05 | Real-shape corpus expansion (failure-spawner) | P1 | — |

## Validation

Per task: the new infrastructure must catch at least one seeded defect
(deliberately injected, then reverted) before being marked done.
