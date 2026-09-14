# T-06: 250k memory-budget investigation and recovery

- Status: planned
- Phase: 2
- Priority: P1 performance
- Depends on: T-05
- Primary targets:
  - `bench/perf_250k.py`
  - `bench/probe_20k.py` or a new focused memory probe
  - check/adapter/rule-engine surfaces identified by profiling
  - focused performance tests

## Goal

Explain the observed ~785.52MB peak RSS and reduce it below the stated 512MB reference budget if this can be done without changing correctness, determinism, or zero-dependency guarantees.

## First Principle

Do not optimize from `tracemalloc`’s 5k streaming sample. The high RSS occurs during the whole benchmark lifetime and `check_file()` materializes canonical events and detector indexes. Measure phase-level memory before choosing a design.

## Measurement Plan

Capture at minimum:

1. process RSS baseline before fixture generation;
2. RSS after generation;
3. RSS after 5k streaming sample;
4. RSS after full `iter_events`;
5. RSS immediately before `check_file`;
6. RSS after adapter load;
7. RSS after each check family where feasible;
8. RSS after report construction.

Also capture Python heap using `tracemalloc` around the **full check path**, not only the streaming sample.

## Investigation Questions

- Is the dominant cost canonical `SessionEvent` object retention?
- Does the adapter hold duplicate representations?
- Do graph/tool/checkpoint checks each create large overlapping maps/sets?
- Are payload dictionaries retained even when checks only need structural coordinates?
- Does A4/reference logic run at 250k? It should remain scale-gated.
- Is peak RSS cumulative allocator high-water rather than simultaneous live memory?
- Are benchmark generation or profiling structures contaminating the process peak?

## Optimization Rules

Allowed:

- remove duplicate in-memory copies;
- free phase-local structures earlier;
- consolidate structural indexes;
- use compact immutable coordinates where behavior is unchanged;
- isolate benchmark phases into subprocesses if the metric is intended to measure a specific phase and the spec is updated accordingly.

Not allowed:

- drop payload needed for output identity;
- weaken checks;
- skip rule families;
- lower record count;
- silently redefine RSS.

## Gateway / Outcome

Preferred acceptance:

- 250k benchmark <= 15.0s and < 512MB on the declared reference host.

If memory remains >512MB after justified optimization, this task stays blocked until the maintainer explicitly chooses one of:

A. continue optimization; or  
B. revise the published budget/spec with a new rationale and update every dependent AC/release statement.

Disclosure alone does not make this task `done`.

## Validation

```bash
python bench/probe_20k.py
python bench/perf_250k.py --records 250000 --time-budget 15.0 --mem-budget 512.0
ruff check .
ruff format --check .
mypy --strict src/
pytest -q
```

## Out of Scope

- Native extension work.
- Changing functional results for performance.
- Provider/network replay.
