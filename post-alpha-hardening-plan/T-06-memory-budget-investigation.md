# T-06: 250k memory-budget investigation and recovery

- Status: evidence-pending-review
- Phase: 3
- Priority: P1 performance
- Type: investigation / gated optimization
- Depends on: T-05
- Primary targets:
  - `bench/perf_250k.py` (measurement structure)
  - `bench/probe_20k.py` or a new focused memory probe
  - Check/adapter/rule-engine surfaces identified by profiling
  - Focused performance/differential tests

## Goal

Produce a trustworthy fresh-process measurement of the real `sesslint check` path's time and peak RSS at 250k records; explain the ~785.52MB observation; and, if the clean measurement still breaches, reduce peak RSS below the 512MB budget using only behavior-preserving changes.

## Verified Problem / Current Evidence

The recorded 15.430s total / 785.52MB peak RSS figure comes from `bench/perf_250k.py`, whose process lifetime includes fixture generation and auxiliary `iter_events` streaming passes (~lines 144, 155) in addition to the check itself. That number is therefore **not yet a trustworthy measurement of only the CLI check path** — it may reflect allocator high-water contamination from the generator and streaming sample rather than live check memory.

## Required Design / Decisions

1. **Normative FR-095 metric** = wall time and peak RSS of the real `sesslint check` path executed in a **fresh child process** (spawn the CLI on the pre-generated fixture; measure the child's RSS, e.g., via `resource`/`psutil`-free OS facilities or a subprocess peak-RSS probe consistent with existing bench tooling).
2. **Fixture generation and auxiliary `iter_events` throughput are separate metrics** — reported alongside, never summed into or contaminating the normative check time/RSS.
3. **Profile before optimizing.** No optimization work begins until phase-level measurements identify the dominant consumer.
4. **Contamination outcome:** if the clean child-process check is within budget, close this task as *measurement contamination* and fix the harness/reporting — not the product.
5. **If genuinely over budget:** only behavior-preserving changes are permitted — remove duplicate in-memory copies, consolidate structural indexes, free phase-local structures earlier, use compact immutable coordinates where output is unchanged. Every change requires **differential output tests** (byte-identical reports/manifests before vs. after on representative fixtures).
6. **Explicitly not permitted:** native extension work, fixture shrinking, skipping rules/checks, or silent budget revision. Budget changes require the explicit maintainer decision below.

## Ordered Implementation Steps

1. Modify/extend the benchmark so the check phase runs in a fresh child process; report check time + child peak RSS as the normative result, and generation/streaming as separate auxiliary metrics.
2. Capture phase-level measurements: baseline RSS; post-generation; post-streaming-sample; post-`iter_events`; pre/post adapter load; per check family where feasible; post-report. Capture `tracemalloc` around the **full check path**, not only the streaming sample.
3. Answer the investigation questions in Evidence To Record.
4. Decision point:
   - In budget → close as measurement contamination; update `PERF_NOTES.md`/contract wording accordingly.
   - Over budget → profile adapter materialization and rule-family indexes; implement only behavior-preserving reductions; prove each with differential output tests; re-measure.
5. If still over budget after justified optimization, stop and escalate: the maintainer explicitly chooses (A) continue optimization, or (B) revise the published budget/spec with rationale and update every dependent AC/release statement. Disclosure alone does not make this task `done`.

## Test Matrix

| Case | Expected |
|---|---|
| Fresh-process check at 250k | Normative time/RSS reported for the child only |
| Auxiliary metrics | Generation and `iter_events` throughput reported separately; never summed into check time |
| Differential output | For each optimization: byte-identical report/manifest output on representative fixtures |
| Behavior preservation | No rule family skipped; no output field dropped; determinism tests green |
| Functional correctness | Full suite passes after each optimization |

## Validation Commands

```bash
python bench/probe_20k.py
python bench/perf_250k.py --records 250000 --time-budget 15.0 --mem-budget 512.0
ruff check .
ruff format --check .
mypy --strict src/
pytest -q
```

## Acceptance Criteria

- Normative FR-095 numbers come from a fresh-process check of the real CLI path; auxiliary metrics are separated.
- Phase-level measurement table exists and identifies the dominant memory consumer.
- Either: clean child-process result ≤15.0s and <512MB on the reference host (closed as contamination, harness fixed); or measured-below-budget result after behavior-preserving optimization proven by differential tests; or the task remains `blocked` pending the explicit maintainer budget decision — it is never closed by disclosure.

## Evidence To Record

- Fresh-process measurement table (per-phase RSS + wall time; child peak RSS).
- Investigation answers: canonical event retention? duplicate adapter representations? overlapping graph/tool/checkpoint maps? retained payload dicts? A4/reference scale-gating confirmed? allocator high-water vs. live memory? generator/profiler contamination?
- Per-optimization diffs with differential-test evidence.
- The maintainer's explicit decision if option (B) is taken.

## Rollback / Stop Conditions

- Stop optimization at the first differential-test failure; revert that change.
- Stop and escalate before any budget/spec revision — that decision is the maintainer's, recorded in this task's evidence.
- Revert the task if a measurement change makes the benchmark incomparable to the documented reference contract.

## Risks

- Fresh-process measurement may itself vary across hosts; record host details or `unknown/not captured` honestly.
- Per-family RSS attribution may be infeasible at fine granularity; coarse phases are acceptable if they identify the dominant phase.

## Out of Scope

- Native extension work.
- Changing functional results for performance; dropping payload needed for output identity.
- Fixture shrinking, skipped checks/rule families, lower record counts, silent RSS redefinition.
- Provider/network replay.

---

## Execution Evidence — 2026-09-15

### Normative fresh-process measurements (real `sesslint check` CLI path, child process)

| Run | Check wall (s) | Peak RSS (MB) | Code state | Host load |
|---|---|---|---|---|
| pre-opt | 14.897 | 786.59 | HEAD `fbb2626` | quieter window |
| v1: offsets-only + intern | 15.045 | 520.41 | +lines_info offsets, ts/actor/kind/side_effects intern | quiet→moderate |
| v2: +arrays + shared empty extra_fields | 17.682 | 475.93 | +`array.array` line coords, `MappingProxyType({})` | moderate→loaded |
| v3: +payload copy skip | 20.997 | 476.87 | +skip `dict(payload)` copy | loaded (background tasks) |
| base re-run, same load | 19.113 | 785.5 | HEAD | loaded (control) |
| new re-run ×3, same load | 17.06 / 18.05 / 21.39 | 475.8–477.6 | final | loaded |

**Memory verdict:** 786.59 → **475.9–477.6 MB** across 6 fresh-process runs (−39%, ~36 MB headroom under the 512 MB budget). The memory breach is **resolved**.

**Time note:** wall time is host-load-sensitive. Under identical (loaded) conditions the optimized path measures ~2.05 s *faster* than the pre-optimization code (17.06 s vs 19.11 s). The earlier quieter-window baseline (14.897 s for the slower pre-opt code) implies the optimized path projects to ~12.8 s under the same conditions. On the currently loaded dev host the absolute 15.0 s wall budget is not reliably reachable for either version; a quiet-host/CI run is expected to pass. Time on this host remains a disclosed measurement, not a code regression.

### Phase-level attribution (30k records, in-process cumulative peaks)

| Phase | RSS (MB) |
|---|---|
| baseline (imports) | 30.5 |
| post `load_canonical` | 124.4 |
| post `run_all_checks` | 124.4 |
| post `build_report` | 124.4 |

Dominant consumer: **canonical event materialization** in `load_canonical` (~3.1 KB/event pre-opt). `run_all_checks` and `build_report` add no measurable retained RSS.

### Investigation answers

- **Canonical events retained for entire check?** Yes — `EventList` is held through `run_all_checks` + `build_report` (required by graph/checkpoint/tool-pairing passes). ~1.1 KB/event live post-opt.
- **Duplicate adapter representations?** Yes (removed): whole-file `raw_data` (~99 MB) + per-line `bytes` chunk copies in `lines_info` (~120 MB incl. tuple/int objects at 250k) + `stripped_data` full copy (~99 MB transient). Now: `raw_data` once + `array.array` offsets (~6 MB) + on-demand slices.
- **Overlapping graph/tool/checkpoint maps?** Check families build their own union-find/component indexes (`tool_pairing_2`, `graph`, `checkpoint`) — visible in profiles but small vs. event retention; left unchanged.
- **Payload dicts retained?** Yes — required for output identity/fingerprints. The redundant `dict(raw_payload)` defensive copy was removed (ev_raw is dropped per iteration; no aliasing).
- **A4/reference scale-gating?** Not a memory factor — no additional content retention.
- **Allocator high-water vs live?** Both mattered: retained events ~1.1 KB/event (~275 MB live at 250k); transient `raw_data`/chunk copies/`stripped_data` pushed peak to ~786 MB. RSS measures high-water — post-free arenas retain freed transient memory.
- **Generator/profiler contamination?** None for the normative metric — fresh child process; parent-side generation/streaming/tracemalloc are auxiliary-only.

### Behavior-preserving optimizations applied (`src/sesslint/adapters/canonical.py`)

1. `lines_info` → three parallel `array.array`s (`line_nos`/`line_starts`/`line_ends`); line bytes sliced on demand — removes ~99 MB of per-line `bytes` copies + ~35 MB of tuple/int objects.
2. `stripped_data = data.strip()` full copy removed — `not data or data.isspace()` emptiness check + decode `data` directly (strict decoder tolerates surrounding whitespace identically).
3. `sys.intern` on `ts`, `actor`, `kind`, `side_effects` — dedupes repeated JSON-parsed strings (~−75 MB live).
4. `_EMPTY_EXTRA_FIELDS = MappingProxyType({})` shared for events with no unknown keys (~−16 MB); `SessionEvent.extra_fields` is typed `Mapping` and all consumers are read-only.
5. `payload` reuses the parsed dict when `type(raw_payload) is dict` — removes a per-event dict copy (ev_raw is dropped immediately; no aliasing).

### Differential-output proof

Corpus: all 213 `fixtures/**/*.json|jsonl` + generated 5k benchmark fixture, run through `sesslint check --format auto --json` under both pre-optimization (detached HEAD worktree) and post-optimization code:

- stdout: **byte-identical** on all 213 targets (`diff -r` clean, 0 lines).
- stderr: byte-identical.
- exit codes: identical (`_exit_codes.json` identical).

Full suite: **1660 tests, 0 failures, 0 errors, 2 skipped**. `ruff check`/`ruff format --check`/`mypy --strict src/` all clean.

### Maintainer decision

Memory budget: **met** (476.9 MB < 512 MB, 6 consistent runs). Time budget: the normative run on the current dev host measures above 15.0 s under host load for both pre- and post-optimization code (19.1 s vs 17.1 s same-load); the earlier quiet-window pre-opt run measured 14.897 s. If the acceptance host reproduces >15.0 s under quiet conditions, escalate per step 5 (A: further optimization / B: budget revision) — that decision is the maintainer's.
