# SessLint UX & Reporting Plan (00)

- Status: done
- Language: English
- Created: 2026-09-08
- Authority: execution plan for CLI surface and report-format additions that
  keep every hard invariant (offline, zero-dep, deterministic, content-free).
- Companion docs: `docs/INTEGRATIONS.md`, `README.md`,
  `plans/README.md` (pack index).

## Goal

Close the remaining UX gaps a daily user hits: shareable report formats,
structural comparison, aggregate visibility, environment diagnostics,
change-time monitoring, pipe-friendly input, and baseline robustness. Every
addition stays read-only on agent state and deterministic in output.

## Verified Facts

1. Human output is the only "shareable" surface today; JSON/SARIF serve
   machines but a maintainer cannot eyeball them quickly.
2. Field-test debt: baseline fingerprints are path-spelling fragile
   (rename/cwd change breaks matching); single-file `--skip-undetected`
   handling was fixed but scan still lacks aggregation views.
3. `completion.py` generates bash/zsh/fish only; Windows-first users get
   nothing.
4. `check` requires a filesystem path; pipe workflows (`tool | sesslint`)
   are impossible.
5. No way to compare two session files structurally (before/after vendor
   update, pre/post compaction) without external diff on raw JSONL.
6. `docs/REPORTING_CORRUPTION.md` serves upstream issues; a static HTML
   report would serve human sharing at the same moment (wedge-aligned).

## Constraints And Non-Goals

- Content-free by default everywhere; `--include-content` stays a local
  debug flag, never wired into hooks/automation paths.
- Deterministic bytes: no timestamps, no host info, no dict-order leaks in
  HTML/diff/stats output.
- `watch` is poll-based observation only — never writes, never installs
  hooks, never mutates agent dirs.
- New commands reuse existing `api.py`/`scan.py`/`report.py` seams; no
  parallel detection logic.

## Task Index

| ID | Title | Priority | Depends on |
| --- | --- | --- | --- |
| T-01 | Self-contained HTML report (`--format html`) | P1 | — |
| T-02 | `sesslint diff` structural comparator | P1 | — |
| T-03 | `sesslint stats` aggregate statistics | P2 | — |
| T-04 | `sesslint doctor` environment diagnostics | P2 | — |
| T-05 | `sesslint watch` directory monitor | P2 | T-13 progress contract (done) |
| T-06 | stdin input (`check -` / `scan -`) | P1 | — |
| T-07 | PowerShell completion | P2 | — |
| T-08 | Scan aggregation views (by-code, top-N) | P1 | — |
| T-09 | Baseline v2 path-normalized fingerprints | P1 | — |

## Validation

Per task: full gates plus snapshot tests pinning deterministic output bytes
for HTML/diff/stats; privacy tests for path minimization in new formats.
