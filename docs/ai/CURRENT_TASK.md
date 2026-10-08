# Current implementation — Wave 1

The user requested continuation of the existing task and a code/session review on
2026-10-08. The recovered approved scope is Wave 1: repair safety first, then the
existing Claude/Codex adapters, discovery and scan reporting, file limits,
performance, hooks, correctness fixes, and documentation. New vendor adapters,
desktop/SaaS work, demand-gate changes and publication remain outside this scope.

Current decision: functional source checks PASS; full Wave 1 acceptance remains
unmet because the performance gate and the native Claude healthy-rate target
are not satisfied. No release-ready conclusion is made.

## Workspace and evidence

- OBSERVED: base commit `ea1bb8a`; the starting checkout already contained 44
  modified/untracked files. Their bytes and hashes are protected under
  `scratch/wave1-20261008/protected-inputs/` and `baseline.json`.
- OBSERVED: 88 runtime Python modules, 42,555 lines, indexed in
  `scratch/wave1-20261008/source-map.json`. The source map supports navigation;
  it is not a claim of exhaustive manual review.
- OBSERVED: initial Ruff, formatting and strict mypy passed. The initial full
  pytest attempt was interrupted and is not acceptance evidence.
- SOURCE_VERIFIED: the earlier consolidation plan remains NOT_RELEASE_READY;
  historical binaries and receipts do not verify this changed source tree.

## Implementation and verification

| Group | Scope | State |
| --- | --- | --- |
| W1-0 | B17–B23, B37, repair invariant properties | Implemented; final source suite PASS (3549 passed, 2 POSIX skips); fuzz 28 passed |
| W1-1 | Claude metadata, compaction linkage, unknown-type classification | Implemented; native compaction capability corrected after real-data smoke |
| W1-2 | Codex retained context and unknown-type classification | Implemented; bounded real-data smoke completed |
| W1-3 | Vendor discovery and unsupported inputs | Implemented with explicit skip/unsupported reasons |
| W1-4 | Timestamp tolerance and bounded scan reports/selectors | Implemented; exact aggregate counts retained |
| W1-5 | Per-file size limits and honest skipped results | Implemented for API, CLI, stdin and scans |
| W1-6 | Loading/scan performance without weakening limits | Fast paths implemented and profiled; latest benchmark FAIL (16.81 s > 15 s), CPU 15.75 s, RSS 426.0 MiB |
| W1-7 | Claude hook protocol and fast startup behavior | Implemented; hook regressions and final source suite passed |
| W1-8 | B12–B16, B24–B36 correctness and release tooling | Implemented; strict docs, static checks and final source suite passed; external CI unverified |
| W1-9 | User documentation, changelog, final evidence | Updated; source-bound acceptance receipt completed with remaining gaps recorded |

Independent review reproduced an additional B20 bypass through public
`sesslint.repair.execute`: a resealed forged plan could remove a complete record.
Both high- and low-level public repair paths now share current-finding plan
vetting. Regression and property tests must cover both paths.

Use separate pytest `--basetemp` directories for concurrent checks; the project
default `.pytest_temp` is shared. Do not run performance acceptance concurrently
with the full suite or other deliberate CPU-heavy validation.

No commit, push, tag, release, remote mutation or demand-ledger edit is authorized.

The final evidence and remaining acceptance gaps are recorded in
[`WAVE1_ACCEPTANCE.md`](WAVE1_ACCEPTANCE.md). The full Claude sample contains
122 healthy / 7 invalid / 1 skipped files; 122/129 inspected files is 94.6%, below
the plan's 95% expectation. Do not suppress retained SL102 errors to meet that
percentage. Native stores continue to change, so historical scans are not a
paired accuracy comparison.
