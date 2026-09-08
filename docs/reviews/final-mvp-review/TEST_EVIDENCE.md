# Test Evidence

## Environment limitation (read first)

All shell execution failed in this review environment: every `bash` invocation
(including bare `echo hello`) terminated with:

```text
bwrap: Creating new namespace failed, likely because the kernel does not
support user namespaces. bwrap must be installed setuid on such systems.
```

Escalated execution was rejected (`escalated execution requires an
unrestricted permission profile`). Consequences:

- Build (`pip install`, `hatchling`), test suite (`pytest`), linters
  (`ruff check`, `ruff format --check`), type check (`mypy --strict src/`),
  benchmark (`bench/perf_250k.py`), fuzz runs, and every CLI behavioral probe
  were NOT executed by the reviewer. Nothing in this review claims a runtime
  result the reviewer observed.
- Git state (`git status`/`log`/`rev-parse`) could not be queried. The review
  therefore records: (a) production files were touched only through
  create-new review artifacts under `docs/reviews/final-mvp-review/` (the
  review tool's write log is the evidence); (b) no edit/delete tool was ever
  invoked on production paths. A post-review `git status` by the operator is
  required to confirm a clean tree apart from the new review directory.
- File discovery used the search tool (output-capped, inconsistent for
  enumeration) plus direct path reads/probes. Coverage claims below rest on
  complete reads of all production modules (verified via the import graph),
  not on directory listings.

## 1. Existing project verification (attempted, all blocked)

| Purpose | Command | Exit | Result / interpretation |
|---------|---------|------|--------------------------|
| Probe shell | `echo hello` | 1 | Sandbox failure (see above). |
| Repo state | `git status; git log; ls` etc. | 1 / rejected | Same sandbox failure; escalated mode rejected. |
| Full tests | `pytest -q` (ci.yml) | NOT RUN | Blocked. |
| Lint/format | `ruff check`, `ruff format --check` | NOT RUN | Blocked. |
| Types | `mypy --strict src/` | NOT RUN | Blocked. |
| Bench | `bench/perf_250k.py --records 20000` | NOT RUN | Blocked; script audited statically (RVW-037). |
| Fuzz profile | hypothesis targets under `tests/fuzz/` | NOT RUN | Blocked; targets read statically. |

Configured gates (from `.github/workflows/ci.yml`, `pyproject.toml`): ruff
check, ruff format check, mypy strict, pytest (incl. offline job), license/
provenance/doc gates, sdist/wheel build + smoke. NONE were executed
in-review; CI logs were not available. No "tests pass" claim is made anywhere
in this review.

## 2. Static evidence gathered in place of execution

Complete reads (every production module, all line ranges):

- `src/sesslint/__init__.py`, `__main__` (via cli), `_version.py`, `api.py`,
  `atomic.py`, `canonical.py`, `checks/__init__.py`, `checks/checkpoint.py`,
  `checks/graph.py`, `checks/identity.py`, `checks/tool_pairing_1.py`,
  `checks/tool_pairing_2.py`, `cli.py`, `codes.py`, `determinism.py`,
  `errors.py`, `finding.py`, `io.py`, `report.py`, `scan.py`, `source.py`,
  `verify.py`, `adapters/__init__.py`, `adapters/canonical.py`,
  `adapters/claude_code.py`, `adapters/detect.py`, `adapters/openai_agents.py`,
  `policy/abstention.py`, `profiles/__init__.py`, `profiles/builtin.py`,
  `profiles/profile.py`, `repair/__init__.py`, `repair/assurance.py`,
  `repair/errors.py`, `repair/executor.py`, `repair/fingerprint.py`,
  `repair/planner.py`, `repair/preconditions.py`, `repair/recipes_conservative.py`,
  `repair/recipes_salvage.py`, `repair/registry.py`.
- `DEMAND.md` (929 lines), `ARCHITECTURE.md`, `REQUIREMENTS_TRACEABILITY.md`,
  `EXECUTION_ORDER.md`, all 28 `TASK-*.md` (scope/metadata + acceptance
  sections as available), `pyproject.toml`, `.github/workflows/ci.yml`,
  `bench/perf_250k.py`, `bench/PERF_NOTES.md`, `schemas/sesslint.session.v1.json`,
  `README.md` (structure + key sections), `CONTRIBUTING.md`/`FIXTURES.md`/
  `RELEASING.md`/`NOTICE`/`LICENSE` (existence + heads).
- Targeted test reads: hostile/expectations corpus, executor/repair CLI/
  verify/parity/privacy/telemetry/egress/offline/determinism/streaming/
  internal-error/content-free/fuzz heads, `conftest.py`, harness heads.
- Targeted fixture reads: healthy sets, repair E2E source, hostile corpus
  (self_parent, cycle_3, torn_final, EXPECTATIONS.json), verify bundles,
  `minimal.json`, `parallel_valid.json`, secret-seed layout, PROVENANCE files.
- Absence probes (direct reads, all confirmed missing): ~20 traceability-cited
  test files (RVW-046), plus `validators/`, `graph.py`, `engine.py` style
  module guesses used only for inventory.
- Import/call-graph greps: network/eval/pickle/subprocess (clean, 0 hits
  outside comments), `atomic_*`/`SourceGuard`/`require_canonical`/
  `strict_unknown_critical` callers (none), `determinism.*` production callers
  (none), `parse_manifest` production callers (none), `salvage_only` readers
  (none), `repairability=` emissions per check module (single deterministic
  site), `def test_` enumerations per test directory.

## 3. Independent reviewer cases (static execution)

The brief's 30 behavioral cases could not be executed (no shell). Each was
instead traced statically through the code; predictions are recorded in the
findings' Reproduction sections (marked "predicted from code"). Cases with
decisive static outcomes:

- healthy, torn-tail, malformed-middle, missing-parent, cycle, orphan,
  dangling, reused-id, multi-result, reversed, cross-branch, compaction-split:
  traced through adapters + checks; codes predicted per finding.
- checkpoint divergence / terminal-output durability / unknown side effects:
  traced; state-vs-history comparison absent (RVW-009), SL203 gap (RVW-010).
- unsupported version / unknown critical: traced; SL301/302 paths + gaps
  (RVW-030, RVW-005).
- changed source / aliasing / existing output / interrupted repair: traced
  through executor; binding absent (RVW-003), races noted (RVW-040).
- determinism repeat / privacy seed / recursive mix / dry-run snapshot /
  revalidation failure: traced; dry-run purity holds in code; privacy leaks
  found statically (RVW-005); scan abort found (RVW-022).

No reviewer harness was added to the repo (review-only run); no temp
behavioral scripts could be executed either (same sandbox).

## 4. Performance

Not measured. `bench/perf_250k.py` + `PERF_NOTES.md` audited statically only
(RVW-037). AC-023/FR-095 recorded NOT_VERIFIED. Reference platform unknown;
reviewer machine: Linux (release verdict notes platform only as observed via
paths, not via `uname`, which was blocked).

## 5. Fuzzing

Not executed. Targets read: `test_fuzz_jsonl.py` (byte/line strategies over
`iter_events`/`read_header`, total-function assertions), canonical/graph
targets. Campaign status: unknown; seed corpus existence asserted by tests
(unrun). No new fuzzing performed (would need execution).

## 6. Platform-limited checks

No platform was directly verified (no shell on any OS). Evidence levels:
Linux/Windows/macOS behavior argued from code + CI matrix config only
(RVW-037 cross-checks: `os.replace` semantics, `PurePosixPath`
normalization, `st_ino` guards, newline handling all read; none executed).

## 7. What "PASS" means in this review's audits

Because nothing executed, a `PASS` in `REQUIREMENTS_AUDIT.md` means:
implemented in code with no defect found on full reading, plus dedicated
tests existing (unrun). It does NOT mean "observed passing". Every test-
existence citation carries the "unrun in-review" qualifier. The release
verdict does not depend on upgrading these: 25 release-blocking findings
stand on code evidence alone.

## 8. Production-tree integrity

Review tools used: file reads, content searches, and 11 file creations under
`docs/reviews/final-mvp-review/` (README, REVIEW_SUMMARY, FINDINGS,
FINDINGS.json, REQUIREMENTS_AUDIT, TASK_IMPLEMENTATION_AUDIT, TEST_EVIDENCE,
SECURITY_PRIVACY_AUDIT, DETERMINISM_REPAIR_AUDIT, RELEASE_VERDICT,
REMEDIATION_PLAN). No production file was created, edited, deleted, formatted,
or moved; no dependency/lockfile/config/test/fixture change was made.
Operator confirmation advised: `git status --porcelain` should show only the
new review directory (plus any pre-existing uncommitted work, which the
reviewer could not inspect and did not touch).
