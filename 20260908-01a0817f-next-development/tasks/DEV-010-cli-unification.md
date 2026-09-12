# DEV-010 -- CLI check onto API + surface hygiene

## Task Metadata

- Task ID: DEV-010
- Title: Unify CLI check onto the library API; clean the command surface
- Program: NDP-001 "Trustworthy Alpha"
- Milestone: M2
- Status: `complete`
- Recommended Gemini effort: medium
- Dependencies: DEV-001
- Blocks: DEV-012, DEV-014, DEV-015
- Related opportunity IDs: OPP-009
- Risk level: medium (large deletion; behavior must stay identical)
- Compatibility classification: BACKWARD_COMPATIBLE (CLI behavior preserved; errors cleaned)
- `CONTRIBUTOR_FRIENDLY = NO`

## Repository Baseline

`cmd_check` (cli.py:565-827) duplicates `api.check_file` (api.py:44-182) line-for-line and
has ALREADY diverged: dead `{Detail}` fallback branch (line 658-670; unreachable because
`resolve_format` always returns a finding on failure -- and it would raise FindingError if
reached), dead `events.source`/`session_id` branches (565-827 vs api 140-153; EventList is
stripped by `list()`). repair/verify commands already wrap api. Surface smells: `scan` is
a limits-diagnostic stub (help+exit 2 otherwise); `validate-session` extra is undocumented;
`check --policy` accepted but meaningless; repair has `--policy salvage` AND
`--salvage-unsupported`.

## Objective

CLI commands are thin wrappers over `sesslint.api` with zero duplicated orchestration;
the command surface is documented and contradiction-free; a full-tree parity test locks
CLI==API behavior.

## User / Maintainer Value

Ends parity-by-copy-paste drift (the class that produced the dead `{Detail}` branch);
smaller CLI review surface; users get one documented behavior.

## Why Now

M2 structural hygiene before M4 adds CLI surface (bundle). DEV-015's action shells out to
the CLI and must inherit API behavior exactly.

## Scope

- Rewrite `cmd_check` as: parse args -> `api.check_file(...)` -> render -> exit code.
  Delete the duplicated detection/adapter/check/report/exit logic (~150 lines).
- Delete dead branches in cli.py AND api.py (`events.source` on plain lists, `{Detail}`
  fallback) -- replacing with correct minimal code, not just deletion (detection-failure
  JSON path must still emit a valid report; prove with a test).
- Full-tree parity differential test: run CLI vs api over every checkable fixture
  (fixtures/cli, fixtures/checks, fixtures/io, fixtures/adapters, fixtures/canonical,
  fixtures/claude_code, fixtures/openai_agents, fixtures/profiles) asserting identical
  reports (fingerprints + findings + coverage + exit mapping).
- Surface decisions (document each): `scan` -> document as diagnostic-only or wire to
  `api.check_dir` (preferred if small: it already exists; the stub contradicts api);
  `validate-session` -> document or remove (preferred: remove if it duplicates check;
  verify by diffing behavior); `check --policy` -> reject with a clear error;
  `--salvage-unsupported` vs `--policy salvage` -> one documented mechanism (keep
  `--policy`, deprecate/remove the other with a clear error, NOT silent alias).
- Update README command matrix + `--help` texts accordingly (DEV-012 does the prose sweep;
  this task makes help text true).

## Out of Scope

- No api behavior changes (api is the reference; CLI conforms to it).
- No new commands (bundle is DEV-014).
- No scan-report schema file (good-first-issue candidate).

## Existing Architecture to Reuse

- `api.check_file/check_dir/repair/verify`; existing repair/verify CLI wrappers
  as the thin-wrapper pattern; `render_json/render_human`; `tests/cli/*`,
  `tests/test_parity.py` (extend or supersede). NOTE: exit mapping is currently CLI-inline
  (`1 if has_error else 0` in cmd_check); there is NO `exit_code_for_report` helper --
  keep the mapping in the thin wrapper (DEV-015 later owns a canonical mapping).

## Files Expected to Change

```text
CREATE: (none expected; extend tests/test_parity.py)
MODIFY: src/sesslint/cli.py (major deletion + thin wrappers + parser hygiene)
        src/sesslint/api.py (dead-branch cleanup only; no behavior change)
        tests/test_parity.py (full-tree differential)
        tests/cli/* (re-pin only where behavior was buggy, e.g. dead branches)
DELETE: (none; validate-session removal counts as MODIFY of cli.py)
```

## Public API / Schema Impact

Backward-compatible: identical reports/exit codes for all documented invocations. Changed:
previously-broken/meaningless inputs now error clearly (`check --policy`, removed
`--salvage-unsupported`, possibly `validate-session`). Each change needs a before/after
note in the completion report for DEV-012.

## Detailed Design

- Thin-wrapper rule: cmd_* functions may contain ONLY arg extraction, api call, render,
  exit mapping, and IO error handling. Any assembled Finding/Report in cli.py is a
  violation (search `make_finding|build_report` in cli.py must return zero hits after).
- Detection-failure JSON: must flow through api's path (valid SL301 report, exit 1);
  add the missing test (`check --json` on undetectable input asserts report shape).
- `scan` decision: if wiring to `check_dir`, keep `--show-limits` and add pathrev
  passthrough with identical JSON shape to `api.check_dir` (no new shape). If removal,
  delete parser + tests + docs references together.
- Deprecation policy: removed flags error with "did you mean --policy salvage"-style
  guidance (clear error, exit 2), never silent ignore.

## Implementation Steps

1. Diff cmd_check vs api.check_file exhaustively; list every divergence + dead branch.
2. Write the full-tree parity test FIRST (against current code; record pre-existing
   divergences as task inputs, not failures).
3. Rewrite cmd_check thin; delete dead branches in cli+api; fix detection-failure JSON.
4. Decide + implement each surface item (scan/validate-session/--policy/--salvage).
5. Update help texts; run CLI + parity + full suites; triage (bugfix-only diffs).

## Required Tests

- Full-tree CLI-vs-API differential (reports byte-equal incl. coverage; exit mapping equal).
- Detection-failure JSON shape test (previously uncovered path).
- Surface tests: removed/meaningless flags error clearly; scan behavior pinned either way.
- Regression: all tests/cli/* + test_parity green.

## Regression Risks

- tests/cli/* expectations that pinned duplicated-logic quirks (e.g. message wording
  differences between CLI and api paths). Triage: api wording wins; re-pin with note.

## Safety / Trust Invariants

- Exit-code contract (0/1/2) unchanged for documented inputs. No stderr leakage of paths
  beyond existing behavior. Fail-closed on ambiguous inputs preserved.

## Performance Constraints

- None (deletion). Suite time must not grow materially (differential test over fixtures
  should stay < 30s; use direct function calls, minimal subprocess).

## Verification Commands

```bash
uv run pytest tests/cli/ tests/test_parity.py -q
uv run pytest tests/test_api_surface.py -q
uv run ruff check src tests && uv run ruff format --check src tests && uv run mypy --strict src/sesslint
uv run pytest -q
```

## Acceptance Criteria

1. `make_finding|build_report` have zero hits in cli.py.
2. Full-tree differential passes over all checkable fixture dirs.
3. Every surface decision implemented + documented (help text true; README matrix updated).
4. Full suite + static gates green.

## Failure Conditions

- Do NOT claim completion if any orchestration duplication remains, if the differential
  skips fixture dirs silently, or if removed flags are silently ignored.
- Do NOT change api behavior to match CLI quirks (direction is CLI -> API).

## Completion Checklist

- [ ] Thin CLI + zero orchestration in cli.py
- [ ] Dead branches deleted + detection-failure JSON tested
- [ ] Surface decisions implemented + help true
- [ ] Differential + suite + gates green

## Gemini Executor Directive

Implement ONLY DEV-010. Diff cmd_check against api.check_file completely before editing.
The API is the reference: CLI conforms to it, never the reverse. Do not implement
subsequent tasks. Add tests with the implementation and run every verification command.
If a CLI quirk has no API equivalent and is load-bearing for a test, report it rather
than preserving the duplication. Do not claim completion while any gate fails.
