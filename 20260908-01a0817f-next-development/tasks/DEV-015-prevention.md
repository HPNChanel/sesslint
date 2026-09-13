# DEV-015 -- Prevention API + GitHub Action + pre-commit

## Task Metadata

- Task ID: DEV-015
- Title: One-call prevention API + GitHub Action + pre-commit hook
- Program: NDP-001 "Trustworthy Alpha"
- Milestone: M4
- Status: `complete`
- Recommended Gemini effort: medium
- Dependencies: DEV-001, DEV-010
- Blocks: (none)
- Related opportunity IDs: OPP-013
- Risk level: low (thin wrappers + config; no engine changes)
- Compatibility classification: BACKWARD_COMPATIBLE (additive API + new CI assets)
- `CONTRIBUTOR_FRIENDLY = YES`

## Repository Baseline

Engine is usable interactively and via `api.check_file`, but there is no one-call
pre-resume/pre-request gate, no CI action, no pre-commit hook (DEMAND Phase 2 unstarted;
DV-004 needs integrations). Enablers: zero-dependency install, stable exit codes,
JSON reports with coverage (DEV-005), thin CLI (DEV-010). CI lives in
`.github/workflows/ci.yml` (3 OS x 2 Python).

## Objective

Integrators can gate on SessLint in one line: `sesslint.precheck(path)` in Python,
`sesslint-action` in GitHub workflows, a pre-commit hook for session files -- with the
action dogfooded on this repo's own fixtures.

## User / Maintainer Value

Cheapest DV-004 path (external CI use); turns SessLint from a forensic tool into a
prevention gate (pre-resume, pre-request, pre-compaction narrative from DEMAND Phase 2).

## Why Now

M4: the machine contract (coverage, exit codes, fingerprints) is final after M2/M3.

## Scope

- `sesslint.precheck(path, *, profile=None, format=None) -> PrecheckResult`
  (`ok: bool, reason: str (closed vocab), report: Report | None, exit_code: int`):
  one call wrapping check_file + exit mapping; exceptions documented (never raises on
  findings; raises typed errors only on IO/usage failures). Export in `__init__.py`.
- `action.yml` (composite, repo root `.github/actions/sesslint-check/`): inputs
  (path, profile, format, fail-on: error|warning), runs `pipx run` or `uvx`-free path?
  Decide for zero-assumption runners: recommend `pip install sesslint==<ver>` + `sesslint
  check` (PyPI-unpublished TODAY -- action must support `ref:` source-install fallback and
  document that PyPI install activates on first release; do NOT publish to PyPI in this task).
- `.pre-commit-hooks.yaml` offering a `sesslint-check` hook (local + entry passthrough).
- Docs: README "CI & pre-commit" section + docstring guide for precheck (pre-resume /
  pre-request / pre-compaction call sites with copy-paste snippets).
- Dogfood: CI job running the action against `fixtures/` (expect pass on healthy subset,
  expect-fail matrix on corrupt subset to prove the gate bites).

## Out of Scope

- No PyPI publish, no marketplace listing (follow-ups; document as such).
- No editor plugins, no daemon/watch mode.
- No engine/detector changes of any kind.

## Existing Architecture to Reuse

- `api.check_file` (returns Report; exit mapping is currently CLI-inline -- precheck
  defines the canonical mapping from Report severities), Report JSON, version info;
- `.github/workflows/ci.yml` job patterns; fixture healthy/corrupt subsets
  (fixtures/cli/check_basic, fixtures/checks/*healthy*, fixtures/io/*tear*).

## Files Expected to Change

```text
CREATE: src/sesslint/precheck.py (or api addition -- smallest: new module re-exported)
        tests/test_precheck.py
        .github/actions/sesslint-check/action.yml
        .pre-commit-hooks.yaml
MODIFY: src/sesslint/__init__.py (exports)
        src/sesslint/api.py (only if precheck lives there instead of a module)
        .github/workflows/ci.yml (dogfood job)
        README.md (CI & pre-commit section)
        tests/test_api_surface.py (new exports)
DELETE: (none)
```

## Public API / Schema Impact

Additive: `precheck` + `PrecheckResult`. Reason vocabulary closed + documented
(`clean`, `findings-error`, `findings-warning`, `detection-failed`, `io-error`,
`usage-error`). No existing signature changes.

## Detailed Design

- `PrecheckResult`: frozen dataclass; `report` is the full Report on any completed check
  (even failing), None only when no check ran (io/usage/detection failure -- detection
  failure SHOULD still include the SL301 report: decide `report` present with reason
  `detection-failed`; document).
- `ok` semantics: True iff exit_code == 0 (clean). `fail_on_warning` param? Keep minimal:
  `ok` follows exit codes; integrators branch on `reason`. No extra knobs.
- Action: composite steps (setup-python, install from ref-or-PyPI with fallback order:
  explicit `package:` input defaulting to PyPI `sesslint`, plus `source-ref` input for
  source install; run check with `--format/--profile` passthrough; map exit codes to
  step outcome with `fail-on` input). Pin action's own runner deps; test the action YAML
  parses (yamllint-ish via python yaml if available in dev group? else careful review +
  CI dogfood IS the test).
- Dogfood job: matrix over 3 healthy fixtures (must pass) + 3 corrupt fixtures (must fail
  with expected codes); uses the local action (`./.github/actions/sesslint-check`).
- Docs snippets: pre-resume (`if not precheck(p).ok: abort_resume(...)`), pre-request,
  pre-compaction -- each 5 lines, copy-paste, using only the new API.

## Implementation Steps

1. Read api.check_file, exit mapping, __init__ exports, api-surface test, ci.yml.
2. Implement precheck + PrecheckResult + export + unit tests (all reasons).
3. Write action.yml + pre-commit config + README section.
4. Add dogfood CI job (healthy/corrupt matrix).
5. Validate YAML by parsing (python -c yaml) + full suite + gates. (Cannot run GH Actions
   locally; correctness via parse + job review + dogfood on push.)

## Required Tests

- Unit: precheck reason matrix (clean/error/warning/detection-fail/io-fail) incl. report
  presence rules; never-raises-on-findings.
- Config: YAML validity is verified via `uv run --with pyyaml` (PyYAML is NOT a repo
  dev dependency -- do not add it to pyproject; the one-off `--with` run keeps the
  lockfile clean) + a committed test asserting required top-level keys by minimal
  stdlib text scan (key presence, not full parse) so CI typos fail locally even
  without PyYAML installed.
- Dogfood job definition exists with the 6-fixture matrix (reviewed, not executed here).
- Regression: api-surface test updated deliberately.

## Regression Risks

- `__init__` export changes. None to engine (untouched).

## Safety / Trust Invariants

- precheck inherits check's read-only posture (no writes, no network). Action installs
  pinned versions only (no floating `main` default for the PACKAGE; source-ref is opt-in).

## Performance Constraints

- precheck overhead ~= check_file. No bench impact.

## Verification Commands

```bash
uv run pytest tests/test_precheck.py tests/test_api_surface.py -q
uv run --with pyyaml python -c "import yaml; [yaml.safe_load(open(p)) for p in ['.github/actions/sesslint-check/action.yml','.pre-commit-hooks.yaml']]; print('yaml-ok')"
uv run ruff check src tests && uv run ruff format --check src tests && uv run mypy --strict src/sesslint
uv run pytest -q
```

## Acceptance Criteria

1. precheck reason matrix green incl. never-raises-on-findings.
2. Both YAML files parse + required-keys test green.
3. Dogfood job present in ci.yml with healthy/corrupt matrix.
4. Full suite + static gates green.

## Failure Conditions

- Do NOT claim completion if precheck can raise on findings, if YAML is unparsed, if the
  action defaults to floating/unpinned installs, or if any engine file was touched.
- Do NOT publish to PyPI or the marketplace.

## Completion Checklist

- [x] precheck + reasons + tests
- [x] action.yml + pre-commit + README
- [x] Dogfood job + YAML tests
- [x] Full suite + gates green

## Gemini Executor Directive

Implement ONLY DEV-015. Read the check API, exit mapping, exports, and ci.yml before
editing. This task adds integration surface ONLY -- do not touch engine behavior. Do not
implement subsequent tasks. Add tests with the implementation and run every verification
command. Do not claim completion while any gate fails.
