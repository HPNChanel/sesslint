# DEV-016 -- Shared adapter conformance + contributor guide

## Task Metadata

- Task ID: DEV-016
- Title: Cross-adapter conformance suite + adapter contributor guide
- Program: NDP-001 "Trustworthy Alpha"
- Milestone: M4
- Status: `complete`
- Recommended Gemini effort: medium
- Dependencies: DEV-001, DEV-007, DEV-008
- Blocks: (none)
- Related opportunity IDs: OPP-014
- Risk level: low (tests + docs; no product behavior change expected)
- Compatibility classification: INTERNAL_ONLY (tests + docs)
- `CONTRIBUTOR_FRIENDLY = YES`

## Repository Baseline

FR-102 conformance is scattered: `tests/harness/conformance.py` covers stream-level cases
(SL001/SL002 via io only); `tests/conformance/test_matrix.py` asserts exit codes over a
small matrix; per-adapter suites (`tests/adapters/`) each invent their own coverage. No
single suite runs THE SAME cases against every adapter; CONTRIBUTING has no adapter path;
real-shape depth is unmeasured (open fidelity questions: `sourceToolAssistantUUID`,
record-type vocabulary, summary/compaction records -- noted from secondary research,
unverified). DEV-007/008 finalize adapter evidence behavior this suite pins.

## Objective

One parametrized conformance suite executed per adapter (same cases, same assertions)
plus a `docs/ADAPTER_GUIDE.md` that takes a first contributor from zero to a passing new
adapter skeleton run.

## User / Maintainer Value

The first-contributor door for adapters (OSS_CONTRIBUTOR_LEVERAGE); a quality floor
preventing the next adapter from reintroducing RVW-016-class fidelity gaps; the
evidenced on-ramp for OPP-017/018 when demand arrives.

## Why Now

M4 contributor readiness; pins post-M2 adapter behavior (DEV-007/008) so later work
cannot silently regress it.

## Scope

- `tests/conformance/` suite parametrized over (canonical, claude-code-jsonl,
  openai-agents) with shared cases: source immutability (input bytes identical after
  check), unknown-version fail-closed + version evidence, parallel tool-call pairing,
  default-report privacy (secret seeds), canonical round-trip determinism (same bytes ->
  same events + same findings twice), detection confidence sanity (each adapter detects
  its own fixtures above threshold, rejects others' below), synthetic-id namespace
  (DEV-007: no `rec_` leaks), discriminator shapes (DEV-008).
- Case table is DATA (list of fixture + expectations), not per-adapter code; adding an
  adapter = adding a row + loader entry point. Prove it: include a worked example adding
  a fake fourth adapter row in a TEST (not product code) that passes/fails appropriately.
- `docs/ADAPTER_GUIDE.md`: interface contract (detect/load function shapes, version sets,
  SL301/SL302 rules incl. the DEV-008 allowlist, scope/side-effect stamping, PROVENANCE
  rules), fixture recipe (dirs, seeds, real-shape capture hygiene: shapes only, zero real
  data), "run the conformance suite" commands, version-bump checklist, fidelity backlog
  table (known open questions incl. sourceToolAssistantUUID, record-type vocab -- marked
  UNVERIFIED/secondary until primary research lands).
- Wire the suite into CI gates explicitly (ci.yml conformance step already runs
  tests/conformance/ -- extend the step or keep; ensure the new cases run there).

## Out of Scope

- No new adapter, no adapter behavior changes (failures found -> report as bugs against
  the owning area; fix ONLY if trivially a test-harness bug, else report).
- No primary upstream research (that's OPP-017/018/019; the guide marks unknowns honestly).
- No plugin/registry framework for adapters (explicit non-goal; data table only).

## Existing Architecture to Reuse

- `tests/harness/conformance.py` (extend the pattern), `tests/conformance/test_matrix.py`,
  adapter `detect_*`/`load_*` signatures, `SUPPORTED_*_VERSIONS` sets, `_safe_type_value`
  discipline, `tests/privacy/*` seed conventions, FIXTURES.md, ci.yml gates step.

## Files Expected to Change

```text
CREATE: tests/conformance/test_adapter_suite.py (or equivalent; data-driven)
        docs/ADAPTER_GUIDE.md
        fixtures/conformance/<case-dirs> (+PROVENANCE.json each)
MODIFY: tests/conformance/test_matrix.py (only if subsumed -- prefer keep + extend)
        .github/workflows/ci.yml (only if the conformance step needs the new path)
        CONTRIBUTING.md (link the guide as the adapter path)
DELETE: (none)
```

## Public API / Schema Impact

None (tests + docs).

## Detailed Design

- Suite shape: `ADAPTERS = {id: (detect_fn, load_fn, fixture_dir)}`; `CASES = [...]` each
  with `name, fixture, adapter_expectations` (per-adapter expected codes/exit/behavior --
  adapters legitimately differ; the TABLE documents the differences instead of hiding
  them in code). Shared assertions where semantics are universal (immutability, privacy,
  determinism); per-adapter expectations where formats differ (codes, strictness).
- Immutability proof: sha256 of fixture bytes before/after `check` via api AND CLI.
- Determinism proof: load+check twice -> identical event id sequences + finding
  fingerprints (uses DEV-003/004 final semantics).
- Privacy proof: secret-seeded fixture per adapter -> JSON report contains zero secrets
  (reuse SECRET_PATTERNS + scanners).
- Fake-fourth-adapter test: a minimal stub loader row proving the table-driven design
  (passes shared assertions trivially or fails loudly -- either proves extensibility
  without product code).
- Guide: every command copy-paste runnable; every contract statement linked to code
  symbol + test file; fidelity backlog table with columns (question, status, evidence
  needed) -- no upstream claim without a primary source (mark secondary ones).

## Implementation Steps

1. Read harness, matrix test, all three adapter interfaces + version sets + privacy tests.
2. Design the CASES table (coverage: the 8 case families above); review table against
   FR-102 wording.
3. Implement suite + fixtures + fake-adapter extensibility proof.
4. Write ADAPTER_GUIDE.md; execute every command in it verbatim.
5. Link from CONTRIBUTING; confirm CI runs the suite; full suite + gates.

## Required Tests

- The suite ITSELF is the deliverable test asset (8 families x 3 adapters + fake-row proof).
- Guide-command execution evidence in the completion report.
- Regression: existing adapter/conformance suites untouched and green.

## Regression Risks

- Suite may EXPOSE adapter bugs (good -- report, don't fix here, unless harness bug).
  Existing suites must stay green (no product edits).

## Safety / Trust Invariants

- Conformance asserts the trust model (immutability, fail-closed versions, privacy) --
  the suite is a safety asset, not just coverage.

## Performance Constraints

- Suite must run in < 60s total (fixture-scale inputs only, no bench data).

## Verification Commands

```bash
uv run pytest tests/conformance/ -q
uv run pytest tests/adapters/ tests/privacy/ -q
uv run ruff check src tests && uv run ruff format --check src tests && uv run mypy --strict src/sesslint
uv run pytest -q
```

## Acceptance Criteria

1. 8 case families x 3 adapters green + fake-fourth-row proof green.
2. ADAPTER_GUIDE.md complete with every command executed verbatim (evidence recorded).
3. CI runs the suite (job/step verified by reading ci.yml + a local run of the same command).
4. Full suite + static gates green; zero product-code behavior changes.

## Failure Conditions

- Do NOT claim completion if any case family is missing, if the fake-row proof is absent,
  if guide commands were not executed, or if adapter bugs found were silently fixed here
  (report them).
- Do NOT build an adapter plugin framework.

## Completion Checklist

- [x] Data-driven suite + fixtures + fake-row proof
- [x] ADAPTER_GUIDE.md + executed commands + fidelity backlog
- [x] CONTRIBUTING link + CI wiring verified
- [x] Full suite + gates green, no product diffs

## Gemini Executor Directive

Implement ONLY DEV-016. Read the harness, matrix test, adapter interfaces, and privacy
conventions before designing the table. Tests + docs only: found adapter bugs get
reported, not fixed here. Preserve every contract. Do not implement anything beyond this
task. Run every verification command. Do not claim completion while any case family is
missing or any gate fails.
