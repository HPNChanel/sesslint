# DEV-014 -- Diagnostic bundle + adapter-request flow

## Task Metadata

- Task ID: DEV-014
- Title: Privacy-safe diagnostic bundle command + adapter-request flow (US-016/UC-07)
- Program: NDP-001 "Trustworthy Alpha"
- Milestone: M4
- Status: `complete`
- Recommended Gemini effort: medium
- Dependencies: DEV-001, DEV-005, DEV-006, DEV-007, DEV-008, DEV-010
- Blocks: (none)
- Related opportunity IDs: OPP-012
- Risk level: medium (new CLI surface carrying evidence -- privacy red-team required)
- Compatibility classification: BACKWARD_COMPATIBLE (new command + new issue template)
- `CONTRIBUTOR_FRIENDLY = NO`

## Repository Baseline

No support artifact exists: users hand-assemble reports; US-016's adapter-request template
exists nowhere (only `.github/ISSUE_TEMPLATE/bug_report.md` + `config.yml`). Building
blocks ready: `api.check_file` JSON reports (with coverage after DEV-005, byte offsets
after DEV-006), version block (`get_version_info`), detection evidence (SL301 findings +
`to_source_block`), thin CLI pattern (DEV-010).

## Objective

`sesslint bundle <path>` emits a single privacy-safe support artifact (report + versions +
detection evidence + fixture skeleton), and the repo gains an adapter-request issue
template + docs so unsupported-format/version encounters convert into actionable requests.

## User / Maintainer Value

Directly serves DV-001..DV-004 (external runs, contributed fixtures, maintainer value,
integrations): the bundle is what users paste into issues; the template is what turns
"unsupported version" into an adapter pipeline.

## Why Now

M4 demand-validation: contracts are honest (M2) and repair is usable (M3); now lower the
cost of the first external interaction to near zero.

## Scope

- `api.build_bundle(path, ...) -> Bundle` + `sesslint bundle <path> [--out FILE] [--json]`
  thin wrapper. Bundle JSON: `{bundle_version, created_by (tool+versions, NO host/user
  info), source: {path basename ONLY (no dirs), size, sha256}, detection, report
  (full check JSON incl. coverage), fixture_skeleton}`.
- `fixture_skeleton`: a content-free structural stub (record count, code histogram,
  shape outline) + a commented template the user can fill with SYNTHETIC records --
  never raw content, never real ids verbatim (hash long ids per existing renderer rule).
- Adapter-request flow: `.github/ISSUE_TEMPLATE/adapter_request.md` (asks for bundle
  output + shape description + version evidence) + `config.yml` entry + README/docs
  section ("Requesting adapter support") + CLI hint: detection-failure/unsupported-version
  stderr gains one line pointing at `sesslint bundle` (no behavior change otherwise).
- Privacy red-team: secret-seeded + PII-laden hostile sessions across all adapters;
  assert bundle bytes contain zero secrets/PII/raw content/absolute paths/hostnames.

## Out of Scope

- No auto-upload, no network, no telemetry (bundle is a local file; user pastes it).
- No fixture GENERATOR that synthesizes records from real ones (skeleton template only;
  automated content-stripping is a future minimizer-adjacent feature, OPP-020).
- No `scan`-level bundling (single path only).

## Existing Architecture to Reuse

- `api.check_file`, `get_version_info`, detection SL301 + `to_source_block`, Report JSON,
  renderer redaction rules (`_redact_id_like`, forbidden keys), thin CLI wrappers,
  `tests/privacy/*` conventions, existing issue template style.

## Files Expected to Change

```text
CREATE: src/sesslint/bundle.py
        tests/test_bundle.py
        tests/privacy/test_bundle_privacy.py
        .github/ISSUE_TEMPLATE/adapter_request.md
        fixtures/bundle/hostile_pii.jsonl (+PROVENANCE coverage)
MODIFY: src/sesslint/api.py (export build_bundle)
        src/sesslint/cli.py (bundle parser + thin wrapper + stderr hint)
        src/sesslint/__init__.py (export, if api surface warrants)
        .github/ISSUE_TEMPLATE/config.yml
        README.md (bundle + adapter-request section)
DELETE: (none)
```

## Public API / Schema Impact

Additive: new api function + CLI command + issue template. Bundle JSON has its own
`bundle_version: "sesslint.bundle/v1"` string (no schemas/ file required in this task;
schema file is a follow-up note -- keep the format minimal and documented in code).

## Detailed Design

- `Bundle` frozen dataclass with `to_dict()` (sorted keys, same canonical JSON discipline).
  `source.path` MUST be basename-only (prove: absolute-path input yields basename).
  `source.sha256` of raw bytes (lets maintainers match re-runs without content).
- `fixture_skeleton`: `{record_count, kinds: {kind: n}, codes: [emitted codes],
  template: <commented JSONL skeleton with synthetic placeholders>}`. Template records use
  obviously-fake ids (`evt_example_1`) + a header comment explaining synthetic-only rules
  with a pointer to FIXTURES.md.
- Determinism: same input bytes -> byte-identical bundle (no timestamps inside; `created_by`
  holds versions only). Test: run twice, byte-compare.
- CLI hint: on detection failure / SL301-unsupported, stderr appends:
  `hint: run 'sesslint bundle <path>' and attach the output to an adapter request`.
  One line, both human and JSON-human paths (NOT inside JSON stdout).
- Size bounds: bundle of a capped stream stays bounded (reuse stream caps; skeleton is O(1)).

## Implementation Steps

1. Read api.check_file, version info, detection evidence, renderer redaction, privacy tests.
2. Implement bundle.py + api export + determinism unit tests.
3. Implement CLI wrapper + hint; add issue template + config + README section.
4. Build hostile PII/secret fixtures; write red-team tests (CLI + api paths).
5. Full suite + gates.

## Required Tests

- Unit: determinism (byte-identical), basename-only, size/hash correctness, skeleton shape.
- Privacy red-team: secrets (all SECRET_PATTERNS), PII prose, absolute paths, hostnames,
  hostile `type` values (DEV-008 shapes must hold inside bundles too).
- Integration: unsupported-version input -> bundle contains detection evidence + hint shown.
- Golden: one bundle JSON golden (structure proof).
- Regression: existing CLI/api suites (hint is stderr-only; JSON stdout untouched).

## Regression Risks

- CLI stderr text changes (hint) may break stderr-matching tests -- re-pin narrowly.
- api export list changes (`__all__`) -- update `tests/test_api_surface.py` deliberately.

## Safety / Trust Invariants

- Bundle is a redistribution of evidence: inherits content-free discipline; basename-only
  paths; no host/user/env info; deterministic; local-only (no network calls added --
  offline gate must still pass with the new command exercised).

## Performance Constraints

- Bundle cost ~= one check run + O(findings) shaping. No bench target change.

## Verification Commands

```bash
uv run pytest tests/test_bundle.py tests/privacy/test_bundle_privacy.py tests/cli/ -q
uv run pytest tests/accept/test_offline.py -q
uv run ruff check src tests && uv run ruff format --check src tests && uv run mypy --strict src/sesslint
uv run pytest -q
```

## Acceptance Criteria

1. Byte-identical bundles across runs; basename-only; hash correct.
2. Red-team green: zero secret/PII/content/path/host bytes in bundle output.
3. Adapter-request template + docs + CLI hint all present and cross-linked.
4. Full suite + static gates green; offline gate green with bundle exercised.

## Failure Conditions

- Do NOT claim completion if any red-team secret appears, if bundles embed timestamps/
  absolute paths, if JSON stdout changed, or if any network call was added.
- Do NOT auto-generate synthetic records from real content (skeleton only).

## Completion Checklist

- [x] bundle.py + api/CLI + determinism proof
- [x] Fixture skeleton + template text
- [x] Red-team green; golden pinned
- [x] Template + docs + hint; suite + gates green

## Gemini Executor Directive

Implement ONLY DEV-014. Read the check API, version info, detection evidence, redaction
rules, and privacy conventions before editing. The bundle redistributes evidence: every
privacy rule applies twice. Preserve all other contracts. Do not implement subsequent
tasks. Add tests with the implementation and run every verification command. Do not claim
completion while any red-team case leaks or any gate fails.
