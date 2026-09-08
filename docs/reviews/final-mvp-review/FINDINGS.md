# SessLint MVP Final Review — Findings

46 findings: S1 x5, S2 x20, S3 x17, S4 x4. All release-blocking flags are explicit.
"Planning-derived" marks defects where a TASK file (or the plan tree) specified or
blessed behavior contradicting `DEMAND.md`; per the authority order the CODEBASE is
still judged against `DEMAND.md`.

Conventions: file paths are repo-relative. Line numbers refer to the reviewed
checkout. No shell was available in this review environment (see
`TEST_EVIDENCE.md`), so every "Reproduction" below is a static procedure plus the
exact runtime command to confirm once execution is possible; nothing below was
executed by the reviewer.

---

## RVW-001

## Title

Canonical session format is fractured into mutually incompatible dialects; `check`
cannot read repair output and the published schema rejects the implementation's
own fixtures and writer output.

## Severity

`S1 — CRITICAL`

## Confidence

`HIGH`

## Category

specification compliance; correctness; adapter

## Specification references

FR-034, FR-035, FR-036, FR-070, AC-007, AC-015, AC-016, AC-029

## Location

- `src/sesslint/adapters/canonical.py:280-300` (`dump_canonical`), `:328-532`
  (`load_canonical`, requires `schema|schema_version` + `version` + `events`)
- `src/sesslint/canonical.py` (`parse_session`/`parse_session_lines`/
  `dump_session`: `schema_version`+`session_id` flat/framed docs and JSONL
  header-line framing)
- `src/sesslint/io.py` (`iter_events`/`read_header`: JSONL framing)
- `src/sesslint/repair/executor.py` (writes `dump_session` JSONL; revalidates
  in-memory only, never re-parses output bytes through the declared adapter)
- `schemas/sesslint.session.v1.json:6-67` (single-doc only; requires
  `schema_version`+`session_id`+`created_at`+`events` or `header`+`events`)
- `fixtures/canonical/minimal.json` (adapter dialect `schema`/`version`/
  `events`/`source`)

## Observed behavior

Three mutually unreadable shapes share the single name `sesslint.session/v1`:

1. Adapter dialect (single JSON doc): `{"schema","version":1,"events","source"}`.
   Written by `dump_canonical`, read by `load_canonical` (used by `check`,
   `api.check_file`, repair fallback for single-doc inputs).
2. JSONL dialect (header line + one event per line). Written by `dump_session`
   (used by repair output), read by `io.iter_events` and
   `canonical.parse_session_lines` (used by repair input).
3. Published-schema dialect (`schemas/sesslint.session.v1.json`): single-doc
   flat (`schema_version`/`session_id`/`created_at`/`events`) or framed
   (`header`/`events`). Read by nothing in production; matched by nothing the
   implementation writes.

Consequences verified by code reading:

- `load_canonical` calls `JSONDecoder.decode` on the whole file, which parses
  only the FIRST JSON value and ignores trailing lines. On repair output
  (JSONL), `doc` becomes the header line, which lacks `version`/`events`, so
  `check <repair-output>` returns SL001 `missing_version_key`/
  `missing_events_key` and exit 1. The check -> repair -> check loop is broken.
- `minimal.json` (the repo's own "minimal valid fixture") fails the published
  schema (missing required `schema_version`/`session_id`/`created_at`, fails
  both `oneOf` branches). So does every `dump_canonical` output.
- Conversely a schema-valid doc (with `schema_version` but no `version`) fails
  `load_canonical` with SL001 `missing_version_key`.
- `bench/perf_250k.py` runs `api.check_file` on a JSONL file and prints the
  (SL001) report without asserting on it, silently tolerating this split.
- No test feeds JSONL-canonical to `load_canonical` or validates
  `dump_canonical` output against the published schema
  (`tests/adapters/test_canonical.py` never mentions JSONL).

## Expected behavior

Per FR-034/035/036: one versioned neutral schema, loadable files, and a
machine-readable schema that describes what the implementation reads and writes.
Per FR-070, the repaired copy is "parsed and validated again" using the declared
adapter — which requires the repaired bytes to be parseable by that adapter.

## Evidence

- `adapters/canonical.py:494-518`: requires `version` + `events` keys.
- `adapters/canonical.py:455` (`decode` of whole text) + stdlib semantics
  (`JSONDecoder.decode` ignores trailing content).
- `canonical.py` header/event required-field sets use `schema_version`, never
  `schema`/`version`.
- `schemas/sesslint.session.v1.json:10,50` (`required` lists).
- `fixtures/canonical/minimal.json:26-30` (`schema` + `version`, no
  `schema_version`/`session_id`/`created_at`).
- `tests/accept/test_healthy.py`: healthy canonical fixtures are single-doc
  only; no JSONL-canonical check coverage.

## Reproduction

1. `sesslint repair fixtures/repair_cli/basic/source.jsonl --output /tmp/r.jsonl`
   (succeeds; writes JSONL).
2. `sesslint check /tmp/r.jsonl` -> SL001 `missing_version_key`/
   `missing_events_key`, exit 1 (predicted from code; runtime unconfirmed —
   no shell in review env).
3. `jsonschema -s schemas/sesslint.session.v1.json -i
   fixtures/canonical/minimal.json` -> invalid (predicted; same caveat).

## Impact

Operators cannot re-check repaired artifacts; the published schema is false
documentation; fixtures validate a dialect the schema forbids. Breaks the core
UC-04 verification loop and AC-029 golden-schema claims.

## Root cause

Planning-derived: TASK-002 specifies JSONL framing with `schema_version` while
TASK-010 specifies single-doc with `schema`/`version`; both were implemented
literally and never reconciled. The schema file follows a third shape.

## Required remediation

Nominate ONE canonical serialization (DEMAND favors a loadable file form);
make `load_canonical`, `dump_canonical`, `parse_session`, `dump_session`,
`iter_events`, the published schema, and all fixtures agree on it; make repair
output re-checkable; validate writer output against the published schema in CI.

## Required regression test

Round-trip test: `dump_canonical`/`dump_session` output validates against
`schemas/sesslint.session.v1.json`, parses via `load_canonical`, and
`check(repair(x))` succeeds for a repaired fixture.

## Release blocking

`YES`

---

## RVW-002

## Title

End-to-end repair is non-functional except for adjacent byte-identical SL003
duplicates: detectors emit `manual`/`unsupported` for every other code while the
planner blocks those values before recipe matching.

## Severity

`S1 — CRITICAL`

## Confidence

`HIGH`

## Category

correctness; repair; testing

## Specification references

FR-055, FR-056, FR-057, FR-058, FR-060, FR-061, UC-03, UC-04, AC-007, AC-008, AC-016

## Location

- `src/sesslint/repair/planner.py:370-405` (repairability gate blocks
  `manual`/`unknown`/other before recipe matching)
- `src/sesslint/checks/graph.py` (SL004->manual, SL005->unsupported,
  SL006->manual), `tool_pairing_1.py` (SL101-104->manual),
  `tool_pairing_2.py` (SL105-108->manual), `checkpoint.py` (SL201/202/203->
  manual), `identity.py:264` (only non-manual override: identical SL003->
  deterministic)
- `src/sesslint/codes.py` (SL002 default deterministic but no recipe handles
  SL002)
- `src/sesslint/repair/recipes_conservative.py`,
  `src/sesslint/repair/recipes_salvage.py` (8 recipes, 7 unreachable via planner)
- `fixtures/repair_cli/basic/source.jsonl` + `tests/accept/test_offline.py:50`
  (only E2E repair test: adjacent identical SL003, tool-free session)

## Observed behavior

The planner blocks findings with repairability `manual`/`unknown`/
`unsupported` before consulting the registry. Every detector emits `manual`
(resp. `unsupported` for SL005) unconditionally, except identical-duplicate
SL003 (deterministic). Therefore via any real CLI/API flow:

- SL004/SL005/SL006/SL101-108/SL201-203 findings can never produce plan steps;
  7 of 8 recipes (parent-restore, suffix-discard, reunion, projection-removal,
  amputate, torn-project, truncate) are dead end-to-end.
- SL002 (torn tail) is classified deterministic but has no registered recipe,
  so the DEMAND-eligible "discard incomplete terminal byte suffix" repair does
  not exist; `torn_final.jsonl` is marked `repairable:true` in
  `fixtures/hostile/EXPECTATIONS.json` yet repair refuses it (`no-recipe`).
- Unit tests exercise recipes with hand-made findings carrying
  deterministic/lossy repairability, so the suite passes while E2E repair of
  every other fault class refuses. The sole E2E repair test uses adjacent
  identical duplicates in a tool-free session — the one live path.
- A second, independent kill-switch: no adapter or parser ever stamps
  `side_effects`, so `must_abstain` fires on ANY session containing tool events
  and the executor refuses even the SL003 path whenever tool events exist.

## Expected behavior

Per UC-04/AC-007/AC-008/FR-055-061, repair plans real detector output for the
registered recipe set (including an adapter-visible SL108 case and a salvage
path), with repairability reflecting per-finding auto-repair eligibility.

## Evidence

- Exhaustive `repairability=` search over `src/sesslint/checks/`: the only
  deterministic emission is `identity.py:264`.
- `planner.py:370-405` gate precedes `recipes_for` matching (`:408`).
- `recipes_for("SL002")` is empty (no recipe lists SL002 in `handles`).
- `tests/accept/test_offline.py` + `fixtures/repair_cli/basic/source.jsonl`
  (lines 3-4 identical) = single E2E success path.
- `policy/abstention.py`: `raw_se is None` (never stamped) -> abstain reason.

## Reproduction

1. Build a canonical JSONL session with an SL004 (missing parent) plus an
   otherwise healthy graph.
2. `sesslint repair src --output out --dry-run --json` -> finding blocked
   `repairability-manual`, zero steps (predicted from code).
3. Same for SL104/SL108/SL102-under-salvage: zero steps in every case.

## Impact

The MVP's headline repair capability (UC-04) does not work for real inputs
beyond duplicate-message collapse; AC-007/AC-008 salvage-success halves fail;
the suite creates false confidence via hand-made findings.

## Root cause

Planning-derived and integration: TASK-018 pins planner vocabulary
(`safe-auto`/`salvage`) while TASK-012..017 pin detectors to DEMAND vocabulary
with `manual` defaults; no task specified the per-instance repairability
override that must bridge them. Additionally nothing stamps `side_effects`.

## Required remediation

Define and implement per-finding repairability overrides at detection time
(safe-auto only when the recipe's machine-checked preconditions provably hold),
add the missing SL002 byte-suffix recipe, stamp or formally default
`side_effects`, and add detector->planner->executor integration tests for every
recipe (no hand-made findings).

## Required regression test

For each of the 8 recipes: raw input file -> `check` emits the finding ->
`repair --dry-run` plans exactly that recipe -> `repair` succeeds -> `verify`
passes -> `check` on output is clean of that code.

## Release blocking

`YES`

---

## RVW-003

## Title

Repair plans are not bound to source bytes: the planner records an events-hash,
test fixtures assume a file-hash, and the executor never compares either.

## Severity

`S1 — CRITICAL`

## Confidence

`HIGH`

## Category

repair; filesystem safety; correctness

## Specification references

FR-062, FR-063, AC-011

## Location

- `src/sesslint/repair/planner.py` (`plan()`: `source_hash =
  compute_events_source_hash(events)` when caller omits it; CLI at
  `cli.py:926` omits it)
- `src/sesslint/repair/executor.py:341-395` (fingerprint self-consistency only;
  no `plan.source_hash` vs `source_pre_hash` comparison anywhere in file)
- `fixtures/repair/exec_basic/plan.json:12`, `tests/test_verify.py:78`
  (`source_hash` = file-bytes hash in fixtures/hand-written plans)

## Observed behavior

- FR-062 requires binding to the exact source SHA-256 plus adapter/profile/
  tool versions. Plans carry an events-derived hash (re-serialization of parsed
  events) and a profile NAME only. Test/hand-written plans instead carry the
  file-bytes hash. Both shapes "work" because nothing compares them.
- `execute()` verifies only fingerprint SELF-consistency
  (`compute_plan_fingerprint(plan_dict) == plan.fingerprint`), which prevents
  plan tampering but not plan misapplication: a valid plan produced for file A
  applies cleanly to unrelated file B (given matching finding fingerprints for
  targeted steps, or index-addressed steps that apply regardless).
- Pre/post source hashing detects mid-repair mutation of one file, but does not
  bind the plan to the file. FR-063 ("MUST not be applied to a source whose
  hash differs from the plan fingerprint") is unimplemented.

## Expected behavior

Plan records source file SHA-256 (+ adapter/profile/tool versions); executor
refuses when the current source hash differs; cross-file plan reuse is
impossible.

## Evidence

- Full read of `executor.py:341-692`: no reference to `plan.source_hash`
  after load; `grep source_hash executor.py` shows only local pre/post vars.
- `cli.py:917-930`: `plan(source_findings, events, ...)` without `source_hash`.
- `fixtures/repair/exec_basic/plan.json:12` vs planner behavior: two
  incompatible semantics, both uncompared.

## Reproduction

1. Plan file A (`--dry-run --json`, save plan). 2. `repair --plan planA.json
   --output outB B` where B differs from A -> executes instead of refusing
   with plan/source mismatch (predicted from code).

## Impact

Stale or foreign plans can be applied to the wrong source; TOCTOU
"changed-source" protection is incomplete; AC-011 plan-binding half fails.

## Root cause

No task wired `source_hash_pinned` (defined in `preconditions.py`, never used
by any recipe or by `execute`) into the execution path; planner and fixtures
diverged on hash semantics.

## Required remediation

Record source file SHA-256 in every plan; compare it to a fresh source hash in
`execute()` before applying steps (and re-check after load); pin the semantic
in one helper used by planner, executor, fixtures, and verify.

## Required regression test

Cross-file plan application refused; mutated-source-after-plan refused even
when the plan fingerprint is valid; fixture hash semantics asserted.

## Release blocking

`YES`

---

## RVW-004

## Title

Salvage and lossy recipes execute under `--policy conservative` via a crafted
plan: no per-step minimum-policy enforcement, unkeyed plan fingerprint, and a
lossy recipe registered as conservative.

## Severity

`S1 — CRITICAL`

## Confidence

`HIGH`

## Category

repair; security; specification compliance

## Specification references

FR-060, FR-061, FR-077, AC-008

## Location

- `src/sesslint/repair/executor.py` (policy check is plan-label-only;
  `salvage_only` never read; step loop applies any registered recipe)
- `src/sesslint/repair/planner.py:505` (lossy flag used only for accounting,
  never to block under conservative)
- `src/sesslint/repair/registry.py` (`Recipe.salvage_only` decorative),
  `fingerprint.py` (unkeyed SHA-256 anyone can recompute)
- `src/sesslint/repair/recipes_conservative.py:519`
  (`terminal-suffix-discard`, `lossy=True`, `salvage_only=False`,
  `handles=(SL005, SL203)`)

## Observed behavior

- `execute()` checks only `plan.policy == policy`. It never checks
  `recipe.salvage_only`, `recipe.lossy`, or any per-step minimum policy
  (PlanStep has no such field, violating FR-061). Salvage gating exists ONLY as
  planner-time preconditions.
- Plan fingerprints are unkeyed SHA-256 over the plan dict: anyone can author
  a self-consistent `policy: conservative` plan containing
  `unresolvable-branch-amputate`, `torn-compaction-project`, or
  `side-effect-unknown-truncate` steps, and `repair --plan` will execute them
  under conservative policy (subject only to each apply function's internal
  structural checks, which do not consult policy).
- Threat shape: an operator applying a third-party/shared plan file with
  `--policy conservative` (the default) silently gets lossy salvage behavior.
- Independently, `terminal-suffix-discard` is registered lossy+conservative
  and handles SL203: lossy repair without salvage authorization (FR-077) and a
  conservative SL203 handler (FR-060) by design. (Unreachable via planner
  today per RVW-002, but reachable via crafted plan since `execute` does not
  re-run preconditions.)

## Expected behavior

Per FR-061/077: every transformation records minimum policy; lossy requires
salvage; the executor enforces per-step policy regardless of plan provenance;
SL203 never flows through a conservative recipe.

## Evidence

- `grep salvage_only|min_policy executor.py planner.py` -> only accounting
  uses; zero enforcement reads.
- `Recipe` dataclass has no `version`/`min_policy` fields.
- `load_plan` + `execute --plan` path performs no precondition re-evaluation.
- TASK-019:30 blesses trigger-based SL203 handling in the conservative pack
  (planning-derived), contradicting DEMAND FR-060/077.

## Reproduction

1. Craft `plan.json` (`policy: conservative`, one `torn-compaction-project`
   step, valid fingerprint). 2. `repair --plan plan.json --output out src`
   with an SL108-bearing source -> executes lossy step (predicted from code).

## Impact

Policy bypass defeats the conservative/salvage trust boundary; shared plan
files become a confused-deputy vector; FR-077 MUST violated by design.

## Root cause

Policy enforced at plan time only; plan treated as trusted input despite being
user-supplied and self-authenticating; recipe metadata lacks enforceable
minimum-policy.

## Required remediation

Add minimum-policy (and version) to recipe metadata and plan steps; enforce
per-step in `execute()` (`salvage_only` steps require salvage even when the
plan label says conservative); re-evaluate policy/safety preconditions at
execution; move `terminal-suffix-discard` to salvage-only or restrict it to
the DEMAND-eligible unparseable-byte-suffix case with hash+length accounting;
treat `--plan` as untrusted input in docs and validation.

## Required regression test

Crafted conservative-labeled plan with salvage steps is refused; every recipe
declares minimum policy; executor tests cover policy matrix (plan x step x
flag).

## Release blocking

`YES`

---

## RVW-005

## Title

Default (non-`--include-content`) outputs can leak source content and absolute
paths: SL302 evidence embeds unknown-field values; remediation strings embed
raw paths; recursive-scan nested findings bypass minimization.

## Severity

`S1 — CRITICAL`

## Confidence

`HIGH`

## Category

privacy; security

## Specification references

FR-081, FR-082, AC-017, AC-028

## Location

- `src/sesslint/adapters/claude_code.py` (SL302 `evidence={"type_value":
  str(obj[key]), ...}`), `openai_agents.py:948`, `canonical.py:870` (same
  pattern)
- `src/sesslint/report.py` (`get_finding_remediation`: f-string embeds
  `f.source.path` raw; used by both `render_json` default and `render_human`)
- `src/sesslint/scan.py` (`FileResult.to_dict`: nested
  `Finding.to_dict()` with raw `source.path`; `OSError` text in evidence)
- `src/sesslint/cli.py` (`format_report_human` "Recommended next command" raw
  path — dead code, same bug class)

## Observed behavior

- Unknown-critical field VALUES (arbitrary JSON, `str()`-ified, including
  nested objects) flow into SL302 `evidence.type_value`, which
  `format_finding_content_free` passes through in default mode (key allowlist
  permits it; only `id`-like long values are shortened). Finding-level
  `enforce_content_free_text` blocks credentials/emails/control chars but not
  general prompt/tool content. A report designed to be shared (UC-07) can carry
  transcript content by default.
- `get_finding_remediation` interpolates the RAW source path
  (`run 'sesslint repair /abs/path ...'`) in default JSON and human output,
  while `span.path` is carefully minimized next to it — the minimization is
  bypassed one field over.
- Recursive scan minimizes the top-level `path` but serializes nested findings
  with raw absolute paths, and puts raw `OSError` strings (which embed paths)
  in finding evidence.
- The repo's secret-seed test (`tests/report/test_content_free.py`) runs
  `check` on a HEALTHY fixture (no findings), so it cannot catch any
  finding-path leak; it is vacuous for this bug class.

## Expected behavior

FR-081/082: no prompt/code/command/output content and no absolute (or
non-minimized) paths in default outputs, including evidence, remediation,
error envelopes, and recursive summaries.

## Evidence

- Evidence construction sites listed above (all three adapters).
- `report.py` remediation builder interpolating `f.source.path`.
- `scan.py` `FileResult.to_dict` using raw `Finding.to_dict()`.
- `tests/report/test_content_free.py:30-47` asserting exit 0 on a healthy
  fixture only.
- README:76 claims reports "are strictly content-free (prompts, code, keys,
  and tokens are scrubbed)" — overclaim given the above.

## Reproduction

1. Craft a Claude JSONL record with an unknown critical field containing a
   canary token. 2. `check --json` -> canary appears in
   `findings[].evidence.type_value` (predicted from code). 3. `check --json`
   with an absolute path on a failing file -> absolute path in
   `findings[].remediation` (predicted).

## Impact

Privacy-contract violation in the default sharing path (support bundles,
CI logs); absolute home paths disclosed; risk of credential-adjacent content
leaving the machine.

## Root cause

Evidence/remediation built from raw source values without minimization;
minimization applied selectively (span/evidence-ids) rather than at the
serialization boundary; secret tests never exercise failing findings.

## Required remediation

Minimize/redact at the report boundary: never emit unknown-field VALUES
(emit field paths + value shapes/hashes only); minimize paths inside
remediation (or drop paths from remediation); minimize nested scan findings;
scrub OSError path text; extend secret-seed tests to failing findings,
remediation, scan, dry-run, manifests, and error envelopes.

## Required regression test

Secret-seeded fixtures for each leak vector asserting token absence in default
JSON/human/scan/manifest outputs, with findings present (not healthy-only).

## Release blocking

`YES`

---

## RVW-006

## Title

Finding sort order contradicts FR-094 and is inconsistent across three code
paths (severity-first vs code-first vs specified position-first).

## Severity

`S2 — HIGH`

## Confidence

`HIGH`

## Category

specification compliance; determinism

## Specification references

FR-045, FR-093, FR-094, AC-019

## Location

- `src/sesslint/finding.py` (`sort_findings`: severity, code, path, line, ...)
- `src/sesslint/report.py` (`finding_report_sort_key`: code, path, line,
  byte, fingerprint — used by `render_json`, silently re-sorting reports)
- `src/sesslint/determinism.py` (`finding_sort_key`: duplicate code-first key)
- `src/sesslint/checks/graph.py` (`_cap_finding_sort_key`: code-first variant)

## Observed behavior

FR-094 mandates position, then severity, then rule code. The implementation
sorts severity-first in `Finding` ordering and code-first in JSON rendering, so
the emitted JSON order matches neither the spec nor the in-memory report order.
"First root finding" (FR-045/FR-085) therefore means different findings in
different surfaces. All orders are deterministic, so AC-019 byte-repeatability
is preserved, but the specified contract is violated.

## Expected behavior

One documented deterministic order — source position, severity, rule code —
used by every surface (in-memory, JSON, human, scan).

## Evidence

Sort-key definitions listed above; `render_json` re-sorts (`report.py`
`render_json` body); TASK-003 pins severity-first while TASK-025/026 pin
code-first — the plan contradicts itself and DEMAND (planning-derived).

## Reproduction

Multi-finding fixture where the earliest-position finding is a warning:
JSON output lists error-code findings first (predicted from code).

## Impact

Contract violation for consumers scripting on finding order; first-finding
semantics unstable across surfaces.

## Root cause

Planning-derived: three task files pin three different orders; implementers
followed different tasks in different modules.

## Required remediation

Implement FR-094 order in one shared helper; delete the duplicates; update
golden snapshots.

## Required regression test

Order-pin test with mixed positions/severities/codes asserting
position->severity->code across `sort_findings`, `render_json`, human, scan.

## Release blocking

`YES`

---

## RVW-007

## Title

Finding fingerprints omit adapter and profile versions required by FR-046, and
two inconsistent fingerprint schemes coexist.

## Severity

`S2 — HIGH`

## Confidence

`HIGH`

## Category

specification compliance; determinism

## Specification references

FR-046, AC-019

## Location

- `src/sesslint/finding.py` (`compute_fingerprint`: code/severity/
  repairability/template/path/line/record_id/related_ids — no versions)
- `src/sesslint/checks/graph.py` (`compute_graph_fingerprint`: code+ids only;
  accepted as-is via explicit `fingerprint=`), same pattern in
  identity/pairing/checkpoint helpers

## Observed behavior

FR-046 requires fingerprints derived from rule ID, adapter/profile version,
and structural coordinates. Neither scheme includes versions; graph-family
fingerprints additionally omit path/line (same fault in different files
collides) while io/adapter fingerprints include severity/repairability (which
can vary by profile for the same structural fault). Planner dedup and
`target_finding_fp` references therefore rest on unstable, version-blind
identity.

## Expected behavior

One fingerprint construction including rule ID, adapter version, profile
version, and structural coordinates.

## Evidence

Function bodies listed above; `make_finding(..., fingerprint=...)` passthrough
(`finding.py` tail); `_version.py` versions never threaded into checks.

## Reproduction

Same session checked under `neutral` vs `claude-strict` yields identical
fingerprints despite different profile versions (predicted from code).

## Impact

Cross-version finding tracking/plan references unreliable; spec violation.

## Root cause

Planning-derived: TASK-003's fingerprint spec omits versions; per-family
helpers invented a second narrower scheme.

## Required remediation

Unify fingerprint construction per FR-046; thread adapter/profile versions
from detection+profile resolution into every finding.

## Required regression test

Fingerprint changes when profile version changes; identical faults in different
files do not collide; planner `target_finding_fp` resolves after re-detection.

## Release blocking

`YES`

---

## RVW-008

## Title

Repair manifest omits plan hash, recipe versions, adapter/profile versions,
final validation report, and assurance; loss accounting lacks byte counts; the
test suite verifies richer manifests than production emits.

## Severity

`S2 — HIGH`

## Confidence

`HIGH`

## Category

specification compliance; repair

## Specification references

FR-061, FR-072, FR-073, AC-015

## Location

- `src/sesslint/report.py` (`RepairManifest`: input/output fingerprints,
  policy, actions, declared_loss, revalidate_report path-or-None,
  idempotency_key)
- `src/sesslint/repair/executor.py` (always passes `revalidate_report=None`;
  `declared_loss` = event-count `k:v` strings only)
- `src/sesslint/repair/registry.py` (`Recipe` has no version field)
- `tests/test_verify.py:95-112` (test manifests carry `assurance` +
  `plan_fingerprint`, which production never emits)
- `src/sesslint/verify.py:377-388` (plan_fingerprint check vacuous without
  the key), `:check 6` (assurance branch vacuous without the key)

## Observed behavior

FR-072 requires binding source hash, plan hash, output hash, recipe versions,
adapter/profile versions, and the final validation report. Production manifests
carry only source/output hashes, policy, action names (no versions), count-only
loss, and a `None` revalidate pointer. FR-073 byte counts and added/changed
classes are absent. `verify`'s plan/assurance checks silently pass on
production manifests via "key absent" branches, while tests exercise manifests
containing those keys — the suite verifies a manifest shape production never
produces. `parse_manifest` (which would reject the test manifests' extra keys
per `test_parse_manifest_unknown_field_raises`) has no production caller; CLI
verify bypasses it.

## Expected behavior

Manifest binds every FR-072 element; loss carries record AND byte counts per
FR-073; verify fails closed on missing bindings; test and production manifest
shapes are identical.

## Evidence

Field lists above; `build_manifest` call sites; `verify.py` vacuous branches;
`grep parse_manifest src/` (definition + export only).

## Reproduction

Successful repair -> inspect `<out>.manifest.json`: no `plan_fingerprint`,
no `assurance`, no versions, `revalidate_report: null` (predicted from code).

## Impact

Manifests cannot detect plan substitution, recipe-version drift, or profile
changes; audit value gutted; AC-015 partial.

## Root cause

Planning-derived: TASK-004's manifest schema omits the bindings while TASK-021
specifies them; implementer followed TASK-004. Recipe versions were never
specified anywhere.

## Required remediation

Extend manifest + `build_manifest` per FR-072/073 (embed validation summary,
not just a path); version recipes and record versions; make verify require the
bindings; unify test/prod shapes; route verify through `parse_manifest`.

## Required regression test

Golden manifest asserting every FR-072/073 field; verify failure when any
binding is stripped; writer/schema conformance test.

## Release blocking

`YES`

---

## RVW-009

## Title

Checkpoint/run-state evidence never reaches the checks: CLI/API convert
`EventList` to `list`, stripping `.source`, so SL201/SL202 cannot compare
serialized state against history (FR-044).

## Severity

`S2 — HIGH`

## Confidence

`HIGH`

## Category

correctness; adapter; replay profile

## Specification references

FR-044, SL201, SL202

## Location

- `src/sesslint/cli.py:755,762,769` (`events = list(can_events)` etc.)
- `src/sesslint/api.py` (same `list(...)` stripping)
- `src/sesslint/adapters/openai_agents.py` (`SourceMetadata` with
  `run_state`/`checkpoints`, attached to `EventList.source`)
- `src/sesslint/checks/checkpoint.py` (in-band checkpoint events only; no
  run-state input)

## Observed behavior

The OpenAI adapter carefully preserves run-state/checkpoints in
`EventList.source`, and every consumer immediately discards it with `list()`.
SL201/SL202 therefore compare checkpoint EVENTS against each other (gaps, seq
jumps, same-seq hash divergence) but never against serialized continuation
state. DEMAND's SL201 ("serialized continuation state and durable records
disagree"), SL202 ("runtime state indicates accepted output the history cannot
recover"), and FR-044 ("when both runtime state and durable history are
provided, MUST validate continuation-step and terminal-output ownership") are
unimplemented despite run-state being provided by the adapter.

## Expected behavior

Run-state flows to the checkpoint rules; SL201/SL202 compare state vs history;
FR-044 ownership validation exists.

## Evidence

Call sites above; `check_checkpoint(events, ...)` signature (no state param);
`run_all_checks` signature (no state param).

## Reproduction

OpenAI export with `run_state` disagreeing with `items` -> no SL201/SL202
about the disagreement (predicted from code).

## Impact

The OpenAI-side headline scenarios (resumption divergence, lost accepted
output) are undetectable; FR-044 fails.

## Root cause

Boundary design: metadata attached to a list subclass that no consumer
preserves; checks designed against events-only input.

## Required remediation

Thread source metadata (or a first-class run-state argument) from adapters
through API/CLI into `run_all_checks`/checkpoint rules; implement FR-044
ownership checks; add state-vs-history fixtures.

## Required regression test

Paired fixtures where identical `items` pass with matching run-state and fail
SL201/SL202 with divergent run-state.

## Release blocking

`YES`

---

## RVW-010

## Title

SL203 is not emitted for the primary unknown-side-effect scenario (dangling
side-effect-capable call with no checkpoint/compaction involvement), violating
FR-060's emission clause.

## Severity

`S2 — HIGH`

## Confidence

`HIGH`

## Category

correctness; detector (SL203)

## Specification references

FR-060, SL102, SL203, AC-008

## Location

- `src/sesslint/checks/checkpoint.py` (`check_unsafe_continuation`: triggers
  only post-SL201/SL202 or post-compaction-without-checkpoint)
- `src/sesslint/policy/abstention.py` (refusal works via side-effect scan, but
  emits no finding)

## Observed behavior

A session with a dangling `write_file`-class call, unknown side effects, and
no checkpoints/compaction emits SL102 (manual) but no SL203. Refusal still
occurs via `must_abstain`, but FR-060's "MUST emit SL203" clause fails: the
required signal is missing, downstream SL203-keyed logic (planner gate,
executor re-scan, user messaging) never engages, and AC-008-style detection is
limited to compaction/checkpoint-shaped fixtures.

## Expected behavior

SL203 emitted whenever repair would require assuming execution outcome with
insufficient evidence — including dangling side-effect-capable calls — per
FR-060.

## Evidence

`check_unsafe_continuation` trigger enumeration (two triggers, both
checkpoint/compaction-keyed); no side-effect-unknown trigger.

## Reproduction

Canonical session: user msg + dangling tool_call + assistant msg, no
checkpoints -> findings contain SL102, not SL203 (predicted from code).

## Impact

Required safety signal missing; SL203-keyed gates operate on an incomplete
trigger set; spec violation.

## Root cause

SL203 specified (TASK-017) and implemented as "unsafe continuation across
loss" only, narrower than DEMAND's "unknown side-effect state".

## Required remediation

Add the side-effect-unknown trigger (dangling/outcome-unknown
side-effect-capable calls) to SL203 with precise evidence; keep checkpoint/
compaction triggers; update docs and AC-008 fixtures.

## Required regression test

Dangling-call-without-checkpoints fixture emits SL203 + refuses conservative;
pure-read dangling call does not over-fire.

## Release blocking

`YES`

---

## RVW-011

## Title

Planner and executor enforce different abstention gates, so `repair --dry-run`
presents plans the executor will always refuse.

## Severity

`S2 — HIGH`

## Confidence

`HIGH`

## Category

correctness; repair; CLI

## Specification references

FR-056, FR-060, UC-03

## Location

- `src/sesslint/repair/planner.py` (conservative `should_refuse =
  has_sl203 AND has_side_effect_abstention` once an SL203-handling recipe is
  registered — i.e. always)
- `src/sesslint/repair/executor.py` step 1e (`must_abstain` on current source
  refuses on SL203 presence OR any non-`none` side effects)

## Observed behavior

Two of four cases diverge: (a) SL203 present with all side effects known-none:
planner plans, executor refuses; (b) unknown side effects without SL203:
planner plans, executor refuses. In both, `--dry-run` exits 0 displaying steps
for a repair that can never execute — UC-03's preview is misleading. The
planner-side weakening comes from `has_sl203_recipe` (true because
`terminal-suffix-discard` handles SL203), which downgrades the task-specified
hard SL203 refusal into a conjunction.

## Expected behavior

Dry-run and execution share one abstention gate: any plan shown by dry-run is
executable barring source change; any source the executor refuses is refused
(or flagged unexecutable) at plan time.

## Evidence

Gate expressions above; `terminal-suffix-discard.handles=(SL005, SL203)`
making `has_sl203_recipe` permanently true.

## Reproduction

Session with SL003-identical pair + tool events lacking `side_effects`:
dry-run shows a collapse step; real repair raises `Abstained`, exit 1
(predicted from code).

## Impact

Misleading previews; operators cannot trust dry-run; acceptance confusion.

## Root cause

Gate logic duplicated with different predicates; registration side effect
(`has_sl203_recipe`) silently weakens planning refusal.

## Required remediation

Unify the gate in one function used by planner and executor (consulting the
same abstention result); remove the `has_sl203_recipe` weakening; dry-run must
surface abstention blocks explicitly.

## Required regression test

Matrix test over (SL203 x side-effect-knowledge x policy) asserting planner
and executor agree in all 12 cells, including dry-run output text.

## Release blocking

`YES`

---

## RVW-012

## Title

Replay profiles do not implement provider placement or adjacency constraints:
all three profiles enable identical rules, SL107/SL108 are hardcoded and
profile-blind, `checkpoint_sensitivity` is ignored, profiles are unversioned.

## Severity

`S2 — HIGH`

## Confidence

`HIGH`

## Category

specification compliance; replay profile

## Specification references

FR-038, FR-042, SL107, SL108

## Location

- `src/sesslint/profiles/builtin.py` (identical `enabled_rules` across
  profiles; only adapter allowlist/margins/flags differ)
- `src/sesslint/profiles/profile.py` (`Profile` has no version field)
- `src/sesslint/checks/tool_pairing_2.py` (no profile parameter; hardcoded
  adjacency/compaction rules)
- `src/sesslint/checks/checkpoint.py` (`checkpoint_sensitivity` accepted and
  ignored)
- `src/sesslint/repair/executor.py` (`run_all_checks`: profiles only gate
  rule families + sensitivity)

## Observed behavior

FR-038 requires provider placement/adjacency as named, versioned profiles.
In reality "claude-strict" and "neutral" produce identical findings on
identical events (except checkpoint sensitivity, which is itself ignored, and
adapter allowlisting). SL107's "selected provider's placement rule" is a
single hardcoded gap rule; SL108 likewise. `Profile` objects carry no version
(`_version.py` has static version maps nothing consumes). FR-042's
profile-dependent parallel/out-of-order validity cannot exist: pairing checks
never see the profile.

## Expected behavior

Per-profile placement/adjacency/threshold rules, versioned profile objects,
effective sensitivity, and demonstrably different strict-vs-neutral verdicts
on provider-edge fixtures.

## Evidence

`builtin.py` rule lists (identical); `tool_pairing_2` signatures (no profile);
`check_checkpoint_gap` body (never references `checkpoint_sensitivity`);
`Profile` field list (no version).

## Reproduction

Interleaved-call fixture under `--profile neutral` vs `--profile
claude-strict` -> identical SL107/SL108 outcomes (predicted from code).

## Impact

FR-038 fails; "strict" profiles are strict in name only; provider-invalid
sessions pass strict checks (see RVW-013).

## Root cause

Planning-derived: TASK-015 pins SL107/SL108 as generic hardcoded rules and
TASK-016 defines profiles as rule-toggle data, never as placement-rule
carriers — contradicting DEMAND FR-038.

## Required remediation

Move placement/adjacency (and related thresholds) into versioned profiles;
thread effective config into pairing/checkpoint rules; implement sensitivity;
publish per-profile behavioral deltas with fixtures.

## Required regression test

Same-input/different-profile test asserting strict-vs-neutral divergence on
adjacency/placement edges, plus version-pinned profile identity in reports.

## Release blocking

`YES`

---

## RVW-013

## Title

Provider-invalid sessions exit 0: SL107/SL108 (and identical-SL003) are
warnings, so `check` reports success for sessions strict providers reject.

## Severity

`S2 — HIGH`

## Confidence

`MEDIUM`

## Category

correctness; CLI; severity

## Specification references

FR-043, FR-098, SL107, SL108, SL003

## Location

- `src/sesslint/codes.py` (SL107/SL108/SL003-identical severity warning)
- `src/sesslint/checks/tool_pairing_2.py` (SL107/SL108 always warning, no
  profile modulation)
- `src/sesslint/cli.py` + `api.py` (`exit_code = 1 if has_error else 0`)

## Observed behavior

DEMAND's failure taxonomy says compaction-split pairs make history
"provider-invalid" and severity `error` means "the selected profile cannot
replay the session". SL108 (compaction-split) and SL107 (adjacency violation)
are emitted as warnings under every profile, so `check` exits 0 ("healthy
with warnings") for sessions the taxonomy calls provider-invalid. Combined
with RVW-012 (no profile modulation), no profile selection can make these
fail. (SL003-identical as warning/exit-0 is more defensible but shares the
mechanism.)

## Expected behavior

Provider-invalid conditions fail (error severity, exit 1) at least under the
strict profiles whose replay rules they violate.

## Evidence

Severity assignments + exit-code expression above; no severity modulation by
profile anywhere in checks.

## Reproduction

Compaction-split clean pair fixture -> `check` exit 0 with SL108 warning
(predicted from code).

## Impact

False "healthy" for provider-rejected sessions; CI gates pass invalid
histories; FR-098's "1 for structural findings" intent defeated.

## Root cause

Static severity assignment without profile awareness; warning chosen for
conditions the taxonomy treats as replay-breaking.

## Required remediation

Make SL107/SL108 severity profile-aware (error under strict profiles at
minimum) or error by default with documented neutral downgrade; pin exit codes
per profile in tests.

## Required regression test

SL108 fixture exits 1 under strict profiles (and documents neutral behavior);
severity table test per profile.

## Release blocking

`YES`

---

## RVW-014

## Title

Internal errors exit 1, but DEMAND FR-098/099 require exit 2.

## Severity

`S2 — HIGH`

## Confidence

`HIGH`

## Category

specification compliance; CLI

## Specification references

FR-097, FR-098, FR-099

## Location

- `src/sesslint/cli.py:32` (`_handle_internal_error` returns 1; docstring
  bakes it in) and all callers (`main`, check/repair/verify dispatch)
- `tests/cli/test_internal_error.py:8,37,59` (pins exit 1)

## Observed behavior

Any internal error (engine exception, unexpected failure) exits 1 — the same
code as "structural findings". DEMAND requires 2 for usage, I/O, or internal
errors, for both check and repair. Pipelines cannot distinguish "session
invalid" from "tool broken". The test suite pins the wrong code, so the bug is
self-perpetuating.

## Expected behavior

Internal errors -> operational envelope + exit 2, per FR-098/099.

## Evidence

Return statements + test assertions above; FR-098/099 text.

## Reproduction

Monkeypatch engine to raise; `check --json` -> `verdict: error`, exit 1
instead of 2 (test already demonstrates the exit code).

## Impact

Exit-code contract violation; automation misclassifies tool failures as
session findings.

## Root cause

Planning-derived: TASK-027:35 specifies exit 1 for internal errors,
contradicting DEMAND; implementation and tests followed the task.

## Required remediation

Return 2 from `_handle_internal_error`; update the pinning tests; audit every
exit path against FR-098/099.

## Required regression test

Internal-error matrix (check/repair/verify x human/JSON) asserting exit 2
with `verdict != healthy` and no stdout traceback.

## Release blocking

`YES`

---

## RVW-015

## Title

Assurance levels are miscomputed and disconnected: any error yields A0
("unreadable"), A3/A4 are unreachable, the human report omits the level, and
repair uses a private lattice absent from manifests.

## Severity

`S2 — HIGH`

## Confidence

`HIGH`

## Category

specification compliance; correctness; reporting

## Specification references

Assurance model (A0-A4), FR-051, FR-071, FR-072, FR-085

## Location

- `src/sesslint/cli.py:801-810` + `src/sesslint/api.py` (error->A0,
  warning->A1, clean->A2; A3/A4 never assigned)
- `src/sesslint/report.py` (`render_human`: prints limitation but not the
  assurance level)
- `src/sesslint/repair/assurance.py` (private
  clean/repaired-lossless/salvaged/unrepairable lattice; no A0-A4 mapping)
- `src/sesslint/report.py` (`RepairManifest`: no assurance field)
- `tests/io/test_hostile.py:38-40` (asserts A0 for every hostile error,
  baking in the bug)

## Observed behavior

Per DEMAND, A0 means "could not safely parse". The implementation assigns A0
to any session with error findings — including fully parsed sessions with
e.g. SL101 — which should be A1 (parseable). Warnings yield A1; clean yields
A2 always, so profile-validated sessions never reach A3 and nothing reaches
A4. Human output prints the limitation sentence but not the level itself.
Repair-side assurance (`cap_assurance`) is never surfaced in user outputs or
manifests (see RVW-008), and `verify` reports `assurance: clean`-style values
instead of A-levels. The hostile-corpus test asserts the buggy mapping.

## Expected behavior

A0 iff parse failed; A1 parseable; A2 structurally valid; A3 profile-replay
valid when profile checks pass; every success surface prints level +
limitation; manifest records the assurance ceiling.

## Evidence

Assignment expressions; `render_human` header lines (no level); `RepairManifest`
field list; hostile-test assertion.

## Reproduction

`check` a parsed-but-SL101 session -> `assurance: A0` (predicted); `check` a
profile-clean session -> `A2`, never `A3` (predicted).

## Impact

Trust-contract violation: unreadable-vs-invalid conflated; assurance ceiling
unrecorded; over/under-claimed confidence.

## Root cause

Assurance computed from severity counts instead of pipeline stage outcomes;
two lattices implemented, neither completed nor connected.

## Required remediation

Compute assurance from pipeline outcomes (parse ok? structure ok? profile ok?
reference-equivalent?); print level+limitation everywhere; unify or map the
repair lattice; record ceiling in manifest; fix the pinning test.

## Required regression test

Stage-matrix test (unparseable/parsed/invalid/valid/profile-valid x
human/JSON) asserting exact A-level + limitation + manifest ceiling.

## Release blocking

`YES`

---

## RVW-016

## Title

Claude adapter models a fictional flat schema: real-world `parentUuid`
linkage, nested message content blocks (`tool_use`/`tool_result`), and
session/scope metadata are dropped, so headline faults are invisible on real
data.

## Severity

`S2 — HIGH`

## Confidence

`HIGH` (code evidence) / `MEDIUM` (real-world prevalence — no real corpus
available in-review)

## Category

correctness; adapter

## Specification references

FR-026, FR-027, FR-029, FR-030, FR-031, FR-037, UC-01, AC-005, AC-006

## Location

- `src/sesslint/adapters/claude_code.py`: `KNOWN_RECORD_KEYS` (has
  `parentId`/`parent_id`, no `parentUuid`), `_process_claude_line` (flat
  top-level `type`/`toolUseId` only; `message.content` copied as opaque
  payload, never parsed for blocks), `branch_id`/`agent_id` never set,
  `load_claude_code_session` hardcodes `session_id="claude-session"`

## Observed behavior

- `parentUuid` (absent from known and critical key sets) is silently ignored,
  so parent linkage is lost on real-shaped data (all roots -> false SL007).
- Nested `tool_use`/`tool_result` blocks inside `message.content` are never
  extracted, so tool-pairing checks (SL101-108) see no tool events on
  real-shaped data — UC-01's headline fault class is undetectable.
- `sessionId` feeds detection only; `isSidechain`/branch/sub-agent metadata
  is dropped (FR-029); session scope is a hardcoded string.
- All repo fixtures use the flat fictional schema (`type: user_message`,
  top-level `parentId`), so the suite cannot catch the mismatch.

## Expected behavior

FR-037/UC-01: preserve UUIDs, parent UUIDs, session boundaries, compaction
markers, tool-use/result IDs, and branch/sub-agent metadata "when present" —
i.e. parse the real record shapes those fields appear in.

## Evidence

Key-set listings; `_build_payload` (no block parsing); hardcoded session id;
fixture shapes (`fixtures/claude/*`, `fixtures/hostile/*.jsonl` all flat).

## Reproduction

Feed a real-shaped Claude record (`parentUuid`, nested `message.content`
tool blocks) -> parent lost, zero tool findings (predicted from code; needs
real-corpus confirmation).

## Impact

Adapter unproven (likely non-functional) on real Claude Code data; false
negatives on the product's core promise; false SL007 positives.

## Root cause

Planning-derived: TASK-008 specifies the flat `id`/`parentId`/`type` schema
with no `parentUuid`/content-block handling.

## Required remediation

Implement real Claude JSONL shapes (parentUuid, content-block extraction,
session/scope mapping) behind version evidence; add real-shape (sanitized)
fixtures; document the supported shape precisely.

## Required regression test

Real-shape fixtures asserting parent linkage, tool pairing extraction, and
scope preservation; flat-legacy fixtures kept as regression.

## Release blocking

`YES`

---

## RVW-017

## Title

SL003 identical-vs-conflicting judgment is polluted by provenance fields:
`canonical_hash` includes `source_line`/`source_location`/`source_record_hash`,
so true duplicates via adapters are always "conflicting".

## Severity

`S2 — HIGH`

## Confidence

`HIGH`

## Category

correctness; detector (SL003); canonical model

## Specification references

FR-033, SL003, AC-005-adjacent

## Location

- `src/sesslint/canonical.py` (`to_canonical_dict`/
  `_normalize_for_canonical_json`: includes ALL non-None dataclass fields in
  the hashed bytes)
- `src/sesslint/checks/identity.py` (identical iff equal `canonical_hash`)
- Adapters (stamp `source_line` per record)

## Observed behavior

Two copies of the same event at different lines get different canonical bytes
(`source_line` differs), hence different `canonical_hash`, hence SL003
"conflicting" (error) instead of "identical" (warning/deterministic). Via any
adapter (which stamps lines), the identical class is nearly unreachable — and
with it the only end-to-end-reachable recipe (RVW-002). The "byte-identical vs
conflicting" distinction required by SL003/FR-033 is decided by coordinates,
not content.

## Expected behavior

Identity/content comparison excludes provenance coordinates; identical content
at different positions classifies identical.

## Evidence

`_normalize_for_canonical_json` field iteration (no provenance exclusion);
`identity.py` grouping by full hash; adapter `source_line` stamping.

## Reproduction

Claude file with the same record twice at different lines -> SL003 error
"conflicting" instead of warning "identical" (predicted from code).

## Impact

Misclassification; error-vs-warning flip; blocks the only live repair path on
adapter inputs; FR-033 content/metadata separation violated in effect.

## Root cause

One serialization serves both identity-hashing and provenance-carrying with no
projection.

## Required remediation

Hash content (kind+actor+payload+ids, documented) separately from provenance;
re-pin identical/conflicting tests for adapter-stamped events.

## Required regression test

Same-content-different-line duplicates via each adapter classify identical;
same-id-different-content classifies conflicting.

## Release blocking

`YES`

---

## RVW-018

## Title

SL106 checks parent-graph components instead of agent/interaction scope, and
adapters never populate scope fields, so specified cross-agent pairing faults
are missed.

## Severity

`S2 — HIGH`

## Confidence

`HIGH`

## Category

correctness; detector (SL106); adapter

## Specification references

FR-029, SL106

## Location

- `src/sesslint/checks/tool_pairing_2.py` (`_DisjointSet` over parent edges;
  SL106 iff different weakly-connected components; `branch_id`/`agent_id`/
  `interaction_id` never read)
- Adapters (never set `branch_id`/`agent_id`/`interaction_id`)

## Observed behavior

DEMAND SL106: "call and result belong to incompatible interaction or agent
scopes". Implementation: different parent components. A main-agent call paired
with a sub-agent result in the SAME parent tree (the interleaved-sub-agent
case) yields no SL106; conversely same-agent pairs in disconnected components
yield SL106 for what is structurally an SL006-shaped problem. Since scope
fields are never populated, a scope-correct implementation could not fire
either — the model, adapters, and detector disagree three ways.

## Expected behavior

Scope-aware SL106 per spec, with adapters populating scope from source
metadata.

## Evidence

Union-find construction over parent links only; `grep branch_id adapters/`
(empty); `component()` implementation.

## Reproduction

Same-tree main/sub-agent cross-pair -> no SL106; cross-component same-agent
pair -> SL106 (predicted from code).

## Impact

Specified failure mode missed; adjacent misclassification; FR-029 scope fields
dead.

## Root cause

Planning-derived: TASK-015 specifies component-based SL106, contradicting
DEMAND's scope-based definition; adapter tasks never require scope mapping.

## Required remediation

Populate scope in adapters; redefine SL106 on scope incompatibility (keeping
component analysis where it adds signal, e.g. as evidence); add interleaved
agent fixtures.

## Required regression test

Interleaved main/sub-agent cross-pair fires SL106; same-scope disconnected
pair does not (fires SL006-family instead).

## Release blocking

`YES`

---

## RVW-019

## Title

`repair` ignores adapters and `--format`: only canonical inputs are repairable,
and the flag is accepted but dead.

## Severity

`S2 — HIGH`

## Confidence

`HIGH`

## Category

correctness; CLI; repair

## Specification references

UC-04, FR-070, AC-007

## Location

- `src/sesslint/cli.py:917` (repair loads via `load_session_source_with_
  findings` only; `format_opt` validated then passed to `execute(format=...)`)
- `src/sesslint/repair/executor.py` (`format` parameter never used)
- `src/sesslint/api.py` (`repair()` same shape)

## Observed behavior

`repair` never runs detection or any vendor adapter: Claude/OpenAI inputs fall
into the canonical reader (every line -> SL001, or refusal), and the output is
always canonical JSONL (`dump_session`). `--format` is validated for spelling
but changes nothing. AC-007's "adapter-specific repair fixture" cannot exist;
UC-04's "safe repaired copy" of a vendor session is in practice unobtainable
(a format-converted canonical file at best, a refusal normally).

## Expected behavior

Repair routes through the declared adapter (or explicitly refuses non-
canonical inputs with a format-specific message and documents the limitation);
`--format` affects repair behavior.

## Evidence

Call graph above; `grep format executor.py` (param only); repair output always
`dump_session`.

## Reproduction

`repair claude.jsonl --format claude-code-jsonl --output ...` -> SL001-driven
refusal, identical with any `--format` value (predicted from code).

## Impact

Repair unusable for the two real adapters; AC-007 fails; flag dishonesty.

## Root cause

Repair path built against the canonical reader only; format threading stubbed
but never implemented.

## Required remediation

Either implement adapter-aware repair (canonicalize -> plan -> render back
through the adapter's documented round-trip contract) or make repair
explicitly canonical-only with a clear refusal + docs + AC-007 re-scoping
(DEMAND change, not just docs).

## Required regression test

Repair-behavior matrix over formats x `--format` values asserting routed
vs refused behavior and output dialect.

## Release blocking

`YES`

---

## RVW-020

## Title

No byte-offset or ordinal coordinates anywhere: FR-015's "most precise
available" coordinate and AC-003's byte boundary are unimplemented; JSON-doc
adapters fabricate line numbers.

## Severity

`S2 — HIGH`

## Confidence

`HIGH`

## Category

specification compliance; parser; adapter

## Specification references

FR-015, AC-003

## Location

- `src/sesslint/finding.py` (`SourceRef`: path/line/record_id only)
- `src/sesslint/io.py` (tracks lines, never byte offsets)
- `src/sesslint/adapters/openai_agents.py` + `canonical.py` (JSON-doc
  `line_num = idx+1`: item index reported as source line)

## Observed behavior

Byte ranges are available at read time (streaming readers know exact offsets)
but never recorded; ordinals/table-keys likewise absent. AC-003's "exact line
and byte boundary" for SL002 is half-missing. Worse, JSON-document inputs
report item INDEX as line number, which is wrong for pretty-printed files —
fabricated precision. TASK-025/026/027 all specify byte coordinates
(`span{path,line,byte}`, "byte-offset (not char-offset) coordinates",
"SL002 with line+byte"), so this is implementation shortfall, not plan gap.

## Expected behavior

Byte offsets (and ordinals where meaningful) recorded end-to-end and rendered;
JSON-doc coordinates reflect true source lines or are honestly ordinal-only.

## Evidence

`SourceRef` definition; reader offset handling (absent); `line_num = idx+1`
sites; task-file byte requirements.

## Reproduction

Torn-tail JSONL -> SL002 finding has `line` but no byte field; pretty-printed
OpenAI JSON with a fault in item 2 at physical line 40 -> reported line 2
(predicted from code).

## Impact

Spec violation; misleading coordinates for JSON inputs; triage/debugging
hampered.

## Root cause

Coordinate model designed without byte/ordinal fields; JSON readers took the
index shortcut.

## Required remediation

Add byte(-range) + ordinal to `SourceRef`/span/renderers; track offsets in
streaming readers; fix JSON readers to record true lines (or label ordinals
honestly); pin SL002 byte-boundary tests.

## Required regression test

SL002 byte-boundary exactness; pretty-JSON coordinate truthfulness; span
`{path,line,byte}` golden tests.

## Release blocking

`YES`

---

## RVW-021

## Title

`verify` and the executor parse sources with different leniency, verify never
audits manifest actions against plan steps, and the idempotence check hardcodes
operator acknowledgement.

## Severity

`S2 — HIGH`

## Confidence

`HIGH`

## Category

correctness; repair; verify

## Specification references

FR-070, FR-072, AC-015, AC-016

## Location

- `src/sesslint/repair/executor.py` (loads via lenient `load_canonical`
  fallback for single-doc: defaults actor/kind, fabricates `<missing:N>` ids)
- `src/sesslint/verify.py` (`_parse_session_events`: strict
  `parse_session_event`, raises on the same inputs)
- `src/sesslint/verify.py` check 4/5 (replay + loss compared; `manifest.actions`
  vs `plan.steps` never compared)
- `src/sesslint/verify.py:636` (`acknowledge_side_effects=True` hardcoded in
  idempotence replan)

## Observed behavior

- A single-doc source with e.g. a missing `actor` executes successfully (lenient
  load + in-memory strict re-parse of defaulted dicts) but fails verify's
  check 4 (strict parse of source bytes raises). Executor and verifier
  disagree on identical inputs.
- `manifest.actions` (kind/record_id/detail per step) is never compared to the
  plan's steps: fabricated or edited action lists pass verify. AC-015's
  "lists every transformation" is unaudited.
- Idempotence replans with `acknowledge_side_effects=True`, which no real CLI
  flow uses by default: residual findings that real re-repair would refuse get
  planned, failing idempotence spuriously for salvage outputs.

## Expected behavior

One parsing contract shared by executor and verifier; actions audited
element-wise against plan steps; idempotence replan mirrors real CLI defaults
(or both ack states, documented).

## Evidence

Loader call sites; `_parse_session_events` strictness; check-4/5 bodies (no
actions comparison); hardcoded `True`.

## Reproduction

Single-doc source missing `actor` + plannable SL003 elsewhere -> repair
succeeds, `verify` fails `transformation_audit/source-parse` (predicted from
code). Manifest with edited `actions` still verifies (predicted).

## Impact

False verify failures erode trust; unaudited actions allow manifest
misrepresentation; AC-015/016 weakened.

## Root cause

Two independently written loaders with different contracts; verify checks
enumerated without an actions-vs-steps check; ack default chosen for
strictness over fidelity.

## Required remediation

Unify on one loader contract; add actions-vs-steps audit (names, targets,
order, loss classes); parameterize idempotence ack (default False + explicit
ack run).

## Required regression test

Lenient-input repair->verify agreement test; tampered-actions verify failure;
idempotence under both ack states.

## Release blocking

`YES`

---

## RVW-022

## Title

One unreadable/hostile file aborts an entire recursive scan: adapter/check
exceptions escape per-file handling, and scan pre-reads whole files.

## Severity

`S2 — HIGH`

## Confidence

`HIGH`

## Category

correctness; robustness; CLI

## Specification references

FR-025, FR-087, UC-06, AC-022

## Location

- `src/sesslint/scan.py` (`_scan_single_file`: try/except covers only the
  initial `read_bytes`; `resolve_format`/adapter loads/`run_all_checks`
  unguarded)

## Observed behavior

`FileTooLargeError`, `MaxRecordsExceededError`, `SchemaError`,
`IsADirectoryError`, or any unexpected adapter exception propagates out of
`_scan_single_file`, killing the whole sweep (surfacing as an internal error,
exit 1) instead of producing a per-file `unreadable`/`invalid` bucket entry.
FR-025 ("read failures reported separately") and the AC-022 totals contract
fail in the presence of a single hostile file. Additionally the pre-read loads
entire files (double I/O with adapter re-reads; 100MB+ resident per file),
defeating streaming for scans.

## Expected behavior

Per-file fault isolation: every file yields exactly one bucket verdict; the
sweep completes; memory stays bounded.

## Evidence

Try-block scope in `_scan_single_file`; exception types raised by loaders;
no per-file catch around steps 3-4.

## Reproduction

Directory with one healthy file + one >100MB file -> `check --recursive`
aborts instead of reporting `unreadable: 1` (predicted from code).

## Impact

UC-06 sweeps unusable on hostile/large trees; single bad file hides all other
results; robustness failure.

## Root cause

Incomplete error boundary: only the pre-read was guarded.

## Required remediation

Wrap per-file processing in a typed catch mapping failures to buckets
(unreadable vs invalid vs unsupported); stream pre-checks (magic + bounded
sniff) instead of full reads; add abort-resistance tests.

## Required regression test

Mixed hostile directory (oversized, binary, bad-UTF8, raising-adapter via
monkeypatch) completes with exact bucket totals and exit 1.

## Release blocking

`YES`

---

## RVW-023

## Title

Reports do not declare which checks ran or were skipped (FR-047): no coverage
block exists in the report model or renderers.

## Severity

`S2 — HIGH`

## Confidence

`HIGH`

## Category

specification compliance; reporting

## Specification references

FR-047, FR-004

## Location

- `src/sesslint/report.py` (`Report`/`KNOWN_REPORT_FIELDS`: no coverage/
  performed/skipped fields; renderers emit none)

## Observed behavior

Profile rule-gating (`enabled_rules`), adapter-specific emission, finding caps,
and dedup all silently narrow what was evaluated, but reports carry no
`checks performed / skipped + reason` record. A report with zero findings is
indistinguishable from a report where every rule was skipped. FR-047 ("MUST
enumerate... and the reason for each skip") fails wholesale.

## Expected behavior

Every report embeds coverage: rules evaluated, rules skipped with reasons
(profile-gated, cap-truncated with counts, adapter-N/A), versions pinned.

## Evidence

Field listings; renderer key allowlists (no coverage keys); `run_all_checks`
filtering without accounting.

## Reproduction

`check --profile neutral` on any file -> JSON has no coverage block
(predicted from code).

## Impact

Unauditable reports; silent ruleskips (e.g. RVW-012's effective no-ops) hide
behind clean verdicts.

## Root cause

Coverage never modeled; rule filtering implemented without accounting.

## Required remediation

Add coverage to report model/schema/renderers; account filtering, caps, and
adapter skips with reasons; pin in goldens.

## Required regression test

Coverage-block assertions across profiles (strict vs neutral deltas visible),
cap-overflow accounting, and adapter-skip reasons.

## Release blocking

`YES`

---

## RVW-024

## Title

`verify` CLI shape contradicts the DEMAND command surface (flag-only, mandatory
`--plan`, no `--json`).

## Severity

`S2 — HIGH`

## Confidence

`HIGH`

## Category

specification compliance; CLI

## Specification references

MVP command surface, FR-002, FR-004

## Location

- `src/sesslint/cli.py:457-495` (verify takes `--source/--plan/--output/
  --manifest`, always prints JSON)
- `DEMAND.md` MVP scope (`sesslint verify <source> <repaired> --manifest
  <manifest> [--json]`)

## Observed behavior

DEMAND specifies positional `source`/`repaired` + `--manifest` + optional
`--json`. Implementation requires four flags (including `--plan`, which DEMAND
never mentions — and which repair never writes to disk; operators must
reconstruct it from `--dry-run` stdout), accepts no positionals, and always
emits JSON with no `--json` flag and no human mode. Scripted usage written
against DEMAND fails.

## Expected behavior

DEMAND's verify surface (or a DEMAND amendment — spec wins until amended).

## Evidence

Parser definition vs DEMAND text; repair writes no plan file (dry-run prints
to stdout only).

## Reproduction

`sesslint verify a b --manifest m` (DEMAND form) -> usage error (predicted
from code).

## Impact

CLI contract violation; verify hard to use (plan-file bootstrapping
undocumented); automation breakage.

## Root cause

Planning-derived: TASK-024 specifies the flag shape; DEMAND was not amended.

## Required remediation

Implement DEMAND's verify surface (keeping flags as aliases if desired);
decide plan-file bootstrapping (repair `--save-plan` or manifest-embedded
plan); add `--json`/human modes.

## Required regression test

DEMAND-literal verify invocations (positional + `--json`) green; flag aliases
green; plan bootstrap documented and tested.

## Release blocking

`YES`

---

## RVW-025

## Title

OpenAI adapter reads unbounded streams fully into memory before size checks,
defeating FR-013/FR-014 bounds.

## Severity

`S2 — HIGH`

## Confidence

`HIGH`

## Category

robustness; parser; resource bounds

## Specification references

FR-013, FR-014

## Location

- `src/sesslint/adapters/openai_agents.py:397-400` (`stream.read()` of all
  bytes, then size check)

## Observed behavior

For stream inputs there is no `stat` pre-gate; `read()` slurps an unbounded
stream (then checks the size and raises — after allocation). A hostile/large
stream OOMs before any limit engages. File inputs are stat-gated, so CLI file
flows are bounded, but the library/stream path (and JSONL branch, which splits
the whole blob) is not. TASK-009 explicitly requires incremental decoding
("never json.load on >limit files").

## Expected behavior

Bounded incremental reads with early abort on all input kinds.

## Evidence

Read-then-check order; no incremental decoder; TASK-009 scope line.

## Reproduction

Pipe a multi-GB stream to the library loader -> resident memory grows past
limits before refusal (predicted from code).

## Impact

Memory-exhaustion shape on untrusted streams; MUST-level bounds unenforced on
one path.

## Root cause

Whole-blob parsing chosen for JSON-doc convenience; stream case forgotten.

## Required remediation

Bounded chunked read with early size abort; incremental JSONL decode; keep
single-doc convenience via bounded temp/spool with the same caps.

## Required regression test

Oversized-stream test asserting early typed refusal with bounded RSS;
JSONL-vs-doc parity on bounded inputs.

## Release blocking

`YES`

---

## RVW-026

## Title

SL001/SL002 stream findings and per-record adapter findings are uncapped: a
fully-malformed file yields one finding per line with no findings limit.

## Severity

`S3 — MEDIUM`

## Confidence

`HIGH`

## Category

robustness; parser; resource bounds

## Specification references

FR-013

## Location

- `src/sesslint/io.py` (`_process_line`: every bad line yields a finding, no
  cap), `adapters/claude_code.py` (same uncapped loop), `adapters/canonical.py`
  (`max_event_findings=1000` cap exists here only)

## Observed behavior

FR-013 requires limits for total findings. Graph/identity/pairing families cap
at 500 each, but the streaming readers emit unboundedly: a 250k-line garbage
file yields 250k Finding objects collected into the report (CLI/API
materialize all), plus JSON serialization of all. Memory scales with hostile
input size despite the streaming reader.

## Expected behavior

Findings limits enforced per FR-013 with deterministic overflow accounting
(counts + overflow finding), not silent growth.

## Evidence

Absence of caps in `io.py`/claude loop vs presence in graph families and the
canonical adapter (1000); CLI `list(...)` materialization.

## Reproduction

100k-line malformed JSONL -> `check --json` emits 100k findings (predicted
from code).

## Impact

Memory DoS shape on hostile files; report bloat; MUST-level bounds gap.

## Root cause

Caps implemented per check family, forgotten on the streaming path.

## Required remediation

Cap stream findings with overflow accounting (kept count, dropped count,
first/last kept coordinates); document cap precedence across families.

## Required regression test

All-malformed large file yields capped findings + exact overflow counts with
bounded memory.

## Release blocking

`NO`

---

## RVW-027

## Title

SL103 fires on any reused call ID without the required non-equivalence check,
flagging identical retried calls as errors.

## Severity

`S3 — MEDIUM`

## Confidence

`HIGH`

## Category

correctness; detector (SL103)

## Specification references

SL103

## Location

- `src/sesslint/checks/tool_pairing_1.py` (`check_reused_call_id`: count > 1
  per correlation -> error; no payload/equivalence comparison)

## Observed behavior

DEMAND SL103: "Same ID maps to non-equivalent calls." The implementation
fires on cardinality alone: two byte-identical tool_call records sharing a
correlation ID (at-least-once redelivery of the same call) produce SL103
error + manual, blocking repair, with no equivalence analysis. SL104 evidence
carries hashes for its own duplicate analysis, but SL103 performs none.

## Expected behavior

Equivalence comparison (documented): identical re-calls distinguished from
genuinely conflicting reuses.

## Evidence

`check_reused_call_id` body (no content comparison); evidence lacks
equivalence fields.

## Reproduction

Two identical tool_call records, same correlation -> SL103 error (predicted
from code).

## Impact

False errors on redelivered calls; repair blocked; noise.

## Root cause

Cardinality-only implementation of an equivalence-defined rule.

## Required remediation

Compare call fingerprints; emit distinct outcomes for identical vs
conflicting reuses (or document why cardinality alone governs and amend the
rule text).

## Required regression test

Identical-recall vs conflicting-reuse fixtures with pinned codes/severities.

## Release blocking

`NO`

---

## RVW-028

## Title

SL201 fires on ordinary hashless checkpoints and its resumption trigger is
unreachable (fictional `run-start` kinds, no parent-chain scoping).

## Severity

`S3 — MEDIUM`

## Confidence

`HIGH`

## Category

correctness; detector (SL201)

## Specification references

SL201

## Location

- `src/sesslint/checks/checkpoint.py` (missing-`state_hash` -> SL201;
  `_KIND_RUN_START = {"run_start","run-start","continuation"}` — kinds the
  schema forbids and no adapter emits; resumption check is global-order, not
  parent-chain)

## Observed behavior

Any checkpoint event without a `state_hash` (the common case: adapters only
preserve `hash` when present) is an SL201 error, although a hashless
checkpoint is not evidence of state/history divergence. Conversely the
resumption trigger (`run-start` with no preceding checkpoint "in the same
parent chain" per TASK-017) can never fire: the kinds fail schema validation,
and the implemented check ignores parent chains anyway. Net: false positives
on the reachable path, dead code on the specified path.

## Expected behavior

SL201 keyed to genuine gap/divergence evidence; reachable, chain-scoped
resumption logic or removal of the fictional trigger.

## Evidence

Trigger bodies; `VALID_KINDS` (no run-start kinds); adapter kind maps (never
emit them).

## Reproduction

OpenAI export with a plain checkpoint (no hash) -> SL201 error (predicted
from code).

## Impact

False errors; SL203 cascades (tools after SL201); repair refused on healthy
resumptions.

## Root cause

Hash-presence confused with divergence evidence; trigger vocabulary drifted
from the schema.

## Required remediation

Restrict SL201 to real gap/divergence signals; implement or remove the
resumption trigger honestly; add hashless-checkpoint valid fixtures.

## Required regression test

Hashless-checkpoint healthy fixture (no SL201); true gap/divergence fixtures
(SL201 with exact evidence).

## Release blocking

`NO`

---

## RVW-029

## Title

SL107 fires on legitimate approval/checkpoint gaps between call and result
(parallel exemption covers tool kinds only).

## Severity

`S3 — MEDIUM`

## Confidence

`HIGH`

## Category

correctness; detector (SL107)

## Specification references

SL107, FR-042

## Location

- `src/sesslint/checks/tool_pairing_2.py` (parallel exemption: all
  intervening events are tool kinds of other complete pairs; `approval`/
  `checkpoint`/`handoff` intervening -> SL107 warning)

## Observed behavior

A call, approval, result sequence (the normal approval-resume flow the OpenAI
adapter is required to validate) yields SL107. Approval/checkpoint/handoff
markers are legitimate intervening events, not "unrelated chatter", but only
tool-kind intervening events are exempted.

## Expected behavior

Legitimate control-flow markers exempted (or profile-parameterized) per the
selected provider's placement rule.

## Evidence

Exemption predicate (`_is_tool_kind` only); no approval/checkpoint handling.

## Reproduction

call -> approval -> result fixture -> SL107 warning (predicted from code).

## Impact

Noise on normal approval flows; warning-level; exit code unaffected.

## Root cause

Exemption written for fan-out only; control-flow markers overlooked.

## Required remediation

Exempt (or profile-gate) approval/checkpoint/handoff intervening events with
documented rationale and fixtures.

## Required regression test

Approval-flow valid fixture (no SL107) alongside true-chatter SL107 fixture.

## Release blocking

`NO`

---

## RVW-030

## Title

Format-version detection conflates app versions with schema versions against
invented supported-sets, with dead once-only SL301 logic emitting per-record
noise.

## Severity

`S3 — MEDIUM`

## Confidence

`HIGH`

## Category

correctness; adapter; format detection

## Specification references

FR-007, FR-022, SL301

## Location

- `src/sesslint/adapters/claude_code.py` (`version_candidate` reads
  `version`/`agentVersion`/`schemaVersion`/`appVersion` against
  `{"1","1.0","1.0.0","0.1","0.1.0","claude-code-v1"}`;
  `seen_version_sl301` passed by value, never updated)
- `src/sesslint/adapters/openai_agents.py` (same dead threading: return value
  of `_check_version` discarded)

## Observed behavior

An app/release version string (e.g. `appVersion: 2.1.3`) is judged as a
schema version and yields SL301 "unsupported format version" (error, exit 1,
`unsupported` bucket). Supported-sets are invented (no documented vendor
schema versions cited). The clearly-intended once-per-file SL301 is dead code
(bool passed by value / return discarded), so offending files emit one SL301
per record (uncapped). Files with NO version anywhere are silently treated as
supported with no version evidence recorded (FR-022 partial).

## Expected behavior

Schema-version evidence distinguished from app versions; documented supported
matrix; bounded, evidence-carrying SL301; absent-version handling documented.

## Evidence

Candidate-key lists; supported-sets; dead `seen_version_sl301` threading.

## Reproduction

Claude record with `appVersion: 9.9.9` -> SL301 error (predicted from code).

## Impact

False "unsupported" verdicts on real versioned files; finding noise; refusal
to check otherwise healthy sessions.

## Root cause

Version-field semantics guessed without vendor references; once-only logic
broken by value passing.

## Required remediation

Separate schema-version from app-version channels; document supported versions
with sources; fix once-only/bounded emission; record absent-version evidence
explicitly.

## Required regression test

App-versioned-but-schema-fine fixtures (no SL301); truly-unknown schema
fixtures (one bounded SL301 with evidence).

## Release blocking

`NO`

---

## RVW-031

## Title

SL002 trigger is broader than its documented repair contract: complete but
schema-invalid terminal records classify as "torn" with deterministic
repairability.

## Severity

`S3 — MEDIUM`

## Confidence

`HIGH`

## Category

correctness; detector (SL002); repair-safety (latent)

## Specification references

FR-017, SL002

## Location

- `src/sesslint/io.py` (`_process_line`: ANY terminal-line error -> SL002:
  over-limit, NUL, bad UTF-8, non-dict JSON, depth, bad header,
  schema-invalid-but-complete event)

## Observed behavior

A complete, well-formed JSON object that merely fails event-schema validation
(e.g. missing `id`) on the last line is reported as SL002 "torn terminal
record" with deterministic repairability ("repairable by conservative suffix
drop"). It is not torn. No SL002 recipe exists today, so no harm executes —
but the classification promises that suffix-drop is the correct repair, which
for a complete record means deleting real data beyond the DEMAND-eligible
"incomplete byte suffix" case. Any future SL002 recipe built on this trigger
inherits the over-breadth.

## Expected behavior

SL002 reserved for genuinely incomplete terminal appends (with byte boundary
per RVW-020); complete-but-invalid terminal records -> SL001 (or a distinct
code), never auto-repairable-by-truncation.

## Evidence

Terminal-error mapping in `_process_line`; SL002 repairability default in
`codes.py`.

## Reproduction

Valid-JSON-but-id-less object as final line -> SL002 deterministic (predicted
from code).

## Impact

Latent data-loss shape for the eventual SL002 recipe; current misclassification
noise.

## Root cause

Position-based (terminality) classification instead of torn-vs-invalid
analysis.

## Required remediation

Narrow SL002 to incomplete-append evidence (truncated JSON/bytes); route
complete-invalid terminal records to SL001; gate any future suffix-drop recipe
on torn evidence + hash/length accounting.

## Required regression test

Complete-invalid-terminal fixture -> SL001; truncated-terminal fixture ->
SL002 with byte boundary; suffix-drop recipe (when added) refuses the former.

## Release blocking

`NO`

---

## RVW-032

## Title

Self-parent edges classify as SL001 on the canonical parse path but SL005 on
the Claude path: identical faults get different codes by adapter.

## Severity

`S3 — MEDIUM`

## Confidence

`HIGH`

## Category

correctness; detector (SL005); parity

## Specification references

SL005, FR-100, AC-005

## Location

- `src/sesslint/canonical.py` (`parse_session_event`: `parent_id == id` ->
  `SchemaError`) + `src/sesslint/io.py` (schema errors -> SL001/SL002,
  event dropped)
- `src/sesslint/adapters/claude_code.py` (constructs `SessionEvent` directly,
  no self-parent rejection) + `checks/graph.py` (self-loop -> SL005 fatal)

## Observed behavior

A self-referencing record in a canonical file yields SL001 (event dropped
from the graph); the same logical record in Claude form yields SL005 with a
cycle path. `check_cycles` documents self-loop detection, but the canonical
parse path makes it unreachable. AC-005's "dedicated code" promise is
adapter-dependent, and the hostile fixture (`self_parent.jsonl`, Claude
shape) only covers the SL005 path.

## Expected behavior

One classification for self-loops regardless of input format (SL005, with the
record preserved for graph analysis or explicitly accounted as dropped).

## Evidence

Parse rejection vs direct construction; finding-code divergence by path;
fixture format.

## Reproduction

Canonical JSONL with self-parent event -> SL001; Claude JSONL equivalent ->
SL005 (predicted from code).

## Impact

Inconsistent codes; graph checks see different graphs for the same fault;
parity violation.

## Root cause

Schema validation rejects what the graph rules are designed to diagnose.

## Required remediation

Let self-loops (and, by the same principle, other graph-diagnosable shapes)
reach graph checks as events, or formally specify parse-level rejection with
SL005-equivalent evidence; cover both formats in fixtures.

## Required regression test

Self-parent fixtures in canonical + Claude + OpenAI shapes asserting the same
code and equivalent evidence.

## Release blocking

`NO`

---

## RVW-033

## Title

Synthetic `rec_N` fallback IDs can collide with real record IDs, manufacturing
false SL003 duplicates.

## Severity

`S3 — MEDIUM`

## Confidence

`HIGH`

## Category

correctness; adapter; canonical model

## Specification references

FR-027

## Location

- `src/sesslint/adapters/claude_code.py:519-521`, `openai_agents.py:850-852`
  (`rec_{seq}` for records without IDs; no collision check against real IDs)

## Observed behavior

FR-027 requires deterministic internal identity, which `rec_N` satisfies, but
nothing prevents collision: a file containing a real `rec_5` plus an id-less
record at seq 5 yields two `rec_5` events -> false SL003 (error if payloads
differ). Deterministic but wrong.

## Expected behavior

Collision-proof synthetic identity (reserved namespace/prefix excluded from
real-ID matching, or content-hash-derived suffix).

## Evidence

Fallback construction (no registry/collision check); SL003 grouping by
string ID.

## Reproduction

Record with `"id": "rec_1"` at line 1 + id-less record at seq 1 -> SL003
(predicted from code).

## Impact

False duplicates; blocked repairs; confusing findings.

## Root cause

Guessable synthetic namespace overlapping the real ID space.

## Required remediation

Use a reserved synthetic namespace (e.g. hash-derived suffix) and assert
no-collision at adapter load; document the scheme.

## Required regression test

Adversarial fixture with real `rec_N` IDs + id-less records -> no SL003.

## Release blocking

`NO`

---

## RVW-034

## Title

`id()` memory addresses flow into SL106 components and finding fingerprints:
nondeterministic fingerprints and false SL106 on empty-string IDs.

## Severity

`S3 — MEDIUM`

## Confidence

`HIGH`

## Category

determinism; correctness; detector (SL106)

## Specification references

FR-041, FR-093, SL106

## Location

- `src/sesslint/checks/tool_pairing_2.py:300-304` (`component()` returns
  f"<unknown:{id(event_id)}>" for missing/blank IDs; components embedded in
  SL106 fingerprints)

## Observed behavior

For events with missing/blank IDs, components contain runtime memory
addresses: fingerprints vary across runs (ASLR) for identical inputs, and
distinct empty-string IDs always land in different components (false SL106
with run-varying fingerprints). Unreachable via CLI today (parsers/adapters
always assign IDs) but reachable via the library's Mapping inputs — and the
`hash()`-ban test does not cover `id()`.

## Expected behavior

No memory addresses in any finding content; deterministic handling of
missing IDs (grouped unknown component or explicit skip with reason).

## Evidence

`component()` body; SL106 fingerprint composition; `test_no_telemetry`
hash-ban regex (no `id(` rule).

## Reproduction

Library call with two empty-ID paired events -> SL106 with differing
fingerprints across processes (predicted from code).

## Impact

Determinism landmine; false positives on degenerate inputs; AC-019 at risk
via library use.

## Root cause

`id()` used as a uniqueness substitute inside hashed content.

## Required remediation

Replace with a deterministic unknown-component scheme; extend the static ban
to `id(` on finding paths.

## Required regression test

Missing/empty-ID pairing fixtures: deterministic fingerprints across
`PYTHONHASHSEED`/processes; no false SL106.

## Release blocking

`NO`

---

## RVW-035

## Title

Report metadata gaps: repro lacks architecture and carries hardcoded
adapter/profile versions; default JSON omits affected relationships.

## Severity

`S3 — MEDIUM`

## Confidence

`HIGH`

## Category

specification compliance; reporting

## Specification references

FR-086, FR-088

## Location

- `src/sesslint/report.py` (`ReproMetadata.platform`: os+python, no arch;
  `build_repro_metadata` defaults adapter/profile versions to `"1.0"`;
  `format_finding_content_free` drops `related_ids` in default mode)

## Observed behavior

FR-088 requires OS, architecture, SessLint version, adapter/profile versions.
Repro omits architecture and reports `"1.0"` versions (CLI never passes real
ones; `_version.py` has `1.0.0` maps nothing consumes). FR-086 requires
"affected relationships" per finding; `related_ids` appear only under
`--include-content`.

## Expected behavior

Real versions + architecture in repro; affected relationships in default
findings (minimized form).

## Evidence

Struct/builder definitions; version literals; `related_ids` gating.

## Reproduction

Any `check --json` -> `repro.platform` has no arch; adapter version `1.0`
(predicted from code).

## Impact

Unreproducible "repro" metadata; incomplete finding details.

## Root cause

Metadata struct left skeletal; version maps never wired.

## Required remediation

Wire `_version.py` maps into repro; add architecture; include minimized
`related_ids` by default.

## Required regression test

Repro golden asserting versions/arch; default-finding golden asserting
`related_ids` presence.

## Release blocking

`NO`

---

## RVW-036

## Title

False-confidence test patterns: the suite pins buggy behavior, asserts
vacuously, and covers the wrong reasons in at least six places.

## Severity

`S3 — MEDIUM`

## Confidence

`HIGH`

## Category

testing

## Specification references

FR-101, AC-017

## Location

- `tests/io/test_hostile.py:38-40` (asserts A0 for every hostile error —
  pins RVW-015)
- `tests/cli/test_internal_error.py:8,37,59` (pins exit 1 — RVW-014)
- `tests/report/test_content_free.py:30-47` (secret test on healthy fixture —
  vacuous for finding-path leaks, RVW-005)
- `tests/cli/test_repair_cli.py` live-store test (`.jsonl` nonexistent path
  passes via missing-directory error, not live-store refusal; real coverage
  exists only in `test_executor.py`)
- `tests/test_verify.py:95-112` (richer test manifests than production —
  RVW-008)
- `bench/perf_250k.py` (no assertions on `check_file` results — RVW-037)
- `fixtures/hostile/EXPECTATIONS.json` (`torn_final` marked `repairable:true`
  with no SL002 recipe; the flag is never positively asserted)

## Observed behavior

Each listed test passes while the underlying behavior is wrong, untested, or
tested for the wrong reason. Collectively they convert six real gaps into
green checks, which is how S1/S2 defects survived a large suite.

## Expected behavior

Tests assert specified behavior for the specified reason; vacuous/green-
for-wrong-reason tests reworked or removed.

## Evidence

Cited assertions/fixtures; each cross-references its finding.

## Reproduction

N/A (static test-quality audit; runtime unconfirmed).

## Impact

Sustained false confidence; regressions in fixed behavior will not be caught
until tests are rewritten.

## Root cause

Tests written against implementation output rather than DEMAND clauses.

## Required remediation

Rewrite each listed test against the DEMAND clause (exact assurance, exit 2,
failing-fixture secrets, real `.db` refusal, prod-shape manifests, asserted
bench checks, positive repairability proof).

## Required regression test

The rewritten tests themselves, each failing on the current implementation
for the right reason (verified by mutation).

## Release blocking

`NO` (process finding; the underlying bugs block via their own IDs)

---

## RVW-037

## Title

Performance target unmeasured and benchmark vacuous: `bench/perf_250k.py`
checks a JSONL file `check` cannot parse, asserts nothing, and PERF_NOTES
figures are unanchored.

## Severity

`S3 — MEDIUM`

## Confidence

`HIGH`

## Category

performance; testing

## Specification references

FR-095, AC-023

## Location

- `bench/perf_250k.py` (generates JSONL; `api.check_file` on it yields SL001
  per RVW-001; prints assurance without asserting; repair step likely refuses)
- `bench/PERF_NOTES.md` ("typical measured" wall/RSS with no run date, host
  spec, or command log)
- `.github/workflows/ci.yml` (no benchmark job; TASK-028's bench-smoke
  requirement unimplemented)

## Observed behavior

The benchmark measures how fast the tool processes a file it cannot actually
check (SL001 short-circuits real validation), never asserts findings/
assurance/repair outcomes, and reports numbers with no provenance. AC-023
cannot be concluded: not PASS (unmeasured), with SHOULD-level disclosure
obligations unmet in release notes.

## Expected behavior

Benchmark over checkable fixtures with asserted outcomes, dated
machine-anchored results, CI smoke, and honest disclosure of any shortfall.

## Evidence

Bench inputs vs RVW-001; absent assertions; PERF_NOTES vagueness; CI job list.

## Reproduction

Run `bench/perf_250k.py --records 20000` and observe printed `assurance=A0`
with exit 0 (predicted from code).

## Impact

AC-023 NOT_VERIFIED; perf claims unsubstantiated; streaming doubts (RVW-041)
unresolved by measurement.

## Root cause

Benchmark written against the JSONL dialect without noticing `check` cannot
read it; results recorded as prose, not artifacts.

## Required remediation

Fix the dialect first (RVW-001), then benchmark checkable fixtures with
asserted outcomes; publish dated results; add CI bench smoke; disclose any
shortfall in release notes per the SHOULD rule.

## Required regression test

Bench-smoke test asserting outcomes + budgets on a small deterministic
fixture; CI job running it.

## Release blocking

`NO` (SHOULD target; disclosure path available)

---

## RVW-038

## Title

CLI duplicates library logic instead of wrapping it (parity by copy-paste),
with dead code and an internal task reference leaking into user output.

## Severity

`S3 — MEDIUM`

## Confidence

`HIGH`

## Category

maintainability; CLI; library parity

## Specification references

FR-100, AC-026

## Location

- `src/sesslint/cli.py` vs `src/sesslint/api.py` (assurance computation,
  session-id extraction, detection-failure envelopes duplicated; CLI never
  calls `api`)
- `src/sesslint/cli.py` ("Directories are not supported without --recursive
  (see task 024)"), dead `format_report_human`, dead `session_id` extraction
  (`events` is a list; `hasattr(events, "source")` never true post-`list()`)
- Undocumented extra commands `validate-session`, `scan` (beyond DEMAND's
  five-command surface)

## Observed behavior

TASK-024 requires thin CLI wrappers over `api.py` and parity tests over every
fixture dir; instead both layers reimplement the same glue (already diverged
in small ways, e.g. dry-run paths: CLI dry-run executes validation, API
dry-run only plans). Parity tests cover ~4 files. A user-facing error cites an
internal plan artifact ("see task 024"). Extra commands expand the
compatibility surface without DEMAND coverage.

## Expected behavior

CLI wraps the library; one implementation of each decision; no internal
references in output; extra commands documented or removed.

## Evidence

Duplicated blocks; error string; parser command list vs DEMAND surface.

## Reproduction

Diff assurance/exit logic between `cli.py` check dispatch and
`api.check_file` (static); invoke `check <dir>` without `--recursive` for the
message (predicted).

## Impact

Drift risk (parity rots); unprofessional output; un-blessed surface area.

## Root cause

API factored after the CLI without rewiring callers.

## Required remediation

Rewire CLI onto `api.*`; expand parity tests toward every fixture dir incl.
repair/verify; scrub internal references; document or drop extras.

## Required regression test

CLI-vs-library differential test over the full fixture tree (check/scan/
repair-plan/verify), failing on any divergence.

## Release blocking

`NO`

---

## RVW-039

## Title

Detection rough edges: dead SQLite heuristic, extension-gated Claude scoring,
and user-overridable thresholds that can weaken fail-closed behavior.

## Severity

`S3 — MEDIUM`

## Confidence

`MEDIUM`

## Category

format detection; robustness

## Specification references

FR-005, FR-007

## Location

- `src/sesslint/adapters/openai_agents.py` (`detect_openai_agents` returns 1.0
  for SQLite magic — unreachable: `detect_format` short-circuits live DBs
  first)
- `src/sesslint/adapters/claude_code.py:detect_claude_code` (0.0 for
  non-.json/.jsonl extensions regardless of content)
- `src/sesslint/cli.py` (`--confidence-min`/`--margin-min` user overrides)

## Observed behavior

The SQLite-1.0 branch is dead (interception happens earlier — behavior
correct, code misleading). Claude content in a `.txt`/extensionless file
scores 0.0 by extension gate (fail-closed but content-blind; explicit
`--format` rescues it). Users can lower detection thresholds below the
documented fail-closed values with no warning, silently widening
auto-acceptance.

## Expected behavior

Content-driven scoring with documented extension priors; no dead branches;
threshold overrides explicit and warned (or removed).

## Evidence

Short-circuit order in `detect_format`; extension gate; override flags.

## Reproduction

Claude JSONL renamed `.txt` -> low-confidence failure despite clear content;
`--confidence-min 0.01` auto-accepts ambiguity (predicted from code).

## Impact

Minor availability/clarity issues; footgun overrides.

## Root cause

Layered detection built incrementally without reconciling gates.

## Required remediation

Content-first scoring; remove dead branch; warn (or refuse) on
below-documented thresholds.

## Required regression test

Extension-mismatch fixtures; threshold-override warning test.

## Release blocking

`NO`

---

## RVW-040

## Title

Atomic-publish hardening gaps: output `exists()`-to-`replace()` race, stale
manifest silently overwritten, no directory fsync, narrow source A->B->A race.

## Severity

`S3 — MEDIUM`

## Confidence

`MEDIUM`

## Category

filesystem safety; repair

## Specification references

FR-020, FR-066, FR-067

## Location

- `src/sesslint/repair/executor.py` (`output_p.exists()` check, later
  unconditional `os.replace`; manifest `os.replace` without existence check;
  file fsync but no dir fsync; pre/post hash with load between)

## Observed behavior

The core temp->validate->publish order is correct (validated before rename),
but: a concurrently created output between the existence check and `os.replace`
is silently overwritten (FR-066 "refuse to overwrite" has a TOCTOU gap); a
stale `<out>.manifest.json` is overwritten without notice; durability lacks
directory fsync (power-loss edge); a source swapped B then restored to A
between pre-hash/load/post-hash would bind the wrong bytes (ultra-narrow,
standard limitation, disclosed here for completeness).

## Expected behavior

O_EXCL-style no-clobber publish; manifest existence handling; dir fsync;
documented TOCTOU residual.

## Evidence

Check-then-act sequence; unconditional replaces; absent dir-fsync call.

## Reproduction

Race-window tests with pre/post hooks forcing file creation between check and
rename (harness-dependent; predicted from code).

## Impact

Low-probability overwrite/durability edges in the single-user threat model;
higher on shared filesystems.

## Root cause

Standard check-then-act without exclusivity primitives.

## Required remediation

Exclusive create/open for final publish (or re-check + abort immediately
before rename under the same failure semantics); manifest collision policy;
dir fsync; document residual races.

## Required regression test

Hook-driven race tests (output-appears-mid-repair -> abort, no overwrite;
stale-manifest policy pinned).

## Release blocking

`NO`

---

## RVW-041

## Title

Adapters and API accumulate all events in memory (`list(...)` everywhere),
defeating the streaming reader; default `max_records=None` leaves no
record-count bound.

## Severity

`S3 — MEDIUM`

## Confidence

`HIGH`

## Category

performance; robustness; resource bounds

## Specification references

FR-013, FR-014

## Location

- `src/sesslint/adapters/*` (all loaders return materialized lists),
  `cli.py`/`api.py`/`scan.py` (`list(...)` materialization),
  `src/sesslint/io.py` (`ReaderLimits.max_records=None` default)

## Observed behavior

`iter_events` streams correctly (and its test proves it), but every consumer
materializes: a 100MB file of small records (~2M events) becomes ~2M
SessionEvents + Findings + report JSON resident simultaneously. Combined with
RVW-026 (uncapped findings), hostile inputs scale memory without bound. The
250k perf target may still pass (needs measurement, RVW-037), but the SHOULD-
streaming design is defeated in practice and no default record cap exists.

## Expected behavior

Bounded end-to-end processing (streaming checks or documented materialization
with enforced caps); safe defaults.

## Evidence

Loader return types; `list()` calls; default limits; streaming test scope
(io-only).

## Reproduction

Many-tiny-records file -> resident memory proportional to record count
(predicted from code).

## Impact

OOM shape on adversarial inputs; SHOULD-level streaming unmet end-to-end.

## Root cause

Streaming implemented at the reader, abandoned at every boundary above it.

## Required remediation

Set safe default caps; stream check families over iterators where feasible or
document+enforce materialization bounds; extend the RSS test to `check_file`.

## Required regression test

Many-record hostile file completes within RSS budget or refuses with a typed
limit error (not OOM).

## Release blocking

`NO`

---

## RVW-042

## Title

Invalid `--profile` on repair surfaces as an internal error (KeyError path)
instead of a clean unsupported-profile error; dead `None`-checks persist.

## Severity

`S3 — MEDIUM`

## Confidence

`HIGH`

## Category

CLI; robustness

## Specification references

FR-006, FR-098, AC-020

## Location

- `src/sesslint/repair/executor.py` + `verify.py` (`get_profile(name)` raises
  `KeyError`; followed by dead `p if p is not None` checks), `cli.py` repair
  dispatch (no profile validation before planning), `planner.py` (records any
  string as profile)

## Observed behavior

`check --profile bogus` fails cleanly (exit 2 via `resolve_effective_config`),
but `repair --profile bogus` plans with the bogus name, fingerprints it, then
raises `KeyError` inside revalidation -> internal-error envelope, exit 1.
Fail-closed (no silent neutral fallback — AC-020's core demand holds) but via
the wrong channel and code. Dead `is not None` checks after a never-None
raising call mark the confusion.

## Expected behavior

Uniform clean unsupported/invalid-profile error (exit 2 on usage-shaped
input per FR-098/AC-020 framing) on every command; no dead checks.

## Evidence

`get_profile` (raises) vs callers (None-check); repair dispatch (no
validation); planner (unvalidated string).

## Reproduction

`repair src --output out --profile bogus` -> internal error exit 1
(predicted from code).

## Impact

Confusing errors; exit-code contract noise; fingerprinted bogus plans.

## Root cause

Profile validated on the check path only; repair/verify assume validity.

## Required remediation

Validate profile (and format) once at CLI entry for every command; drop dead
None-checks; assert clean errors in matrix tests.

## Required regression test

Invalid-profile matrix across check/repair/verify/dry-run asserting clean
error + exit code, no internal envelope.

## Release blocking

`NO`

---

## RVW-043

## Title

Dead safety infrastructure and speculative branches: `atomic.py`,
`SourceGuard`, `require_canonical`, `strict_unknown_critical`,
per-step policy flags, verify `in_place`/`loss_totals` branches, and a dead
CLI formatter carrying the raw-path bug.

## Severity

`S4 — LOW`

## Confidence

`HIGH`

## Category

maintainability; code quality

## Specification references

FR-020, FR-067 (hardening quality)

## Location

- `src/sesslint/atomic.py` (no production callers; executor hand-rolls)
- `src/sesslint/source.py` (`SourceGuard`/`guard`/`verify`/`guarded_iter_events`
  unused; only `fingerprint_file` used)
- `src/sesslint/profiles/profile.py:187` (`require_canonical`: broken key
  check, no callers)
- `strict_unknown_critical` (set, never read), `Recipe.salvage_only` (set,
  never read), `repairability_is_*` preconditions (registered, unused),
  `safe-auto`/`salvage` vocabulary (accepted, unemittable)
- `src/sesslint/verify.py` (`in_place`, `loss_totals`, `source_post_hash`
  branches for manifest fields production never writes)
- `src/sesslint/cli.py` (`format_report_human`: dead, leaks raw path)

## Observed behavior

A parallel "safety toolkit" exists beside the code paths that actually run.
None of it is harmful at runtime (all inert), but it inflates the trusted
surface, confuses auditors (two atomic writers, two guard systems), and
includes one broken validator (`require_canonical` checks a `schema` key real
canonical dicts lack) plus one dead formatter duplicating RVW-005's leak.

## Expected behavior

One live implementation per safety contract; dead/speculative code removed or
clearly quarantined to tests.

## Evidence

Import/call grep results (definitions + exports only); branch conditions over
never-emitted keys.

## Reproduction

Static (grep); no runtime effect claimed.

## Impact

Audit burden; drift risk (a future caller may pick the wrong helper);
broken-validator trap.

## Root cause

Scaffolding committed before/after callers without pruning.

## Required remediation

Delete or test-quarantine dead helpers; fix-or-remove `require_canonical`;
remove dead verify branches (or implement the fields); delete dead formatter.

## Required regression test

Dead-code gate (e.g. coverage-based or import-graph assertion on the pruned
helpers) at the reviewers' discretion — optional.

## Release blocking

`NO`

---

## RVW-044

## Title

Three divergent canonical-JSON implementations (`ensure_ascii` and trailing-
newline splits) risk hash-domain mismatches on non-ASCII content.

## Severity

`S4 — LOW`

## Confidence

`MEDIUM`

## Category

determinism; maintainability

## Specification references

FR-046, FR-091, FR-093

## Location

- `src/sesslint/canonical.py` (`to_canonical_json`: `ensure_ascii=False`,
  no newline)
- `src/sesslint/repair/fingerprint.py` (`canonical_json_bytes`:
  `ensure_ascii=True`, no newline)
- `src/sesslint/determinism.py` (`canonical_json_bytes`: `ensure_ascii=False`
  + trailing newline; production-unused)

## Observed behavior

All-ASCII fixtures hash identically under all three, so the suite cannot see
the split. Non-ASCII payloads hash differently across subsystems (event
hashes vs plan fingerprints vs verify replay bytes), risking false verify
mismatches and fingerprint instability for internationalized sessions.

## Expected behavior

One canonical-JSON primitive used by every hashing/comparison path.

## Evidence

Serializer arguments at each site; ASCII-only fixtures.

## Reproduction

Non-ASCII payload session through repair->verify: compare event/record hashes
across subsystems (predicted divergence; needs runtime confirmation).

## Impact

Latent internationalization correctness risk; currently untriggered in tests.

## Root cause

Independent helpers per milestone without consolidation.

## Required remediation

Consolidate on one primitive; add non-ASCII golden hashes through
plan/repair/verify.

## Required regression test

Non-ASCII fixture with pinned hashes at every stage (plan, manifest, verify).

## Release blocking

`NO`

---

## RVW-045

## Title

Minor robustness nits (bounded impact): duplicate JSON keys, silent timestamp
normalization, unvalidated evidence containers, CWD-sensitive minimization,
and miscellaneous small edges.

## Severity

`S4 — LOW`

## Confidence

`MEDIUM`

## Category

robustness; code quality

## Specification references

FR-011, FR-082, FR-093

## Location

Various (see behaviors).

## Observed behavior

Each item below was verified in code; each has bounded, non-blocking impact:

1. Duplicate JSON object keys: last-wins silently (stdlib default) in every
   reader — no duplicate-key finding.
2. Invalid/missing timestamps normalized to epoch `1970-01-01T00:00:00Z`
   without a finding (adapters).
3. `Finding` evidence validation covers strings only; nested lists/dicts pass
   unvalidated (graph evidence relies on per-site `_safe_id` instead).
4. `minimize_path` calls `Path.resolve()` (filesystem + CWD dependent):
   same input from different directories can minimize pseudo-paths
   differently (AC-019 edge); scan sorts by minimized paths (hash-suffixed
   order varies across machines).
5. `Loss.to_dict` omits totals under conservative (asymmetric round-trip;
   consistent today, fragile).
6. `repair --plan` unwraps `{"expected_plan": ...}` test-shaped dicts in
   production code (test vocabulary in prod path).
7. Planner `_resolve_target_index` takes the first int-valued evidence key
   (heuristic target resolution).
8. Correlation IDs untrimmed on canonical path (`"x"` vs `"x "` diverge);
   empty-string correlations group together.
9. Non-string event IDs coerced via `str()` in identity grouping (`1` vs
   `"1"` collide).
10. OSError evidence strings in scan embed raw paths (also noted in RVW-005).

## Expected behavior

Documented, pinned behavior per edge; no silent normalization where a finding
is owed; no environment-dependent rendering.

## Evidence

Cited code sites (read in full during review).

## Reproduction

Per-item micro-fixtures (static procedures; runtime unconfirmed).

## Impact

Bounded: minor misclassification/normalization/privacy-adjacent edges.

## Root cause

Small-input robustness deferred across milestones.

## Required remediation

Pin each edge (finding vs normalize vs refuse) with a micro-test; remove
CWD-dependence from minimization; move test-shape handling out of prod code.

## Required regression test

One micro-test per numbered item.

## Release blocking

`NO`

---

## RVW-046

## Title

`REQUIREMENTS_TRACEABILITY.md` claims 100% verification while citing ~20
nonexistent test files; task files over-claim completion on DEMAND-
contradicting specs.

## Severity

`S4 — LOW`

## Confidence

`HIGH`

## Category

documentation; process

## Specification references

FR-101, TASK-028 (audit duty)

## Location

- `docs/implementation/REQUIREMENTS_TRACEABILITY.md` (cites e.g.
  `tests/engine/test_no_vendor_leak.py`, `tests/engine/test_coverage.py`,
  `tests/profiles/test_parallel.py`, `tests/profiles/test_compaction.py`,
  `tests/accept/test_parallel.py`, `test_projection_repair.py`,
  `test_no_synth.py`, `test_paths.py`, `test_revalidate.py`,
  `test_manifest.py`, `test_idempotent.py`, `tests/cli/test_version_help.py`,
  `test_commands.py`, `test_scan.py`, `test_live_refusal.py`,
  `test_version.py`, `tests/repair/test_no_synth.py`, `test_plan_fp.py`,
  `test_manifest.py`, `test_idempotent.py`, `test_live_refusal.py` — all
  verified absent by direct probe)
- All 28 `TASK-*.md` (`Status: completed/complete`)

## Observed behavior

The traceability doc's "verified" column rests partly on files that do not
exist; several behaviors those files were to prove (parallel profiles,
projection repair, no-synth, revalidation, idempotence E2E) are exactly the
gaps found in this review (RVW-002/004/012/019). All task files claim
completion including ones whose specs contradict DEMAND (see planning-derived
notes in RVW-001/006/007/008/012/014/016/018) or whose acceptance behaviors
are absent (byte offsets, SL002 recipe, bench-in-CI).

## Expected behavior

Traceability cites only existing, passing evidence; task statuses distinguish
"complete per task text" from "satisfies DEMAND".

## Evidence

Direct file probes (present/absent) for each cited path; task status lines.

## Reproduction

Probe the listed paths; all absent (static, confirmed).

## Impact

Release-gate documentation unreliable; contributed to shipping unready code.

## Root cause

Traceability written ahead of implementation and never reconciled; TASK-028's
audit duty executed as paperwork.

## Required remediation

Rebuild traceability from this review's `REQUIREMENTS_AUDIT.md`; reconcile
task statuses; require evidence links to resolve in CI.

## Required regression test

CI check that every traceability-cited path exists (and, where feasible, that
cited tests fail when the behavior is mutated).

## Release blocking

`NO` (process finding; underlying gaps block via their own IDs)


