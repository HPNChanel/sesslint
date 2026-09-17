# Changelog

All notable changes to SessLint are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- PEP 561 `py.typed` marker — downstream consumers now get the strict inline
  types; `Typing :: Typed` classifier added.
- `SECURITY.md` (private-advisory reporting + security model),
  `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1), `CITATION.cff`,
  `AGENTS.md`, `docs/README.md` index, `.editorconfig`.
- GitHub: `PULL_REQUEST_TEMPLATE.md`, `feature_request` issue template,
  `dependabot.yml` (actions + dev/packaging pip extras), `CODEOWNERS`.
- CI: CodeQL analysis workflow; `ci.yml` gains least-privilege
  `permissions`, `concurrency` cancellation, and Python 3.13/3.14 matrix legs.
- Repo-level `.pre-commit-config.yaml` mirroring the lint/format/mypy gates
  (consumer hook spec `.pre-commit-hooks.yaml` unchanged).
- Dev extra gains `pytest-cov` with `[tool.coverage]` branch-coverage config.
- `sesslint scan --agent claude|codex|all` (DW-T-05): auto-discovers
  well-known session roots (`$CLAUDE_CONFIG_DIR/projects` else
  `~/.claude/projects`; `$CODEX_HOME/sessions` else `~/.codex/sessions`),
  read-only, missing/non-directory roots classified `skipped`. New public
  API `sesslint.discover_session_roots()` returning frozen `DiscoveredRoot`s.
- `docs/INTEGRATIONS.md` (DW-T-06): Claude Code `SessionStart`/`PreCompact`
  hook recipes with the exit-code contract, latency notes, and the
  content-free guarantee for hook output.
- `docs/REPORTING_CORRUPTION.md` (DW-T-02): the check → bundle → attach
  flow for filing privacy-safe upstream corruption reports; new
  `session_corruption` issue template plus a contact link to the guide.
- `schemas/sesslint.plan.v1.json` and `schemas/sesslint.bundle.v1.json`
  (DW-T-09): shipped JSON Schemas describing the actual emitted documents,
  with `get_plan_schema_path`/`load_plan_schema` and
  `get_bundle_schema_path`/`load_bundle_schema` accessors.
- `codex-rollout` adapter (DW-T-12): fourth production format — detects,
  parses, and validates Codex CLI/Desktop `rollout-*.jsonl` session files.
  Envelope records (`type`/`timestamp`/`ordinal`/`payload`) canonicalize via
  a per-payload-type map: `function_call`/`custom_tool_call` → `tool_call`,
  `function_call_output`/`custom_tool_call_output` → `tool_result` (paired on
  `call_id` via `correlation_id`), `message` → role-disambiguated `message`,
  `agent_message` → assistant `message`, `reasoning` → `opaque` (encrypted
  content never projected), `compacted` → `compaction_boundary`, and
  telemetry envelopes (`session_meta`, `event_msg`, `turn_context`,
  `world_state`, `inter_agent_communication_metadata`) → `system` `opaque`.
  Parentage is mapped linearly from envelope `ordinal` continuity — dropped
  or spliced records surface as honest new roots (`SL006`/`SL007`) rather
  than fabricated links. Explicit format-version markers fail closed with
  `SL301` (`cli_version` is evidence-only); unknown envelope/payload types
  and unknown critical fields route to `SL302` with bounded discriminators.
  Synthetic IDs namespace as `sesslint:synthetic:codex_rollout:*`.
  `detect_openai_agents` carries an envelope-shape disambiguation guard so
  rollouts never tie with the Agents SDK export format. Profile interplay:
  `codex` is allowed under `neutral` and `openai-strict` (strict adjacency
  applies by design — async pairings flag `SL107`), refused under
  `claude-strict`. New conformance fixtures under
  `fixtures/conformance/codex_rollout/` and corruption-family fixtures under
  `fixtures/adapters/codex/` (all synthetic, `PROVENANCE.json` present).
- Progress/cancellation contract (DW-T-13): `sesslint.progress` exports
  frozen `ProgressEvent`, `CancellationToken`, and `OperationCancelled`.
  `api.check_file`, `api.check_dir`, `api.check`, and `api.repair` accept an
  optional `progress_cb` (phase-scoped events carrying counters and
  basename/step coordinates only — never record content) and an optional
  `cancel_token` checked at existing loop boundaries. Cancellation raises
  `OperationCancelled` through the same cleanup paths as `KeyboardInterrupt`
  (no partial outputs); CLI exit semantics unchanged (130). New
  `--progress-json` flag on `check`/`scan`/`repair` emits NDJSON progress
  events to stderr for supervising processes — stdout stays the result
  channel.
### Changed

- `sesslint.plan/v1` steps now always serialize `min_policy` and
  `recipe_version` (DW-T-08). Plan fingerprints therefore differ from
  pre-change emissions for the same logical plan; plans written by older
  builds that lack these fields fail closed on load. Unified
  deserialization behind `RepairPlan.from_dict` (single authoritative path
  for `load_plan` and verify), which also accepts `{"expected_plan": …}`
  wrappers and recomputes a missing fingerprint.
- `verify` session fallback parsing now enforces strict-reader parity
  (DW-T-08): file/line size caps, NUL rejection, strict JSON constants (no
  `NaN`/`Infinity`/out-of-range floats), and bounded nesting — matching
  what `check` rejects.
- Detector execution is unified in `sesslint.checks.runner.run_all_checks`
  (DW-T-07); `sesslint.repair.executor.run_all_checks` remains as a
  transitional re-export, and `verify` delegates to the same runner.
- Shared `_event_*` helpers consolidated into `sesslint._events` (DW-T-10);
  the executor keeps its stricter no-fallback copy semantics as
  `_copy_events_as_dicts_strict`.
- `sesslint scan`'s binary/UTF-8 probe now streams bounded 1 MiB chunks
  with an incremental decoder (DW-T-11) instead of reading whole files —
  same verdicts, O(chunk) memory.
- Detection-failed coverage in `check` reports now derives from the
  authoritative `ALL_RULES` registry (DW-T-04) instead of a duplicated
  hardcoded list.
- `DEMAND.md`: added the 2026-09-17 evidence refresh (new corruption classes
  across Claude Code, Codex, OpenCode; adoption-signal qualification) plus
  dated annotations under "Demand hypothesis" and "Future opportunities";
  header status updated to reflect the published MVP. No FR/AC/DV clause was
  modified.

### Fixed

- Issue-template contact links pointed at a non-existent `sesslint/sesslint`
  org instead of `HPNChanel/sesslint`.
- `[tool.mypy] files` included `tests/`, so bare `mypy` failed with hundreds
  of errors; it now matches the enforced gate (`src/sesslint` only).
- Changelog link refs: added missing `[0.2.0]` link and corrected the
  `[Unreleased]` compare base to `v0.2.0`.
- `CONTRIBUTING.md` no longer points contributors at the git-ignored
  `docs/implementation/` path.
- `mypy --strict` now passes on a clean checkout without the optional
  `sesslint._accel` native extension: the module is declared
  `ignore_missing_imports` in `[tool.mypy.overrides]` and the plain import
  stays inside the existing fail-closed try/except, so no
  environment-dependent `type: ignore` codes remain.

## [0.2.0] - 2026-09-16

### Added

- **Vendor write-back** (`--emit`): `sesslint repair` now accepts vendor
  inputs (`claude-code-jsonl`, `openai-agents`) and emits the repaired
  session back in the same format via drop-only line-verbatim projection.
  Every surviving source record stays byte-identical; only lines explicitly
  discarded by the plan are removed. Projection refuses (exit 2, reasons
  R1-R6) when a safe verbatim projection cannot be proven: synthesized or
  field-rewritten events, partial-line survival, reordered lines, source
  drift, or non-line formats (single-document JSON). Emitted artifacts are
  re-loaded through the original adapter and fully revalidated before the
  manifest is written. `--emit canonical` preserves the v0.1.0 artifact.
- `verify` accepts vendor source/output pairs (adapter reload +
  canonical content-identity comparison).
- **Refusal registry** (`sesslint.repair.refusals`): every detector code
  without a repair recipe now carries a documented, content-free refusal
  rationale with a DEMAND.md citation, surfaced in `check` output, blocked
  plan entries, and remediation hints — refusals are explicit contract,
  not silent gaps.
- New salvage recipe `orphan-result-drop` (SL101): drops exactly one
  verified orphan `tool_result` under `--policy salvage
  --acknowledge-side-effects`; refuses ambiguous, non-orphan, or
  child-referenced targets. Loss class `orphan-result` is disclosed in
  plan and manifest.
- **Native binary packaging**: `packaging/sesslint.spec` +
  `scripts/package.py` produce onefile executables with deterministic
  `sesslint-<version>-<os>-<arch>` naming, SHA256SUMS, and opt-in signing
  hooks (signtool/codesign/notarytool/GPG). Release workflow gains a 3-OS
  `binaries` job that attaches executables to the draft release without
  gating PyPI publish.
- `repair --plan` output now prints per-finding blocked descriptions.

### Changed

- `repair` on vendor formats no longer refuses with exit 2; it repairs via
  write-back when safe, refuses with a projection reason when not.
- Repair manifests for vendor write-back record `adapter_id` and
  `record_counts.{source,output,source_lines,output_lines,dropped_lines}`.
- Recipe catalog: 9 → 10 recipes (6 conservative, 4 salvage).

### Fixed

- Hostile fixtures `huge_line.jsonl`, `null_bytes.jsonl`, `torn_final.jsonl`
  are now legitimately repairable via `torn-terminal-record-discard`;
  expectations updated accordingly.

## [0.1.0] - 2026-09-15

First public alpha release. Published to PyPI and GitHub Releases with
hash-verified identical artifacts on both channels.

### Added

- CLI: `check`, `repair`, `verify`, `scan`, `validate-session`, `formats`,
  `version`, `bundle`, `export`, `completion` (bash/zsh/fish).
- Adapters: `canonical` (sesslint.session/v1), `claude-code-jsonl`,
  `openai-agents` (item export + JSONL).
- Replay profiles: `neutral`, `claude-strict`, `openai-strict`.
- 20 diagnostic reason codes: SL001-SL007 (structure/graph),
  SL101-SL108 (tool pairing), SL201-SL203 (checkpoint/run-state),
  SL301-SL302 (format/version negotiation).
- Repair engine: 9 deterministic recipes (5 conservative, 4 salvage),
  plan fingerprinting, SHA-256 plan-to-source binding, atomic 8-step
  execution, `RepairManifest` (sesslint.repair-manifest/v1), independent
  `verify` auditor, A0-A4 assurance taxonomy with reference
  reconstruction check.
- Privacy: content-free reports by default, path minimization,
  opt-in `--include-content`, diagnostic `bundle` for safe issue reports.
- Python API: `sesslint.api` (`check_file`, `check_dir`, `repair`,
  `verify`) and one-call `sesslint.precheck` prevention gate.
- Integrations: `sesslint-check` GitHub Action, pre-commit hook.
- Zero runtime dependencies; Python >= 3.11; offline-only operation.

### Notes

- Repair output format: canonical session streams only in 0.1.0;
  vendor artifacts require `export` first.
- GitHub Release: https://github.com/HPNChanel/sesslint/releases/tag/v0.1.0
- PyPI: https://pypi.org/project/sesslint/0.1.0/

[Unreleased]: https://github.com/HPNChanel/sesslint/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/HPNChanel/sesslint/releases/tag/v0.2.0
[0.1.0]: https://github.com/HPNChanel/sesslint/releases/tag/v0.1.0
