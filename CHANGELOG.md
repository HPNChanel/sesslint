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

### Fixed

- Issue-template contact links pointed at a non-existent `sesslint/sesslint`
  org instead of `HPNChanel/sesslint`.
- `[tool.mypy] files` included `tests/`, so bare `mypy` failed with hundreds
  of errors; it now matches the enforced gate (`src/sesslint` only).
- Changelog link refs: added missing `[0.2.0]` link and corrected the
  `[Unreleased]` compare base to `v0.2.0`.
- `CONTRIBUTING.md` no longer points contributors at the git-ignored
  `docs/implementation/` path.

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
