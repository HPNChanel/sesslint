# Changelog

All notable changes to SessLint are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Fixed

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

[Unreleased]: https://github.com/HPNChanel/sesslint/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/HPNChanel/sesslint/releases/tag/v0.1.0
