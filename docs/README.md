# SessLint Documentation Index

Public documentation shipped with the repository. The primary user-facing
reference is the root [README.md](../README.md); this directory holds the deep
reference material.

## Contents

| Path | Description |
| ---- | ----------- |
| [ADAPTER_GUIDE.md](ADAPTER_GUIDE.md) | Authoring and conformance requirements for session-format adapters (`detect_*` / `load_*` contracts, `ReaderLimits`, SL301 fail-closed versioning, SL302 bounded discriminators, synthetic ID namespacing). |
| [MATRIX.md](MATRIX.md) | Adapter × check conformance matrix (generated; kept in sync by `tests/conformance/test_matrix.py`). |
| [REPORTING_CORRUPTION.md](REPORTING_CORRUPTION.md) | The check → bundle → attach flow for filing privacy-safe upstream corruption reports. |
| [INTEGRATIONS.md](INTEGRATIONS.md) | Agent runtime hook recipes (Claude Code `SessionStart`/`PreCompact`) and the precheck gate contract. |
| [codes/](codes/README.md) | Per-code documentation for all 20 diagnostic reason codes (SL001–SL302), including the A4 assurance ceiling and the closed coverage-skip vocabulary. |
| [recipes/](recipes/README.md) | Per-recipe documentation for the 10 deterministic repair recipes (6 conservative, 4 salvage). |
| [reviews/](reviews/) | Historical review artifacts: audit findings, release verdicts, and remediation plans. |

## Related References

- [CHANGELOG.md](../CHANGELOG.md) — versioned release notes.
- [RELEASING.md](../RELEASING.md) — reproducible build and release protocol.
- [CONTRIBUTING.md](../CONTRIBUTING.md) — development gates and adapter
  contribution requirements.
- [FIXTURES.md](../FIXTURES.md) — fixture provenance and synthetic-data rules.
- [SECURITY.md](../SECURITY.md) — vulnerability reporting and security model.
- [DEMAND.md](../DEMAND.md) — original product requirements document.
- [schemas/](../schemas/) — JSON Schemas for sessions, reports, findings, scan
  reports, repair manifests, repair plans, and support bundles.
