# SessLint Documentation Index

Public documentation shipped with the repository. The primary user-facing
reference is the root [README.md](../README.md); this directory holds the deep
reference material.

## Contents

| Path | Description |
| ---- | ----------- |
| [ADAPTER_GUIDE.md](ADAPTER_GUIDE.md) | Authoring and conformance requirements for session-format adapters (`detect_*` / `load_*` contracts, `ReaderLimits`, SL301 fail-closed versioning, SL302 bounded discriminators, synthetic ID namespacing). |
| [ADAPTER_SDK.md](ADAPTER_SDK.md) | External contributor contract (Adapter SDK v1): mandatory `detect_*`/`load_*` signatures, canonical event fields, synthetic-id and fail-closed rules, privacy invariants, and the registration checklist — every normative claim cites its enforcing code. |
| [VENDOR_DRIFT.md](VENDOR_DRIFT.md) | Vendor-drift watch protocol: triggers, inventory procedure (`scripts/shape_inventory.py`), drift classification, response matrix, task template, and evidence-hygiene rules — names and counts only, never content. |
| [MATRIX.md](MATRIX.md) | Adapter × check conformance matrix (generated; kept in sync by `tests/conformance/test_matrix.py`). |
| [REPORTING_CORRUPTION.md](REPORTING_CORRUPTION.md) | The check → bundle → attach flow for filing privacy-safe upstream corruption reports. |
| [INTEGRATIONS.md](INTEGRATIONS.md) | Agent runtime hook recipes (Claude Code `SessionStart`/`PreCompact`), the precheck gate contract, MCP server, and editor problem-matchers. |
| [CI_TEMPLATES.md](CI_TEMPLATES.md) | Copy-paste pipeline templates for GitLab CI, Azure Pipelines, and CircleCI — pinned installs, flag parity with the GitHub action, artifact upload. |
| [SPEC.md](SPEC.md) | Canonical event model — Spec v0.1: normative field/identity/ordering/hash semantics and assurance vocabulary with `file:symbol` enforcement cites. |
| [adr/](adr/README.md) | Architecture decision records — why pinned invariants exist (fail-closed, identity, privacy, determinism). |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Structured threat model: assets, trust boundaries, per-boundary threats with enforcing-code citations, residual risks. |
| [MUTATION_TESTING.md](MUTATION_TESTING.md) | Scoped mutmut protocol (qa-infra T-02): POSIX-only requirement, module scope, triage classes, baseline note. |
| [hygiene.md](hygiene.md) | Transcript hygiene: SL009 persisted-secret detection surface, the rotate-don't-redact workflow, digest-based removal verification, and the `--fail-on warning` CI recipe. |
| [codes/](codes/README.md) | Per-code documentation for all 31 diagnostic reason codes (SL001–SL402), including the A4 assurance ceiling and the closed coverage-skip vocabulary. |
| [recipes/](recipes/README.md) | Per-recipe documentation for the 12 deterministic repair recipes. |
| [reviews/](reviews/README.md) | Historical review artifacts: audit findings, release verdicts, and remediation plans. |

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
