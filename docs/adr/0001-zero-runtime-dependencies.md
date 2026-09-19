# ADR-0001: Zero runtime dependencies

- Status: accepted
- Date: 2026-09-19 (retroactive record of a standing invariant)

## Context

SessLint audits clinical-style session ledgers on user machines. Every
runtime dependency adds supply-chain surface, version-skew failure modes,
and an offline-compatibility risk for a tool whose core promise is that it
works anywhere Python ≥3.11 runs — including air-gapped environments.

## Decision

`project.dependencies` in `pyproject.toml` MUST remain `[]`. All runtime
code under `src/sesslint/` is stdlib-only. Development, packaging, and
analysis tools live exclusively in the `dev`, `packaging`, and `mutation`
extras and are never imported by `src/sesslint`.

## Consequences

- The wheel installs with zero transitive resolution; offline install
  cannot fail on a missing dependency.
- stdlib gaps (e.g. terminal UI, packaging) are absorbed as code cost
  inside the repo rather than as dependencies.
- Any PR adding a runtime import outside the stdlib is a policy violation,
  not a style issue.

## Alternatives rejected

- *Small pinned utility deps (e.g. `rich`, `pydantic`)* — rejected: each is
  a permanent supply-chain and offline-install liability for cosmetic gain.
- *Optional extras for runtime features* — rejected: creates two
  behavioral tiers of the checker; feature parity must be unconditional.

## Evidence

- `pyproject.toml` — `dependencies = []` under `[project]`.
- `tests/io/test_no_eval.py:test_zero_dev_dependencies_in_runtime_source`
- `tests/test_no_egress.py`, `tests/test_no_telemetry.py` — runtime audit.
