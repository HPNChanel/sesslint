# AGENTS.md — Working Agreements for AI Coding Agents

Guidance for AI agents (and humans) making changes in this repository.

## What this project is

SessLint: an **offline, zero-runtime-dependency** session-integrity checker and
conservative repair engine for AI agent session ledgers. Python ≥ 3.11,
stdlib-only at runtime (`src/sesslint`), packaged with hatchling, released to
PyPI + GitHub Releases + PyInstaller binaries.

## Hard invariants — never violate these

- **Zero runtime dependencies**: `project.dependencies` in `pyproject.toml`
  must stay `[]`. Dev/build tools go in `dev`/`packaging` extras only.
- **No dynamic evaluation**: no `eval`, `exec`, `pickle`, or `subprocess` in
  `src/sesslint` (enforced by `tests/io/test_no_eval.py`).
- **No network or telemetry** in the runtime (`tests/test_no_egress.py`,
  `tests/test_no_telemetry.py`).
- **Content-free output by default**: never put session payload content into
  reports, findings, logs, or commit messages.
- **Fail closed**: when repair safety cannot be proven, refuse/abstain — never
  guess (see `docs/codes/SL203.md`, `src/sesslint/repair/refusals.py`).
- **Determinism**: same input → same bytes/findings everywhere. Use
  `sesslint.determinism` / `sesslint._canonical_codec` primitives; no wall
  clocks, randomness, or dict-ordering leaks in output paths.
- **Fixtures are synthetic only**: real transcripts are never committed; every
  `fixtures/**/` directory carries a `PROVENANCE.json` with
  `contains_real_data: false`.

## Layout

| Path | Purpose |
| ---- | ------- |
| `src/sesslint/` | Library + CLI (`cli.py`, `api.py`, `checks/`, `adapters/`, `repair/`, `scan.py`, `report.py`, `verify.py`, `bundle.py`) |
| `tests/` | pytest suite: unit + `conformance/`, `fuzz/` (hypothesis), `accept/`, `privacy/`, `io/` hostile-input tests |
| `docs/codes/`, `docs/recipes/` | One doc per SL code / per repair recipe — gated by `tests/test_rule_docs.py`, `tests/test_registry_docs.py` |
| `schemas/` | JSON Schemas shipped as wheel shared-data |
| `fixtures/` | Synthetic test fixtures, each with `PROVENANCE.json` |
| `bench/` | Performance probes (`perf_250k.py` contract: 250k events / 100 MB) |
| `packaging/`, `scripts/` | PyInstaller spec + `package.py` (build-time only, never shipped) |

## Required gates (all must pass)

```bash
uv sync --extra dev                 # or: pip install -e ".[dev]"
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy --strict src/sesslint   # bare `mypy` checks the same set
uv run pytest -q                    # full suite incl. conformance + fuzz
uv run pytest tests/fuzz/           # property-based suite alone
uv run python bench/perf_250k.py    # perf contract smoke
```

`.pre-commit-config.yaml` wires the lint/format/mypy gates for contributors
(`uv run pre-commit install`).

## Conventions

- Type everything; `mypy --strict` must stay clean on `src/sesslint`. The
  package ships `py.typed` (PEP 561) — keep annotations accurate.
- Match existing module docstrings citing requirement IDs (e.g. `FR-…`,
  `SL…`, `T-…`, `DEV-…`) when extending behavior.
- New detector codes need: `codes.py` registry entry + `docs/codes/SL*.md` +
  fixtures + conformance rows. New recipes need `docs/recipes/*.md`.
- User-visible changes get a `CHANGELOG.md` `Unreleased` entry
  (Keep a Changelog + SemVer).
- Line endings are LF everywhere (`.gitattributes`); fixtures are byte-exact.

## Things not to add

SaaS/web surfaces, cloud SDKs, telemetry, LLM-driven heuristics, live
agent-database mutation, runtime deps, `requests`/`urllib` in `src/`,
non-deterministic ordering, or real session data in fixtures/issues.
