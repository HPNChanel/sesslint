# Contributing to SessLint

Thank you for your interest in contributing to SessLint! SessLint is an offline, vendor-neutral session-integrity checker and conservative repair tool built to rigorous engineering standards.

---

## Core Engineering Principles

1. **Stdlib-First Architecture**:
   - The production runtime (`src/sesslint`) has **zero** third-party dependencies. It runs strictly on Python 3.11+ standard library.
   - Development and testing dependencies (`pytest`, `hypothesis`, `ruff`, `mypy`) must **never** be imported in `src/`.

2. **Strictly Out of Scope**:
   SessLint has a hard architectural perimeter. Pull requests introducing the following will be rejected:
   - SaaS platforms, cloud dashboards, or web interfaces.
   - Telemetry, analytics, network calls, or phone-home telemetry.
   - AI/LLM-based heuristics, dynamic hallucinated repair, or probabilistic guessing.
   - In-place mutation of live agent databases (e.g. SQLite live stores).

3. **Clean Code & Strict Typing**:
   - Every file must pass `mypy --strict` with zero type errors.
   - Code must adhere to SOLID, DRY, and KISS principles.
   - Zero use of `eval()`, `exec()`, `pickle`, `subprocess`, or dynamic code evaluation.

4. **Fixture Provenance & Privacy**:
   - **Never** upload, commit, or attach real user or agent session transcripts.
   - All fixtures must be strictly synthetic or consented with secret-seeding and documented provenance in `PROVENANCE.json`.
   - Maintainers will purge real transcripts on sight.

---

## Local Development Workflow

### Prerequisites
- Python 3.11 or higher
- [uv](https://github.com/astral-sh/uv) (recommended) or standard `pip` / `venv`

### Setting up Environment
```bash
git clone https://github.com/HPNChanel/sesslint.git
cd sesslint
uv sync --extra dev
```

### Running Verification Gates
Before submitting any pull request, all gates must be 100% green:

```bash
# 1. Lint and style checks
uv run ruff check src tests
uv run ruff format --check src tests

# 2. Strict static type analysis
uv run mypy --strict src/sesslint

# 3. Unit, adversarial, and conformance tests
uv run pytest

# 4. Property-based fuzz suite
uv run pytest tests/fuzz/

# 5. Performance benchmark smoke test
uv run python bench/perf_250k.py
```

---

## Contributing Format Adapters

If you are adding a new session format adapter or updating an existing one (e.g. Claude Code, OpenAI Agents SDK, or custom orchestrators):

- Read and follow the [Adapter Authoring & Conformance Guide](docs/ADAPTER_GUIDE.md).
- Ensure your adapter implements `detect_<adapter>` and `load_<adapter>` contracts, adheres to `ReaderLimits`, fail-closed `SL301` versions, bounded `SL302` discriminators, and synthetic ID namespacing (`DEV-007`).
- All adapters must pass the unified cross-adapter conformance test suite:
  ```bash
  uv run pytest tests/conformance/test_adapter_suite.py -v
  ```

---

## Submitting Pull Requests

1. Keep PRs focused, single-purpose, and well-tested.
2. Include comprehensive docstrings and inline explanation for complex invariants.
3. Update relevant reason-code documentation in `docs/codes/` if adding or modifying detection logic.
4. Update `docs/implementation/REQUIREMENTS_TRACEABILITY.md` if addressing a tracked functional requirement.

