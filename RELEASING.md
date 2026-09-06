# SessLint Release & Build Guide (TASK-028)

This document specifies the reproducible release and distribution protocol for SessLint.

## Core Guarantees & Constraints

1. **Zero Runtime Dependencies**: The `src/sesslint` package relies exclusively on the Python 3.11+ standard library. No runtime packages may ever be added to `dependencies` in `pyproject.toml`.
2. **Offline-by-Default**: SessLint never makes network connections during build, test, linting, scanning, or repair execution.
3. **Reproducible Artifacts**: Builds must produce byte-deterministic source distributions (`.tar.gz`) and binary wheels (`.whl`).
4. **Apache-2.0 Conformance**: All released source files must carry the Apache-2.0 license notice.

---

## Release Prerequisites

Before preparing a release, ensure all verification gates pass locally:

```bash
# 1. Code formatting & linting
ruff check .
ruff format --check .

# 2. Strict type checking
mypy --strict src/

# 3. Complete test suite (unit, conformance, fixtures, smoke, offline)
pytest -q

# 4. Release smoke verification
pytest -q tests/test_smoke_release.py tests/accept/test_healthy.py
```

---

## Reproducible Build Protocol

### 1. Clean Workspace & Build Artifacts

Ensure the git working tree is clean and build wheels using `build` (or `uv build` / `hatchling`):

```bash
# Clean previous build artifacts
rm -rf dist/ build/ *.egg-info

# Build standard source distribution and wheel
python -m build --sdist --wheel
```

### 2. Generate Checksums (`sha256sums.txt`)

Compute cryptographically secure SHA-256 digests for all generated distribution artifacts:

```bash
# On Linux / macOS
cd dist && sha256sum * > sha256sums.txt && cd ..

# On Windows PowerShell
Get-FileHash -Algorithm SHA256 dist/* | ForEach-Object { "$($_.Hash.ToLower())  $($_.Path | Split-Path -Leaf)" } | Out-File -Encoding ascii dist/sha256sums.txt
```

### 3. Verify Checksums

```bash
# On Linux / macOS
cd dist && sha256sum -c sha256sums.txt && cd ..

# On Windows PowerShell
Get-Content dist/sha256sums.txt | ForEach-Object {
    $parts = $_ -split '\s+'
    $hash = $parts[0]
    $file = "dist/$($parts[1])"
    $calc = (Get-FileHash -Algorithm SHA256 $file).Hash.ToLower()
    if ($calc -ne $hash) { throw "Checksum mismatch for $file" }
}
```

---

## Clean-Environment Smoke Test

Test installing the built distribution into an isolated, clean virtual environment without network access:

```bash
# Create isolated temporary virtual environment
python -m venv .smoke_env

# Activate virtual environment
# Windows:
.smoke_env\Scripts\activate
# Linux/macOS:
source .smoke_env/bin/activate

# Install from built wheel (offline)
pip install --no-index --find-links=dist sesslint

# Verify CLI version and schema versions
sesslint version --json

# Verify healthy check returns exit code 0
sesslint check fixtures/cli/check_basic/healthy.jsonl --json

# Verify verify command returns exit code 0
sesslint verify --source fixtures/verify/ok/source.jsonl --plan fixtures/verify/ok/plan.json --output fixtures/verify/ok/output.jsonl --manifest fixtures/verify/ok/manifest.json

# Cleanup
deactivate
rm -rf .smoke_env
```

---

## Release Checklist

- [ ] `LICENSE` contains full Apache-2.0 text and `NOTICE` details zero runtime dependencies.
- [ ] `docs/MATRIX.md` matches generator output from `tests/conformance/test_matrix.py`.
- [ ] All 20 reason codes have synced documentation in `docs/codes/SL*.md` (`tests/test_rule_docs.py` passes).
- [ ] All 8 repair recipes have synced documentation in `docs/recipes/*.md` (`tests/test_registry_docs.py` passes).
- [ ] Every fixture directory contains a valid `PROVENANCE.json` with `contains_real_data: false` (`tests/test_fixture_provenance.py` passes).
- [ ] Multi-platform CI workflow succeeds across Ubuntu, Windows, and macOS on Python 3.11 and 3.12.
