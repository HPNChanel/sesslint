"""Structural tests for native-binary packaging configs (Phase 3).

Verifies, using pure standard-library scanning (no PyYAML/PyInstaller needed):
- packaging/sesslint.spec exists and parses as Python (PyInstaller onefile).
- scripts/package.py exists, compiles, exposes the documented signing env
  hooks, and performs no network I/O itself (offline-by-default).
- pyproject.toml keeps runtime dependencies empty while declaring the
  build-time-only `packaging` extra, and ships neither scripts/ nor
  packaging/ inside the wheel.
- .github/workflows/release.yml has a `binaries` 3-OS matrix job that does
  NOT gate pypi-publish (PyPI ships only wheel+sdist).
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC_PATH = REPO_ROOT / "packaging" / "sesslint.spec"
PACKAGE_PY = REPO_ROOT / "scripts" / "package.py"
PYPROJECT = REPO_ROOT / "pyproject.toml"
RELEASE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release.yml"
SCHEMAS_DIR = REPO_ROOT / "schemas"


def _read(path: Path) -> str:
    assert path.is_file(), f"Missing required file: {path}"
    content = path.read_text(encoding="utf-8")
    assert content.strip(), f"{path} must not be empty"
    return content


def _job_blocks(content: str) -> dict[str, str]:
    """Split the jobs: section into {job_name: block_text} via 2-space-indent keys."""
    jobs_pos = content.find("\njobs:")
    assert jobs_pos != -1, "release.yml must define a jobs: section"
    jobs_section = content[jobs_pos:]
    starts = [
        (m.start(), m.group(1)) for m in re.finditer(r"\n  ([A-Za-z][\w-]*):\n", jobs_section)
    ]
    blocks: dict[str, str] = {}
    for i, (pos, name) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(jobs_section)
        blocks[name] = jobs_section[pos:end]
    return blocks


def _needs(block: str) -> set[str]:
    """Extract the needs: target set from a job block (scalar or list form)."""
    list_form = re.search(r"needs:\s*\[([^\]]+)\]", block)
    if list_form:
        return {n.strip() for n in list_form.group(1).split(",")}
    scalar = re.search(r"needs:\s*([A-Za-z][\w-]*)", block)
    return {scalar.group(1)} if scalar else set()


# ---------------------------------------------------------------------------
# PyInstaller spec
# ---------------------------------------------------------------------------


def test_pyinstaller_spec_exists_and_parses() -> None:
    """packaging/sesslint.spec must exist and compile as Python source."""
    content = _read(SPEC_PATH)
    compile(content, str(SPEC_PATH), "exec")  # raises SyntaxError if invalid


def test_pyinstaller_spec_onefile_console_contract() -> None:
    """Spec must declare a onefile console EXE named 'sesslint' for the package entry."""
    content = _read(SPEC_PATH)
    for token in ("Analysis", "PYZ", "EXE"):
        assert token in content, f"spec must call {token}()"
    assert "__main__.py" in content, "entry script must be src/sesslint/__main__.py"
    assert re.search(r'name\s*=\s*"sesslint"', content), "EXE name must be 'sesslint'"
    assert re.search(r"console\s*=\s*True", content), "must be a console executable"
    # Onefile: EXE consumes binaries/datas directly; no COLLECT (onedir) stage.
    assert "COLLECT" not in content, "onefile spec must not define a COLLECT step"


def test_pyinstaller_spec_bundles_shared_schemas() -> None:
    """Schemas must be bundled where runtime lookup finds them.

    Runtime code probes <sys.prefix>/share/sesslint/schemas/ (the wheel's
    shared-data location); under PyInstaller sys.prefix is the bundle dir, so
    the spec must place schemas there via datas.
    """
    content = _read(SPEC_PATH)
    assert "schemas" in content, "spec must reference the schemas directory"
    assert "share/sesslint/schemas" in content or "share\\sesslint\\schemas" in content, (
        "datas must map schemas -> share/sesslint/schemas"
    )
    assert SCHEMAS_DIR.is_dir(), "schemas/ directory must exist at repo root"
    assert list(SCHEMAS_DIR.glob("sesslint.*.json")), "schemas/ must hold JSON schemas"


# ---------------------------------------------------------------------------
# scripts/package.py orchestrator
# ---------------------------------------------------------------------------


def test_package_script_exists_and_compiles() -> None:
    """scripts/package.py must exist and compile as Python source."""
    content = _read(PACKAGE_PY)
    compile(content, str(PACKAGE_PY), "exec")


def test_package_script_cli_contract() -> None:
    """package.py exposes --platforms {auto,windows,macos,linux} and --outdir."""
    content = _read(PACKAGE_PY)
    for token in ("--platforms", "--outdir", "auto", "windows", "macos", "linux"):
        assert token in content, f"package.py must support {token!r}"
    assert "PyInstaller" in content
    assert "sesslint.spec" in content
    assert "_version.py" in content, "version must come from src/sesslint/_version.py"
    assert "SHA256SUMS" in content, "must emit a SHA256SUMS file"


def test_package_script_signing_hooks_are_opt_in() -> None:
    """All signing hooks key off env vars (opt-in; skip cleanly when absent)."""
    content = _read(PACKAGE_PY)
    for env_var in (
        "CODESIGN_PFX",
        "CERT_THUMBPRINT",
        "APPLE_SIGNING_IDENTITY",
        "APPLE_NOTARY_PROFILE",
        "GPG_KEY_ID",
    ):
        assert env_var in content, f"missing signing env hook {env_var!r}"
    for tool in ("signtool", "codesign", "notarytool", "gpg"):
        assert tool in content, f"missing signing tool invocation {tool!r}"
    assert "--detach-sign" in content, "GPG hook must produce a detached signature"


def test_package_script_offline_no_network_imports() -> None:
    """package.py must not import networking modules (offline-by-default).

    Signing tools it shells out to may use the network, but only when the
    operator opted in via env vars — the script itself opens no sockets.
    """
    content = _read(PACKAGE_PY)
    banned = ("import urllib", "import requests", "import socket", "import http")
    for token in banned:
        assert token not in content, f"network import forbidden in package.py: {token!r}"


def test_packaging_files_outside_shipped_package() -> None:
    """Build tooling must live outside src/sesslint (never shipped in the wheel)."""
    assert SPEC_PATH.is_file() and "src" not in SPEC_PATH.parts
    assert PACKAGE_PY.is_file() and "src" not in PACKAGE_PY.parts
    assert not (REPO_ROOT / "src" / "sesslint" / "package.py").exists()


# ---------------------------------------------------------------------------
# pyproject.toml
# ---------------------------------------------------------------------------


def _pyproject() -> dict[str, Any]:
    with open(PYPROJECT, "rb") as f:
        return tomllib.load(f)


def test_pyproject_runtime_deps_stay_empty() -> None:
    """Hard invariant: zero runtime dependencies (RELEASING.md guarantee #1)."""
    deps = _pyproject()["project"]["dependencies"]
    assert deps == [], f"runtime dependencies must stay empty, got {deps}"


def test_pyproject_packaging_extra_declared() -> None:
    """The build-time-only 'packaging' extra must require pyinstaller>=6."""
    extras = _pyproject()["project"]["optional-dependencies"]
    assert "packaging" in extras, "missing [project.optional-dependencies] 'packaging'"
    reqs = extras["packaging"]
    assert any(r.startswith("pyinstaller") for r in reqs), (
        f"packaging extra must include pyinstaller, got {reqs}"
    )


def test_wheel_excludes_build_tooling() -> None:
    """The wheel ships only src/sesslint + shared schemas — no scripts/packaging."""
    build = _pyproject()["tool"]["hatch"]["build"]["targets"]
    assert build["wheel"]["packages"] == ["src/sesslint"]
    sdist_includes = build["sdist"]["include"]
    assert not any("scripts" in inc or "packaging" in inc for inc in sdist_includes), (
        "sdist must not ship build tooling"
    )


# ---------------------------------------------------------------------------
# release.yml binaries job
# ---------------------------------------------------------------------------


def test_release_workflow_binaries_job_matrix() -> None:
    """release.yml must define a `binaries` job over the 3-OS matrix."""
    blocks = _job_blocks(_read(RELEASE_WORKFLOW))
    assert "binaries" in blocks, "release.yml must define a binaries job"
    block = blocks["binaries"]
    for os_name in ("ubuntu-latest", "windows-latest", "macos-latest"):
        assert os_name in block, f"binaries matrix missing {os_name!r}"
    assert "matrix:" in block and "runs-on: ${{ matrix.os }}" in block
    assert "scripts/package.py" in block, "binaries must run scripts/package.py"
    assert "gh release upload" in block, "binaries must attach assets to the release"


def test_release_workflow_binaries_smoke_test() -> None:
    """Each OS leg must smoke-test the produced binary against a checked-in fixture."""
    block = _job_blocks(_read(RELEASE_WORKFLOW))["binaries"]
    assert "version --json" in block
    assert re.search(r"check\s+fixtures/cli/check_basic/healthy\.jsonl", block)
    assert (REPO_ROOT / "fixtures" / "cli" / "check_basic" / "healthy.jsonl").is_file()


def test_release_workflow_binaries_do_not_gate_pypi() -> None:
    """pypi-publish must depend on github-draft only — never on binaries."""
    blocks = _job_blocks(_read(RELEASE_WORKFLOW))
    pypi_needs = _needs(blocks["pypi-publish"])
    assert pypi_needs == {"github-draft"}, (
        f"binaries must not gate pypi-publish; pypi needs={pypi_needs}"
    )
    binaries_needs = _needs(blocks["binaries"])
    assert binaries_needs == {"github-draft"}, (
        "binaries must wait for github-draft (the draft release it attaches to)"
    )


def test_release_workflow_yaml_parses_if_pyyaml_installed() -> None:
    """If PyYAML is available, validate the binaries job structurally."""
    try:
        import yaml
    except ImportError:
        pytest.skip("PyYAML not installed; stdlib structural checks succeeded")

    with open(RELEASE_WORKFLOW, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    binaries = data["jobs"]["binaries"]
    assert set(binaries["strategy"]["matrix"]["os"]) == {
        "ubuntu-latest",
        "windows-latest",
        "macos-latest",
    }
    assert binaries["needs"] == "github-draft"
    pypi_needs = data["jobs"]["pypi-publish"]["needs"]
    assert "binaries" not in ([pypi_needs] if isinstance(pypi_needs, str) else pypi_needs)
