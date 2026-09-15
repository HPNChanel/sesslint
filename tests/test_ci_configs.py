"""Tests for CI configurations and pre-commit hook specifications (DEV-015).

Verifies file existence, non-emptiness, and mandatory top-level keys using pure
standard library text scanning to ensure CI configuration validity even without PyYAML.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
ACTION_YML = REPO_ROOT / ".github" / "actions" / "sesslint-check" / "action.yml"
PRE_COMMIT_HOOKS = REPO_ROOT / ".pre-commit-hooks.yaml"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release.yml"


def test_action_yml_contract() -> None:
    """Verify .github/actions/sesslint-check/action.yml exists and declares mandatory interface."""
    assert ACTION_YML.is_file(), f"Missing action metadata file: {ACTION_YML}"
    content = ACTION_YML.read_text(encoding="utf-8")
    assert len(content.strip()) > 0, "action.yml must not be empty"

    # Top-level keys
    for top_key in ("name:", "description:", "inputs:", "outputs:", "runs:"):
        assert top_key in content, f"Missing required top-level key {top_key!r} in action.yml"

    # Inputs
    required_inputs = (
        "path:",
        "profile:",
        "format:",
        "fail-on:",
        "package:",
        "source-ref:",
        "python-version:",
    )
    for inp in required_inputs:
        assert inp in content, f"Missing required input {inp!r} in action.yml"

    # Outputs
    required_outputs = (
        "exit-code:",
        "verdict:",
        "report-json:",
    )
    for out in required_outputs:
        assert out in content, f"Missing required output {out!r} in action.yml"

    # Composite runs declaration
    assert 'using: "composite"' in content or "using: 'composite'" in content


def test_pre_commit_hooks_contract() -> None:
    """Verify .pre-commit-hooks.yaml exists and defines sesslint-check hook."""
    assert PRE_COMMIT_HOOKS.is_file(), f"Missing hook metadata file: {PRE_COMMIT_HOOKS}"
    content = PRE_COMMIT_HOOKS.read_text(encoding="utf-8")
    assert len(content.strip()) > 0, ".pre-commit-hooks.yaml must not be empty"

    # Hook declaration and mandatory fields
    assert "- id: sesslint-check" in content
    assert "name: sesslint check" in content
    assert "entry: sesslint check" in content
    assert "language: python" in content
    assert "files:" in content


def test_ci_workflow_dogfood_job() -> None:
    """Verify .github/workflows/ci.yml defines action-dogfood job with 6-fixture matrix."""
    assert CI_WORKFLOW.is_file(), f"Missing CI workflow file: {CI_WORKFLOW}"
    content = CI_WORKFLOW.read_text(encoding="utf-8")
    assert len(content.strip()) > 0, "ci.yml must not be empty"

    # Job name
    assert "action-dogfood:" in content

    # 3 healthy fixtures (expect pass)
    healthy_fixtures = (
        "fixtures/canonical/minimal.json",
        "fixtures/cli/check_basic/healthy.jsonl",
        "fixtures/checks/graph_healthy.json",
    )
    for hf in healthy_fixtures:
        assert hf in content, f"Missing healthy fixture {hf!r} in action-dogfood matrix"

    # 3 corrupt fixtures (expect fail)
    corrupt_fixtures = (
        "fixtures/checks/sl005_cycle.json",
        "fixtures/checks/sl101_orphan.json",
        "fixtures/canonical/unknown_critical.json",
    )
    for cf in corrupt_fixtures:
        assert cf in content, f"Missing corrupt fixture {cf!r} in action-dogfood matrix"

    # Gate behavior: continue-on-error and verified failure outcome
    assert "continue-on-error: true" in content
    assert (
        'steps.corrupt-check.outcome }}" != "failure"' in content
        or "steps.corrupt-check.outcome" in content
    )

    # action-dogfood required in build-and-smoke gate dependencies
    assert "action-dogfood" in content[content.find("build-and-smoke:") :]


def test_yaml_parses_if_pyyaml_installed() -> None:
    """If PyYAML is available, verify full syntax parsing of CI metadata files."""
    try:
        import yaml
    except ImportError:
        pytest.skip("PyYAML not installed; stdlib key-presence check succeeded")

    for path in (ACTION_YML, PRE_COMMIT_HOOKS, CI_WORKFLOW):
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        assert data is not None, f"YAML document at {path} parsed to None"


# ---------------------------------------------------------------------------
# Release workflow (post-alpha-hardening-plan/T-07a)
# ---------------------------------------------------------------------------

import re  # noqa: E402


def _release_content() -> str:
    assert RELEASE_WORKFLOW.is_file(), f"Missing release workflow: {RELEASE_WORKFLOW}"
    content = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    assert len(content.strip()) > 0, "release.yml must not be empty"
    return content


def _job_blocks(content: str) -> dict[str, str]:
    """Split the jobs: section into {job_name: block_text} via 2-space-indent keys."""
    jobs_pos = content.find("\njobs:")
    assert jobs_pos != -1, "release.yml must define a jobs: section"
    jobs_section = content[jobs_pos:]
    blocks: dict[str, str] = {}
    starts = [
        (m.start(), m.group(1)) for m in re.finditer(r"\n  ([A-Za-z][\w-]*):\n", jobs_section)
    ]
    for i, (pos, name) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(jobs_section)
        blocks[name] = jobs_section[pos:end]
    return blocks


def test_release_workflow_trigger_tag_gated() -> None:
    """release.yml triggers only on v* tag pushes and is not a reusable workflow."""
    content = _release_content()
    on_pos = content.find("\non:")
    jobs_pos = content.find("\njobs:")
    on_block = content[on_pos:jobs_pos]
    assert "tags:" in on_block and '"v*"' in on_block or "'v*'" in on_block
    forbidden = (
        "workflow_call",
        "workflow_dispatch",
        "pull_request",
        "schedule:",
        "push:\n      branches",
    )
    for token in forbidden:
        assert token not in on_block, f"release.yml must not trigger on {token!r}"


def test_release_workflow_four_job_dag_order() -> None:
    """Exactly four jobs ordered build -> github-draft -> pypi-publish -> github-promote."""
    content = _release_content()
    blocks = _job_blocks(content)
    assert list(blocks) == ["build", "github-draft", "pypi-publish", "github-promote"], (
        f"job order/set mismatch: {list(blocks)}"
    )
    assert "needs: build" in blocks["github-draft"]
    assert "needs: github-draft" in blocks["pypi-publish"]
    assert "needs: pypi-publish" in blocks["github-promote"]


def test_release_workflow_tag_version_validation() -> None:
    """The build job validates tag == 'v' + _version.py version before building."""
    build = _job_blocks(_release_content())["build"]
    assert "_version.py" in build
    assert "GITHUB_REF_NAME" in build
    assert re.search(r"GITHUB_REF_NAME#v", build), "tag must be stripped of leading 'v'"
    assert re.search(r"mismatch|!=", build), "build must abort on tag/version mismatch"


def test_release_workflow_minimal_permissions() -> None:
    """contents:write only on draft/promote; id-token:write only on pypi-publish; read elsewhere."""
    content = _release_content()
    top = content[: content.find("\njobs:")]
    assert "contents: write" not in top, "no workflow-level write permission allowed"
    assert re.search(r"permissions:\s*\n\s*contents:\s*read", top)

    blocks = _job_blocks(content)
    for name, block in blocks.items():
        writes_contents = "contents: write" in block
        writes_idtoken = "id-token: write" in block
        if name in ("github-draft", "github-promote"):
            assert writes_contents, f"{name} must hold contents: write"
        else:
            assert not writes_contents, f"{name} must not hold contents: write"
        if name == "pypi-publish":
            assert writes_idtoken, "pypi-publish must hold id-token: write"
        else:
            assert not writes_idtoken, f"{name} must not hold id-token: write"


def test_release_workflow_pypi_environment_and_no_tokens() -> None:
    """pypi-publish runs in the protected 'pypi' environment; no API-token secrets anywhere."""
    content = _release_content()
    pypi_block = _job_blocks(content)["pypi-publish"]
    assert re.search(r"environment:\s*pypi\b", pypi_block)
    for tokenish in ("pypi-token", "api-token", "PYPI_TOKEN", "password:"):
        assert tokenish not in content, f"no API token allowed in release.yml: {tokenish!r}"


def test_release_workflow_draft_before_pypi_promote_only() -> None:
    """Draft release (with assets) precedes PyPI; promote only mutates the existing draft."""
    content = _release_content()
    draft = _job_blocks(content)["github-draft"]
    promote = _job_blocks(content)["github-promote"]
    assert "gh release create" in draft and "--draft" in draft
    assert "sha256sums.txt" in draft and "artifact-manifest.json" in draft
    assert re.search(r"\.whl.*\.tar\.gz", draft)
    assert "gh release edit" in promote and "--draft=false" in promote
    assert "gh release create" not in promote, "promote must never create a second release"


def test_release_workflow_source_date_epoch_commit_derived() -> None:
    """SOURCE_DATE_EPOCH derives from the tagged commit timestamp and lands in the manifest."""
    build = _job_blocks(_release_content())["build"]
    assert "SOURCE_DATE_EPOCH" in build
    assert re.search(r"git show -s --format=%ct.*GITHUB_SHA", build)
    assert "source_date_epoch" in build, "epoch must be recorded in the artifact manifest"


def test_release_workflow_pypi_packages_only_distributions() -> None:
    """The PyPI publish step receives only .whl/.tar.gz; checksums/manifest excluded."""
    pypi_block = _job_blocks(_release_content())["pypi-publish"]
    assert "packages-dir: pypi_dist/" in pypi_block
    stage = pypi_block[pypi_block.find("pypi_dist") :]
    assert "sha256sums" not in stage.split("uses:")[0].replace("sha256sum -c", ""), (
        "packages-only dir must exclude sha256sums.txt"
    )
    assert re.search(r"cp dist/\*\.whl dist/\*\.tar\.gz pypi_dist/", pypi_block)


def test_release_workflow_actions_pinned_to_full_sha() -> None:
    """Every third-party action uses a full-length commit SHA (no floating tags)."""
    content = _release_content()
    for m in re.finditer(r"uses:\s*([^\s#]+)", content):
        ref = m.group(1)
        if ref.startswith("./"):
            continue
        assert re.search(r"@[0-9a-f]{40}$", ref), f"action not SHA-pinned: {ref}"


def test_release_workflow_yaml_parses_if_pyyaml_installed() -> None:
    """If PyYAML is available, release.yml must parse and expose the four-job DAG."""
    try:
        import yaml
    except ImportError:
        pytest.skip("PyYAML not installed; stdlib structural checks succeeded")

    with open(RELEASE_WORKFLOW, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert data is not None
    assert list(data["jobs"]) == ["build", "github-draft", "pypi-publish", "github-promote"]


def test_package_metadata_consistency() -> None:
    """pyproject/_version.py agree on name, version, license, python floor (T-07a audit)."""
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    version_py = (REPO_ROOT / "src" / "sesslint" / "_version.py").read_text(encoding="utf-8")

    assert re.search(r'^name\s*=\s*"sesslint"', pyproject, re.M)
    assert 'path = "src/sesslint/_version.py"' in pyproject
    m = re.search(r'__version__\s*=\s*"([^"]+)"', version_py)
    assert m and m.group(1) == "0.1.0"
    assert 'license = "Apache-2.0"' in pyproject
    assert 'requires-python = ">=3.11"' in pyproject
    assert 'readme = "README.md"' in pyproject
    assert (REPO_ROOT / "LICENSE").is_file()
    assert (REPO_ROOT / "README.md").is_file()
