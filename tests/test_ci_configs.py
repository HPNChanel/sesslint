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


def test_release_workflow_required_dag() -> None:
    """T-11: all gates and delivery artifacts precede irreversible publication."""
    import yaml

    jobs = yaml.safe_load(_release_content())["jobs"]
    assert jobs["quality"]["uses"] == "./.github/workflows/ci.yml"
    assert jobs["build"]["needs"] == "quality"
    assert set(jobs["binaries"]["needs"]) == {"quality", "build"}
    assert set(jobs["assemble"]["needs"]) == {"build", "binaries"}
    assert jobs["github-draft"]["needs"] == "assemble"
    assert set(jobs["provenance-verify"]["needs"]) == {"assemble", "github-draft", "provenance"}
    assert "provenance-verify" in jobs["pypi-publish"]["needs"]
    assert jobs["pypi-verify"]["needs"] == "pypi-publish"
    assert set(jobs["github-promote"]["needs"]) == {"pypi-verify", "provenance-verify"}
    assert jobs["published-verify"]["needs"] == "github-promote"


def test_release_workflow_tag_version_and_exact_commit_validation() -> None:
    blocks = _job_blocks(_release_content())
    assert "_version.py" in blocks["build"] and "Tag/version mismatch" in blocks["build"]
    assert "git show -s --format=%ct" in blocks["build"]
    assert '"$GITHUB_SHA"' in blocks["build"]
    assert "--commit" in blocks["assemble"]
    assert "--complete" in blocks["assemble"]
    assert "release_artifacts.py compare" in blocks["build"]
    assert "smoke_distributions.py" in blocks["build"]
    assert "installed_smoke.py" in blocks["binaries"]
    assert "--source-tag" in blocks["provenance-verify"]


def test_release_workflow_minimal_permissions() -> None:
    import yaml

    data = yaml.safe_load(_release_content())
    assert data["permissions"] == {"contents": "read"}
    for name, job in data["jobs"].items():
        perms = job.get("permissions", {})
        assert (perms.get("contents") == "write") == (
            name in {"github-draft", "github-promote", "provenance"}
        )
        assert (perms.get("id-token") == "write") == (
            name in {"assemble", "provenance", "pypi-publish"}
        )
        assert "packages" not in perms
    assert data["jobs"]["pypi-publish"]["environment"] == "pypi"
    assert "PYPI_TOKEN" not in _release_content()


def test_release_retry_reuses_verified_bytes() -> None:
    blocks = _job_blocks(_release_content())
    for name in ("build", "binaries", "assemble"):
        assert "github.run_attempt > 1" in blocks[name]
        assert "steps.reuse.outputs.restored != 'true'" in blocks[name]
        assert "restore_release_artifact.py" in blocks[name]
        assert "continue-on-error" not in blocks[name]
    assert "--clobber" not in _release_content()
    assert "github_stage.py" in blocks["github-draft"]
    assert "--stage-missing" in blocks["pypi-publish"]
    assert "provenance-exists" in blocks["provenance"]
    assert "needs.provenance.result == 'skipped'" in blocks["provenance-verify"]


def test_release_workflow_pypi_packages_only_distributions() -> None:
    publish = _job_blocks(_release_content())["pypi-publish"]
    assert "release_artifacts.py stage" in publish
    assert "published_verify.py --directory validated-dist" in publish
    assert "packages-dir: pypi_dist/" in publish
    assert "cp dist/*.whl dist/*.tar.gz" not in publish
    assert "skip-existing" not in publish


def test_release_workflow_actions_are_reviewed_pins() -> None:
    content = _release_content()
    for ref in re.findall(r"uses:\s*([^\s#]+)", content):
        if ref.startswith("./"):
            continue
        if "generator_generic_slsa3.yml" in ref:
            # Upstream fails when called by SHA; exact semver is mandatory for
            # the signing certificate identity. The tag SHA is checked first.
            assert ref.endswith("@v2.1.0")
            assert "git ls-remote" in content
            assert "f7dd8c54c2067bafc12ca7a55595d5ee9b75204a" in content
        else:
            assert re.search(r"@[0-9a-f]{40}$", ref), ref


def test_release_workflow_binary_os_and_complete_signatures() -> None:
    import yaml

    data = yaml.safe_load(_release_content())
    legs = data["jobs"]["binaries"]["strategy"]["matrix"]["include"]
    assert {leg["os"] for leg in legs} == {"windows", "macos", "linux"}
    assert next(leg for leg in legs if leg["os"] == "linux")["runner"] == "ubuntu-22.04"
    assemble = _job_blocks(_release_content())["assemble"]
    assert "cosign sign-blob" in assemble and "cosign verify-blob" in assemble
    assert "--certificate-identity" in assemble and "--certificate-oidc-issuer" in assemble
    assert "sha256sum -- *" in assemble


def test_release_publication_requires_download_and_install_evidence() -> None:
    blocks = _job_blocks(_release_content())
    assert "published_verify.py" in blocks["pypi-verify"]
    assert "smoke_distributions.py" in blocks["pypi-verify"]
    assert "gh release edit" in blocks["github-promote"]
    assert "--draft=false" in blocks["github-promote"]
    assert "gh release download" in blocks["published-verify"]
    assert "cmp dist/artifact-manifest.json" in blocks["published-verify"]
    assert "smoke_distributions.py" in blocks["published-verify"]


def test_package_metadata_consistency() -> None:
    """pyproject/_version.py agree on name, version, license, python floor (T-07a audit)."""
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    version_py = (REPO_ROOT / "src" / "sesslint" / "_version.py").read_text(encoding="utf-8")

    assert re.search(r'^name\s*=\s*"sesslint"', pyproject, re.M)
    assert 'path = "src/sesslint/_version.py"' in pyproject
    m = re.search(r'__version__\s*=\s*"([^"]+)"', version_py)
    assert m and m.group(1) == "0.4.1"
    assert 'license = "Apache-2.0"' in pyproject
    assert 'requires-python = ">=3.11"' in pyproject
    assert 'readme = "README.md"' in pyproject
    assert (REPO_ROOT / "LICENSE").is_file()
    assert (REPO_ROOT / "README.md").is_file()


# ---------------------------------------------------------------------------
# docs/CI_TEMPLATES.md — copy-paste pipeline snippets (integrations/T-05)
# ---------------------------------------------------------------------------

CI_TEMPLATES_DOC = REPO_ROOT / "docs" / "CI_TEMPLATES.md"


def _extract_templates() -> dict[str, str]:
    """Extract fenced yaml blocks carrying a `# ci-template: <name>` marker."""
    text = CI_TEMPLATES_DOC.read_text(encoding="utf-8")
    blocks = re.findall(r"```yaml\n(.*?)```", text, re.S)
    out: dict[str, str] = {}
    for block in blocks:
        m = re.search(r"# ci-template: (\w+)", block)
        if m:
            out[m.group(1)] = block
    return out


def test_ci_templates_doc_has_all_platforms() -> None:
    assert CI_TEMPLATES_DOC.is_file(), "docs/CI_TEMPLATES.md missing"
    assert set(_extract_templates()) == {"gitlab", "azure", "circleci"}


@pytest.mark.parametrize("platform", ["gitlab", "azure", "circleci"])
def test_template_pins_version_and_invocation(platform: str) -> None:
    block = _extract_templates()[platform]
    assert re.search(r"sesslint==\d+\.\d+\.\d+", block), (
        f"{platform}: template must pin a released version"
    )
    assert re.search(r"sesslint (scan|check) ", block), f"{platform}: no check/scan invocation"
    assert "--fail-on" in block, f"{platform}: missing --fail-on"
    assert "--output-format" in block, f"{platform}: missing --output-format"


def test_template_required_keys_per_platform() -> None:
    blocks = _extract_templates()
    for key in ("image:", "script:", "artifacts:"):
        assert key in blocks["gitlab"], f"gitlab template missing {key}"
    for key in ("steps:", "task:"):
        assert key in blocks["azure"], f"azure template missing {key}"
    for key in ("version:", "jobs:", "steps:", "workflows:"):
        assert key in blocks["circleci"], f"circleci template missing {key}"


def test_templates_no_tabs_and_yaml_parseable() -> None:
    blocks = _extract_templates()
    for name, block in blocks.items():
        assert "\t" not in block, f"{name}: YAML must not contain tabs"
    yaml = pytest.importorskip("yaml", reason="PyYAML not installed")
    for name, block in blocks.items():
        data = yaml.safe_load(block)
        assert isinstance(data, dict), f"{name}: template must parse to a mapping"
        if name == "gitlab":
            assert any(isinstance(v, dict) and "script" in v for v in data.values()), (
                "gitlab: no job with script"
            )
        elif name == "azure":
            assert isinstance(data.get("steps"), list), "azure: steps must be a list"
        elif name == "circleci":
            assert "jobs" in data and "workflows" in data


def test_parity_table_covers_every_action_input() -> None:
    """Every action.yml input must appear in the parity table."""
    action = ACTION_YML.read_text(encoding="utf-8")
    doc = CI_TEMPLATES_DOC.read_text(encoding="utf-8")
    inputs_match = re.search(r"^inputs:\n((?:  .+\n)+)", action, re.M)
    assert inputs_match
    input_names = re.findall(r"^  ([a-z][\w-]*):", inputs_match.group(1), re.M)
    assert input_names, "no action inputs parsed"
    for name in input_names:
        assert f"`{name}`" in doc, f"action input {name!r} missing from parity table"


def test_release_workflow_slsa_provenance() -> None:
    blocks = _job_blocks(_release_content())
    assert "needs.assemble.outputs.artifact-subjects" in blocks["provenance"]
    assert "upload-assets: true" in blocks["provenance"]
    assert "slsa-verifier verify-artifact dist/*" in blocks["provenance-verify"]
    assert "provenance-verify" in blocks["pypi-publish"]


def test_ghcr_is_prepared_not_automatically_published() -> None:
    assert "docker push" not in _release_content()
    assert "image" not in _job_blocks(_release_content())


def test_ghcr_dockerfile() -> None:
    """Repo-root Dockerfile: distroless nonroot, /sesslint entrypoint (T-05)."""
    df = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "FROM gcr.io/distroless/base-debian12:nonroot" in df
    assert "COPY sesslint /sesslint" in df
    assert 'ENTRYPOINT ["/sesslint"]' in df


def test_ci_matrix_covers_declared_python_and_arm() -> None:
    """ci.yml matrix covers the declared python range + one ARM leg (qa-infra T-04)."""
    yaml = pytest.importorskip("yaml", reason="PyYAML required for matrix assertions")
    with open(CI_WORKFLOW, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    matrix = data["jobs"]["test"]["strategy"]["matrix"]
    versions = matrix["python-version"]
    for v in ("3.11", "3.12", "3.13", "3.14"):
        assert v in versions, f"py{v} missing from test matrix"
    assert set(matrix["os"]) == {"ubuntu-latest", "windows-latest", "macos-latest"}
    includes = matrix.get("include", [])
    arm_legs = [i for i in includes if "arm" in str(i.get("os", ""))]
    assert len(arm_legs) == 1, "exactly one ARM leg expected (cost-bounded)"
    assert arm_legs[0]["python-version"] == versions[-1], "ARM leg should run the newest py"
