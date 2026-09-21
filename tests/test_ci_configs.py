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


def test_release_workflow_five_job_dag_order() -> None:
    """Five jobs: build -> github-draft -> {binaries, pypi-publish} -> github-promote.

    The ``binaries`` matrix job fans out after github-draft and attaches native
    executables to the draft release. It must never gate ``pypi-publish``
    (PyPI ships only wheel+sdist); ``github-promote`` waits on both so the
    public release is complete.
    """
    content = _release_content()
    blocks = _job_blocks(content)
    assert list(blocks) == [
        "build",
        "github-draft",
        "binaries",
        "provenance",
        "image",
        "pypi-publish",
        "github-promote",
    ], f"job order/set mismatch: {list(blocks)}"
    assert "needs: build" in blocks["github-draft"]
    assert "needs: github-draft" in blocks["binaries"]
    assert "needs: github-draft" in blocks["pypi-publish"]
    promote_needs = re.search(r"needs:\s*\[([^\]]+)\]", blocks["github-promote"])
    assert promote_needs, "github-promote must declare a multi-job needs list"
    needed = {n.strip() for n in promote_needs.group(1).split(",")}
    assert needed == {"pypi-publish", "binaries"}, (
        f"github-promote must wait on pypi-publish AND binaries, got {needed}"
    )


def test_release_workflow_tag_version_validation() -> None:
    """The build job validates tag == 'v' + _version.py version before building."""
    build = _job_blocks(_release_content())["build"]
    assert "_version.py" in build
    assert "GITHUB_REF_NAME" in build
    assert re.search(r"GITHUB_REF_NAME#v", build), "tag must be stripped of leading 'v'"
    assert re.search(r"mismatch|!=", build), "build must abort on tag/version mismatch"


def test_release_workflow_minimal_permissions() -> None:
    """contents:write only on draft/promote/binaries; id-token:write only on pypi-publish."""
    content = _release_content()
    top = content[: content.find("\njobs:")]
    assert "contents: write" not in top, "no workflow-level write permission allowed"
    assert re.search(r"permissions:\s*\n\s*contents:\s*read", top)

    blocks = _job_blocks(content)
    for name, block in blocks.items():
        writes_contents = "contents: write" in block
        writes_idtoken = "id-token: write" in block
        if name in ("github-draft", "github-promote", "binaries", "provenance"):
            # binaries: gh release upload; provenance: .intoto.jsonl asset upload
            assert writes_contents, f"{name} must hold contents: write"
        else:
            assert not writes_contents, f"{name} must not hold contents: write"
        if name in ("pypi-publish", "build", "binaries", "provenance"):
            # pypi-publish: Trusted Publisher OIDC; build/binaries: Sigstore
            # keyless signing; provenance: SLSA generator Fulcio OIDC —
            # id-token only where OIDC is used.
            assert writes_idtoken, f"{name} must hold id-token: write"
        else:
            assert not writes_idtoken, f"{name} must not hold id-token: write"
        if name == "image":
            # GHCR push needs packages: write; no other job may hold it.
            assert "packages: write" in block, "image must hold packages: write"
        else:
            assert "packages: write" not in block, f"{name} must not hold packages: write"


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


def test_release_workflow_gh_commands_have_repo_context() -> None:
    """gh release calls run in jobs without checkout, so each must pass explicit repo.

    Regression guard for the v0.1.0 first-run failure: `gh release create` without
    `-R/--repo` in a job lacking actions/checkout fails with 'not a git repository'.
    """
    for job_name, block in _job_blocks(_release_content()).items():
        for m in re.finditer(r"gh release \w+", block):
            seg = block[m.start() : m.start() + 300]
            assert re.search(r"--repo|-R\s", seg), (
                f"{job_name}: gh release command missing explicit repo context"
            )


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
    """If PyYAML is available, release.yml must parse and expose the five-job DAG."""
    try:
        import yaml
    except ImportError:
        pytest.skip("PyYAML not installed; stdlib structural checks succeeded")

    with open(RELEASE_WORKFLOW, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert data is not None
    assert list(data["jobs"]) == [
        "build",
        "github-draft",
        "binaries",
        "provenance",
        "image",
        "pypi-publish",
        "github-promote",
    ]
    # SLSA provenance is off the promote critical path (non-blocking until
    # verified end-to-end — flip deliberately, not silently).
    assert "provenance" not in data["jobs"]["github-promote"]["needs"]
    assert set(data["jobs"]["provenance"]["needs"]) == {"build", "github-draft"}


def test_package_metadata_consistency() -> None:
    """pyproject/_version.py agree on name, version, license, python floor (T-07a audit)."""
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    version_py = (REPO_ROOT / "src" / "sesslint" / "_version.py").read_text(encoding="utf-8")

    assert re.search(r'^name\s*=\s*"sesslint"', pyproject, re.M)
    assert 'path = "src/sesslint/_version.py"' in pyproject
    m = re.search(r'__version__\s*=\s*"([^"]+)"', version_py)
    assert m and m.group(1) == "0.3.0"
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
    """release.yml generates SLSA L3 provenance via pinned reusable generator (T-03)."""
    content = _release_content()
    assert re.search(
        r"slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3\.yml@[0-9a-f]{40}\s*#\s*v\d+\.\d+\.\d+",
        content,
    ), "SLSA generator must be pinned by SHA"
    blocks = _job_blocks(content)
    prov = blocks["provenance"]
    assert "base64-subjects" in prov and "needs.build.outputs.artifact-subjects" in prov
    assert "upload-assets: true" in prov
    assert "provenance-name" in prov and ".intoto.jsonl" in prov
    assert "artifact-subjects" in blocks["build"]
    for perm in ("actions: read", "id-token: write", "contents: write"):
        assert perm in prov, f"provenance missing {perm}"


def test_release_workflow_ghcr_image() -> None:
    """release.yml builds + pushes a GHCR image from the linux binary (T-05)."""
    content = _release_content()
    blocks = _job_blocks(content)
    img = blocks["image"]
    # Consumes the ubuntu-leg binary via short-lived workflow artifact.
    assert "sesslint-linux-x86_64" in img
    assert "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093" in img
    assert "ghcr.io" in img and "docker login" in img
    assert "docker build" in img and "docker push" in img
    # In-job smoke before push: version --json must run against the image.
    assert img.index("docker run --rm") < img.index("docker push"), "smoke must precede push"
    # Ubuntu leg of binaries uploads the binary as a 1-day artifact.
    binaries = blocks["binaries"]
    assert "sesslint-linux-x86_64" in binaries and "retention-days: 1" in binaries
    # Image is off the promote critical path (like provenance).
    assert "image" not in _job_blocks(content)["github-promote"].split("needs:")[1]


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
