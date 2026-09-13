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
