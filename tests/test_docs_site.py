"""Drift checks for the docs site (docs-spec/T-04).

Guards: mkdocs.yml config sanity, docs_dir coverage, workflow pins and
permissions, docs extra isolation from runtime deps.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
MKDOCS_YML = REPO_ROOT / "mkdocs.yml"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "docs.yml"

yaml = pytest.importorskip("yaml", reason="PyYAML needed for workflow checks")


def test_mkdocs_yml_exists_and_uses_docs_dir() -> None:
    assert MKDOCS_YML.is_file()
    cfg = yaml.safe_load(MKDOCS_YML.read_text(encoding="utf-8"))
    assert cfg["docs_dir"] == "docs"
    assert cfg["theme"]["name"] == "material"


def test_no_nav_key_auto_includes_docs() -> None:
    # No `nav:` → mkdocs auto-includes every docs/ file; nav drift is
    # impossible and new rule/recipe docs reach the site automatically.
    cfg = yaml.safe_load(MKDOCS_YML.read_text(encoding="utf-8"))
    assert "nav" not in cfg


def test_docs_extra_is_dev_only() -> None:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    project = re.search(r"^dependencies = \[(.*?)\]", text, re.M | re.S)
    assert project and project.group(1).strip() == ""
    assert '"mkdocs-material' in text


def test_workflow_exists_with_build_and_deploy_jobs() -> None:
    wf = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert set(wf["jobs"]) == {"build", "deploy"}
    assert wf["jobs"]["deploy"]["needs"] == ["build"]


def test_workflow_permissions_least_privilege() -> None:
    wf = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert wf["permissions"] == {"contents": "read"}
    build = wf["jobs"]["build"]
    assert "permissions" not in build or build["permissions"] == {}
    deploy = wf["jobs"]["deploy"]
    assert deploy["permissions"] == {"pages": "write", "id-token": "write"}
    assert deploy["environment"]["name"] == "github-pages"


def test_workflow_sha_pins() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    uses = re.findall(r"uses: ([\w./-]+)@([0-9a-f]{40}) # (v\d+)", text)
    assert len(uses) >= 5
    for _repo, _sha, _ver in uses:
        assert len(_sha) == 40


def test_workflow_trigger_scoped_to_docs() -> None:
    wf = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    push = wf[True]["push"]  # YAML parses `on:` as True
    assert push["branches"] == ["main"]
    assert "docs/**" in push["paths"]
    assert "workflow_dispatch" in wf[True]


def test_mkdocs_build_produces_site() -> None:
    # Local smoke evidence: site/index.html + sitemap exist after
    # `mkdocs build`. Skipped when site/ absent (CI builds fresh anyway).
    site = REPO_ROOT / "site"
    if not site.is_dir():
        pytest.skip("site/ not built locally")
    assert (site / "index.html").is_file()
    assert (site / "sitemap.xml").is_file()


def test_site_output_gitignored() -> None:
    assert "\nsite/" in "\n" + (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
