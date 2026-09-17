"""Tests for repository governance and contributor-facing metadata files.

Verifies existence and mandatory content of standard project files that the
test/config gates do not otherwise cover: security policy, code of conduct,
PR/issue templates, dependabot, CODEOWNERS, PEP 561 marker, and editor config.
Pure standard-library text scanning — no PyYAML required.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GITHUB_DIR = REPO_ROOT / ".github"


def _read(rel: str) -> str:
    path = REPO_ROOT / rel
    assert path.is_file(), f"Missing required file: {rel}"
    content = path.read_text(encoding="utf-8")
    assert content.strip(), f"{rel} must not be empty"
    return content


def test_py_typed_marker_shipped() -> None:
    """PEP 561 marker must exist so downstream mypy sees inline types."""
    assert (REPO_ROOT / "src" / "sesslint" / "py.typed").is_file()
    pyproject = _read("pyproject.toml")
    assert "Typing :: Typed" in pyproject


def test_security_policy_exists() -> None:
    """SECURITY.md must exist and route reports to private advisories."""
    content = _read("SECURITY.md")
    assert "github.com/HPNChanel/sesslint/security/advisories" in content
    assert re.search(r"[Ss]upported [Vv]ersions", content)


def test_code_of_conduct_exists() -> None:
    """CODE_OF_CONDUCT.md must exist and reference Contributor Covenant."""
    content = _read("CODE_OF_CONDUCT.md")
    assert "Contributor Covenant" in content
    assert "Enforcement" in content


def test_pull_request_template_exists() -> None:
    """PR template must carry the privacy warning and the gate checklist."""
    content = _read(".github/PULL_REQUEST_TEMPLATE.md")
    assert "NEVER" in content and "session transcripts" in content
    assert "mypy --strict" in content
    assert "PROVENANCE.json" in content


def test_feature_request_template_exists() -> None:
    """feature_request.md must have frontmatter and the perimeter check."""
    content = _read(".github/ISSUE_TEMPLATE/feature_request.md")
    assert "name: Feature Request" in content
    assert "enhancement" in content
    assert "network access" in content


def test_dependabot_config_exists() -> None:
    """dependabot.yml must cover github-actions and pip ecosystems."""
    content = _read(".github/dependabot.yml")
    assert "package-ecosystem: github-actions" in content
    assert "package-ecosystem: pip" in content


def test_codeowners_exists() -> None:
    """CODEOWNERS must assign a default owner."""
    content = _read(".github/CODEOWNERS")
    assert re.search(r"\*\s+@\S+", content)


def test_editorconfig_exists() -> None:
    """.editorconfig must pin LF endings and final newlines."""
    content = _read(".editorconfig")
    assert "root = true" in content
    assert "end_of_line = lf" in content
    assert "insert_final_newline = true" in content


def test_pre_commit_config_exists() -> None:
    """Repo-level pre-commit config must run the lint/format/type gates."""
    content = _read(".pre-commit-config.yaml")
    assert "ruff" in content
    assert "mypy" in content
    # Consumer-facing hook spec must remain intact alongside it.
    hooks = _read(".pre-commit-hooks.yaml")
    assert "- id: sesslint-check" in hooks


def test_citation_file_exists() -> None:
    """CITATION.cff must be valid cff-version 1.2.0+ and point at this repo."""
    content = _read("CITATION.cff")
    assert "cff-version:" in content
    assert "github.com/HPNChanel/sesslint" in content


def test_docs_index_exists() -> None:
    """docs/README.md index must exist and link to real documents."""
    content = _read("docs/README.md")
    for link in ("ADAPTER_GUIDE.md", "MATRIX.md", "codes/", "recipes/"):
        assert link in content, f"docs/README.md must link to {link}"
        assert (REPO_ROOT / "docs" / link.rstrip("/")).exists()


def test_agents_file_exists() -> None:
    """AGENTS.md must document the invariants and verification gates."""
    content = _read("AGENTS.md")
    assert "zero" in content.lower() and "dependenc" in content.lower()
    assert "pytest" in content and "mypy" in content and "ruff" in content


def test_codeql_workflow_exists() -> None:
    """codeql.yml must run the CodeQL python suite with least privileges."""
    content = _read(".github/workflows/codeql.yml")
    assert "github/codeql-action/init@" in content
    assert "github/codeql-action/analyze@" in content
    assert "languages: python" in content
    assert "security-events: write" in content


def test_no_stale_org_references() -> None:
    """No .github file may reference a non-existent 'sesslint/sesslint' org.

    Regression guard: the issue-template contact links originally pointed at
    github.com/sesslint/sesslint instead of github.com/HPNChanel/sesslint.
    """
    for path in GITHUB_DIR.rglob("*"):
        if path.is_file():
            content = path.read_text(encoding="utf-8")
            assert "github.com/sesslint/" not in content, (
                f"stale org reference in {path.relative_to(REPO_ROOT)}"
            )
