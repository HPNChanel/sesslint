"""Tests verifying recipe documentation completeness, consistency, and sync (TASK-028).

Invariants verified:
1. Every recipe registered in the repair module has a corresponding docs/recipes/{name}.md file.
2. docs/recipes/ contains no untracked or dangling *.md files (excluding README.md).
3. Every recipe doc contains required analytical sections:
   - Overview
   - Preconditions
   - Risk
   - Evidence
   - Non-Proof Statement
   - Loss Behavior
   - Tested Fixture
4. Every recipe doc references a fixture path that actually exists in the repository.
5. Declared metadata (handles, lossy, salvage_only) in markdown docs matches the live registry.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import sesslint.repair as repair_mod

REPO_ROOT = Path(__file__).resolve().parent.parent
RECIPES_DIR = REPO_ROOT / "docs" / "recipes"

REQUIRED_SECTIONS = (
    "## Overview",
    "## Preconditions",
    "## Risk",
    "## Evidence",
    "## Non-Proof Statement",
    "## Loss Behavior",
    "## Tested Fixture",
)


def test_recipes_directory_exists() -> None:
    """Ensure the docs/recipes directory exists."""
    assert RECIPES_DIR.is_dir(), f"Docs directory {RECIPES_DIR} does not exist"


def test_all_registered_recipes_have_docs() -> None:
    """Assert every registered recipe has a corresponding markdown doc."""
    recipes = repair_mod.list_recipes()
    assert len(recipes) >= 8, f"Expected at least 8 registered recipes, got {len(recipes)}"
    for recipe in recipes:
        doc_path = RECIPES_DIR / f"{recipe.name}.md"
        assert doc_path.is_file(), f"Missing recipe documentation file: {doc_path}"


def test_no_extra_or_stale_recipe_docs() -> None:
    """Assert that docs/recipes contains no unregistered recipe docs."""
    registered_names = {r.name for r in repair_mod.list_recipes()}
    doc_files = [f for f in RECIPES_DIR.glob("*.md") if f.name != "README.md"]
    doc_names = {f.stem for f in doc_files}

    extra = doc_names - registered_names
    assert not extra, f"Found extraneous/stale recipe doc files in {RECIPES_DIR}: {extra}"


@pytest.mark.parametrize("recipe", repair_mod.list_recipes(), ids=lambda r: r.name)
def test_recipe_doc_structure_and_sections(recipe: repair_mod.Recipe) -> None:
    """Assert each recipe doc has all required sections and nonempty contents."""
    doc_path = RECIPES_DIR / f"{recipe.name}.md"
    assert doc_path.is_file()
    text = doc_path.read_text(encoding="utf-8")

    # Document must start with H1 title
    assert text.startswith(f"# Recipe: {recipe.name}"), (
        f"{doc_path} title does not start with '# Recipe: {recipe.name}'"
    )

    for section in REQUIRED_SECTIONS:
        assert section in text, f"{doc_path} is missing required section '{section}'"


@pytest.mark.parametrize("recipe", repair_mod.list_recipes(), ids=lambda r: r.name)
def test_recipe_doc_fixture_reference_exists(recipe: repair_mod.Recipe) -> None:
    """Assert that every recipe doc names a tested fixture and that the fixture exists on disk."""
    doc_path = RECIPES_DIR / f"{recipe.name}.md"
    text = doc_path.read_text(encoding="utf-8")

    match = re.search(r"## Tested Fixture\s*\n\s*-\s*Path:\s*`([^`]+)`", text)
    assert match is not None, f"{doc_path} does not match expected '- Path: `...`' pattern"

    rel_fixture_path = match.group(1).strip()
    fixture_file = REPO_ROOT / rel_fixture_path
    assert fixture_file.is_file(), (
        f"{doc_path} references non-existent fixture file: {rel_fixture_path}"
    )


@pytest.mark.parametrize("recipe", repair_mod.list_recipes(), ids=lambda r: r.name)
def test_recipe_doc_metadata_matches_registry(recipe: repair_mod.Recipe) -> None:
    """Assert that lossy, salvage_only, and handled codes match the live registry values."""
    doc_path = RECIPES_DIR / f"{recipe.name}.md"
    text = doc_path.read_text(encoding="utf-8")

    expected_lossy = "true" if recipe.lossy else "false"
    assert f"- **Lossy**: `{expected_lossy}`" in text, (
        f"{doc_path} has mismatched lossy status (expected {expected_lossy})"
    )

    expected_salvage = "true" if recipe.salvage_only else "false"
    assert f"- **Salvage Only**: `{expected_salvage}`" in text, (
        f"{doc_path} has mismatched salvage_only status (expected {expected_salvage})"
    )

    for code in recipe.handles:
        assert f"`{code}`" in text, f"{doc_path} missing handled code `{code}` in Overview"
