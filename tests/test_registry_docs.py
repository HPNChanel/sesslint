"""Tests verifying recipe documentation completeness, consistency, and sync (TASK-028, DEV-012).

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
6. The recipe catalog in README.md matches the live registry (names, partition, count).
7. The recipe catalog in docs/recipes/README.md matches the live registry.
8. RELEASING.md checklist verifies the exact count of 9 recipes.
9. Negative unit tests prove that the catalog-lock assertions catch drift.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import NamedTuple

import pytest

import sesslint.repair as repair_mod

REPO_ROOT = Path(__file__).resolve().parent.parent
RECIPES_DIR = REPO_ROOT / "docs" / "recipes"
README_PATH = REPO_ROOT / "README.md"
RECIPES_README_PATH = RECIPES_DIR / "README.md"
RELEASING_PATH = REPO_ROOT / "RELEASING.md"

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
    assert len(recipes) == 9, f"Expected exactly 9 registered recipes, got {len(recipes)}"
    cons_count = sum(1 for r in recipes if not r.salvage_only)
    salv_count = sum(1 for r in recipes if r.salvage_only)
    assert cons_count == 5, f"Expected 5 conservative recipes, got {cons_count}"
    assert salv_count == 4, f"Expected 4 salvage recipes, got {salv_count}"
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

    handles_match = re.search(r"-\s+\*\*Handles Codes\*\*:\s*([^\n]+)", text)
    assert handles_match is not None, f"{doc_path} missing '- **Handles Codes**:' metadata"
    doc_codes = tuple(sorted(re.findall(r"`(SL\d+)`", handles_match.group(1))))
    expected_codes = tuple(sorted(recipe.handles))
    assert doc_codes == expected_codes, (
        f"{doc_path} handled codes mismatch: declared {doc_codes}, registry has {expected_codes}"
    )


class CatalogPartition(NamedTuple):
    conservative: dict[str, tuple[str, ...]]
    salvage: dict[str, tuple[str, ...]]


def parse_readme_catalog(text: str) -> CatalogPartition:
    """Extract conservative and salvage recipe dictionaries with handled codes from README.md."""
    start_pos = text.find("### Recipe Catalog")
    if start_pos == -1:
        raise ValueError("README.md missing '### Recipe Catalog' section")
    end_pos = text.find("\n---", start_pos)
    catalog_text = text[start_pos:] if end_pos == -1 else text[start_pos:end_pos]

    cons_match = re.search(
        r"#### Conservative Recipes[^\n]*\n(.*?)(?=#### Salvage Recipes|\Z)",
        catalog_text,
        re.DOTALL,
    )
    if not cons_match:
        raise ValueError("README.md missing '#### Conservative Recipes' section")

    salv_match = re.search(
        r"#### Salvage Recipes[^\n]*\n(.*?)(?=\n---|###|\Z)",
        catalog_text,
        re.DOTALL,
    )
    if not salv_match:
        raise ValueError("README.md missing '#### Salvage Recipes' section")

    def _extract_bullets(section_text: str) -> dict[str, tuple[str, ...]]:
        result: dict[str, tuple[str, ...]] = {}
        for line in section_text.splitlines():
            m = re.search(r"-\s+\*\*`([a-z0-9-]+)`\*\*(?:\s*\(([^)]+)\))?", line)
            if m:
                name = m.group(1)
                codes_raw = m.group(2)
                codes = tuple(sorted(re.findall(r"SL\d+", codes_raw))) if codes_raw else ()
                result[name] = codes
        return result

    return CatalogPartition(
        conservative=_extract_bullets(cons_match.group(1)),
        salvage=_extract_bullets(salv_match.group(1)),
    )


def parse_recipes_readme_catalog(text: str) -> CatalogPartition:
    """Extract conservative and salvage recipe sets from docs/recipes/README.md."""
    cons_match = re.search(
        r"1\.\s+\*\*Conservative Recipes\*\*.*?\n(.*?)(?=2\.\s+\*\*Salvage Recipes\*\*|\Z)",
        text,
        re.DOTALL,
    )
    if not cons_match:
        raise ValueError("docs/recipes/README.md missing Conservative Recipes section")

    salv_match = re.search(
        r"2\.\s+\*\*Salvage Recipes\*\*.*?\n(.*?)(?=##|\Z)",
        text,
        re.DOTALL,
    )
    if not salv_match:
        raise ValueError("docs/recipes/README.md missing Salvage Recipes section")

    def _extract_simple_bullets(section_text: str) -> dict[str, tuple[str, ...]]:
        result: dict[str, tuple[str, ...]] = {}
        for line in section_text.splitlines():
            m = re.search(r"-\s+`([a-z0-9-]+)`", line)
            if m:
                result[m.group(1)] = ()
        return result

    return CatalogPartition(
        conservative=_extract_simple_bullets(cons_match.group(1)),
        salvage=_extract_simple_bullets(salv_match.group(1)),
    )


def assert_catalog_sync(
    doc_partition: CatalogPartition,
    registered_recipes: tuple[repair_mod.Recipe, ...],
    doc_name: str,
) -> None:
    """Assert doc recipe catalog matches live registry partition and handled codes exactly."""
    expected_conservative = {r.name for r in registered_recipes if not r.salvage_only}
    expected_salvage = {r.name for r in registered_recipes if r.salvage_only}
    recipe_by_name = {r.name: r for r in registered_recipes}

    doc_cons_names = set(doc_partition.conservative.keys())
    doc_salv_names = set(doc_partition.salvage.keys())

    errors: list[str] = []

    missing_cons = expected_conservative - doc_cons_names
    extra_cons = doc_cons_names - expected_conservative
    if missing_cons:
        errors.append(f"Missing conservative recipes in {doc_name}: {sorted(missing_cons)}")
    if extra_cons:
        errors.append(f"Unexpected conservative recipes in {doc_name}: {sorted(extra_cons)}")

    missing_salv = expected_salvage - doc_salv_names
    extra_salv = doc_salv_names - expected_salvage
    if missing_salv:
        errors.append(f"Missing salvage recipes in {doc_name}: {sorted(missing_salv)}")
    if extra_salv:
        errors.append(f"Unexpected salvage recipes in {doc_name}: {sorted(extra_salv)}")

    misplaced_salvage_in_cons = doc_cons_names & expected_salvage
    if misplaced_salvage_in_cons:
        errors.append(
            f"Salvage recipes misclassified as conservative in {doc_name}: "
            f"{sorted(misplaced_salvage_in_cons)}"
        )
    misplaced_cons_in_salvage = doc_salv_names & expected_conservative
    if misplaced_cons_in_salvage:
        errors.append(
            f"Conservative recipes misclassified as salvage in {doc_name}: "
            f"{sorted(misplaced_cons_in_salvage)}"
        )

    # Verify handled codes when present in doc
    combined_docs = {**doc_partition.conservative, **doc_partition.salvage}
    for name, declared_codes in combined_docs.items():
        if declared_codes and name in recipe_by_name:
            expected_codes = tuple(sorted(recipe_by_name[name].handles))
            if declared_codes != expected_codes:
                errors.append(
                    f"Recipe `{name}` in {doc_name} declares handled codes {declared_codes}, "
                    f"expected {expected_codes} from registry"
                )

    if errors:
        raise AssertionError("\n".join(errors))


def test_readme_recipe_catalog_matches_registry() -> None:
    """Assert README.md's Recipe Catalog matches live registry exactly."""
    text = README_PATH.read_text(encoding="utf-8")
    assert "9 deterministic repair recipes" in text, (
        "README.md must mention exactly '9 deterministic repair recipes'"
    )
    partition = parse_readme_catalog(text)
    recipes = repair_mod.list_recipes()
    assert_catalog_sync(partition, recipes, "README.md")


def test_recipes_readme_catalog_matches_registry() -> None:
    """Assert docs/recipes/README.md's catalog matches live registry exactly."""
    text = RECIPES_README_PATH.read_text(encoding="utf-8")
    assert "9 deterministic repair recipes" in text, (
        "docs/recipes/README.md must mention '9 deterministic repair recipes'"
    )
    partition = parse_recipes_readme_catalog(text)
    recipes = repair_mod.list_recipes()
    assert_catalog_sync(partition, recipes, "docs/recipes/README.md")


def test_releasing_checklist_recipe_count() -> None:
    """Assert RELEASING.md checklist has the correct 9 recipes count."""
    text = RELEASING_PATH.read_text(encoding="utf-8")
    assert "- [ ] All 9 repair recipes have synced documentation" in text, (
        "RELEASING.md checklist must mention 'All 9 repair recipes'"
    )


def test_catalog_lock_catches_missing_recipe() -> None:
    """Negative unit test: assert_catalog_sync catches a missing recipe."""
    fake_partition = CatalogPartition(
        conservative={"identical-duplicate-collapse": ()},
        salvage={
            "terminal-suffix-discard": (),
            "unresolvable-branch-amputate": (),
            "torn-compaction-project": (),
            "side-effect-unknown-truncate": (),
        },
    )
    recipes = repair_mod.list_recipes()
    with pytest.raises(AssertionError, match="Missing conservative recipes in test_doc"):
        assert_catalog_sync(fake_partition, recipes, "test_doc")


def test_catalog_lock_catches_extra_recipe() -> None:
    """Negative unit test: assert_catalog_sync catches an extra unregistered recipe."""
    recipes = repair_mod.list_recipes()
    real_cons = {r.name: () for r in recipes if not r.salvage_only}
    real_salv = {r.name: () for r in recipes if r.salvage_only}
    fake_partition = CatalogPartition(
        conservative={**real_cons, "fake-conservative-recipe": ()},
        salvage=real_salv,
    )
    with pytest.raises(AssertionError, match="Unexpected conservative recipes in test_doc"):
        assert_catalog_sync(fake_partition, recipes, "test_doc")


def test_catalog_lock_catches_misclassified_recipe() -> None:
    """Negative unit test: assert_catalog_sync catches misclassified partition."""
    recipes = repair_mod.list_recipes()
    real_cons = {r.name: () for r in recipes if not r.salvage_only}
    real_salv = {r.name: () for r in recipes if r.salvage_only}
    fake_cons = {k: v for k, v in real_cons.items() if k != "identical-duplicate-collapse"}
    fake_cons["terminal-suffix-discard"] = ()
    fake_salv = {k: v for k, v in real_salv.items() if k != "terminal-suffix-discard"}
    fake_salv["identical-duplicate-collapse"] = ()
    fake_partition = CatalogPartition(conservative=fake_cons, salvage=fake_salv)
    with pytest.raises(
        AssertionError, match="Salvage recipes misclassified as conservative in test_doc"
    ):
        assert_catalog_sync(fake_partition, recipes, "test_doc")


def test_catalog_lock_catches_mismatched_handled_codes() -> None:
    """Negative unit test: assert_catalog_sync catches mismatched handled codes in doc."""
    recipes = repair_mod.list_recipes()
    cons_dict = {r.name: tuple(sorted(r.handles)) for r in recipes if not r.salvage_only}
    salv_dict = {r.name: tuple(sorted(r.handles)) for r in recipes if r.salvage_only}
    # Mutate a handled code to an incorrect one
    cons_dict["torn-terminal-record-discard"] = ("SL005",)
    fake_partition = CatalogPartition(conservative=cons_dict, salvage=salv_dict)
    with pytest.raises(
        AssertionError,
        match=r"Recipe `torn-terminal-record-discard` in test_doc declares handled codes",
    ):
        assert_catalog_sync(fake_partition, recipes, "test_doc")
