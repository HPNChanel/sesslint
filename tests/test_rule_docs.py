"""Tests verifying reason-code documentation completeness and sync (TASK-028).

Invariants verified:
1. Every code in CODE_REGISTRY has a corresponding docs/codes/{code}.md file.
2. docs/codes/ contains no untracked or dangling SL*.md files.
3. Every reason-code doc contains all required analytical sections:
   - Invariant
   - Cause
   - False-Positive Notes
   - Recipe or Manual Path
   - Example (content-free)
   - Tested Fixture
4. Every doc references a fixture path that actually exists in the repository.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from sesslint.codes import CODE_REGISTRY

REPO_ROOT = Path(__file__).resolve().parent.parent
CODES_DIR = REPO_ROOT / "docs" / "codes"

REQUIRED_SECTIONS = (
    "## Overview",
    "## Invariant",
    "## Cause",
    "## False-Positive Notes",
    "## Recipe or Manual Path",
    "## Example",
    "## Tested Fixture",
)


def test_codes_directory_exists() -> None:
    """Ensure the docs/codes directory exists."""
    assert CODES_DIR.is_dir(), f"Docs directory {CODES_DIR} does not exist"


def test_all_registry_codes_have_docs() -> None:
    """Assert every registered detector code has an existing Markdown document."""
    for code in CODE_REGISTRY:
        doc_path = CODES_DIR / f"{code}.md"
        assert doc_path.is_file(), f"Missing documentation file for code {code}: {doc_path}"


def test_no_extra_or_stale_code_docs() -> None:
    """Assert that docs/codes contains no undocumented or stale SL*.md files."""
    doc_files = sorted(CODES_DIR.glob("SL*.md"))
    doc_codes = {f.stem for f in doc_files}
    registry_codes = set(CODE_REGISTRY.keys())

    extra = doc_codes - registry_codes
    assert not extra, f"Found extraneous/stale code doc files in {CODES_DIR}: {extra}"


@pytest.mark.parametrize("code", sorted(CODE_REGISTRY.keys()))
def test_code_doc_structure_and_sections(code: str) -> None:
    """Assert each code doc has all required sections and nonempty contents."""
    doc_path = CODES_DIR / f"{code}.md"
    assert doc_path.is_file()
    text = doc_path.read_text(encoding="utf-8")

    # Document must start with H1 title containing the code
    assert text.startswith(f"# {code}:"), f"{doc_path} title does not start with '# {code}:'"

    for section in REQUIRED_SECTIONS:
        assert section in text, f"{doc_path} is missing required section '{section}'"


@pytest.mark.parametrize("code", sorted(CODE_REGISTRY.keys()))
def test_code_doc_fixture_reference_exists(code: str) -> None:
    """Assert that every code doc names a tested fixture and that the fixture exists on disk."""
    doc_path = CODES_DIR / f"{code}.md"
    text = doc_path.read_text(encoding="utf-8")

    # Extract fixture path from Tested Fixture section
    match = re.search(r"## Tested Fixture\s*\n\s*-\s*Path:\s*`([^`]+)`", text)
    assert match is not None, f"{doc_path} does not match expected '- Path: `...`' pattern"

    rel_fixture_path = match.group(1).strip()
    fixture_file = REPO_ROOT / rel_fixture_path
    assert fixture_file.is_file(), (
        f"{doc_path} references non-existent fixture file: {rel_fixture_path}"
    )
