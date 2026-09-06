"""Tests verifying fixture provenance and data privacy guarantees (TASK-028, AC-030).

Guarantees:
- Every fixture directory contains a valid PROVENANCE.json.
- contains_real_data is strictly false across all fixtures.
- Synthetic fixtures have explicit integer seeds.
- Any non-text binary blobs have an accompanying ASCII description.
"""

from __future__ import annotations

import json
from pathlib import Path

FIXTURES_ROOT = Path(__file__).resolve().parent.parent / "fixtures"


def test_all_fixture_dirs_have_valid_provenance() -> None:
    """Every directory containing test fixtures must have a conforming PROVENANCE.json."""
    assert FIXTURES_ROOT.is_dir(), f"Missing fixtures directory: {FIXTURES_ROOT}"

    # Collect all directories containing files other than PROVENANCE.json
    fixture_dirs: set[Path] = set()
    for file_path in FIXTURES_ROOT.rglob("*"):
        if file_path.is_file() and file_path.name != "PROVENANCE.json":
            fixture_dirs.add(file_path.parent)

    assert len(fixture_dirs) > 0, "No fixture directories found"

    for d in sorted(fixture_dirs):
        prov_path = d / "PROVENANCE.json"
        rel_path = d.relative_to(FIXTURES_ROOT)
        assert prov_path.is_file(), (
            f"Fixture directory '{rel_path}' is missing PROVENANCE.json (AC-030)"
        )

        try:
            data = json.loads(prov_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as err:
            raise AssertionError(f"Malformed PROVENANCE.json in '{rel_path}': {err}") from err

        # 1. origin check
        assert data.get("origin") in ("synthetic", "consented"), (
            f"'{rel_path}/PROVENANCE.json': origin must be 'synthetic' or 'consented', "
            f"got {data.get('origin')}"
        )

        # 2. Strict no-real-data policy
        assert data.get("contains_real_data") is False, (
            f"'{rel_path}/PROVENANCE.json': contains_real_data must be strictly false (AC-030)"
        )

        # 3. Synthetic seed check
        if data.get("origin") == "synthetic":
            assert isinstance(data.get("seed"), int), (
                f"'{rel_path}/PROVENANCE.json': synthetic fixtures must provide integer seed"
            )

        # 4. Description check
        desc = data.get("description")
        assert isinstance(desc, str) and bool(desc.strip()), (
            f"'{rel_path}/PROVENANCE.json': description must be a non-empty string"
        )


def test_binary_fixtures_have_ascii_descriptions() -> None:
    """Any binary fixture file must have an ASCII description or documented layout."""
    for bin_file in FIXTURES_ROOT.rglob("*.bin"):
        prov_path = bin_file.parent / "PROVENANCE.json"
        assert prov_path.is_file(), f"Binary fixture {bin_file} missing PROVENANCE.json"
        data = json.loads(prov_path.read_text(encoding="utf-8"))
        assert "description" in data and len(data["description"]) > 0
