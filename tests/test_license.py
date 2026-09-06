"""Tests verifying OSS license compliance and coverage (TASK-028, FR-105).

Guarantees:
- LICENSE file exists at repository root and contains the canonical Apache 2.0 text.
- NOTICE file exists and accurately describes runtime vs dev dependencies.
- pyproject.toml explicitly declares the Apache-2.0 license and OSI classifier.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LICENSE_PATH = REPO_ROOT / "LICENSE"
NOTICE_PATH = REPO_ROOT / "NOTICE"
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"


def test_license_file_exists_and_valid() -> None:
    """Repository root must contain the Apache License 2.0 text."""
    assert LICENSE_PATH.is_file(), f"Missing {LICENSE_PATH}"
    content = LICENSE_PATH.read_text(encoding="utf-8")
    assert "Apache License" in content
    assert "Version 2.0, January 2004" in content
    assert "http://www.apache.org/licenses/" in content


def test_notice_file_exists_and_accurate() -> None:
    """NOTICE file exists and notes zero runtime third-party dependencies."""
    assert NOTICE_PATH.is_file(), f"Missing {NOTICE_PATH}"
    content = NOTICE_PATH.read_text(encoding="utf-8")
    assert "SessLint" in content
    assert "Apache License, Version 2.0" in content
    assert "standard library" in content


def test_pyproject_license_metadata() -> None:
    """pyproject.toml must specify Apache-2.0 and OSI classifier."""
    assert PYPROJECT_PATH.is_file()
    with open(PYPROJECT_PATH, "rb") as f:
        data = tomllib.load(f)

    project = data.get("project", {})
    assert project.get("license") == "Apache-2.0"

    classifiers = project.get("classifiers", [])
    assert "License :: OSI Approved :: Apache Software License" in classifiers
