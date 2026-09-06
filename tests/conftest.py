"""Shared pytest fixtures, Hypothesis profiles, and test constants for SessLint."""

from __future__ import annotations

import pytest
from hypothesis import settings

from sesslint.io import ReaderLimits
from sesslint.report import Assurance

TEST_TOOL_VERSION: str = "0.1.0+test"
TEST_ASSURANCE: Assurance = "A1"
TEST_LIMITATION: str = "test-harness-conformance"
DEFAULT_TEST_LIMITS: ReaderLimits = ReaderLimits(
    max_line_bytes=1_000_000,
    max_depth=100,
    max_file_bytes=100 * 1024 * 1024,
)

# Hypothesis test profiles
settings.register_profile("ci", max_examples=100, deadline=None, derandomize=True)
settings.register_profile("dev", max_examples=25, deadline=None)
settings.load_profile("dev")


@pytest.fixture
def test_tool_version() -> str:
    """Fixture providing the canonical test tool version string."""
    return TEST_TOOL_VERSION


@pytest.fixture
def default_limits() -> ReaderLimits:
    """Fixture providing standard testing reader limits."""
    return DEFAULT_TEST_LIMITS
