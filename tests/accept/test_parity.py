"""Acceptance parity tests re-exporting TASK-024 library <-> CLI parity checks (TASK-028)."""

from __future__ import annotations

from tests.test_parity import (
    test_parity_check_dir_recursive,
    test_parity_check_file_ambiguity,
    test_parity_check_file_healthy,
    test_parity_verify_command,
)

__all__ = [
    "test_parity_check_dir_recursive",
    "test_parity_check_file_ambiguity",
    "test_parity_check_file_healthy",
    "test_parity_verify_command",
]
