"""Tests for safe cleanup and absence of partial outputs on abort/interrupt (TASK-026).

Verifies:
- An interrupted or killed repair process never publishes a partial or complete-looking
- No manifest is ever emitted on incomplete or interrupted operations
  (FR-068, FR-071, FR-096, AC-013).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from sesslint.atomic import atomic_write_bytes
from sesslint.errors import AtomicWriteError


def test_interrupted_repair_leaves_no_manifest_or_output(tmp_path: Path) -> None:
    """Simulating an unhandled KeyboardInterrupt or exception mid-stream produces zero output."""
    dest = tmp_path / "dest.jsonl"
    data = b'{"schema_version": "sesslint.session/v1", "session_id": "test"}\n'

    # Inject KeyboardInterrupt during writing/syncing
    with patch("os.fsync", side_effect=KeyboardInterrupt("Simulated SIGINT / cancel")):
        with pytest.raises(KeyboardInterrupt):
            atomic_write_bytes(dest, data)

    # Destination MUST NOT exist
    assert not dest.exists(), "Destination file was created despite interruption"

    # Temporary files cleaned up
    temp_files = list(tmp_path.glob(".sesslint_tmp_*"))
    assert len(temp_files) == 0


def test_write_error_cleans_temporary_storage(tmp_path: Path) -> None:
    """When disk write raises OSError (e.g. ENOSPC), temporary file is deleted immediately."""
    dest = tmp_path / "dest.jsonl"
    data = b'{"hello": "world"}\n'

    with patch("os.fsync", side_effect=OSError(28, "No space left on device")):
        with pytest.raises(AtomicWriteError, match="No space left on device"):
            atomic_write_bytes(dest, data)

    assert not dest.exists()
    temp_files = list(tmp_path.glob(".sesslint_tmp_*"))
    assert len(temp_files) == 0
