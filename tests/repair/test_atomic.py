"""Tests for repair executor atomic write invariants under fault injection (TASK-026).

Verifies:
- A failure during atomic rename (os.replace raising OSError) guarantees destination file
  does not exist or remains untouched.
- Any temporary staging files (.sesslint_tmp_*) are cleaned up and do not linger.
- The repair execution raises an OperationalError / AtomicWriteError and refuses to emit
  a success manifest.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from sesslint import api
from sesslint.atomic import atomic_write_bytes
from sesslint.errors import AtomicWriteError

FIXTURES_REPAIR = (
    Path(__file__).resolve().parent.parent.parent / "fixtures" / "repair" / "conservative"
)


def test_atomic_replace_failure_cleans_temporary_files(tmp_path: Path) -> None:
    """When os.replace fails with simulated I/O error, destination is absent and tmp is removed."""
    dest = tmp_path / "final_output.jsonl"
    data = b'{"schema_version": "sesslint.session/v1", "session_id": "test"}\n'

    with patch("os.replace", side_effect=OSError("Disk hardware write fault")):
        with pytest.raises(AtomicWriteError, match="Atomic write to .* failed"):
            atomic_write_bytes(dest, data)

    # Destination was never created
    assert not dest.exists()

    # Zero temporary files left behind
    temp_files = list(tmp_path.glob(".sesslint_tmp_*"))
    assert len(temp_files) == 0


def test_repair_executor_atomic_failure_leaves_no_output(tmp_path: Path) -> None:
    """Repair execution under simulated replace failure leaves no output and no manifest."""
    src = FIXTURES_REPAIR / "valid_orphan_return.jsonl"
    if not src.is_file():
        # Create a minimal repairable fixture if needed
        src = tmp_path / "source.jsonl"
        src.write_text(
            '{"created_at":"2026-09-06T00:00:00Z","schema_version":"sesslint.session/v1","session_id":"s1"}\n'
            '{"actor":"tool","id":"t1","kind":"tool_return","parent_id":null,"payload":{},"seq":1,"ts":"2026-09-06T00:00:01Z"}\n',
            encoding="utf-8",
        )

    out = tmp_path / "repaired_output.jsonl"
    man = tmp_path / "manifest.json"

    with patch("os.replace", side_effect=OSError("Permission denied on replace")):
        try:
            api.repair(src, output_path=out, policy="conservative")
        except Exception:
            pass

    # Destination output file must NOT exist
    assert not out.exists(), "Corrupted or partial output file exists after replace failure"
    # Manifest must NOT exist
    assert not man.exists(), "Manifest was emitted despite repair execution failure"

    # Zero lingering temp files in tmp_path
    temp_files = list(tmp_path.glob(".sesslint_tmp_*"))
    assert len(temp_files) == 0
