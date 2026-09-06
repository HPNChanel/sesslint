"""Tests for source session immutability contract across repair and check operations (TASK-026).

Verifies:
- Source file bytes and SHA-256 digest are strictly identical before and after any repair operation.
- Neither check, plan, nor repair ever modifies the source file in place (FR-069, AC-010, AC-011).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from sesslint import api
from sesslint.source import fingerprint_file

FIXTURE_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "fixtures"
    / "determinism"
    / "repeat"
    / "repeat_session.json"
)


def test_source_file_immutability_under_check_and_repair(tmp_path: Path) -> None:
    """Source file bytes and SHA-256 digest are unchanged across check, plan, and repair."""
    # Copy fixture to tmp_path to test in isolation
    isolated_source = tmp_path / "source_session.jsonl"
    isolated_source.write_bytes(FIXTURE_PATH.read_bytes())

    initial_bytes = isolated_source.read_bytes()
    initial_sha = hashlib.sha256(initial_bytes).hexdigest()
    initial_fp = fingerprint_file(isolated_source)

    # 1. Run check
    rep = api.check_file(isolated_source)
    assert rep.source_fingerprint == initial_fp
    assert isolated_source.read_bytes() == initial_bytes

    # 2. Run plan
    plan = api.plan(isolated_source, policy="conservative")
    assert len(plan.source_hash) == 64
    assert isolated_source.read_bytes() == initial_bytes

    # 3. Run repair
    dest = tmp_path / "repaired_copy.jsonl"
    plan_obj, manifest = api.repair(
        isolated_source,
        output_path=dest,
        policy="conservative",
        acknowledge_side_effects=True,
    )

    # Post-repair assertions on source
    post_bytes = isolated_source.read_bytes()
    post_sha = hashlib.sha256(post_bytes).hexdigest()
    assert post_bytes == initial_bytes, "Source file was modified during repair execution!"
    assert post_sha == initial_sha, "Source file SHA-256 changed after repair execution!"

    # Output file is distinct and exists
    assert dest.exists()
    assert dest != isolated_source
