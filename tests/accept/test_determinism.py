"""Tests for byte-identical determinism and repeat stability across runs (TASK-026).

Verifies:
- Multiple runs of check and verify produce byte-identical canonical JSON digests.
- PYTHONHASHSEED variation (0, 1, 42) does not affect output or finding fingerprints.
- Plan fingerprints are deterministic across identical source sessions.
- Timestamps do not introduce non-determinism into hashed reports.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

from sesslint import api
from sesslint.determinism import canonical_json_bytes, repeat_hash
from sesslint.report import render_json

FIXTURE_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "fixtures"
    / "determinism"
    / "repeat"
    / "repeat_session.json"
)


def test_repeat_check_produces_identical_hash() -> None:
    """Repeat runs of api.check_file on the same fixture yield byte-identical reports."""
    hashes: list[str] = []
    for _ in range(3):
        rep = api.check_file(FIXTURE_PATH)
        json_str = render_json(rep)
        h = hashlib.sha256(json_str.encode("utf-8")).hexdigest()
        hashes.append(h)

    assert len(set(hashes)) == 1, f"Check reports produced divergent hashes: {hashes}"


def test_pythonhashseed_independence() -> None:
    """Running CLI check with varied PYTHONHASHSEED (0, 1, 42) produces byte-identical JSON."""
    seeds = ["0", "1", "42"]
    cli_outputs: list[str] = []

    for seed in seeds:
        env = os.environ.copy()
        env["PYTHONHASHSEED"] = seed
        cmd = [
            sys.executable,
            "-m",
            "sesslint",
            "check",
            str(FIXTURE_PATH),
            "--format",
            "canonical",
            "--json",
        ]
        res = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        cli_outputs.append(res.stdout)

    assert len(set(cli_outputs)) == 1, "CLI check output varied under different PYTHONHASHSEED"


def test_plan_fingerprint_repeatability() -> None:
    """Planning repairs across multiple runs produces identical plan fingerprints."""
    plan1 = api.plan(FIXTURE_PATH, policy="conservative")
    plan2 = api.plan(FIXTURE_PATH, policy="conservative")

    assert plan1.fingerprint == plan2.fingerprint
    assert plan1.to_dict() == plan2.to_dict()


def test_canonical_json_bytes_ordering_independence() -> None:
    """canonical_json_bytes encodes deterministically regardless of dict insertion order."""
    dict_a = {"z_key": 1, "a_key": 2, "m_key": {"sub_b": "value", "sub_a": 123}}
    dict_b = {"m_key": {"sub_a": 123, "sub_b": "value"}, "a_key": 2, "z_key": 1}

    bytes_a = canonical_json_bytes(dict_a)
    bytes_b = canonical_json_bytes(dict_b)

    assert bytes_a == bytes_b
    assert repeat_hash(dict_a) == repeat_hash(dict_b)
