"""Tests for reproduction metadata and zero machine/user identity leakage (TASK-025)."""

from __future__ import annotations

import json
import re

from sesslint.report import build_report, build_repro_metadata, render_json


def test_repro_metadata_structure() -> None:
    """Verify repro metadata contains exact required non-identifying fields."""
    repro = build_repro_metadata(
        adapter_name="claude-code-jsonl",
        profile_name="claude-strict",
    )
    d = repro.to_dict()

    assert "cli_version" in d
    assert "schema_versions" in d
    assert d["adapter"] == {"name": "claude-code-jsonl", "version": "1.0"}
    assert d["profile"] == {"name": "claude-strict", "version": "1.0"}
    assert "detection" in d
    assert set(d["platform"].keys()) == {"os", "python"}


def test_repro_metadata_contains_zero_machine_identity() -> None:
    """Verify serialized repro block contains no hostname, username, MAC address, or env vars."""
    rep = build_report(
        session_id="sess_repro",
        source_fingerprint="0" * 64,
        tool_version="0.1.0",
        findings=[],
        assurance="A2",
        limitation="Limitation",
    )

    repro = build_repro_metadata()
    rendered_json = render_json(rep, repro=repro)
    data = json.loads(rendered_json)
    assert "repro" in data
    repro_json = json.dumps(data["repro"])

    # Regex test for machine/user identity patterns
    forbidden_identity_patterns = [
        r"\bhostname\b",
        r"\bnode\b",
        r"\buser(name)?\b",
        r"\bgetpass\b",
        r"\bmac\b",
        r"\buuid\.getnode\b",
    ]

    for pat in forbidden_identity_patterns:
        match = re.search(pat, repro_json, re.IGNORECASE)
        msg = f"Forbidden identity pattern {pat!r} found in repro block: {repro_json}"
        assert match is None, msg
