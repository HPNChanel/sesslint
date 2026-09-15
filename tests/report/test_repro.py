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
    assert d["adapter"] == {"name": "claude-code-jsonl", "version": "unknown"}
    assert d["profile"] == {"name": "claude-strict", "version": "unknown"}
    assert "detection" in d
    assert set(d["platform"].keys()) == {"architecture", "os", "python"}


def test_repro_metadata_defaults_are_honest_sentinels() -> None:
    """Omitted helper arguments produce unknown/null sentinels, never fabrications."""
    repro = build_repro_metadata()
    d = repro.to_dict()

    assert d["adapter"] == {"name": "unknown", "version": "unknown"}
    assert d["profile"] == {"name": "unknown", "version": "unknown"}
    assert d["detection"] == {"confidence": None, "method": "unknown"}


def test_repro_metadata_explicit_bound_values() -> None:
    """Explicitly bound adapter/profile versions and a legitimately bound score
    pass through verbatim."""
    repro = build_repro_metadata(
        adapter_name="canonical",
        adapter_version="1.0.0",
        profile_name="openai-strict",
        profile_version="1.0.0",
        detection_method="auto",
        detection_confidence=0.87,
    )
    d = repro.to_dict()

    assert d["adapter"] == {"name": "canonical", "version": "1.0.0"}
    assert d["profile"] == {"name": "openai-strict", "version": "1.0.0"}
    assert d["detection"] == {"confidence": 0.87, "method": "auto"}


def test_repro_metadata_architecture_field() -> None:
    """platform.architecture is always present and non-identifying."""
    import platform as _platform

    d = build_repro_metadata().to_dict()
    arch = d["platform"]["architecture"]
    expected = _platform.machine().strip() or "unknown"
    assert arch == expected
    assert isinstance(arch, str) and arch


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
