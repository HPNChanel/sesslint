"""Unit and integration tests for replay profiles framework (TASK-016).

Covers:
- Profile registry listing and exact lookup
- Three data-only profiles (neutral, claude-strict, openai-strict)
- Snapshot matching against fixtures/profiles/*.json
- CLI override precedence and out-of-range validation
- Static adapter-rule separation (zero adapter imports in checks/profiles)
- Runtime require_canonical guard
- CLI exit-2 paths on invalid profile/thresholds
- Determinism and immutability
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from sesslint.canonical import SessionEvent
from sesslint.cli import main
from sesslint.profiles import (
    ALL_RULES,
    CLAUDE_STRICT_PROFILE,
    NEUTRAL_PROFILE,
    OPENAI_STRICT_PROFILE,
    get_profile,
    list_profiles,
    require_canonical,
    resolve_effective_config,
    stamp_source_profile,
)

FIXTURES_PROFILES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "profiles"
SRC_DIR = Path(__file__).resolve().parent.parent / "src" / "sesslint"


def test_registry_lists_three() -> None:
    """Registry lists exactly the three standard profiles and suggests alternatives on typo."""
    names = list_profiles()
    assert names == ["claude-strict", "neutral", "openai-strict"]

    # Exact match retrieval
    assert get_profile("neutral") == NEUTRAL_PROFILE
    assert get_profile("claude-strict") == CLAUDE_STRICT_PROFILE
    assert get_profile("openai-strict") == OPENAI_STRICT_PROFILE

    # Unknown profile raises KeyError with suggestion
    with pytest.raises(KeyError) as exc_info:
        get_profile("Neutral")  # Case variant
    assert "Unknown profile 'Neutral'" in str(exc_info.value)
    assert "Did you mean 'neutral'?" in str(exc_info.value)

    with pytest.raises(KeyError) as exc_info_bogus:
        get_profile("bogus")
    assert "Unknown profile 'bogus'" in str(exc_info_bogus.value)


def test_snapshots() -> None:
    """Resolved default config for each profile equals its snapshot fixture JSON."""
    profiles_to_test = [
        ("neutral", FIXTURES_PROFILES_DIR / "neutral.json"),
        ("claude-strict", FIXTURES_PROFILES_DIR / "claude_strict.json"),
        ("openai-strict", FIXTURES_PROFILES_DIR / "openai_strict.json"),
    ]

    for prof_name, fixture_path in profiles_to_test:
        assert fixture_path.is_file(), f"Missing fixture file: {fixture_path}"
        expected_dict = json.loads(fixture_path.read_text(encoding="utf-8"))

        resolved = resolve_effective_config(prof_name)
        actual_dict = resolved.to_dict()

        assert actual_dict == expected_dict, (
            f"Snapshot mismatch for profile {prof_name} against {fixture_path}"
        )


def test_override_precedence() -> None:
    """Explicit CLI args beat profile defaults and match override.json snapshot."""
    override_fixture = FIXTURES_PROFILES_DIR / "override.json"
    assert override_fixture.is_file(), f"Missing fixture file: {override_fixture}"
    fixture_data = json.loads(override_fixture.read_text(encoding="utf-8"))

    inputs = fixture_data["input"]
    expected = fixture_data["expected"]

    resolved = resolve_effective_config(
        inputs["profile"],
        format=inputs["format"],
        confidence_min=inputs["confidence_min"],
        margin_min=inputs["margin_min"],
    )
    assert resolved.to_dict() == expected


def test_override_validation_errors() -> None:
    """Out-of-range thresholds or margin > confidence raise ValueError."""
    # confidence_min out of range
    with pytest.raises(ValueError, match="confidence_min must be strictly between"):
        resolve_effective_config("neutral", confidence_min=0.0)

    with pytest.raises(ValueError, match="confidence_min must be strictly between"):
        resolve_effective_config("neutral", confidence_min=1.0)

    with pytest.raises(ValueError, match="confidence_min must be a finite float"):
        resolve_effective_config("neutral", confidence_min=float("nan"))

    # margin_min out of range
    with pytest.raises(ValueError, match="margin_min must be strictly between"):
        resolve_effective_config("neutral", margin_min=0.0)

    with pytest.raises(ValueError, match="margin_min must be strictly between"):
        resolve_effective_config("neutral", margin_min=1.0)

    with pytest.raises(ValueError, match="margin_min must be a finite float"):
        resolve_effective_config("neutral", margin_min=float("inf"))

    # margin_min > confidence_min
    with pytest.raises(ValueError, match="cannot exceed confidence_min"):
        resolve_effective_config("neutral", confidence_min=0.5, margin_min=0.6)

    # Invalid format override
    with pytest.raises(ValueError, match="Invalid format override 'unsupported'"):
        resolve_effective_config("neutral", format="unsupported")


def test_enabled_rules_pinned() -> None:
    """Each profile's rule list contains all 20 SL codes; flags reflect specialization."""
    assert len(ALL_RULES) == 20
    assert ALL_RULES == tuple(sorted(ALL_RULES))

    for p in (NEUTRAL_PROFILE, CLAUDE_STRICT_PROFILE, OPENAI_STRICT_PROFILE):
        assert p.enabled_rules == ALL_RULES

    # Differences in flags
    assert NEUTRAL_PROFILE.strict_unknown_critical is False
    assert NEUTRAL_PROFILE.checkpoint_sensitivity == "default"
    assert NEUTRAL_PROFILE.thresholds["margin_min"] == 0.15

    assert CLAUDE_STRICT_PROFILE.strict_unknown_critical is True
    assert CLAUDE_STRICT_PROFILE.checkpoint_sensitivity == "default"
    assert CLAUDE_STRICT_PROFILE.thresholds["margin_min"] == 0.20

    assert OPENAI_STRICT_PROFILE.strict_unknown_critical is True
    assert OPENAI_STRICT_PROFILE.checkpoint_sensitivity == "high"
    assert OPENAI_STRICT_PROFILE.thresholds["margin_min"] == 0.15


def test_separation_static() -> None:
    """Checks and profiles packages must NEVER import from sesslint.adapters."""
    dirs_to_check = [
        SRC_DIR / "checks",
        SRC_DIR / "profiles",
    ]

    import_pattern = re.compile(
        r"^\s*(?:from\s+sesslint\.adapters|import\s+sesslint\.adapters)",
        re.MULTILINE,
    )

    for check_dir in dirs_to_check:
        for py_file in check_dir.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            match = import_pattern.search(content)
            assert match is None, f"Forbidden adapter import in {py_file}: '{match.group(0)}'"


def test_require_canonical() -> None:
    """require_canonical accepts valid canonical structures and rejects non-canonical data."""
    # Valid canonical dict session
    canonical_dict: dict[str, Any] = {
        "schema": "sesslint.session/v1",
        "events": [],
    }
    require_canonical(canonical_dict)

    # Valid SessionEvent sequence
    event = SessionEvent(
        id="e1",
        parent_id=None,
        seq=0,
        ts="2026-09-05T12:00:00Z",
        actor="user",
        kind="message",
    )
    require_canonical([event])

    # Rejection: None
    with pytest.raises(TypeError, match="Input cannot be None"):
        require_canonical(None)

    # Rejection: Wrong schema
    with pytest.raises(TypeError, match="Expected canonical session schema"):
        require_canonical({"schema": "wrong.schema/v1", "events": []})

    # Rejection: Missing events
    with pytest.raises(TypeError, match="must contain 'events' array"):
        require_canonical({"schema": "sesslint.session/v1"})

    # Rejection: Non-canonical event mapping missing 'kind'
    with pytest.raises(TypeError, match="missing required 'kind' field"):
        require_canonical([{"id": "e1"}])


def test_stamp_source_profile() -> None:
    """stamp_source_profile injects profile name and resolution block into source dict."""
    config = resolve_effective_config("neutral", format="canonical")
    source = stamp_source_profile({"format": "canonical"}, config)

    assert source["profile"] == "neutral"
    assert source["resolution"]["profile"] == "neutral"
    assert source["resolution"]["format_override"] == "canonical"
    assert source["resolution"]["thresholds_source"] == "profile"
    assert source["resolution"]["confidence_min"] == 0.55
    assert source["resolution"]["margin_min"] == 0.15


def test_cli_profile_exit_codes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """CLI exits with code 2 on invalid profile or invalid threshold parameters."""
    dummy_file = tmp_path / "session.json"
    dummy_file.write_text('{"schema": "sesslint.session/v1", "events": []}', encoding="utf-8")

    # Unknown profile name -> exit 2
    with pytest.raises(SystemExit) as exc_info:
        main(["check", "--profile", "bogus", str(dummy_file)])
    assert exc_info.value.code == 2

    # Empty profile name -> exit 2
    with pytest.raises(SystemExit) as exc_info_empty:
        main(["check", "--profile", "", str(dummy_file)])
    assert exc_info_empty.value.code == 2

    # Case-variant profile name -> exit 2
    with pytest.raises(SystemExit) as exc_info_case:
        main(["check", "--profile", "Neutral", str(dummy_file)])
    assert exc_info_case.value.code == 2

    # Invalid confidence-min threshold -> exit 2
    with pytest.raises(SystemExit) as exc_info_conf:
        main(["check", "--confidence-min", "1.5", str(dummy_file)])
    assert exc_info_conf.value.code == 2

    # Valid default check run -> exit 0
    valid_fixture = (
        Path(__file__).resolve().parent.parent / "fixtures" / "checks" / "pairing_healthy.json"
    )
    exit_code = main(["check", str(valid_fixture)])
    assert exit_code == 0


def test_determinism_and_vendor_free() -> None:
    """Profiles are stable singletons and free of vendor payload keys."""
    # 10k rapid calls produce identical singleton instances
    first = get_profile("neutral")
    for _ in range(1000):
        assert get_profile("neutral") is first

    # Zero vendor payload keywords in profiles module
    profiles_dir = SRC_DIR / "profiles"
    forbidden_vendor_patterns = [
        re.compile(r"\btoolUse\b"),
        re.compile(r"\bcall_id\b"),
        re.compile(r"\banthropic\b", re.IGNORECASE),
        re.compile(r"\bchatgpt\b", re.IGNORECASE),
    ]

    for py_file in profiles_dir.rglob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        for pat in forbidden_vendor_patterns:
            match = pat.search(content)
            assert match is None, f"Forbidden vendor pattern in {py_file}: '{match.group(0)}'"
