"""Schema conformance, fixture validation, and CLI tests for sesslint.session/v1."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from sesslint.canonical import (
    KNOWN_EVENT_FIELDS,
    KNOWN_HEADER_FIELDS,
    REQUIRED_EVENT_FIELDS,
    REQUIRED_HEADER_FIELDS,
    VALID_ACTORS,
    VALID_EXECUTION_STATES,
    VALID_KINDS,
    dump_session,
    load_session_file,
    parse_session_event,
)
from sesslint.cli import main
from sesslint.errors import UnknownFieldError, VersionError

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "schemas" / "sesslint.session.v1.json"
FIXTURES_DIR = REPO_ROOT / "fixtures" / "sessions"


def test_schema_file_exists_and_parses() -> None:
    """Verify that schemas/sesslint.session.v1.json exists and is valid JSON."""
    assert SCHEMA_PATH.is_file(), f"Schema file not found at {SCHEMA_PATH}"
    schema_text = SCHEMA_PATH.read_text(encoding="utf-8")
    data = json.loads(schema_text)
    assert data.get("$id") == "https://sesslint.dev/schemas/sesslint.session/v1"
    assert data.get("$schema") == "https://json-schema.org/draft/2020-12/schema"


def test_schema_and_parser_required_keys_match() -> None:
    """Verify JSON schema and canonical parser key sets and enums are equal (anti-drift)."""
    schema_text = SCHEMA_PATH.read_text(encoding="utf-8")
    schema = json.loads(schema_text)

    # 1. Required fields anti-drift
    header_required_schema = set(schema["$defs"]["header"]["required"])
    event_required_schema = set(schema["$defs"]["event"]["required"])
    assert header_required_schema == REQUIRED_HEADER_FIELDS, (
        f"Drift in header required fields: {header_required_schema} != {REQUIRED_HEADER_FIELDS}"
    )
    assert event_required_schema == REQUIRED_EVENT_FIELDS, (
        f"Drift in event required fields: {event_required_schema} != {REQUIRED_EVENT_FIELDS}"
    )

    # 2. Known properties anti-drift
    header_known_schema = set(schema["$defs"]["header"]["properties"].keys())
    event_known_schema = set(schema["$defs"]["event"]["properties"].keys())
    assert header_known_schema == KNOWN_HEADER_FIELDS, (
        f"Drift in header known properties: {header_known_schema} != {KNOWN_HEADER_FIELDS}"
    )
    assert event_known_schema == KNOWN_EVENT_FIELDS, (
        f"Drift in event known properties: {event_known_schema} != {KNOWN_EVENT_FIELDS}"
    )

    # 3. Closed enum vocabulary anti-drift
    actor_enum_schema = set(schema["$defs"]["event"]["properties"]["actor"]["enum"])
    assert actor_enum_schema == VALID_ACTORS, (
        f"Drift in actor vocabulary: {actor_enum_schema} != {VALID_ACTORS}"
    )

    kind_enum_schema = set(schema["$defs"]["event"]["properties"]["kind"]["enum"])
    assert kind_enum_schema == VALID_KINDS, (
        f"Drift in kind vocabulary: {kind_enum_schema} != {VALID_KINDS}"
    )

    exec_states_schema = {
        x
        for x in schema["$defs"]["event"]["properties"]["execution_state"]["enum"]
        if x is not None
    }
    assert exec_states_schema == VALID_EXECUTION_STATES, (
        f"Drift in execution_state vocabulary: {exec_states_schema} != {VALID_EXECUTION_STATES}"
    )

    # 4. Top-level flat and framed session schema consistency
    flat_schema = schema["oneOf"][0]
    assert set(flat_schema["required"]) == (REQUIRED_HEADER_FIELDS | {"events"})
    assert set(flat_schema["properties"].keys()) == (KNOWN_HEADER_FIELDS | {"events"})

    framed_schema = schema["oneOf"][1]
    assert set(framed_schema["required"]) == {"header", "events"}
    assert set(framed_schema["properties"].keys()) == {"header", "events"}


def test_vendor_neutrality_in_canonical_and_schema() -> None:
    """Verify no vendor-specific strings leak into canonical.py or session schema."""
    vendor_pattern = re.compile(
        r"\b(?:anthropic|openai|claude|gpt|tool_use|function_call)\b",
        re.IGNORECASE,
    )

    canonical_path = REPO_ROOT / "src" / "sesslint" / "canonical.py"
    canonical_content = canonical_path.read_text(encoding="utf-8")
    match_canonical = vendor_pattern.search(canonical_content)
    assert match_canonical is None, (
        f"Vendor-specific string '{match_canonical.group(0)}' found in {canonical_path}"
    )

    schema_content = SCHEMA_PATH.read_text(encoding="utf-8")
    match_schema = vendor_pattern.search(schema_content)
    assert match_schema is None, (
        f"Vendor-specific string '{match_schema.group(0)}' found in {SCHEMA_PATH}"
    )


def test_minimal_valid_fixture() -> None:
    """Verify fixtures/sessions/minimal-valid.jsonl loads and round-trips byte-identically."""
    fixture_path = FIXTURES_DIR / "minimal-valid.jsonl"
    assert fixture_path.is_file(), f"Fixture not found: {fixture_path}"

    session = load_session_file(fixture_path)
    assert session.header.session_id == "sess_min_001"
    assert session.header.schema_version == "sesslint.session/v1"
    assert len(session.events) == 3

    # Check chained lineage
    assert session.events[0].parent_id is None
    assert session.events[1].parent_id == session.events[0].id
    assert session.events[2].parent_id == session.events[1].id

    # Re-dump and verify byte-identical match
    dumped = dump_session(session)
    original_lines = [
        line.strip()
        for line in fixture_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    original_normalized = "\n".join(original_lines) + "\n"
    assert dumped == original_normalized


def test_wrong_version_fixture() -> None:
    """Verify wrong-version fixture raises VersionError mentioning VERSION and SL301."""
    fixture_path = FIXTURES_DIR / "wrong-version.jsonl"
    assert fixture_path.is_file(), f"Fixture not found: {fixture_path}"

    with pytest.raises(VersionError) as exc_info:
        load_session_file(fixture_path)

    err = exc_info.value
    assert err.code == "VERSION"
    assert err.reason_code == "SL301"
    assert "VERSION" in str(err)
    assert "SL301" in str(err)


def test_unknown_top_level_field_fixture() -> None:
    """Verify unknown-top-level-field fixture raises UnknownFieldError mentioning SL302."""
    fixture_path = FIXTURES_DIR / "unknown-top-level-field.jsonl"
    assert fixture_path.is_file(), f"Fixture not found: {fixture_path}"

    with pytest.raises(UnknownFieldError) as exc_info:
        load_session_file(fixture_path)

    err = exc_info.value
    assert err.code == "UNKNOWN_FIELD"
    assert err.reason_code == "SL302"
    assert "UNKNOWN_FIELD" in str(err)
    assert "SL302" in str(err)


def test_unknown_nested_payload_keys_permitted() -> None:
    """Verify unknown nested keys inside payload are permitted while unknown top-level keys fail."""
    valid_event_with_nested_unknown = {
        "id": "e_payload_test",
        "parent_id": None,
        "seq": 0,
        "ts": "2026-09-05T12:00:00Z",
        "actor": "user",
        "kind": "message",
        "payload": {
            "arbitrary_user_key": 42,
            "nested_dict": {"foo": "bar", "deep_setting": [1, 2, 3]},
        },
    }
    event = parse_session_event(valid_event_with_nested_unknown)
    assert event.payload["arbitrary_user_key"] == 42
    assert event.payload["nested_dict"]["foo"] == "bar"


def test_cli_validate_session_subcommand(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify CLI validate-session exit codes and outputs for valid and invalid fixtures."""
    min_valid = str(FIXTURES_DIR / "minimal-valid.jsonl")
    wrong_ver = str(FIXTURES_DIR / "wrong-version.jsonl")
    unk_field = str(FIXTURES_DIR / "unknown-top-level-field.jsonl")

    # Positive test
    exit_code = main(["validate-session", min_valid])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Valid session: sess_min_001" in captured.out

    # Wrong version negative test
    exit_code = main(["validate-session", wrong_ver])
    assert exit_code != 0
    captured = capsys.readouterr()
    assert "VERSION" in captured.err
    assert "SL301" in captured.err

    # Unknown field negative test
    exit_code = main(["validate-session", unk_field])
    assert exit_code != 0
    captured = capsys.readouterr()
    assert "UNKNOWN_FIELD" in captured.err
    assert "SL302" in captured.err


def test_cli_subprocess_validate_session() -> None:
    """Verify python -m sesslint validate-session via subprocess across all fixtures."""
    min_valid = str(FIXTURES_DIR / "minimal-valid.jsonl")
    wrong_ver = str(FIXTURES_DIR / "wrong-version.jsonl")

    res_valid = subprocess.run(
        [sys.executable, "-m", "sesslint", "validate-session", min_valid],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_valid.returncode == 0
    assert "sess_min_001" in res_valid.stdout

    res_wrong = subprocess.run(
        [sys.executable, "-m", "sesslint", "validate-session", wrong_ver],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_wrong.returncode != 0
    assert "SL301" in res_wrong.stderr or "VERSION" in res_wrong.stderr


def test_cli_validate_session_missing_file(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify CLI returns exit code 2 on missing file."""
    exit_code = main(["validate-session", "non_existent_file.jsonl"])
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "Error:" in captured.err


def test_cli_validate_session_unexpected_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify CLI handles unexpected exceptions gracefully and returns exit code 2."""

    def _mock_raise(_path: Path) -> None:
        raise RuntimeError("Unexpected boom")

    monkeypatch.setattr("sesslint.cli.load_session_file", _mock_raise)
    exit_code = main(["validate-session", "some_file.jsonl"])
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "Unexpected error: Unexpected boom" in captured.err


def test_jsonl_header_and_event_lines_satisfy_schema() -> None:
    """Verify JSONL stream Line 1 header and Lines 2+ events satisfy session schema (RVW-001)."""
    schema_text = SCHEMA_PATH.read_text(encoding="utf-8")
    schema = json.loads(schema_text)

    # Validate oneOf contains header and event references
    one_of_refs = [branch.get("$ref") for branch in schema["oneOf"]]
    assert "#/$defs/header" in one_of_refs
    assert "#/$defs/event" in one_of_refs

    min_valid = FIXTURES_DIR / "minimal-valid.jsonl"
    lines = [
        line.strip() for line in min_valid.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    assert len(lines) >= 2

    # Line 1: Header
    hdr = json.loads(lines[0])
    hdr_required = set(schema["$defs"]["header"]["required"])
    hdr_known = set(schema["$defs"]["header"]["properties"].keys())
    assert hdr_required.issubset(set(hdr.keys()))
    assert set(hdr.keys()).issubset(hdr_known)

    # Lines 2+: Events
    ev_required = set(schema["$defs"]["event"]["required"])
    ev_known = set(schema["$defs"]["event"]["properties"].keys())
    for ev_line in lines[1:]:
        ev = json.loads(ev_line)
        assert ev_required.issubset(set(ev.keys()))
        assert set(ev.keys()).issubset(ev_known)


def test_minimal_canonical_fixture_satisfies_flat_schema() -> None:
    """Verify fixtures/canonical/minimal.json satisfies the published flat schema (RVW-001)."""
    minimal_path = REPO_ROOT / "fixtures" / "canonical" / "minimal.json"
    doc = json.loads(minimal_path.read_text(encoding="utf-8"))

    schema_text = SCHEMA_PATH.read_text(encoding="utf-8")
    schema = json.loads(schema_text)
    flat_required = set(schema["oneOf"][0]["required"])
    flat_known = set(schema["oneOf"][0]["properties"].keys())

    missing_keys = flat_required - set(doc.keys())
    assert flat_required.issubset(set(doc.keys())), f"Missing keys: {missing_keys}"
    assert set(doc.keys()).issubset(flat_known), f"Unknown keys: {set(doc.keys()) - flat_known}"

    # Also verify parse_session parses it without error
    from sesslint.canonical import parse_session

    session = parse_session(doc)
    assert session.header.session_id == "canonical-session"
    assert len(session.events) == 2
