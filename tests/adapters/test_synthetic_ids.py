"""Comprehensive tests for collision-proof synthetic event IDs (DEV-007 / FR-083).

Validates:
- Reserved namespace format `sesslint:synthetic:<adapter>:<ordinal>:<8-hex-hash>`
- SHA-256 hash determinism and sensitivity to all coordinate components
- SyntheticIdCollisionGuard fail-closed collision prevention
- Zero false SL003 findings on the namespace squatting regression fixture
- Hostile real-vs-synthetic collision rejection in Claude Code and OpenAI Agents adapters
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from sesslint.adapters.claude_code import load_claude_code
from sesslint.adapters.openai_agents import load_openai_agents
from sesslint.adapters.synthetic import (
    SYNTHETIC_ID_PREFIX,
    SyntheticIdCollisionGuard,
    is_synthetic_id,
    synthetic_event_id,
)
from sesslint.canonical import SessionEvent, compute_content_hash
from sesslint.checks.identity import check_identities
from sesslint.errors import AdapterError


def test_synthetic_event_id_format() -> None:
    """Verify generated synthetic ID matches the reserved schema format."""
    synth_id = synthetic_event_id("claude_code", 42, source_hint="session.jsonl", payload_len=128)

    pattern = r"^sesslint:synthetic:claude_code:42:[0-9a-f]{8}$"
    assert re.match(pattern, synth_id) is not None, f"Malformed synthetic ID: {synth_id}"
    assert is_synthetic_id(synth_id) is True


def test_synthetic_event_id_hash_exact() -> None:
    """Verify hash component matches truncated SHA-256 over input coordinates."""
    adapter = "openai_agents"
    ordinal = 7
    source_hint = "test_source.json"
    payload_len = 256

    expected_hash = hashlib.sha256(f"{source_hint}:{ordinal}:{payload_len}".encode()).hexdigest()[
        :8
    ]

    result = synthetic_event_id(adapter, ordinal, source_hint=source_hint, payload_len=payload_len)
    expected_id = f"sesslint:synthetic:{adapter}:{ordinal}:{expected_hash}"
    assert result == expected_id


def test_synthetic_event_id_determinism_and_differentiation() -> None:
    """Verify helper is strictly deterministic and distinguishes variations."""
    base = synthetic_event_id("adapter_a", 0, source_hint="file.jsonl", payload_len=100)
    repeat = synthetic_event_id("adapter_a", 0, source_hint="file.jsonl", payload_len=100)
    assert base == repeat

    # Different adapter
    diff_adapter = synthetic_event_id("adapter_b", 0, source_hint="file.jsonl", payload_len=100)
    assert base != diff_adapter

    # Different ordinal
    diff_ordinal = synthetic_event_id("adapter_a", 1, source_hint="file.jsonl", payload_len=100)
    assert base != diff_ordinal

    # Different source hint
    diff_hint = synthetic_event_id("adapter_a", 0, source_hint="other.jsonl", payload_len=100)
    assert base != diff_hint

    # Different payload length
    diff_len = synthetic_event_id("adapter_a", 0, source_hint="file.jsonl", payload_len=101)
    assert base != diff_len


def test_synthetic_event_id_edge_cases() -> None:
    """Verify helper handles boundary values and non-ASCII characters gracefully."""
    # Ordinal 0, empty hint, 0 payload length
    id_zero = synthetic_event_id("test", 0, source_hint="", payload_len=0)
    assert id_zero.startswith("sesslint:synthetic:test:0:")
    assert len(id_zero.split(":")[-1]) == 8

    # Unicode source hint
    id_unicode = synthetic_event_id(
        "test", 10, source_hint="/путь/к/файлу/日本語/session.jsonl", payload_len=1024
    )
    assert id_unicode.startswith("sesslint:synthetic:test:10:")
    assert len(id_unicode.split(":")[-1]) == 8

    # Large ordinal and length
    id_large = synthetic_event_id("test", 10_000_000, source_hint="stream", payload_len=50_000_000)
    assert id_large.startswith("sesslint:synthetic:test:10000000:")
    assert len(id_large.split(":")[-1]) == 8


def test_is_synthetic_id() -> None:
    """Verify is_synthetic_id prefix recognition."""
    assert is_synthetic_id(SYNTHETIC_ID_PREFIX + "any:1:abc") is True
    assert is_synthetic_id("rec_0") is False
    assert is_synthetic_id("uuid-1234") is False
    assert is_synthetic_id("") is False


def test_collision_guard_clean_operation() -> None:
    """Verify guard tracks disjoint real and synthetic ID sets without error."""
    guard = SyntheticIdCollisionGuard()

    guard.register_real("real_1")
    guard.register_real("real_2")
    guard.register_synthetic("sesslint:synthetic:adapter:0:12345678")
    guard.register_synthetic("sesslint:synthetic:adapter:1:87654321")

    assert guard.seen_real_ids == frozenset({"real_1", "real_2"})
    assert guard.seen_synthetic_ids == frozenset(
        {"sesslint:synthetic:adapter:0:12345678", "sesslint:synthetic:adapter:1:87654321"}
    )

    # Idempotent re-registration of same real or synthetic ID
    guard.register_real("real_1")
    guard.register_synthetic("sesslint:synthetic:adapter:0:12345678")

    # Assert no collision succeeds
    guard.assert_no_collision()


def test_collision_guard_fires_on_synthetic_colliding_with_prior_real() -> None:
    """Verify guard raises AdapterError when a synthetic ID collides with prior real ID."""
    guard = SyntheticIdCollisionGuard()
    target_id = "sesslint:synthetic:claude_code:0:deadbeef"

    guard.register_real(target_id)
    with pytest.raises(AdapterError, match="Synthetic ID collision: synthetic ID"):
        guard.register_synthetic(target_id)


def test_collision_guard_fires_on_real_colliding_with_prior_synthetic() -> None:
    """Verify guard raises AdapterError when a real ID collides with prior synthetic ID."""
    guard = SyntheticIdCollisionGuard()
    target_id = "sesslint:synthetic:openai_agents:1:cafebabe"

    guard.register_synthetic(target_id)
    with pytest.raises(AdapterError, match="Synthetic ID collision: real ID"):
        guard.register_real(target_id)


def test_collision_guard_check_event() -> None:
    """Verify check_event registers events using original_id inference."""
    guard = SyntheticIdCollisionGuard()

    real_event = SessionEvent(
        id="real_event_1",
        parent_id=None,
        seq=0,
        ts="2026-01-01T00:00:00Z",
        actor="user",
        kind="message",
        payload={"role": "user", "content": "hi"},
        content_hash=compute_content_hash({"role": "user", "content": "hi"}),
        correlation_id=None,
        source_line=1,
        source_record_hash="sha256:abc",
        original_id="real_event_1",
        source_adapter="claude-code-jsonl",
    )
    guard.check_event(real_event)
    assert "real_event_1" in guard.seen_real_ids

    synth_event = SessionEvent(
        id="sesslint:synthetic:claude_code:1:11223344",
        parent_id=None,
        seq=1,
        ts="2026-01-01T00:00:01Z",
        actor="assistant",
        kind="message",
        payload={"role": "assistant", "content": "hello"},
        content_hash=compute_content_hash({"role": "assistant", "content": "hello"}),
        correlation_id=None,
        source_line=2,
        source_record_hash="sha256:def",
        original_id=None,
        source_adapter="claude-code-jsonl",
    )
    guard.check_event(synth_event)
    assert "sesslint:synthetic:claude_code:1:11223344" in guard.seen_synthetic_ids

    # Conflicting real event matching the synthetic event ID
    colliding_event = SessionEvent(
        id="sesslint:synthetic:claude_code:1:11223344",
        parent_id=None,
        seq=2,
        ts="2026-01-01T00:00:02Z",
        actor="user",
        kind="message",
        payload={"role": "user", "content": "malicious collision"},
        content_hash=compute_content_hash({"role": "user", "content": "malicious collision"}),
        correlation_id=None,
        source_line=3,
        source_record_hash="sha256:ghi",
        original_id="sesslint:synthetic:claude_code:1:11223344",
        source_adapter="claude-code-jsonl",
    )
    with pytest.raises(AdapterError, match="Synthetic ID collision: real ID"):
        guard.check_event(colliding_event)


def test_namespace_squat_fixture_claude_code() -> None:
    """Verify namespace_squat.jsonl yields zero false SL003 findings on Claude Code adapter."""
    fixture_path = Path("fixtures/adapters/namespace_squat.jsonl")
    assert fixture_path.is_file(), f"Fixture missing: {fixture_path}"

    events, findings = load_claude_code(fixture_path)
    assert len(findings) == 0, f"Unexpected adapter findings: {findings}"
    assert len(events) == 4

    # Record 0: real 'rec_0'
    assert events[0].id == "rec_0"
    assert events[0].original_id == "rec_0"

    # Record 1: id-less synthetic
    assert events[1].id.startswith("sesslint:synthetic:claude_code:1:")
    assert events[1].original_id is None

    # Record 2: real 'rec_1' (squats on old rec_ namespace)
    assert events[2].id == "rec_1"
    assert events[2].original_id == "rec_1"

    # Record 3: id-less synthetic
    assert events[3].id.startswith("sesslint:synthetic:claude_code:3:")
    assert events[3].original_id is None

    # Check for duplicate identity findings (SL003)
    identity_findings = check_identities(events)
    assert len(identity_findings) == 0, f"False SL003 duplicate findings: {identity_findings}"


def test_namespace_squat_fixture_openai_agents() -> None:
    """Verify namespace_squat.jsonl yields zero false SL003 findings on OpenAI Agents adapter."""
    fixture_path = Path("fixtures/adapters/namespace_squat.jsonl")
    assert fixture_path.is_file(), f"Fixture missing: {fixture_path}"

    events, findings = load_openai_agents(fixture_path)
    assert len(findings) == 0, f"Unexpected adapter findings: {findings}"
    assert len(events) == 4

    # Record 0: real 'rec_0'
    assert events[0].id == "rec_0"
    assert events[0].original_id == "rec_0"

    # Record 1: id-less synthetic
    assert events[1].id.startswith("sesslint:synthetic:openai_agents:1:")
    assert events[1].original_id is None

    # Record 2: real 'rec_1'
    assert events[2].id == "rec_1"
    assert events[2].original_id == "rec_1"

    # Record 3: id-less synthetic
    assert events[3].id.startswith("sesslint:synthetic:openai_agents:3:")
    assert events[3].original_id is None

    # Check for duplicate identity findings (SL003)
    identity_findings = check_identities(events)
    assert len(identity_findings) == 0, f"False SL003 duplicate findings: {identity_findings}"


def test_hostile_collision_claude_code_fails_closed(tmp_path: Path) -> None:
    """Verify load_claude_code fails closed when a real ID squats on an active synthetic ID."""
    hostile_file = tmp_path / "hostile_claude.jsonl"
    path_str = str(hostile_file).replace("\\", "/")

    # Determine what synthetic ID line 1 (id-less) will produce
    line1_dict = {
        "type": "message",
        "role": "user",
        "message": "hello",
        "timestamp": "2026-01-01T00:00:00Z",
    }
    line1_bytes = json.dumps(line1_dict).encode("utf-8") + b"\n"
    predicted_synth_id = synthetic_event_id(
        "claude_code",
        0,
        source_hint=path_str,
        payload_len=len(line1_bytes),
    )

    # Line 2 intentionally squats on that exact synthetic ID
    line2_dict = {
        "id": predicted_synth_id,
        "type": "message",
        "role": "assistant",
        "message": "hostile squat",
        "timestamp": "2026-01-01T00:00:01Z",
    }
    line2_bytes = json.dumps(line2_dict).encode("utf-8") + b"\n"

    hostile_file.write_bytes(line1_bytes + line2_bytes)

    with pytest.raises(AdapterError, match="Synthetic ID collision"):
        load_claude_code(hostile_file)


def test_hostile_collision_openai_agents_jsonl_fails_closed(tmp_path: Path) -> None:
    """Verify load_openai_agents JSONL fails closed when a real ID collides with synthetic ID."""
    hostile_file = tmp_path / "hostile_openai.jsonl"
    path_str = str(hostile_file).replace("\\", "/")

    line1_dict = {
        "type": "message",
        "role": "user",
        "content": "hello",
        "timestamp": "2026-01-01T00:00:00Z",
    }
    line1_bytes = json.dumps(line1_dict).encode("utf-8") + b"\n"
    predicted_synth_id = synthetic_event_id(
        "openai_agents",
        0,
        source_hint=path_str,
        payload_len=len(line1_bytes),
    )

    line2_dict = {
        "id": predicted_synth_id,
        "type": "message",
        "role": "assistant",
        "content": "hostile squat",
        "timestamp": "2026-01-01T00:00:01Z",
    }
    line2_bytes = json.dumps(line2_dict).encode("utf-8") + b"\n"

    hostile_file.write_bytes(line1_bytes + line2_bytes)

    with pytest.raises(AdapterError, match="Synthetic ID collision"):
        load_openai_agents(hostile_file)


def test_hostile_collision_openai_agents_json_fails_closed(tmp_path: Path) -> None:
    """Verify load_openai_agents JSON export fails closed with AdapterError on collision."""
    hostile_file = tmp_path / "hostile_openai.json"
    path_str = str(hostile_file).replace("\\", "/")

    from sesslint.canonical import canonical_bytes

    item0 = {
        "type": "message",
        "role": "user",
        "content": "hello",
        "timestamp": "2026-01-01T00:00:00Z",
    }
    payload_len = len(canonical_bytes(item0))
    predicted_synth_id = synthetic_event_id(
        "openai_agents",
        0,
        source_hint=path_str,
        payload_len=payload_len,
    )

    doc = {
        "items": [
            item0,
            {
                "id": predicted_synth_id,
                "type": "message",
                "role": "assistant",
                "content": "hostile squat",
                "timestamp": "2026-01-01T00:00:01Z",
            },
        ]
    }
    hostile_file.write_text(json.dumps(doc), encoding="utf-8")

    with pytest.raises(AdapterError, match="Synthetic ID collision"):
        load_openai_agents(hostile_file)
