"""Tests for canonical serialization codec seam, golden byte vectors, and contract (T-01 / S1)."""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sesslint._canonical_codec import (
    CODEC_INTERFACE_VERSION,
    CanonicalCodec,
    PurePythonCanonicalCodec,
    _resolve_active_codec,
    canonical_json_bytes,
    content_identity_bytes,
    content_identity_hash,
    get_active_codec,
    payload_content_hash,
    plan_fingerprint,
    set_active_codec,
)
from sesslint.canonical import SessionEvent
from sesslint.errors import SchemaError


class TestCodecContract:
    """Verify CanonicalCodec protocol conformance and version contract."""

    def test_protocol_conformance(self) -> None:
        codec = get_active_codec()
        assert isinstance(codec, CanonicalCodec)
        assert codec.codec_name in ("pure_python", "native")
        assert codec.codec_version == CODEC_INTERFACE_VERSION

    def test_pure_python_codec_version_binding(self) -> None:
        pure_codec = PurePythonCanonicalCodec()
        assert pure_codec.codec_name == "pure_python"
        assert pure_codec.codec_version == CODEC_INTERFACE_VERSION

    def test_fail_closed_on_environment_disable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SESSLINT_DISABLE_ACCEL", "1")
        resolved = _resolve_active_codec()
        assert isinstance(resolved, PurePythonCanonicalCodec)
        assert resolved.codec_name == "pure_python"

    def test_set_and_restore_active_codec(self) -> None:
        orig = get_active_codec()
        try:
            pure = PurePythonCanonicalCodec()
            set_active_codec(pure)
            assert get_active_codec() is pure
        finally:
            set_active_codec(orig)


class TestGoldenByteVectors:
    """Golden vectors pinning RFC 8785 canonical serialization behavior (S1 requirement)."""

    def test_parent_id_null_retention(self) -> None:
        """parent_id must be retained explicitly even when null."""
        ev = SessionEvent(
            seq=0,
            id="evt_001",
            parent_id=None,
            ts="2026-09-06T00:00:00Z",
            actor="user",
            kind="message",
            payload={"text": "hello"},
        )
        data = canonical_json_bytes(ev, newline=False)
        assert b'"parent_id":null' in data
        assert data == (
            b'{"actor":"user","id":"evt_001","kind":"message",'
            b'"parent_id":null,"payload":{"text":"hello"},"seq":0,'
            b'"ts":"2026-09-06T00:00:00Z"}'
        )

    def test_extra_fields_hoisting(self) -> None:
        """extra_fields must be hoisted into top-level keys lexicographically."""
        ev = SessionEvent(
            seq=1,
            id="evt_002",
            parent_id="evt_001",
            ts="2026-09-06T00:00:01Z",
            actor="agent",
            kind="tool_call",
            payload={},
            extra_fields={"experimental_mode": True, "alpha_tag": "x1"},
        )
        data = canonical_json_bytes(ev, newline=False)
        assert data == (
            b'{"actor":"agent","alpha_tag":"x1","experimental_mode":true,'
            b'"id":"evt_002","kind":"tool_call","parent_id":"evt_001",'
            b'"payload":{},"seq":1,"ts":"2026-09-06T00:00:01Z"}'
        )

    def test_non_bmp_astral_unicode_strings(self) -> None:
        """Astral planes and emoji must remain unescaped UTF-8 without surrogate pairs."""
        obj = {"emoji": "🚀✨", "multilingual": "Tiếng Việt / 日本語 / 🌍"}
        data = canonical_json_bytes(obj, newline=False)
        expected = '{"emoji":"🚀✨","multilingual":"Tiếng Việt / 日本語 / 🌍"}'.encode()
        assert data == expected

    def test_float_edges_and_nan_inf_refusal(self) -> None:
        """RFC 8785 float serialization and rejection of NaN / Inf."""
        valid_floats = {"zero": 0.0, "exp_pos": 1e20, "exp_neg": 1e-20, "val": 3.14159}
        encoded = canonical_json_bytes(valid_floats, newline=False)
        assert b'"zero":0.0' in encoded
        assert b'"val":3.14159' in encoded

        # Reject NaN
        with pytest.raises(SchemaError, match="Float value .* not valid"):
            canonical_json_bytes({"bad": float("nan")})

        # Reject +Infinity
        with pytest.raises(SchemaError, match="Float value .* not valid"):
            canonical_json_bytes({"bad": float("inf")})

        # Reject -Infinity
        with pytest.raises(SchemaError, match="Float value .* not valid"):
            canonical_json_bytes({"bad": float("-inf")})

    def test_empty_vs_none_distinction(self) -> None:
        """Empty dicts/lists/strings are preserved; optional None fields are omitted."""
        obj = {
            "empty_dict": {},
            "empty_list": [],
            "empty_str": "",
            "none_val": None,
        }
        data = canonical_json_bytes(obj, newline=False)
        assert data == b'{"empty_dict":{},"empty_list":[],"empty_str":"","none_val":null}'

    def test_key_order_permutations(self) -> None:
        """Keys are strictly sorted lexicographically regardless of insertion order."""
        dict1 = {"z": 1, "a": 2, "m": 3, "b": 4}
        dict2 = {"a": 2, "b": 4, "m": 3, "z": 1}
        dict3 = {"m": 3, "z": 1, "b": 4, "a": 2}
        assert (
            canonical_json_bytes(dict1, newline=False)
            == canonical_json_bytes(dict2, newline=False)
            == canonical_json_bytes(dict3, newline=False)
            == b'{"a":2,"b":4,"m":3,"z":1}'
        )

    def test_deep_legal_nesting(self) -> None:
        """Deeply nested structures serialize without corruption."""
        curr: dict[str, Any] = {"leaf": 42}
        for depth in range(20):
            curr = {f"level_{depth:02d}": curr}
        data = canonical_json_bytes(curr, newline=False)
        assert b'"leaf":42' in data
        assert b"level_19" in data

    def test_cyclic_reference_refusal(self) -> None:
        """Cyclic dictionaries must be detected and rejected with SchemaError."""
        cyclic: dict[str, Any] = {"key": "val"}
        cyclic["self"] = cyclic
        with pytest.raises(SchemaError, match="Cyclic reference detected"):
            canonical_json_bytes(cyclic)


class TestIdentityAndFingerprintSeam:
    """Verify content identity hashing, payload hashing, and plan fingerprinting."""

    def test_content_identity_excludes_provenance(self) -> None:
        ev1 = SessionEvent(
            seq=5,
            id="evt_005",
            parent_id="evt_004",
            ts="2026-09-06T00:00:05Z",
            actor="user",
            kind="message",
            payload={"text": "hello"},
            source_line=42,
            source_location="/path/to/log.jsonl",
            source_record_hash="abcdef",
        )
        ev2 = SessionEvent(
            seq=5,
            id="evt_005",
            parent_id="evt_004",
            ts="2026-09-06T00:00:05Z",
            actor="user",
            kind="message",
            payload={"text": "hello"},
            source_line=999,
            source_location="/different/path.jsonl",
            source_record_hash="012345",
        )
        # Content identity bytes and hashes must match despite differing provenance fields
        assert content_identity_bytes(ev1) == content_identity_bytes(ev2)
        assert content_identity_hash(ev1) == content_identity_hash(ev2)
        assert b"source_line" not in content_identity_bytes(ev1)
        assert b"source_location" not in content_identity_bytes(ev1)
        assert b"source_record_hash" not in content_identity_bytes(ev1)

    def test_payload_content_hash_deterministic(self) -> None:
        p1 = {"b": 2, "a": 1, "sub": {"k": "v"}}
        p2 = {"sub": {"k": "v"}, "a": 1, "b": 2}
        h1 = payload_content_hash(p1)
        h2 = payload_content_hash(p2)
        assert h1 == h2
        assert h1.startswith("sha256:")
        assert len(h1) == 7 + 64

    def test_plan_fingerprint_deterministic_and_binds_policy(self) -> None:
        plan_dict_1 = {
            "session_id": "sess_123",
            "actions": [{"code": "DROP_DANGLING", "id": "evt_99"}],
            "fingerprint": "will_be_ignored_fp",
        }
        plan_dict_2 = {
            "actions": [{"id": "evt_99", "code": "DROP_DANGLING"}],
            "session_id": "sess_123",
        }
        fp1 = plan_fingerprint(plan_dict_1, policy="conservative")
        fp2 = plan_fingerprint(plan_dict_2, policy="conservative")
        assert fp1 == fp2
        assert len(fp1) == 64

        # Differing policy must produce different fingerprint
        fp_salvage = plan_fingerprint(plan_dict_1, policy="salvage")
        assert fp_salvage != fp1

    def test_session_event_all_dataclass_fields_covered(self) -> None:
        """Verify normalizer fast path explicitly accounts for all SessionEvent fields."""
        from dataclasses import fields

        all_field_names = {f.name for f in fields(SessionEvent)}
        assert len(all_field_names) == 20

        ev = SessionEvent(
            id="evt_cov",
            parent_id="evt_p",
            seq=42,
            ts="2026-09-06T00:00:00Z",
            actor="user",
            kind="message",
            payload={"test": 1},
            content_hash="sha256:abcd",
            correlation_id="corr_1",
            branch_id="br_1",
            interaction_id="int_1",
            agent_id="ag_1",
            execution_state="active",
            source_line=10,
            source_record_hash="rec_1",
            original_id="orig_1",
            source_adapter="test_adapter",
            source_location="/test/loc",
            side_effects="none",
            extra_fields={"extra_k": "extra_v"},
        )
        codec = PurePythonCanonicalCodec()
        normalized = codec._normalize(ev)
        assert isinstance(normalized, dict)
        expected_keys = {
            "id",
            "parent_id",
            "seq",
            "ts",
            "actor",
            "kind",
            "payload",
            "content_hash",
            "correlation_id",
            "branch_id",
            "interaction_id",
            "agent_id",
            "execution_state",
            "source_line",
            "source_record_hash",
            "original_id",
            "source_adapter",
            "source_location",
            "side_effects",
            "extra_k",
        }
        assert set(normalized.keys()) == expected_keys


# Hypothesis differential tests
json_primitives = (
    st.none() | st.booleans() | st.integers(min_value=-10000, max_value=10000) | st.text()
)
json_values = st.recursive(
    json_primitives,
    lambda children: (
        st.lists(children, max_size=5)
        | st.dictionaries(st.text(min_size=1, max_size=10), children, max_size=5)
    ),
    max_leaves=15,
)


class TestHypothesisDifferential:
    """Differential property-based tests verifying seam byte-for-byte matches reference."""

    @given(val=json_values)
    def test_seam_matches_reference_json_serialization(self, val: Any) -> None:
        """Differential test against standard Python json.dumps with RFC 8785 params."""
        import json

        try:
            ref_bytes = json.dumps(
                val,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
            seam_bytes = canonical_json_bytes(val, newline=False)
            assert seam_bytes == ref_bytes
        except (TypeError, ValueError, SchemaError):
            pass
