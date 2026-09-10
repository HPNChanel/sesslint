"""Unit and regression tests for canonical JSON determinism and non-ASCII hashing (DEV-004).

Verifies:
1. Exactly ONE canonical JSON primitive implementation in sesslint.determinism, adhering to:
   - ensure_ascii=False (preserves UTF-8 CJK, emoji, and accented characters)
   - sort_keys=True (lexicographical key ordering)
   - separators=(",", ":") (compact, no extra whitespace)
   - newline policy: newline=False for hashing domain, newline=True for file storage domain
2. Delegation: repair.fingerprint.canonical_json_bytes delegates to
   determinism.canonical_json_bytes.
3. Non-ASCII plan and finding golden hash stability against fixtures/fingerprint/nonascii_plan.json.
4. Dict insertion-order invariance and repeat hashing determinism.
"""

from __future__ import annotations

import json
from pathlib import Path

from sesslint import api
from sesslint.determinism import canonical_json_bytes, repeat_hash
from sesslint.repair.fingerprint import (
    canonical_json_bytes as repair_canonical_json_bytes,
)
from sesslint.repair.fingerprint import (
    compute_plan_fingerprint,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
NONASCII_PLAN_FIXTURE = FIXTURES_DIR / "fingerprint" / "nonascii_plan.json"
REPEAT_SESSION_FIXTURE = FIXTURES_DIR / "determinism" / "repeat" / "repeat_session.json"


def test_canonical_json_key_sorting() -> None:
    """Keys are sorted lexicographically at all nesting depths."""
    nested_a = {"z": 1, "a": {"b": 2, "a": 1}, "m": [3, 2, 1]}
    nested_b = {"m": [3, 2, 1], "a": {"a": 1, "b": 2}, "z": 1}

    bytes_a = canonical_json_bytes(nested_a, newline=False)
    bytes_b = canonical_json_bytes(nested_b, newline=False)

    assert bytes_a == bytes_b
    # Lexicographical verification
    assert bytes_a == b'{"a":{"a":1,"b":2},"m":[3,2,1],"z":1}'


def test_canonical_json_compact_separators() -> None:
    """Separators are compact (',', ':') with no whitespace around them."""
    data = {"key1": "val1", "key2": 123}
    encoded = canonical_json_bytes(data, newline=False)
    assert b": " not in encoded
    assert b", " not in encoded
    assert encoded == b'{"key1":"val1","key2":123}'


def test_canonical_json_ensure_ascii_false_utf8() -> None:
    """Non-ASCII characters (CJK, emojis, accents) are emitted as raw UTF-8 bytes."""
    data = {
        "cjk": "测试CJK字符",
        "emoji": "🛡️🚀",
        "accents": "café crème brûlée",
        "symbols": "«таблиця»",
    }
    encoded = canonical_json_bytes(data, newline=False)

    # Ensure raw UTF-8 representation without \u escaping
    assert b"\\u" not in encoded
    assert "测试CJK字符".encode() in encoded
    assert "🛡️🚀".encode() in encoded
    assert "café crème brûlée".encode() in encoded

    decoded = json.loads(encoded.decode("utf-8"))
    assert decoded == data


def test_canonical_json_newline_policy() -> None:
    """Hashing domain uses newline=False; file storage domain uses newline=True."""
    data = {"hello": "world"}

    # Hash domain: NO trailing newline
    hash_domain_bytes = canonical_json_bytes(data, newline=False)
    assert not hash_domain_bytes.endswith(b"\n")
    assert hash_domain_bytes == b'{"hello":"world"}'

    # File storage domain: exactly one trailing newline
    file_domain_bytes = canonical_json_bytes(data, newline=True)
    assert file_domain_bytes.endswith(b"\n")
    assert file_domain_bytes == b'{"hello":"world"}\n'

    # Default is newline=True for file storage compatibility
    default_bytes = canonical_json_bytes(data)
    assert default_bytes == file_domain_bytes


def test_repair_fingerprint_delegation() -> None:
    """repair.fingerprint.canonical_json_bytes is determinism.canonical_json_bytes."""
    data = {"z": 10, "a": "text", "cjk": "汉字"}
    assert repair_canonical_json_bytes is canonical_json_bytes

    determinism_hash_bytes = canonical_json_bytes(data, newline=False)
    repair_hash_bytes = repair_canonical_json_bytes(data, newline=False)
    assert repair_hash_bytes == determinism_hash_bytes
    assert not repair_hash_bytes.endswith(b"\n")

    determinism_file_bytes = canonical_json_bytes(data, newline=True)
    repair_file_bytes = repair_canonical_json_bytes(data, newline=True)
    assert repair_file_bytes == determinism_file_bytes
    assert repair_file_bytes.endswith(b"\n")


def test_nonascii_plan_golden_hash() -> None:
    """fixtures/fingerprint/nonascii_plan.json matches the pinned golden fingerprints."""
    assert NONASCII_PLAN_FIXTURE.is_file(), f"Fixture missing: {NONASCII_PLAN_FIXTURE}"

    with open(NONASCII_PLAN_FIXTURE, encoding="utf-8") as f:
        fixture_data = json.load(f)

    # 1. Finding fingerprint matches golden value
    finding_dict = fixture_data["finding"]
    assert finding_dict["fingerprint"] == "2f416d11011ef0b7"

    # 2. Plan fingerprint matches golden value
    plan_dict = fixture_data["plan"]
    computed_plan_fp = compute_plan_fingerprint(plan_dict)
    assert computed_plan_fp == "f71dbb66ffd2934a91adac37f03141a3ef3651a071742170023a034914a0e625"
    assert plan_dict["fingerprint"] == computed_plan_fp


def test_repeat_hash_determinism() -> None:
    """repeat_hash produces identical 64-hex SHA-256 digest across runs and dict orders."""
    dict_1 = {"b": 2, "a": 1, "c": [1, 2, 3]}
    dict_2 = {"a": 1, "c": [1, 2, 3], "b": 2}

    h1 = repeat_hash(dict_1)
    h2 = repeat_hash(dict_2)

    assert len(h1) == 64
    assert h1 == h2


def test_plan_repeatability() -> None:
    """Planning repairs across multiple invocations produces identical plan fingerprints."""
    if REPEAT_SESSION_FIXTURE.is_file():
        plan1 = api.plan(REPEAT_SESSION_FIXTURE, policy="conservative")
        plan2 = api.plan(REPEAT_SESSION_FIXTURE, policy="conservative")

        assert plan1.fingerprint == plan2.fingerprint
        assert plan1.to_dict() == plan2.to_dict()
