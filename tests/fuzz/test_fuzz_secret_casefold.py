"""T-10: ASCII shadow scanning keeps exact match spans and original digests."""

import hashlib

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sesslint.checks.hygiene import (
    _GENERIC_ASSIGNMENT_LOWER,
    _SECRET_FAMILIES,
    SecretScanTracker,
)

REFERENCE = next(p for name, p, _ in _SECRET_FAMILIES if name == "generic-credential-assignment")


@given(
    keyword=st.sampled_from(
        [
            b"PASSWORD",
            b"api_KEY",
            b"Access-Key",
            b"client_SECRET",
            b"auth-token",
            b"secret",
            b"token",
        ]
    ),
    middle=st.sampled_from([b":", b" = ", b'\\":\\"', b".-\t=\n", b"_hint:"]),
    value=st.binary(min_size=0, max_size=96),
    prefix=st.binary(max_size=32),
    suffix=st.binary(max_size=32),
)
def test_folded_scanner_is_span_equivalent(keyword, middle, value, prefix, suffix):
    raw = prefix + keyword + middle + value + suffix
    assert [match.span(1) for match in _GENERIC_ASSIGNMENT_LOWER.finditer(raw.lower())] == [
        match.span(1) for match in REFERENCE.finditer(raw)
    ]


@pytest.mark.parametrize("keyword", [b"PASSWORD", b"api_Key", b"client_SECRET"])
def test_tracker_hashes_original_case_sensitive_bytes(keyword):
    values = [b"SyntheticAbCdE12345", b"syntheticabcde12345"]
    raw = b" ".join(keyword + b"=" + value for value in values)
    tracker = SecretScanTracker()
    tracker.feed(raw, line_number=1, byte_offset=0, byte_end=len(raw), record_ordinal=1)
    findings = tracker.into_findings(path_str="synthetic.jsonl")
    assert len(findings) == 1
    assert findings[0].evidence is not None
    assert findings[0].evidence["occurrence_count"] == 2
    assert set(findings[0].evidence["match_sha256"]) == {
        hashlib.sha256(value).hexdigest() for value in values
    }
    rendered = str(findings[0].to_dict())
    assert all(value.decode() not in rendered for value in values)
