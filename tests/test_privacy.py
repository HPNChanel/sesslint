"""Tests ensuring strict privacy guarantees and automated PII scanning."""

from __future__ import annotations

from pathlib import Path

import pytest

from sesslint.finding import SourceRef, make_finding
from tests.harness.conformance import CASES, run_case
from tests.utils.privacy import KNOWN_PII_SAMPLES, assert_fixtures_pii_free, assert_no_pii


def test_fixtures_directory_is_pii_free() -> None:
    """Scan all committed fixtures to guarantee zero PII or credential leaks."""
    assert_fixtures_pii_free(Path("fixtures"))


@pytest.mark.parametrize("sample", KNOWN_PII_SAMPLES)
def test_assert_no_pii_catches_known_samples(sample: str) -> None:
    """assert_no_pii loudly fails when any known sample string is present."""
    payload = {"user_data": f"Prefix text {sample} suffix text"}
    with pytest.raises(AssertionError, match="PII sample detected"):
        assert_no_pii(payload)


def test_assert_no_pii_catches_email_addresses() -> None:
    """assert_no_pii loudly fails on email address patterns."""
    with pytest.raises(AssertionError, match="Email address pattern detected"):
        assert_no_pii("Contact lead developer at dev_lead@enterprise.com for details")


def test_assert_no_pii_catches_credential_prefixes() -> None:
    """assert_no_pii loudly fails on secret / API key prefixes."""
    with pytest.raises(AssertionError, match="Credential marker detected"):
        assert_no_pii({"authorization": "Bearer eyJhbGciOi..."})
    with pytest.raises(AssertionError, match="Credential marker detected"):
        assert_no_pii({"api_key": "ghp_1234567890abcdef"})


def test_assert_no_pii_passes_on_clean_structures() -> None:
    """assert_no_pii succeeds on synthetic, sanitized structures."""
    clean_data = {
        "session_id": "sess_001",
        "events": [
            {"id": "evt_001", "actor": "user", "text": "run test"},
            {"id": "evt_002", "actor": "tool", "status": "ok"},
        ],
        "metadata": {"count": 42, "enabled": True},
    }
    assert_no_pii(clean_data)


def test_conformance_reports_are_pii_free() -> None:
    """Verify that all reports produced by the conformance cases are 100% PII-free."""
    for case in CASES:
        report = run_case(case)
        assert_no_pii(report)


def test_finding_message_with_injected_pii_caught_by_scanner(tmp_path: Path) -> None:
    """Verify that if a finding inadvertently contained PII, the scanner catches it."""
    # make_finding itself enforces content-free, but if an adversarial finding is constructed:
    f = make_finding(
        code="SL001",
        message_template="Malformed record on line {line} for record {record_id}",
        template_args={"line": "10", "record_id": "evt_leak"},
        source=SourceRef(path="test.jsonl", line=10, record_id="evt_leak"),
    )
    # Clean finding passes
    assert_no_pii(f)

    # Injected finding structure fails
    leaked_dict = {"finding": f, "leak": "leaked_address@company.org"}
    with pytest.raises(AssertionError, match="Email address pattern detected"):
        assert_no_pii(leaked_dict)
