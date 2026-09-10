"""Tests for unified version-bearing fingerprints in identity checks (DEV-004, FR-046).

Verifies:
- Preimage composition adheres to the 10-element array contract:
  [code, adapter_id, adapter_version, profile_id, profile_version,
   path, line, ordinal, record_id, canonical_evidence_subset]
- Unavailable/empty versions normalize to explicit 'unknown' marker.
- Version-sensitivity: changing adapter_id, adapter_version, profile_id, or
  profile_version alters fingerprint.
- Structural coordinates: changing path, line, or record_id alters fingerprint.
- Non-ASCII stability: CJK, emoji, and accented characters hash identically.
- Content-free invariant: non-whitelisted evidence fields do not affect fingerprint.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from sesslint.canonical import SessionEvent
from sesslint.checks.identity import check_identities
from sesslint.codes import SL003
from sesslint.context import CheckContext
from sesslint.determinism import canonical_json_bytes
from sesslint.finding import (
    SourceRef,
    compute_finding_fingerprint,
    make_finding,
)
from sesslint.profiles import get_profile

FIXTURES_FP_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "fingerprint"


def test_preimage_ten_element_structure() -> None:
    """Fingerprint preimage must be a 10-element array with exact field positions."""
    finding = make_finding(
        code=SL003,
        message_template="Duplicate record {record_id}",
        source=SourceRef(path="session.json", line=10, record_id="rec_1"),
        evidence={"id": "rec_1", "count": 2, "variant": "identical", "ignored_field": "secret"},
        adapter_id="canonical",
        adapter_version="1.0.0",
        profile_id="neutral",
        profile_version="1.0.0",
    )

    expected_evidence = {
        "count": 2,
        "id": "rec_1",
        "variant": "identical",
    }
    expected_preimage = [
        "SL003",
        "canonical",
        "1.0.0",
        "neutral",
        "1.0.0",
        "session.json",
        10,
        None,
        "rec_1",
        expected_evidence,
    ]

    expected_encoded = canonical_json_bytes(expected_preimage, newline=False)
    expected_fp = hashlib.sha256(expected_encoded).hexdigest()[:16]

    assert finding.fingerprint == expected_fp
    assert len(finding.fingerprint) == 16


def test_direct_compute_finding_fingerprint() -> None:
    """Direct invocation of compute_finding_fingerprint matches make_finding."""
    source = SourceRef(path="session.json", line=10, record_id="rec_1")
    evidence = {"id": "rec_1", "count": 2, "variant": "identical"}
    context = CheckContext(
        adapter_id="canonical",
        adapter_version="1.0.0",
        profile_id="neutral",
        profile_version="1.0.0",
    )

    fp1 = compute_finding_fingerprint(
        code=SL003,
        source=source,
        evidence=evidence,
        context=context,
    )
    fp2 = make_finding(
        code=SL003,
        message_template="Duplicate record {record_id}",
        source=source,
        evidence=evidence,
        context=context,
    ).fingerprint

    assert fp1 == fp2


def test_unknown_version_marker() -> None:
    """Missing or whitespace versions must normalize to 'unknown', never empty string."""
    f_none = make_finding(
        code=SL003,
        message_template="Duplicate record",
        source=SourceRef(path="test.json"),
        adapter_id=None,
        adapter_version=None,
        profile_id=None,
        profile_version=None,
    )
    f_empty = make_finding(
        code=SL003,
        message_template="Duplicate record",
        source=SourceRef(path="test.json"),
        adapter_id="   ",
        adapter_version="",
        profile_id="",
        profile_version="  ",
    )
    f_explicit_unknown = make_finding(
        code=SL003,
        message_template="Duplicate record",
        source=SourceRef(path="test.json"),
        adapter_id="unknown",
        adapter_version="unknown",
        profile_id="unknown",
        profile_version="unknown",
    )

    assert f_none.fingerprint == f_empty.fingerprint
    assert f_none.fingerprint == f_explicit_unknown.fingerprint


def test_version_sensitivity_matrix() -> None:
    """Varying any single version coordinate must produce a distinct fingerprint."""
    base_params = {
        "code": SL003,
        "message_template": "Duplicate record {record_id}",
        "source": SourceRef(path="session.json", line=5, record_id="evt_1"),
        "evidence": {"id": "evt_1", "count": 2},
        "adapter_id": "canonical",
        "adapter_version": "1.0.0",
        "profile_id": "neutral",
        "profile_version": "1.0.0",
    }

    base_fp = make_finding(**base_params).fingerprint

    # 1. Vary adapter_id
    fp_alt_adapter_id = make_finding(**{**base_params, "adapter_id": "claude_code"}).fingerprint
    assert fp_alt_adapter_id != base_fp

    # 2. Vary adapter_version
    fp_alt_adapter_ver = make_finding(**{**base_params, "adapter_version": "1.1.0"}).fingerprint
    assert fp_alt_adapter_ver != base_fp

    # 3. Vary profile_id
    fp_alt_profile_id = make_finding(**{**base_params, "profile_id": "claude-strict"}).fingerprint
    assert fp_alt_profile_id != base_fp

    # 4. Vary profile_version
    fp_alt_profile_ver = make_finding(**{**base_params, "profile_version": "2.0.0"}).fingerprint
    assert fp_alt_profile_ver != base_fp

    # All 5 fingerprints must be mutually distinct
    all_fps = {
        base_fp,
        fp_alt_adapter_id,
        fp_alt_adapter_ver,
        fp_alt_profile_id,
        fp_alt_profile_ver,
    }
    assert len(all_fps) == 5


def test_structural_coordinates_sensitivity() -> None:
    """Varying path, line, or record_id must produce distinct fingerprints (RVW-007)."""
    base_params = {
        "code": SL003,
        "message_template": "Duplicate record {record_id}",
        "source": SourceRef(path="sessions/a.json", line=5, record_id="evt_1"),
        "evidence": {"id": "evt_1", "count": 2},
    }
    base_fp = make_finding(**base_params).fingerprint

    # Cross-file collision prevention
    fp_other_file = make_finding(
        **{**base_params, "source": SourceRef(path="sessions/b.json", line=5, record_id="evt_1")}
    ).fingerprint
    assert fp_other_file != base_fp

    # Line sensitivity
    fp_other_line = make_finding(
        **{**base_params, "source": SourceRef(path="sessions/a.json", line=6, record_id="evt_1")}
    ).fingerprint
    assert fp_other_line != base_fp

    # Record ID sensitivity
    fp_other_rec = make_finding(
        **{**base_params, "source": SourceRef(path="sessions/a.json", line=5, record_id="evt_2")}
    ).fingerprint
    assert fp_other_rec != base_fp


def test_context_object_threading() -> None:
    """CheckContext passed to check_identities stamps version metadata into findings."""
    profile = get_profile("neutral")
    ctx = CheckContext.from_profile_and_adapter(profile, "canonical")

    events = [
        SessionEvent(
            id="msg-1",
            parent_id=None,
            seq=0,
            ts="2026-09-09T00:00:00Z",
            actor="user",
            kind="message",
        ),
        SessionEvent(
            id="msg-2",
            parent_id="msg-1",
            seq=1,
            ts="2026-09-09T00:00:01Z",
            actor="assistant",
            kind="message",
        ),
        SessionEvent(
            id="msg-2",
            parent_id="msg-1",
            seq=2,
            ts="2026-09-09T00:00:02Z",
            actor="assistant",
            kind="message",
        ),
    ]

    findings_with_ctx = check_identities(events, source_path="session.json", context=ctx)
    findings_no_ctx = check_identities(events, source_path="session.json", context=None)

    assert len(findings_with_ctx) == 1
    assert len(findings_no_ctx) == 1

    assert findings_with_ctx[0].fingerprint != findings_no_ctx[0].fingerprint


def test_nonascii_golden_fixture() -> None:
    """Non-ASCII finding from fixture must match golden fingerprint identically."""
    fixture_path = FIXTURES_FP_DIR / "nonascii_plan.json"
    data = json.loads(fixture_path.read_text(encoding="utf-8"))

    golden_finding = data["finding"]
    expected_fp = golden_finding["fingerprint"]

    recomputed = make_finding(
        code=golden_finding["code"],
        message_template=golden_finding["message"],
        source=SourceRef(**golden_finding["source"]),
        evidence=golden_finding.get("evidence"),
        adapter_id="canonical",
        adapter_version="1.0.0",
        profile_id="neutral",
        profile_version="1.0.0",
    )

    assert recomputed.fingerprint == expected_fp
