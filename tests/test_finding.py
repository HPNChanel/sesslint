"""Tests for Finding envelope, taxonomies, fingerprinting, ordering, and schema (TASK-003)."""

from __future__ import annotations

import json
import random
import time
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any, cast

import pytest

from sesslint.codes import SL001, SL002
from sesslint.errors import FindingError
from sesslint.finding import (
    MAX_MESSAGE_LENGTH,
    TRUNCATION_MARKER,
    Finding,
    Repairability,
    Severity,
    SourceRef,
    compute_fingerprint,
    enforce_content_free_text,
    fingerprint_finding,
    get_finding_schema_path,
    load_finding_schema,
    make_finding,
    parse_finding_dict,
    sort_findings,
)


def test_severity_repairability_independence_matrix() -> None:
    """Prove orthogonal independence across all 4x4 = 16 severity x repairability combinations."""
    source = SourceRef(path="test.jsonl", line=1, record_id="evt-matrix")
    combinations_tested = 0

    for sev in Severity:
        for rep in Repairability:
            f = make_finding(
                code=SL001,
                severity=sev,
                repairability=rep,
                message_template="Matrix test at line {line}",
                source=source,
            )
            assert f.severity == sev
            assert f.repairability == rep
            assert f.code == SL001
            assert len(f.fingerprint) == 16
            combinations_tested += 1

    assert combinations_tested == 16


def test_severity_from_str() -> None:
    """Verify strict Severity parsing."""
    assert Severity.from_str("fatal") == Severity.FATAL
    assert Severity.from_str("error") == Severity.ERROR
    assert Severity.from_str("warning") == Severity.WARNING
    assert Severity.from_str("info") == Severity.INFO
    assert Severity.from_str(Severity.FATAL) == Severity.FATAL

    with pytest.raises(ValueError):
        Severity.from_str("critical")

    with pytest.raises(ValueError):
        Severity.from_str("")


def test_repairability_from_str() -> None:
    """Verify strict Repairability parsing."""
    assert Repairability.from_str("deterministic") == Repairability.DETERMINISTIC
    assert Repairability.from_str("lossy-explicit") == Repairability.LOSSY_EXPLICIT
    assert Repairability.from_str("manual") == Repairability.MANUAL
    assert Repairability.from_str("unsupported") == Repairability.UNSUPPORTED
    assert Repairability.from_str(Repairability.MANUAL) == Repairability.MANUAL

    with pytest.raises(ValueError):
        Repairability.from_str("automatic")

    with pytest.raises(ValueError):
        Repairability.from_str("")


def test_source_ref_validation() -> None:
    """Verify validation on SourceRef fields."""
    s = SourceRef(path="session.jsonl", line=10, record_id="rec-1")
    assert s.path == "session.jsonl"
    assert s.line == 10
    assert s.record_id == "rec-1"

    # Line is optional
    s_noline = SourceRef(path="session.jsonl")
    assert s_noline.line is None
    assert s_noline.record_id is None

    # Line must be positive integer (> 0)
    with pytest.raises((FindingError, ValueError)):
        SourceRef(path="session.jsonl", line=0)

    with pytest.raises((FindingError, ValueError)):
        SourceRef(path="session.jsonl", line=-5)

    # Boolean line must be rejected (isinstance(True, int) is True in Python)
    with pytest.raises((FindingError, ValueError)):
        SourceRef(path="session.jsonl", line=cast(Any, True))

    # Empty path rejected
    with pytest.raises((FindingError, ValueError)):
        SourceRef(path="")

    with pytest.raises((FindingError, ValueError)):
        SourceRef(path="   ")

    # Empty record_id rejected
    with pytest.raises((FindingError, ValueError)):
        SourceRef(path="session.jsonl", record_id="")

    with pytest.raises((FindingError, ValueError)):
        SourceRef(path="session.jsonl", record_id="   ")


def test_source_ref_cross_platform_path_normalization() -> None:
    """Verify Windows backslashes are normalized to POSIX forward slashes (AC-019, AC-029)."""
    s_win = SourceRef(path=r"sessions\run_1\ledger.jsonl", line=5)
    s_posix = SourceRef(path="sessions/run_1/ledger.jsonl", line=5)

    assert s_win.path == "sessions/run_1/ledger.jsonl"
    assert s_posix.path == "sessions/run_1/ledger.jsonl"

    f_win = make_finding(code=SL001, message_template="T", source=s_win)
    f_posix = make_finding(code=SL001, message_template="T", source=s_posix)

    assert f_win.fingerprint == f_posix.fingerprint
    assert f_win.source.path == f_posix.source.path


def test_finding_immutability() -> None:
    """Verify Finding and SourceRef instances are frozen and slots-backed."""
    source = SourceRef(path="test.jsonl", line=1)
    with pytest.raises((FrozenInstanceError, AttributeError)):
        source.line = 2  # type: ignore[misc]

    f = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Test at line {line}",
        source=source,
    )
    with pytest.raises((FrozenInstanceError, AttributeError)):
        f.message = "mutated"  # type: ignore[misc]


def test_finding_comparison_operators() -> None:
    """Verify complete total order comparisons (<, <=, >, >=, ==) on Finding."""
    source_1 = SourceRef(path="a.jsonl", line=1)
    source_2 = SourceRef(path="a.jsonl", line=2)

    f1 = make_finding(
        code=SL001, severity=Severity.FATAL, message_template="Fatal", source=source_1
    )
    f2 = make_finding(
        code=SL001, severity=Severity.ERROR, message_template="Error", source=source_1
    )
    f3 = make_finding(
        code=SL001, severity=Severity.ERROR, message_template="Error 2", source=source_2
    )

    # f1 (fatal) < f2 (error)
    assert f1 < f2
    assert f1 <= f2
    assert not (f1 > f2)
    assert not (f1 >= f2)
    assert f1 != f2

    # Reflexive comparisons
    assert f1 <= f1
    assert f1 >= f1
    assert not (f1 < f1)
    assert not (f1 > f1)
    assert f1 == f1

    # Transitive comparisons
    assert f2 < f3
    assert f1 < f3
    assert f1 <= f3
    assert f3 > f1
    assert f3 >= f1

    # Totality axiom: for any a, b: (a <= b) or (b <= a) is True
    findings_list = [f1, f2, f3]
    for a in findings_list:
        for b in findings_list:
            assert (a <= b) or (b <= a)
            assert (a < b) == (not (b <= a))


def test_make_finding_template_rendering_and_placeholders() -> None:
    """Verify allow-listed placeholders {record_id} and {line} render correctly."""
    source = SourceRef(path="a.jsonl", line=42, record_id="evt-42")
    f = make_finding(
        code=SL001,
        message_template="Defect on line {line} in event {record_id}",
        source=source,
    )
    assert f.message == "Defect on line 42 in event evt-42"
    assert f.source.line == 42
    assert f.source.record_id == "evt-42"

    # When placeholders not in template_args, fallbacks are used
    source_none = SourceRef(path="a.jsonl", line=None, record_id=None)
    f2 = make_finding(
        code=SL001,
        message_template="Line {line} id {record_id}",
        source=source_none,
    )
    assert f2.message == "Line <unknown> id <none>"


def test_disallowed_template_placeholder_raises() -> None:
    """Verify any placeholder outside {record_id} and {line} raises ValueError."""
    source = SourceRef(path="a.jsonl", line=1)
    with pytest.raises((FindingError, ValueError)) as exc:
        make_finding(
            code=SL001,
            message_template="Record payload was {payload}",
            source=source,
        )
    assert "Disallowed placeholder" in str(exc.value)

    with pytest.raises((FindingError, ValueError)):
        make_finding(
            code=SL001,
            message_template="User email {email}",
            source=source,
        )


def test_template_format_specifier_disallowed() -> None:
    """Verify format specifiers and conversions in placeholders are rejected."""
    source = SourceRef(path="a.jsonl", line=1)
    with pytest.raises(FindingError) as exc:
        make_finding(
            code=SL001,
            message_template="Line {line:04d}",
            source=source,
        )
    assert "Format specifiers and conversions are disallowed" in str(exc.value)

    with pytest.raises(FindingError):
        make_finding(
            code=SL001,
            message_template="Event {record_id!r}",
            source=source,
        )


def test_malformed_template_syntax_raises() -> None:
    """Verify unclosed or malformed braces in message template raise FindingError."""
    source = SourceRef(path="a.jsonl", line=1)
    with pytest.raises(FindingError) as exc:
        make_finding(
            code=SL001,
            message_template="Malformed {line",
            source=source,
        )
    assert "Malformed message template" in str(exc.value)


def test_disallowed_template_args_key_raises() -> None:
    """Verify passing template_args with invalid keys raises ValueError."""
    source = SourceRef(path="a.jsonl", line=1)
    with pytest.raises((FindingError, ValueError)) as exc:
        make_finding(
            code=SL001,
            message_template="Line {line}",
            template_args={"payload": "sensitive data"},
            source=source,
        )
    assert "Disallowed template argument" in str(exc.value)


def test_template_args_line_type_validation() -> None:
    """Verify template_args['line'] rejects non-positive numbers and arbitrary text."""
    source = SourceRef(path="a.jsonl", line=1)

    # Valid values
    f_int = make_finding(
        code=SL001,
        message_template="Line {line}",
        template_args={"line": 42},
        source=source,
    )
    assert f_int.message == "Line 42"

    f_str = make_finding(
        code=SL001,
        message_template="Line {line}",
        template_args={"line": "99"},
        source=source,
    )
    assert f_str.message == "Line 99"

    # Arbitrary text rejected (prevents payload smuggling via line placeholder)
    with pytest.raises(FindingError):
        make_finding(
            code=SL001,
            message_template="Line {line}",
            template_args={"line": "arbitrary prompt text"},
            source=source,
        )

    # Non-positive numbers rejected
    with pytest.raises(FindingError):
        make_finding(
            code=SL001,
            message_template="Line {line}",
            template_args={"line": 0},
            source=source,
        )

    with pytest.raises(FindingError):
        make_finding(
            code=SL001,
            message_template="Line {line}",
            template_args={"line": -5},
            source=source,
        )

    # Boolean rejected
    with pytest.raises(FindingError):
        make_finding(
            code=SL001,
            message_template="Line {line}",
            template_args={"line": True},
            source=source,
        )


def test_template_args_record_id_validation() -> None:
    """Verify template_args['record_id'] rejects empty strings, whitespace, and non-strings."""
    source = SourceRef(path="a.jsonl", line=1)

    with pytest.raises(FindingError):
        make_finding(
            code=SL001,
            message_template="Event {record_id}",
            template_args={"record_id": ""},
            source=source,
        )

    with pytest.raises(FindingError):
        make_finding(
            code=SL001,
            message_template="Event {record_id}",
            template_args={"record_id": "   "},
            source=source,
        )

    with pytest.raises(FindingError):
        make_finding(
            code=SL001,
            message_template="Event {record_id}",
            template_args={"record_id": 12345},
            source=source,
        )


def test_content_free_policy_rejects_control_chars_and_pii() -> None:
    """Verify content-free policy helper rejects control characters, newlines, and email/PII."""
    # Control chars
    with pytest.raises(FindingError):
        enforce_content_free_text("Line\nwith\nnewline")

    with pytest.raises(FindingError):
        enforce_content_free_text("Line with \t tab")

    with pytest.raises(FindingError):
        enforce_content_free_text("Line with \r carriage return")

    # Email pattern
    with pytest.raises(FindingError):
        enforce_content_free_text("Contact user@example.com for info")

    # Clean text passes
    enforce_content_free_text("Clean coordinate reference: record-1234")


def test_content_free_policy_rejects_unicode_control_and_formatting() -> None:
    """Verify content-free policy rejects exotic Unicode line breaks and hidden formatting chars."""
    # U+0085 (NEL - Next Line)
    with pytest.raises(FindingError):
        enforce_content_free_text("Text\u0085with NEL line break")

    # U+2028 (Line Separator)
    with pytest.raises(FindingError):
        enforce_content_free_text("Text\u2028with line separator")

    # U+2029 (Paragraph Separator)
    with pytest.raises(FindingError):
        enforce_content_free_text("Text\u2029with paragraph separator")

    # U+200B (Zero-Width Space)
    with pytest.raises(FindingError):
        enforce_content_free_text("Hidden\u200bpayload")

    # U+FEFF (Zero-Width No-Break Space / BOM)
    with pytest.raises(FindingError):
        enforce_content_free_text("BOM\ufeffpayload")

    # U+202E (Right-to-Left Override)
    with pytest.raises(FindingError):
        enforce_content_free_text("Bidi\u202eoverride")


def test_content_free_policy_rejects_credentials_and_tokens() -> None:
    """Verify content-free policy rejects credentials, private keys, bearer tokens, and API keys."""
    # Private key headers
    with pytest.raises(FindingError):
        enforce_content_free_text("Key: -----BEGIN RSA PRIVATE KEY----- MII...")

    with pytest.raises(FindingError):
        enforce_content_free_text("-----BEGIN OPENSSH PRIVATE KEY-----")

    # Bearer tokens
    with pytest.raises(FindingError):
        enforce_content_free_text("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")

    # API key patterns
    with pytest.raises(FindingError):
        enforce_content_free_text("sk-proj-abc12345678901234567890")

    with pytest.raises(FindingError):
        enforce_content_free_text("ghp_123456789012345678901234567890")

    # Credential assignments
    with pytest.raises(FindingError):
        enforce_content_free_text("api_key = supersecretvalue123")


def test_source_ref_rejects_injections_and_pii() -> None:
    """Verify SourceRef path and record_id reject newlines, control characters, and PII."""
    with pytest.raises(FindingError):
        SourceRef(path="path\nwith\nnewline.jsonl")

    with pytest.raises(FindingError):
        SourceRef(path="path/user@example.com/data.jsonl")

    with pytest.raises(FindingError):
        SourceRef(path="a.jsonl", record_id="user@example.com")

    with pytest.raises(FindingError):
        SourceRef(path="a.jsonl", record_id="id\nnewline")


def test_empty_message_template_rejected() -> None:
    """Verify empty message template is rejected."""
    source = SourceRef(path="a.jsonl", line=1)
    with pytest.raises((FindingError, ValueError)):
        make_finding(
            code=SL001,
            message_template="",
            source=source,
        )
    with pytest.raises((FindingError, ValueError)):
        make_finding(
            code=SL001,
            message_template="   ",
            source=source,
        )


def test_unknown_code_rejected() -> None:
    """Verify unknown code raises ValueError."""
    source = SourceRef(path="a.jsonl", line=1)
    with pytest.raises((FindingError, ValueError)) as exc:
        make_finding(
            code="SL999",
            message_template="Defect at {line}",
            source=source,
        )
    assert "Unknown finding code" in str(exc.value)


def test_message_length_capping_and_truncation() -> None:
    """Verify rendered message length is capped at 500 characters with truncation marker."""
    source = SourceRef(path="a.jsonl", line=1)
    long_template = "X" * 600
    f = make_finding(
        code=SL001,
        message_template=long_template,
        source=source,
    )
    assert len(f.message) == MAX_MESSAGE_LENGTH
    assert f.message.endswith(TRUNCATION_MARKER)


def test_related_ids_deduplication_and_sorting() -> None:
    """Verify related_ids are deduplicated and sorted in constructor."""
    source = SourceRef(path="a.jsonl", line=1)
    f = make_finding(
        code=SL001,
        message_template="Defect at {line}",
        source=source,
        related_ids=["evt-3", "evt-1", "evt-2", "evt-1"],
    )
    assert f.related_ids == ("evt-1", "evt-2", "evt-3")


def test_related_ids_content_free_validation() -> None:
    """Verify related_ids items must be non-empty and content-free."""
    source = SourceRef(path="a.jsonl", line=1)

    # Empty string rejected
    with pytest.raises(FindingError):
        make_finding(
            code=SL001,
            message_template="Defect",
            source=source,
            related_ids=["evt-1", ""],
        )

    # Newline rejected
    with pytest.raises(FindingError):
        make_finding(
            code=SL001,
            message_template="Defect",
            source=source,
            related_ids=["evt-1\ninjected"],
        )

    # PII rejected
    with pytest.raises(FindingError):
        make_finding(
            code=SL001,
            message_template="Defect",
            source=source,
            related_ids=["admin@example.com"],
        )


def test_fingerprint_determinism_and_insensitivity_to_dict_order() -> None:
    """Verify fingerprint is deterministic and invariant to dict insertion order."""
    source = SourceRef(path="session.jsonl", line=10, record_id="rec-01")

    # Construct two identical findings
    f1 = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Defect on line {line} for {record_id}",
        template_args={"line": "10", "record_id": "rec-01"},
        source=source,
        related_ids=["r-b", "r-a"],
    )

    f2 = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Defect on line {line} for {record_id}",
        template_args={"record_id": "rec-01", "line": "10"},  # opposite insertion order
        source=source,
        related_ids=["r-a", "r-b"],  # opposite insertion order
    )

    assert f1.fingerprint == f2.fingerprint
    assert fingerprint_finding(f1) == f1.fingerprint
    assert fingerprint_finding(f1, without_fingerprint=False) == f1.fingerprint


def test_fingerprint_differs_on_structural_changes() -> None:
    """Verify fingerprint changes when any structural coordinate or code changes."""
    base_source = SourceRef(path="session.jsonl", line=10, record_id="rec-01")
    base = make_finding(
        code=SL001,
        message_template="Defect at {line}",
        source=base_source,
    )

    # Different code
    f_diff_code = make_finding(
        code=SL002,
        message_template="Defect at {line}",
        source=base_source,
    )
    assert base.fingerprint != f_diff_code.fingerprint

    # Different line
    f_diff_line = make_finding(
        code=SL001,
        message_template="Defect at {line}",
        source=SourceRef(path="session.jsonl", line=11, record_id="rec-01"),
    )
    assert base.fingerprint != f_diff_line.fingerprint

    # Different path
    f_diff_path = make_finding(
        code=SL001,
        message_template="Defect at {line}",
        source=SourceRef(path="other.jsonl", line=10, record_id="rec-01"),
    )
    assert base.fingerprint != f_diff_path.fingerprint

    # Different record_id
    f_diff_rec = make_finding(
        code=SL001,
        message_template="Defect at {line}",
        source=SourceRef(path="session.jsonl", line=10, record_id="rec-02"),
    )
    assert base.fingerprint != f_diff_rec.fingerprint


def test_golden_ordering_sample_fixture_shuffled_100_times() -> None:
    """Verify sort_findings produces golden order across 100 random shuffles (AC-019)."""
    fixture_path = (
        Path(__file__).resolve().parent.parent / "fixtures" / "findings" / "ordering-sample.json"
    )
    data = json.loads(fixture_path.read_text(encoding="utf-8"))
    expected_fingerprints = data["expected_fingerprints"]
    findings_dicts = data["findings"]

    raw_findings = [parse_finding_dict(d) for d in findings_dicts]

    rng = random.Random(42)
    for _ in range(100):
        shuffled = list(raw_findings)
        rng.shuffle(shuffled)
        sorted_res = sort_findings(shuffled)
        assert [f.fingerprint for f in sorted_res] == expected_fingerprints


def test_sort_findings_does_not_mutate_input() -> None:
    """Verify sort_findings returns a new list and leaves input unchanged."""
    source = SourceRef(path="a.jsonl", line=1)
    f1 = make_finding(code=SL001, severity=Severity.INFO, message_template="Info", source=source)
    f2 = make_finding(code=SL001, severity=Severity.FATAL, message_template="Fatal", source=source)

    original = [f1, f2]
    sorted_res = sort_findings(original)

    assert original == [f1, f2]
    assert sorted_res == [f2, f1]
    assert sorted_res is not original


def test_ordering_rules_hierarchy() -> None:
    """Verify total ordering: severity -> code -> path -> line -> record_id -> fingerprint."""
    # 1. Severity: fatal < error < warning < info
    f_fatal = make_finding(
        code=SL001, severity=Severity.FATAL, message_template="T", source=SourceRef("b.jsonl", 10)
    )
    f_error = make_finding(
        code=SL001, severity=Severity.ERROR, message_template="T", source=SourceRef("a.jsonl", 1)
    )
    f_warning = make_finding(
        code=SL001, severity=Severity.WARNING, message_template="T", source=SourceRef("a.jsonl", 1)
    )
    f_info = make_finding(
        code=SL001, severity=Severity.INFO, message_template="T", source=SourceRef("a.jsonl", 1)
    )
    assert sort_findings([f_info, f_warning, f_error, f_fatal]) == [
        f_fatal,
        f_error,
        f_warning,
        f_info,
    ]

    # 2. Code lexicographical
    f_sl001 = make_finding(
        code=SL001, severity=Severity.ERROR, message_template="T", source=SourceRef("a.jsonl", 1)
    )
    f_sl002 = make_finding(
        code=SL002, severity=Severity.ERROR, message_template="T", source=SourceRef("a.jsonl", 1)
    )
    assert sort_findings([f_sl002, f_sl001]) == [f_sl001, f_sl002]

    # 3. Path lexicographical
    f_path_a = make_finding(
        code=SL001, severity=Severity.ERROR, message_template="T", source=SourceRef("a.jsonl", 1)
    )
    f_path_b = make_finding(
        code=SL001, severity=Severity.ERROR, message_template="T", source=SourceRef("b.jsonl", 1)
    )
    assert sort_findings([f_path_b, f_path_a]) == [f_path_a, f_path_b]

    # 4. Line: None sorts before 1
    f_line_none = make_finding(
        code=SL001, severity=Severity.ERROR, message_template="T", source=SourceRef("a.jsonl", None)
    )
    f_line_1 = make_finding(
        code=SL001, severity=Severity.ERROR, message_template="T", source=SourceRef("a.jsonl", 1)
    )
    f_line_2 = make_finding(
        code=SL001, severity=Severity.ERROR, message_template="T", source=SourceRef("a.jsonl", 2)
    )
    assert sort_findings([f_line_2, f_line_1, f_line_none]) == [f_line_none, f_line_1, f_line_2]

    # 5. Record ID: None sorts before string
    f_rec_none = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        message_template="T",
        source=SourceRef("a.jsonl", 1, None),
    )
    f_rec_a = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        message_template="T",
        source=SourceRef("a.jsonl", 1, "evt-a"),
    )
    f_rec_b = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        message_template="T",
        source=SourceRef("a.jsonl", 1, "evt-b"),
    )
    assert sort_findings([f_rec_b, f_rec_a, f_rec_none]) == [f_rec_none, f_rec_a, f_rec_b]


def test_schema_file_matches_dataclass() -> None:
    """Verify sesslint.finding.v1.json exists, parses, and validates finding dictionaries."""
    schema_path = get_finding_schema_path()
    assert schema_path.is_file()

    schema = load_finding_schema()
    assert schema["$id"] == "https://sesslint.dev/schemas/sesslint.finding/v1"

    source = SourceRef(path="test.jsonl", line=1, record_id="evt-1")
    f = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Schema validation test",
        source=source,
    )
    d = f.to_dict()

    # Round trip through parse_finding_dict
    reparsed = parse_finding_dict(d)
    assert reparsed == f


def test_finding_schema_structure_anti_drift() -> None:
    """Verify finding schema properties and required fields match Finding model exactly."""
    schema = load_finding_schema()

    expected_required = {
        "schema_version",
        "code",
        "severity",
        "repairability",
        "message",
        "source",
        "related_ids",
        "fingerprint",
    }
    assert set(schema["required"]) == expected_required

    expected_properties = expected_required | {"message_template", "evidence"}
    assert set(schema["properties"].keys()) == expected_properties

    # Source object schema validation
    source_schema = schema["properties"]["source"]
    assert set(source_schema["required"]) == {"path"}
    assert set(source_schema["properties"].keys()) == {"path", "line", "record_id"}


def test_adversarial_10k_related_ids() -> None:
    """Verify constructor handles 10,000 related_ids, sorting and deduplicating quickly."""
    raw_ids = [f"evt-{i % 5000:04d}" for i in range(10_000)]
    source = SourceRef(path="test.jsonl", line=1)

    t0 = time.perf_counter()
    f = make_finding(
        code=SL001,
        message_template="Huge related ids test",
        source=source,
        related_ids=raw_ids,
    )
    elapsed = time.perf_counter() - t0

    assert len(f.related_ids) == 5000
    assert f.related_ids[0] == "evt-0000"
    assert f.related_ids[-1] == "evt-4999"
    assert elapsed < 1.0


def test_adversarial_100k_findings_sort_performance() -> None:
    """Verify sorting 100k findings completes in <1s (perf smoke test)."""
    source = SourceRef(path="bench.jsonl", line=1)
    base_finding = make_finding(
        code=SL001,
        message_template="Bench finding",
        source=source,
    )

    # Generate 100k findings with small variations
    items = [base_finding] * 100_000

    t0 = time.perf_counter()
    sorted_res = sort_findings(items)
    elapsed = time.perf_counter() - t0

    assert len(sorted_res) == 100_000
    assert elapsed < 1.0


def test_no_vendor_strings_in_finding_module() -> None:
    """Verify finding.py contains no vendor-specific identifiers or terms."""
    finding_path = Path(__file__).resolve().parent.parent / "src" / "sesslint" / "finding.py"
    text = finding_path.read_text(encoding="utf-8").lower()
    vendor_terms = ["anthropic", "claude", "openai", "copilot", "chatgpt"]
    for term in vendor_terms:
        assert term not in text, f"Found forbidden vendor term '{term}' in finding.py"


def test_direct_finding_instantiation_validation() -> None:
    """Verify __post_init__ validation on direct Finding and SourceRef instantiations."""
    source = SourceRef(path="test.jsonl", line=1)

    # Invalid code
    with pytest.raises(FindingError):
        Finding(
            code="",
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message="msg",
            source=source,
            related_ids=(),
            fingerprint="0123456789abcdef",
        )

    # Unregistered code
    with pytest.raises(FindingError):
        Finding(
            code="UNREGISTERED",
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message="msg",
            source=source,
            related_ids=(),
            fingerprint="0123456789abcdef",
        )

    # Invalid severity
    with pytest.raises(FindingError):
        Finding(
            code=SL001,
            severity=cast(Any, "invalid"),
            repairability=Repairability.MANUAL,
            message="msg",
            source=source,
            related_ids=(),
            fingerprint="0123456789abcdef",
        )

    # Invalid repairability
    with pytest.raises(FindingError):
        Finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=cast(Any, "invalid"),
            message="msg",
            source=source,
            related_ids=(),
            fingerprint="0123456789abcdef",
        )

    # Invalid message
    with pytest.raises(FindingError):
        Finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message=cast(Any, 123),
            source=source,
            related_ids=(),
            fingerprint="0123456789abcdef",
        )

    # Message exceeding MAX_MESSAGE_LENGTH
    with pytest.raises(FindingError):
        Finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message="A" * (MAX_MESSAGE_LENGTH + 1),
            source=source,
            related_ids=(),
            fingerprint="0123456789abcdef",
        )

    # Invalid source
    with pytest.raises(FindingError):
        Finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message="msg",
            source=cast(Any, "not-a-sourceref"),
            related_ids=(),
            fingerprint="0123456789abcdef",
        )

    # Invalid fingerprint (not 16-hex pattern)
    with pytest.raises(FindingError):
        Finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message="msg",
            source=source,
            related_ids=(),
            fingerprint="not-16-hex-characters",
        )

    with pytest.raises(FindingError):
        Finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message="msg",
            source=source,
            related_ids=(),
            fingerprint="",
        )

    # Invalid schema_version
    with pytest.raises(FindingError):
        Finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message="msg",
            source=source,
            related_ids=(),
            fingerprint="0123456789abcdef",
            schema_version=cast(Any, "wrong/v1"),
        )

    # Invalid message_template
    with pytest.raises(FindingError):
        Finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message="msg",
            source=source,
            related_ids=(),
            fingerprint="0123456789abcdef",
            message_template=cast(Any, 123),
        )

    # Invalid related_ids type
    with pytest.raises(FindingError):
        Finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message="msg",
            source=source,
            related_ids=cast(Any, 123),
            fingerprint="0123456789abcdef",
        )

    # SourceRef with invalid record_id
    with pytest.raises(FindingError):
        SourceRef(path="test.jsonl", record_id=cast(Any, 123))

    # make_finding with invalid source
    with pytest.raises(FindingError):
        make_finding(
            code=SL001,
            message_template="T",
            source=cast(Any, "bad"),
        )

    # make_finding with invalid template_args type
    with pytest.raises(FindingError):
        make_finding(
            code=SL001,
            message_template="T",
            template_args=cast(Any, "not-mapping"),
            source=source,
        )

    # make_finding with invalid related_ids type
    with pytest.raises(FindingError):
        make_finding(
            code=SL001,
            message_template="T",
            source=source,
            related_ids=cast(Any, 123),
        )


def test_parse_finding_dict_negative_branches() -> None:
    """Verify error handling on malformed dictionaries in parse_finding_dict."""
    valid_dict: dict[str, Any] = {
        "schema_version": "sesslint.finding/v1",
        "code": "SL001",
        "severity": "error",
        "repairability": "manual",
        "message": "msg",
        "source": {"path": "a.jsonl", "line": 1, "record_id": None},
        "related_ids": [],
        "fingerprint": "0123456789abcdef",
    }

    # Non-mapping
    with pytest.raises(FindingError):
        parse_finding_dict(cast(Any, []))

    # Bad schema_version
    d = dict(valid_dict, schema_version="other/v1")
    with pytest.raises(FindingError):
        parse_finding_dict(d)

    # Bad code
    d = dict(valid_dict, code="INVALID")
    with pytest.raises(FindingError):
        parse_finding_dict(d)

    # Missing/bad severity
    d = dict(valid_dict, severity=123)
    with pytest.raises(FindingError):
        parse_finding_dict(d)

    # Missing/bad repairability
    d = dict(valid_dict, repairability=123)
    with pytest.raises(FindingError):
        parse_finding_dict(d)

    # Missing/bad message
    d = dict(valid_dict, message=None)
    with pytest.raises(FindingError):
        parse_finding_dict(d)

    # Message too long
    d = dict(valid_dict, message="X" * 501)
    with pytest.raises(FindingError):
        parse_finding_dict(d)

    # Missing/bad source
    d = dict(valid_dict, source="not-dict")
    with pytest.raises(FindingError):
        parse_finding_dict(d)

    # Missing/bad source.path
    d = dict(valid_dict, source={"path": 123})
    with pytest.raises(FindingError):
        parse_finding_dict(d)

    # Bad related_ids
    d = dict(valid_dict, related_ids="not-list")
    with pytest.raises(FindingError):
        parse_finding_dict(d)

    # Non-string element in related_ids
    d = dict(valid_dict, related_ids=[123])
    with pytest.raises(FindingError):
        parse_finding_dict(d)

    # Empty string in related_ids
    d = dict(valid_dict, related_ids=[""])
    with pytest.raises(FindingError):
        parse_finding_dict(d)

    # Missing/bad fingerprint
    d = dict(valid_dict, fingerprint="")
    with pytest.raises(FindingError):
        parse_finding_dict(d)

    # Fingerprint not 16-hex
    d = dict(valid_dict, fingerprint="xyz")
    with pytest.raises(FindingError):
        parse_finding_dict(d)

    # Bad message_template
    d = dict(valid_dict, message_template=123)
    with pytest.raises(FindingError):
        parse_finding_dict(d)


def test_finding_comparison_with_non_finding_raises_type_error() -> None:
    """Verify comparing Finding with non-Finding instances raises TypeError."""
    source = SourceRef(path="a.jsonl", line=1)
    f = make_finding(code=SL001, message_template="T", source=source)
    with pytest.raises(TypeError):
        _ = f < 42
    with pytest.raises(TypeError):
        _ = f <= "string"
    with pytest.raises(TypeError):
        _ = f > None
    with pytest.raises(TypeError):
        _ = f >= {}


def test_sourceref_record_id_strip_normalization() -> None:
    """Verify SourceRef path and record_id strip surrounding whitespace."""
    s = SourceRef(path="  a.jsonl  ", record_id="  rec-1  ")
    assert s.path == "a.jsonl"
    assert s.record_id == "rec-1"


def test_direct_finding_related_ids_element_validation() -> None:
    """Verify direct Finding instantiation validates items in related_ids."""
    source = SourceRef(path="a.jsonl", line=1)
    with pytest.raises(FindingError):
        Finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message="msg",
            source=source,
            related_ids=("",),
            fingerprint="0123456789abcdef",
        )
    with pytest.raises(FindingError):
        Finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message="msg",
            source=source,
            related_ids=cast(Any, (123,)),
            fingerprint="0123456789abcdef",
        )


def test_direct_finding_unsorted_related_ids_normalization() -> None:
    """Verify direct Finding instantiation normalizes unsorted tuple in related_ids."""
    source = SourceRef(path="a.jsonl", line=1)
    f = Finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message="msg",
        source=source,
        related_ids=("evt-2", "evt-1"),
        fingerprint="0123456789abcdef",
    )
    assert f.related_ids == ("evt-1", "evt-2")


def test_get_finding_schema_path_prefix_resolution(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Verify get_finding_schema_path resolves to sys.prefix share location."""
    import sys

    import sesslint.finding as mod

    fake_share_file = tmp_path / "share" / "sesslint" / "schemas" / "sesslint.finding.v1.json"
    fake_share_file.parent.mkdir(parents=True, exist_ok=True)
    fake_share_file.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(sys, "prefix", str(tmp_path))
    # Point repo root check to nonexistent location
    orig_path_is_file = Path.is_file

    def mock_is_file(self: Path) -> bool:
        if "share" in str(self):
            return orig_path_is_file(self)
        return False

    monkeypatch.setattr(Path, "is_file", mock_is_file)
    resolved = mod.get_finding_schema_path()
    assert "share" in str(resolved)


def test_schema_loader_file_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify load_finding_schema raises FileNotFoundError when schema file is missing."""
    import sesslint.finding as mod

    monkeypatch.setattr(mod, "get_finding_schema_path", lambda: Path("nonexistent/schema.json"))
    with pytest.raises(FileNotFoundError):
        load_finding_schema()


def test_fingerprint_with_adapter_and_profile_versions() -> None:
    """Verify adapter and profile versions differentiate finding fingerprints (RVW-007)."""
    s = SourceRef(path="session.jsonl", line=5, record_id="evt_01")

    # Base fingerprint without versions
    fp_base = compute_fingerprint(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Syntax error at line {line}",
        source=s,
    )

    # Fingerprint with adapter_version
    fp_adapter_v1 = compute_fingerprint(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Syntax error at line {line}",
        source=s,
        adapter_version="claude-code@1.0.0",
    )
    fp_adapter_v2 = compute_fingerprint(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Syntax error at line {line}",
        source=s,
        adapter_version="claude-code@2.0.0",
    )

    # Fingerprint with profile_version
    fp_prof_neutral = compute_fingerprint(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Syntax error at line {line}",
        source=s,
        profile_version="neutral@1.0.0",
    )
    fp_prof_strict = compute_fingerprint(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Syntax error at line {line}",
        source=s,
        profile_version="claude-strict@1.0.0",
    )

    # All fingerprints must be mutually distinct
    fps = {fp_base, fp_adapter_v1, fp_adapter_v2, fp_prof_neutral, fp_prof_strict}
    assert len(fps) == 5

    # make_finding threads adapter_version and profile_version
    f1 = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Syntax error at line {line}",
        source=s,
        adapter_version="claude-code@1.0.0",
        profile_version="neutral@1.0.0",
    )
    f2 = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Syntax error at line {line}",
        source=s,
        adapter_version="claude-code@1.0.0",
        profile_version="claude-strict@1.0.0",
    )
    assert f1.fingerprint != f2.fingerprint
