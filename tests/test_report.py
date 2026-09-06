"""Tests for Report envelope, counts aggregation, assurance levels, and schemas (TASK-004)."""

from __future__ import annotations

import inspect
import random
import time
from pathlib import Path
from typing import cast

import pytest

from sesslint.codes import SL001, SL002, SL003, SL101
from sesslint.errors import (
    AssuranceError,
    ContentLeakError,
    SchemaError,
    UnknownFieldError,
    VersionError,
)
from sesslint.finding import Finding, Repairability, Severity, SourceRef, make_finding
from sesslint.report import (
    ASSURANCE_LIMITATIONS,
    KNOWN_REPORT_FIELDS,
    REPORT_SCHEMA_VERSION,
    REQUIRED_REPORT_FIELDS,
    REQUIRED_SEVERITIES,
    VALID_ASSURANCE_LEVELS,
    Assurance,
    Counts,
    Report,
    build_report,
    dump_report,
    enforce_content_free,
    get_report_schema_path,
    load_report_schema,
    parse_report,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
REPORT_FIXTURE_PATH = REPO_ROOT / "fixtures" / "reports" / "minimal.json"


def _make_sample_finding(
    code: str = SL001,
    sev: Severity = Severity.ERROR,
    rep: Repairability = Repairability.MANUAL,
    path: str = "session.jsonl",
    line: int | None = 1,
    record_id: str | None = None,
    msg_tpl: str = "Test defect at line {line}",
) -> Finding:
    return make_finding(
        code=code,
        severity=sev,
        repairability=rep,
        message_template=msg_tpl,
        source=SourceRef(path=path, line=line, record_id=record_id),
    )


def test_build_report_derives_counts_correctly() -> None:
    """Verify counts are derived accurately across all severities and rule codes."""
    f1 = _make_sample_finding(SL001, Severity.FATAL, line=1)
    f2 = _make_sample_finding(SL001, Severity.ERROR, line=2)
    f3 = _make_sample_finding(SL002, Severity.ERROR, line=3)
    f4 = _make_sample_finding(SL003, Severity.WARNING, line=4)
    f5 = _make_sample_finding(SL101, Severity.INFO, line=5)
    f6 = _make_sample_finding(SL002, Severity.ERROR, line=6)

    findings = [f1, f2, f3, f4, f5, f6]
    report = build_report(
        session_id="sess-test-counts",
        source_fingerprint="fp-test-123",
        tool_version="0.1.0",
        findings=findings,
        assurance="A2",
        limitation="Provider/runtime replay has not been independently exercised.",
    )

    assert report.counts.total == 6
    assert report.counts.by_severity["fatal"] == 1
    assert report.counts.by_severity["error"] == 3
    assert report.counts.by_severity["warning"] == 1
    assert report.counts.by_severity["info"] == 1

    for s in REQUIRED_SEVERITIES:
        assert s in report.counts.by_severity

    assert report.counts.by_code == {
        "SL001": 2,
        "SL002": 2,
        "SL003": 1,
        "SL101": 1,
    }


def test_build_report_signature_has_no_counts_parameter() -> None:
    """Assert build_report has no 'counts' parameter and rejects caller-supplied counts."""
    sig = inspect.signature(build_report)
    assert "counts" not in sig.parameters, (
        "build_report must not accept a caller-supplied 'counts' parameter"
    )

    f = _make_sample_finding()
    with pytest.raises(TypeError, match="unexpected keyword argument 'counts'"):
        build_report(  # type: ignore[call-arg]
            session_id="sess-1",
            source_fingerprint="fp-1",
            tool_version="0.1.0",
            findings=[f],
            assurance="A1",
            limitation="Some limitation",
            counts=Counts(by_severity={}, by_code={}, total=999),
        )


def test_empty_findings_clean_bill_report() -> None:
    """Verify zero findings produces all-zero counts and valid clean report."""
    report = build_report(
        session_id="sess-clean",
        source_fingerprint="fp-clean-000",
        tool_version="0.1.0",
        findings=[],
        assurance="A2",
        limitation="No findings detected; graph invariants validated.",
    )

    assert report.counts.total == 0
    assert report.counts.by_severity == {"fatal": 0, "error": 0, "warning": 0, "info": 0}
    assert report.counts.by_code == {}
    assert report.findings == ()

    dumped = dump_report(report)
    parsed = parse_report(dumped)
    assert parsed.counts.total == 0
    assert parsed.counts.by_severity == report.counts.by_severity


@pytest.mark.parametrize("level", ["A0", "A1", "A2", "A3", "A4"])
def test_limitation_required_for_all_assurance_levels(level: str) -> None:
    """Verify any assurance without a non-empty limitation raises AssuranceError."""
    as_level = cast(Assurance, level)
    f = _make_sample_finding()

    # Empty string raises
    with pytest.raises(AssuranceError, match="limitation is required and must be non-empty"):
        build_report(
            session_id="sess-1",
            source_fingerprint="fp-1",
            tool_version="0.1.0",
            findings=[f],
            assurance=as_level,
            limitation="",
        )

    # Whitespace-only string raises
    with pytest.raises(AssuranceError, match="limitation is required and must be non-empty"):
        build_report(
            session_id="sess-1",
            source_fingerprint="fp-1",
            tool_version="0.1.0",
            findings=[f],
            assurance=as_level,
            limitation="   \t\n  ",
        )

    # Direct Report instantiation with empty limitation raises
    with pytest.raises(AssuranceError, match="Report.limitation is required"):
        Report(
            schema_version=REPORT_SCHEMA_VERSION,
            session_id="sess-1",
            source_fingerprint="fp-1",
            tool_version="0.1.0",
            findings=(f,),
            counts=Counts(
                by_severity={"fatal": 0, "error": 1, "warning": 0, "info": 0},
                by_code={"SL001": 1},
                total=1,
            ),
            assurance=as_level,
            limitation="",
        )


def test_invalid_assurance_level_raises() -> None:
    """Verify invalid assurance strings raise AssuranceError."""
    f = _make_sample_finding()
    for bad_lvl in ("A5", "clean", "healthy", "A", ""):
        with pytest.raises(AssuranceError, match="Invalid assurance level"):
            build_report(
                session_id="sess-1",
                source_fingerprint="fp-1",
                tool_version="0.1.0",
                findings=[f],
                assurance=bad_lvl,  # type: ignore[arg-type]
                limitation="Valid limitation string",
            )


def test_build_report_sorts_shuffled_findings_deterministically() -> None:
    """Verify shuffled finding inputs yield identical sorted tuple and identical dump bytes."""
    f_fatal = _make_sample_finding(SL001, Severity.FATAL, line=10)
    f_err_1 = _make_sample_finding(SL001, Severity.ERROR, line=1)
    f_err_2 = _make_sample_finding(SL002, Severity.ERROR, line=5)
    f_warn = _make_sample_finding(SL003, Severity.WARNING, line=20)
    f_info = _make_sample_finding(SL101, Severity.INFO, line=30)

    findings_base = [f_fatal, f_err_1, f_err_2, f_warn, f_info]

    r_base = build_report(
        session_id="sess-det",
        source_fingerprint="fp-det",
        tool_version="0.1.0",
        findings=findings_base,
        assurance="A2",
        limitation="Deterministic sort test",
    )
    base_dump = dump_report(r_base)

    # Shuffle repeatedly and verify identical bytes every time
    rng = random.Random(42)
    for _ in range(10):
        shuffled = list(findings_base)
        rng.shuffle(shuffled)
        r_shuffled = build_report(
            session_id="sess-det",
            source_fingerprint="fp-det",
            tool_version="0.1.0",
            findings=shuffled,
            assurance="A2",
            limitation="Deterministic sort test",
        )
        assert r_shuffled.findings == r_base.findings
        assert dump_report(r_shuffled) == base_dump


def test_minimal_report_fixture_roundtrip() -> None:
    """Verify fixtures/reports/minimal.json exists, parses, and round-trips byte-stably."""
    assert REPORT_FIXTURE_PATH.is_file(), f"Fixture missing at {REPORT_FIXTURE_PATH}"
    fixture_text = REPORT_FIXTURE_PATH.read_text(encoding="utf-8")
    report = parse_report(fixture_text)

    assert report.schema_version == "sesslint.report/v1"
    assert report.session_id == "session-minimal-001"
    assert report.assurance == "A1"
    assert len(report.findings) == 2
    assert report.counts.total == 2
    assert report.counts.by_severity["error"] == 2

    # Byte stability across dump -> parse -> dump
    dumped = dump_report(report)
    reparsed = parse_report(dumped)
    redumped = dump_report(reparsed)
    assert dumped == redumped


def test_report_schema_anti_drift() -> None:
    """Verify committed JSON Schema matches Report model properties and enums."""
    assert get_report_schema_path().is_file()
    schema = load_report_schema()
    assert schema["$id"] == "https://sesslint.dev/schemas/sesslint.report/v1"
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["additionalProperties"] is False

    assert set(schema["required"]) == REQUIRED_REPORT_FIELDS
    assert set(schema["properties"].keys()) == KNOWN_REPORT_FIELDS

    assurance_enum = set(schema["properties"]["assurance"]["enum"])
    assert assurance_enum == VALID_ASSURANCE_LEVELS

    counts_schema = schema["properties"]["counts"]
    assert set(counts_schema["required"]) == {"by_code", "by_severity", "total"}
    sev_schema = counts_schema["properties"]["by_severity"]
    assert set(sev_schema["required"]) == set(REQUIRED_SEVERITIES)


def test_parse_report_unknown_field_raises_sl302() -> None:
    """Verify unknown top-level field in report raises UnknownFieldError (SL302)."""
    f = _make_sample_finding()
    rep = build_report(
        session_id="sess-1",
        source_fingerprint="fp-1",
        tool_version="0.1.0",
        findings=[f],
        assurance="A1",
        limitation="Some limitation",
    )
    d = rep.to_dict()
    d["rogue_field"] = "unexpected"

    with pytest.raises(UnknownFieldError) as exc:
        parse_report(d)
    assert exc.value.reason_code == "SL302"
    assert "rogue_field" in str(exc.value)


def test_parse_report_unsupported_version_raises_sl301() -> None:
    """Verify unsupported report schema version raises VersionError (SL301)."""
    f = _make_sample_finding()
    rep = build_report(
        session_id="sess-1",
        source_fingerprint="fp-1",
        tool_version="0.1.0",
        findings=[f],
        assurance="A1",
        limitation="Some limitation",
    )
    d = rep.to_dict()
    d["schema_version"] = "sesslint.report/v99"

    with pytest.raises(VersionError) as exc:
        parse_report(d)
    assert exc.value.reason_code == "SL301"


def test_enforce_content_free_report_catches_smuggled_payload() -> None:
    """Adversarial test: finding message smuggling payload text is caught by enforcer."""
    f_smuggle = _make_sample_finding(
        code=SL001,
        sev=Severity.ERROR,
        msg_tpl="Invoice line defect: Filament invoice 1234",
    )
    report = build_report(
        session_id="sess-1",
        source_fingerprint="fp-1",
        tool_version="0.1.0",
        findings=[f_smuggle],
        assurance="A1",
        limitation="Some limitation",
    )

    # Enforce with matching payload sample raises ContentLeakError
    with pytest.raises(ContentLeakError) as exc:
        enforce_content_free(report, forbidden_substrings=["Filament invoice 1234"])
    assert "Forbidden payload text 'Filament invoice 1234'" in str(exc.value)

    # Case-insensitive match also raises
    with pytest.raises(ContentLeakError):
        enforce_content_free(report, forbidden_substrings=["filament invoice 1234"])

    # Disjoint sample does not raise
    enforce_content_free(report, forbidden_substrings=["completely unrelated string"])


def test_enforce_content_free_report_catches_intrinsic_credentials() -> None:
    """Verify intrinsic credential leaks in session_id or limitation raise ContentLeakError."""
    f = _make_sample_finding()
    report_bad_lim = build_report(
        session_id="sess-1",
        source_fingerprint="fp-1",
        tool_version="0.1.0",
        findings=[f],
        assurance="A1",
        limitation="Valid until user@company.com email mentioned",
    )
    with pytest.raises(ContentLeakError, match="Intrinsic content leak"):
        enforce_content_free(report_bad_lim)


def test_unicode_session_id_support() -> None:
    """Verify Unicode session IDs serialize and deserialize cleanly without escaping."""
    unicode_id = "sess-ünicöde-測試-🚀"
    f = _make_sample_finding()
    report = build_report(
        session_id=unicode_id,
        source_fingerprint="fp-uni",
        tool_version="0.1.0",
        findings=[f],
        assurance="A1",
        limitation="Unicode session ID verification",
    )

    dumped = dump_report(report)
    assert unicode_id in dumped
    parsed = parse_report(dumped)
    assert parsed.session_id == unicode_id


def test_large_findings_performance() -> None:
    """Verify building report with 10,000 findings finishes in under 1 second."""
    source = SourceRef(path="large.jsonl", line=1)
    findings = [
        make_finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message_template="Large scale defect",
            source=source,
            related_ids=(f"rel-{i % 50}",),
        )
        for i in range(10_000)
    ]

    t0 = time.perf_counter()
    report = build_report(
        session_id="sess-large",
        source_fingerprint="fp-large",
        tool_version="0.1.0",
        findings=findings,
        assurance="A1",
        limitation="High-scale benchmark test",
    )
    elapsed = time.perf_counter() - t0

    assert report.counts.total == 10_000
    assert report.counts.by_code["SL001"] == 10_000
    assert elapsed < 1.0, f"10k findings took {elapsed:.2f}s, expected < 1.0s"


def test_a0_unreadable_invariant_documented_and_asserted() -> None:
    """Verify A0 unreadable level accepts findings while requiring explicit limitation."""
    f_unreadable = _make_sample_finding(
        code=SL001,
        sev=Severity.FATAL,
        rep=Repairability.UNSUPPORTED,
        msg_tpl="Catastrophic encoding failure on line 1",
    )
    report = build_report(
        session_id="sess-unreadable",
        source_fingerprint="fp-unreadable",
        tool_version="0.1.0",
        findings=[f_unreadable],
        assurance="A0",
        limitation=ASSURANCE_LIMITATIONS["A0"],
    )
    assert report.assurance == "A0"
    assert report.limitation == "No structural conclusion."


def test_report_counts_mismatch_in_dataclass_raises() -> None:
    """Verify Report constructor rejects counts.total != len(findings)."""
    f = _make_sample_finding()
    bad_counts = Counts(
        by_severity={"fatal": 0, "error": 1, "warning": 0, "info": 0},
        by_code={"SL001": 1},
        total=99,
    )
    with pytest.raises(SchemaError, match="Counts.total .* does not match findings count"):
        Report(
            schema_version=REPORT_SCHEMA_VERSION,
            session_id="sess-1",
            source_fingerprint="fp-1",
            tool_version="0.1.0",
            findings=(f,),
            counts=bad_counts,
            assurance="A1",
            limitation="Mismatch test",
        )


def test_tool_version_variance_affects_dump_not_counts() -> None:
    """Verify tool_version differences change report bytes but preserve identical counts."""
    f = _make_sample_finding()
    r1 = build_report(
        session_id="sess-1",
        source_fingerprint="fp-1",
        tool_version="0.1.0",
        findings=[f],
        assurance="A1",
        limitation="Tool version test",
    )
    r2 = build_report(
        session_id="sess-1",
        source_fingerprint="fp-1",
        tool_version="0.2.0",
        findings=[f],
        assurance="A1",
        limitation="Tool version test",
    )
    assert r1.counts == r2.counts
    assert dump_report(r1) != dump_report(r2)


def test_schema_loader_file_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify load_report_schema raises FileNotFoundError when schema file is missing."""
    monkeypatch.setattr(
        "sesslint.report.get_report_schema_path",
        lambda: Path("/nonexistent/sesslint.report.v1.json"),
    )
    with pytest.raises(FileNotFoundError):
        load_report_schema()


def test_counts_model_validation_errors() -> None:
    """Verify Counts __post_init__ strictly rejects invalid types and negative counts."""
    with pytest.raises(SchemaError, match="Counts.total must be a non-negative integer"):
        Counts(by_severity={"fatal": 0, "error": 0, "warning": 0, "info": 0}, by_code={}, total=-1)

    with pytest.raises(SchemaError, match="Counts.total must be a non-negative integer"):
        Counts(
            by_severity={"fatal": 0, "error": 0, "warning": 0, "info": 0},
            by_code={},
            total=True,
        )

    with pytest.raises(SchemaError, match="Counts.by_severity must be a Mapping"):
        Counts(by_severity="not-a-map", by_code={}, total=0)  # type: ignore[arg-type]

    with pytest.raises(
        SchemaError, match="Counts.by_severity\\['error'\\] must be non-negative int"
    ):
        Counts(
            by_severity={"fatal": 0, "error": -1, "warning": 0, "info": 0},
            by_code={},
            total=0,
        )

    with pytest.raises(SchemaError, match="Counts.by_code must be a Mapping"):
        Counts(
            by_severity={"fatal": 0, "error": 0, "warning": 0, "info": 0},
            by_code=123,  # type: ignore[arg-type]
            total=0,
        )

    with pytest.raises(SchemaError, match="Counts.by_code key must be str"):
        Counts(
            by_severity={"fatal": 0, "error": 0, "warning": 0, "info": 0},
            by_code={123: 1},  # type: ignore[dict-item]
            total=0,
        )

    with pytest.raises(SchemaError, match="Counts.by_code\\['SL001'\\] must be non-negative int"):
        Counts(
            by_severity={"fatal": 0, "error": 0, "warning": 0, "info": 0},
            by_code={"SL001": -5},
            total=0,
        )


def test_report_model_validation_errors() -> None:
    """Verify Report constructor rejects invalid schema_version, empty IDs, or bad types."""
    f = _make_sample_finding()
    valid_counts = Counts(
        by_severity={"fatal": 0, "error": 1, "warning": 0, "info": 0},
        by_code={"SL001": 1},
        total=1,
    )

    with pytest.raises(VersionError, match="Report.schema_version must be"):
        Report(
            schema_version="sesslint.report/v2",  # type: ignore[arg-type]
            session_id="sess-1",
            source_fingerprint="fp-1",
            tool_version="0.1.0",
            findings=(f,),
            counts=valid_counts,
            assurance="A1",
            limitation="Test",
        )

    with pytest.raises(SchemaError, match="Report.session_id must be a non-empty string"):
        Report(
            schema_version=REPORT_SCHEMA_VERSION,
            session_id="   ",
            source_fingerprint="fp-1",
            tool_version="0.1.0",
            findings=(f,),
            counts=valid_counts,
            assurance="A1",
            limitation="Test",
        )

    with pytest.raises(SchemaError, match="Report.source_fingerprint must be a non-empty string"):
        Report(
            schema_version=REPORT_SCHEMA_VERSION,
            session_id="sess-1",
            source_fingerprint="",
            tool_version="0.1.0",
            findings=(f,),
            counts=valid_counts,
            assurance="A1",
            limitation="Test",
        )

    with pytest.raises(SchemaError, match="Report.tool_version must be a non-empty string"):
        Report(
            schema_version=REPORT_SCHEMA_VERSION,
            session_id="sess-1",
            source_fingerprint="fp-1",
            tool_version="",
            findings=(f,),
            counts=valid_counts,
            assurance="A1",
            limitation="Test",
        )

    with pytest.raises(AssuranceError, match="Report.assurance must be one of"):
        Report(
            schema_version=REPORT_SCHEMA_VERSION,
            session_id="sess-1",
            source_fingerprint="fp-1",
            tool_version="0.1.0",
            findings=(f,),
            counts=valid_counts,
            assurance="INVALID",  # type: ignore[arg-type]
            limitation="Test",
        )

    with pytest.raises(SchemaError, match="Report.findings must be a tuple"):
        Report(
            schema_version=REPORT_SCHEMA_VERSION,
            session_id="sess-1",
            source_fingerprint="fp-1",
            tool_version="0.1.0",
            findings=[f],  # type: ignore[arg-type]
            counts=valid_counts,
            assurance="A1",
            limitation="Test",
        )

    with pytest.raises(SchemaError, match="Report.findings\\[0\\] must be a Finding instance"):
        Report(
            schema_version=REPORT_SCHEMA_VERSION,
            session_id="sess-1",
            source_fingerprint="fp-1",
            tool_version="0.1.0",
            findings=("not-a-finding",),  # type: ignore[arg-type]
            counts=Counts(
                by_severity={"fatal": 0, "error": 0, "warning": 0, "info": 0}, by_code={}, total=1
            ),
            assurance="A1",
            limitation="Test",
        )

    with pytest.raises(SchemaError, match="Report.counts must be a Counts instance"):
        Report(
            schema_version=REPORT_SCHEMA_VERSION,
            session_id="sess-1",
            source_fingerprint="fp-1",
            tool_version="0.1.0",
            findings=(f,),
            counts="not-counts",  # type: ignore[arg-type]
            assurance="A1",
            limitation="Test",
        )


def test_build_report_argument_validation() -> None:
    """Verify build_report rejects invalid non-empty string arguments."""
    f = _make_sample_finding()
    with pytest.raises(SchemaError, match="session_id must be a non-empty string"):
        build_report(
            session_id="",
            source_fingerprint="fp-1",
            tool_version="0.1.0",
            findings=[f],
            assurance="A1",
            limitation="Test",
        )

    with pytest.raises(SchemaError, match="source_fingerprint must be a non-empty string"):
        build_report(
            session_id="sess-1",
            source_fingerprint="",
            tool_version="0.1.0",
            findings=[f],
            assurance="A1",
            limitation="Test",
        )

    with pytest.raises(SchemaError, match="tool_version must be a non-empty string"):
        build_report(
            session_id="sess-1",
            source_fingerprint="fp-1",
            tool_version="",
            findings=[f],
            assurance="A1",
            limitation="Test",
        )


def test_dump_report_type_error() -> None:
    """Verify dump_report raises TypeError when passed a non-Report object."""
    with pytest.raises(TypeError, match="Expected Report instance"):
        dump_report({"not": "a report"})  # type: ignore[arg-type]


def test_parse_report_error_cases() -> None:
    """Verify parse_report error paths for malformed inputs."""
    with pytest.raises(SchemaError, match="Malformed JSON in report"):
        parse_report("not valid json {")

    with pytest.raises(SchemaError, match="Report must be a Mapping or JSON string"):
        parse_report(123)  # type: ignore[arg-type]

    with pytest.raises(SchemaError, match="Report root must be a mapping"):
        parse_report("[]")

    # Missing required field
    f = _make_sample_finding()
    rep = build_report(
        session_id="sess-1",
        source_fingerprint="fp-1",
        tool_version="0.1.0",
        findings=[f],
        assurance="A1",
        limitation="Test",
    )
    d = rep.to_dict()
    del d["session_id"]
    with pytest.raises(SchemaError, match="Missing required field in report: 'session_id'"):
        parse_report(d)

    # findings not a list
    d2 = rep.to_dict()
    d2["findings"] = "not-a-list"
    with pytest.raises(SchemaError, match="findings must be a list or tuple"):
        parse_report(d2)

    # counts not a mapping
    d3 = rep.to_dict()
    d3["counts"] = "not-a-map"
    with pytest.raises(SchemaError, match="counts must be a mapping"):
        parse_report(d3)

    # counts missing required key
    d4 = rep.to_dict()
    del d4["counts"]["total"]
    with pytest.raises(SchemaError, match="Missing required field in counts: 'total'"):
        parse_report(d4)


def test_enforce_content_free_report_all_locations() -> None:
    """Verify enforce_content_free checks finding path, record_id, and related_ids."""
    f = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Normal message",
        source=SourceRef(path="secret_project_contract.jsonl", line=1, record_id="rec_invoice_99"),
        related_ids=("rel_secret_payment",),
    )
    rep = build_report(
        session_id="sess-1",
        source_fingerprint="fp-1",
        tool_version="0.1.0",
        findings=[f],
        assurance="A1",
        limitation="Test",
    )

    # Leak in path
    with pytest.raises(ContentLeakError, match="Forbidden payload text 'secret_project_contract'"):
        enforce_content_free(rep, forbidden_substrings=["secret_project_contract"])

    # Leak in record_id
    with pytest.raises(ContentLeakError, match="Forbidden payload text 'rec_invoice_99'"):
        enforce_content_free(rep, forbidden_substrings=["rec_invoice_99"])

    # Leak in related_ids
    with pytest.raises(ContentLeakError, match="Forbidden payload text 'rel_secret_payment'"):
        enforce_content_free(rep, forbidden_substrings=["rel_secret_payment"])

    # Invalid artifact type
    with pytest.raises(TypeError, match="Expected Report or RepairManifest"):
        enforce_content_free("not-an-artifact")  # type: ignore[arg-type]


def test_get_report_schema_path_prefix_resolution(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Verify get_report_schema_path resolves via sys.prefix when dev_path does not exist."""
    fake_share = tmp_path / "share" / "sesslint" / "schemas"
    fake_share.mkdir(parents=True, exist_ok=True)
    fake_schema = fake_share / "sesslint.report.v1.json"
    fake_schema.write_text("{}", encoding="utf-8")

    monkeypatch.setattr("sys.prefix", str(tmp_path))
    monkeypatch.setattr(
        "sesslint.report.Path.is_file",
        lambda self: str(self) == str(fake_schema),
    )

    resolved = get_report_schema_path()
    assert resolved == fake_schema


def test_parse_report_invalid_assurance_and_limitation() -> None:
    """Verify parse_report rejects invalid assurance levels and missing/empty limitation."""
    f = _make_sample_finding()
    rep = build_report(
        session_id="sess-1",
        source_fingerprint="fp-1",
        tool_version="0.1.0",
        findings=[f],
        assurance="A1",
        limitation="Valid limitation",
    )
    d = rep.to_dict()
    d["assurance"] = "INVALID"
    with pytest.raises(AssuranceError, match="Invalid assurance level"):
        parse_report(d)

    d2 = rep.to_dict()
    d2["limitation"] = ""
    with pytest.raises(AssuranceError, match="Report limitation must be a non-empty string"):
        parse_report(d2)

    d3 = rep.to_dict()
    d3["limitation"] = 123
    with pytest.raises(AssuranceError, match="Report limitation must be a non-empty string"):
        parse_report(d3)


def test_get_schema_paths_fallback_when_neither_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify get_report_schema_path and get_manifest_schema_path return dev_path fallback."""
    from sesslint.report import get_manifest_schema_path

    monkeypatch.setattr("sesslint.report.Path.is_file", lambda self: False)
    assert get_report_schema_path().name == "sesslint.report.v1.json"
    assert get_manifest_schema_path().name == "sesslint.repair-manifest.v1.json"


def test_enforce_content_free_source_fingerprint_and_tool_version_leaks() -> None:
    """Verify enforce_content_free detects leaks in source_fingerprint and tool_version."""
    f = _make_sample_finding()
    r_leak_fp = build_report(
        session_id="sess-1",
        source_fingerprint="leak_invoice_999",
        tool_version="0.1.0",
        findings=[f],
        assurance="A1",
        limitation="Limitation test",
    )
    with pytest.raises(ContentLeakError, match="Forbidden payload text 'leak_invoice_999'"):
        enforce_content_free(r_leak_fp, forbidden_substrings=["leak_invoice_999"])

    r_leak_ver = build_report(
        session_id="sess-1",
        source_fingerprint="fp-1",
        tool_version="0.1.0-leak_token_abc",
        findings=[f],
        assurance="A1",
        limitation="Limitation test",
    )
    with pytest.raises(ContentLeakError, match="Forbidden payload text 'leak_token_abc'"):
        enforce_content_free(r_leak_ver, forbidden_substrings=["leak_token_abc"])


def test_enforce_content_free_handles_none_forbidden_substrings() -> None:
    """Verify enforce_content_free gracefully accepts forbidden_substrings=None."""
    f = _make_sample_finding()
    r = build_report(
        session_id="sess-1",
        source_fingerprint="fp-1",
        tool_version="0.1.0",
        findings=[f],
        assurance="A1",
        limitation="Limitation test",
    )
    enforce_content_free(r, forbidden_substrings=None)


def test_parse_report_strict_string_field_validation() -> None:
    """Verify parse_report rejects non-string types for string fields instead of coercing."""
    f = _make_sample_finding()
    rep = build_report(
        session_id="sess-1",
        source_fingerprint="fp-1",
        tool_version="0.1.0",
        findings=[f],
        assurance="A1",
        limitation="Valid limitation",
    )

    d_bad_sess = rep.to_dict()
    d_bad_sess["session_id"] = 12345
    with pytest.raises(SchemaError, match="Report.session_id must be a non-empty string"):
        parse_report(d_bad_sess)

    d_bad_fp = rep.to_dict()
    d_bad_fp["source_fingerprint"] = ["invalid", "type"]
    with pytest.raises(SchemaError, match="Report.source_fingerprint must be a non-empty string"):
        parse_report(d_bad_fp)

    d_bad_ver = rep.to_dict()
    d_bad_ver["tool_version"] = 1.0
    with pytest.raises(SchemaError, match="Report.tool_version must be a non-empty string"):
        parse_report(d_bad_ver)


def test_parse_report_counts_unknown_fields_and_severities() -> None:
    """Verify parse_report enforces counts schema with additionalProperties: false."""
    f = _make_sample_finding()
    rep = build_report(
        session_id="sess-1",
        source_fingerprint="fp-1",
        tool_version="0.1.0",
        findings=[f],
        assurance="A1",
        limitation="Valid limitation",
    )

    # Unknown field in counts
    d_extra_counts = rep.to_dict()
    d_extra_counts["counts"]["rogue_counts_field"] = 99
    with pytest.raises(UnknownFieldError) as exc1:
        parse_report(d_extra_counts)
    assert exc1.value.reason_code == "SL302"
    assert "rogue_counts_field" in str(exc1.value)

    # Unknown severity in by_severity
    d_extra_sev = rep.to_dict()
    d_extra_sev["counts"]["by_severity"]["critical"] = 5
    with pytest.raises(UnknownFieldError) as exc2:
        parse_report(d_extra_sev)
    assert exc2.value.reason_code == "SL302"
    assert "critical" in str(exc2.value)

    # Missing required severity in by_severity
    d_missing_sev = rep.to_dict()
    del d_missing_sev["counts"]["by_severity"]["fatal"]
    with pytest.raises(SchemaError, match="Missing required severity in counts.by_severity"):
        parse_report(d_missing_sev)


def test_report_and_parse_report_reject_counts_mismatch_with_findings() -> None:
    """Verify Report constructor and parse_report reject counts contradicting findings."""
    f = _make_sample_finding(code=SL001, sev=Severity.ERROR)

    # Mismatch in by_severity (claims fatal instead of error)
    bad_sev_counts = Counts(
        by_severity={"fatal": 1, "error": 0, "warning": 0, "info": 0},
        by_code={"SL001": 1},
        total=1,
    )
    with pytest.raises(SchemaError, match="Counts.by_severity .* does not match"):
        Report(
            schema_version=REPORT_SCHEMA_VERSION,
            session_id="sess-1",
            source_fingerprint="fp-1",
            tool_version="0.1.0",
            findings=(f,),
            counts=bad_sev_counts,
            assurance="A1",
            limitation="Test",
        )

    # Mismatch in by_code (claims SL002 instead of SL001)
    bad_code_counts = Counts(
        by_severity={"fatal": 0, "error": 1, "warning": 0, "info": 0},
        by_code={"SL002": 1},
        total=1,
    )
    with pytest.raises(SchemaError, match="Counts.by_code .* does not match"):
        Report(
            schema_version=REPORT_SCHEMA_VERSION,
            session_id="sess-1",
            source_fingerprint="fp-1",
            tool_version="0.1.0",
            findings=(f,),
            counts=bad_code_counts,
            assurance="A1",
            limitation="Test",
        )


def test_counts_rejects_unknown_severity() -> None:
    """Verify Counts model rejects unknown severity keys in by_severity."""
    with pytest.raises(SchemaError, match="Counts.by_severity contains unknown severity"):
        Counts(
            by_severity={"fatal": 0, "error": 0, "warning": 0, "info": 0, "bogus": 1},
            by_code={},
            total=0,
        )


def test_parse_report_counts_subfield_types() -> None:
    """Verify parse_report validates types of counts.by_severity, counts.by_code, counts.total."""
    f = _make_sample_finding()
    rep = build_report(
        session_id="sess-1",
        source_fingerprint="fp-1",
        tool_version="0.1.0",
        findings=[f],
        assurance="A1",
        limitation="Valid limitation",
    )

    d_bad_by_sev = rep.to_dict()
    d_bad_by_sev["counts"]["by_severity"] = "not-a-mapping"
    with pytest.raises(SchemaError, match="counts.by_severity must be a mapping"):
        parse_report(d_bad_by_sev)

    d_bad_by_code = rep.to_dict()
    d_bad_by_code["counts"]["by_code"] = "not-a-mapping"
    with pytest.raises(SchemaError, match="counts.by_code must be a mapping"):
        parse_report(d_bad_by_code)

    d_bad_total = rep.to_dict()
    d_bad_total["counts"]["total"] = -1
    with pytest.raises(SchemaError, match="counts.total must be a non-negative integer"):
        parse_report(d_bad_total)

    d_bad_total_bool = rep.to_dict()
    d_bad_total_bool["counts"]["total"] = True
    with pytest.raises(SchemaError, match="counts.total must be a non-negative integer"):
        parse_report(d_bad_total_bool)
