"""Tests for scan-report JSON schema conformance (T-11)."""

from __future__ import annotations

import json
from typing import Any

from sesslint.codes import ALL_CODES, SL001, Repairability, Severity
from sesslint.finding import SourceRef, make_finding
from sesslint.scan import (
    FileResult,
    ScanReport,
    ScanTotals,
    get_scan_schema_path,
    load_scan_schema,
)

VALID_VERDICTS = ("healthy", "invalid", "unsupported", "unreadable", "skipped")


def _validate_scan_dict_strictly(data: dict[str, Any]) -> None:
    """Hand-rolled strict validator conforming to schemas/sesslint.scan-report.v1.json."""
    assert data["schema_version"] == "sesslint.scan-report/v1"
    assert isinstance(data["root_path"], str)

    totals = data["totals"]
    for key in ("healthy", "invalid", "unsupported", "unreadable", "skipped", "total"):
        assert isinstance(totals[key], int) and totals[key] >= 0
    assert totals["total"] == (
        totals["healthy"]
        + totals["invalid"]
        + totals["unsupported"]
        + totals["unreadable"]
        + totals["skipped"]
    )
    if "skipped_reasons" in totals:
        reasons = totals["skipped_reasons"]
        assert isinstance(reasons, dict)
        assert list(reasons) == sorted(reasons)
        assert all(isinstance(k, str) and k for k in reasons)
        assert all(isinstance(v, int) and v >= 1 for v in reasons.values())
        assert sum(reasons.values()) <= totals["skipped"]

    assert isinstance(data["files"], list)
    for f in data["files"]:
        assert isinstance(f["path"], str) and f["path"]
        assert f["verdict"] in VALID_VERDICTS
        assert isinstance(f["error_count"], int) and f["error_count"] >= 0
        assert isinstance(f["warning_count"], int) and f["warning_count"] >= 0
        if "skipped_reason" in f:
            assert isinstance(f["skipped_reason"], str) and f["skipped_reason"]
        for finding in f.get("findings", []):
            assert finding["code"] in ALL_CODES
            assert isinstance(finding["fingerprint"], str) and finding["fingerprint"]
            assert isinstance(finding["severity"], str)
            assert isinstance(finding["repairability"], str)
            assert isinstance(finding["span"]["path"], str) and finding["span"]["path"]


def _sample_report() -> ScanReport:
    finding = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Unreadable file [detail: LIMIT_OR_IO]",
        source=SourceRef(path="bad.jsonl", line=3),
        evidence={"byte_offset": 128},
    )
    files = (
        FileResult(path="good.jsonl", verdict="healthy"),
        FileResult(
            path="bad.jsonl",
            verdict="invalid",
            findings=(finding,),
            error_count=1,
            warning_count=0,
        ),
        FileResult(path="future.json", verdict="unsupported"),
        FileResult(path="binary.dat", verdict="unreadable", error_count=1),
        FileResult(path="huge.jsonl", verdict="skipped", skipped_reason="size-cap"),
    )
    totals = ScanTotals(healthy=1, invalid=1, unsupported=1, unreadable=1, skipped=1)
    return ScanReport(root_path="/tmp/scan-root", totals=totals, files=files)


def test_scan_schema_loads_and_self_consistent() -> None:
    assert get_scan_schema_path().is_file()
    schema = load_scan_schema()
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert set(schema["required"]).issubset(set(schema["properties"].keys()))
    totals = schema["properties"]["totals"]
    assert set(totals["required"]).issubset(set(totals["properties"].keys()))
    file_item = schema["properties"]["files"]["items"]
    assert set(file_item["required"]).issubset(set(file_item["properties"].keys()))
    assert set(file_item["properties"]["verdict"]["enum"]) == set(VALID_VERDICTS)
    finding_item = file_item["properties"]["findings"]["items"]
    assert set(finding_item["properties"]["code"]["enum"]) == set(ALL_CODES)
    assert len(ALL_CODES) == 34


def test_scan_report_dict_validates() -> None:
    _validate_scan_dict_strictly(_sample_report().to_dict())


def test_scan_report_json_round_trip_validates() -> None:
    parsed = json.loads(_sample_report().to_json())
    _validate_scan_dict_strictly(parsed)


def test_scan_report_skipped_reasons_aggregated() -> None:
    files = (
        FileResult(path="a.jsonl", verdict="healthy"),
        FileResult(path="b.jsonl", verdict="skipped", skipped_reason="z-reason"),
        FileResult(path="c.jsonl", verdict="skipped", skipped_reason="a-reason"),
        FileResult(path="d.jsonl", verdict="skipped", skipped_reason="z-reason"),
        FileResult(path="e.jsonl", verdict="skipped"),
    )
    rep = ScanReport(
        root_path="/x",
        totals=ScanTotals(healthy=1, skipped=4),
        files=files,
    )
    assert rep.skipped_reason_totals() == {"a-reason": 1, "z-reason": 2}
    totals = rep.to_dict()["totals"]
    assert totals["skipped_reasons"] == {"a-reason": 1, "z-reason": 2}
    _validate_scan_dict_strictly(rep.to_dict())


def test_scan_report_skipped_reasons_omitted_when_empty() -> None:
    rep = ScanReport(
        root_path="/x",
        totals=ScanTotals(healthy=1),
        files=(FileResult(path="a.jsonl", verdict="healthy"),),
    )
    assert "skipped_reasons" not in rep.to_dict()["totals"]
