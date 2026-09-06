"""Conformance test harness for discovering, running, and asserting fixture test cases."""

from __future__ import annotations

import difflib
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sesslint.canonical import canonical_bytes, to_canonical_json
from sesslint.errors import HeaderMissingError, SchemaError, SesslintError
from sesslint.finding import Finding
from sesslint.io import ReaderLimits, read_header
from sesslint.report import Report, build_report
from sesslint.source import fingerprint_file, guarded_iter_events

TEST_TOOL_VERSION: str = "0.1.0+test"
TEST_ASSURANCE: str = "A1"
TEST_LIMITATION: str = "test-harness-conformance"


@dataclass(frozen=True, slots=True)
class Case:
    """A conformance test case binding an input JSONL session to expected outcomes."""

    name: str
    input_path: Path
    expected_path: Path
    expected: dict[str, Any]


def discover_cases(root: Path = Path("fixtures")) -> list[Case]:
    """Discover all test cases in root by locating paired *.jsonl and *.expected.json files.

    Cases are strictly sorted by case name to guarantee determinism across platforms.

    Args:
        root: Root directory of fixtures.

    Returns:
        Sorted list of Case descriptors.

    Raises:
        FileNotFoundError: If an expected.json file has no corresponding .jsonl input.
    """
    if not root.exists():
        return []

    cases: list[Case] = []
    # Locate all *.expected.json files
    for expected_path in root.rglob("*.expected.json"):
        if not expected_path.is_file():
            continue

        raw_name = expected_path.name[: -len(".expected.json")]
        input_path = expected_path.with_name(f"{raw_name}.jsonl")
        if not input_path.exists():
            raise FileNotFoundError(
                f"Missing input fixture {input_path} for expected file {expected_path}"
            )

        expected_data = json.loads(expected_path.read_text(encoding="utf-8"))
        case_name = str(input_path.relative_to(root).with_suffix("")).replace("\\", "/")

        cases.append(
            Case(
                name=case_name,
                input_path=input_path,
                expected_path=expected_path,
                expected=expected_data,
            )
        )

    # Sort strictly by name for total ordering determinism
    cases.sort(key=lambda c: c.name)
    return cases


def run_case(
    case: Case,
    *,
    tool_version: str = TEST_TOOL_VERSION,
    limits: ReaderLimits | None = None,
) -> Report:
    """Execute a single test case through reader and report builder.

    Args:
        case: The Case descriptor to run.
        tool_version: Tool version string to pin in the report.
        limits: Optional reader limits.

    Returns:
        Constructed Report instance.
    """
    source_fp = fingerprint_file(case.input_path)

    effective_limits = ReaderLimits() if limits is None else limits
    session_id: str
    try:
        header = read_header(case.input_path, limits=effective_limits)
        session_id = header.session_id
    except (HeaderMissingError, SchemaError, SesslintError, OSError):
        fallback_name = case.name.replace("/", "_").replace(".", "_")
        session_id = f"sess_{fallback_name}"

    items = list(guarded_iter_events(case.input_path, limits=effective_limits))
    findings = [it for it in items if isinstance(it, Finding)]

    return build_report(
        session_id=session_id,
        source_fingerprint=source_fp,
        tool_version=tool_version,
        findings=findings,
        assurance="A1",
        limitation=TEST_LIMITATION,
    )


def assert_case(
    case: Case,
    *,
    tool_version: str = TEST_TOOL_VERSION,
    limits: ReaderLimits | None = None,
) -> None:
    """Run a test case and assert actual findings and counts match expected specifications.

    Args:
        case: The Case descriptor to assert.
        tool_version: Tool version string.
        limits: Optional reader limits.

    Raises:
        AssertionError: If actual counts, findings, or report sha256 mismatch with diff.
    """
    report = run_case(case, tool_version=tool_version, limits=limits)

    actual_counts = {
        "total": report.counts.total,
        "by_severity": dict(report.counts.by_severity),
        "by_code": dict(report.counts.by_code),
    }

    actual_findings = [
        {
            "code": f.code,
            "severity": f.severity.value,
            "line": f.source.line,
            "record_id": f.source.record_id,
        }
        for f in report.findings
    ]

    expected_counts = case.expected.get("counts")
    if actual_counts != expected_counts:
        diff = "\n".join(
            difflib.unified_diff(
                json.dumps(expected_counts, indent=2, sort_keys=True).splitlines(),
                json.dumps(actual_counts, indent=2, sort_keys=True).splitlines(),
                fromfile="expected_counts",
                tofile="actual_counts",
                lineterm="",
            )
        )
        raise AssertionError(f"Counts mismatch for case '{case.name}':\n{diff}")

    expected_findings = case.expected.get("findings", [])
    if actual_findings != expected_findings:
        diff = "\n".join(
            difflib.unified_diff(
                json.dumps(expected_findings, indent=2, sort_keys=True).splitlines(),
                json.dumps(actual_findings, indent=2, sort_keys=True).splitlines(),
                fromfile="expected_findings",
                tofile="actual_findings",
                lineterm="",
            )
        )
        raise AssertionError(f"Findings mismatch for case '{case.name}':\n{diff}")

    expected_report_sha = case.expected.get("report_sha256")
    if expected_report_sha:
        actual_report_bytes = canonical_bytes(to_canonical_json(report))
        actual_report_sha = hashlib.sha256(actual_report_bytes).hexdigest()
        if actual_report_sha != expected_report_sha:
            raise AssertionError(
                f"Report SHA-256 mismatch for case '{case.name}':\n"
                f"Expected: {expected_report_sha}\n"
                f"Actual:   {actual_report_sha}"
            )


CASES: list[Case] = discover_cases()
