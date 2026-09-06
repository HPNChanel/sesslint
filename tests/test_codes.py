"""Tests for detector reason codes registry (TASK-003)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.codes import (
    ALL_CODES,
    CODE_REGISTRY,
    Code,
    Repairability,
    Severity,
    get_code_info,
    is_valid_code,
)
from sesslint.errors import FindingError

EXPECTED_20_CODES: frozenset[str] = frozenset(
    {
        "SL001",
        "SL002",
        "SL003",
        "SL004",
        "SL005",
        "SL006",
        "SL007",
        "SL101",
        "SL102",
        "SL103",
        "SL104",
        "SL105",
        "SL106",
        "SL107",
        "SL108",
        "SL201",
        "SL202",
        "SL203",
        "SL301",
        "SL302",
    }
)

DEMAND_VERBATIM_NAMES: dict[str, str] = {
    "SL001": "Malformed record",
    "SL002": "Torn terminal record",
    "SL003": "Duplicate event ID",
    "SL004": "Missing parent",
    "SL005": "Parent cycle",
    "SL006": "Disconnected branch",
    "SL007": "Ambiguous session head",
    "SL101": "Orphan tool result",
    "SL102": "Dangling tool call",
    "SL103": "Reused tool-call ID",
    "SL104": "Multiple tool results",
    "SL105": "Tool result precedes call",
    "SL106": "Cross-branch tool pairing",
    "SL107": "Provider adjacency violation",
    "SL108": "Compaction split pair",
    "SL201": "Checkpoint/history divergence",
    "SL202": "Accepted terminal output not durable",
    "SL203": "Unknown side-effect state",
    "SL301": "Unsupported format version",
    "SL302": "Unknown critical record",
}

DEMAND_VERBATIM_SUMMARIES: dict[str, str] = {
    "SL001": "Report record ordinal plus line and byte offset where available.",
    "SL002": (
        "Distinguish an incomplete final append from malformed data followed by later records."
    ),
    "SL003": "Distinguish byte-identical duplicates from conflicting duplicates.",
    "SL004": "Identify the missing reference and affected descendants.",
    "SL005": "Emit a deterministic cycle path.",
    "SL006": "Report unreachable components without assuming they should be merged.",
    "SL007": "Report multiple plausible terminal heads.",
    "SL101": "Result references no call in the permitted branch and replay window.",
    "SL102": "Required result is absent before the next disallowed boundary.",
    "SL103": "Same ID maps to non-equivalent calls.",
    "SL104": "More than one result maps to one call.",
    "SL105": "Ordering is structurally impossible under the selected profile.",
    "SL106": "Call and result belong to incompatible interaction or agent scopes.",
    "SL107": "Pair exists but does not satisfy the selected provider’s placement rule.",
    "SL108": "A retained compaction boundary separates a required atomic pair.",
    "SL201": "Serialized continuation state and durable records disagree.",
    "SL202": "Runtime state indicates accepted output that the history cannot recover.",
    "SL203": "Repair would require assuming whether execution occurred.",
    "SL301": "Adapter recognizes the family but not the version safely enough to repair.",
    "SL302": "Unrecognized record participates in identity, parentage, pairing, or continuation.",
}


def test_registry_has_exact_20_codes() -> None:
    """Verify registry contains exactly the 20 codes from DEMAND.md, no more, no less."""
    assert ALL_CODES == EXPECTED_20_CODES
    assert frozenset(CODE_REGISTRY.keys()) == EXPECTED_20_CODES
    assert len(CODE_REGISTRY) == 20
    assert len(Code) == 20


def test_code_enum_matches_registry() -> None:
    """Verify Code enum values match registry keys."""
    enum_values = {e.value for e in Code}
    assert enum_values == EXPECTED_20_CODES


def test_verbatim_demand_names_and_summaries() -> None:
    """Verify all 20 code names and summaries match DEMAND.md verbatim."""
    for code, expected_name in DEMAND_VERBATIM_NAMES.items():
        info = get_code_info(code)
        assert info.name == expected_name
        assert info.summary == DEMAND_VERBATIM_SUMMARIES[code]
        assert isinstance(info.default_severity, Severity)
        assert isinstance(info.default_repairability, Repairability)
        assert bool(info.category)
        assert bool(info.override_policy)


def test_is_valid_code() -> None:
    """Verify is_valid_code returns True for registered codes and False otherwise."""
    for code in EXPECTED_20_CODES:
        assert is_valid_code(code) is True

    assert is_valid_code("SL000") is False
    assert is_valid_code("SL999") is False
    assert is_valid_code("INVALID") is False
    assert is_valid_code("") is False


def test_get_code_info_unknown_raises_finding_error() -> None:
    """Verify get_code_info raises FindingError (which is a ValueError) for unknown codes."""
    with pytest.raises(FindingError) as exc_info:
        get_code_info("NONEXISTENT")
    assert "Unknown detector code" in str(exc_info.value)
    # Proves it is also a ValueError subclass
    assert isinstance(exc_info.value, ValueError)


def test_no_vendor_strings_in_codes_module() -> None:
    """Verify codes.py contains no vendor-specific identifiers or terms."""
    codes_path = Path(__file__).resolve().parent.parent / "src" / "sesslint" / "codes.py"
    text = codes_path.read_text(encoding="utf-8").lower()
    vendor_terms = ["anthropic", "claude", "openai", "copilot", "chatgpt"]
    for term in vendor_terms:
        assert term not in text, f"Found forbidden vendor term '{term}' in codes.py"


def test_codes_and_taxonomies_match_finding_schema_anti_drift() -> None:
    """Verify JSON schema and codes.py enums are in exact lockstep (anti-drift check)."""
    schema_path = Path(__file__).resolve().parent.parent / "schemas" / "sesslint.finding.v1.json"
    assert schema_path.is_file(), f"Finding schema not found at {schema_path}"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    # Codes enum anti-drift
    schema_codes = set(schema["properties"]["code"]["enum"])
    assert schema_codes == EXPECTED_20_CODES
    assert schema_codes == ALL_CODES

    # Severity enum anti-drift
    schema_severities = set(schema["properties"]["severity"]["enum"])
    expected_severities = {s.value for s in Severity}
    assert schema_severities == expected_severities

    # Repairability enum anti-drift
    schema_repairabilities = set(schema["properties"]["repairability"]["enum"])
    expected_repairabilities = {r.value for r in Repairability}
    assert schema_repairabilities == expected_repairabilities
