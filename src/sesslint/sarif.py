"""SARIF 2.1.0 rendering for SessLint findings (CI code-scanning interop).

Produces a minimal, deterministic SARIF document consumable by GitHub code
scanning and other SARIF viewers. Invariants preserved:

- Content-free: only finding codes, severities, content-free messages, paths,
  line numbers, and fingerprints are emitted — never session payload content.
- Deterministic: rules sorted by id, results follow the finding order the
  report already fixes (FR-094), keys emitted via ``sort_keys=True``.
- Offline: ``helpUri`` values are documentation links only; nothing is
  fetched at runtime.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any, Final

from sesslint.codes import CODE_REGISTRY, Severity
from sesslint.finding import Finding
from sesslint.report import minimize_path
from sesslint.scan import ScanReport

SARIF_VERSION: Final[str] = "2.1.0"
SARIF_SCHEMA: Final[str] = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_INFORMATION_URI: Final[str] = "https://github.com/HPNChanel/sesslint"
_RULE_HELP_BASE: Final[str] = f"{TOOL_INFORMATION_URI}/blob/main/docs/codes"

_LEVEL_MAP: Final[dict[Severity, str]] = {
    Severity.FATAL: "error",
    Severity.ERROR: "error",
    Severity.WARNING: "warning",
    Severity.INFO: "note",
}


def _rule_objects() -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for code in sorted(CODE_REGISTRY):
        info = CODE_REGISTRY[code]
        rules.append(
            {
                "id": info.code,
                "name": info.name,
                "shortDescription": {"text": info.summary},
                "defaultConfiguration": {
                    "level": _LEVEL_MAP[info.default_severity],
                },
                "helpUri": f"{_RULE_HELP_BASE}/{info.code}.md",
                "properties": {
                    "category": info.category,
                    "repairability": info.default_repairability.value,
                },
            }
        )
    return rules


def _artifact_uri(path: str) -> str:
    """Render a finding path for SARIF without leaking absolute host paths.

    Relative paths pass through verbatim (forward slashes) — code scanning
    maps results to repository files by relative URI. Absolute paths are
    minimized: ``~/``-relative under home, ``.._<hash>/name`` elsewhere —
    a SARIF document is shareable and must not embed the operator's host
    filesystem layout.
    """
    p_str = str(path).replace("\\", "/")
    is_abs = p_str.startswith("/") or (len(p_str) > 1 and p_str[1] == ":") or p_str.startswith("~/")
    if is_abs:
        return minimize_path(p_str)
    return p_str


def _result_object(finding: Finding) -> dict[str, Any]:
    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": _artifact_uri(finding.source.path)},
        }
    }
    if finding.source.line is not None:
        location["physicalLocation"]["region"] = {"startLine": finding.source.line}

    return {
        "ruleId": finding.code,
        "level": _LEVEL_MAP[finding.severity],
        "message": {"text": finding.message},
        "locations": [location],
        "partialFingerprints": {
            "sesslint/finding-fingerprint": finding.fingerprint,
        },
    }


def build_sarif(
    findings: Sequence[Finding],
    *,
    tool_version: str,
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document from SessLint findings."""
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SessLint",
                        "version": tool_version,
                        "informationUri": TOOL_INFORMATION_URI,
                        "rules": _rule_objects(),
                    }
                },
                "results": [_result_object(f) for f in findings],
            }
        ],
    }


def render_sarif(
    findings: Sequence[Finding],
    *,
    tool_version: str,
) -> str:
    """Render findings as a deterministic SARIF JSON string."""
    return json.dumps(build_sarif(findings, tool_version=tool_version), indent=2, sort_keys=True)


def scan_report_sarif(scan_report: ScanReport, *, tool_version: str) -> str:
    """Render a ScanReport's findings as a SARIF JSON string."""
    findings: list[Finding] = []
    for file_result in scan_report.files:
        findings.extend(file_result.findings)
    return render_sarif(findings, tool_version=tool_version)
