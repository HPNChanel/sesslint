"""Vendor-to-canonical export for repair enablement (T-12).

Repair operates exclusively on canonical session streams, so vendor sessions
are repair dead-ends. Export bridges that gap: it loads a supported artifact
through the existing adapters and writes a byte-deterministic canonical file
that the repair pipeline accepts.

This is repair-enablement, not migration: single artifact in, single canonical
file out, atomic write, refusals fail closed, and the summary discloses what
the projection dropped (unknown-field counts, finding counts). Exported files
contain session content by design (like repair output); only the printed
summary is content-free.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sesslint.adapters.canonical import dump_canonical, load_canonical
from sesslint.adapters.claude_code import load_claude_code
from sesslint.adapters.detect import (
    FORMAT_CANONICAL,
    FORMAT_CLAUDE_CODE,
    FORMAT_OPENAI_AGENTS,
    resolve_format,
)
from sesslint.adapters.openai_agents import load_openai_agents
from sesslint.atomic import atomic_write_bytes
from sesslint.canonical import SessionEvent
from sesslint.codes import SL302, Severity
from sesslint.errors import SesslintError
from sesslint.finding import Finding
from sesslint.repair.executor import is_live_store_path
from sesslint.report import minimize_path


class ExportRefused(SesslintError):
    """Raised when export pre-flight or input validation fails closed."""

    code: str = "EXPORT_REFUSED"

    def __init__(self, message: str, *, code: str = "EXPORT_REFUSED") -> None:
        super().__init__(message, code=code)


@dataclass(frozen=True, slots=True)
class ExportSummary:
    """Content-free summary of a vendor-to-canonical export."""

    input_path: str
    input_format: str
    output_path: str
    input_sha256: str
    output_sha256: str
    event_count: int
    dropped_unknown_fields: int
    findings_by_severity: Mapping[str, int]

    def to_dict(self) -> dict[str, Any]:
        """Serialize summary to a JSON-compatible dictionary."""
        return {
            "dropped_unknown_fields": self.dropped_unknown_fields,
            "event_count": self.event_count,
            "findings_by_severity": dict(sorted(self.findings_by_severity.items())),
            "input_format": self.input_format,
            "input_path": self.input_path,
            "input_sha256": self.input_sha256,
            "output_path": self.output_path,
            "output_sha256": self.output_sha256,
        }


def export_to_canonical(
    source_path: Path | str,
    output_path: Path | str,
    *,
    format: str | None = None,
) -> ExportSummary:
    """Export a supported session artifact to a canonical file.

    Args:
        source_path: Path to the source session file.
        output_path: Destination path for the canonical file (must not exist).
        format: Format override ('auto', None, or known format name).

    Returns:
        Content-free ExportSummary describing the projection.

    Raises:
        ExportRefused: On pre-flight failure, undetectable format, or fatal input.
        FileNotFoundError: If the source file does not exist.
    """
    src = Path(source_path)
    if not src.is_file():
        raise FileNotFoundError(f"Source file not found: {src}")
    out = Path(output_path)

    if is_live_store_path(out):
        raise ExportRefused(f"Refusing to write to live-store path: {out}")
    if os.path.realpath(src) == os.path.realpath(out):
        raise ExportRefused(f"Output path resolves to the source file: {out}")
    if out.exists():
        raise ExportRefused(f"Output path already exists (refusing to overwrite): {out}")

    resolved_fmt, detection_res, det_findings = resolve_format(format, src)
    if resolved_fmt is None:
        reason = detection_res.reason if detection_res is not None else "unknown"
        raise ExportRefused(f"Format detection failed: {reason}")

    events: Sequence[SessionEvent]
    adapter_findings: Sequence[Finding]
    if resolved_fmt == FORMAT_CANONICAL:
        events, adapter_findings = load_canonical(src)
    elif resolved_fmt == FORMAT_CLAUDE_CODE:
        events, adapter_findings = load_claude_code(src)
    elif resolved_fmt == FORMAT_OPENAI_AGENTS:
        events, adapter_findings = load_openai_agents(src)
    else:
        raise ExportRefused(f"Unsupported format for export: {resolved_fmt}")

    all_findings: list[Finding] = list(det_findings) + list(adapter_findings)
    if any(f.severity in (Severity.FATAL, Severity.ERROR) for f in all_findings):
        raise ExportRefused(
            "Input has fatal or error findings; export refused to prevent "
            "laundering corrupted sessions"
        )
    if len(events) == 0:
        raise ExportRefused("Input contains zero valid events; export refused")

    data = dump_canonical(events, None)
    output_sha256 = atomic_write_bytes(out, data, refuse_paths=[src])
    input_sha256 = hashlib.sha256(src.read_bytes()).hexdigest()

    by_severity: dict[str, int] = {}
    for f in all_findings:
        key = f.severity.value
        by_severity[key] = by_severity.get(key, 0) + 1

    return ExportSummary(
        input_path=minimize_path(src),
        input_format=resolved_fmt,
        output_path=minimize_path(out),
        input_sha256=input_sha256,
        output_sha256=output_sha256,
        event_count=len(events),
        dropped_unknown_fields=sum(1 for f in all_findings if f.code == SL302),
        findings_by_severity=by_severity,
    )


__all__ = [
    "ExportRefused",
    "ExportSummary",
    "export_to_canonical",
]
