"""Self-contained HTML report rendering (ux-reporting T-01).

``check``/``scan --output-format html`` emit a single ``.html`` document a
human can open and share — the shareable artifact for "show my maintainer
what broke" without pasting terminal text.

Invariants preserved:

- Content-free: same fields as the JSON reports — minimized paths, bounded
  identifiers, codes, counts. Never session payload content.
- Deterministic: fixed template, findings follow ``finding_report_sort_key``,
  no timestamps, no random ids — same input produces the same bytes.
- Offline: inline CSS only, no JavaScript, no external assets, fonts, or
  network references — the file is greppable and cannot phone home.
- Bounded: tables are capped at ``MAX_ROWS`` rows with an explicit
  "N more" counter row, mirroring the human output truncation contract.
- Safe: every emitted value passes through ``html.escape`` — bounded
  identifiers are already content-free, escaping is belt-and-suspenders.
"""

from __future__ import annotations

import html
from collections.abc import Mapping
from pathlib import Path
from typing import Final

from sesslint.codes import CODE_REGISTRY
from sesslint.finding import Finding
from sesslint.report import (
    Report,
    finding_report_sort_key,
    get_finding_remediation,
    minimize_path,
)
from sesslint.scan import ScanReport

MAX_ROWS: Final[int] = 500

_CSS: Final[str] = (
    "body{font-family:ui-sans-serif,system-ui,sans-serif;margin:0;background:#f3f4f6;color:#111827}"
    ".wrap{max-width:960px;margin:0 auto;padding:24px}"
    ".banner{border-radius:8px;padding:16px 20px;color:#fff;font-weight:600;font-size:18px}"
    ".ok{background:#047857}.warn{background:#b45309}.err{background:#b91c1c}"
    ".card{background:#fff;border:1px solid #e5e7eb;border-radius:8px;"
    "padding:16px 20px;margin-top:16px}"
    "h2{font-size:14px;margin:0 0 10px;text-transform:uppercase;letter-spacing:.05em;color:#6b7280}"
    "table{width:100%;border-collapse:collapse;font-size:13px}"
    "th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #e5e7eb;vertical-align:top}"
    "th{color:#6b7280;font-size:11px;text-transform:uppercase;letter-spacing:.05em}"
    ".meta{color:#6b7280;font-size:12px;margin-top:4px}"
    ".tag{display:inline-block;border-radius:4px;padding:2px 8px;font-size:12px;font-weight:600}"
    ".t-healthy{background:#d1fae5;color:#065f46}"
    ".t-invalid,.t-unreadable{background:#fee2e2;color:#991b1b}"
    ".t-unsupported{background:#fef3c7;color:#92400e}.t-skipped{background:#e5e7eb;color:#374151}"
    ".sev-error,.sev-fatal{color:#b91c1c;font-weight:600}.sev-warning{color:#b45309;font-weight:600}"
    ".sev-info{color:#1d4ed8}.mono{font-family:ui-monospace,monospace;font-size:12px}"
)


def _esc(value: object) -> str:
    """HTML-escape any emitted value — belt and suspenders on bounded identifiers."""
    return html.escape("" if value is None else str(value), quote=True)


def _page(title: str, body: str) -> str:
    return (
        "<!DOCTYPE html>\n"
        '<html lang="es">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{_esc(title)}</title>\n<style>{_CSS}</style>\n</head>\n"
        f'<body>\n<div class="wrap">\n{body}\n</div>\n</body>\n</html>\n'
    )


def _span(finding: Finding, *, home: Path | None) -> str:
    """Content-free span label: minimized path, optional line and byte offsets."""
    min_path = minimize_path(finding.source.path, home=home)
    span = f"{min_path}:{finding.source.line}" if finding.source.line is not None else min_path
    evidence = finding.evidence if isinstance(finding.evidence, Mapping) else {}
    b_start, b_end = evidence.get("byte_offset"), evidence.get("byte_end")
    if (
        isinstance(b_start, int)
        and not isinstance(b_start, bool)
        and b_start >= 0
        and isinstance(b_end, int)
        and not isinstance(b_end, bool)
        and b_end >= b_start
    ):
        span = f"{span} (bytes {b_start}-{b_end})"
    return span


def render_html(
    report: Report,
    *,
    adapter: str = "canonical",
    profile: str = "neutral",
    home: Path | None = None,
) -> str:
    """Render a single-file check ``Report`` as a standalone HTML document.

    Same content-free fields as the JSON report, byte-deterministic, no
    JavaScript and no external assets — safe to attach to an issue.
    """
    err = report.counts.by_severity.get("error", 0) + report.counts.by_severity.get("fatal", 0)
    warn = report.counts.by_severity.get("warning", 0)
    if err > 0:
        banner_class = "err"
        verdict_label = "Integrity check failed"
        verdict_detail = f"{err} error(s), {warn} warning(s)"
    elif warn > 0:
        banner_class = "warn"
        verdict_label = "Session is healthy with warnings"
        verdict_detail = f"{warn} warning(s)"
    else:
        banner_class = "ok"
        verdict_label = "Session is healthy"
        verdict_detail = "0 errors, 0 warnings"

    cov = report.coverage
    performed = ", ".join(_esc(c) for c in cov.performed) or "none"
    skipped = ", ".join(f"{_esc(s.check)} ({_esc(s.reason)})" for s in cov.skipped)

    ordered = sorted(report.findings, key=finding_report_sort_key)
    rows: list[str] = []
    for f in ordered[:MAX_ROWS]:
        title = CODE_REGISTRY[f.code].name if f.code in CODE_REGISTRY else "Integrity finding"
        rows.append(
            "<tr>"
            f'<td class="mono">{_esc(f.code)}</td>'
            f'<td class="sev-{_esc(f.severity.value)}">{_esc(f.severity.value)}</td>'
            f"<td>{_esc(f.repairability.value)}</td>"
            f"<td>{_esc(title)}</td>"
            f'<td class="mono">{_esc(_span(f, home=home))}</td>'
            f"<td>{_esc(f.message)}</td>"
            f"<td>{_esc(get_finding_remediation(f, home=home))}</td>"
            f'<td class="mono">{_esc(f.fingerprint)}</td>'
            "</tr>"
        )
    hidden = len(ordered) - len(rows)
    if hidden:
        rows.append(
            f'<tr><td colspan="8" class="meta">... {hidden} more finding(s) not shown</td></tr>'
        )

    findings_section = ""
    if ordered:
        findings_section = (
            '<div class="card"><h2>Findings</h2><table>'
            "<tr><th>Code</th><th>Severity</th><th>Repair</th><th>Finding</th>"
            "<th>Span</th><th>Why</th><th>Fix</th><th>Fingerprint</th></tr>"
            + "".join(rows)
            + "</table></div>"
        )

    fingerprint_row = (
        "<tr><td>Source fingerprint</td>"
        f'<td class="mono">{_esc(report.source_fingerprint)}</td></tr>'
    )
    body = (
        f'<div class="banner {banner_class}">{_esc(verdict_label)}</div>\n'
        f'<div class="meta">{_esc(verdict_detail)} - sesslint {_esc(report.tool_version)}</div>\n'
        '<div class="card"><h2>Summary</h2><table>'
        "<tr><th>Field</th><th>Value</th></tr>"
        f'<tr><td>Session</td><td class="mono">{_esc(report.session_id)}</td></tr>'
        f"<tr><td>Assurance</td><td>{_esc(report.assurance)}</td></tr>"
        f"<tr><td>Limitation</td><td>{_esc(report.limitation)}</td></tr>"
        f"{fingerprint_row}"
        f"<tr><td>Adapter</td><td>{_esc(adapter)}</td></tr>"
        f"<tr><td>Profile</td><td>{_esc(profile)}</td></tr>"
        f"<tr><td>Checks performed</td><td>{performed}</td></tr>"
        f"<tr><td>Checks skipped</td><td>{skipped or 'none'}</td></tr>"
        "</table></div>\n"
        f"{findings_section}"
    )
    return _page("SessLint report", body)


def scan_report_html(scan_report: ScanReport, *, tool_version: str) -> str:
    """Render a ``ScanReport`` as a standalone HTML document.

    Same fields as ``sesslint.scan-report/v1`` JSON: 5-bucket totals, per-file
    table, aggregation summary and bounded findings — escaped, no JavaScript.
    """
    t = scan_report.totals
    if t.invalid + t.unreadable > 0:
        banner_class = "err"
    elif t.unsupported + t.skipped > 0:
        banner_class = "warn"
    else:
        banner_class = "ok"

    file_rows: list[str] = []
    for r in scan_report.files[:MAX_ROWS]:
        detail = f" - {_esc(r.skipped_reason)}" if r.skipped_reason else ""
        if r.cache_hit:
            detail += " [cache-hit]"
        file_rows.append(
            "<tr>"
            f'<td><span class="tag t-{_esc(r.verdict)}">{_esc(r.verdict.upper())}</span></td>'
            f'<td class="mono">{_esc(minimize_path(r.path))}</td>'
            f"<td>{r.error_count}</td>"
            f"<td>{r.warning_count}</td>"
            f"<td>{detail or '&mdash;'}</td>"
            "</tr>"
        )
    hidden_files = len(scan_report.files) - len(file_rows)
    if hidden_files:
        file_rows.append(
            f'<tr><td colspan="5" class="meta">... {hidden_files} more file(s) not shown</td></tr>'
        )

    summary = scan_report.summary
    summary_section = ""
    if summary is not None and (summary.by_code or summary.worst_files):
        code_rows = "".join(
            f'<tr><td class="mono">{_esc(row.code)}</td><td>{_esc(row.severity)}</td>'
            f"<td>{row.count}</td><td>{row.files}</td></tr>"
            for row in summary.by_code
        )
        worst_rows = "".join(
            f'<tr><td class="mono">{_esc(minimize_path(row.path))}</td>'
            f"<td>{row.error_count}</td><td>{row.warning_count}</td></tr>"
            for row in summary.worst_files
        )
        summary_section = (
            '<div class="card"><h2>Findings by code</h2><table>'
            "<tr><th>Code</th><th>Severity</th><th>Findings</th><th>Files</th></tr>"
            + (code_rows or '<tr><td colspan="4">none</td></tr>')
            + '</table></div><div class="card"><h2>Worst files</h2><table>'
            "<tr><th>Path</th><th>Errors</th><th>Warnings</th></tr>"
            + (worst_rows or '<tr><td colspan="3">none</td></tr>')
            + "</table></div>"
        )

    findings_rows: list[str] = []
    total_findings = 0
    for r in scan_report.files:
        for f in r.findings:
            total_findings += 1
            if len(findings_rows) < MAX_ROWS:
                title = (
                    CODE_REGISTRY[f.code].name if f.code in CODE_REGISTRY else "Integrity finding"
                )
                loc = minimize_path(f.source.path)
                if f.source.line is not None:
                    loc = f"{loc}:{f.source.line}"
                findings_rows.append(
                    "<tr>"
                    f'<td class="mono">{_esc(minimize_path(r.path))}</td>'
                    f'<td class="mono">{_esc(f.code)}</td>'
                    f'<td class="sev-{_esc(f.severity.value)}">{_esc(f.severity.value)}</td>'
                    f"<td>{_esc(title)}</td>"
                    f'<td class="mono">{_esc(loc)}</td>'
                    f"<td>{_esc(f.message)}</td>"
                    "</tr>"
                )
    hidden_findings = total_findings - len(findings_rows)
    if hidden_findings:
        findings_rows.append(
            '<tr><td colspan="6" class="meta">... '
            f"{hidden_findings} more finding(s) not shown</td></tr>"
        )
    findings_section = ""
    if findings_rows:
        findings_section = (
            '<div class="card"><h2>Findings</h2><table>'
            "<tr><th>File</th><th>Code</th><th>Severity</th><th>Finding</th>"
            "<th>Span</th><th>Why</th></tr>" + "".join(findings_rows) + "</table></div>"
        )

    root_cell = _esc(minimize_path(scan_report.root_path))
    body = (
        f'<div class="banner {banner_class}">Scan report: {root_cell}</div>\n'
        f'<div class="meta">sesslint {_esc(tool_version)} - {t.total} file(s)</div>\n'
        '<div class="card"><h2>Totals</h2><table>'
        "<tr><th>Healthy</th><th>Invalid</th><th>Unsupported</th><th>Unreadable</th>"
        "<th>Skipped</th><th>Total</th></tr>"
        f"<tr><td>{t.healthy}</td><td>{t.invalid}</td><td>{t.unsupported}</td>"
        f"<td>{t.unreadable}</td><td>{t.skipped}</td><td>{t.total}</td></tr>"
        "</table></div>\n"
        '<div class="card"><h2>Files</h2><table>'
        "<tr><th>Verdict</th><th>Path</th><th>Errors</th><th>Warnings</th><th>Detail</th></tr>"
        + "".join(file_rows)
        + f"</table></div>\n{summary_section}\n{findings_section}"
    )
    return _page("SessLint scan report", body)


__all__ = [
    "MAX_ROWS",
    "render_html",
    "scan_report_html",
]
