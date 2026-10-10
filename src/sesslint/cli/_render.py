"""Human/structured report emission shared by the check/scan commands."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from sesslint import __version__
from sesslint.cli._common import (
    FORMAT_DISPLAY_NAMES,
    _output_format,
    _write_baseline_arg,
    should_color,
)


def format_scan_report_human(scan_report: Any, color: bool = False) -> str:
    """Format human-readable summary of ScanReport with 5-bucket totals."""
    bold = "\033[1m" if color else ""
    reset = "\033[0m" if color else ""
    red = "\033[31m" if color else ""
    green = "\033[32m" if color else ""
    yellow = "\033[33m" if color else ""

    lines: list[str] = [
        f"[read-only] Scan report for: {scan_report.root_path}",
        (
            f"Totals: healthy={scan_report.totals.healthy} "
            f"invalid={scan_report.totals.invalid} "
            f"unsupported={scan_report.totals.unsupported} "
            f"unreadable={scan_report.totals.unreadable} "
            f"skipped={scan_report.totals.skipped} "
            f"(total={scan_report.totals.total})"
        ),
    ]
    reason_totals = scan_report.skipped_reason_totals()
    if reason_totals:
        lines.append("Skipped reasons: " + " ".join(f"{k}={v}" for k, v in reason_totals.items()))
        if "max-bytes-cap-exceeded" in reason_totals or "max-files-cap-exceeded" in reason_totals:
            lines.append(
                "Hint: resource budget exhausted -- raise --max-bytes/--max-files "
                "to scan remaining files."
            )
    lines.append("-" * 80)
    for r in scan_report.files:
        if r.verdict == "healthy":
            tag_color = green
            raw_tag = "[HEALTHY]"
            detail = ""
        elif r.verdict == "invalid":
            tag_color = red
            raw_tag = "[INVALID]"
            detail = f" ({r.error_count} error(s), {r.warning_count} warning(s))"
        elif r.verdict == "unsupported":
            tag_color = yellow
            raw_tag = "[UNSUPPORTED]"
            detail = f" ({r.skipped_reason or 'unsupported version'})"
        elif r.verdict == "unreadable":
            tag_color = red
            raw_tag = "[UNREADABLE]"
            detail = " (read error or non-UTF8)"
        else:  # skipped
            tag_color = bold
            raw_tag = "[SKIPPED]"
            detail = f" (reason: {r.skipped_reason})"
        if getattr(r, "cache_hit", False):
            detail += " [cache-hit]"
        tag_col = f"{tag_color}{raw_tag}{reset}{' ' * max(0, 20 - len(raw_tag))}"
        lines.append(f"  {tag_col} {r.path}{detail}")

    summary = getattr(scan_report, "summary", None)
    if summary is not None and (summary.by_code or summary.worst_files):
        lines.append("-" * 80)
        if summary.by_code:
            lines.append("Findings by code:")
            for row in summary.by_code:
                lines.append(
                    f"  {row.code}  {row.severity:<8} {row.count} finding(s) in {row.files} file(s)"
                )
        if summary.worst_files:
            lines.append("Worst files:")
            for row in summary.worst_files:
                lines.append(
                    f"  {row.path}  ({row.error_count} error(s), {row.warning_count} warning(s))"
                )

    # SL009 hygiene rollup: secret-shaped material deserves its own
    # section — a warning-bucket row can hide inside a long by_code list.
    secret_files = sum(1 for r in scan_report.files if any(f.code == "SL009" for f in r.findings))
    if secret_files:
        lines.append("-" * 80)
        lines.append(f"  secret-shaped material: {secret_files} file(s)")

    # SL402 index-divergence rollup (index-reconciliation T-03): divergence
    # is invisible in per-file verdicts — the file itself is healthy.
    kinds: dict[str, int] = {}
    for r in scan_report.files:
        for f in r.findings:
            if f.code == "SL402" and f.evidence:
                kind = f.evidence.get("divergence")
                if isinstance(kind, str):
                    kinds[kind] = kinds.get(kind, 0) + 1
    if kinds:
        parts: list[str] = []
        if kinds.get("file-not-in-index"):
            parts.append(f"{kinds['file-not-in-index']} session file(s) not listed in vendor index")
        if kinds.get("index-entry-no-file"):
            n = kinds["index-entry-no-file"]
            parts.append(f"{n} dangling index {'entry' if n == 1 else 'entries'}")
        if kinds.get("index-malformed"):
            parts.append("malformed index")
        if kinds.get("index-truncated"):
            parts.append("truncated index")
        hint = (
            "resumable by explicit id; see docs/codes/SL402.md"
            if kinds.get("file-not-in-index")
            else "see docs/codes/SL402.md"
        )
        lines.append("-" * 80)
        lines.append(f"  index divergence: {', '.join(parts)} ({hint})")

    return "\n".join(lines)


def _emit_check_report(
    report: Any,
    args: argparse.Namespace,
    *,
    display_path: str,
    format_opt: str,
    profile_opt: str,
) -> int:
    """Shared check-report emission for file and stdin sources (ux T-06).

    ``display_path`` is the path shown in skip/hint messages — ``<stdin>``
    for piped input.
    """
    _write_baseline_arg(args, report.findings)

    # --skip-undetected: detection-failed files are skipped, not failed
    if getattr(args, "skip_undetected", False) and report.limitation.startswith("Unsupported:"):
        skip_fmt = _output_format(args)
        if skip_fmt == "json":
            # Valid empty-state payload keeps `| jq` pipelines alive —
            # an empty stdout would strand JSON consumers.
            from sesslint.report import minimize_path

            print(
                json.dumps(
                    {
                        "findings": [],
                        "ok": True,
                        "path": minimize_path(display_path),
                        "skipped": True,
                        "skipped_reason": "format-undetected",
                    },
                    sort_keys=True,
                )
            )
        elif skip_fmt == "sarif":
            from sesslint.sarif import render_sarif

            print(render_sarif((), tool_version=__version__))
        else:
            print(f"skipped (format-undetected): {display_path}", file=sys.stderr)
        return 0

    has_error = (
        report.counts.by_severity.get("error", 0) > 0
        or report.counts.by_severity.get("fatal", 0) > 0
    )
    if getattr(args, "fail_on", "error") == "warning":
        has_error = has_error or report.counts.by_severity.get("warning", 0) > 0
    exit_code = 1 if has_error else 0

    if report.limitation.startswith("Unsupported:"):
        exit_code = int(getattr(args, "fail_on_unsupported", False))
        print(
            "unsupported (format-undetected): use sesslint formats to inspect supported inputs",
            file=sys.stderr,
        )
    elif report.limitation.startswith("Skipped:"):
        print(
            "skipped (file-too-large): increase --max-file-bytes to inspect this file",
            file=sys.stderr,
        )
    # If format detection failed or was ambiguous, emit actionable hints on stderr
    has_detection_or_version_failure = False
    for f in report.findings:
        if f.code == "SL302":
            has_detection_or_version_failure = True
            if isinstance(f.evidence, dict):
                reason = f.evidence.get("reason")
                if reason in ("tie", "low-confidence", "empty"):
                    print(
                        "Format detection ambiguous. Please specify --format explicitly "
                        "(see sesslint formats).",
                        file=sys.stderr,
                    )
                    confidences = f.evidence.get("confidences")
                    if confidences and isinstance(confidences, dict):
                        sorted_conf = dict(sorted(confidences.items()))
                        print(
                            f"Candidate confidences: {sorted_conf}",
                            file=sys.stderr,
                        )
            print(f"Format detection error [{f.code}]: {f.message}", file=sys.stderr)
        elif f.code == "SL301":
            has_detection_or_version_failure = True
            print(f"Format detection error [{f.code}]: {f.message}", file=sys.stderr)

    if has_detection_or_version_failure and (
        display_path == "<stdin>" or Path(display_path).suffix.lower() in (".json", ".jsonl")
    ):
        if display_path == "<stdin>":
            print(
                "hint: save the stream to a file, then run 'sesslint bundle <file>' "
                "and attach the output to an adapter request",
                file=sys.stderr,
            )
        else:
            target_disp = display_path.replace("\\", "/")
            print(
                f"hint: run 'sesslint bundle {target_disp}' "
                "and attach the output to an adapter request",
                file=sys.stderr,
            )

    adapter_id = report.coverage.adapter.get("id", "canonical")
    format_display = FORMAT_DISPLAY_NAMES.get(adapter_id, adapter_id)

    single_out_fmt = _output_format(args)
    if single_out_fmt == "json":
        from sesslint.report import build_repro_metadata, render_json

        adapter_cov = report.coverage.adapter
        profile_cov = report.coverage.profile
        repro_meta = build_repro_metadata(
            adapter_name=str(adapter_cov.get("id", "unknown")),
            adapter_version=str(adapter_cov.get("version", "unknown")),
            profile_name=str(profile_cov.get("id", "unknown")),
            profile_version=str(profile_cov.get("version", "unknown")),
            detection_method="manual" if format_opt != "auto" else "auto",
            detection_confidence=None,
        )
        print(
            render_json(
                report,
                include_content=getattr(args, "include_content", False),
                repro=repro_meta,
            )
        )
        return exit_code
    if single_out_fmt == "sarif":
        from sesslint.sarif import render_sarif

        print(render_sarif(report.findings, tool_version=report.tool_version))
        return exit_code
    if single_out_fmt == "html":
        from sesslint.html_report import render_html

        print(
            render_html(
                report,
                adapter=format_display,
                profile=report.coverage.profile.get("id", profile_opt),
            )
        )
        return exit_code
    from sesslint.report import render_human

    use_color = should_color(args, sys.stdout)
    human_text = render_human(
        report,
        color=use_color,
        adapter=format_display,
        profile=report.coverage.profile.get("id", profile_opt),
    )
    if not has_error:
        print(f"Valid {format_display} session")
    print(human_text)
    return exit_code
