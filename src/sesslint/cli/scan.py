"""The ``sesslint scan`` subcommand."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any, Final

from sesslint import __version__
from sesslint.cli._common import (
    _apply_config,
    _load_baseline_arg,
    _ndjson_progress_cb,
    _output_format,
    _read_stdin_bytes,
    _rule_codes_arg,
    _write_baseline_arg,
    should_color,
)
from sesslint.cli._options import (
    _validate_positive_int,
    add_baseline_options,
    add_config_option,
    add_detection_threshold_options,
    add_fail_on_option,
    add_format_option,
    add_profile_option,
    add_progress_json_option,
    add_rule_selection_options,
    add_walk_filter_options,
    add_walk_options,
)
from sesslint.cli._render import format_scan_report_human

NAME: Final[str] = "scan"


def configure(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> argparse.ArgumentParser:
    sub = subparsers.add_parser(
        "scan",
        help="[read-only] Scan directory trees for session artifacts or display limits.",
        description="[read-only] Scan directory trees for session artifacts or display limits.",
    )
    sub.add_argument(
        "path",
        type=Path,
        nargs="?",
        default=None,
        help="Directory path to scan (or omit when using --agent or --show-limits). "
        "'-' scans one session artifact from stdin (max 100 MB)",
    )
    sub.add_argument(
        "--agent",
        choices=["claude", "codex", "all"],
        default=None,
        help="Scan well-known session roots for an agent runtime "
        "($CLAUDE_CONFIG_DIR/projects or ~/.claude/projects; "
        "$CODEX_HOME/sessions or ~/.codex/sessions). Explicit PATH overrides.",
    )
    sub.add_argument(
        "--show-limits",
        action="store_true",
        help="Display default hostile-input reader limits.",
    )
    sub.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        default=True,
        help="Recursively scan directory trees (default: True)",
    )
    sub.add_argument(
        "--follow-symlinks",
        action="store_true",
        default=False,
        help="Follow directory symlinks during scan",
    )
    sub.add_argument(
        "--max-files",
        type=_validate_positive_int,
        default=None,
        help="Maximum files to scan (default: 10000)",
    )
    sub.add_argument(
        "--max-bytes",
        type=_validate_positive_int,
        default=None,
        help="Maximum cumulative bytes to read during recursive scan (default: 1GB)",
    )
    add_format_option(sub)
    add_profile_option(sub)
    add_detection_threshold_options(sub)
    sub.add_argument(
        "--skip-undetected",
        action="store_true",
        default=False,
        help=(
            "Classify files whose format cannot be detected as skipped instead "
            "of invalid (useful for hooks and mixed-content trees)"
        ),
    )
    add_fail_on_option(sub)
    add_config_option(sub)
    add_rule_selection_options(sub)
    add_baseline_options(sub)
    add_walk_filter_options(sub)
    scan_out_group = sub.add_mutually_exclusive_group()
    scan_out_group.add_argument(
        "--json",
        action="store_true",
        help="Output scan report as JSON",
    )
    scan_out_group.add_argument(
        "--output-format",
        choices=["human", "json", "sarif", "html"],
        default=None,
        help="Output format (default: human; --json is equivalent to 'json')",
    )
    add_progress_json_option(sub)
    sub.add_argument(
        "--top",
        type=int,
        default=10,
        metavar="N",
        help=(
            "Show up to N worst files in the report summary (default: 10; "
            "0 disables the worst-files view)"
        ),
    )
    sub.add_argument(
        "--group-by",
        choices=["code", "none"],
        default="code",
        help="Summary grouping: 'code' aggregates findings by rule code (default), 'none' disables",
    )
    sub.add_argument(
        "--jobs",
        default="1",
        metavar="N",
        help=(
            "Parallel worker processes for per-file analysis (default: 1 = "
            "sequential; 'auto' or 0 = CPU count). Report output is identical "
            "for any N; only wall time changes. Ignored for single-file input."
        ),
    )
    sub.add_argument(
        "--incremental",
        action="store_true",
        help=(
            "Reuse cached per-file results when content is provably unchanged "
            "(sqlite cache; findings/verdicts identical, hits marked 'cache: hit')"
        ),
    )
    sub.add_argument(
        "--cache-dir",
        default=None,
        metavar="DIR",
        help=(
            "Override the incremental cache directory "
            "(default: SESSLINT_CACHE_DIR or platform cache location)"
        ),
    )
    sub.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default=argparse.SUPPRESS,
        help="Control colored terminal output (default: auto)",
    )
    sub.add_argument(
        "--no-color",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Disable ANSI color styling",
    )
    add_walk_options(sub)
    sub.add_argument(
        "--max-findings-per-code",
        type=int,
        default=None,
        help="Maximum displayed samples per code per file (default: 20)",
    )
    sub.add_argument(
        "--newest",
        type=int,
        default=None,
        metavar="N",
        help="Inspect the N most recently modified session files",
    )
    sub.add_argument(
        "--since",
        default=None,
        metavar="YYYY-MM-DD",
        help="Inspect files modified on/after this absolute UTC date",
    )
    sub.add_argument(
        "--include-archived",
        action="store_true",
        help="Include Codex archived_sessions during agent discovery",
    )
    return sub


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from sesslint.config import ConfigError, load_config

    try:
        cli_cfg = load_config(explicit=getattr(args, "config", None))
    except ConfigError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 2
    _apply_config(args, cli_cfg)

    if getattr(args, "show_limits", False):
        from sesslint.io import ReaderLimits

        limits = ReaderLimits()
        print(
            f"ReaderLimits: max_line_bytes={limits.max_line_bytes}, "
            f"max_depth={limits.max_depth}, "
            f"max_file_bytes={limits.max_file_bytes}, "
            f"max_records={limits.max_records}"
        )
        return 0

    agent = getattr(args, "agent", None)
    explicit_scan_path = getattr(args, "path", None)
    if agent is not None and explicit_scan_path is not None:
        print(
            "Warning: explicit PATH overrides --agent; scanning PATH only.",
            file=sys.stderr,
        )
        agent = None

    if agent is None and explicit_scan_path is None:
        parser.print_help(sys.stderr)
        return 2

    from sesslint.api import check_dir

    try:
        scan_baseline = _load_baseline_arg(args)
    except ValueError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 2

    scan_kwargs: dict[str, Any] = {
        "recursive": getattr(args, "recursive", True),
        "follow_symlinks": getattr(args, "follow_symlinks", False),
        "max_files": getattr(args, "max_files", 10000),
        "max_bytes": getattr(args, "max_bytes", 1024 * 1024 * 1024),
        "max_file_bytes": args.max_file_bytes,
        "timestamp_skew_ms": args.timestamp_skew_ms,
        "max_findings_per_code": args.max_findings_per_code,
        "newest": args.newest,
        "since": args.since,
        "format": getattr(args, "format", "auto"),
        "profile": getattr(args, "profile", "neutral"),
        "confidence_min": getattr(args, "confidence_min", None),
        "margin_min": getattr(args, "margin_min", None),
        "progress_cb": _ndjson_progress_cb(args),
        "skip_undetected": getattr(args, "skip_undetected", False),
        "select": _rule_codes_arg(args, "select"),
        "ignore": _rule_codes_arg(args, "ignore"),
        "baseline": scan_baseline,
        "exclude": getattr(args, "exclude", None),
        "ext": getattr(args, "ext", None),
        "incremental": getattr(args, "incremental", False),
        "cache_dir": getattr(args, "cache_dir", None),
    }

    jobs_raw = str(getattr(args, "jobs", "1")).strip().lower()
    if jobs_raw in ("auto", "0"):
        scan_kwargs["jobs"] = os.cpu_count() or 1
    else:
        try:
            scan_kwargs["jobs"] = int(jobs_raw)
        except ValueError:
            print(
                f"Error: --jobs must be a positive integer or 'auto', got '{jobs_raw}'",
                file=sys.stderr,
            )
            return 2
        if scan_kwargs["jobs"] < 1:
            print(
                f"Error: --jobs must be a positive integer or 'auto', got '{jobs_raw}'",
                file=sys.stderr,
            )
            return 2

    if agent is not None:
        from sesslint.api import discover_session_roots
        from sesslint.report import minimize_path
        from sesslint.scan import FileResult, ScanReport, ScanTotals

        requested = ("claude", "codex") if agent == "all" else (agent,)
        roots = discover_session_roots(requested, include_archived=args.include_archived)

        merged_files: list[FileResult] = []
        totals = ScanTotals()

        def _acc_totals(t: ScanTotals, r: ScanTotals) -> ScanTotals:
            return ScanTotals(
                healthy=t.healthy + r.healthy,
                invalid=t.invalid + r.invalid,
                unsupported=t.unsupported + r.unsupported,
                unreadable=t.unreadable + r.unreadable,
                skipped=t.skipped + r.skipped,
            )

        try:
            for root in roots:
                if root.exists:
                    rep = check_dir(
                        root.path,
                        **{**scan_kwargs, "vendor_layout": root.agent, "skip_undetected": True},
                    )
                    merged_files.extend(rep.files)
                    totals = _acc_totals(totals, rep.totals)
                else:
                    skip_reason = (
                        "agent-root-missing"
                        if not root.path.exists()
                        else "agent-root-not-directory"
                    )
                    merged_files.append(
                        FileResult(
                            path=minimize_path(root.path),
                            verdict="skipped",
                            skipped_reason=skip_reason,
                        )
                    )
                    totals = _acc_totals(totals, ScanTotals(skipped=1))
        except (ValueError, KeyError) as err:
            err_msg = err.args[0] if err.args else str(err)
            print(f"Error: {err_msg}", file=sys.stderr)
            return 2

        root_str = ";".join(minimize_path(r.path) for r in roots)
        scan_rep = ScanReport(root_path=root_str, totals=totals, files=tuple(merged_files))
    else:
        target_scan_path: Path = args.path
        if str(target_scan_path) == "-":
            # `-` scans one session artifact streamed on stdin (ux T-06).
            from sesslint.scan import scan_bytes

            try:
                stdin_data = _read_stdin_bytes(args.max_file_bytes)
                scan_rep = scan_bytes(
                    stdin_data,
                    max_input_bytes=args.max_file_bytes,
                    format=scan_kwargs["format"],
                    profile=scan_kwargs["profile"],
                    confidence_min=scan_kwargs["confidence_min"],
                    margin_min=scan_kwargs["margin_min"],
                    progress_cb=scan_kwargs["progress_cb"],
                    skip_undetected=scan_kwargs["skip_undetected"],
                    select=scan_kwargs["select"],
                    ignore=scan_kwargs["ignore"],
                    baseline=scan_kwargs["baseline"],
                    max_file_bytes=args.max_file_bytes,
                    timestamp_skew_ms=args.timestamp_skew_ms,
                    max_findings_per_code=args.max_findings_per_code,
                )
            except (ValueError, KeyError) as err:
                err_msg = err.args[0] if err.args else str(err)
                print(f"Error: {err_msg}", file=sys.stderr)
                return 2
        else:
            if not target_scan_path.exists():
                print(f"Error: Path not found: {target_scan_path}", file=sys.stderr)
                return 2
            if scan_kwargs["jobs"] > 1 and not target_scan_path.is_dir():
                print("Note: --jobs is ignored for single-file input.", file=sys.stderr)

            try:
                scan_rep = check_dir(target_scan_path, **scan_kwargs)
            except (ValueError, KeyError) as err:
                err_msg = err.args[0] if err.args else str(err)
                print(f"Error: {err_msg}", file=sys.stderr)
                return 2

    _write_baseline_arg(args, [f for fr in scan_rep.files for f in fr.findings])

    # Attach the aggregated summary view (ux T-08): by-code grouping and
    # top-N worst files. Pure presentation — findings are unchanged.
    top_n = getattr(args, "top", 10)
    group_by = getattr(args, "group_by", "code")
    if top_n < 0:
        print(f"Error: --top must be >= 0, got {top_n}", file=sys.stderr)
        return 2
    if group_by != "none" or top_n > 0:
        import dataclasses

        from sesslint.scan import aggregate_scan

        scan_rep = dataclasses.replace(
            scan_rep, summary=aggregate_scan(scan_rep.files, top=top_n, group_by=group_by)
        )

    out_fmt = _output_format(args)
    if out_fmt == "json":
        print(scan_rep.to_json())
    elif out_fmt == "sarif":
        from sesslint.sarif import scan_report_sarif

        print(scan_report_sarif(scan_rep, tool_version=__version__))
    elif out_fmt == "html":
        from sesslint.html_report import scan_report_html

        print(scan_report_html(scan_rep, tool_version=__version__))
    else:
        use_color = should_color(args, sys.stdout)
        print(format_scan_report_human(scan_rep, color=use_color))

    warn_total = sum(f.warning_count for f in scan_rep.files)
    if (
        scan_rep.totals.invalid > 0
        or (getattr(args, "fail_on_unsupported", False) and scan_rep.totals.unsupported > 0)
        or scan_rep.totals.unreadable > 0
        or (getattr(args, "fail_on", "error") == "warning" and warn_total > 0)
    ):
        return 1
    return 0
