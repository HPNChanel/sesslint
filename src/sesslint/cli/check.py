"""The ``sesslint check`` subcommand."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Final

from sesslint import __version__
from sesslint.cli._common import (
    _apply_config,
    _handle_internal_error,
    _load_baseline_arg,
    _ndjson_progress_cb,
    _output_format,
    _read_stdin_bytes,
    _rule_codes_arg,
    _write_baseline_arg,
    should_color,
)
from sesslint.cli._options import (
    _add_seal_args,
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
from sesslint.cli._render import _emit_check_report, format_scan_report_human
from sesslint.cli._seal import _check_seal_verdict, _maybe_append_seal
from sesslint.errors import SesslintError

NAME: Final[str] = "check"


def configure(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> argparse.ArgumentParser:
    sub = subparsers.add_parser(
        "check",
        help="[read-only] Check a session file with auto-detection.",
        description=(
            "[read-only] Check a session file for structural defects, causal breaks, "
            "and schema violations."
        ),
    )
    sub.add_argument(
        "path",
        type=Path,
        nargs="+",
        help=(
            "Path(s) to session file(s) (.json or .jsonl) or directories. "
            "Multiple paths produce one aggregated scan report. "
            "'-' reads one session artifact from stdin (max 100 MB)."
        ),
    )
    add_format_option(sub)
    add_profile_option(sub)
    sub.add_argument(
        "--policy",
        dest="check_policy",
        default=None,
        help="[Invalid for check] Repair policy is only applicable to 'repair'",
    )
    sub.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        default=False,
        help="Recursively scan directory trees for session artifacts",
    )
    sub.add_argument(
        "--follow-symlinks",
        action="store_true",
        default=False,
        help="[lossy: follows links] Follow directory symlinks during recursive scanning",
    )
    sub.add_argument(
        "--max-files",
        type=_validate_positive_int,
        default=None,
        help="Maximum number of files to inspect during recursive scan (default: 10000)",
    )
    sub.add_argument(
        "--max-bytes",
        type=_validate_positive_int,
        default=None,
        help="Maximum cumulative bytes to read during recursive scan (default: 1GB)",
    )
    check_out_group = sub.add_mutually_exclusive_group()
    check_out_group.add_argument(
        "--json",
        action="store_true",
        help="Output check report as a single canonical JSON document to stdout",
    )
    check_out_group.add_argument(
        "--output-format",
        choices=["human", "json", "sarif", "html"],
        default=None,
        help="Output format (default: human; --json is equivalent to 'json')",
    )
    add_progress_json_option(sub)
    sub.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default=argparse.SUPPRESS,
        help="Control colored output in human report mode (default: auto)",
    )
    sub.add_argument(
        "--no-color",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Disable ANSI color styling",
    )
    add_detection_threshold_options(sub)
    sub.add_argument(
        "--skip-undetected",
        action="store_true",
        default=False,
        help=(
            "Classify files whose format cannot be detected as skipped instead "
            "of invalid (useful for pre-commit hooks and mixed-content trees)"
        ),
    )
    add_fail_on_option(sub)
    add_config_option(sub)
    add_rule_selection_options(sub)
    add_baseline_options(sub)
    add_walk_filter_options(sub)
    sub.add_argument(
        "--include-content",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Embed raw transcript content in reports (warning: emits raw sensitive data)",
    )
    _add_seal_args(sub)
    add_walk_options(sub)
    return sub


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from sesslint.config import ConfigError, load_config

    try:
        cli_cfg = load_config(explicit=getattr(args, "config", None))
    except ConfigError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 2
    _apply_config(args, cli_cfg)

    if getattr(args, "check_policy", None) is not None:
        print(
            "Error: The --policy option is only valid for 'repair', not 'check'.",
            file=sys.stderr,
        )
        return 2

    try:
        check_baseline = _load_baseline_arg(args)
    except ValueError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 2

    def _emit_scan_rep(scan_rep: Any) -> int:
        _write_baseline_arg(args, [f for fr in scan_rep.files for f in fr.findings])
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

    target_paths: list[Path] = args.path

    # --seal binds one verdict artifact per line; aggregate scan modes
    # have no single subject artifact, so refuse rather than seal a
    # partial picture (evidence-assurance T-01).
    if getattr(args, "seal", None) is not None and len(target_paths) != 1:
        print(
            "Error: --seal applies to single-file checks only "
            "(one artifact per line; scans are not sealed).",
            file=sys.stderr,
        )
        return 2

    # `-` reads one session artifact from stdin (ux T-06). It cannot be
    # combined with filesystem paths — one stream is one virtual file.
    if any(str(p) == "-" for p in target_paths):
        if len(target_paths) > 1:
            print(
                "Error: '-' (stdin) cannot be combined with other paths.",
                file=sys.stderr,
            )
            return 2
        from sesslint.api import check_bytes

        format_opt = getattr(args, "format", "auto")
        profile_opt = getattr(args, "profile", "neutral")
        try:
            stdin_data = _read_stdin_bytes(args.max_file_bytes)
            report = check_bytes(
                stdin_data,
                max_input_bytes=args.max_file_bytes,
                format=format_opt if format_opt != "auto" else None,
                profile=profile_opt,
                confidence_min=getattr(args, "confidence_min", None),
                margin_min=getattr(args, "margin_min", None),
                progress_cb=_ndjson_progress_cb(args),
                select=_rule_codes_arg(args, "select"),
                ignore=_rule_codes_arg(args, "ignore"),
                baseline=check_baseline,
                max_file_bytes=args.max_file_bytes,
                timestamp_skew_ms=args.timestamp_skew_ms,
            )
        except (ValueError, KeyError) as err:
            if "not permitted by profile" in str(err):
                print(str(err), file=sys.stderr)
                return 2
            parser.error(str(err))
        except SesslintError as err:
            print(f"Validation error [{err.code}]: {err}", file=sys.stderr)
            return 1
        except Exception as err:
            return _handle_internal_error(err, args)

        rc = _emit_check_report(
            report,
            args,
            display_path="<stdin>",
            format_opt=format_opt,
            profile_opt=profile_opt,
        )
        from sesslint.report import render_json as _render_check_json

        seal_rc = _maybe_append_seal(
            args,
            tool="check",
            artifact_bytes=stdin_data,
            artifact_path=None,
            verdict=_check_seal_verdict(report),
            codes=dict(report.counts.by_code),
            report_bytes=_render_check_json(report).encode("utf-8"),
        )
        return seal_rc if seal_rc is not None else rc

    # Multi-path mode: aggregate per-path results into one ScanReport
    # (pre-commit appends every staged filename to a single invocation).
    if len(target_paths) > 1:
        for p in target_paths:
            if not p.exists() and not p.is_symlink():
                print(f"Error: Path not found: {p}", file=sys.stderr)
                return 2
            if p.is_dir() and not getattr(args, "recursive", False):
                print(
                    f"Error: Path {p} is a directory. Use --recursive to scan directories.",
                    file=sys.stderr,
                )
                return 2

        from sesslint.report import minimize_path
        from sesslint.scan import FileResult, ScanReport, ScanTotals, scan_path

        multi_files: list[FileResult] = []
        totals = ScanTotals()
        for p in target_paths:
            try:
                rep = scan_path(
                    p,
                    recursive=getattr(args, "recursive", False),
                    follow_symlinks=getattr(args, "follow_symlinks", False),
                    max_files=getattr(args, "max_files", 10000),
                    max_bytes=getattr(args, "max_bytes", 1024 * 1024 * 1024),
                    format=getattr(args, "format", "auto"),
                    profile=getattr(args, "profile", "neutral"),
                    confidence_min=getattr(args, "confidence_min", None),
                    margin_min=getattr(args, "margin_min", None),
                    progress_cb=_ndjson_progress_cb(args),
                    skip_undetected=getattr(args, "skip_undetected", False),
                    select=_rule_codes_arg(args, "select"),
                    ignore=_rule_codes_arg(args, "ignore"),
                    baseline=check_baseline,
                    max_file_bytes=args.max_file_bytes,
                    timestamp_skew_ms=args.timestamp_skew_ms,
                    exclude=getattr(args, "exclude", None),
                    ext=getattr(args, "ext", None),
                )
            except (ValueError, KeyError) as err:
                err_msg = err.args[0] if err.args else str(err)
                print(f"Error: {err_msg}", file=sys.stderr)
                return 2
            multi_files.extend(rep.files)
            t = rep.totals
            totals = ScanTotals(
                healthy=totals.healthy + t.healthy,
                invalid=totals.invalid + t.invalid,
                unsupported=totals.unsupported + t.unsupported,
                unreadable=totals.unreadable + t.unreadable,
                skipped=totals.skipped + t.skipped,
            )
        multi_files.sort(key=lambda r: r.path)
        scan_rep = ScanReport(
            root_path=";".join(minimize_path(p) for p in target_paths),
            totals=totals,
            files=tuple(multi_files),
        )
        return _emit_scan_rep(scan_rep)

    target_path: Path = target_paths[0]
    if target_path.is_dir():
        if getattr(args, "seal", None) is not None:
            print(
                "Error: --seal applies to single-file checks only "
                "(one artifact per line; directory scans are not sealed).",
                file=sys.stderr,
            )
            return 2
        if not getattr(args, "recursive", False):
            print(
                f"Error: Path {target_path} is a directory. Use --recursive to scan directories.",
                file=sys.stderr,
            )
            return 2

        from sesslint.api import check_dir

        try:
            scan_rep = check_dir(
                target_path,
                recursive=True,
                follow_symlinks=getattr(args, "follow_symlinks", False),
                max_files=getattr(args, "max_files", 10000),
                max_bytes=getattr(args, "max_bytes", 1024 * 1024 * 1024),
                format=getattr(args, "format", "auto"),
                profile=getattr(args, "profile", "neutral"),
                confidence_min=getattr(args, "confidence_min", None),
                margin_min=getattr(args, "margin_min", None),
                progress_cb=_ndjson_progress_cb(args),
                skip_undetected=getattr(args, "skip_undetected", False),
                select=_rule_codes_arg(args, "select"),
                ignore=_rule_codes_arg(args, "ignore"),
                baseline=check_baseline,
                max_file_bytes=args.max_file_bytes,
                timestamp_skew_ms=args.timestamp_skew_ms,
                exclude=getattr(args, "exclude", None),
                ext=getattr(args, "ext", None),
            )
        except (ValueError, KeyError) as err:
            err_msg = err.args[0] if err.args else str(err)
            print(f"Error: {err_msg}", file=sys.stderr)
            return 2

        return _emit_scan_rep(scan_rep)

    if not target_path.exists():
        print(f"Error: Path not found: {target_path}", file=sys.stderr)
        return 2

    format_opt = getattr(args, "format", "auto")
    profile_opt = getattr(args, "profile", "neutral")

    try:
        from sesslint.api import check_file

        try:
            report = check_file(
                target_path,
                format=format_opt if format_opt != "auto" else None,
                profile=profile_opt,
                confidence_min=getattr(args, "confidence_min", None),
                margin_min=getattr(args, "margin_min", None),
                progress_cb=_ndjson_progress_cb(args),
                select=_rule_codes_arg(args, "select"),
                ignore=_rule_codes_arg(args, "ignore"),
                baseline=check_baseline,
                max_file_bytes=args.max_file_bytes,
                timestamp_skew_ms=args.timestamp_skew_ms,
            )
        except (ValueError, KeyError) as err:
            if "not permitted by profile" in str(err):
                print(str(err), file=sys.stderr)
                return 2
            parser.error(str(err))

        rc = _emit_check_report(
            report,
            args,
            display_path=str(target_path),
            format_opt=format_opt,
            profile_opt=profile_opt,
        )
        from sesslint.report import render_json as _render_check_json

        seal_rc = _maybe_append_seal(
            args,
            tool="check",
            artifact_sha256=report.source_fingerprint,
            artifact_bytes=None,
            artifact_path=target_path,
            verdict=_check_seal_verdict(report),
            codes=dict(report.counts.by_code),
            report_bytes=_render_check_json(report).encode("utf-8"),
        )
        return seal_rc if seal_rc is not None else rc

    except SesslintError as err:
        print(f"Validation error [{err.code}]: {err}", file=sys.stderr)
        return 1
    except FileNotFoundError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 2
    except Exception as err:
        return _handle_internal_error(err, args)
