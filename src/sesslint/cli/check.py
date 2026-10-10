"""The ``sesslint check`` subcommand (absorbs the old ``scan`` command)."""

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
    add_adapter_option,
    add_baseline_options,
    add_color_options,
    add_config_option,
    add_detection_threshold_options,
    add_fail_on_option,
    add_profile_option,
    add_progress_json_option,
    add_rule_selection_options,
    add_walk_filter_options,
    add_walk_options,
)
from sesslint.cli._render import _emit_check_report, format_scan_report_human
from sesslint.cli._scan_args import build_scan_kwargs
from sesslint.cli._seal import _check_seal_verdict, _maybe_append_seal
from sesslint.errors import SesslintError

NAME: Final[str] = "check"
ALIASES: Final[tuple[str, ...]] = ("scan",)


def configure(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> argparse.ArgumentParser:
    sub = subparsers.add_parser(
        "check",
        aliases=list(ALIASES),
        help="[read-only] Check session artifacts (files, directories, or agent session roots).",
        description=(
            "[read-only] Check session artifacts for structural defects, causal "
            "breaks, and schema violations. Positional targets may be files, "
            "directories (scanned recursively), or '-' to read one session "
            "file from stdin. 'scan' is an alias for this command."
        ),
    )
    sub.add_argument(
        "path",
        type=Path,
        nargs="*",
        help=(
            "Path(s) to session file(s) (.json or .jsonl) or directories. "
            "Multiple paths produce one aggregated scan report. "
            "'-' reads one session artifact from stdin (max 100 MB). "
            "Omit PATH only when using --agent."
        ),
    )
    add_adapter_option(sub)
    add_profile_option(sub)
    sub.add_argument(
        "--agent",
        choices=["claude", "codex", "all"],
        default=None,
        help="Scan well-known session roots for an agent runtime "
        "($CLAUDE_CONFIG_DIR/projects or ~/.claude/projects; "
        "$CODEX_HOME/sessions or ~/.codex/sessions). Explicit PATH overrides.",
    )
    sub.add_argument(
        "--latest",
        action="store_true",
        default=False,
        help="Check only the newest primary ledger for --agent claude|codex",
    )
    sub.add_argument(
        "--include-archived",
        action="store_true",
        default=False,
        help="Include Codex archived_sessions during agent discovery",
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
        "-f",
        "--format",
        dest="output_format",
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
        default=False,
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
    add_color_options(sub)
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
    return sub


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from sesslint.config import ConfigError, load_config

    try:
        cli_cfg = load_config(explicit=getattr(args, "config", None))
    except ConfigError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 2
    _apply_config(args, cli_cfg)

    agent = getattr(args, "agent", None)
    target_paths: list[Path] = list(getattr(args, "path", None) or [])

    # --latest resolves one primary ledger through agent discovery, then
    # continues down the ordinary single-file path (scan-triage T-09).
    if getattr(args, "latest", False):
        if agent not in ("claude", "codex"):
            print(
                "Error: --latest requires --agent claude or --agent codex.",
                file=sys.stderr,
            )
            return 2
        if target_paths:
            print(
                "Error: positional paths cannot be combined with --latest.",
                file=sys.stderr,
            )
            return 2
        from sesslint.discovery import latest_session

        try:
            target_paths = [latest_session(agent)]
        except (OSError, FileNotFoundError) as err:
            print(f"Error: {err}", file=sys.stderr)
            return 2
        agent = None

    if agent is not None and target_paths:
        print(
            "Warning: explicit PATH overrides --agent; scanning PATH only.",
            file=sys.stderr,
        )
        agent = None

    if agent is None and not target_paths:
        parser.print_help(sys.stderr)
        return 2

    try:
        check_baseline = _load_baseline_arg(args)
        scan_kwargs = build_scan_kwargs(args, baseline=check_baseline)
    except ValueError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 2

    def _emit_scan_rep(scan_rep: Any) -> int:
        _write_baseline_arg(args, [f for fr in scan_rep.files for f in fr.findings])

        # Attach the aggregated summary view (ux T-08): by-code grouping and
        # top-N worst files. Pure presentation — findings are unchanged.
        top_n = getattr(args, "top", 10)
        group_by = getattr(args, "group_by", "code")
        if top_n is not None and top_n < 0:
            print(f"Error: --top must be >= 0, got {top_n}", file=sys.stderr)
            return 2
        if group_by != "none" or (top_n or 0) > 0:
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

    # --seal binds one verdict artifact per line; aggregate scan modes
    # have no single subject artifact, so refuse rather than seal a
    # partial picture (evidence-assurance T-01).
    if getattr(args, "seal", None) is not None and (agent is not None or len(target_paths) != 1):
        print(
            "Error: --seal applies to single-file checks only "
            "(one artifact per line; scans are not sealed).",
            file=sys.stderr,
        )
        return 2

    if agent is not None:
        from sesslint.api import check_dir, discover_session_roots
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
        return _emit_scan_rep(scan_rep)

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

        format_opt = getattr(args, "adapter", "auto")
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

        from sesslint.report import minimize_path
        from sesslint.scan import FileResult, ScanReport, ScanTotals, scan_path

        multi_files: list[FileResult] = []
        totals = ScanTotals()
        for p in target_paths:
            try:
                rep = scan_path(p, **scan_kwargs)
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

        from sesslint.api import check_dir

        try:
            scan_rep = check_dir(target_path, **scan_kwargs)
        except (ValueError, KeyError) as err:
            err_msg = err.args[0] if err.args else str(err)
            print(f"Error: {err_msg}", file=sys.stderr)
            return 2

        return _emit_scan_rep(scan_rep)

    if not target_path.exists():
        print(f"Error: Path not found: {target_path}", file=sys.stderr)
        return 2

    if scan_kwargs["jobs"] > 1:
        print("Note: --jobs is ignored for single-file input.", file=sys.stderr)

    format_opt = getattr(args, "adapter", "auto")
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
