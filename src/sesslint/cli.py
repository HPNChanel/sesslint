"""SessLint command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from sesslint import __version__, load_session_file
from sesslint._version import CLI_VERSION, get_version_info
from sesslint.adapters.canonical import SUPPORTED_CANONICAL_VERSIONS
from sesslint.adapters.claude_code import SUPPORTED_CLAUDE_VERSIONS
from sesslint.adapters.openai_agents import SUPPORTED_OPENAI_AGENTS_VERSIONS
from sesslint.errors import SesslintError
from sesslint.report import Report


def should_color(args: argparse.Namespace, stream: Any = sys.stdout) -> bool:
    """Determine whether color output should be enabled."""
    if getattr(args, "no_color", False):
        return False
    if getattr(args, "json", False):
        return False
    if "NO_COLOR" in os.environ and os.environ["NO_COLOR"]:
        return False
    color_opt = getattr(args, "color", "auto")
    if color_opt == "never":
        return False
    if color_opt == "always":
        return True
    return hasattr(stream, "isatty") and bool(stream.isatty())


def format_report_human(report: Report, *, color: bool = False) -> str:
    """Format Report as human-readable actionable text with optional ANSI colors."""
    green = "\033[32m" if color else ""
    red = "\033[31m" if color else ""
    yellow = "\033[33m" if color else ""
    bold = "\033[1m" if color else ""
    reset = "\033[0m" if color else ""

    lines: list[str] = []
    has_errors = (
        report.counts.by_severity.get("error", 0) > 0
        or report.counts.by_severity.get("fatal", 0) > 0
    )
    if not has_errors and report.counts.total == 0:
        lines.append(
            f"[read-only] {bold}{green}Session is healthy{reset} "
            f"(0 findings, assurance: {report.assurance})"
        )
        lines.append(f"Limitation: {report.limitation}")
        lines.append(f"Source fingerprint: {report.source_fingerprint}")
    elif not has_errors and report.counts.total > 0:
        warn_cnt = report.counts.by_severity.get("warning", 0)
        lines.append(
            f"[read-only] {bold}{yellow}Session is healthy with warnings{reset} "
            f"({warn_cnt} warning(s), assurance: {report.assurance})"
        )
        lines.append(f"Limitation: {report.limitation}")
        for f in report.findings:
            loc = f"{f.source.path}:{f.source.line}" if f.source.line else f.source.path
            lines.append(
                f"  [{f.code}] {yellow}{f.severity.value.upper()}{reset}: {f.message} ({loc})"
            )
    else:
        err_cnt = report.counts.by_severity.get("error", 0) + report.counts.by_severity.get(
            "fatal", 0
        )
        warn_cnt = report.counts.by_severity.get("warning", 0)
        lines.append(
            f"[read-only] {bold}{red}Integrity check failed{reset} "
            f"({err_cnt} error(s), {warn_cnt} warning(s), assurance: {report.assurance})"
        )
        lines.append(f"Limitation: {report.limitation}")
        root = report.findings[0]
        root_loc = (
            f"{root.source.path}:{root.source.line}" if root.source.line else root.source.path
        )
        lines.append(f"First root finding: [{root.code}] {root.message} ({root_loc})")
        lines.append("Findings:")
        for f in report.findings:
            loc = f"{f.source.path}:{f.source.line}" if f.source.line else f.source.path
            sev_color = red if f.severity.value in ("error", "fatal") else yellow
            lines.append(
                f"  [{f.code}] {sev_color}{f.severity.value.upper()}{reset} "
                f"({f.repairability.value}): {f.message} ({loc})"
            )
        if any(f.repairability.value == "lossy-explicit" for f in report.findings):
            lines.append(
                f"Recommended next command: sesslint repair {report.findings[0].source.path} "
                f"--output <output_path> --policy salvage"
            )
        elif any(f.repairability.value == "deterministic" for f in report.findings):
            lines.append(
                f"Recommended next command: sesslint repair {report.findings[0].source.path} "
                f"--output <output_path>"
            )
        else:
            lines.append(
                "Recommended next command: Review findings and inspect source artifact manually."
            )

    return "\n".join(lines)


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
        "-" * 80,
    ]
    for r in scan_report.files:
        if r.verdict == "healthy":
            tag = f"{green}[HEALTHY]{reset}"
            detail = ""
        elif r.verdict == "invalid":
            tag = f"{red}[INVALID]{reset}"
            detail = f" ({r.error_count} error(s), {r.warning_count} warning(s))"
        elif r.verdict == "unsupported":
            tag = f"{yellow}[UNSUPPORTED]{reset}"
            detail = " (unsupported version)"
        elif r.verdict == "unreadable":
            tag = f"{red}[UNREADABLE]{reset}"
            detail = " (read error or non-UTF8)"
        else:  # skipped
            tag = f"{bold}[SKIPPED]{reset}"
            detail = f" (reason: {r.skipped_reason})"
        lines.append(f"  {tag:<20} {r.path}{detail}")

    return "\n".join(lines)


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser for sesslint CLI."""
    parser = argparse.ArgumentParser(
        prog="sesslint",
        description=(
            "Offline, vendor-neutral session integrity checker and conservative repair tool."
        ),
        epilog=(
            "Exit codes:\n"
            "  0  Healthy session / verification passed / dry-run plan generated\n"
            "  1  Integrity findings detected / verification failed / repair refused\n"
            "  2  Usage error / invalid flag combination / I/O failure"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    parser.add_argument(
        "--format",
        choices=["auto", "claude-code-jsonl", "openai-agents", "canonical"],
        default="auto",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--profile",
        default="neutral",
        help="Replay validation profile (default: neutral)",
    )
    parser.add_argument(
        "--policy",
        choices=["conservative", "salvage"],
        default="conservative",
        help="Repair policy (choices: conservative, salvage; default: conservative)",
    )
    parser.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default="auto",
        help="Control colored terminal output (default: auto)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color styling (equivalent to NO_COLOR=1)",
    )

    subparsers = parser.add_subparsers(dest="command")

    # validate-session
    val_parser = subparsers.add_parser(
        "validate-session",
        help="[read-only] Validate a canonical session file against schema.",
        description="[read-only] Validate a canonical session file against schema.",
    )
    val_parser.add_argument(
        "path",
        type=Path,
        help="Path to session file (.json or .jsonl)",
    )

    # check
    check_parser = subparsers.add_parser(
        "check",
        help="[read-only] Check a session file with auto-detection.",
        description=(
            "[read-only] Check a session file for structural defects, causal breaks, "
            "and schema violations."
        ),
    )
    check_parser.add_argument(
        "path",
        type=Path,
        help="Path to session file (.json or .jsonl)",
    )
    check_parser.add_argument(
        "--format",
        choices=["auto", "claude-code-jsonl", "openai-agents", "canonical"],
        default=argparse.SUPPRESS,
        help="Session format adapter (default: auto)",
    )
    check_parser.add_argument(
        "--profile",
        default="neutral",
        help="Replay validation profile (default: neutral)",
    )
    check_parser.add_argument(
        "--policy",
        choices=["conservative", "salvage"],
        default="conservative",
        help="Repair policy (choices: conservative, salvage; default: conservative)",
    )
    check_parser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        default=False,
        help="Recursively scan directory trees for session artifacts",
    )
    check_parser.add_argument(
        "--follow-symlinks",
        action="store_true",
        default=False,
        help="[lossy: follows links] Follow directory symlinks during recursive scanning",
    )
    check_parser.add_argument(
        "--max-files",
        type=int,
        default=10000,
        help="Maximum number of files to inspect during recursive scan (default: 10000)",
    )
    check_parser.add_argument(
        "--max-bytes",
        type=int,
        default=1024 * 1024 * 1024,
        help="Maximum cumulative bytes to read during recursive scan (default: 1GB)",
    )
    check_parser.add_argument(
        "--json",
        action="store_true",
        help="Output check report as a single canonical JSON document to stdout",
    )
    check_parser.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default="auto",
        help="Control colored output in human report mode",
    )
    check_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color styling",
    )
    check_parser.add_argument(
        "--confidence-min",
        type=float,
        default=None,
        help="Format auto-detection minimum confidence threshold",
    )
    check_parser.add_argument(
        "--margin-min",
        type=float,
        default=None,
        help="Format auto-detection minimum margin threshold",
    )

    # formats
    formats_parser = subparsers.add_parser(
        "formats",
        help="[read-only] List supported session format adapters.",
        description=(
            "[read-only] List supported session format adapters and their supported version specs."
        ),
    )
    formats_parser.add_argument(
        "--json",
        action="store_true",
        help="Output supported formats as JSON array",
    )

    # version
    version_parser = subparsers.add_parser(
        "version",
        help="[read-only] Display detailed component and schema version information.",
        description="[read-only] Display detailed component and schema version information.",
    )
    version_parser.add_argument(
        "--json",
        action="store_true",
        help="Output version details as JSON object",
    )

    # scan
    scan_parser = subparsers.add_parser(
        "scan",
        help="[read-only] Scan a session file (limits diagnostic).",
        description="[read-only] Scan a session file (limits diagnostic).",
    )
    scan_parser.add_argument(
        "--show-limits",
        action="store_true",
        help="Display default hostile-input reader limits.",
    )

    # repair
    repair_parser = subparsers.add_parser(
        "repair",
        help=(
            "[writes: output file and manifest, lossy under --policy salvage] "
            "Safely repair a session file."
        ),
        description=(
            "[writes: output file and manifest, lossy under --policy salvage] "
            "Safely repair a session file with atomic execution."
        ),
    )
    repair_parser.add_argument(
        "path",
        type=Path,
        help="Path to source session file",
    )
    repair_parser.add_argument(
        "--output",
        "--out",
        "-o",
        type=Path,
        default=None,
        dest="output",
        help="Path to output repaired session file",
    )
    repair_parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Plan-only mode; do not write any files",
    )
    repair_parser.add_argument(
        "--policy",
        choices=["conservative", "salvage"],
        default="conservative",
        help="Repair policy (choices: conservative, salvage; default: conservative)",
    )
    repair_parser.add_argument(
        "--format",
        choices=["auto", "claude-code-jsonl", "openai-agents", "canonical"],
        default=argparse.SUPPRESS,
        help="Session format adapter (default: auto)",
    )
    repair_parser.add_argument(
        "--profile",
        default="neutral",
        help="Replay validation profile (default: neutral)",
    )
    repair_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output manifest or plan in JSON format",
    )
    repair_parser.add_argument(
        "--plan",
        type=Path,
        default=None,
        help="Path to pre-computed plan JSON file (optional)",
    )
    repair_parser.add_argument(
        "--acknowledge-side-effects",
        action="store_true",
        default=False,
        help="Acknowledge tool side-effects for salvage policy",
    )

    # verify
    verify_parser = subparsers.add_parser(
        "verify",
        help="[read-only] Verify integrity, hash bindings, and idempotence of a repaired session.",
        description=(
            "[read-only] Verify integrity, hash bindings, and idempotence of a repaired "
            "session artifact."
        ),
    )
    verify_parser.add_argument(
        "--source",
        type=Path,
        required=True,
        help="Path to source session file",
    )
    verify_parser.add_argument(
        "--plan",
        type=Path,
        required=True,
        help="Path to repair plan JSON file",
    )
    verify_parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Path to repaired session file",
    )
    verify_parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="Path to repair manifest JSON file",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point returning exit code."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help(sys.stdout)
        return 0

    if args.command == "formats":
        adapter_data = [
            {
                "default_profile": "neutral",
                "description": "SessLint Canonical Session Format v1 (JSON/JSONL)",
                "name": "canonical",
                "versions_supported": sorted(SUPPORTED_CANONICAL_VERSIONS),
            },
            {
                "default_profile": "claude-strict",
                "description": "Claude Code JSONL session logs adapter",
                "name": "claude-code-jsonl",
                "versions_supported": sorted(SUPPORTED_CLAUDE_VERSIONS),
            },
            {
                "default_profile": "openai-strict",
                "description": "OpenAI Agents SDK item-export adapter",
                "name": "openai-agents",
                "versions_supported": sorted(SUPPORTED_OPENAI_AGENTS_VERSIONS),
            },
        ]
        if getattr(args, "json", False):
            print(json.dumps(adapter_data, indent=2, sort_keys=True))
        else:
            print(f"{'NAME':<20} {'DEFAULT PROFILE':<18} {'SUPPORTED VERSIONS':<24} DESCRIPTION")
            print("-" * 80)
            for item in adapter_data:
                vers_str = ", ".join(item["versions_supported"])
                print(
                    f"{item['name']:<20} {item['default_profile']:<18} "
                    f"{vers_str:<24} {item['description']}"
                )
        return 0

    if args.command == "version":
        info = get_version_info()
        if getattr(args, "json", False):
            print(json.dumps(info, indent=2, sort_keys=True))
        else:
            print(f"SessLint CLI: {info['cli']}")
            print("Schemas:")
            print(f"  session:  {info['schema_session']}")
            print(f"  report:   {info['schema_report']}")
            print(f"  manifest: {info['schema_manifest']}")
            print("Adapters:")
            for k, v in sorted(info["adapters"].items()):
                print(f"  {k}: {v}")
            print("Profiles:")
            for k, v in sorted(info["profiles"].items()):
                print(f"  {k}: {v}")
        return 0

    if args.command == "scan":
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
        parser.print_help(sys.stderr)
        return 2

    if args.command == "validate-session":
        try:
            session = load_session_file(args.path)
            print(f"Valid session: {session.header.session_id} ({len(session.events)} events)")
            return 0
        except SesslintError as err:
            print(f"Validation error [{err.code}]: {err}", file=sys.stderr)
            return 1
        except FileNotFoundError as err:
            print(f"Error: {err}", file=sys.stderr)
            return 2
        except Exception as err:
            print(f"Unexpected error: {err}", file=sys.stderr)
            return 2

    if args.command == "check":
        target_path: Path = args.path
        if target_path.is_dir():
            if not getattr(args, "recursive", False):
                print(
                    f"Error: Path {target_path} is a directory. "
                    "Directories are not supported without --recursive (see task 024).",
                    file=sys.stderr,
                )
                return 2

            from sesslint.api import check_dir

            scan_rep = check_dir(
                target_path,
                recursive=True,
                follow_symlinks=getattr(args, "follow_symlinks", False),
                max_files=getattr(args, "max_files", 10000),
                max_bytes=getattr(args, "max_bytes", 1024 * 1024 * 1024),
                format=getattr(args, "format", "auto"),
                profile=getattr(args, "profile", "neutral"),
            )

            if getattr(args, "json", False):
                print(scan_rep.to_json())
            else:
                use_color = should_color(args, sys.stdout)
                print(format_scan_report_human(scan_rep, color=use_color))

            if (
                scan_rep.totals.invalid > 0
                or scan_rep.totals.unsupported > 0
                or scan_rep.totals.unreadable > 0
            ):
                return 1
            return 0

        if not target_path.exists():
            print(f"Error: Path not found: {target_path}", file=sys.stderr)
            return 2

        format_opt = getattr(args, "format", "auto")
        profile_opt = getattr(args, "profile", "neutral")
        from sesslint.profiles import resolve_effective_config

        try:
            effective_cfg = resolve_effective_config(
                profile_opt,
                format=format_opt if format_opt != "auto" else None,
                confidence_min=getattr(args, "confidence_min", None),
                margin_min=getattr(args, "margin_min", None),
            )
        except Exception as err:
            parser.error(str(err))

        if not effective_cfg.allowed_adapters:
            print(f"Profile {effective_cfg.profile} has empty adapter allowlist", file=sys.stderr)
            return 2

        from sesslint.adapters.detect import (
            FORMAT_CANONICAL,
            FORMAT_CLAUDE_CODE,
            FORMAT_OPENAI_AGENTS,
            resolve_format,
        )

        try:
            resolved_fmt, detection_res, det_findings = resolve_format(format_opt, target_path)
            if resolved_fmt is None:
                if detection_res and detection_res.reason in ("tie", "low-confidence", "empty"):
                    print(
                        "Format detection ambiguous. Please specify --format explicitly "
                        "(see sesslint formats).",
                        file=sys.stderr,
                    )
                    if detection_res.confidences:
                        sorted_conf = dict(sorted(detection_res.confidences.items()))
                        print(
                            f"Candidate confidences: {sorted_conf}",
                            file=sys.stderr,
                        )
                if det_findings:
                    f = det_findings[0]
                    print(f"Format detection error [{f.code}]: {f.message}", file=sys.stderr)
                else:
                    print(f"Format detection failed for {target_path}", file=sys.stderr)

                if getattr(args, "json", False):
                    from sesslint.codes import SL302, Repairability, Severity
                    from sesslint.finding import SourceRef, make_finding
                    from sesslint.report import build_report, dump_report
                    from sesslint.source import fingerprint_file

                    rep_findings = (
                        list(det_findings)
                        if det_findings
                        else [
                            make_finding(
                                code=SL302,
                                severity=Severity.ERROR,
                                repairability=Repairability.MANUAL,
                                message_template="Format detection failed [detail: {detail}]",
                                source=SourceRef(path=str(target_path)),
                                template_args={
                                    "detail": detection_res.reason if detection_res else "unknown"
                                },
                            )
                        ]
                    )
                    fp = fingerprint_file(target_path) if target_path.is_file() else "0" * 64
                    rep = build_report(
                        session_id=target_path.stem,
                        source_fingerprint=fp,
                        tool_version=CLI_VERSION,
                        findings=rep_findings,
                        assurance="A0",
                        limitation="No structural conclusion.",
                    )
                    print(dump_report(rep))
                return 1

            fmt_key = (
                "claude"
                if resolved_fmt == FORMAT_CLAUDE_CODE
                else (
                    "openai"
                    if resolved_fmt == FORMAT_OPENAI_AGENTS
                    else ("canonical" if resolved_fmt == FORMAT_CANONICAL else resolved_fmt)
                )
            )
            if (
                fmt_key not in effective_cfg.allowed_adapters
                and resolved_fmt not in effective_cfg.allowed_adapters
            ):
                print(
                    f"Format {resolved_fmt} is not permitted by profile {effective_cfg.profile}",
                    file=sys.stderr,
                )
                return 2

            events: list[Any] = []
            adapter_findings: list[Any] = list(det_findings)

            if resolved_fmt == FORMAT_CANONICAL:
                from sesslint.adapters.canonical import load_canonical

                can_events, can_findings = load_canonical(target_path)
                events = list(can_events)
                adapter_findings.extend(can_findings)
                format_display = "canonical"
            elif resolved_fmt == FORMAT_CLAUDE_CODE:
                from sesslint.adapters.claude_code import load_claude_code

                c_events, c_findings = load_claude_code(target_path)
                events = list(c_events)
                adapter_findings.extend(c_findings)
                format_display = "Claude Code"
            elif resolved_fmt == FORMAT_OPENAI_AGENTS:
                from sesslint.adapters.openai_agents import load_openai_agents

                o_events, o_findings = load_openai_agents(target_path)
                events = list(o_events)
                adapter_findings.extend(o_findings)
                format_display = "OpenAI Agents"
            else:
                print(f"Unsupported format: {resolved_fmt}", file=sys.stderr)
                return 2

            from sesslint.codes import Severity
            from sesslint.repair.executor import run_all_checks
            from sesslint.report import Assurance, build_report, dump_report
            from sesslint.source import fingerprint_file

            check_findings = run_all_checks(
                events,
                profile=effective_cfg.profile,
                source_path=str(target_path),
            )
            all_findings = list(adapter_findings) + list(check_findings)

            session_id: str = target_path.stem
            if (
                hasattr(events, "source")
                and isinstance(events.source, dict)
                and events.source.get("session_id")
            ):
                session_id = str(events.source["session_id"])
            elif events and hasattr(events[0], "session_id") and events[0].session_id:
                session_id = str(events[0].session_id)

            has_error = any(f.severity in (Severity.ERROR, Severity.FATAL) for f in all_findings)
            has_warning = any(f.severity == Severity.WARNING for f in all_findings)

            assurance: Assurance
            if has_error:
                assurance = "A0"
                limitation = "No structural conclusion."
            elif has_warning:
                assurance = "A1"
                limitation = "Relationships may still be invalid."
            else:
                assurance = "A2"
                limitation = "Provider/runtime replay has not been independently exercised."

            fp = fingerprint_file(target_path)
            report = build_report(
                session_id=session_id,
                source_fingerprint=fp,
                tool_version=CLI_VERSION,
                findings=all_findings,
                assurance=assurance,
                limitation=limitation,
            )

            exit_code = 1 if has_error else 0

            if getattr(args, "json", False):
                print(dump_report(report))
                return exit_code
            else:
                use_color = should_color(args, sys.stdout)
                human_text = format_report_human(report, color=use_color)
                # Ensure existing test compatibility by printing Valid format summary line
                if not has_error:
                    print(f"Valid {format_display} session ({len(events)} events)")
                print(human_text)
                return exit_code

        except SesslintError as err:
            print(f"Validation error [{err.code}]: {err}", file=sys.stderr)
            return 1
        except FileNotFoundError as err:
            print(f"Error: {err}", file=sys.stderr)
            return 2
        except Exception as err:
            print(f"Unexpected error: {err}", file=sys.stderr)
            return 2

    if args.command == "repair":
        if not args.dry_run and args.output is None:
            print("Error: --output is required unless --dry-run is specified.", file=sys.stderr)
            return 2

        if not args.path.is_file():
            print(f"Error: Source file not found: {args.path}", file=sys.stderr)
            return 2

        policy_opt = getattr(args, "policy", "conservative")
        profile_opt = getattr(args, "profile", "neutral")
        ack_side_effects = getattr(args, "acknowledge_side_effects", False)
        format_opt = getattr(args, "format", "auto")

        from sesslint.adapters.detect import VALID_FORMAT_OPTIONS

        if format_opt not in VALID_FORMAT_OPTIONS:
            print(f"Error: Unsupported format option: {format_opt}", file=sys.stderr)
            return 2

        from sesslint.codes import Severity
        from sesslint.repair import (
            Abstained,
            OutputInvalid,
            PlanTampered,
            PolicyMismatch,
            RepairPlan,
            RepairRefused,
            execute,
            load_plan,
            load_session_source,
            run_all_checks,
        )
        from sesslint.repair.planner import plan as planner_plan
        from sesslint.report import dump_manifest

        plan_obj: RepairPlan
        if getattr(args, "plan", None) is not None:
            try:
                plan_obj = load_plan(args.plan)
            except Exception as err:
                print(f"Error loading plan: {err}", file=sys.stderr)
                return 2
        else:
            try:
                _source_header, source_events = load_session_source(args.path)
                source_findings = run_all_checks(
                    source_events,
                    profile=profile_opt,
                    source_path=str(args.path),
                )
                plan_obj = planner_plan(
                    findings=source_findings,
                    events=source_events,
                    profile=profile_opt,
                    policy=policy_opt,
                    acknowledge_side_effects=ack_side_effects,
                )
            except SesslintError as err:
                print(f"Error preparing repair plan [{err.code}]: {err}", file=sys.stderr)
                return 1
            except Exception as err:
                print(f"Error preparing repair plan: {err}", file=sys.stderr)
                return 2

            has_error_findings = any(
                f.severity in (Severity.ERROR, Severity.FATAL) for f in source_findings
            )
            if has_error_findings and len(plan_obj.steps) == 0:
                print(
                    "Findings exist on source session, but no authorized safe "
                    "repair plan completes.",
                    file=sys.stderr,
                )
                return 1

        try:
            manifest = execute(
                source_path=args.path,
                plan=plan_obj,
                output_path=args.output,
                policy=policy_opt,
                dry_run=args.dry_run,
                profile=profile_opt,
                format=format_opt if format_opt != "auto" else None,
                acknowledge_side_effects=ack_side_effects,
            )
            if args.dry_run:
                if getattr(args, "json", False):
                    print(json.dumps(plan_obj.to_dict(), indent=2, sort_keys=True))
                else:
                    print(f"Plan fingerprint: {plan_obj.fingerprint}")
                    print(f"Policy: {plan_obj.policy}")
                    print(f"Proposed steps: {len(plan_obj.steps)}")
                    print(f"Blocked findings: {len(plan_obj.blocked)}")
                return 0

            if getattr(args, "json", False):
                print(dump_manifest(manifest))
            else:
                print(f"Repair successful. Output: {args.output}")
                print(f"Manifest written to: {args.output}.manifest.json")
                print(f"Output fingerprint: {manifest.output_fingerprint}")
                print(f"Idempotency key: {manifest.idempotency_key}")
            return 0
        except (PlanTampered, Abstained, PolicyMismatch, OutputInvalid, RepairRefused) as err:
            print(f"Repair refused [{err.code}]: {err}", file=sys.stderr)
            return 1
        except FileNotFoundError as err:
            print(f"File error: {err}", file=sys.stderr)
            return 2
        except Exception as err:
            print(f"Unexpected error: {err}", file=sys.stderr)
            return 2

    if args.command == "verify":
        try:
            from sesslint.verify import verify

            verdict = verify(
                source_path=args.source,
                plan_path=args.plan,
                output_path=args.output,
                manifest_path=args.manifest,
            )
            print(verdict.to_json())
            return 0 if verdict.ok else 1
        except (FileNotFoundError, OSError) as err:
            print(f"Verify I/O error: {err}", file=sys.stderr)
            return 2
        except Exception as err:
            print(f"Verify error: {err}", file=sys.stderr)
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
