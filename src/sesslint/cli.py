"""SessLint command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final, Literal

from sesslint import __version__, load_session_file
from sesslint._version import get_version_info
from sesslint.adapters.canonical import SUPPORTED_CANONICAL_VERSIONS
from sesslint.adapters.claude_code import SUPPORTED_CLAUDE_VERSIONS
from sesslint.adapters.openai_agents import SUPPORTED_OPENAI_AGENTS_VERSIONS
from sesslint.errors import SesslintError

FORMAT_DISPLAY_NAMES: Final[dict[str, str]] = {
    "canonical": "canonical",
    "claude-code-jsonl": "Claude Code",
    "openai-agents": "OpenAI Agents",
}


def _handle_internal_error(err: Exception, args: argparse.Namespace | None = None) -> int:
    """Handle unexpected internal operational errors per FR-097, FR-098, FR-099.

    Guarantees:
    - Generates a unique, content-free diagnostic ID matching ^ERR-[0-9a-f]{8}$.
    - In JSON mode: outputs a JSON envelope to stdout with verdict='error', code='INTERNAL_ERROR',
      error_id, and message.
    - In human mode: outputs actionable error information to stderr.
    - Never prints raw Python tracebacks to stdout.
    - Never verdicts healthy.
    - Exits with return code 2.
    """
    import secrets

    error_id = f"ERR-{secrets.token_hex(4)}"
    is_json = getattr(args, "json", False) if args is not None else False
    if is_json:
        envelope = {
            "code": "INTERNAL_ERROR",
            "error_id": error_id,
            "message": str(err),
            "verdict": "error",
        }
        print(json.dumps(envelope, sort_keys=True))
    else:
        print(f"Operational error [{error_id}]: {err}", file=sys.stderr)
    return 2


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
            "  2  Usage error / invalid flag combination / I/O failure\n\n"
            "Important Notes:\n"
            "  - redaction is best-effort minimization, not a completeness guarantee\n"
            "  - sesslint makes no semantic or side-effect safety claims"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--include-content",
        action="store_true",
        default=False,
        help="Embed raw transcript content in reports (warning: emits raw sensitive data)",
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
        dest="check_policy",
        default=None,
        help="[Invalid for check] Repair policy is only applicable to 'repair'",
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
    check_parser.add_argument(
        "--include-content",
        action="store_true",
        default=False,
        help="Embed raw transcript content in reports (warning: emits raw sensitive data)",
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
        help="[read-only] Scan directory trees for session artifacts or display limits.",
        description="[read-only] Scan directory trees for session artifacts or display limits.",
    )
    scan_parser.add_argument(
        "path",
        type=Path,
        nargs="?",
        default=None,
        help="Directory path to scan (or omit when using --show-limits)",
    )
    scan_parser.add_argument(
        "--show-limits",
        action="store_true",
        help="Display default hostile-input reader limits.",
    )
    scan_parser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        default=True,
        help="Recursively scan directory trees (default: True)",
    )
    scan_parser.add_argument(
        "--follow-symlinks",
        action="store_true",
        default=False,
        help="Follow directory symlinks during scan",
    )
    scan_parser.add_argument(
        "--max-files",
        type=int,
        default=10000,
        help="Maximum files to scan (default: 10000)",
    )
    scan_parser.add_argument(
        "--max-bytes",
        type=int,
        default=1024 * 1024 * 1024,
        help="Maximum cumulative bytes to read during recursive scan (default: 1GB)",
    )
    scan_parser.add_argument(
        "--format",
        choices=["auto", "claude-code-jsonl", "openai-agents", "canonical"],
        default="auto",
        help="Session format adapter (default: auto)",
    )
    scan_parser.add_argument(
        "--profile",
        default="neutral",
        help="Replay validation profile (default: neutral)",
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Output scan report as JSON",
    )
    scan_parser.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default="auto",
        help="Control colored terminal output",
    )
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color styling",
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
    repair_parser.add_argument(
        "--salvage-unsupported",
        action="store_true",
        default=False,
        help="[Deprecated] Use '--policy salvage' instead",
    )
    repair_parser.add_argument(
        "--include-content",
        action="store_true",
        default=False,
        help="Embed raw transcript content in manifests (warning: emits raw sensitive data)",
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
        "source",
        type=Path,
        nargs="?",
        default=None,
        help="Path to source session file",
    )
    verify_parser.add_argument(
        "repaired",
        type=Path,
        nargs="?",
        default=None,
        help="Path to repaired session file",
    )
    verify_parser.add_argument(
        "--source",
        type=Path,
        default=None,
        dest="source_flag",
        help=argparse.SUPPRESS,
    )
    verify_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        dest="output_flag",
        help=argparse.SUPPRESS,
    )
    verify_parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="Path to repair manifest JSON file",
    )
    verify_parser.add_argument(
        "--plan",
        type=Path,
        default=None,
        help="Path to repair plan JSON file (optional)",
    )
    verify_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output verify verdict as JSON to stdout",
    )
    verify_parser.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default="auto",
        help="Control colored output in human report mode",
    )
    verify_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color styling",
    )
    verify_parser.add_argument(
        "--acknowledge-side-effects",
        action="store_true",
        default=False,
        help="Acknowledge tool side-effects for salvage policy during verify idempotence check",
    )
    verify_parser.add_argument(
        "--include-content",
        action="store_true",
        default=False,
        help="Embed raw transcript content (warning: emits raw sensitive data)",
    )

    # bundle
    bundle_parser = subparsers.add_parser(
        "bundle",
        help="[read-only] Generate a privacy-safe diagnostic support bundle and fixture skeleton.",
        description=(
            "[read-only] Generate a privacy-safe diagnostic support bundle and fixture skeleton."
        ),
    )
    bundle_parser.add_argument(
        "path",
        type=Path,
        help="Path to session file (.json or .jsonl)",
    )
    bundle_parser.add_argument(
        "--output",
        "--out",
        "-o",
        type=Path,
        default=None,
        dest="output",
        help="Path to output bundle JSON file",
    )
    bundle_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output bundle as JSON to stdout",
    )
    bundle_parser.add_argument(
        "--format",
        choices=["auto", "claude-code-jsonl", "openai-agents", "canonical"],
        default="auto",
        help="Session format adapter (default: auto)",
    )
    bundle_parser.add_argument(
        "--profile",
        default="neutral",
        help="Replay validation profile (default: neutral)",
    )
    bundle_parser.add_argument(
        "--confidence-min",
        type=float,
        default=None,
        help="Minimum confidence threshold for format auto-detection",
    )
    bundle_parser.add_argument(
        "--margin-min",
        type=float,
        default=None,
        help="Minimum margin threshold between top candidates for auto-detection",
    )

    return parser


def _dispatch_command(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """Dispatch parsed CLI command and return exit code."""
    if getattr(args, "include_content", False):
        sys.stderr.write(
            "WARNING: --include-content embeds raw transcript content; do not share output\n"
        )
        sys.stderr.flush()

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

        if getattr(args, "path", None) is None:
            parser.print_help(sys.stderr)
            return 2

        target_scan_path: Path = args.path
        if not target_scan_path.exists():
            print(f"Error: Path not found: {target_scan_path}", file=sys.stderr)
            return 2

        from sesslint.api import check_dir

        scan_rep = check_dir(
            target_scan_path,
            recursive=getattr(args, "recursive", True),
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
        if getattr(args, "check_policy", None) is not None:
            print(
                "Error: The --policy option is only valid for 'repair', not 'check'.",
                file=sys.stderr,
            )
            return 2

        target_path: Path = args.path
        if target_path.is_dir():
            if not getattr(args, "recursive", False):
                print(
                    f"Error: Path {target_path} is a directory. "
                    "Use --recursive to scan directories.",
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

        try:
            from sesslint.api import check_file

            try:
                report = check_file(
                    target_path,
                    format=format_opt if format_opt != "auto" else None,
                    profile=profile_opt,
                    confidence_min=getattr(args, "confidence_min", None),
                    margin_min=getattr(args, "margin_min", None),
                )
            except (ValueError, KeyError) as err:
                if "not permitted by profile" in str(err):
                    print(str(err), file=sys.stderr)
                    return 2
                parser.error(str(err))

            has_error = (
                report.counts.by_severity.get("error", 0) > 0
                or report.counts.by_severity.get("fatal", 0) > 0
            )
            exit_code = 1 if has_error else 0

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

            if has_detection_or_version_failure:
                target_disp = str(target_path).replace("\\", "/")
                print(
                    f"hint: run 'sesslint bundle {target_disp}' "
                    "and attach the output to an adapter request",
                    file=sys.stderr,
                )

            adapter_id = report.coverage.adapter.get("id", "canonical")
            format_display = FORMAT_DISPLAY_NAMES.get(adapter_id, adapter_id)

            if getattr(args, "json", False):
                from sesslint.report import build_repro_metadata, render_json

                repro_meta = build_repro_metadata(
                    adapter_name=format_display,
                    profile_name=report.coverage.profile.get("id", profile_opt),
                    detection_method="manual" if format_opt != "auto" else "auto",
                    detection_confidence=1.0,
                )
                print(
                    render_json(
                        report,
                        include_content=getattr(args, "include_content", False),
                        repro=repro_meta,
                    )
                )
                return exit_code
            else:
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

        except SesslintError as err:
            print(f"Validation error [{err.code}]: {err}", file=sys.stderr)
            return 1
        except FileNotFoundError as err:
            print(f"Error: {err}", file=sys.stderr)
            return 2
        except Exception as err:
            return _handle_internal_error(err, args)

    if args.command == "repair":
        if getattr(args, "salvage_unsupported", False):
            print(
                "Error: The --salvage-unsupported flag has been deprecated and removed. "
                "Please use '--policy salvage' instead.",
                file=sys.stderr,
            )
            return 2

        if not args.dry_run and args.output is None:
            print("Error: --output is required unless --dry-run is specified.", file=sys.stderr)
            return 2

        if not args.path.is_file():
            print(f"Error: Source file not found: {args.path}", file=sys.stderr)
            return 2

        policy_opt: Literal["conservative", "salvage"] = (
            "salvage" if getattr(args, "policy", "conservative") == "salvage" else "conservative"
        )
        profile_opt = getattr(args, "profile", "neutral")
        ack_side_effects = getattr(args, "acknowledge_side_effects", False)
        format_opt = getattr(args, "format", "auto")

        from sesslint.adapters.detect import (
            FORMAT_CLAUDE_CODE,
            FORMAT_OPENAI_AGENTS,
            VALID_FORMAT_OPTIONS,
            detect_format,
        )
        from sesslint.profiles.profile import get_profile

        if format_opt not in VALID_FORMAT_OPTIONS:
            print(f"Error: Unsupported format option: {format_opt}", file=sys.stderr)
            return 2

        # RVW-019: Direct repair of vendor formats is rejected (canonical only)
        vendor_err_msg = (
            "Repair operates exclusively on canonical session streams (JSONL). "
            "Convert the session to canonical format first, or run 'check' to view findings."
        )
        if format_opt in (FORMAT_CLAUDE_CODE, FORMAT_OPENAI_AGENTS):
            print(
                f"Error: Direct repair of vendor format '{format_opt}' is not supported. "
                f"{vendor_err_msg}",
                file=sys.stderr,
            )
            return 2

        if format_opt == "auto":
            det = detect_format(args.path)
            if det.format in (FORMAT_CLAUDE_CODE, FORMAT_OPENAI_AGENTS):
                print(
                    f"Error: Direct repair of vendor format '{det.format}' is not supported. "
                    f"{vendor_err_msg}",
                    file=sys.stderr,
                )
                return 2

        try:
            get_profile(profile_opt)
        except (KeyError, ValueError) as err:
            err_msg = err.args[0] if err.args else str(err)
            print(f"Error: {err_msg}", file=sys.stderr)
            return 2

        from sesslint import api
        from sesslint.repair import (
            Abstained,
            OutputInvalid,
            PlanSourceMismatch,
            PlanTampered,
            PolicyMismatch,
            RepairRefused,
        )
        from sesslint.report import dump_manifest

        try:
            plan_obj, manifest = api.repair(
                source_path=args.path,
                output_path=args.output,
                policy=policy_opt,
                format=format_opt if format_opt != "auto" else None,
                profile=profile_opt,
                plan_path=getattr(args, "plan", None),
                dry_run=args.dry_run,
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

            if manifest is not None:
                if getattr(args, "json", False):
                    print(dump_manifest(manifest))
                else:
                    print(f"Repair successful. Output: {args.output}")
                    print(f"Manifest written to: {args.output}.manifest.json")
                    print(f"Output fingerprint: {manifest.output_fingerprint}")
                    print(f"Idempotency key: {manifest.idempotency_key}")
            return 0
        except (
            PlanTampered,
            Abstained,
            PolicyMismatch,
            OutputInvalid,
            RepairRefused,
            PlanSourceMismatch,
        ) as err:
            print(f"Repair refused [{err.code}]: {err}", file=sys.stderr)
            return 1
        except FileNotFoundError as err:
            print(f"File error: {err}", file=sys.stderr)
            return 2
        except Exception as err:
            return _handle_internal_error(err, args)

    if args.command == "verify":
        source_target = args.source or getattr(args, "source_flag", None)
        repaired_target = args.repaired or getattr(args, "output_flag", None)

        if source_target is None or repaired_target is None:
            parser.error("sesslint verify requires both source and repaired session paths.")

        try:
            from sesslint import api
            from sesslint.verify import render_verify_human

            verdict = api.verify(
                source_path=source_target,
                output_path=repaired_target,
                manifest_path=args.manifest,
                plan_path=getattr(args, "plan", None),
                acknowledge_side_effects=getattr(args, "acknowledge_side_effects", False),
            )
            use_json = getattr(args, "json", False)
            is_legacy_flags = args.source is None and getattr(args, "source_flag", None) is not None
            if use_json or is_legacy_flags:
                print(verdict.to_json())
            else:
                use_color = should_color(args, sys.stdout)
                print(render_verify_human(verdict, color=use_color))
            return 0 if verdict.ok else 1
        except (FileNotFoundError, OSError) as err:
            print(f"Verify I/O error: {err}", file=sys.stderr)
            return 2
        except Exception as err:
            return _handle_internal_error(err, args)

    if args.command == "bundle":
        target_bundle_path: Path = args.path
        if not target_bundle_path.exists():
            print(f"Error: Path not found: {target_bundle_path}", file=sys.stderr)
            return 2
        if target_bundle_path.is_dir():
            print(
                "Error: Path is a directory. "
                f"Bundle requires a single session file: {target_bundle_path}",
                file=sys.stderr,
            )
            return 2

        from sesslint.api import build_bundle

        format_opt = getattr(args, "format", "auto")
        profile_opt = getattr(args, "profile", "neutral")

        try:
            bundle = build_bundle(
                target_bundle_path,
                format=format_opt if format_opt != "auto" else None,
                profile=profile_opt,
                confidence_min=getattr(args, "confidence_min", None),
                margin_min=getattr(args, "margin_min", None),
            )
        except (ValueError, KeyError) as err:
            if "not permitted by profile" in str(err):
                print(str(err), file=sys.stderr)
                return 2
            parser.error(str(err))
        except FileNotFoundError as err:
            print(f"Error: {err}", file=sys.stderr)
            return 2
        except Exception as err:
            return _handle_internal_error(err, args)

        bundle_json = bundle.to_json()

        out_path: Path | None = getattr(args, "output", None)
        if out_path is not None:
            try:
                from sesslint.atomic import atomic_write_text

                atomic_write_text(out_path, bundle_json)
            except Exception as err:
                print(f"Error writing bundle to {out_path}: {err}", file=sys.stderr)
                return 2

            if getattr(args, "json", False):
                print(bundle_json.rstrip("\n"))
            else:
                print(f"Diagnostic bundle written to: {out_path}")
            return 0

        # No --out specified: emit bundle JSON to stdout
        print(bundle_json.rstrip("\n"))
        return 0

    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point returning exit code with top-level safety guarantees."""
    parser = create_parser()
    args = parser.parse_args(argv)

    try:
        return _dispatch_command(args, parser)
    except KeyboardInterrupt:
        print("Operation cancelled by user", file=sys.stderr)
        return 130
    except FileNotFoundError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 2
    except Exception as err:
        return _handle_internal_error(err, args)


if __name__ == "__main__":
    sys.exit(main())
