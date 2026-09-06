"""SessLint command line interface."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from sesslint import __version__, load_session_file
from sesslint.errors import SesslintError


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser for sesslint CLI."""
    parser = argparse.ArgumentParser(
        prog="sesslint",
        description=(
            "Offline, vendor-neutral session integrity checker and conservative repair tool."
        ),
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

    subparsers = parser.add_subparsers(dest="command")
    val_parser = subparsers.add_parser(
        "validate-session",
        help="Validate a canonical session file against schema.",
    )
    val_parser.add_argument(
        "path",
        type=Path,
        help="Path to session file (.json or .jsonl)",
    )

    check_parser = subparsers.add_parser(
        "check",
        help="Check a session file with auto-detection.",
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

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a session file (limits diagnostic).",
    )
    scan_parser.add_argument(
        "--show-limits",
        action="store_true",
        help="Display default hostile-input reader limits.",
    )

    repair_parser = subparsers.add_parser(
        "repair",
        help="Safely repair a session file with atomic execution.",
    )
    repair_parser.add_argument(
        "path",
        type=Path,
        help="Path to source session file",
    )
    repair_parser.add_argument(
        "--output",
        type=Path,
        default=None,
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

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point returning exit code."""
    parser = create_parser()
    args = parser.parse_args(argv)

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
        except (KeyError, ValueError) as err:
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
            resolved_fmt, _detection_res, findings = resolve_format(format_opt, args.path)
            if resolved_fmt is None:
                if findings:
                    f = findings[0]
                    print(f"Format detection error [{f.code}]: {f.message}", file=sys.stderr)
                else:
                    print(f"Format detection failed for {args.path}", file=sys.stderr)
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

            if resolved_fmt == FORMAT_CANONICAL:
                from sesslint.adapters.canonical import load_canonical

                can_events, can_findings = load_canonical(args.path)
                if can_findings:
                    f = can_findings[0]
                    print(f"Validation error [{f.code}]: {f.message}", file=sys.stderr)
                    return 1
                session_id = (
                    can_events.source.get("session_id")
                    if hasattr(can_events, "source") and isinstance(can_events.source, dict)
                    else None
                )
                if session_id:
                    print(f"Valid session: {session_id} ({len(can_events)} events)")
                else:
                    print(f"Valid canonical session ({len(can_events)} events)")
                return 0
            elif resolved_fmt == FORMAT_CLAUDE_CODE:
                from sesslint.adapters.claude_code import load_claude_code

                c_events, c_findings = load_claude_code(args.path)
                if c_findings:
                    f = c_findings[0]
                    print(f"Validation error [{f.code}]: {f.message}", file=sys.stderr)
                    return 1
                print(f"Valid Claude Code session ({len(c_events)} events)")
                return 0
            elif resolved_fmt == FORMAT_OPENAI_AGENTS:
                from sesslint.adapters.openai_agents import load_openai_agents

                o_events, o_findings = load_openai_agents(args.path)
                if o_findings:
                    f = o_findings[0]
                    print(f"Validation error [{f.code}]: {f.message}", file=sys.stderr)
                    return 1
                print(f"Valid OpenAI Agents session ({len(o_events)} events)")
                return 0
            else:
                print(f"Unsupported format: {resolved_fmt}", file=sys.stderr)
                return 2
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

            # If structural error findings exist on source, but no plannable steps could be produced
            has_error_findings = any(
                f.severity in (Severity.ERROR, Severity.FATAL) for f in source_findings
            )
            if has_error_findings and len(plan_obj.steps) == 0:
                print(
                    "Findings exist on source session, but no authorized safe repair plan "
                    "completes.",
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
                    import json

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

    return 0


if __name__ == "__main__":
    sys.exit(main())
