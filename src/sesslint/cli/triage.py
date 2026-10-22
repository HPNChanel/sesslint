"""The ``sesslint triage`` subcommand."""

from __future__ import annotations

import argparse
from typing import TYPE_CHECKING, Final

from sesslint.adapters.detect import VALID_FORMAT_OPTIONS
from sesslint.cli._common import _output_format
from sesslint.cli._options import _validate_positive_int, add_report_output_option, cli_path
from sesslint.cli._output import emit_text
from sesslint.io import DEFAULT_MAX_FILE_BYTES

if TYPE_CHECKING:
    from sesslint.cli._context import CliContext

NAME: Final[str] = "triage"


def configure(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> argparse.ArgumentParser:
    # triage: compose checking and previews without executing any action.
    sub = subparsers.add_parser(
        "triage",
        help="[read-only] Diagnose a session and explain the next steps.",
        description="Content-free evidence and repair previews; never repairs or resumes.",
    )
    sub.add_argument("path", type=cli_path, nargs="?")
    sub.add_argument("--agent", choices=["claude", "codex"])
    sub.add_argument("--latest", action="store_true")
    sub.add_argument("--adapter", choices=sorted(VALID_FORMAT_OPTIONS), default=argparse.SUPPRESS)
    sub.add_argument("--profile", default=argparse.SUPPRESS)
    sub.add_argument(
        "--policy",
        choices=["conservative", "salvage"],
        default=argparse.SUPPRESS,
        help="Explicit salvage opt-in compares both policies; never acknowledges side effects.",
    )
    sub.add_argument(
        "--state-copy",
        type=cli_path,
        help="Optional closed Codex registry copy outside live agent storage (no WAL).",
    )
    sub.add_argument(
        "--max-file-bytes", type=_validate_positive_int, default=DEFAULT_MAX_FILE_BYTES
    )
    sub.add_argument(
        "--include-content",
        action="store_true",
        default=argparse.SUPPRESS,
        help="[Invalid for triage] Triage never emits transcript content.",
    )
    out_group = sub.add_mutually_exclusive_group()
    out_group.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=["human", "json"],
        default=None,
        help="Output format (default: human)",
    )
    out_group.add_argument("--json", action="store_true")
    add_report_output_option(sub)
    return sub


def run(ctx: CliContext, args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from sesslint.discovery import latest_session
    from sesslint.triage import triage

    path = args.path
    if (path is None and not (args.latest and args.agent)) or (
        path is not None and (args.latest or args.agent is not None)
    ):
        ctx.error("Error: choose a file OR --agent claude|codex --latest.")
        return 2
    if getattr(args, "include_content", False):
        ctx.error("Error: triage does not support --include-content.")
        return 2
    try:
        target = path if path is not None else latest_session(args.agent)
        triage_result = triage(
            target,
            format=getattr(args, "adapter", None),
            profile=getattr(args, "profile", "neutral"),
            policy=getattr(args, "policy", "conservative"),
            state_copy=args.state_copy,
            max_file_bytes=args.max_file_bytes,
        )
    except (OSError, ValueError, KeyError):
        ctx.error("Error: triage input/discovery/options could not be resolved.")
        return 2
    emit_text(
        ctx,
        args,
        triage_result.to_json() if _output_format(args) == "json" else triage_result.render_human(),
        inputs=(target,),
        summary=f"{triage_result.finding_count} finding(s)",
    )
    return triage_result.exit_code
