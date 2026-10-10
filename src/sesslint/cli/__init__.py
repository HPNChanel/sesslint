"""SessLint command line interface."""

from __future__ import annotations

import argparse
import io
import sys
from collections.abc import Sequence

from sesslint import __version__, api
from sesslint.adapters.detect import VALID_FORMAT_OPTIONS
from sesslint.cli._common import FORMAT_DISPLAY_NAMES, _handle_internal_error, should_color
from sesslint.cli._options import add_policy_option
from sesslint.cli._registry import COMMANDS
from sesslint.cli._render import format_scan_report_human
from sesslint.progress import OperationCancelled

__all__ = [
    "FORMAT_DISPLAY_NAMES",
    "_handle_internal_error",
    "create_parser",
    "format_scan_report_human",
    "load_session_file",
    "main",
    "should_color",
]

load_session_file = api.validate_session


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
        choices=sorted(VALID_FORMAT_OPTIONS),
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--profile",
        default=argparse.SUPPRESS,
        help="Replay validation profile (default: neutral)",
    )
    add_policy_option(parser)
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
    for command in COMMANDS:
        command.configure(subparsers)

    return parser


_COMMANDS_BY_NAME = {command.name: command for command in COMMANDS}


def _dispatch(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """Dispatch parsed CLI command and return exit code."""
    if getattr(args, "include_content", False):
        sys.stderr.write(
            "WARNING: --include-content embeds raw transcript content; do not share output\n"
        )
        sys.stderr.flush()

    # --policy only takes effect on 'repair'; warn instead of silently ignoring
    # (e.g. 'sesslint --policy salvage check' reads as if it applies).
    if (
        getattr(args, "command", None) not in (None, "repair", "triage")
        and getattr(args, "policy", None) is not None
    ):
        sys.stderr.write(
            f"WARNING: --policy has no effect on '{args.command}' (it only applies to 'repair')\n"
        )
        sys.stderr.flush()

    if args.command is None:
        parser.print_help(sys.stdout)
        return 2

    command = _COMMANDS_BY_NAME.get(args.command)
    if command is not None:
        return command.run(args, parser)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point returning exit code with top-level safety guarantees."""
    # T-12: redirected Windows streams otherwise use the legacy ANSI code page.
    # Reports and diagnostics must accept Unicode filenames even in a frozen
    # executable, where PYTHONUTF8 may be ignored. Leave caller-owned StringIO
    # and other custom streams untouched; importing the API has no side effects.
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(encoding="utf-8")
    parser = create_parser()
    args = parser.parse_args(argv)

    try:
        return _dispatch(args, parser)
    except KeyboardInterrupt:
        print("Operation cancelled by user", file=sys.stderr)
        return 130
    except OperationCancelled:
        # Cooperative cancellation keeps the same CLI exit semantics as
        # Ctrl+C (DW-T-13): cleanup already ran inside the callee.
        print("Operation cancelled", file=sys.stderr)
        return 130
    except FileNotFoundError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 2
    except Exception as err:
        return _handle_internal_error(err, args)
