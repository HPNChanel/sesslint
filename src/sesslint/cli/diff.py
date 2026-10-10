"""The ``sesslint diff`` subcommand."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Final

from sesslint.adapters.detect import SUPPORTED_FORMATS, VALID_FORMAT_OPTIONS
from sesslint.cli._common import _output_format
from sesslint.cli._options import add_output_format_option

NAME: Final[str] = "diff"


def configure(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> argparse.ArgumentParser:
    sub = subparsers.add_parser(
        "diff",
        help="[read-only] Structurally diff two session files.",
        description=(
            "[read-only] Compare two session files by event identity "
            "(not text diff): added/removed events, kind changes, parent "
            "relinks, sequence reorders, content changes (hash only)."
        ),
    )
    sub.add_argument("a", type=Path, help="Path to the first session file")
    sub.add_argument("b", type=Path, help="Path to the second session file")
    sub.add_argument(
        "--format",
        choices=sorted(VALID_FORMAT_OPTIONS),
        default="auto",
        help="Session format adapter for both inputs (default: auto)",
    )
    sub.add_argument(
        "--format-a",
        dest="format_a",
        choices=sorted(SUPPORTED_FORMATS),
        default=None,
        help="Format override for input A only",
    )
    sub.add_argument(
        "--format-b",
        dest="format_b",
        choices=sorted(SUPPORTED_FORMATS),
        default=None,
        help="Format override for input B only",
    )
    add_output_format_option(sub)
    sub.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit sesslint.diff/v1 JSON (shortcut for --output-format json)",
    )
    return sub


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from sesslint.diff import DiffInputError, diff_sessions

    shared_fmt = getattr(args, "format", "auto")
    shared = None if shared_fmt in (None, "auto") else shared_fmt
    try:
        diff_result = diff_sessions(
            args.a,
            args.b,
            format_a=getattr(args, "format_a", None) or shared,
            format_b=getattr(args, "format_b", None) or shared,
        )
    except DiffInputError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 2
    except ValueError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 2

    if _output_format(args) == "json":
        print(diff_result.to_json())
    else:
        print(diff_result.render_human())
    return 0 if diff_result.identical else 1
