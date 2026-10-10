"""The ``sesslint diff`` subcommand."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Final

from sesslint.adapters.detect import SUPPORTED_FORMATS, VALID_FORMAT_OPTIONS
from sesslint.cli._common import _output_format

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
        "--adapter",
        choices=sorted(VALID_FORMAT_OPTIONS),
        default="auto",
        help="Session format adapter for both inputs (default: auto)",
    )
    sub.add_argument(
        "--adapter-a",
        dest="adapter_a",
        choices=sorted(SUPPORTED_FORMATS),
        default=None,
        help="Adapter override for input A only",
    )
    sub.add_argument(
        "--adapter-b",
        dest="adapter_b",
        choices=sorted(SUPPORTED_FORMATS),
        default=None,
        help="Adapter override for input B only",
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
    out_group.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit sesslint.diff/v1 JSON (shortcut for --format json)",
    )
    return sub


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from sesslint.diff import DiffInputError, diff_sessions

    shared_fmt = getattr(args, "adapter", "auto")
    shared = None if shared_fmt in (None, "auto") else shared_fmt
    try:
        diff_result = diff_sessions(
            args.a,
            args.b,
            format_a=getattr(args, "adapter_a", None) or shared,
            format_b=getattr(args, "adapter_b", None) or shared,
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
