"""The ``sesslint stats`` subcommand."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Final

from sesslint.adapters.detect import VALID_FORMAT_OPTIONS
from sesslint.cli._common import _output_format
from sesslint.cli._options import add_output_format_option

NAME: Final[str] = "stats"


def configure(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> argparse.ArgumentParser:
    sub = subparsers.add_parser(
        "stats",
        help="[read-only] Aggregate content-free statistics over session files.",
        description=(
            "[read-only] Aggregate statistics over session files or "
            "directories: event counts by kind/actor, tool-call volume per "
            "hashed tool name, compactions, checkpoints, size percentiles."
        ),
    )
    sub.add_argument(
        "path",
        type=Path,
        nargs="*",
        help="Path(s) to session file(s) or directories (use -r for dirs)",
    )
    sub.add_argument(
        "--agent",
        choices=["claude", "codex", "all"],
        default=None,
        help="Aggregate over a well-known agent session root instead of paths",
    )
    sub.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        default=False,
        help="Recursively walk directory arguments",
    )
    sub.add_argument(
        "--format",
        choices=sorted(VALID_FORMAT_OPTIONS),
        default="auto",
        help="Session format adapter for all inputs (default: auto)",
    )
    add_output_format_option(sub)
    sub.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit sesslint.stats/v1 JSON (shortcut for --output-format json)",
    )
    return sub


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from sesslint.api import discover_session_roots
    from sesslint.stats import stats_paths

    agent = getattr(args, "agent", None)
    arg_paths: list[Path] = list(getattr(args, "path", []) or [])
    if agent is not None:
        if arg_paths:
            print(
                "Error: --agent cannot be combined with explicit paths.",
                file=sys.stderr,
            )
            return 2
        agents = None if agent == "all" else [agent]
        root_paths = [r.path for r in discover_session_roots(agents) if r.exists]
        if not root_paths:
            print(f"Error: no existing session roots found for agent '{agent}'.", file=sys.stderr)
            return 2
        arg_paths = [Path(rp) for rp in root_paths]
        args.recursive = True
    if not arg_paths:
        print("Error: stats requires at least one path or --agent.", file=sys.stderr)
        return 2
    shared_fmt = getattr(args, "format", "auto")
    try:
        result = stats_paths(
            arg_paths,
            recursive=getattr(args, "recursive", False),
            format=None if shared_fmt in (None, "auto") else shared_fmt,
        )
    except ValueError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 2

    if _output_format(args) == "json":
        print(result.to_json())
    else:
        print(result.render_human())
    return 0
