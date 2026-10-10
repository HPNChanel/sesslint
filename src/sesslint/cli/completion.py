"""The ``sesslint completion`` subcommand."""

from __future__ import annotations

import argparse
import sys
from typing import Final

NAME: Final[str] = "completion"


def configure(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> argparse.ArgumentParser:
    sub = subparsers.add_parser(
        "completion",
        help="[read-only] Print shell completion script.",
        description=("[read-only] Print a shell completion script generated from the live parser."),
    )
    sub.add_argument(
        "shell",
        choices=["bash", "zsh", "fish", "powershell"],
        help="Shell dialect (bash, zsh, fish, powershell)",
    )
    return sub


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from sesslint.completion import generate_completion

    try:
        print(generate_completion(args.shell).rstrip("\n"))
    except ValueError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 2
    return 0
