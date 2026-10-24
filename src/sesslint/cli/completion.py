"""The ``sesslint completion`` subcommand."""

from __future__ import annotations

import argparse
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from sesslint.cli._context import CliContext

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


def run(ctx: CliContext, args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from sesslint.completion import generate_completion

    try:
        print(generate_completion(args.shell).rstrip("\n"))
    except ValueError as err:
        ctx.error(f"Error: {err}")
        return 2
    return 0
