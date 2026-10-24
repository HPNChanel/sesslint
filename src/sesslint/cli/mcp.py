"""The ``sesslint mcp`` subcommand."""

from __future__ import annotations

import argparse
import sys
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from sesslint.cli._context import CliContext

NAME: Final[str] = "mcp"


def configure(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> argparse.ArgumentParser:
    return subparsers.add_parser(
        "mcp",
        help="[read-only] Run a Model Context Protocol server over stdio.",
        description=(
            "[read-only] MCP stdio server (protocol 2025-06-18, newline-"
            "delimited JSON-RPC): exposes sesslint_check / sesslint_precheck / "
            "sesslint_scan tools so agents can call checks natively. "
            "Long-running process — EOF or Ctrl+C exits cleanly."
        ),
    )


def run(ctx: CliContext, args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from sesslint.mcp_server import serve

    return serve(sys.stdin.buffer, sys.stdout.buffer)
