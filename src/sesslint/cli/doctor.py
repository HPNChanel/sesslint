"""The ``sesslint doctor`` subcommand."""

from __future__ import annotations

import argparse
from typing import TYPE_CHECKING, Final

from sesslint.cli._common import _output_format
from sesslint.cli._options import add_report_output_option
from sesslint.cli._output import emit_text

if TYPE_CHECKING:
    from sesslint.cli._context import CliContext

NAME: Final[str] = "doctor"


def configure(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> argparse.ArgumentParser:
    sub = subparsers.add_parser(
        "doctor",
        help="[read-only] Environment diagnostics for support reports.",
        description=(
            "[read-only] Report what SessLint sees on this machine: tool "
            "and adapter versions, resolved config file, agent session "
            "roots, bounded quick verdicts. Counts only — never file names."
        ),
    )
    sub.add_argument(
        "--agent",
        choices=["claude", "codex", "all"],
        default=None,
        help="Restrict diagnostics to one agent (default: all)",
    )
    sub.add_argument(
        "--no-quick-checks",
        dest="no_quick_checks",
        action="store_true",
        default=False,
        help="Skip the bounded per-file check pass (counts only)",
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
        help="Emit sesslint.doctor/v1 JSON (shortcut for --format json)",
    )
    add_report_output_option(sub)
    return sub


def run(ctx: CliContext, args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from sesslint.config import ConfigError
    from sesslint.doctor import doctor_report

    agent = getattr(args, "agent", None)
    agents = None if agent in (None, "all") else [agent]
    try:
        diag = doctor_report(
            agents=agents,
            quick_checks=not getattr(args, "no_quick_checks", False),
        )
    except ConfigError as err:
        ctx.error(f"Error: {err}")
        return 2
    if _output_format(args) == "json":
        emit_text(ctx, args, diag.to_json(), summary="doctor report")
    else:
        emit_text(ctx, args, diag.render_human(), summary="doctor report")
    return 0
