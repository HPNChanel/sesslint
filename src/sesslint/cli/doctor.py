"""The ``sesslint doctor`` subcommand."""

from __future__ import annotations

import argparse
from typing import Final

from sesslint.cli._common import _output_format
from sesslint.cli._options import add_output_format_option

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
    add_output_format_option(sub)
    sub.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit sesslint.doctor/v1 JSON (shortcut for --output-format json)",
    )
    return sub


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from sesslint.doctor import doctor_report

    agent = getattr(args, "agent", None)
    agents = None if agent in (None, "all") else [agent]
    diag = doctor_report(
        agents=agents,
        quick_checks=not getattr(args, "no_quick_checks", False),
    )
    if _output_format(args) == "json":
        print(diag.to_json())
    else:
        print(diag.render_human())
    return 0
