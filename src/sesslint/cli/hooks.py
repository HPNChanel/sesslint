"""The ``sesslint init-hooks`` subcommand."""

from __future__ import annotations

import argparse
import sys
from typing import Final

NAME: Final[str] = "init-hooks"


def configure(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> argparse.ArgumentParser:
    sub = subparsers.add_parser(
        "init-hooks",
        help="[read-only] Print ready-to-merge agent hook snippets (never writes config).",
        description=(
            "[read-only] Print ready-to-merge settings.json hook blocks for "
            "the documented SessionStart/PreCompact recipes. Print-only by "
            "permanent design — SessLint never writes agent configuration."
        ),
    )
    sub.add_argument(
        "--agent",
        choices=["claude", "codex", "all"],
        default="all",
        help="Agent to generate snippets for (default: all)",
    )
    sub.add_argument(
        "--print",
        dest="print_mode",
        action="store_true",
        default=True,
        help="Print snippets (the only mode — nothing is ever written)",
    )
    sub.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit sesslint.init-hooks/v1 JSON instead of human text",
    )
    return sub


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from sesslint.hooks import init_hooks_doc

    hooks_doc = init_hooks_doc(getattr(args, "agent", "all"))
    if getattr(args, "json", False):
        print(hooks_doc.to_json())
    else:
        sys.stdout.write(hooks_doc.render_human())
    return 0
