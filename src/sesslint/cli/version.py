"""The ``sesslint version`` subcommand."""

from __future__ import annotations

import argparse
import json
from typing import TYPE_CHECKING, Final

from sesslint._version import get_version_info

if TYPE_CHECKING:
    from sesslint.cli._context import CliContext

NAME: Final[str] = "version"


def configure(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> argparse.ArgumentParser:
    sub = subparsers.add_parser(
        "version",
        help="[read-only] Display detailed component and schema version information.",
        description="[read-only] Display detailed component and schema version information.",
    )
    sub.add_argument(
        "--json",
        action="store_true",
        help="Output version details as JSON object",
    )
    return sub


def run(ctx: CliContext, args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    info = get_version_info()
    if getattr(args, "json", False):
        print(json.dumps(info, indent=2, sort_keys=True))
    else:
        print(f"SessLint CLI: {info['cli']}")
        print("Schemas:")
        print(f"  session:  {info['schema_session']}")
        print(f"  report:   {info['schema_report']}")
        print(f"  manifest: {info['schema_manifest']}")
        print("Adapters:")
        for k, v in sorted(info["adapters"].items()):
            print(f"  {k}: {v}")
        print("Profiles:")
        for k, v in sorted(info["profiles"].items()):
            print(f"  {k}: {v}")
    return 0
