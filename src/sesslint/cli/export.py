"""The ``sesslint export`` subcommand."""

from __future__ import annotations

import argparse
import json
from typing import TYPE_CHECKING, Final

from sesslint.cli._common import _handle_internal_error
from sesslint.cli._options import add_adapter_option, cli_path

if TYPE_CHECKING:
    from sesslint.cli._context import CliContext

NAME: Final[str] = "export"


def configure(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> argparse.ArgumentParser:
    sub = subparsers.add_parser(
        "export",
        help="[writes: output file] Export a session artifact to canonical format for repair.",
        description=(
            "[writes: output file] Export a supported session artifact to a "
            "byte-deterministic canonical file that the repair pipeline accepts."
        ),
    )
    sub.add_argument(
        "path",
        type=cli_path,
        help="Path to session file (.json or .jsonl)",
    )
    sub.add_argument(
        "-o",
        "--output",
        type=cli_path,
        default=None,
        dest="output",
        help="Path to output canonical file (required)",
    )
    add_adapter_option(sub)
    sub.add_argument(
        "--json",
        action="store_true",
        help="Output export summary as JSON",
    )
    return sub


def run(ctx: CliContext, args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.output is None:
        ctx.error("Error: --output is required for export.")
        return 2
    if not args.path.is_file():
        ctx.error(f"Error: Source file not found: {args.path}")
        return 2

    from sesslint import api
    from sesslint.exporter import ExportRefused

    try:
        summary = api.export_file(
            source_path=args.path,
            output_path=args.output,
            format=getattr(args, "adapter", "auto"),
        )
    except ExportRefused as err:
        ctx.error(f"Export refused [{err.code}]: {err}")
        return 1
    except FileNotFoundError as err:
        ctx.error(f"File error: {err}")
        return 2
    except Exception as err:
        return _handle_internal_error(err, args)

    if getattr(args, "json", False):
        print(json.dumps(summary.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"Exported {summary.event_count} events ({summary.input_format} -> canonical)")
        print(f"Output: {args.output} (sha256: {summary.output_sha256[:16]}...)")
        if summary.dropped_unknown_fields:
            print(f"Dropped unknown fields: {summary.dropped_unknown_fields}")
        from sesslint._hints import repair_plan_hint
        from sesslint.report import hint_path

        plan = repair_plan_hint(hint_path(args.output))
        print(f"Next Action: Run '{plan}' to plan repair.")
    return 0
