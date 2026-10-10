"""The ``sesslint export`` subcommand."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Final

from sesslint.cli._common import _handle_internal_error
from sesslint.cli._options import add_format_option

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
        type=Path,
        help="Path to session file (.json or .jsonl)",
    )
    sub.add_argument(
        "--output",
        "--out",
        "-o",
        type=Path,
        default=None,
        dest="output",
        help="Path to output canonical file (required)",
    )
    add_format_option(sub)
    sub.add_argument(
        "--json",
        action="store_true",
        help="Output export summary as JSON",
    )
    return sub


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.output is None:
        print("Error: --output is required for export.", file=sys.stderr)
        return 2
    if not args.path.is_file():
        print(f"Error: Source file not found: {args.path}", file=sys.stderr)
        return 2

    from sesslint import api
    from sesslint.exporter import ExportRefused

    try:
        summary = api.export_file(
            source_path=args.path,
            output_path=args.output,
            format=getattr(args, "format", "auto"),
        )
    except ExportRefused as err:
        print(f"Export refused [{err.code}]: {err}", file=sys.stderr)
        return 1
    except FileNotFoundError as err:
        print(f"File error: {err}", file=sys.stderr)
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
        print(f"Next Action: Run 'sesslint repair {args.output} --output <file>' to plan repair.")
    return 0
