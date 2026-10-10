"""The ``sesslint verify`` subcommand."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Final

from sesslint.cli._common import _handle_internal_error, should_color
from sesslint.cli._options import _add_seal_args, add_color_options
from sesslint.cli._seal import _maybe_append_seal

NAME: Final[str] = "verify"


def configure(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> argparse.ArgumentParser:
    sub = subparsers.add_parser(
        "verify",
        help="[read-only] Verify integrity, hash bindings, and idempotence of a repaired session.",
        description=(
            "[read-only] Verify integrity, hash bindings, and idempotence of a repaired "
            "session artifact."
        ),
    )
    sub.add_argument(
        "source",
        type=Path,
        nargs="?",
        default=None,
        help="Path to source session file",
    )
    sub.add_argument(
        "repaired",
        type=Path,
        nargs="?",
        default=None,
        help="Path to repaired session file",
    )
    sub.add_argument(
        "--source",
        type=Path,
        default=None,
        dest="source_flag",
        help=argparse.SUPPRESS,
    )
    sub.add_argument(
        "--output",
        type=Path,
        default=None,
        dest="output_flag",
        help=argparse.SUPPRESS,
    )
    sub.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="Path to repair manifest JSON file",
    )
    sub.add_argument(
        "--plan",
        type=Path,
        default=None,
        help="Path to repair plan JSON file (optional)",
    )
    sub.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output verify verdict as JSON to stdout",
    )
    add_color_options(sub)
    sub.add_argument(
        "--acknowledge-side-effects",
        action="store_true",
        default=False,
        help="Acknowledge tool side-effects for salvage policy during verify idempotence check",
    )
    _add_seal_args(sub)
    return sub


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    source_target = args.source or getattr(args, "source_flag", None)
    repaired_target = args.repaired or getattr(args, "output_flag", None)

    if source_target is None or repaired_target is None:
        parser.error("sesslint verify requires both source and repaired session paths.")

    try:
        from sesslint import api
        from sesslint.verify import render_verify_human

        verdict = api.verify(
            source_path=source_target,
            output_path=repaired_target,
            manifest_path=args.manifest,
            plan_path=getattr(args, "plan", None),
            acknowledge_side_effects=getattr(args, "acknowledge_side_effects", False),
        )
        use_json = getattr(args, "json", False)
        is_legacy_flags = args.source is None and getattr(args, "source_flag", None) is not None
        if use_json or is_legacy_flags:
            print(verdict.to_json())
        else:
            use_color = should_color(args, sys.stdout)
            print(render_verify_human(verdict, color=use_color))
        seal_rc = _maybe_append_seal(
            args,
            tool="verify",
            artifact_sha256=verdict.artifact_sha256,
            artifact_bytes=None,
            artifact_path=Path(repaired_target),
            verdict="ok" if verdict.ok else "failed",
            codes={},
            report_bytes=verdict.to_json().encode("utf-8"),
        )
        if seal_rc is not None:
            return seal_rc
        return 0 if verdict.ok else 1
    except (FileNotFoundError, OSError) as err:
        print(f"Verify I/O error: {err}", file=sys.stderr)
        return 2
    except Exception as err:
        return _handle_internal_error(err, args)
