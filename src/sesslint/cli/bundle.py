"""The ``sesslint bundle`` subcommand."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import TYPE_CHECKING, Final

from sesslint.cli._common import _handle_internal_error
from sesslint.cli._options import (
    _validate_unit_interval_float,
    add_adapter_option,
    add_profile_option,
)

if TYPE_CHECKING:
    from sesslint.cli._context import CliContext

NAME: Final[str] = "bundle"


def configure(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> argparse.ArgumentParser:
    sub = subparsers.add_parser(
        "bundle",
        help="[read-only] Generate a privacy-safe diagnostic support bundle and fixture skeleton.",
        description=(
            "[read-only] Generate a privacy-safe diagnostic support bundle and fixture skeleton."
        ),
    )
    sub.add_argument(
        "path",
        type=Path,
        help="Path to session file (.json or .jsonl)",
    )
    sub.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        dest="output",
        help="Path to output bundle JSON file",
    )
    sub.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output bundle as JSON to stdout",
    )
    add_adapter_option(sub)
    add_profile_option(sub)
    sub.add_argument(
        "--confidence-min",
        type=_validate_unit_interval_float,
        default=None,
        help="Minimum confidence threshold for format auto-detection",
    )
    sub.add_argument(
        "--margin-min",
        type=_validate_unit_interval_float,
        default=None,
        help="Minimum margin threshold between top candidates for auto-detection",
    )
    sub.add_argument(
        "--strict-share",
        action="store_true",
        default=False,
        help=(
            "Exit 1 without writing output when the source file contains "
            "secret-shaped material (SL009 share_advisory present)"
        ),
    )
    return sub


def run(ctx: CliContext, args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    target_bundle_path: Path = args.path
    if not target_bundle_path.exists():
        ctx.error(f"Error: Path not found: {target_bundle_path}")
        return 2
    if target_bundle_path.is_dir():
        ctx.error(
            "Error: Path is a directory. "
            f"Bundle requires a single session file: {target_bundle_path}"
        )
        return 2

    from sesslint.api import build_bundle

    format_opt = getattr(args, "adapter", "auto")
    profile_opt = getattr(args, "profile", "neutral")

    try:
        bundle = build_bundle(
            target_bundle_path,
            format=format_opt if format_opt != "auto" else None,
            profile=profile_opt,
            confidence_min=getattr(args, "confidence_min", None),
            margin_min=getattr(args, "margin_min", None),
        )
    except (ValueError, KeyError) as err:
        if "not permitted by profile" in str(err):
            ctx.error(str(err))
            return 2
        parser.error(str(err))
    except FileNotFoundError as err:
        ctx.error(f"Error: {err}")
        return 2
    except Exception as err:
        return _handle_internal_error(err, args)

    # SL009 pre-share advisory (transcript-hygiene T-03): the bundle is
    # content-free, but the source file it describes may still hold live
    # secret-shaped material. Warn on stderr (stdout stays pure JSON);
    # --strict-share turns the advisory into a gate.
    if bundle.share_advisory is not None:
        adv = bundle.share_advisory
        fams = ", ".join(str(x) for x in adv.get("families", ()))
        ctx.warn(
            f"share_advisory: source contains secret-shaped material "
            f"({adv.get('finding_count', 0)} finding(s); families: {fams}) - "
            "rotate affected credentials before sharing the source file "
            "(docs/codes/SL009.md)"
        )
        if getattr(args, "strict_share", False):
            return 1

    bundle_json = bundle.to_json()

    out_path: Path | None = getattr(args, "output", None)
    if out_path is not None:
        try:
            from sesslint.atomic import atomic_write_text

            # The bundle must never replace the session it describes (B18).
            atomic_write_text(
                out_path, bundle_json, refuse_paths=[target_bundle_path], overwrite=False
            )
        except Exception as err:
            ctx.error(f"Error writing bundle to {out_path}: {err}")
            return 2

        if getattr(args, "json", False):
            print(bundle_json.rstrip("\n"))
        else:
            print(f"Diagnostic bundle written to: {out_path}")
        return 0

    # No --out specified: emit bundle JSON to stdout
    print(bundle_json.rstrip("\n"))
    return 0
