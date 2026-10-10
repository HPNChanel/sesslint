"""The ``sesslint baseline`` subcommand."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Final

from sesslint import __version__
from sesslint.adapters.detect import VALID_FORMAT_OPTIONS

NAME: Final[str] = "baseline"


def configure(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> argparse.ArgumentParser:
    sub = subparsers.add_parser(
        "baseline",
        help="[writes: output file] Upgrade a v1 baseline to the path-normalized v2 format.",
        description=(
            "[writes: output file] Baseline maintenance: --upgrade rewrites a "
            "sesslint.baseline/v1 file as v2 (path-normalized keys). With "
            "--source, findings are reproduced to verify entries; without it "
            "every entry migrates 'unverified' (still matchable via the v1 leg)."
        ),
    )
    sub.add_argument(
        "--upgrade",
        required=True,
        type=Path,
        metavar="FILE",
        help="Baseline file to upgrade (must be sesslint.baseline/v1)",
    )
    sub.add_argument(
        "--source",
        type=Path,
        default=None,
        metavar="PATH",
        help="Session file or directory to re-check for verified migration",
    )
    sub.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        metavar="PATH",
        help="Write the upgraded baseline here (default: stdout)",
    )
    sub.add_argument(
        "--format",
        choices=sorted(VALID_FORMAT_OPTIONS),
        default="auto",
        help="Input format override for --source (default: auto)",
    )
    sub.add_argument(
        "--profile",
        default="neutral",
        help="Validation profile for --source re-check (default: neutral)",
    )
    return sub


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from sesslint.baseline import BaselineError, upgrade_baseline

    findings: Any = None
    if args.source is not None:
        source_p: Path = args.source
        if not source_p.exists():
            print(f"Error: Path not found: {source_p}", file=sys.stderr)
            return 2
        format_opt = getattr(args, "format", "auto")
        profile_opt = getattr(args, "profile", "neutral")
        format_arg = None if format_opt in (None, "auto") else format_opt
        try:
            if source_p.is_dir():
                from sesslint.scan import scan_path

                rep = scan_path(
                    source_p,
                    recursive=True,
                    format=format_arg,
                    profile=profile_opt,
                )
                findings = [f for fr in rep.files for f in fr.findings]
            else:
                from sesslint.api import check_file

                report = check_file(
                    source_p,
                    format=format_arg,
                    profile=profile_opt,
                )
                findings = list(report.findings)
        except (ValueError, KeyError) as err:
            err_msg = err.args[0] if err.args else str(err)
            print(f"Error: {err_msg}", file=sys.stderr)
            return 2

    try:
        doc, verified, unverified = upgrade_baseline(
            args.upgrade, findings, created_by=f"sesslint {__version__}"
        )
    except BaselineError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 2

    if args.output is not None:
        from sesslint.atomic import atomic_write_text

        atomic_write_text(args.output, doc)
        print(
            f"upgraded baseline: {verified} verified, {unverified} unverified -> {args.output}",
            file=sys.stderr,
        )
    else:
        sys.stdout.write(doc)
        print(
            f"upgraded baseline: {verified} verified, {unverified} unverified",
            file=sys.stderr,
        )
    return 0
