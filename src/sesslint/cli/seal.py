"""The ``sesslint seal`` subcommand."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from sesslint.cli._context import CliContext

NAME: Final[str] = "seal"


def configure(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> argparse.ArgumentParser:
    # seal (evidence-assurance T-01)
    sub = subparsers.add_parser(
        "seal",
        help="[read-only] Verify a tamper-evident seal ledger's hash chain.",
        description=(
            "[read-only] Re-walk a seal ledger produced by "
            "check/verify/repair --seal and report the first chain "
            "divergence (edited, dropped, reordered, or truncated lines). "
            "The ledger is a tamper-evident record of SessLint verdicts — "
            "self-verifying, no keys or trusted clock."
        ),
    )
    sub.add_argument(
        "--verify",
        type=Path,
        required=True,
        metavar="LEDGER",
        help="Ledger JSONL file to re-walk and verify",
    )
    sub.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output the verification result as JSON to stdout",
    )
    return sub


def run(ctx: CliContext, args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from sesslint.seal import SealError, verify_ledger

    try:
        entries_ok, divergence = verify_ledger(args.verify)
    except SealError as err:
        ctx.error(f"Error: {err}")
        return 2
    if getattr(args, "json", False):
        print(
            json.dumps(
                {
                    "entries": entries_ok,
                    "ok": divergence is None,
                    "divergence": divergence,
                },
                sort_keys=True,
            )
        )
    elif divergence is None:
        print(f"ok: {entries_ok} sealed entries")
    else:
        ctx.error(
            f"divergence at line {divergence['line']}: "
            f"{divergence['kind']} — {divergence['detail']}"
        )
    return 0 if divergence is None else 1
