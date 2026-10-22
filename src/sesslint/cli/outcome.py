"""The ``sesslint outcome`` subcommand (OutcomeGuard, ITF-02/ITF-04).

Reads a contract and two snapshot files, never the network or a live agent
store. Exit 0 means the outcome is VERIFIED; 1 means any other outcome
(VIOLATED, PENDING, INCONCLUSIVE, NOT_APPLICABLE, NOT_EVALUATED) — the JSON
``run_status`` says the check itself completed; 2 is a usage/input error.
"""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final

from sesslint.cli._common import _output_format
from sesslint.cli._options import _validate_positive_int, add_report_output_option
from sesslint.cli._output import emit_text
from sesslint.io import DEFAULT_MAX_FILE_BYTES

if TYPE_CHECKING:
    from sesslint.cli._context import CliContext

NAME: Final[str] = "outcome"
_COMPLETENESS: Final[tuple[str, ...]] = ("complete", "partial", "unknown", "unavailable")
_ORIGINS: Final[tuple[str, ...]] = ("target_system", "workflow_log", "user_file", "manual")


def _instant(text: str) -> datetime:
    from sesslint.outcome.snapshot import parse_instant

    parsed = parse_instant(text)
    if parsed is None:
        raise argparse.ArgumentTypeError(
            f"{text!r} is not an ISO-8601 time with a UTC offset (e.g. 2026-10-21T10:00:00Z)"
        )
    return parsed


def configure(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> argparse.ArgumentParser:
    sub = subparsers.add_parser(
        "outcome",
        help="[read-only] Verify an outcome contract against source/target snapshots.",
        description=(
            "OutcomeGuard: reconcile work items in a source snapshot with results in a "
            "target snapshot, per a declared contract. Offline and read-only; absence is "
            "proven only from a complete target snapshot observed after the deadline."
        ),
    )
    sub.add_argument("contract", type=Path, help="sesslint.outcome-contract/v1 JSON file")
    sub.add_argument(
        "--explain",
        action="store_true",
        help="Validate the contract and print what it checks; read no snapshots",
    )
    sub.add_argument("--source", type=Path, help="Source snapshot (.csv/.json/.jsonl)")
    sub.add_argument("--target", type=Path, help="Target snapshot (.csv/.json/.jsonl)")
    sub.add_argument(
        "--as-of",
        type=_instant,
        default=None,
        help="Evaluation instant (default: the target observation time; no wall clock)",
    )
    for role in ("source", "target"):
        sub.add_argument(
            f"--{role}-observed-at",
            type=_instant,
            default=None,
            help=f"When the {role} snapshot was taken (UTC offset required)",
        )
        sub.add_argument(
            f"--{role}-completeness",
            choices=_COMPLETENESS,
            default=None,
            help=f"Declared completeness of the {role} snapshot (default: unknown)",
        )
        sub.add_argument(
            f"--{role}-origin",
            choices=_ORIGINS,
            default=None,
            help=f"Where the {role} snapshot came from (default: user_file)",
        )
    sub.add_argument(
        "--session",
        type=Path,
        default=None,
        help="Session file you link to this run (user-asserted); checked, never modified",
    )
    sub.add_argument(
        "--hash-keys",
        action="store_true",
        help="Show keys as truncated SHA-256 pseudonyms (pseudonymous, not anonymous)",
    )
    sub.add_argument(
        "--all-conditions",
        action="store_true",
        help="List every condition result for passing items too (default: problems only)",
    )
    sub.add_argument(
        "--max-file-bytes", type=_validate_positive_int, default=DEFAULT_MAX_FILE_BYTES
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
    out_group.add_argument("--json", action="store_true")
    add_report_output_option(sub)
    return sub


def run(ctx: CliContext, args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from sesslint.outcome import (
        ContractError,
        EvaluationError,
        OutcomeReport,
        SnapshotError,
        evaluate,
        explain_contract,
        load_contract,
        load_snapshot,
        session_dimension,
    )

    try:
        contract = load_contract(args.contract)
    except ContractError as err:
        ctx.error("Error: invalid outcome contract:")
        for problem in err.problems:
            ctx.error(f"  - {problem}")
        return 2
    except OSError:
        ctx.error("Error: outcome contract could not be read.")
        return 2
    if args.explain:
        if args.source is not None or args.target is not None:
            ctx.error("Error: --explain reads only the contract; drop --source/--target.")
            return 2
        emit_text(ctx, args, explain_contract(contract), inputs=(args.contract,), summary="explain")
        return 0
    if args.source is None or args.target is None:
        ctx.error("Error: outcome needs --source and --target snapshots (or --explain).")
        return 2
    snapshots = []
    for role in ("source", "target"):
        try:
            snapshots.append(
                load_snapshot(
                    getattr(args, role),
                    role=role,
                    observed_at=getattr(args, f"{role}_observed_at"),
                    completeness=getattr(args, f"{role}_completeness"),
                    origin=getattr(args, f"{role}_origin"),
                    max_bytes=args.max_file_bytes,
                )
            )
        except SnapshotError as err:
            ctx.error(f"Error: {role} snapshot: {err}")
            return 2
        except OSError:
            ctx.error(f"Error: {role} snapshot could not be read.")
            return 2
    source, target = snapshots
    as_of = args.as_of if args.as_of is not None else target.observed_at
    if as_of is None:
        ctx.error("Error: pass --as-of or --target-observed-at; the wall clock is never used.")
        return 2
    try:
        evaluation = evaluate(contract, source, target, as_of=as_of)
    except EvaluationError as err:
        ctx.error(f"Error: {err}")
        return 2
    report = OutcomeReport(
        evaluation,
        session_dimension(args.session, max_file_bytes=args.max_file_bytes),
        hash_keys=args.hash_keys,
        all_conditions=args.all_conditions,
    )
    inputs = tuple(p for p in (args.contract, args.source, args.target, args.session) if p)
    emit_text(
        ctx,
        args,
        report.to_json() if _output_format(args) == "json" else report.render_human(),
        inputs=inputs,
        summary=f"outcome {report.outcome}",
    )
    return report.exit_code
