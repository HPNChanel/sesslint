"""Shared argparse validators and identical option-group declarations."""

from __future__ import annotations

import argparse
import math
import os
from pathlib import Path

from sesslint.adapters.detect import VALID_FORMAT_OPTIONS


def cli_path(value: str) -> Path:
    """argparse ``type=`` for path arguments: expand a leading ``~`` (AC-04).

    Hints print paths under home as ``~/...``. Windows PowerShell 5.1 and
    cmd pass that through literally, so the CLI expands the current user's
    ``~`` itself. ``-`` (stdin), ``~user`` forms and every other value pass
    through unchanged.
    """
    if value == "~" or value.startswith("~/") or (os.sep == "\\" and value.startswith("~\\")):
        return Path(value).expanduser()
    return Path(value)


def _validate_positive_int(val_str: str) -> int:
    """Validate that integer flag is strictly positive (> 0) (P1-02)."""
    try:
        val = int(val_str)
    except (ValueError, TypeError) as err:
        raise argparse.ArgumentTypeError(f"Invalid integer value: {val_str!r}") from err
    if val <= 0:
        raise argparse.ArgumentTypeError(f"Value must be a positive integer (> 0), got {val}")
    return val


def _validate_unit_interval_float(val_str: str) -> float:
    """Validate that float threshold is strictly between 0.0 and 1.0 exclusive (P1-02)."""
    try:
        val = float(val_str)
    except (ValueError, TypeError) as err:
        raise argparse.ArgumentTypeError(f"Invalid float value: {val_str!r}") from err
    if math.isnan(val) or math.isinf(val) or not (0.0 < val < 1.0):
        raise argparse.ArgumentTypeError(
            f"Value must be a float strictly between 0.0 and 1.0 (0.0 < value < 1.0), got {val}"
        )
    return val


def _add_seal_args(sub: argparse.ArgumentParser) -> None:
    """Register the seal-ledger flags on a verdict-producing subcommand
    (evidence-assurance T-01)."""
    sub.add_argument(
        "--seal",
        type=cli_path,
        default=None,
        metavar="LEDGER",
        help=(
            "Append a tamper-evident seal line to LEDGER (append-only "
            "hash-chained verdict record; 'sesslint seal --verify' re-checks it)"
        ),
    )
    sub.add_argument(
        "--seal-no-path",
        action="store_true",
        default=False,
        help="Omit the artifact path from the seal line (multi-machine ledgers)",
    )
    sub.add_argument(
        "--seal-genesis-of",
        type=str,
        default=None,
        metavar="HEX",
        help=(
            "Bind a new ledger's first line to a prior ledger's last entry hash (ledger rotation)"
        ),
    )


def add_adapter_option(sub: argparse.ArgumentParser) -> None:
    """Shared ``--adapter`` declaration (check/repair/bundle/export)."""
    sub.add_argument(
        "--adapter",
        choices=sorted(VALID_FORMAT_OPTIONS),
        default=argparse.SUPPRESS,
        help="Session format adapter (default: auto)",
    )


def add_color_options(sub: argparse.ArgumentParser, *, root: bool = False) -> None:
    """Shared ``--color``/``--no-color``/``-q``/``-v`` global flags.

    ``root=True`` gives the root parser concrete defaults; subcommands use
    ``argparse.SUPPRESS`` so an unset flag falls through to the root value.
    """
    sub.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default="auto" if root else argparse.SUPPRESS,
        help="Control colored terminal output (default: auto)",
    )
    sub.add_argument(
        "--no-color",
        action="store_true",
        default=False if root else argparse.SUPPRESS,
        help="Disable ANSI color styling" + (" (equivalent to NO_COLOR=1)" if root else ""),
    )
    add_verbosity_options(sub, root=root)


def add_verbosity_options(sub: argparse.ArgumentParser, *, root: bool = False) -> None:
    """Shared ``-q/--quiet``/``-v/--verbose`` pair (every parser)."""
    sub.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=False if root else argparse.SUPPRESS,
        help="Suppress non-error stderr output",
    )
    sub.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False if root else argparse.SUPPRESS,
        help="Print debug diagnostics (settings provenance, elapsed) to stderr",
    )


def add_report_output_option(sub: argparse.ArgumentParser) -> None:
    """Shared ``-o/--output FILE`` for report-producing commands.

    The report bytes stdout would have received are written atomically to
    FILE instead; existing report files are overwritten.
    """
    sub.add_argument(
        "-o",
        "--output",
        type=cli_path,
        default=None,
        metavar="FILE",
        help=(
            "Write the report to FILE instead of stdout "
            "(existing report files are overwritten atomically)"
        ),
    )


def add_profile_option(sub: argparse.ArgumentParser) -> None:
    """Shared ``--profile`` declaration (check/repair/bundle)."""
    sub.add_argument(
        "--profile",
        default=argparse.SUPPRESS,
        help="Replay validation profile (default: neutral)",
    )


def add_policy_option(sub: argparse.ArgumentParser) -> None:
    """Shared ``--policy`` declaration (root parser and repair)."""
    sub.add_argument(
        "--policy",
        choices=["conservative", "salvage"],
        default=argparse.SUPPRESS,
        help="Repair policy (choices: conservative, salvage; default: conservative)",
    )


def add_detection_threshold_options(sub: argparse.ArgumentParser) -> None:
    """Shared ``--confidence-min``/``--margin-min`` pair (check/scan)."""
    sub.add_argument(
        "--confidence-min",
        type=_validate_unit_interval_float,
        default=None,
        help="Format auto-detection minimum confidence threshold",
    )
    sub.add_argument(
        "--margin-min",
        type=_validate_unit_interval_float,
        default=None,
        help="Format auto-detection minimum margin threshold",
    )


def add_fail_on_option(sub: argparse.ArgumentParser) -> None:
    """Shared ``--fail-on`` declaration (check/scan)."""
    sub.add_argument(
        "--fail-on",
        choices=["error", "warning"],
        default=None,
        help="Minimum finding severity that fails the command (default: error)",
    )


def add_config_option(sub: argparse.ArgumentParser) -> None:
    """Shared ``--config`` declaration (check/scan/repair)."""
    sub.add_argument(
        "--config",
        type=cli_path,
        default=None,
        metavar="PATH",
        help="Explicit config file path (overrides [tool.sesslint] discovery)",
    )


def add_rule_selection_options(sub: argparse.ArgumentParser) -> None:
    """Shared mutually exclusive ``--select``/``--ignore`` group (check/scan)."""
    rules_group = sub.add_mutually_exclusive_group()
    rules_group.add_argument(
        "--select",
        metavar="CODES",
        default=None,
        help="Comma-separated rule codes to run exclusively (e.g. SL101,SL102)",
    )
    rules_group.add_argument(
        "--ignore",
        metavar="CODES",
        default=None,
        help="Comma-separated rule codes to skip (e.g. SL101,SL102)",
    )


def add_baseline_options(sub: argparse.ArgumentParser) -> None:
    """Shared mutually exclusive ``--baseline``/``--write-baseline`` group (check/scan)."""
    baseline_group = sub.add_mutually_exclusive_group()
    baseline_group.add_argument(
        "--baseline",
        type=cli_path,
        default=None,
        metavar="PATH",
        help="Suppress findings whose fingerprints are recorded in baseline file",
    )
    baseline_group.add_argument(
        "--write-baseline",
        type=cli_path,
        default=None,
        metavar="PATH",
        help="Write the current finding fingerprints as a new baseline file",
    )


def add_walk_filter_options(sub: argparse.ArgumentParser) -> None:
    """Shared ``--exclude``/``--ext`` walk filters (check/scan)."""
    sub.add_argument(
        "--exclude",
        action="append",
        default=None,
        metavar="GLOB",
        help="Skip files/dirs whose name or root-relative path matches GLOB (repeatable)",
    )
    sub.add_argument(
        "--ext",
        action="append",
        default=None,
        metavar="EXT",
        help="Only inspect files with these extensions during directory walks (repeatable)",
    )


def add_walk_options(sub: argparse.ArgumentParser) -> None:
    """Shared trailing input-limit flags (check/scan)."""
    sub.add_argument(
        "--max-file-bytes",
        type=int,
        default=None,
        help="Skip files above this byte limit (default: 104857600)",
    )
    sub.add_argument(
        "--timestamp-skew-ms",
        type=int,
        default=None,
        help="Allowed backwards timestamp skew in milliseconds (default: 2000)",
    )
    sub.add_argument(
        "--fail-on-unsupported",
        action="store_true",
        help="Exit 1 for unsupported formats as well as invalid inputs",
    )


def add_progress_json_option(sub: argparse.ArgumentParser) -> None:
    """Shared ``--progress-json``/``--no-progress`` pair (check/scan/repair)."""
    sub.add_argument(
        "--progress-json",
        action="store_true",
        help="Emit NDJSON progress events to stderr (stdout stays the result channel)",
    )
    sub.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable interactive progress output on stderr",
    )


def add_output_format_option(sub: argparse.ArgumentParser) -> None:
    """Shared ``-f``/``--format`` human/json declaration (diff/stats/doctor/triage).

    ``dest`` stays ``output_format`` so ``_output_format`` keeps working.
    """
    sub.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=["human", "json"],
        default=None,
        help="Output format (default: human)",
    )
