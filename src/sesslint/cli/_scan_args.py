"""Shared scan-kwarg assembly for ``check`` (single source for the 4 old copies)."""

from __future__ import annotations

import argparse
import os
from collections.abc import Collection
from typing import TYPE_CHECKING, Any

from sesslint.cli._common import _rule_codes_arg

if TYPE_CHECKING:
    from sesslint.cli._context import CliContext


def build_scan_kwargs(
    ctx: CliContext,
    args: argparse.Namespace,
    *,
    baseline: Collection[str] | None,
    progress_cb: Any = None,
) -> dict[str, Any]:
    """Assemble the shared ``check_dir``/``scan_path`` kwargs for ``check``.

    Directories are always recursive. ``--jobs`` accepts a positive integer,
    ``'auto'`` or ``'0'`` (CPU count); anything else raises ``ValueError``
    for the caller to surface as a usage error.
    """
    kwargs: dict[str, Any] = {
        "recursive": True,
        "follow_symlinks": getattr(args, "follow_symlinks", False),
        "max_files": getattr(args, "max_files", 10000),
        "max_bytes": getattr(args, "max_bytes", 1024 * 1024 * 1024),
        "max_file_bytes": args.max_file_bytes,
        "timestamp_skew_ms": args.timestamp_skew_ms,
        "max_findings_per_code": args.max_findings_per_code,
        "newest": getattr(args, "newest", None),
        "since": getattr(args, "since", None),
        "format": getattr(args, "adapter", "auto"),
        "profile": getattr(args, "profile", "neutral"),
        "confidence_min": getattr(args, "confidence_min", None),
        "margin_min": getattr(args, "margin_min", None),
        "progress_cb": progress_cb if progress_cb is not None else ctx.progress_callback(args),
        "skip_undetected": getattr(args, "skip_undetected", False),
        "select": _rule_codes_arg(args, "select"),
        "ignore": _rule_codes_arg(args, "ignore"),
        "baseline": baseline,
        "exclude": getattr(args, "exclude", None),
        "ext": getattr(args, "ext", None),
        "incremental": getattr(args, "incremental", False),
        "cache_dir": getattr(args, "cache_dir", None),
    }
    jobs_raw = str(getattr(args, "jobs", "1")).strip().lower()
    if jobs_raw in ("auto", "0"):
        kwargs["jobs"] = os.cpu_count() or 1
    else:
        try:
            kwargs["jobs"] = int(jobs_raw)
        except ValueError:
            raise ValueError(
                f"--jobs must be a positive integer or 'auto', got '{jobs_raw}'"
            ) from None
        if kwargs["jobs"] < 1:
            raise ValueError(f"--jobs must be a positive integer or 'auto', got '{jobs_raw}'")
    return kwargs
