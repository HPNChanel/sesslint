"""Seal-ledger verdict helpers shared by check/repair/verify (T-01)."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any


def _check_seal_verdict(report: Any) -> str:
    """Derive the seal verdict vocabulary for a check report — mirrors the
    scan bucket classification (SL301->unsupported, errors->invalid)."""
    if report.limitation.startswith("Unsupported:"):
        return "unsupported"
    if report.limitation.startswith("Skipped:"):
        return "skipped"
    codes = report.counts.by_code
    if codes.get("SL301"):
        return "unsupported"
    err = report.counts.by_severity.get("error", 0) + report.counts.by_severity.get("fatal", 0)
    return "invalid" if err > 0 else "healthy"


def _maybe_append_seal(
    args: argparse.Namespace,
    *,
    tool: str,
    artifact_bytes: bytes | None,
    artifact_path: Path | None,
    verdict: str,
    codes: Mapping[str, int],
    report_bytes: bytes,
    artifact_sha256: str | None = None,
) -> int | None:
    """Append one seal-ledger line when ``--seal`` was passed.

    Returns an exit code only on failure (``2`` — sealing must never be
    silently skipped); returns None when the flag is absent or the append
    succeeded, so callers keep their normal exit path.
    """
    ledger = getattr(args, "seal", None)
    if ledger is None:
        return None
    from sesslint import seal as seal_mod
    from sesslint.report import minimize_path

    try:
        if artifact_sha256 is not None and artifact_sha256 != "0" * 64:
            file_sha = artifact_sha256
        elif artifact_bytes is not None:
            file_sha = seal_mod.sha256_bytes(artifact_bytes)
        else:
            raise seal_mod.SealError("no artifact bytes or path to seal")
        entry_path = (
            None
            if getattr(args, "seal_no_path", False) or artifact_path is None
            else minimize_path(artifact_path)
        )
        entry = seal_mod.append_seal(
            ledger,
            tool=tool,
            file_sha256=file_sha,
            path=entry_path,
            verdict=verdict,
            codes=codes,
            report_sha256=seal_mod.sha256_bytes(report_bytes),
            genesis_of=getattr(args, "seal_genesis_of", None),
        )
    except (seal_mod.SealError, OSError) as err:
        print(f"Error: seal failed: {err}", file=sys.stderr)
        return 2
    print(f"sealed: seq {entry['seq']} -> {ledger}", file=sys.stderr)
    return None
