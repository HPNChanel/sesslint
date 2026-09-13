"""One-call session integrity prevention API (DEV-015 / US-014 / UC-05).

Provides a single function `precheck` returning a frozen `PrecheckResult` dataclass
with normalized reason codes, exit codes, and embedded reports. Designed for
fast pre-resume, pre-request, and pre-compaction gates.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from sesslint.report import Report

PrecheckReason = Literal[
    "clean",
    "findings-error",
    "findings-warning",
    "detection-failed",
    "io-error",
    "usage-error",
]


@dataclass(frozen=True, slots=True)
class PrecheckResult:
    """Outcome of one-call session precheck gate.

    Attributes:
        ok: True iff exit_code == 0 (clean or warning only).
        reason: Normalized outcome reason in closed vocabulary.
        report: Report dataclass on completed check, or None on io/usage error.
        exit_code: Standardized exit code (0=clean/warning, 1=findings/detection-failed,
            2=io/usage-error).
    """

    ok: bool
    reason: PrecheckReason
    report: Report | None
    exit_code: int


def precheck(
    path: Path | str,
    *,
    profile: str | None = None,
    format: str | None = None,
) -> PrecheckResult:
    """Evaluate session file integrity with one call and return a PrecheckResult.

    Wraps `check_file` with canonical exit code and reason mapping. Strictly
    never raises exceptions on session findings or format detection failures.
    I/O and usage errors are converted into PrecheckResult with exit_code=2.

    Integration Patterns & Call Sites:

    1. Pre-Resume Gate (Prevent corrupt session reload):
        ```python
        from sesslint import precheck

        result = precheck("sessions/active.jsonl")
        if not result.ok:
            raise RuntimeError(f"Cannot resume corrupted session: {result.reason}")
        # Session verified; safe to resume agent execution
        ```

    2. Pre-Request Gate (Gate before invoking LLM provider):
        ```python
        from sesslint import precheck

        result = precheck("sessions/active.jsonl", profile="claude-strict")
        if not result.ok:
            abort_request(f"Pre-request gate rejected session ({result.reason})")
        # Session conforms to provider turn rules; send prompt to provider
        ```

    3. Pre-Compaction Gate (Safeguard before history compaction):
        ```python
        from sesslint import precheck

        result = precheck("sessions/active.jsonl")
        if not result.ok:
            logger.warning("Compaction skipped: %s", result.reason)
            return
        # Session structure intact; safe to compute compaction summary
        ```

    Args:
        path: Path to session file.
        profile: Validation profile name (default: "neutral").
        format: Session format override (default: auto-detect).

    Returns:
        A frozen PrecheckResult dataclass.
    """
    try:
        target_path = Path(path)
        if target_path.is_dir():
            raise IsADirectoryError(f"Expected session file, got directory: {target_path}")
        from sesslint.api import check_file

        report = check_file(target_path, profile=profile or "neutral", format=format)
    except (FileNotFoundError, PermissionError, IsADirectoryError, OSError):
        return PrecheckResult(
            ok=False,
            reason="io-error",
            report=None,
            exit_code=2,
        )
    except (ValueError, KeyError, TypeError, AttributeError):
        return PrecheckResult(
            ok=False,
            reason="usage-error",
            report=None,
            exit_code=2,
        )

    # 1. Format detection failure or unsupported format version
    if any(f.code in ("SL301", "SL302") for f in report.findings):
        return PrecheckResult(
            ok=False,
            reason="detection-failed",
            report=report,
            exit_code=1,
        )

    # 2. Structural defects or integrity errors/fatals
    has_error = (
        report.counts.by_severity.get("error", 0) > 0
        or report.counts.by_severity.get("fatal", 0) > 0
    )
    if has_error:
        return PrecheckResult(
            ok=False,
            reason="findings-error",
            report=report,
            exit_code=1,
        )

    # 3. Non-blocking warnings
    has_warning = report.counts.by_severity.get("warning", 0) > 0
    if has_warning:
        return PrecheckResult(
            ok=True,
            reason="findings-warning",
            report=report,
            exit_code=0,
        )

    # 4. Clean session
    return PrecheckResult(
        ok=True,
        reason="clean",
        report=report,
        exit_code=0,
    )


__all__ = [
    "PrecheckReason",
    "PrecheckResult",
    "precheck",
]
