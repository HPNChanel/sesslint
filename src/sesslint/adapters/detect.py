"""Format auto-detection with confidence threshold, margin arbitration, and --format override.

Provides conservative, fail-closed format arbitration across supported session adapters:
- Claude Code JSONL (claude-code-jsonl)
- OpenAI Agents SDK export (openai-agents)
- SessLint Canonical Session Format (canonical)

Architectural Note:
    Detection logic strictly separates signal extraction from arbitration.
    Vendor heuristics are encapsulated exclusively inside their respective adapter
    modules. This module operates as a pure policy arbiter: it gathers scalar confidence
    scores in [0.0, 1.0], evaluates threshold and margin constraints, enforces live-database
    and empty-file safety gates, and fails closed by emitting an explicit finding whenever
    ambiguity or low confidence is encountered.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from sesslint.adapters.canonical import detect_canonical
from sesslint.adapters.claude_code import detect_claude_code
from sesslint.adapters.codex_rollout import detect_codex_rollout
from sesslint.adapters.openai_agents import SQLITE_MAGIC, detect_openai_agents
from sesslint.codes import SL001, SL302, Repairability, Severity
from sesslint.finding import Finding, SourceRef, make_finding

CONFIDENCE_MIN: Final[float] = 0.55
MARGIN_MIN: Final[float] = 0.15
SNIFF_BYTES: Final[int] = 65536
EPSILON: Final[float] = 1e-9

FORMAT_CLAUDE_CODE: Final[str] = "claude-code-jsonl"
FORMAT_OPENAI_AGENTS: Final[str] = "openai-agents"
FORMAT_CODEX_ROLLOUT: Final[str] = "codex-rollout"
FORMAT_CANONICAL: Final[str] = "canonical"
FORMAT_AUTO: Final[str] = "auto"

SUPPORTED_FORMATS: Final[frozenset[str]] = frozenset(
    {
        FORMAT_CLAUDE_CODE,
        FORMAT_OPENAI_AGENTS,
        FORMAT_CODEX_ROLLOUT,
        FORMAT_CANONICAL,
    }
)

VALID_FORMAT_OPTIONS: Final[frozenset[str]] = SUPPORTED_FORMATS | {FORMAT_AUTO}

REASON_CLEAR_WINNER: Final[str] = "clear-winner"
REASON_LOW_CONFIDENCE: Final[str] = "low-confidence"
REASON_TIE: Final[str] = "tie"
REASON_EMPTY: Final[str] = "empty"
REASON_REFUSED_LIVE_DB: Final[str] = "refused-live-db"
REASON_EXPLICIT_OVERRIDE: Final[str] = "explicit-override"


def validate_detection_thresholds(
    confidence_min: float | None,
    margin_min: float | None,
) -> None:
    """Validate detection threshold values — the single authority for threshold rules.

    Each value may be None (meaning "use the caller's default"). A non-None value must be
    a finite int/float (not bool, not str) strictly inside (0.0, 1.0). When both values are
    provided, margin_min may not exceed confidence_min.

    Raises:
        ValueError: On any invalid threshold value or pair.
    """
    for name, value in (("confidence_min", confidence_min), ("margin_min", margin_min)):
        if value is None:
            continue
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or math.isnan(value)
            or math.isinf(value)
            or not (0.0 < value < 1.0)
        ):
            raise ValueError(f"{name} must be strictly between 0.0 and 1.0 exclusive, got {value}")
    if confidence_min is not None and margin_min is not None and margin_min > confidence_min:
        raise ValueError(
            f"margin_min ({margin_min}) cannot exceed confidence_min ({confidence_min})"
        )


@dataclass(frozen=True, slots=True)
class DetectionResult:
    """Outcome of format auto-detection with confidence scores and decision rationale."""

    format: str | None
    confidences: dict[str, float] = field(default_factory=dict)
    reason: str = ""

    def to_source_block(self, requested: str | None = None) -> dict[str, Any]:
        """Convert detection result to source.detection audit block struct."""
        return to_source_block(self, requested=requested)


def to_source_block(
    result: DetectionResult | None,
    requested: str | None = None,
) -> dict[str, Any]:
    """Emit source.detection audit block struct with content-free scores and resolution metadata."""
    req = requested.strip().lower() if requested is not None else FORMAT_AUTO
    if result is None:
        return {
            "requested": req,
            "resolved": None,
            "confidences": {},
            "reason": "unknown",
        }
    return {
        "requested": req,
        "resolved": result.format,
        "confidences": {k: round(v, 3) for k, v in result.confidences.items()},
        "reason": result.reason,
    }


def detect_format(
    path: Path | str,
    *,
    confidence_min: float = CONFIDENCE_MIN,
    margin_min: float = MARGIN_MIN,
) -> DetectionResult:
    """Sniff session file header to detect format with confidence threshold and margin arbitration.

    Steps:
    1. Read up to SNIFF_BYTES (64KB). File I/O exceptions (FileNotFoundError, PermissionError,
       OSError) are propagated to caller to be mapped into the standard I/O finding path.
    2. Check for SQLite database magic header (refused-live-db short-circuit).
    3. Check for empty or whitespace/BOM-only input (empty refusal).
    4. Call vendor-specific detector heuristics without duplicating pattern matching here.
    5. Evaluate the effective confidence_min and margin_min rules (defaulting to
       CONFIDENCE_MIN / MARGIN_MIN), treating ties within EPSILON as ambiguity.

    Args:
        path: Session file path to sniff.
        confidence_min: Effective minimum winner confidence (default CONFIDENCE_MIN).
        margin_min: Effective minimum winner margin (default MARGIN_MIN).

    Returns:
        DetectionResult with detected format (or None if ambiguous/refused) and audit confidences.
    """
    validate_detection_thresholds(confidence_min, margin_min)
    path_obj = Path(path)
    if not path_obj.exists():
        raise FileNotFoundError(f"Session file not found: {path_obj}")
    if path_obj.is_dir():
        raise IsADirectoryError(f"Expected session file, got directory: {path_obj}")

    with open(path_obj, "rb") as stream:
        head_bytes = stream.read(SNIFF_BYTES)

    # 1. Live SQLite magic short-circuit
    if head_bytes.startswith(SQLITE_MAGIC):
        return DetectionResult(
            format=None,
            confidences={
                FORMAT_CLAUDE_CODE: 0.0,
                FORMAT_OPENAI_AGENTS: 0.0,
                FORMAT_CODEX_ROLLOUT: 0.0,
                FORMAT_CANONICAL: 0.0,
            },
            reason=REASON_REFUSED_LIVE_DB,
        )

    # 2. Empty / whitespace-only / BOM-only check
    clean_bytes = head_bytes[3:] if head_bytes.startswith(b"\xef\xbb\xbf") else head_bytes
    if not clean_bytes.strip():
        return DetectionResult(
            format=None,
            confidences={
                FORMAT_CLAUDE_CODE: 0.0,
                FORMAT_OPENAI_AGENTS: 0.0,
                FORMAT_CODEX_ROLLOUT: 0.0,
                FORMAT_CANONICAL: 0.0,
            },
            reason=REASON_EMPTY,
        )

    # 3. Call adapter detection heuristics
    filename = path_obj.name
    raw_scores: dict[str, float] = {
        FORMAT_CLAUDE_CODE: detect_claude_code(head_bytes, filename),
        FORMAT_OPENAI_AGENTS: detect_openai_agents(head_bytes, filename),
        FORMAT_CODEX_ROLLOUT: detect_codex_rollout(head_bytes, filename),
        FORMAT_CANONICAL: detect_canonical(head_bytes, filename),
    }

    # Defensive validation: ensure all scores are finite numbers in [0.0, 1.0]
    # and round to 3 decimal places for deterministic evidence and float comparison
    confidences: dict[str, float] = {}
    for fmt, score in raw_scores.items():
        if not isinstance(score, (int, float)) or not math.isfinite(score):
            confidences[fmt] = 0.0
        else:
            clamped = max(0.0, min(1.0, float(score)))
            confidences[fmt] = round(clamped, 3)

    # 4. Rank candidates by confidence
    sorted_candidates = sorted(
        confidences.items(),
        key=lambda item: item[1],
        reverse=True,
    )
    winner_fmt, winner_score = sorted_candidates[0]
    second_score = sorted_candidates[1][1] if len(sorted_candidates) > 1 else 0.0

    # Rule A: Minimum confidence threshold
    if winner_score < confidence_min:
        return DetectionResult(
            format=None,
            confidences=confidences,
            reason=REASON_LOW_CONFIDENCE,
        )

    # Rule B: Margin threshold & epsilon tie check
    score_diff = winner_score - second_score
    if (score_diff + EPSILON) < margin_min or abs(score_diff) <= EPSILON:
        return DetectionResult(
            format=None,
            confidences=confidences,
            reason=REASON_TIE,
        )

    # Clear winner identified
    return DetectionResult(
        format=winner_fmt,
        confidences=confidences,
        reason=REASON_CLEAR_WINNER,
    )


def resolve_format(
    explicit: str | None,
    path: Path | str,
    *,
    confidence_min: float = CONFIDENCE_MIN,
    margin_min: float = MARGIN_MIN,
) -> tuple[str | None, DetectionResult | None, list[Finding]]:
    """Resolve format either from explicit override or auto-detection, failing closed on ambiguity.

    Args:
        explicit: Format string passed via --format ('auto', None, or known format name).
        path: Path to the session artifact.
        confidence_min: Effective minimum winner confidence for auto-detection
            (default CONFIDENCE_MIN). Ignored for explicit (non-auto) overrides.
        margin_min: Effective minimum winner margin for auto-detection
            (default MARGIN_MIN). Ignored for explicit (non-auto) overrides.

    Returns:
        tuple of (resolved_format, detection_result, findings):
        - On successful resolution: (format_name, result, [])
        - On detection failure: (None, result, [finding])

    Raises:
        ValueError: If explicit format string is unknown (caller maps to exit code 2).
        FileNotFoundError / IsADirectoryError: Propagated from filesystem inspection.
    """
    validate_detection_thresholds(confidence_min, margin_min)
    path_obj = Path(path)
    path_str = str(path_obj).replace("\\", "/")

    if explicit is not None:
        normalized = explicit.strip().lower()
        if normalized != FORMAT_AUTO:
            if normalized not in SUPPORTED_FORMATS:
                valid_sorted = sorted(VALID_FORMAT_OPTIONS)
                raise ValueError(f"Unknown format {explicit!r}. Must be one of {valid_sorted}")
            return (
                normalized,
                DetectionResult(
                    format=normalized,
                    confidences={},
                    reason=REASON_EXPLICIT_OVERRIDE,
                ),
                [],
            )

    result = detect_format(path_obj, confidence_min=confidence_min, margin_min=margin_min)
    if result.format is not None:
        return (result.format, result, [])

    # Format could not be determined: fail closed with exactly one finding
    source_ref = SourceRef(path=path_str, line=1, record_id=None)

    if result.reason == REASON_REFUSED_LIVE_DB:
        finding = make_finding(
            code=SL001,
            severity=Severity.FATAL,
            repairability=Repairability.UNSUPPORTED,
            message_template=(
                "Refused live SQLite database; SessLint requires exported items or "
                "checkpoints [detail: refused_live_db]"
            ),
            source=source_ref,
            evidence={"reason": "refused_live_db"},
        )
        return (None, result, [finding])

    if result.reason == REASON_EMPTY:
        finding = make_finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message_template="Session input is empty [detail: EMPTY]",
            source=source_ref,
            evidence={"reason": "empty_input"},
        )
        return (None, result, [finding])

    # Low-confidence or tie -> emit SL302 ambiguous_format finding
    finding = make_finding(
        code=SL302,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template=(
            "Unable to determine session format with sufficient confidence "
            "[detail: ambiguous_format]"
        ),
        source=source_ref,
        evidence={
            "reason": result.reason,
            "confidences": result.confidences,
            "confidence_min": confidence_min,
            "margin_min": margin_min,
        },
    )
    return (None, result, [finding])
