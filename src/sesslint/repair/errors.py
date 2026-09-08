"""Typed error hierarchy for repair execution (TASK-021).

All repair execution errors inherit from RepairError (which subclasses SesslintError
and ValueError), ensuring structured refusal and failure reporting across library
and CLI entry points.
"""

from __future__ import annotations

from sesslint.errors import SesslintError


class RepairError(SesslintError, ValueError):
    """Base exception for all repair execution failures and refusals."""

    code: str = "REPAIR_ERROR"


class PlanTampered(RepairError):
    """Raised when recomputed plan fingerprint does not match declared plan fingerprint."""

    code: str = "PLAN_TAMPERED"


class Abstained(RepairError):
    """Raised when repair execution must abstain due to SL203 or side-effects."""

    code: str = "ABSTAINED"


class PolicyMismatch(RepairError):
    """Raised when plan policy does not match the execution policy."""

    code: str = "POLICY_MISMATCH"


class OutputInvalid(RepairError):
    """Raised when repaired output fails schema, multiset, revalidation, or cap checks."""

    code: str = "OUTPUT_INVALID"


class RepairRefused(RepairError):
    """Raised when repair is refused due to invalid destination, live-store, etc."""

    code: str = "REPAIR_REFUSED"


class PlanSourceMismatch(RepairError):
    """Raised when plan.source_hash does not match the source file bytes SHA-256."""

    code: str = "PLAN_SOURCE_MISMATCH"


__all__ = [
    "Abstained",
    "OutputInvalid",
    "PlanSourceMismatch",
    "PlanTampered",
    "PolicyMismatch",
    "RepairError",
    "RepairRefused",
]
