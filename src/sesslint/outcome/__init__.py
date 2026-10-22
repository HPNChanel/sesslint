"""OutcomeGuard: offline outcome-contract verification over observed snapshots.

Session integrity answers "is this transcript structurally sound?"; outcome
verification answers "did the work produce the declared result at the
target?". The two are reported side by side and never merged (EXE-04).
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from sesslint.outcome.contract import (
    CONTRACT_SCHEMA_VERSION,
    Contract,
    ContractError,
    contract_from_dict,
    load_contract,
)
from sesslint.outcome.engine import (
    REASONS,
    STATUSES,
    EvaluationError,
    evaluate,
)
from sesslint.outcome.report import (
    OUTCOME_REPORT_SCHEMA_VERSION,
    OutcomeReport,
    explain_contract,
    session_dimension,
)
from sesslint.outcome.snapshot import (
    SNAPSHOT_SCHEMA_VERSION,
    Snapshot,
    SnapshotError,
    load_snapshot,
    parse_instant,
)

__all__ = [
    "CONTRACT_SCHEMA_VERSION",
    "OUTCOME_REPORT_SCHEMA_VERSION",
    "REASONS",
    "SNAPSHOT_SCHEMA_VERSION",
    "STATUSES",
    "Contract",
    "ContractError",
    "EvaluationError",
    "OutcomeReport",
    "Snapshot",
    "SnapshotError",
    "contract_from_dict",
    "evaluate",
    "explain_contract",
    "load_contract",
    "load_snapshot",
    "parse_instant",
    "session_dimension",
    "verify_outcome",
]


def verify_outcome(
    contract: Path | str | Contract,
    source: Path | str | Snapshot,
    target: Path | str | Snapshot,
    *,
    as_of: datetime | None = None,
    session: Path | str | None = None,
    hash_keys: bool = False,
    all_conditions: bool = False,
) -> OutcomeReport:
    """Load inputs, reconcile them and return the report (ITF-02).

    ``as_of`` defaults to the target observation time; with neither, an
    ``EvaluationError`` is raised — the wall clock is never consulted.
    """
    resolved = contract if isinstance(contract, Contract) else load_contract(contract)
    src = source if isinstance(source, Snapshot) else load_snapshot(source, role="source")
    tgt = target if isinstance(target, Snapshot) else load_snapshot(target, role="target")
    instant = as_of if as_of is not None else tgt.observed_at
    if instant is None:
        raise EvaluationError(
            "an evaluation instant is required: pass as_of or a target observed_at"
        )
    evaluation = evaluate(resolved, src, tgt, as_of=instant)
    return OutcomeReport(
        evaluation,
        session_dimension(session),
        hash_keys=hash_keys,
        all_conditions=all_conditions,
    )
