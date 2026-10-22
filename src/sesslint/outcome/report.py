"""OutcomeGuard report envelope, human rendering and contract explanation.

``sesslint.outcome-report/v1`` keeps four dimensions apart (session integrity,
outcome verification, monitoring health, incident handling) so no single
green light can stand in for them. Reports carry keys, field names, counts and
times only — never other field values from the snapshots (EVD-04).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from sesslint._canonical_codec import canonical_json_bytes
from sesslint._version import CLI_VERSION
from sesslint.outcome.contract import Condition, Contract, Predicate
from sesslint.outcome.engine import (
    HASHED_KEY_LIMITATION,
    LIMITATIONS,
    MAX_UNMATCHED_KEYS,
    NOT_APPLICABLE,
    REASONS,
    STATUSES,
    VERIFIED,
    Evaluation,
    ItemResult,
)
from sesslint.outcome.snapshot import format_instant

OUTCOME_REPORT_SCHEMA_VERSION: Final[str] = "sesslint.outcome-report/v1"
MAX_HUMAN_ITEMS: Final[int] = 50
_PASSING: Final[frozenset[str]] = frozenset({VERIFIED, NOT_APPLICABLE})
_SESSION_LABELS: Final[dict[str, str]] = {
    "not_linked": "not linked (no session supplied)",
    "no_findings": "no findings in the checks run",
    "findings": "findings present",
    "unreadable": "unreadable or unsupported format",
}


def session_dimension(
    path: Path | str | None, *, max_file_bytes: int | None = None
) -> dict[str, Any]:
    """Session integrity for a user-linked session file, kept separate from outcomes (EXE-03).

    The link is recorded as user-asserted: SessLint never infers which session
    produced which outcome, and never edits or replays the session.
    """
    if path is None:
        return {"status": "not_linked"}
    from sesslint.api import check_file
    from sesslint.io import DEFAULT_MAX_FILE_BYTES

    try:
        report = check_file(path, max_file_bytes=max_file_bytes or DEFAULT_MAX_FILE_BYTES)
    except (OSError, ValueError):
        return {"status": "unreadable", "link": "user_asserted", "assurance": "A0"}
    if report.assurance == "A0":
        status = "unreadable"
    else:
        status = "findings" if report.counts.total else "no_findings"
    return {
        "status": status,
        "link": "user_asserted",
        "assurance": report.assurance,
        "finding_count": report.counts.total,
        "by_code": dict(sorted(report.counts.by_code.items())),
        "source_fingerprint": report.source_fingerprint,
    }


def _hashed(key: tuple[str, ...]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(list(key))).hexdigest()[:16]


@dataclass(frozen=True, slots=True)
class OutcomeReport:
    """Frozen presentation of one evaluation; ``exit_code`` is 0 only for VERIFIED."""

    evaluation: Evaluation
    session: Mapping[str, Any] = field(default_factory=lambda: {"status": "not_linked"})
    hash_keys: bool = False
    all_conditions: bool = False

    @property
    def outcome(self) -> str:
        return self.evaluation.outcome

    @property
    def exit_code(self) -> int:
        return 0 if self.evaluation.outcome == VERIFIED else 1

    @property
    def demo(self) -> bool:
        return self.evaluation.source.demo or self.evaluation.target.demo

    def _key(self, key: tuple[str, ...] | None) -> list[str] | str | None:
        if key is None:
            return None
        return _hashed(key) if self.hash_keys else list(key)

    def _limitations(self) -> list[str]:
        limitations = list(LIMITATIONS)
        if self.hash_keys:
            limitations.append(HASHED_KEY_LIMITATION)
        return limitations

    def _ordered_items(self) -> list[ItemResult]:
        items = list(self.evaluation.items)
        if self.hash_keys:
            # Plain-key order would leak the relative order of the hidden keys.
            items.sort(key=lambda i: (i.key is None, _hashed(i.key) if i.key else "", i.source_row))
        return items

    def _conditions(self, item: ItemResult) -> list[dict[str, Any]]:
        if self.all_conditions or item.status not in _PASSING:
            return [c.to_dict() for c in item.conditions]
        # Passing items list only the conditions that did not pass (advisory, disabled).
        return [c.to_dict() for c in item.conditions if c.status not in _PASSING]

    def _condition_summary(self) -> dict[str, dict[str, int]]:
        summary = {c.id: dict.fromkeys(STATUSES, 0) for c in self.evaluation.contract.conditions}
        for item in self.evaluation.items:
            for result in item.conditions:
                summary[result.id][result.status] += 1
        return summary

    def _item(self, item: ItemResult) -> dict[str, Any]:
        out: dict[str, Any] = {
            "key": self._key(item.key),
            "source_row": item.source_row,
            "source_rows": item.source_rows,
            "status": item.status,
            "reason": item.reason,
            "deadline": format_instant(item.deadline),
            "matched_records": item.matched_records,
            "conditions": self._conditions(item),
        }
        if item.detail:
            out["detail"] = dict(item.detail)
        return out

    def to_dict(self) -> dict[str, Any]:
        ev = self.evaluation
        unmatched: list[list[str] | str | None] = [self._key(k) for k in ev.unmatched_target_keys]
        if self.hash_keys:
            unmatched.sort(key=str)
        return {
            "schema_version": OUTCOME_REPORT_SCHEMA_VERSION,
            "tool_version": CLI_VERSION,
            "run_status": "completed",
            "evaluated_at": format_instant(ev.as_of),
            "outcome": ev.outcome,
            "outcome_reasons": list(ev.outcome_reasons),
            "demo": self.demo,
            "dimensions": {
                "session_integrity": dict(self.session),
                "outcome_verification": {"status": ev.outcome},
                "monitoring_health": {
                    "status": "not_configured",
                    "detail": "snapshot evaluation; no live monitoring",
                },
                "incident_handling": {"status": "not_tracked"},
            },
            "contract": {
                "name": ev.contract.name,
                "version": ev.contract.version,
                "sha256": ev.contract.sha256,
                "condition_count": len(ev.contract.conditions),
                "warnings": list(ev.contract.warnings()),
            },
            "observations": {
                "source": ev.source.to_dict(),
                "target": ev.target.to_dict(),
            },
            "coverage": dict(ev.coverage),
            "condition_summary": self._condition_summary(),
            "condition_detail": "all" if self.all_conditions else "non_passing",
            "key_display": "sha256" if self.hash_keys else "plain",
            "items": [self._item(item) for item in self._ordered_items()],
            "unmatched_target_keys": unmatched[:MAX_UNMATCHED_KEYS],
            "unmatched_target_keys_truncated": len(unmatched) > MAX_UNMATCHED_KEYS,
            "limitations": self._limitations(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=True, indent=2, sort_keys=True)

    def _display_key(self, item: ItemResult) -> str:
        if item.key is None:
            return f"(source record {item.source_row}, no key)"
        if self.hash_keys:
            return _hashed(item.key)
        return " | ".join(json.dumps(part, ensure_ascii=True) for part in item.key)

    def render_human(self) -> str:
        ev = self.evaluation
        counts = ev.coverage["counts"]
        lines = [
            f"SessLint outcome: {ev.outcome}  "
            f"(contract {ev.contract.name} v{ev.contract.version}, "
            f"evaluated at {format_instant(ev.as_of)})",
        ]
        if self.demo:
            lines.append("  DEMO DATA - not a verification of real work")
        session_status = str(self.session.get("status", "not_linked"))
        lines += [
            "Dimensions:",
            f"  session integrity:    {_SESSION_LABELS.get(session_status, session_status)}",
            f"  outcome verification: {ev.outcome}",
            "  monitoring health:    not configured (snapshot evaluation)",
            "  incident handling:    not tracked",
            "Observations:",
        ]
        for snap in (ev.source, ev.target):
            observed = format_instant(snap.observed_at) or "time unknown"
            lines.append(
                f"  {snap.role}: {len(snap.records)} records, {snap.completeness}, "
                f"observed {observed} ({snap.origin}, {snap.input_format})"
            )
        cov = ev.coverage
        lines.append(
            f"Items: {cov['work_items']} work items from {cov['source_rows']} source rows; "
            + ", ".join(f"{s} {counts[s]}" for s in STATUSES if counts[s])
        )
        if cov["unmatched_target_records"]:
            lines.append(
                f"  {cov['unmatched_target_records']} target record(s) match no source item"
            )
        problems = [i for i in self._ordered_items() if i.status not in _PASSING]
        if problems:
            lines.append(f"Items needing attention (first {MAX_HUMAN_ITEMS}):")
        for item in problems[:MAX_HUMAN_ITEMS]:
            lines.append(f"  {item.status:<13} {self._display_key(item)}")
            decisive = [c for c in item.conditions if c.status == item.status and not c.advisory]
            if not decisive:
                lines.append(f"      {REASONS[item.reason]}")
            by_reason: dict[str, list[str]] = {}
            for cond in decisive:
                by_reason.setdefault(cond.reason, []).append(cond.id)
            for reason, ids in by_reason.items():
                lines.append(f"      {', '.join(ids)}: {reason} - {REASONS[reason]}")
        if len(problems) > MAX_HUMAN_ITEMS:
            lines.append(f"  ... {len(problems) - MAX_HUMAN_ITEMS} more (use --json)")
        lines.append("Outcome reasons:")
        lines.extend(f"  - {code}: {REASONS[code]}" for code in ev.outcome_reasons)
        warnings = ev.contract.warnings()
        if warnings:
            lines.append("Contract warnings:")
            lines.extend(f"  - {w}" for w in warnings)
        lines.append("Limitations:")
        lines.extend(f"  - {text}" for text in self._limitations())
        return "\n".join(lines)


def _literal(value: object) -> str:
    """A contract value in JSON text form; numbers keep every written digit (CON-03)."""
    return json.dumps(value, ensure_ascii=True)


def _describe_predicate(pred: Predicate) -> str:
    if pred.op == "present":
        return f"{pred.field} is present and non-empty"
    if pred.op == "absent":
        return f"{pred.field} is absent, null or empty"
    if pred.op in ("in", "not_in"):
        joined = ", ".join(_literal(v) for v in pred.values)
        return f"{pred.field} {'is' if pred.op == 'in' else 'is not'} one of {joined}"
    symbol = {"eq": "=", "ne": "!=", "gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[pred.op]
    return f"{pred.field} {symbol} {_literal(pred.value)}"


def _describe_condition(cond: Condition) -> str:
    norm = f" (after {', '.join(cond.normalize)})" if cond.normalize else ""
    values = ", ".join(_literal(v) for v in cond.values)
    if cond.type == "exists":
        text = "at least one matching target record exists"
    elif cond.type == "count":
        low = int(cond.minimum or 0)
        high = None if cond.maximum is None else int(cond.maximum)
        if high is None:
            text = f"at least {low} matching target record(s) exist"
        elif low == high:
            text = f"exactly {low} matching target record(s) exist"
        else:
            text = f"between {low} and {high} matching target records exist"
    elif cond.type == "required":
        allowed = [n for n, ok in (("null", cond.allow_null), ("empty", cond.allow_empty)) if ok]
        extra = f" ({' and '.join(allowed)} allowed)" if allowed else ""
        text = f"target field {cond.field} is present, non-null and non-empty{extra}"
    elif cond.type == "type":
        text = f"target field {cond.field}, when present, is a {cond.kind}"
    elif cond.type == "one_of":
        text = f"target field {cond.field}, when present, is one of {values}{norm}"
    elif cond.type == "equals":
        text = f"target field {cond.field} equals source field {cond.source_field}{norm}"
    elif cond.type == "range":
        bounds = []
        if cond.minimum is not None:
            bounds.append(f">= {_literal(cond.minimum)}")
        if cond.maximum is not None:
            bounds.append(f"<= {_literal(cond.maximum)}")
        text = f"target field {cond.field}, when present, is a number {' and '.join(bounds)}"
    elif cond.type == "route":
        when = " and ".join(_describe_predicate(p) for p in cond.when)
        text = f"when {when}: target field {cond.field} is one of {values}{norm}"
    elif cond.type == "on_time":
        if cond.basis == "target_time":
            text = (
                f"target completion time {cond.field} is at or before the deadline; only times "
                "from the source event up to the target observation count"
            )
        else:
            text = (
                "the record is visible in a target snapshot taken at or before the deadline "
                "and not before the source event"
            )
    else:
        text = "any one of: " + "; ".join(_describe_condition(c) for c in cond.conditions)
    if cond.disabled is not None:
        text += f" [disabled: {cond.disabled}]"
    elif cond.advisory:
        text += " [advisory: reported, does not decide the outcome]"
    return text


def explain_contract(contract: Contract) -> str:
    """Plain-language restatement of exactly what the contract checks (CON-03)."""
    lines = [
        f"Contract {contract.name} v{contract.version} (sha256 {contract.sha256[:16]})",
    ]
    if contract.description:
        lines.append(f"  {contract.description}")
    lines.append(
        "Work items: one per distinct source key ("
        + ", ".join(contract.source_key)
        + "), matched exactly to target key ("
        + ", ".join(contract.target_key)
        + ")."
    )
    if contract.eligibility:
        lines.append("Applies only when all of:")
        lines.extend(f"  - {_describe_predicate(p)}" for p in contract.eligibility)
    else:
        lines.append("Applies to every keyed source record.")
    if contract.due is not None:
        lines.append(
            f"Deadline: {contract.due.source_time_field} + {contract.due.within_seconds}s; "
            "before it, missing results are PENDING."
        )
    lines.append("Conditions:")
    lines.extend(f"  - {c.id}: {_describe_condition(c)}" for c in contract.conditions)
    for warning in contract.warnings():
        lines.append(f"Warning: {warning}")
    lines.append(
        "Absence is proven only from a target snapshot declared complete and observed at "
        "or after the deadline; otherwise the verdict is INCONCLUSIVE."
    )
    return "\n".join(lines)
