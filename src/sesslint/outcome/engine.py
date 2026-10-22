"""OutcomeGuard reconciliation engine (REC-01…REC-08, RULE-01…RULE-08, EVD-06/07).

Deterministic and offline: the evaluation instant is an input, never the wall
clock. Every verdict is scoped to the supplied observations. Absence is proven
only from a complete target snapshot observed at or after the deadline; any
weaker evidence yields INCONCLUSIVE with the reason that blocked the proof.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Final

from sesslint.outcome.contract import Condition, Contract, Predicate, Scalar
from sesslint.outcome.snapshot import (
    NON_SCALAR,
    Record,
    Snapshot,
    Value,
    format_instant,
    parse_instant,
)

VERIFIED: Final = "VERIFIED"
VIOLATED: Final = "VIOLATED"
PENDING: Final = "PENDING"
INCONCLUSIVE: Final = "INCONCLUSIVE"
NOT_APPLICABLE: Final = "NOT_APPLICABLE"
NOT_EVALUATED: Final = "NOT_EVALUATED"
STATUSES: Final[tuple[str, ...]] = (
    VERIFIED,
    VIOLATED,
    PENDING,
    INCONCLUSIVE,
    NOT_APPLICABLE,
    NOT_EVALUATED,
)

# Stable reason vocabulary (ITF-04). Text explains the evidence, never the data.
REASONS: Final[dict[str, str]] = {
    "present": "a matching target record was observed",
    "count_within": "the matched record count is within bounds in a complete snapshot",
    "missing": "no matching target record in a complete snapshot observed at or after the deadline",
    "too_few": "fewer matching records than required in a complete snapshot observed at or after "
    "the deadline",
    "too_many": "more matching records than allowed in a complete snapshot",
    "duplicates_unconfirmed": "more matching records than allowed were seen, but the snapshot is "
    "not declared complete, so paging artifacts cannot be excluded",
    "upper_bound_unproven": "enough records were seen, but only a complete snapshot can show "
    "there are no extra ones",
    "awaiting_due": "the deadline has not passed at the evaluation instant",
    "due_unknown": "the source event time is absent or has no UTC offset, so the deadline is "
    "unknown",
    "target_unavailable": "the target observation is marked unavailable",
    "target_incomplete": "the target snapshot is not declared complete, so absence cannot be "
    "proven",
    "target_stale": "the target snapshot was observed before the deadline",
    "target_observed_at_unknown": "the target snapshot has no observation time",
    "target_unkeyed_rows": "some target rows have no usable key, so a missing record may be "
    "hidden behind a broken mapping",
    "no_target_record": "no matched target record to inspect",
    "field_not_in_snapshot": "the field does not occur anywhere in the snapshot (mapping changed?)",
    "field_present": "the field holds an accepted value",
    "field_absent": "the field is absent from the matched record",
    "field_null": "the field is null",
    "field_empty": "the field is an empty string",
    "value_absent": "the optional value is absent or null; pair with a required condition to "
    "demand it",
    "value_nested": "the value is nested and cannot be compared",
    "type_ok": "the value has the declared kind",
    "type_mismatch": "the value does not have the declared kind",
    "value_allowed": "the value is in the allowed set",
    "value_not_allowed": "the value is not in the allowed set",
    "in_range": "the value is within the declared bounds",
    "out_of_range": "the value is outside the declared bounds",
    "not_a_number": "the value is not a number",
    "values_match": "source and target values match after the declared normalization",
    "values_differ": "source and target values differ after the declared normalization",
    "source_value_absent": "the source value is absent, null or nested",
    "target_value_absent": "the target value is absent or null",
    "route_not_applicable": "the route predicate is false for this item",
    "route_undecidable": "a route predicate field is absent or not comparable",
    "route_ok": "the record is on the declared route",
    "wrong_route": "the record exists but is not on the declared route",
    "completed_on_time": "the target completion time is at or before the deadline",
    "late": "the target completion time is after the deadline",
    "late_unconfirmed": (
        "the visible completion is late, but an earlier record may be missing from an "
        "incomplete snapshot"
    ),
    "not_completed_by_deadline": "no matching record in a complete snapshot observed at or after "
    "the deadline",
    "completion_time_unusable": "the target completion time is absent or has no UTC offset",
    "observed_on_time": "the record was visible in a snapshot taken at or before the deadline",
    "first_seen_after_deadline": "the record was first supplied in a snapshot taken after the "
    "deadline; earlier visibility is unknown",
    "disabled": "the condition is disabled in the contract",
    "any_branch_verified": "at least one branch is verified",
    "all_branches_violated": "every applicable branch is violated",
    "branches_undecided": "no branch is verified and at least one could not be decided",
    "branches_pending": "no branch is verified and at least one is still within its deadline",
    "branches_not_applicable": "no branch applies to this item",
    "conditions_verified": "every decisive condition is verified",
    "condition_violated": "at least one decisive condition is violated",
    "condition_inconclusive": "at least one decisive condition could not be decided",
    "condition_pending": "at least one decisive condition is still within its deadline",
    "conditions_not_applicable": "no decisive condition applies to this item",
    "conditions_not_evaluated": "no decisive condition could be evaluated",
    "conditions_partly_evaluated": (
        "the evaluated conditions are verified, but at least one decisive condition "
        "could not be evaluated"
    ),
    "key_missing": "the source record has no value for a key field",
    "key_invalid": "a key value is not a non-empty string or integer",
    "source_conflict": "source rows sharing this key disagree on contract-relevant fields",
    "not_eligible": "an eligibility predicate is false; excluded by the contract",
    "eligibility_undecidable": "an eligibility field is absent or not comparable",
    "source_unavailable": "the source observation is marked unavailable",
    "source_coverage_unproven": "the source snapshot is not declared complete, so items it does "
    "not list were not evaluated",
    "source_key_field_absent": "a source key field occurs nowhere in the source snapshot",
    "target_key_field_absent": "a target key field occurs nowhere in the target snapshot",
    "no_source_items": "the source snapshot lists no work items",
    "some_items_violated": "at least one item is violated",
    "some_items_inconclusive": "at least one item could not be decided",
    "some_items_pending": "at least one item is still within its deadline",
    "all_items_verified": "every applicable item is verified",
    "all_items_not_applicable": "every item is excluded by eligibility",
    "items_not_evaluated": "no item could be evaluated",
    "some_items_not_evaluated": (
        "the other items are verified, but at least one item could not be evaluated"
    ),
}

LIMITATIONS: Final[tuple[str, ...]] = (
    "Verdicts cover only the supplied snapshots at their observation times; they do not "
    "prove who or what produced a record, exactly-once effects, or semantic correctness.",
    "Absence is proven only from a target snapshot declared complete and observed at or "
    "after the deadline; a session that looks clean is not evidence of a correct outcome.",
    "Keys are compared exactly, without trimming, case folding or numeric conversion.",
)
HASHED_KEY_LIMITATION: Final[str] = (
    "Hashed keys are pseudonymous, not anonymous: small key spaces can be enumerated."
)
MAX_UNMATCHED_KEYS: Final[int] = 1000

_PRIORITY: Final[dict[str, int]] = {
    VIOLATED: 0,
    INCONCLUSIVE: 1,
    PENDING: 2,
    VERIFIED: 3,
    NOT_EVALUATED: 4,
    NOT_APPLICABLE: 5,
}
_NUMBER_RE: Final = re.compile(r"^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$")
_INTEGER_RE: Final = re.compile(r"^[+-]?\d+$")


class EvaluationError(ValueError):
    """Inputs are mutually inconsistent (e.g. an evaluation instant before an observation)."""


@dataclass(frozen=True, slots=True)
class ConditionResult:
    """Verdict for one condition on one work item."""

    id: str
    type: str
    status: str
    reason: str
    advisory: bool = False
    detail: Mapping[str, Any] = field(default_factory=dict)
    branches: tuple[ConditionResult, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "type": self.type,
            "status": self.status,
            "reason": self.reason,
            "advisory": self.advisory,
        }
        if self.detail:
            out["detail"] = dict(self.detail)
        if self.branches:
            out["branches"] = [b.to_dict() for b in self.branches]
        return out


@dataclass(frozen=True, slots=True)
class ItemResult:
    """Verdict for one work item (a unique source key, or an unkeyed source row)."""

    key: tuple[str, ...] | None
    source_row: int
    source_rows: int
    status: str
    reason: str
    deadline: datetime | None
    matched_records: int
    conditions: tuple[ConditionResult, ...]
    detail: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Evaluation:
    """Engine output before presentation (see ``sesslint.outcome.report``)."""

    contract: Contract
    source: Snapshot
    target: Snapshot
    as_of: datetime
    outcome: str
    outcome_reasons: tuple[str, ...]
    items: tuple[ItemResult, ...]
    coverage: Mapping[str, Any]
    unmatched_target_keys: tuple[tuple[str, ...], ...]


def worst(statuses: Iterable[str]) -> str | None:
    """Highest-priority status (VIOLATED first), or None for an empty input."""
    return min(statuses, key=_PRIORITY.__getitem__, default=None)


def _text(value: Value) -> str | None:
    """Canonical comparison text; integral numbers render without a fraction."""
    if value is None or value is NON_SCALAR:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(int(value)) if value.is_integer() and abs(value) < 2**63 else repr(value)
    return str(value)


def _normalized(value: Value | Scalar, steps: Sequence[str]) -> str | None:
    text = _text(value)
    if text is None:
        return None
    if "trim" in steps:
        text = text.strip()
    if "casefold" in steps:
        text = text.casefold()
    return text


def _number(value: Value, *, typed: bool) -> float | None:
    """Strict numeric coercion; strings parse only for untyped (CSV) snapshots."""
    if isinstance(value, bool) or value is None or value is NON_SCALAR:
        return None
    try:
        if isinstance(value, int):
            # Exact: Python compares big integers with floats without overflow.
            return value
        if isinstance(value, float):
            number = value
        elif isinstance(value, str) and not typed and _NUMBER_RE.match(value):
            number = float(value)
        else:
            return None
    except OverflowError:
        return None
    return number if number == number and abs(number) != float("inf") else None


def _equal(source: Value, target: Value, steps: Sequence[str], ctx: _Context) -> bool:
    """Text equality, except that a typed JSON number compares numerically.

    CSV ``12.50`` and JSON ``12.5`` denote the same number; two strings are
    still compared as text so codes such as ``0012`` and ``12`` stay distinct.
    """
    json_number = any(
        isinstance(v, (int, float)) and not isinstance(v, bool) for v in (source, target)
    )
    if json_number:
        left = _number(source, typed=ctx.source_typed)
        right = _number(target, typed=ctx.target_typed)
        if left is not None and right is not None:
            return left == right
    return _normalized(source, steps) == _normalized(target, steps)


def _kind_ok(value: Value, kind: str, *, typed: bool) -> bool:
    if kind == "string":
        return isinstance(value, str)
    if kind == "integer":
        if isinstance(value, bool):
            return False
        if isinstance(value, int):
            return True
        return isinstance(value, str) and not typed and bool(_INTEGER_RE.match(value))
    if kind == "number":
        return _number(value, typed=typed) is not None
    if kind == "boolean":
        if isinstance(value, bool):
            return True
        return isinstance(value, str) and not typed and value in ("true", "false")
    if kind == "date-time":
        return parse_instant(value) is not None
    return False


def _predicate(pred: Predicate, record: Record, *, typed: bool) -> bool | None:
    """True/False, or None when the field is absent or not comparable."""
    if pred.op in ("present", "absent"):
        present = pred.field in record and record[pred.field] not in (None, "")
        return present if pred.op == "present" else not present
    if pred.field not in record or record[pred.field] is NON_SCALAR:
        return None
    value = record[pred.field]
    if pred.op in ("eq", "ne", "in", "not_in"):
        wanted = pred.values if pred.op in ("in", "not_in") else (pred.value,)
        match = _text(value) in {_text(w) for w in wanted}
        return match if pred.op in ("eq", "in") else not match
    number = _number(value, typed=typed)
    if number is None or not isinstance(pred.value, (int, float)):
        return None
    bound: float = pred.value
    return {
        "gt": number > bound,
        "gte": number >= bound,
        "lt": number < bound,
        "lte": number <= bound,
    }[pred.op]


def _all_predicates(
    preds: Sequence[Predicate], record: Record, *, typed: bool
) -> tuple[bool | None, int]:
    """Conjunction: False wins over unknown; returns (result, deciding index)."""
    unknown = -1
    for index, pred in enumerate(preds):
        result = _predicate(pred, record, typed=typed)
        if result is False:
            return False, index
        if result is None and unknown < 0:
            unknown = index
    return (None, unknown) if unknown >= 0 else (True, -1)


def _key(record: Record, fields: Sequence[str]) -> tuple[tuple[str, ...] | None, str | None]:
    parts: list[str] = []
    for name in fields:
        if name not in record or record[name] is None:
            return None, "key_missing"
        value = record[name]
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            return None, "key_invalid"
        text = str(value)
        if not text:
            return None, "key_missing"
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            return None, "key_invalid"
        parts.append(text)
    return tuple(parts), None


@dataclass(slots=True)
class _Context:
    contract: Contract
    target: Snapshot
    as_of: datetime
    unkeyed_target_rows: int
    source_typed: bool
    target_typed: bool
    _allowed: dict[str, frozenset[str | None]] = field(default_factory=dict)

    def allowed(self, cond: Condition) -> frozenset[str | None]:
        """Normalized allowed values, computed once per condition."""
        cached = self._allowed.get(cond.id)
        if cached is None:
            cached = frozenset(_normalized(v, cond.normalize) for v in cond.values)
            self._allowed[cond.id] = cached
        return cached


def _absence_blocker(ctx: _Context, deadline: datetime | None) -> str | None:
    """Why absence at the target cannot be proven, or None when it can (REC-03/07)."""
    target = ctx.target
    if target.completeness != "complete":
        return "target_incomplete"
    if target.observed_at is None:
        return "target_observed_at_unknown"
    if deadline is not None and target.observed_at < deadline:
        return "target_stale"
    if ctx.unkeyed_target_rows:
        return "target_unkeyed_rows"
    return None


def _waiting(ctx: _Context, deadline: datetime | None, due_known: bool) -> tuple[str, str] | None:
    """Shared gate for conditions that need a target record that is not there yet."""
    if ctx.target.completeness == "unavailable":
        return INCONCLUSIVE, "target_unavailable"
    if not due_known:
        return INCONCLUSIVE, "due_unknown"
    if deadline is not None and ctx.as_of < deadline:
        return PENDING, "awaiting_due"
    return None


def _per_record(
    results: Sequence[tuple[str, str, Mapping[str, Any]]],
) -> tuple[str, str, Mapping[str, Any]]:
    status = worst(r[0] for r in results) or NOT_EVALUATED
    for result in results:
        if result[0] == status:
            return result
    return status, "no_target_record", {}


def _field_check(
    cond: Condition, records: Sequence[Record], ctx: _Context, source: Record
) -> tuple[str, str, Mapping[str, Any]]:
    assert cond.field is not None
    name = cond.field
    if name not in ctx.target.fields:
        return INCONCLUSIVE, "field_not_in_snapshot", {"field": name}
    typed = ctx.target_typed
    results: list[tuple[str, str, Mapping[str, Any]]] = []
    for record in records:
        present = name in record
        value = record.get(name)
        if cond.type == "required":
            if not present:
                results.append((VIOLATED, "field_absent", {"field": name}))
            elif value is None and not cond.allow_null:
                results.append((VIOLATED, "field_null", {"field": name}))
            elif value == "" and not cond.allow_empty:
                results.append((VIOLATED, "field_empty", {"field": name}))
            else:
                results.append((VERIFIED, "field_present", {"field": name}))
            continue
        if cond.type == "equals":
            assert cond.source_field is not None
            if cond.source_field not in source or _text(source[cond.source_field]) is None:
                results.append((INCONCLUSIVE, "source_value_absent", {"field": cond.source_field}))
            elif not present or value is None:
                results.append((VIOLATED, "target_value_absent", {"field": name}))
            elif value is NON_SCALAR:
                results.append((INCONCLUSIVE, "value_nested", {"field": name}))
            elif _equal(source[cond.source_field], value, cond.normalize, ctx):
                results.append((VERIFIED, "values_match", {"field": name}))
            else:
                results.append((VIOLATED, "values_differ", {"field": name}))
            continue
        if not present or value is None:
            if cond.type == "route":
                results.append((VIOLATED, "wrong_route", {"field": name}))
            else:
                results.append((NOT_APPLICABLE, "value_absent", {"field": name}))
            continue
        if value is NON_SCALAR:
            results.append((INCONCLUSIVE, "value_nested", {"field": name}))
            continue
        if cond.type == "type":
            assert cond.kind is not None
            ok = _kind_ok(value, cond.kind, typed=typed)
            results.append((VERIFIED if ok else VIOLATED, "type_ok" if ok else "type_mismatch", {}))
        elif cond.type in ("one_of", "route"):
            ok = _normalized(value, cond.normalize) in ctx.allowed(cond)
            if cond.type == "one_of":
                reason = "value_allowed" if ok else "value_not_allowed"
            else:
                reason = "route_ok" if ok else "wrong_route"
            results.append((VERIFIED if ok else VIOLATED, reason, {"field": name}))
        elif cond.type == "range":
            number = _number(value, typed=typed)
            if number is None:
                results.append((VIOLATED, "not_a_number", {"field": name}))
                continue
            low_ok = cond.minimum is None or number >= cond.minimum
            high_ok = cond.maximum is None or number <= cond.maximum
            ok = low_ok and high_ok
            results.append(
                (
                    VERIFIED if ok else VIOLATED,
                    "in_range" if ok else "out_of_range",
                    {"field": name},
                )
            )
    return _per_record(results)


def _count_check(
    cond: Condition, matched: int, ctx: _Context, deadline: datetime | None, due_known: bool
) -> tuple[str, str, Mapping[str, Any]]:
    low = 1 if cond.type == "exists" else int(cond.minimum or 0)
    high = None if cond.type == "exists" or cond.maximum is None else int(cond.maximum)
    detail: dict[str, Any] = {"matched_records": matched}
    if high is not None:
        detail["max"] = high
    if cond.type == "count":
        detail["min"] = low
    complete = ctx.target.completeness == "complete"
    if high is not None and matched > high:
        return (
            (VIOLATED, "too_many", detail)
            if complete
            else (
                INCONCLUSIVE,
                "duplicates_unconfirmed",
                detail,
            )
        )
    if matched >= max(low, 1) or (low == 0 and matched == 0 and high is not None):
        if high is None:
            return VERIFIED, "present", detail
        return (
            (VERIFIED, "count_within", detail)
            if complete
            else (
                INCONCLUSIVE,
                "upper_bound_unproven",
                detail,
            )
        )
    gate = _waiting(ctx, deadline, due_known)
    if gate is not None:
        return gate[0], gate[1], detail
    blocker = _absence_blocker(ctx, deadline)
    if blocker is not None:
        return INCONCLUSIVE, blocker, detail
    return VIOLATED, ("missing" if matched == 0 else "too_few"), detail


def _on_time_check(
    cond: Condition,
    records: Sequence[Record],
    ctx: _Context,
    deadline: datetime | None,
    due_known: bool,
) -> tuple[str, str, Mapping[str, Any]]:
    if ctx.target.completeness == "unavailable":
        return INCONCLUSIVE, "target_unavailable", {}
    if not due_known or deadline is None:
        return INCONCLUSIVE, "due_unknown", {}
    detail: dict[str, Any] = {"deadline": format_instant(deadline), "basis": cond.basis}
    if records:
        if cond.basis == "observation":
            observed = ctx.target.observed_at
            if observed is None:
                return INCONCLUSIVE, "target_observed_at_unknown", detail
            if observed <= deadline:
                return VERIFIED, "observed_on_time", detail
            return INCONCLUSIVE, "first_seen_after_deadline", detail
        assert cond.field is not None
        if cond.field not in ctx.target.fields:
            return INCONCLUSIVE, "field_not_in_snapshot", {**detail, "field": cond.field}
        times = [parse_instant(r.get(cond.field)) for r in records]
        valid = [t for t in times if t is not None]
        earliest = min(valid) if valid else None
        if earliest is not None and earliest <= deadline:
            return VERIFIED, "completed_on_time", detail
        if earliest is None or len(valid) != len(times):
            return INCONCLUSIVE, "completion_time_unusable", detail
        late_by = int((earliest - deadline).total_seconds())
        if ctx.target.completeness != "complete":
            # The earliest completion may sit in a record this snapshot does not show.
            return INCONCLUSIVE, "late_unconfirmed", {**detail, "late_by_seconds": late_by}
        return VIOLATED, "late", {**detail, "late_by_seconds": late_by}
    gate = _waiting(ctx, deadline, due_known)
    if gate is not None:
        return gate[0], gate[1], detail
    blocker = _absence_blocker(ctx, deadline)
    if blocker is not None:
        return INCONCLUSIVE, blocker, detail
    return VIOLATED, "not_completed_by_deadline", detail


def _evaluate_condition(
    cond: Condition,
    source: Record,
    records: Sequence[Record],
    ctx: _Context,
    deadline: datetime | None,
    due_known: bool,
) -> ConditionResult:
    def done(status: str, reason: str, detail: Mapping[str, Any] | None = None) -> ConditionResult:
        return ConditionResult(cond.id, cond.type, status, reason, cond.advisory, detail or {})

    if cond.disabled is not None:
        return done(NOT_EVALUATED, "disabled")
    if cond.type in ("exists", "count"):
        return done(*_count_check(cond, len(records), ctx, deadline, due_known))
    if cond.type == "on_time":
        return done(*_on_time_check(cond, records, ctx, deadline, due_known))
    if cond.type == "any_of":
        branches = tuple(
            _evaluate_condition(b, source, records, ctx, deadline, due_known)
            for b in cond.conditions
        )
        statuses = {b.status for b in branches}
        if VERIFIED in statuses:
            status, reason = VERIFIED, "any_branch_verified"
        elif INCONCLUSIVE in statuses:
            status, reason = INCONCLUSIVE, "branches_undecided"
        elif PENDING in statuses:
            status, reason = PENDING, "branches_pending"
        elif VIOLATED in statuses:
            status, reason = VIOLATED, "all_branches_violated"
        elif NOT_EVALUATED in statuses:
            status, reason = NOT_EVALUATED, "no_target_record"
        else:
            status, reason = NOT_APPLICABLE, "branches_not_applicable"
        return ConditionResult(cond.id, cond.type, status, reason, cond.advisory, {}, branches)
    if cond.type == "route":
        applies, index = _all_predicates(cond.when, source, typed=ctx.source_typed)
        if applies is False:
            return done(NOT_APPLICABLE, "route_not_applicable")
        if applies is None:
            return done(INCONCLUSIVE, "route_undecidable", {"field": cond.when[index].field})
    if not records:
        gate = _waiting(ctx, deadline, due_known)
        if gate is not None:
            return done(*gate)
        return done(NOT_EVALUATED, "no_target_record")
    if ctx.target.completeness == "unavailable":
        return done(INCONCLUSIVE, "target_unavailable")
    return done(*_field_check(cond, records, ctx, source))


def _item_verdict(results: Sequence[ConditionResult]) -> tuple[str, str]:
    decisive = [r.status for r in results if not r.advisory and r.reason != "disabled"]
    status = worst(decisive) or NOT_EVALUATED
    if status == VERIFIED and NOT_EVALUATED in decisive:
        # A condition that could not run is never counted as a pass.
        return INCONCLUSIVE, "conditions_partly_evaluated"
    reason = {
        VIOLATED: "condition_violated",
        INCONCLUSIVE: "condition_inconclusive",
        PENDING: "condition_pending",
        VERIFIED: "conditions_verified",
        NOT_EVALUATED: "conditions_not_evaluated",
        NOT_APPLICABLE: "conditions_not_applicable",
    }[status]
    return status, reason


@dataclass(slots=True)
class _Group:
    key: tuple[str, ...]
    first_row: int
    rows: list[Record]


def _conflicting(rows: Sequence[Record], fields: frozenset[str]) -> bool:
    first = rows[0]
    for row in rows[1:]:
        for name in fields:
            if (name in first) != (name in row) or _text(first.get(name)) != _text(row.get(name)):
                return True
            if (first.get(name) is NON_SCALAR) != (row.get(name) is NON_SCALAR):
                return True
    return False


def _evaluate_item(
    contract: Contract,
    ctx: _Context,
    key: tuple[str, ...],
    group: _Group,
    matched: Sequence[Record],
    relevant: frozenset[str],
) -> ItemResult:
    def item(
        status: str,
        reason: str,
        *,
        deadline: datetime | None = None,
        conditions: tuple[ConditionResult, ...] = (),
        detail: Mapping[str, Any] | None = None,
    ) -> ItemResult:
        return ItemResult(
            key=key,
            source_row=group.first_row,
            source_rows=len(group.rows),
            status=status,
            reason=reason,
            deadline=deadline,
            matched_records=len(matched),
            conditions=conditions,
            detail=detail or {},
        )

    if len(group.rows) > 1 and _conflicting(group.rows, relevant):
        return item(INCONCLUSIVE, "source_conflict")
    record = group.rows[0]
    eligible, pred_index = _all_predicates(contract.eligibility, record, typed=ctx.source_typed)
    if eligible is not True:
        detail = {"predicate": pred_index, "field": contract.eligibility[pred_index].field}
        if eligible is False:
            return item(NOT_APPLICABLE, "not_eligible", detail=detail)
        return item(INCONCLUSIVE, "eligibility_undecidable", detail=detail)
    deadline: datetime | None = None
    due_known = True
    if contract.due is not None:
        started = parse_instant(record.get(contract.due.source_time_field))
        if started is None:
            due_known = False
        else:
            try:
                deadline = started + timedelta(seconds=contract.due.within_seconds)
            except OverflowError:
                due_known = False
    results = tuple(
        _evaluate_condition(cond, record, matched, ctx, deadline, due_known)
        for cond in contract.conditions
    )
    status, reason = _item_verdict(results)
    return item(status, reason, deadline=deadline, conditions=results)


def evaluate(
    contract: Contract,
    source: Snapshot,
    target: Snapshot,
    *,
    as_of: datetime,
) -> Evaluation:
    """Reconcile one source and one target observation against ``contract``."""
    if as_of.tzinfo is None:
        raise EvaluationError("the evaluation instant needs a UTC offset")
    for snap in (source, target):
        if snap.observed_at is not None and snap.observed_at > as_of:
            raise EvaluationError(
                f"the evaluation instant precedes the {snap.role} observation time"
            )
    issues: list[str] = []
    for name in contract.source_key:
        if source.records and name not in source.fields:
            issues.append("source_key_field_absent")
    for name in contract.target_key:
        if target.records and name not in target.fields:
            issues.append("target_key_field_absent")

    index: dict[tuple[str, ...], list[Record]] = {}
    unkeyed_target = 0
    for record in target.records:
        key, _problem = _key(record, contract.target_key)
        if key is None:
            unkeyed_target += 1
            continue
        index.setdefault(key, []).append(record)

    groups: dict[tuple[str, ...], _Group] = {}
    items: list[ItemResult] = []
    for row_no, record in enumerate(source.records, start=1):
        key, problem = _key(record, contract.source_key)
        if key is None:
            items.append(
                ItemResult(None, row_no, 1, INCONCLUSIVE, problem or "key_missing", None, 0, ())
            )
            continue
        group = groups.get(key)
        if group is None:
            groups[key] = _Group(key, row_no, [record])
        else:
            group.rows.append(record)

    ctx = _Context(
        contract=contract,
        target=target,
        as_of=as_of,
        unkeyed_target_rows=unkeyed_target,
        source_typed=source.input_format != "csv",
        target_typed=target.input_format != "csv",
    )
    relevant = contract.relevant_source_fields()
    for key, group in groups.items():
        items.append(_evaluate_item(contract, ctx, key, group, index.get(key, []), relevant))

    source_keys = set(groups)
    unmatched = tuple(sorted(k for k in index if k not in source_keys))
    items.sort(key=lambda i: (i.key is None, i.key or (), i.source_row))

    statuses = [i.status for i in items]
    outcome_reasons: list[str] = sorted(set(issues))
    if source.completeness == "unavailable":
        outcome, outcome_reasons = INCONCLUSIVE, ["source_unavailable", *outcome_reasons]
    elif not items:
        outcome, outcome_reasons = NOT_EVALUATED, ["no_source_items", *outcome_reasons]
    else:
        top = worst(statuses) or NOT_EVALUATED
        outcome, reason = {
            VIOLATED: (VIOLATED, "some_items_violated"),
            INCONCLUSIVE: (INCONCLUSIVE, "some_items_inconclusive"),
            PENDING: (PENDING, "some_items_pending"),
            VERIFIED: (VERIFIED, "all_items_verified"),
            NOT_EVALUATED: (NOT_EVALUATED, "items_not_evaluated"),
            NOT_APPLICABLE: (NOT_APPLICABLE, "all_items_not_applicable"),
        }[top]
        outcome_reasons.insert(0, reason)
        if outcome == VERIFIED and NOT_EVALUATED in statuses:
            # Items that could not be evaluated are never counted as passes.
            outcome, outcome_reasons[0] = INCONCLUSIVE, "some_items_not_evaluated"
        if source.completeness != "complete":
            outcome_reasons.append("source_coverage_unproven")
            if outcome == VERIFIED:
                # Items the source did not list were never checked (AT-21).
                outcome = INCONCLUSIVE
        if issues and outcome == VERIFIED:
            outcome = INCONCLUSIVE
    counts = {status: statuses.count(status) for status in STATUSES}
    coverage = {
        "source_rows": len(source.records),
        "work_items": len(items),
        "unkeyed_source_rows": sum(1 for i in items if i.key is None),
        "excluded_items": sum(1 for i in items if i.reason == "not_eligible"),
        "retried_items": sum(1 for i in items if i.source_rows > 1),
        "target_rows": len(target.records),
        "matched_target_records": sum(len(index[k]) for k in source_keys if k in index),
        "unmatched_target_records": sum(len(index[k]) for k in unmatched),
        "unkeyed_target_rows": unkeyed_target,
        "counts": counts,
    }
    return Evaluation(
        contract=contract,
        source=source,
        target=target,
        as_of=as_of,
        outcome=outcome,
        outcome_reasons=tuple(outcome_reasons),
        items=tuple(items),
        coverage=coverage,
        unmatched_target_keys=unmatched,
    )
