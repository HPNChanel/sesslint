"""OutcomeGuard contract model and validation (CON-01, CON-02, CON-05, CON-07).

A contract is declarative data: a correlation key, eligibility predicates, an
optional due window and a closed set of condition types (RULE-01…RULE-08).
Nothing in a contract is executed; unknown keys, types and operators are
rejected so a typo can never silently weaken a check (fail closed).

Numbers keep their written value: integers are exact at any size, and a
number with a fraction or exponent must round-trip through a binary64 float
(the contract is fingerprinted as written), otherwise it is rejected.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Final

from sesslint._canonical_codec import canonical_json_bytes
from sesslint.errors import SchemaError

CONTRACT_SCHEMA_VERSION: Final[str] = "sesslint.outcome-contract/v1"
MAX_CONTRACT_BYTES: Final[int] = 1024 * 1024
MAX_CONDITIONS: Final[int] = 64
MAX_PREDICATES: Final[int] = 32
MAX_VALUES: Final[int] = 1000
MAX_KEY_FIELDS: Final[int] = 8
MAX_WITHIN_SECONDS: Final[int] = 10 * 366 * 24 * 3600
# A snapshot holds at most 1,000,000 records, so a larger count bound is meaningless.
MAX_COUNT_BOUND: Final[int] = 1_000_000

CONDITION_TYPES: Final[frozenset[str]] = frozenset(
    {
        "exists",
        "count",
        "required",
        "type",
        "one_of",
        "equals",
        "range",
        "route",
        "on_time",
        "any_of",
    }
)
PREDICATE_OPS: Final[frozenset[str]] = frozenset(
    {"eq", "ne", "in", "not_in", "gt", "gte", "lt", "lte", "present", "absent"}
)
VALUE_KINDS: Final[frozenset[str]] = frozenset(
    {"string", "integer", "number", "boolean", "date-time"}
)
NORMALIZATIONS: Final[tuple[str, ...]] = ("trim", "casefold")
DEADLINE_BASES: Final[frozenset[str]] = frozenset({"target_time", "observation"})

# Used with fullmatch: "$" would also accept a trailing newline.
_ID_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_MAX_FIELD_CHARS: Final[int] = 256
_MAX_TEXT_CHARS: Final[int] = 2000

Scalar = str | int | float | bool | None

_COMMON_KEYS: Final = frozenset({"id", "type", "advisory", "disabled", "description"})
_TYPE_KEYS: Final[dict[str, frozenset[str]]] = {
    "exists": frozenset(),
    "count": frozenset({"min", "max"}),
    "required": frozenset({"field", "allow_null", "allow_empty"}),
    "type": frozenset({"field", "kind"}),
    "one_of": frozenset({"field", "values", "normalize"}),
    "equals": frozenset({"field", "source_field", "normalize"}),
    "range": frozenset({"field", "min", "max"}),
    "route": frozenset({"field", "values", "when", "normalize"}),
    "on_time": frozenset({"basis", "field"}),
    "any_of": frozenset({"conditions"}),
}
_TOP_KEYS: Final = frozenset(
    {"schema_version", "name", "version", "description", "key", "eligibility", "due", "conditions"}
)


class ContractError(ValueError):
    """The contract is unreadable or inconsistent; no verdict may be produced."""

    def __init__(self, problems: Sequence[str]) -> None:
        self.problems: tuple[str, ...] = tuple(problems)
        super().__init__("; ".join(self.problems))


@dataclass(frozen=True, slots=True)
class Predicate:
    """One eligibility/route test against a source record field."""

    field: str
    op: str
    value: Scalar = None
    values: tuple[Scalar, ...] = ()


@dataclass(frozen=True, slots=True)
class Due:
    """Deadline window: source event time plus ``within_seconds``."""

    source_time_field: str
    within_seconds: int


@dataclass(frozen=True, slots=True)
class Condition:
    """One declared outcome condition; unused attributes keep their defaults."""

    id: str
    type: str
    advisory: bool = False
    disabled: str | None = None
    description: str | None = None
    field: str | None = None
    source_field: str | None = None
    values: tuple[Scalar, ...] = ()
    normalize: tuple[str, ...] = ()
    kind: str | None = None
    # As written in the contract: int for count; int or finite float for range.
    minimum: int | float | None = None
    maximum: int | float | None = None
    allow_null: bool = False
    allow_empty: bool = False
    when: tuple[Predicate, ...] = ()
    basis: str | None = None
    conditions: tuple[Condition, ...] = ()


@dataclass(frozen=True, slots=True)
class Contract:
    """Validated, immutable outcome contract."""

    name: str
    version: str
    description: str | None
    source_key: tuple[str, ...]
    target_key: tuple[str, ...]
    eligibility: tuple[Predicate, ...]
    due: Due | None
    conditions: tuple[Condition, ...]
    sha256: str

    def warnings(self) -> tuple[str, ...]:
        """Configuration gaps that are legal but limit what can be proven (CON-02)."""
        out: list[str] = []
        active = [c for c in self.conditions if c.disabled is None and not c.advisory]
        if not any(c.type in ("exists", "count") for c in active):
            out.append(
                "no active exists/count condition: a missing target record cannot be "
                "reported as a violation"
            )
        if self.due is None:
            out.append("no due window declared: absence is judged at the evaluation instant")
        if active and all(c.type == "any_of" for c in active):
            out.append("every decisive condition is an any_of branch")
        return tuple(out)

    def relevant_source_fields(self) -> frozenset[str]:
        """Source fields whose values influence a verdict (duplicate-row merging)."""
        fields: set[str] = set(self.source_key)
        fields.update(p.field for p in self.eligibility)
        if self.due is not None:
            fields.add(self.due.source_time_field)
        stack = list(self.conditions)
        while stack:
            cond = stack.pop()
            if cond.source_field is not None:
                fields.add(cond.source_field)
            fields.update(p.field for p in cond.when)
            stack.extend(cond.conditions)
        return frozenset(fields)

    def iter_conditions(self) -> tuple[Condition, ...]:
        """All conditions including any_of branches, in declaration order."""
        out: list[Condition] = []
        for cond in self.conditions:
            out.append(cond)
            out.extend(cond.conditions)
        return tuple(out)


class _Problems:
    def __init__(self) -> None:
        self.items: list[str] = []

    def add(self, where: str, message: str) -> None:
        self.items.append(f"{where}: {message}")


def _reject_constant(token: str) -> None:
    raise ValueError(f"non-finite number {token} is not allowed")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def parse_strict_json(text: str, *, parse_float: Callable[[str], Any] | None = None) -> Any:
    """Parse JSON rejecting NaN/Infinity and duplicate object keys."""
    return json.loads(
        text,
        parse_float=parse_float,
        parse_constant=_reject_constant,
        object_pairs_hook=_no_duplicate_keys,
    )


class _InexactNumber(ValueError):
    """A contract number that a binary64 float cannot hold exactly."""


def _contract_float(text: str) -> float:
    """``parse_float`` hook: accept a literal only if its float has the same value.

    Contracts are fingerprinted as written, so non-integers stay floats; a
    literal such as ``9007199254740993.0``, ``0.1000000000000000001`` or
    ``1e400`` would silently become a different number and is rejected.
    """
    value = float(text)
    try:
        exact = math.isfinite(value) and Decimal(repr(value)) == Decimal(text)
    except InvalidOperation:
        exact = False
    if not exact:
        raise _InexactNumber("number does not equal a 64-bit float exactly")
    return value


def _is_scalar(value: object) -> bool:
    return value is None or isinstance(value, (str, bool)) or _is_number(value)


def _is_number(value: object) -> bool:
    if isinstance(value, bool):
        return False
    return isinstance(value, int) or (isinstance(value, float) and math.isfinite(value))


def _one_of(value: object, allowed: frozenset[str]) -> bool:
    """Membership that never raises: lists and objects are unhashable."""
    return isinstance(value, str) and value in allowed


def _field(raw: Mapping[str, Any], key: str, where: str, problems: _Problems) -> str | None:
    value = raw.get(key)
    if not isinstance(value, str) or not value or len(value) > _MAX_FIELD_CHARS:
        problems.add(where, f"'{key}' must be a non-empty field name (at most 256 characters)")
        return None
    return value


def _text(raw: Mapping[str, Any], key: str, where: str, problems: _Problems) -> str | None:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT_CHARS:
        problems.add(where, f"'{key}' must be a non-empty string (at most 2000 characters)")
        return None
    return value


def _unknown_keys(
    raw: Mapping[Any, Any], allowed: frozenset[str], where: str, problems: _Problems
) -> None:
    """Report keys outside ``allowed``; a non-string key is a problem, never a crash.

    Decoded JSON always has string keys, but ``contract_from_dict`` also takes
    Python dicts, whose keys may be of any type and need not sort together.
    """
    odd_types = sorted({type(key).__name__ for key in raw if not isinstance(key, str)})
    for name in odd_types:
        problems.add(where, f"keys must be strings, not {name}")
    for key in sorted({key for key in raw if isinstance(key, str)} - allowed):
        problems.add(where, f"unknown key {key!r}")


def _values(
    raw: Mapping[str, Any], where: str, problems: _Problems, *, key: str = "values"
) -> tuple[Scalar, ...]:
    value = raw.get(key)
    if not isinstance(value, list) or not value or len(value) > MAX_VALUES:
        problems.add(where, f"'{key}' must be a non-empty list of at most {MAX_VALUES} values")
        return ()
    if not all(_is_scalar(item) for item in value):
        problems.add(where, f"'{key}' may only hold strings, numbers, booleans or null")
        return ()
    return tuple(value)


def _normalize(raw: Mapping[str, Any], where: str, problems: _Problems) -> tuple[str, ...]:
    value = raw.get("normalize", [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        problems.add(where, "'normalize' must be a list of step names")
        return ()
    unknown = sorted(set(value) - set(NORMALIZATIONS))
    if unknown:
        problems.add(where, f"unsupported normalize step(s) {unknown}; use trim, casefold")
    if len(set(value)) != len(value):
        problems.add(where, "'normalize' lists a step twice")
    # Published order is fixed so the same contract always means the same thing.
    return tuple(step for step in NORMALIZATIONS if step in value)


def _predicate(raw: object, where: str, problems: _Problems) -> Predicate | None:
    if not isinstance(raw, dict):
        problems.add(where, "predicate must be an object")
        return None
    op = raw.get("op")
    if not _one_of(op, PREDICATE_OPS):
        problems.add(where, f"'op' must be one of {sorted(PREDICATE_OPS)}")
        return None
    allowed = {"field", "op"}
    field = _field(raw, "field", where, problems)
    value: Scalar = None
    values: tuple[Scalar, ...] = ()
    if op in ("in", "not_in"):
        allowed.add("values")
        values = _values(raw, where, problems)
    elif op in ("gt", "gte", "lt", "lte"):
        allowed.add("value")
        if not _is_number(raw.get("value")):
            problems.add(where, f"'{op}' needs a numeric 'value'")
        else:
            value = raw["value"]
    elif op in ("eq", "ne"):
        allowed.add("value")
        if "value" not in raw or not _is_scalar(raw["value"]):
            problems.add(where, f"'{op}' needs a scalar 'value'")
        else:
            value = raw["value"]
    _unknown_keys(raw, frozenset(allowed), where, problems)
    if field is None:
        return None
    return Predicate(field=field, op=str(op), value=value, values=values)


def _predicates(raw: object, where: str, problems: _Problems) -> tuple[Predicate, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list) or len(raw) > MAX_PREDICATES:
        problems.add(where, f"must be a list of at most {MAX_PREDICATES} predicates")
        return ()
    out = [_predicate(item, f"{where}[{i}]", problems) for i, item in enumerate(raw)]
    return tuple(p for p in out if p is not None)


def _bound(raw: Mapping[str, Any], key: str, where: str, problems: _Problems) -> int | float | None:
    """A range bound kept as written; the engine compares it exactly, never as a float."""
    if key not in raw or raw[key] is None:
        return None
    value = raw[key]
    if not _is_number(value):
        problems.add(where, f"'{key}' must be a finite number")
        return None
    return int(value) if isinstance(value, int) else float(value)


def _count_bounds(
    raw: Mapping[str, Any], where: str, problems: _Problems
) -> tuple[int | None, int | None]:
    """``count`` bounds: integers in 0..MAX_COUNT_BOUND; ``null`` is not a bound (RULE-02)."""
    bounds: dict[str, int | None] = {"min": 1, "max": None}
    valid = True
    for name in ("min", "max"):
        if name not in raw:
            continue
        value = raw[name]
        if type(value) is not int or not 0 <= value <= MAX_COUNT_BOUND:
            problems.add(where, f"'{name}' must be an integer from 0 to {MAX_COUNT_BOUND}")
            valid = False
        else:
            bounds[name] = value
    low, high = bounds["min"], bounds["max"]
    if valid and low is not None:
        if high is not None and low > high:
            problems.add(where, "'min' must not exceed 'max'")
        if low == 0 and high is None:
            problems.add(where, "count with min 0 and no max can never be violated")
        if high == 0:
            problems.add(where, "'max' 0 asks for absence, which v1 cannot prove; omit it")
    return low, high


def _condition(
    raw: object, where: str, problems: _Problems, *, nested: bool, has_due: bool
) -> Condition | None:
    if not isinstance(raw, dict):
        problems.add(where, "condition must be an object")
        return None
    ctype = raw.get("type")
    if not _one_of(ctype, CONDITION_TYPES):
        problems.add(where, f"'type' must be one of {sorted(CONDITION_TYPES)}")
        return None
    cond_id = raw.get("id")
    if not isinstance(cond_id, str) or not _ID_RE.fullmatch(cond_id):
        problems.add(where, "'id' must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}")
        cond_id = "?"
    where = f"condition {cond_id!r}"
    _unknown_keys(raw, _COMMON_KEYS | _TYPE_KEYS[str(ctype)], where, problems)
    advisory = raw.get("advisory", False)
    if not isinstance(advisory, bool):
        problems.add(where, "'advisory' must be true or false")
        advisory = False
    disabled = _text(raw, "disabled", where, problems)
    fields: dict[str, Any] = {
        "id": cond_id,
        "type": ctype,
        "advisory": advisory,
        "disabled": disabled,
        "description": _text(raw, "description", where, problems),
    }
    if ctype in ("required", "type", "one_of", "equals", "range", "route"):
        fields["field"] = _field(raw, "field", where, problems)
    if ctype == "count":
        fields["minimum"], fields["maximum"] = _count_bounds(raw, where, problems)
    elif ctype == "required":
        for flag in ("allow_null", "allow_empty"):
            value = raw.get(flag, False)
            if not isinstance(value, bool):
                problems.add(where, f"'{flag}' must be true or false")
                value = False
            fields[flag] = value
    elif ctype == "type":
        if not _one_of(raw.get("kind"), VALUE_KINDS):
            problems.add(where, f"'kind' must be one of {sorted(VALUE_KINDS)}")
        fields["kind"] = raw.get("kind")
    elif ctype == "one_of":
        fields["values"] = _values(raw, where, problems)
        fields["normalize"] = _normalize(raw, where, problems)
    elif ctype == "equals":
        fields["source_field"] = _field(raw, "source_field", where, problems)
        fields["normalize"] = _normalize(raw, where, problems)
    elif ctype == "range":
        fields["minimum"] = _bound(raw, "min", where, problems)
        fields["maximum"] = _bound(raw, "max", where, problems)
        low, high = fields["minimum"], fields["maximum"]
        if low is None and high is None:
            problems.add(where, "range needs 'min', 'max' or both")
        elif low is not None and high is not None and low > high:
            problems.add(where, "'min' must not exceed 'max'")
    elif ctype == "route":
        fields["values"] = _values(raw, where, problems)
        fields["normalize"] = _normalize(raw, where, problems)
        fields["when"] = _predicates(raw.get("when"), f"{where} when", problems)
        if not fields["when"]:
            problems.add(where, "route needs at least one 'when' predicate")
    elif ctype == "on_time":
        basis = raw.get("basis")
        if not _one_of(basis, DEADLINE_BASES):
            problems.add(where, "'basis' must be 'target_time' or 'observation'")
        fields["basis"] = basis
        if basis == "target_time":
            fields["field"] = _field(raw, "field", where, problems)
        elif "field" in raw:
            # The observation basis judges the snapshot time, never a record field.
            problems.add(where, "the observation basis takes no 'field'")
        if not has_due:
            problems.add(where, "on_time needs a contract-level 'due' window")
    elif ctype == "any_of":
        if nested:
            problems.add(where, "any_of branches cannot nest another any_of")
        branches = raw.get("conditions")
        if not isinstance(branches, list) or len(branches) < 2:
            problems.add(where, "any_of needs at least two branch conditions")
            branches = []
        parsed = [
            _condition(item, f"{where} branch {i}", problems, nested=True, has_due=has_due)
            for i, item in enumerate(branches)
        ]
        fields["conditions"] = tuple(c for c in parsed if c is not None)
        if any(c.advisory or c.disabled for c in fields["conditions"]):
            problems.add(where, "any_of branches cannot be advisory or disabled themselves")
    return Condition(**fields)


def _key_fields(raw: object, where: str, problems: _Problems) -> tuple[str, ...]:
    items = [raw] if isinstance(raw, str) else raw
    if (
        not isinstance(items, list)
        or not items
        or len(items) > MAX_KEY_FIELDS
        or not all(isinstance(i, str) and i and len(i) <= _MAX_FIELD_CHARS for i in items)
    ):
        problems.add(where, f"must be a field name or a list of 1-{MAX_KEY_FIELDS} field names")
        return ()
    if len(set(items)) != len(items):
        problems.add(where, "lists a field twice")
    return tuple(items)


def contract_from_dict(raw: object) -> Contract:
    """Validate a decoded contract document; raise ``ContractError`` listing every problem."""
    problems = _Problems()
    if not isinstance(raw, dict):
        raise ContractError(["contract: top level must be a JSON object"])
    if raw.get("schema_version") != CONTRACT_SCHEMA_VERSION:
        problems.add("contract", f"'schema_version' must be {CONTRACT_SCHEMA_VERSION!r}")
    _unknown_keys(raw, _TOP_KEYS, "contract", problems)
    name = _text(raw, "name", "contract", problems)
    description = _text(raw, "description", "contract", problems)
    if name is None and "name" not in raw:
        problems.add("contract", "'name' is required")
    version = raw.get("version")
    if not isinstance(version, str) or not version.strip() or len(version) > 64:
        problems.add("contract", "'version' must be a non-empty string (at most 64 characters)")
    key = raw.get("key")
    source_key: tuple[str, ...] = ()
    target_key: tuple[str, ...] = ()
    if not isinstance(key, dict):
        problems.add("contract", "'key' must be an object with 'source' and 'target'")
    else:
        _unknown_keys(key, frozenset({"source", "target"}), "key", problems)
        source_key = _key_fields(key.get("source"), "key.source", problems)
        target_key = _key_fields(key.get("target"), "key.target", problems)
        if source_key and target_key and len(source_key) != len(target_key):
            problems.add("key", "source and target must list the same number of fields")
    eligibility = _predicates(raw.get("eligibility"), "eligibility", problems)
    due: Due | None = None
    if raw.get("due") is not None:
        due_raw = raw["due"]
        if not isinstance(due_raw, dict):
            problems.add("due", "must be an object")
        else:
            _unknown_keys(
                due_raw, frozenset({"source_time_field", "within_seconds"}), "due", problems
            )
            field = _field(due_raw, "source_time_field", "due", problems)
            within = due_raw.get("within_seconds")
            if type(within) is not int or not 0 <= within <= MAX_WITHIN_SECONDS:
                problems.add("due", "'within_seconds' must be a non-negative integer (<= 10 years)")
            elif field is not None:
                due = Due(source_time_field=field, within_seconds=within)
    conditions_raw = raw.get("conditions")
    conditions: tuple[Condition, ...] = ()
    if not isinstance(conditions_raw, list) or not conditions_raw:
        problems.add(
            "contract", "'conditions' must be a non-empty list (an empty contract proves nothing)"
        )
    elif len(conditions_raw) > MAX_CONDITIONS:
        problems.add("contract", f"at most {MAX_CONDITIONS} conditions are supported")
    else:
        parsed = [
            _condition(
                item, f"conditions[{i}]", problems, nested=False, has_due=raw.get("due") is not None
            )
            for i, item in enumerate(conditions_raw)
        ]
        conditions = tuple(c for c in parsed if c is not None)
        if conditions and all(c.disabled is not None for c in conditions):
            problems.add("contract", "every condition is disabled; nothing would be evaluated")
        if conditions and all(c.advisory or c.disabled is not None for c in conditions):
            problems.add("contract", "no decisive condition: at least one must be non-advisory")
    seen: set[str] = set()
    for cond in conditions:
        for item in (cond, *cond.conditions):
            if item.id in seen and item.id != "?":
                problems.add(f"condition {item.id!r}", "duplicate condition id")
            seen.add(item.id)
    if problems.items or name is None or not isinstance(version, str):
        raise ContractError(problems.items or ["contract: incomplete"])
    try:
        fingerprint = hashlib.sha256(canonical_json_bytes(raw)).hexdigest()
    except (SchemaError, ValueError, TypeError, RecursionError) as err:
        # e.g. a lone surrogate escape ("\ud800"): no canonical UTF-8 form exists.
        cause = err.__cause__ if isinstance(err, SchemaError) else err
        if isinstance(cause, UnicodeError):
            problem = "contract: holds text that is not valid Unicode (e.g. a lone surrogate)"
        else:
            problem = (
                f"contract: holds a value with no canonical JSON form ({type(cause).__name__})"
            )
        raise ContractError([problem]) from err
    return Contract(
        name=name,
        version=version,
        description=description,
        source_key=source_key,
        target_key=target_key,
        eligibility=eligibility,
        due=due,
        conditions=conditions,
        sha256=fingerprint,
    )


def load_contract(path: Path | str) -> Contract:
    """Read and validate a contract file (UTF-8 JSON, at most 1 MiB)."""
    target = Path(path)
    with target.open("rb") as stream:
        data = stream.read(MAX_CONTRACT_BYTES + 1)
    if len(data) > MAX_CONTRACT_BYTES:
        raise ContractError(["contract: file exceeds 1 MiB"])
    try:
        text = data.decode("utf-8-sig")
        raw = parse_strict_json(text, parse_float=_contract_float)
    except _InexactNumber as err:
        raise ContractError(
            [
                "contract: a number with a fraction or exponent must equal a 64-bit float "
                "exactly; up to 15 significant digits are always safe for magnitudes from "
                "1e-307 to 1e308, and integers are exact at any size"
            ]
        ) from err
    except (UnicodeDecodeError, ValueError, RecursionError) as err:
        raise ContractError(
            [f"contract: not valid strict UTF-8 JSON ({type(err).__name__})"]
        ) from err
    return contract_from_dict(raw)
