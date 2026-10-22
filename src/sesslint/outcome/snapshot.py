"""OutcomeGuard observations: bounded snapshot readers (EVD-02, EVD-03, REC-07).

A snapshot is one observation of a source or target system: its records plus
the metadata that limits what it can prove — when it was observed, whether it
is complete, and where it came from. Metadata is never inferred: a file with
no declared completeness is ``unknown``, so absence cannot be proven from it.
"""

from __future__ import annotations

import csv
import hashlib
import io
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from sesslint.outcome.contract import parse_strict_json

SNAPSHOT_SCHEMA_VERSION: Final[str] = "sesslint.snapshot/v1"
COMPLETENESS: Final[tuple[str, ...]] = ("complete", "partial", "unknown", "unavailable")
ORIGINS: Final[tuple[str, ...]] = ("target_system", "workflow_log", "user_file", "manual")
MAX_RECORDS: Final[int] = 1_000_000
DEFAULT_MAX_SNAPSHOT_BYTES: Final[int] = 100 * 1024 * 1024
_ENVELOPE_KEYS: Final = frozenset(
    {"schema_version", "observed_at", "completeness", "origin", "demo", "records"}
)


class NonScalar:
    """Marker for nested values: present, but never compared or coerced."""

    _instance: NonScalar | None = None

    def __new__(cls) -> NonScalar:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "NON_SCALAR"


NON_SCALAR: Final = NonScalar()
Value = str | int | float | bool | None | NonScalar
Record = Mapping[str, Value]


class SnapshotError(ValueError):
    """A snapshot could not be read or its metadata is contradictory."""


def parse_instant(value: object) -> datetime | None:
    """Parse an ISO-8601 instant that carries an explicit UTC offset, else None.

    Naive times are rejected rather than assumed local (RULE-07, AT-42).
    """
    if not isinstance(value, str) or not 10 <= len(value) <= 64:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    try:
        return parsed.astimezone(UTC)
    except OverflowError:
        return None


def format_instant(value: datetime | None) -> str | None:
    """Render an aware instant as canonical UTC ``YYYY-MM-DDTHH:MM:SSZ``."""
    if value is None:
        return None
    text = value.astimezone(UTC).isoformat()
    return text.replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class Snapshot:
    """One observation; ``records`` keep file order, values stay uncoerced."""

    role: str
    name: str
    sha256: str
    input_format: str
    records: tuple[Record, ...]
    fields: frozenset[str]
    observed_at: datetime | None
    completeness: str
    origin: str
    demo: bool

    def to_dict(self) -> dict[str, Any]:
        """Content-free observation metadata for reports (EVD-01)."""
        return {
            "role": self.role,
            "name": self.name,
            "sha256": self.sha256,
            "input_format": self.input_format,
            "record_count": len(self.records),
            "observed_at": format_instant(self.observed_at),
            "completeness": self.completeness,
            "origin": self.origin,
            "demo": self.demo,
        }


def _scalarize(record: Mapping[str, Any]) -> dict[str, Value]:
    out: dict[str, Value] = {}
    for key, value in record.items():
        if value is None or isinstance(value, (str, int, float, bool)):
            out[key] = value
        else:
            out[key] = NON_SCALAR
    return out


def _from_csv(text: str) -> tuple[list[dict[str, Value]], set[str]]:
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    try:
        rows = list(reader)
    except csv.Error as err:
        raise SnapshotError(f"CSV is malformed near line {reader.line_num}") from err
    rows = [row for row in rows if row]
    if not rows:
        raise SnapshotError("CSV has no header row")
    header = rows[0]
    if any(not name for name in header) or len(set(header)) != len(header):
        raise SnapshotError("CSV header has empty or duplicate column names")
    records: list[dict[str, Value]] = []
    for ordinal, row in enumerate(rows[1:], start=2):
        if len(row) > len(header):
            raise SnapshotError(f"CSV row {ordinal} has more cells than the header")
        # Short rows leave trailing columns absent, which differs from an empty cell.
        records.append(dict(zip(header, row, strict=False)))
        if len(records) > MAX_RECORDS:
            raise SnapshotError(f"snapshot exceeds {MAX_RECORDS} records")
    return records, set(header)


def _from_objects(items: object, where: str) -> tuple[list[dict[str, Value]], set[str]]:
    if not isinstance(items, list):
        raise SnapshotError(f"{where} must be a JSON array of objects")
    if len(items) > MAX_RECORDS:
        raise SnapshotError(f"snapshot exceeds {MAX_RECORDS} records")
    records: list[dict[str, Value]] = []
    fields: set[str] = set()
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise SnapshotError(f"{where}[{index}] is not a JSON object")
        records.append(_scalarize(item))
        fields.update(item)
    return records, fields


def _from_jsonl(text: str) -> tuple[list[dict[str, Value]], set[str]]:
    items: list[object] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            items.append(parse_strict_json(line))
        except (ValueError, RecursionError) as err:
            raise SnapshotError(f"JSONL line {line_no} is not strict JSON") from err
        if len(items) > MAX_RECORDS:
            raise SnapshotError(f"snapshot exceeds {MAX_RECORDS} records")
    return _from_objects(items, "JSONL")


def _pick(name: str, declared: object, flag: object, allowed: tuple[str, ...]) -> object:
    if declared is not None and flag is not None and declared != flag:
        raise SnapshotError(f"{name} given on the command line contradicts the snapshot file")
    value = flag if flag is not None else declared
    if value is not None and value not in allowed:
        raise SnapshotError(f"{name} must be one of {', '.join(allowed)}")
    return value


def load_snapshot(
    path: Path | str,
    *,
    role: str,
    observed_at: datetime | None = None,
    completeness: str | None = None,
    origin: str | None = None,
    max_bytes: int = DEFAULT_MAX_SNAPSHOT_BYTES,
) -> Snapshot:
    """Read a CSV, JSON array, JSONL or ``sesslint.snapshot/v1`` envelope file.

    Keyword metadata comes from the caller (CLI flags); an envelope may declare
    the same fields, and a contradiction between the two is an error (EVD-07).
    """
    if role not in ("source", "target"):
        raise ValueError("role must be 'source' or 'target'")
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    target = Path(path)
    with target.open("rb") as stream:
        data = stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise SnapshotError(f"{role} snapshot exceeds {max_bytes} bytes")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as err:
        raise SnapshotError(f"{role} snapshot is not valid UTF-8") from err
    suffix = target.suffix.lower()
    declared: dict[str, object] = {}
    if suffix == ".csv":
        input_format = "csv"
        records, fields = _from_csv(text)
    elif suffix in (".jsonl", ".ndjson"):
        input_format = "jsonl"
        records, fields = _from_jsonl(text)
    elif suffix == ".json":
        try:
            doc = parse_strict_json(text)
        except (ValueError, RecursionError) as err:
            raise SnapshotError(f"{role} snapshot is not strict JSON") from err
        if isinstance(doc, dict):
            input_format = "envelope"
            if doc.get("schema_version") != SNAPSHOT_SCHEMA_VERSION:
                raise SnapshotError(
                    f"JSON object snapshots need schema_version {SNAPSHOT_SCHEMA_VERSION}"
                )
            unknown = sorted(set(doc) - _ENVELOPE_KEYS)
            if unknown:
                raise SnapshotError(f"snapshot envelope has unknown key(s) {unknown}")
            if "demo" in doc and not isinstance(doc["demo"], bool):
                raise SnapshotError("snapshot 'demo' must be true or false")
            declared = doc
            records, fields = _from_objects(doc.get("records", []), "records")
        else:
            input_format = "json"
            records, fields = _from_objects(doc, "JSON snapshot")
    else:
        raise SnapshotError("snapshot files must end in .csv, .json, .jsonl or .ndjson")

    declared_time: datetime | None = None
    if declared.get("observed_at") is not None:
        declared_time = parse_instant(declared["observed_at"])
        if declared_time is None:
            raise SnapshotError("snapshot 'observed_at' must be an ISO-8601 time with an offset")
    if declared_time is not None and observed_at is not None and declared_time != observed_at:
        raise SnapshotError("observed-at given on the command line contradicts the snapshot file")
    chosen_completeness = _pick(
        "completeness", declared.get("completeness"), completeness, COMPLETENESS
    )
    chosen_origin = _pick("origin", declared.get("origin"), origin, ORIGINS)
    final_completeness = str(chosen_completeness or "unknown")
    if final_completeness == "unavailable" and records:
        raise SnapshotError("an unavailable observation cannot carry records")
    return Snapshot(
        role=role,
        name=target.name,
        sha256=hashlib.sha256(data).hexdigest(),
        input_format=input_format,
        records=tuple(records),
        fields=frozenset(fields),
        observed_at=observed_at if observed_at is not None else declared_time,
        completeness=final_completeness,
        origin=str(chosen_origin or "user_file"),
        demo=bool(declared.get("demo", False)),
    )
