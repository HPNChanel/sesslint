"""Builders for synthetic OutcomeGuard contracts and snapshots (no real data)."""

from __future__ import annotations

import json
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from sesslint.outcome import (
    Contract,
    OutcomeReport,
    Snapshot,
    contract_from_dict,
    evaluate,
    load_snapshot,
    parse_instant,
)

ROOT = Path(__file__).resolve().parents[2]
ORDERS = ROOT / "fixtures" / "outcome" / "orders"
T0 = "2026-10-20T08:00:00Z"
DEADLINE = "2026-10-20T09:00:00Z"
LATER = "2026-10-20T12:00:00Z"


def at(text: str) -> datetime:
    value = parse_instant(text)
    assert value is not None
    return value


@contextmanager
def digit_limit(limit: int) -> Iterator[None]:
    """Run with Python's int/str digit limit at ``limit`` (0: none), restoring it after."""
    previous = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(limit)
    try:
        yield
    finally:
        sys.set_int_max_str_digits(previous)


def contract(*conditions: dict[str, Any], **top: Any) -> Contract:
    raw: dict[str, Any] = {
        "schema_version": "sesslint.outcome-contract/v1",
        "name": "synthetic",
        "version": "1",
        "key": {"source": "id", "target": "ref"},
        "conditions": list(conditions) or [{"id": "exists", "type": "exists"}],
    }
    raw.update(top)
    return contract_from_dict(raw)


def due(seconds: int = 3600) -> dict[str, Any]:
    return {"source_time_field": "at", "within_seconds": seconds}


def snapshot(
    tmp_path: Path,
    role: str,
    records: list[dict[str, Any]],
    *,
    observed_at: str | None = LATER,
    completeness: str | None = "complete",
    origin: str | None = None,
    demo: bool | None = None,
) -> Snapshot:
    envelope: dict[str, Any] = {"schema_version": "sesslint.snapshot/v1", "records": records}
    for name, value in (
        ("observed_at", observed_at),
        ("completeness", completeness),
        ("origin", origin),
        ("demo", demo),
    ):
        if value is not None:
            envelope[name] = value
    path = tmp_path / f"{role}.json"
    path.write_bytes(json.dumps(envelope).encode("utf-8"))
    return load_snapshot(path, role=role)


def run(
    tmp_path: Path,
    spec: Contract,
    source: list[dict[str, Any]],
    target: list[dict[str, Any]],
    *,
    as_of: str = LATER,
    source_meta: dict[str, Any] | None = None,
    target_meta: dict[str, Any] | None = None,
) -> OutcomeReport:
    src = snapshot(tmp_path, "source", source, **(source_meta or {}))
    tgt = snapshot(tmp_path, "target", target, **(target_meta or {}))
    return OutcomeReport(evaluate(spec, src, tgt, as_of=at(as_of)), all_conditions=True)


def item(report: OutcomeReport, *key: str) -> dict[str, Any]:
    for entry in report.to_dict()["items"]:
        if entry["key"] == list(key):
            return dict(entry)
    raise AssertionError(f"no item {key}")


def cond(entry: dict[str, Any], cond_id: str) -> tuple[str, str]:
    for result in entry["conditions"]:
        if result["id"] == cond_id:
            return result["status"], result["reason"]
    raise AssertionError(f"no condition {cond_id}")
