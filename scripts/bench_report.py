#!/usr/bin/env python3
"""Render the last N bench-ledger runs per host tag as a Markdown table
(perf-scale T-04). Stdlib only; dev/CI artifact, never a runtime path.

Usage:
    python scripts/bench_report.py [--ledger bench/LEDGER.jsonl] [--last 5]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LEDGER = _REPO_ROOT / "bench" / "LEDGER.jsonl"


def load_rows(path: Path) -> list[dict[str, Any]]:
    """Parse the ledger, skipping malformed lines."""
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return rows
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def render(rows: list[dict[str, Any]], last: int) -> str:
    """Markdown table: last ``last`` runs per host tag."""
    by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_host[str(row.get("host_tag", "unknown"))].append(row)

    lines = [
        "| date | host | source | records | wall_s | peak_rss_mb | py | os | git_sha |",
        "| :--- | :--- | :--- | ---: | ---: | ---: | :--- | :--- | :--- |",
    ]
    for host in sorted(by_host):
        for row in by_host[host][-last:]:
            lines.append(
                "| {date} | {host} | {source} | {records} | {wall} | {rss} | "
                "{py} | {os} | {sha} |".format(
                    date=row.get("date", "?"),
                    host=host,
                    source=row.get("source", "?"),
                    records=row.get("records", "?"),
                    wall=row.get("wall_s", "?"),
                    rss=row.get("peak_rss_mb", "?"),
                    py=row.get("py_version", "?"),
                    os=row.get("os", "?"),
                    sha=str(row.get("git_sha", "?"))[:8],
                )
            )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", default=str(DEFAULT_LEDGER))
    parser.add_argument("--last", type=int, default=5)
    args = parser.parse_args()

    rows = load_rows(Path(args.ledger))
    if not rows:
        print("no ledger rows", file=sys.stderr)
        return 1
    print(render(rows, args.last))
    return 0


if __name__ == "__main__":
    sys.exit(main())
