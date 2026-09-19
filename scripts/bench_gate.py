#!/usr/bin/env python3
"""CI perf-regression gate over bench/LEDGER.jsonl (perf-scale T-04).

Compares the LAST ledger row (the just-recorded run) against the latest
prior row for the same OS family. Fails (exit 1) when wall time regresses
beyond ``--tolerance`` of baseline or peak RSS exceeds ``--mem-budget``.
Missing or malformed baselines degrade to a record-only pass — the gate
never fails on absent history.

Usage:
    python scripts/bench_gate.py [--ledger bench/LEDGER.jsonl]
                                 [--tolerance 1.25] [--mem-budget 512]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LEDGER = _REPO_ROOT / "bench" / "LEDGER.jsonl"


def load_rows(path: Path) -> list[dict[str, Any]]:
    """Parse the ledger, skipping malformed lines (never crashes)."""
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", default=str(DEFAULT_LEDGER))
    parser.add_argument("--tolerance", type=float, default=1.25)
    parser.add_argument("--mem-budget", type=float, default=512.0)
    args = parser.parse_args()

    rows = load_rows(Path(args.ledger))
    if not rows:
        print("perf-gate: no ledger rows; record-only pass")
        return 0

    current = rows[-1]
    same_os = [r for r in rows[:-1] if r.get("os") == current.get("os")]
    if not same_os:
        print(f"perf-gate: no baseline for os={current.get('os')!r}; record-only pass")
        return 0
    baseline = same_os[-1]

    wall = current.get("wall_s")
    base_wall = baseline.get("wall_s")
    rss = current.get("peak_rss_mb")
    if not isinstance(wall, (int, float)) or not isinstance(base_wall, (int, float)):
        print("perf-gate: insufficient metric data; record-only pass")
        return 0

    failures: list[str] = []
    if base_wall > 0 and wall > base_wall * args.tolerance:
        failures.append(f"wall_s {wall:.3f}s > baseline {base_wall:.3f}s x {args.tolerance}")
    if isinstance(rss, (int, float)) and rss > args.mem_budget:
        failures.append(f"peak_rss_mb {rss:.1f} > budget {args.mem_budget:.1f}")

    where = f"os={current.get('os')}"
    if failures:
        print(f"perf-gate FAIL ({where}): {'; '.join(failures)}", file=sys.stderr)
        return 1
    print(
        f"perf-gate PASS ({where}): wall {wall:.3f}s vs baseline "
        f"{base_wall:.3f}s (tol x{args.tolerance}); "
        f"rss {rss}MB (budget {args.mem_budget}MB)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
