"""Focused memory probe: phase-level RSS + tracemalloc top allocators (T-06).

Answers the memory-budget investigation questions: which phase dominates the
`sesslint check` path's memory, and whether observed peak RSS is live check
memory or harness contamination.

Usage:
    python bench/mem_probe.py [--records 30000] [--top 15]
"""

from __future__ import annotations

import argparse
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_PATH = _REPO_ROOT / "src"
for _p in (str(_REPO_ROOT), str(_SRC_PATH)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from bench.perf_250k import generate_benchmark_file, get_rss_mb  # noqa: E402
from sesslint import api  # noqa: E402
from sesslint.io import iter_events  # noqa: E402


def _fmt_mb(v: float | None) -> str:
    return f"{v:.1f} MB" if v is not None else "N/A"


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase-level check-path memory probe.")
    parser.add_argument("--records", type=int, default=30_000)
    parser.add_argument("--top", type=int, default=15)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="sesslint_memprobe_") as tmp_dir:
        bench_file = Path(tmp_dir) / "probe.jsonl"

        phases: list[tuple[str, float | None]] = []
        phases.append(("baseline (imports)", get_rss_mb()))

        t0 = time.perf_counter()
        generate_benchmark_file(bench_file, args.records)
        gen_s = time.perf_counter() - t0
        phases.append(("post-generation", get_rss_mb()))

        t0 = time.perf_counter()
        count = sum(1 for _ in iter_events(bench_file))
        stream_s = time.perf_counter() - t0
        phases.append(("post-iter-events (no retention)", get_rss_mb()))

        tracemalloc.start()
        t0 = time.perf_counter()
        report = api.check_file(bench_file)
        check_s = time.perf_counter() - t0
        _curr, traced_peak = tracemalloc.get_traced_memory()
        snapshot = tracemalloc.take_snapshot()
        tracemalloc.stop()
        phases.append(("post-check", get_rss_mb()))

    print(f"=== Memory probe: {args.records:,} records ===")
    print(f"generation: {gen_s:.2f}s | stream pass ({count:,} items): {stream_s:.2f}s")
    print(
        f"check_file: {check_s:.2f}s (assurance={report.assurance}, "
        f"findings={len(report.findings)})"
    )
    print(f"tracemalloc traced peak (full check): {traced_peak / (1024 * 1024):.1f} MB")
    print("Phase RSS (in-process cumulative peaks):")
    for name, rss in phases:
        print(f"  {name}: {_fmt_mb(rss)}")
    print(f"Top {args.top} traced allocations (by traceback):")
    for i, stat in enumerate(snapshot.statistics("traceback")[: args.top], 1):
        frame = stat.traceback[0]
        print(
            f"  {i:>2}. {stat.size / (1024 * 1024):7.1f} MB "
            f"({stat.count:>7,} blocks) — {Path(frame.filename).name}:{frame.lineno}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
