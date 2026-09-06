"""Performance benchmark: streaming 250k records within 15s and 512MB memory budget.

This benchmark verifies SessLint's streaming reader throughput and bounded RSS memory
guarantees under hostile load constraints (FR-013, FR-014, AC-023).

Usage:
    python bench/perf_250k.py --records 250000 --time-budget 15 --mem-budget 512
"""

from __future__ import annotations

import argparse
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

# Ensure sesslint from src/ is importable even when not installed in editable mode
_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_PATH = _REPO_ROOT / "src"
if str(_SRC_PATH) not in sys.path:
    sys.path.insert(0, str(_SRC_PATH))

from sesslint.io import iter_events  # noqa: E402


def generate_benchmark_file(path: Path, num_records: int) -> None:
    """Generate synthetic canonical session JSONL file with num_records events."""
    batch_size = 5000
    with open(path, "w", encoding="utf-8") as f:
        # Write canonical header
        f.write(
            '{"created_at":"2026-09-05T00:00:00Z","schema_version":"sesslint.session/v1",'
            '"session_id":"sess_perf_250k"}\n'
        )
        # Write events in batches for memory-efficient generation
        for start in range(0, num_records, batch_size):
            end = min(start + batch_size, num_records)
            lines = [
                f'{{"actor":"user","id":"evt_{i:06d}","kind":"message","parent_id":null,'
                f'"payload":{{"index":{i}}},"seq":{i},"ts":"2026-09-05T00:00:00Z"}}'
                for i in range(start, end)
            ]
            f.write("\n".join(lines) + "\n")


def get_rss_mb() -> float | None:
    """Retrieve process RSS/WorkingSet in megabytes cross-platform (Linux, macOS, Windows)."""
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes

            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            k32 = ctypes.windll.kernel32
            psapi = ctypes.windll.psapi
            k32.GetCurrentProcess.restype = wintypes.HANDLE
            psapi.GetProcessMemoryInfo.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
                wintypes.DWORD,
            ]
            psapi.GetProcessMemoryInfo.restype = wintypes.BOOL

            pmc = PROCESS_MEMORY_COUNTERS()
            pmc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            if psapi.GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(pmc), pmc.cb):
                return float(pmc.PeakWorkingSetSize) / (1024 * 1024)
        except Exception:
            return None
    else:
        try:
            import resource

            raw_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            if sys.platform == "darwin":
                return raw_rss / (1024 * 1024)
            return raw_rss / 1024  # Linux KiB to MiB
        except Exception:
            return None
    return None


def run_benchmark(records: int, time_budget: float, mem_budget: float) -> int:
    """Execute streaming benchmark and return 0 for PASS, 1 for FAIL."""
    print("=== SessLint 250k Streaming Benchmark ===")
    print(
        f"Records: {records:,} | Time budget: {time_budget:.1f}s | "
        f"Memory budget: {mem_budget:.1f}MB"
    )

    with tempfile.TemporaryDirectory(prefix="sesslint_bench_") as tmp_dir:
        bench_file = Path(tmp_dir) / "synthetic_250k.jsonl"
        gen_start = time.perf_counter()
        generate_benchmark_file(bench_file, records)
        gen_elapsed = time.perf_counter() - gen_start
        file_size_mb = bench_file.stat().st_size / (1024 * 1024)
        print(f"Generated {records:,} records ({file_size_mb:.2f} MB) in {gen_elapsed:.2f}s")

        # Step 1: Measure tracemalloc peak on a sample batch (5k records) to verify heap bounds
        sample_records = min(5000, records)
        tracemalloc.start()
        sample_count = 0
        for _ in iter_events(bench_file):
            sample_count += 1
            if sample_count >= sample_records:
                break
        _curr, tracemalloc_peak_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        tracemalloc_mb = tracemalloc_peak_bytes / (1024 * 1024)

        # Step 2: Measure full throughput wall-clock time without allocation profiling overhead
        stream_start = time.perf_counter()
        count = 0
        for _ in iter_events(bench_file):
            count += 1
        elapsed = time.perf_counter() - stream_start

        # Step 3: Measure process peak RSS
        rss_mb = get_rss_mb()
        reported_mem_mb = rss_mb if rss_mb is not None else tracemalloc_mb
        rss_str = f"{rss_mb:.1f} MB" if rss_mb is not None else "N/A"

        throughput = count / elapsed if elapsed > 0 else 0.0
        print(f"Processed {count:,} items in {elapsed:.3f}s ({throughput:,.0f} items/sec)")
        print(f"Tracemalloc heap peak (sample): {tracemalloc_mb:.3f} MB")
        print(f"Process peak RSS: {rss_str} (Budget: {mem_budget:.1f} MB)")

        passed = True
        reasons: list[str] = []

        if count != records:
            passed = False
            reasons.append(f"Item count mismatch: expected {records}, got {count}")

        if elapsed > time_budget:
            passed = False
            reasons.append(f"Time exceeded budget: {elapsed:.3f}s > {time_budget:.1f}s")

        if reported_mem_mb > mem_budget:
            passed = False
            reasons.append(f"Memory exceeded budget: {reported_mem_mb:.2f}MB > {mem_budget:.1f}MB")

        if passed:
            print(
                f"PASS: {count:,} records processed in {elapsed:.3f}s "
                f"(budget: {time_budget:.1f}s), "
                f"peak memory {reported_mem_mb:.2f}MB (budget: {mem_budget:.1f}MB)"
            )
            return 0
        else:
            print(f"FAIL: {'; '.join(reasons)}", file=sys.stderr)
            return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SessLint 250k streaming benchmark.")
    parser.add_argument("--records", type=int, default=250_000, help="Number of records to stream")
    parser.add_argument("--time-budget", type=float, default=15.0, help="Time budget in seconds")
    parser.add_argument(
        "--mem-budget", type=float, default=512.0, help="Memory budget in megabytes"
    )
    args = parser.parse_args()

    return run_benchmark(
        records=args.records,
        time_budget=args.time_budget,
        mem_budget=args.mem_budget,
    )


if __name__ == "__main__":
    sys.exit(main())
