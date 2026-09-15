"""Performance benchmark: streaming ~100MB / 250k records within 15s and 512MB (TASK-026 / P2-04).

This benchmark verifies SessLint's streaming reader throughput, bounded heap, and peak
RSS memory guarantees under production-scale load (FR-013, FR-014, FR-095, AC-023).
It asserts strict adherence to time and memory budgets, exiting with non-zero code on breach.

Usage:
    python bench/perf_250k.py [--records 250000] [--time-budget 15.0] [--mem-budget 512.0]
"""

from __future__ import annotations

import argparse
import json
import platform
import random
import re
import subprocess
import sys
import tempfile
import time
import tracemalloc
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Ensure sesslint from src/ is importable even when not installed in editable mode
_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_PATH = _REPO_ROOT / "src"
if str(_SRC_PATH) not in sys.path:
    sys.path.insert(0, str(_SRC_PATH))

from sesslint import api  # noqa: E402
from sesslint.io import iter_events  # noqa: E402


def generate_benchmark_file(path: Path, num_records: int) -> None:
    """Generate deterministic synthetic ~100MB session JSONL file with num_records events.

    Uses fixed random seed 0x026 per TASK-026 specification.
    """
    rng = random.Random(0x026)
    pad_chars = "abcdefghijklmnopqrstuvwxyz0123456789-_"
    # Pre-generate 100 deterministic payload padding chunks (~260 bytes each)
    padding_pool = ["".join(rng.choices(pad_chars, k=260)) for _ in range(100)]

    batch_size = 5000
    with open(path, "w", encoding="utf-8") as f:
        # Write canonical header
        f.write(
            '{"created_at":"2026-09-06T00:00:00Z","schema_version":"sesslint.session/v1",'
            '"session_id":"sess_perf_250k"}\n'
        )
        for start in range(0, num_records, batch_size):
            end = min(start + batch_size, num_records)
            lines: list[str] = []
            for i in range(start, end):
                pid_str = "null" if i == 0 else f'"evt_{i - 1:07d}"'
                lines.append(
                    f'{{"actor":"user","id":"evt_{i:07d}","kind":"message",'
                    f'"parent_id":{pid_str},'
                    f'"payload":{{"index":{i},"text":"{padding_pool[i % 100]}"}},'
                    f'"seq":{i},"ts":"2026-09-06T00:00:00Z"}}'
                )
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


def verify_reference_disclosure_recorded() -> bool:
    """Validate the latest reference baseline block in bench/PERF_NOTES.md.

    The block (delimited by REFERENCE-BASELINE markers) must be complete and
    internally consistent: run ID, ISO date, host status (an honest
    "unknown/not captured" is allowed), record count, input size, measured
    values, budgets, breach classes that match the classes derived from those
    values, and a status consistent with them ("BREACH" iff classes non-empty,
    "PASS" iff empty).

    This validator never compares a current run's fluctuating values against
    the static notes, and never claims the notes describe a future run.
    """
    perf_notes = _REPO_ROOT / "bench" / "PERF_NOTES.md"
    if not perf_notes.is_file():
        return False
    content = perf_notes.read_text(encoding="utf-8")
    begin = "<!-- REFERENCE-BASELINE:BEGIN -->"
    end = "<!-- REFERENCE-BASELINE:END -->"
    if content.count(begin) != 1 or content.count(end) != 1:
        return False
    block = content.split(begin, 1)[1].split(end, 1)[0]

    fields: dict[str, str] = {}
    for raw_line in block.splitlines():
        line = raw_line.strip()
        if line.startswith("-") and ":" in line:
            key, _, val = line[1:].partition(":")
            fields[key.strip().lower().strip("*")] = val.strip()

    required = (
        "run id",
        "date",
        "host",
        "records",
        "input size mb",
        "total time s",
        "time budget s",
        "peak rss mb",
        "memory budget mb",
        "breach classes",
        "status",
    )
    if any(not fields.get(k) for k in required):
        return False
    if not re.match(r"^\d{4}-\d{2}-\d{2}\b", fields["date"]):
        return False
    try:
        records = int(fields["records"].replace(",", ""))
        float(fields["input size mb"])
        total_s = float(fields["total time s"])
        time_budget = float(fields["time budget s"])
        rss_mb = float(fields["peak rss mb"])
        mem_budget = float(fields["memory budget mb"])
    except ValueError:
        return False
    if records <= 0:
        return False

    declared = {
        c.strip().lower()
        for c in fields["breach classes"].split(",")
        if c.strip() and c.strip().lower() != "none"
    }
    if not declared.issubset({"time", "memory"}):
        return False
    derived: set[str] = set()
    if total_s > time_budget:
        derived.add("time")
    if rss_mb > mem_budget:
        derived.add("memory")
    if declared != derived:
        return False

    status = fields["status"].lower()
    if derived and "breach" not in status:
        return False
    if not derived and "pass" not in status:
        return False
    return True


_CHILD_RUNNER = """\
import json
import sys
import time

sys.path.insert(0, {src!r})
sys.path.insert(0, {repo!r})

from bench.perf_250k import get_rss_mb  # noqa: E402
from sesslint.cli import main  # noqa: E402

t0 = time.perf_counter()
code = main(["check", sys.argv[1], "--json"])
elapsed = time.perf_counter() - t0
sys.stderr.write(
    "CHILD-STATS "
    + json.dumps(
        {{"check_s": elapsed, "peak_rss_mb": get_rss_mb(), "exit_code": code}}
    )
    + "\\n"
)
sys.exit(code)
"""


def run_fresh_process_check(bench_file: Path) -> dict[str, Any] | None:
    """Run the real `sesslint check` CLI path in a fresh child process.

    The child executes the CLI `main()` and self-reports its elapsed wall time
    and process-lifetime peak RSS on a `CHILD-STATS` stderr line. The parent's
    RSS never includes the child's memory, so these are the normative FR-095
    measurements — isolated from fixture-generation and streaming-pass
    contamination.
    """
    runner = _CHILD_RUNNER.format(src=str(_SRC_PATH), repo=str(_REPO_ROOT))
    try:
        proc = subprocess.run(
            [sys.executable, "-c", runner, str(bench_file)],
            capture_output=True,
            text=True,
            timeout=600,
        )
    except Exception:
        return None
    stats: dict[str, Any] | None = None
    for line in proc.stderr.splitlines():
        if line.startswith("CHILD-STATS "):
            try:
                stats = json.loads(line[len("CHILD-STATS ") :])
            except json.JSONDecodeError:
                stats = None
    return {
        "exit_code": proc.returncode,
        "stats": stats,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def run_benchmark(records: int, time_budget: float, mem_budget: float) -> int:
    """Execute 100MB / 250k streaming and validation benchmark.

    The run discloses itself: measured values, budgets, derived breach
    classes, and run context are always printed. Returns 0 only when the run
    is functionally correct AND within all budgets; returns 1 on any
    functional failure or budget breach — disclosure is mandatory context,
    never a waiver.
    """
    print("=== SessLint 100MB / 250k Performance Benchmark (TASK-026) ===")
    print(
        f"Records: {records:,} | Time budget: {time_budget:.1f}s | "
        f"Memory budget: {mem_budget:.1f}MB"
    )
    print(
        f"Run context: date={datetime.now(UTC).date().isoformat()} "
        f"host={platform.machine() or 'unknown'}/{sys.platform} "
        f"python={platform.python_version()}"
    )

    with tempfile.TemporaryDirectory(prefix="sesslint_bench_") as tmp_dir:
        bench_file = Path(tmp_dir) / "synthetic_100mb.jsonl"
        gen_start = time.perf_counter()
        generate_benchmark_file(bench_file, records)
        gen_elapsed = time.perf_counter() - gen_start
        file_size_mb = bench_file.stat().st_size / (1024 * 1024)
        print(f"Generated {records:,} records ({file_size_mb:.2f} MB) in {gen_elapsed:.2f}s")

        # Auxiliary phase-level in-process RSS readings (cumulative peaks; used
        # for contamination evidence, never summed into the normative result).
        phase_rss: dict[str, float | None] = {"baseline": get_rss_mb()}
        phase_rss["post-generation"] = get_rss_mb()

        # Auxiliary metric: tracemalloc heap peak on a streaming sample (5k records)
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
        phase_rss["post-streaming-sample"] = get_rss_mb()

        # Auxiliary metric: full streaming throughput pass (no retention)
        stream_start = time.perf_counter()
        count = 0
        for _ in iter_events(bench_file):
            count += 1
        stream_elapsed = time.perf_counter() - stream_start
        phase_rss["post-iter-events"] = get_rss_mb()

        # Auxiliary metric: in-process check under tracemalloc — also the
        # functional-correctness gate for this run.
        tracemalloc.start()
        check_start = time.perf_counter()
        report = api.check_file(bench_file)
        check_elapsed = time.perf_counter() - check_start
        _curr2, check_heap_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        check_heap_mb = check_heap_bytes / (1024 * 1024)
        phase_rss["post-check"] = get_rss_mb()

        # Normative FR-095 metric: the real `sesslint check` CLI path executed
        # in a fresh child process — its own wall time and peak RSS.
        child = run_fresh_process_check(bench_file)
        child_stats = child["stats"] if child is not None else None
        child_check_s = float(child_stats["check_s"]) if isinstance(child_stats, dict) else None
        child_peak_mb = (
            float(child_stats["peak_rss_mb"])
            if isinstance(child_stats, dict)
            and isinstance(child_stats.get("peak_rss_mb"), (int, float))
            else None
        )
        child_report: dict[str, Any] | None = None
        if child is not None and child.get("stdout"):
            try:
                parsed_report = json.loads(child["stdout"])
                if isinstance(parsed_report, dict):
                    child_report = parsed_report
            except json.JSONDecodeError:
                child_report = None

        rss_mb = get_rss_mb()
        rss_str = f"{rss_mb:.1f} MB" if rss_mb is not None else "N/A"
        throughput = count / stream_elapsed if stream_elapsed > 0 else 0.0
        t_msg = f"{throughput:,.0f} items/sec"
        print(f"Streaming parse (auxiliary): {count:,} items in {stream_elapsed:.3f}s ({t_msg})")
        print(
            f"In-process check (auxiliary): {check_elapsed:.3f}s "
            f"(verdict: assurance={report.assurance})"
        )
        print(f"Tracemalloc heap peak, 5k sample (auxiliary): {tracemalloc_mb:.3f} MB")
        print(f"Tracemalloc heap peak, full check path (auxiliary): {check_heap_mb:.3f} MB")
        phase_str = " | ".join(
            f"{k}={v:.1f}MB" if v is not None else f"{k}=N/A" for k, v in phase_rss.items()
        )
        print(f"Phase RSS, in-process cumulative (auxiliary): {phase_str}")
        print(f"Parent process peak RSS (auxiliary): {rss_str}")
        if child_stats is not None and child_check_s is not None:
            print(
                f"Fresh-process check (normative): {child_check_s:.3f}s, "
                f"peak RSS {child_peak_mb:.1f} MB, exit={child['exit_code']}"
            )
        else:
            print("Fresh-process check (normative): UNAVAILABLE")

        # 1. Functional correctness: MUST ALWAYS PASS (RVW-037).
        # Disclosure rule applies ONLY to performance budget shortfalls, never functional bugs.
        functional_failures: list[str] = []
        if count != records:
            functional_failures.append(f"Item count mismatch: expected {records}, got {count}")

        if len(report.findings) != 0:
            finding_codes = [f.code for f in report.findings]
            functional_failures.append(
                f"Expected 0 findings on clean session, got {len(report.findings)}: {finding_codes}"
            )

        if report.assurance not in ("A3", "A4"):
            functional_failures.append(
                f"Expected assurance A3 or A4 on clean session, got {report.assurance}"
            )

        error_cnt = report.counts.by_severity.get("error", 0) + report.counts.by_severity.get(
            "fatal", 0
        )
        if error_cnt != 0:
            functional_failures.append(f"Expected 0 errors on clean session, got {error_cnt}")

        warn_cnt = report.counts.by_severity.get("warning", 0)
        if warn_cnt != 0:
            functional_failures.append(f"Expected 0 warnings on clean session, got {warn_cnt}")

        # The fresh child must also produce a valid clean report.
        if child is None or child["exit_code"] != 0 or child_report is None:
            child_exit = child["exit_code"] if child is not None else "spawn-error"
            functional_failures.append(
                f"Fresh-process check did not produce a clean report (exit={child_exit})"
            )
        else:
            c_findings = child_report.get("counts", {}).get("total")
            if c_findings != 0:
                functional_failures.append(
                    f"Fresh-process check reported {c_findings} findings on clean session"
                )

        if functional_failures:
            print(
                f"FATAL FUNCTIONAL CORRECTNESS FAILURE (RVW-037):\n"
                f"  {'; '.join(functional_failures)}\n"
                "Functional correctness cannot be excused by performance disclosure.",
                file=sys.stderr,
            )
            return 1

        # 2. Normative performance budget evaluation — fresh-child metrics only.
        if child_check_s is None or child_peak_mb is None:
            print(
                "FATAL: normative fresh-process measurement unavailable (child stats missing)",
                file=sys.stderr,
            )
            return 1

        perf_shortfalls: list[str] = []
        if child_check_s > time_budget:
            perf_shortfalls.append(
                f"Check time exceeded budget: {child_check_s:.3f}s > {time_budget:.1f}s"
            )

        if child_peak_mb > mem_budget:
            perf_shortfalls.append(
                f"Check peak RSS exceeded budget: {child_peak_mb:.2f}MB > {mem_budget:.1f}MB"
            )

        breach_classes: list[str] = []
        if child_check_s > time_budget:
            breach_classes.append("time")
        if child_peak_mb > mem_budget:
            breach_classes.append("memory")
        breach_str = ", ".join(breach_classes) if breach_classes else "none"
        print(f"Breach classes: {breach_str}")

        if perf_shortfalls:
            reference_ok = verify_reference_disclosure_recorded()
            disclosure_info = (
                "Latest reference baseline recorded in bench/PERF_NOTES.md."
                if reference_ok
                else "No valid reference baseline in bench/PERF_NOTES.md."
            )
            print(
                f"PERFORMANCE BUDGET BREACH (FAIL):\n"
                f"  {'; '.join(perf_shortfalls)}\n"
                f"  Fresh-process check time: {child_check_s:.3f}s (budget: {time_budget:.1f}s)\n"
                f"  Fresh-process peak RSS: {child_peak_mb:.2f}MB (budget: {mem_budget:.1f}MB)\n"
                f"  Breach classes: {breach_str}\n"
                f"  {disclosure_info}",
                file=sys.stderr,
            )
            return 1

        print(
            f"PASS: {count:,} records ({file_size_mb:.1f} MB); fresh-process check "
            f"{child_check_s:.3f}s (budget: {time_budget:.1f}s), "
            f"peak RSS {child_peak_mb:.2f}MB (budget: {mem_budget:.1f}MB)"
        )
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SessLint 100MB / 250k streaming benchmark.")
    parser.add_argument(
        "--records", type=int, default=250_000, help="Number of records to stream (~100MB)"
    )
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
