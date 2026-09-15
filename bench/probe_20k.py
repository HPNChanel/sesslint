"""20k-record probe for native-accel-plan profiling."""

from __future__ import annotations

import cProfile
import pstats
import sys
import tempfile
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_PATH = _REPO_ROOT / "src"
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
if str(_SRC_PATH) not in sys.path:
    sys.path.insert(0, str(_SRC_PATH))

from bench.perf_250k import generate_benchmark_file  # noqa: E402
from sesslint import api  # noqa: E402


def main() -> None:
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tf:
        p = Path(tf.name)
    try:
        print("Generating 20k-record benchmark file...")
        generate_benchmark_file(p, 20000)
        file_size_mb = p.stat().st_size / (1024 * 1024)
        print(f"Generated {file_size_mb:.2f} MB file.")

        pr = cProfile.Profile()
        t0 = time.perf_counter()
        pr.enable()
        res = api.check_file(p)
        pr.disable()
        t1 = time.perf_counter()

        wall_time = t1 - t0
        print(
            f"Probe complete: wall_time={wall_time:.3f}s, findings={len(res.findings)}, "
            f"assurance={res.assurance}"
        )

        ps = pstats.Stats(pr)
        print("\n--- Call Counts for key functions ---")
        ps.print_stats("content_identity_bytes")
        ps.print_stats("_parse_canonical_event_record")
        ps.print_stats("_normalize_for_canonical_json")
        ps.print_stats("reference_equivalent")

        print("\n--- Top 15 cumulative time functions ---")
        ps.strip_dirs().sort_stats("cumtime").print_stats(15)
    finally:
        p.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
