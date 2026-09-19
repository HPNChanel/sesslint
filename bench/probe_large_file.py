"""Byte-source probe: buffered reader vs mmap reader on large files (T-03).

Generates a canonical JSONL file and measures wall time + peak RSS for
``iter_events`` under both byte sources (forced via ``_MMAP_MIN_BYTES`` /
``_MMAP_MIN_LINE_BYTES``). mmap engages only for large files with large
lines — the copy-bound workload it was built for.

Usage:
    python bench/probe_large_file.py [--mib 95] [--line-bytes 1500000]
"""

from __future__ import annotations

import argparse
import sys
import tempfile
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_PATH = _REPO_ROOT / "src"
for _p in (str(_REPO_ROOT), str(_SRC_PATH)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import sesslint.io as io_mod  # noqa: E402
from bench.perf_250k import get_rss_mb  # noqa: E402
from sesslint.io import iter_events  # noqa: E402

_HEADER = (
    '{"schema_version":"sesslint.canonical/v1","kind":"session_meta",'
    '"id":"probe","ts":"2026-01-01T00:00:00Z","payload":{}}\n'
)


def generate(path: Path, mib: int, line_bytes: int) -> int:
    """Write ~``mib`` MiB of valid canonical JSONL; return record count."""
    line = (
        '{"kind":"message","id":"m%08d","parent_id":"m%08d",'
        '"ts":"2026-01-01T00:%02d:%02dZ","seq":%d,'
        '"payload":{"role":"assistant","blob":"%s"}}\n'
    )
    blob_len = max(16, line_bytes - 200)
    blob = "x" * blob_len
    count = 0
    with open(path, "wb") as fh:
        fh.write(_HEADER.encode())
        target = mib * 1024 * 1024
        written = fh.tell()
        while written < target:
            i = count + 1
            rec = line % (i, i - 1, (i // 60) % 60, i % 60, i, blob)
            b = rec.encode()
            fh.write(b)
            written += len(b)
            count = i
    return count


def measure(path: Path, *, mapped: bool) -> tuple[float, float, int]:
    """Run iter_events under a forced byte source; return (secs, peak_rss_mb, events)."""
    orig_bytes = io_mod._MMAP_MIN_BYTES
    orig_line = io_mod._MMAP_MIN_LINE_BYTES
    if mapped:
        io_mod._MMAP_MIN_BYTES = 0
        io_mod._MMAP_MIN_LINE_BYTES = 0
    else:
        io_mod._MMAP_MIN_BYTES = 10**15
    try:
        start_rss = get_rss_mb() or 0.0
        t0 = time.perf_counter()
        n = 0
        for _ in iter_events(path):
            n += 1
        elapsed = time.perf_counter() - t0
        peak = (get_rss_mb() or 0.0) - start_rss
        return elapsed, peak, n
    finally:
        io_mod._MMAP_MIN_BYTES = orig_bytes
        io_mod._MMAP_MIN_LINE_BYTES = orig_line


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mib", type=int, default=95, help="approximate file size in MiB")
    parser.add_argument(
        "--line-bytes",
        type=int,
        default=1_500_000,
        help="approximate record line size in bytes (default ~1.5 MiB, the "
        "multi-MB Codex rollout shape mmap was built for)",
    )
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="sesslint-mmap-probe-") as td:
        path = Path(td) / "probe.jsonl"
        records = generate(path, args.mib, args.line_bytes)
        size_mb = path.stat().st_size / (1024 * 1024)
        avg_kb = (path.stat().st_size / max(1, records)) / 1024
        print(f"file: {size_mb:.1f} MiB, {records} records, ~{avg_kb:.0f} KiB/line")

        t_buf, rss_buf, n_buf = measure(path, mapped=False)
        t_map, rss_map, n_map = measure(path, mapped=True)

        print(f"buffered : {t_buf:7.2f}s  peak-rss+{rss_buf:7.1f} MB  events={n_buf}")
        print(f"mmap     : {t_map:7.2f}s  peak-rss+{rss_map:7.1f} MB  events={n_map}")
        assert n_buf == n_map, "byte sources must yield identical event streams"
        if t_map > 0:
            print(f"wall ratio mmap/buffered: {t_map / t_buf:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
