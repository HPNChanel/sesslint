"""T-10: unchanged 10k-finding / <1 second gate in a fresh untraced process."""

from __future__ import annotations

import json
import sys
import time
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sesslint.codes import SL001, Repairability, Severity  # noqa: E402
from sesslint.finding import SourceRef, make_finding  # noqa: E402
from sesslint.report import build_report  # noqa: E402


def measure() -> dict[str, object]:
    source = SourceRef(path="large.jsonl", line=1)
    findings = [
        make_finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message_template="Large scale defect",
            source=source,
            related_ids=(f"rel-{i % 50}",),
        )
        for i in range(10_000)
    ]
    traced = sys.gettrace() is not None or sys.getprofile() is not None or tracemalloc.is_tracing()
    start, cpu = time.perf_counter(), time.process_time()
    report = build_report(
        session_id="sess-large",
        source_fingerprint="fp-large",
        tool_version="0.1.0",
        findings=findings,
        assurance="A1",
        limitation="High-scale benchmark test",
    )
    elapsed, cpu_s = time.perf_counter() - start, time.process_time() - cpu
    passed = (
        not traced
        and report.counts.total == 10_000
        and report.counts.by_code["SL001"] == 10_000
        and 0 <= elapsed < 1.0
    )
    return {
        "status": "PASS" if passed else "FAIL",
        "total": report.counts.total,
        "by_code": dict(report.counts.by_code),
        "wall_s": elapsed,
        "cpu_s": cpu_s,
        "tracing": traced,
        "python": sys.version,
    }


if __name__ == "__main__":
    result = measure()
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["status"] == "PASS" else 1)
