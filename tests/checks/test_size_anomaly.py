"""Tests for SL011 record size anomaly (checks-rules T-07).

Contract: fire when a record's byte size exceeds
``max(median * 20, 256 KiB)`` of the file's own distribution — a *relative*
outlier check (legit ~1.5 MiB rollout lines exist; absolute limits are the
reader line cap's job). INFO severity, one finding per file max, <8 records
skip via coverage ``adapter-not-applicable``.
"""

from __future__ import annotations

import json
from pathlib import Path

from sesslint.adapters.claude_code import load_claude_code
from sesslint.api import check_file
from sesslint.checks.size import (
    SIZE_FLOOR_BYTES,
    SIZE_MIN_RECORDS,
    SIZE_RATIO_K,
    check_size_anomaly,
)
from sesslint.context import CheckContext
from sesslint.finding import Severity

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"
CHECKS = FIXTURES_DIR / "checks"


def _ctx(sizes: list[int]) -> CheckContext:
    return CheckContext(
        adapter_id="claude-code-jsonl",
        adapter_version="1.0.0",
        profile_id="neutral",
        profile_version="1.0.0",
        source_metadata={"record_sizes": sizes},
    )


def _claude_record(rid: str, parent: str | None, content: str = "x") -> dict:
    r = {
        "type": "user",
        "uuid": rid,
        "sessionId": "sess-t",
        "timestamp": "2025-01-01T00:00:01Z",
        "message": {"role": "user", "content": content},
    }
    if parent:
        r["parentUuid"] = parent
    return r


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with open(path, "w", newline="\n") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


def test_outlier_fires_once_with_numbers_only_evidence():
    sizes = [150] * 9 + [300_000]
    findings = check_size_anomaly([], source_path="f.jsonl", context=_ctx(sizes))
    assert len(findings) == 1
    f = findings[0]
    assert f.code == "SL011"
    assert f.severity is Severity.INFO
    assert f.evidence["record_index"] == 9
    assert f.evidence["record_bytes"] == 300_000
    assert f.evidence["file_median_bytes"] == 150
    assert f.evidence["ratio"] == round(300_000 / 150, 3)


def test_uniform_file_stays_clean():
    sizes = [1024] * 12
    assert check_size_anomaly([], source_path="f", context=_ctx(sizes)) == []


def test_uniformly_large_file_stays_clean():
    """Legit codex-shape: every record ~1.5 MiB — median scales the threshold."""
    sizes = [1_500_000] * 10
    assert check_size_anomaly([], source_path="f", context=_ctx(sizes)) == []


def test_bimodal_within_ratio_stays_clean():
    """A 1.5 MiB record among ~100 KiB records: threshold 2 MiB — no fire."""
    sizes = [100_000] * 9 + [1_500_000]
    assert check_size_anomaly([], source_path="f", context=_ctx(sizes)) == []


def test_below_floor_never_fires():
    """Outlier under the absolute floor is ignored even at huge ratio."""
    sizes = [10] * 9 + [50_000]  # ratio 5000x but below 256 KiB floor
    assert check_size_anomaly([], source_path="f", context=_ctx(sizes)) == []


def test_under_min_records_skips():
    sizes = [300_000] * (SIZE_MIN_RECORDS - 1)
    assert check_size_anomaly([], source_path="f", context=_ctx(sizes)) == []


def test_missing_size_metadata_yields_nothing():
    assert check_size_anomaly([], source_path="f", context=_ctx([])) == []
    ctx = CheckContext(
        adapter_id="x",
        adapter_version="1",
        profile_id="p",
        profile_version="1",
        source_metadata={},
    )
    assert check_size_anomaly([], source_path="f", context=ctx) == []
    assert check_size_anomaly([], source_path="f", context=None) == []


def test_threshold_boundary_exact():
    """record == threshold does not fire; record > threshold fires."""
    median = 150
    threshold = max(median * SIZE_RATIO_K, SIZE_FLOOR_BYTES)
    sizes = [median] * 9 + [threshold]
    assert check_size_anomaly([], source_path="f", context=_ctx(sizes)) == []
    sizes = [median] * 9 + [threshold + 1]
    assert len(check_size_anomaly([], source_path="f", context=_ctx(sizes))) == 1


def test_largest_only_one_finding():
    """Multiple over-threshold records still yield exactly one finding."""
    sizes = [150] * 8 + [400_000, 350_000]
    findings = check_size_anomaly([], source_path="f", context=_ctx(sizes))
    assert len(findings) == 1
    assert findings[0].evidence["record_bytes"] == 400_000
    assert findings[0].evidence["record_index"] == 8


def test_zero_median_edge_no_division_error():
    sizes = [0] * 9 + [300_000]
    findings = check_size_anomaly([], source_path="f", context=_ctx(sizes))
    assert len(findings) == 1
    assert findings[0].evidence["file_median_bytes"] == 0
    assert findings[0].evidence["ratio"] is None


def test_e2e_outlier_fixture():
    res = check_file(CHECKS / "sl011_outlier.jsonl")
    hits = [f for f in res.findings if f.code == "SL011"]
    assert len(hits) == 1
    assert hits[0].severity is Severity.INFO
    assert hits[0].evidence["record_index"] == 9


def test_e2e_uniform_fixture_clean():
    res = check_file(CHECKS / "sl011_uniform.jsonl")
    assert all(f.code != "SL011" for f in res.findings)


def test_e2e_small_fixture_coverage_skip():
    res = check_file(CHECKS / "sl011_small.jsonl")
    assert all(f.code != "SL011" for f in res.findings)
    skips = {(s.check, s.reason) for s in res.coverage.skipped}
    assert ("SL011", "adapter-not-applicable") in skips
    assert "size" not in res.coverage.performed


def test_e2e_legit_large_codex_shape_clean(tmp_path: Path):
    """A codex rollout of uniform ~1.5 MiB output records does not fire."""
    p = tmp_path / "rollout-big.jsonl"
    rows = [
        {
            "type": "session_meta",
            "payload": {"id": "thread-x"},
        }
    ]
    for i in range(9):
        rows.append(
            {
                "type": "response_item",
                "id": f"e{i}",
                "payload": {
                    "type": "custom_tool_call_output",
                    "output": "Q" * 1_500_000,
                },
            }
        )
    _write_jsonl(p, rows)
    res = check_file(p, format="codex-rollout")
    assert all(f.code != "SL011" for f in res.findings)


def test_codex_adapter_skips_size_check(tmp_path: Path):
    """codex-rollout skips SL011 entirely: bulk payload records are
    vendor-normal there (~84% real-corpus fire rate = no signal), so the
    family is gated ``adapter-not-applicable`` — even a genuine
    20x-median outlier stays silent."""
    p = tmp_path / "rollout-outlier.jsonl"
    rows = [{"type": "session_meta", "payload": {"id": "thread-x"}}]
    for i in range(9):
        rows.append(
            {
                "type": "response_item",
                "id": f"e{i}",
                "payload": {"type": "custom_tool_call_output", "output": "Q" * 1000},
            }
        )
    rows.append(
        {
            "type": "response_item",
            "id": "big",
            "payload": {"type": "custom_tool_call_output", "output": "Q" * 5_000_000},
        }
    )
    _write_jsonl(p, rows)
    res = check_file(p, format="codex-rollout")
    assert all(f.code != "SL011" for f in res.findings)
    skips = {(s.check, s.reason) for s in res.coverage.skipped}
    assert ("SL011", "adapter-not-applicable") in skips
    assert "size" not in res.coverage.performed


def test_adapter_publishes_record_sizes(tmp_path: Path):
    """Adapter normalization feeds the distribution — no re-read needed."""
    p = tmp_path / "sizes.jsonl"
    rows, prev = [], None
    for i in range(9):
        rid = f"r{i}"
        rows.append(_claude_record(rid, prev))
        prev = rid
    _write_jsonl(p, rows)
    events, _ = load_claude_code(p)
    sizes = events.source.get("record_sizes")
    assert isinstance(sizes, list)
    assert len(sizes) == 9
    assert all(isinstance(s, int) and s > 0 for s in sizes)


def test_select_ignore_gating(tmp_path: Path):
    """SL011 honors profile gating like every rule."""
    from sesslint.scan import scan_path

    d = tmp_path / "sel"
    d.mkdir()
    rows, prev = [], None
    for i in range(9):
        rid = f"r{i}"
        rows.append(_claude_record(rid, prev))
        prev = rid
    rows.append(_claude_record("big", prev, "Z" * 300_000))
    _write_jsonl(d / "f.jsonl", rows)
    rep = scan_path(d, recursive=True, ignore=["SL011"])
    assert all(f.code != "SL011" for fr in rep.files for f in fr.findings)


def test_determinism():
    sizes = [150, 300_000, 150, 150, 150, 150, 150, 150, 150]
    a = check_size_anomaly([], source_path="f", context=_ctx(sizes))
    b = check_size_anomaly([], source_path="f", context=_ctx(list(sizes)))
    assert len(a) == len(b) == 1
    assert a[0].fingerprint == b[0].fingerprint
