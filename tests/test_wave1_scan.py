"""Wave 1 scan scope, reporting and snapshot safety regressions (B3-B8, B27)."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path

import pytest

from sesslint import api
from sesslint.cli import main
from sesslint.scan import aggregate_scan, scan_path


def _session(path: Path, *, warnings: int = 0) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    records = [
        {
            "schema_version": "sesslint.session/v1",
            "session_id": "synthetic",
            "created_at": "2026-01-01T00:00:00Z",
            "source": {},
        }
    ]
    for i in range(max(1, warnings)):
        records.append(
            {
                "id": f"evt-{i}",
                "parent_id": None if i == 0 else f"evt-{i - 1}",
                "seq": i,
                "ts": "2026-01-01T00:00:00Z",
                "actor": "user",
                "kind": "message",
                "payload": {"text": "sk-" + "a" * 48 if warnings else "synthetic"},
            }
        )
    data = b"".join(json.dumps(rec).encode() + b"\n" for rec in records)
    path.write_bytes(data)
    return data


def test_unknown_input_has_no_synthetic_integrity_error(tmp_path: Path, capsys) -> None:
    source = tmp_path / "notes.md"
    source.write_text("synthetic notes")
    result = scan_path(source)
    assert result.totals.unsupported == 1
    assert result.files[0].findings == ()
    assert result.files[0].skipped_reason == "format-undetected"
    assert main(["check", str(source)]) == 0
    output = capsys.readouterr()
    assert "Session is healthy" not in output.out
    assert "Unsupported input" in output.out
    assert "No repair needed" not in output.out
    assert "bundle" not in output.err
    assert main(["check", str(source), "--fail-on-unsupported"]) == 1
    assert main(["scan", str(source), "--fail-on-unsupported"]) == 1


def test_vendor_scope_excludes_memory_and_tool_results(tmp_path: Path) -> None:
    included = ["project/session.jsonl", "project/session/subagents/agent-a.jsonl"]
    excluded = [
        "project/tool-results/file.jsonl",
        "project/memory/note.jsonl",
        "project/session/subagents/agent-a.meta.json",
        "project/custom-title.json",
    ]
    for rel in included + excluded:
        _session(tmp_path / rel)
    result = scan_path(tmp_path, recursive=True, vendor_layout="claude")
    assert result.totals.total == 2
    assert all(r.verdict == "healthy" for r in result.files)


def test_newest_and_since_select_before_cumulative_caps(tmp_path: Path) -> None:
    for i in range(3):
        path = tmp_path / f"{i}.jsonl"
        _session(path)
        os.utime(path, (1767225600 + i * 86400, 1767225600 + i * 86400))
    result = scan_path(tmp_path, recursive=True, newest=1, since="2026-01-02")
    assert result.totals.healthy == 1
    assert result.totals.skipped == 2
    assert next(r for r in result.files if r.verdict == "healthy").path.endswith("2.jsonl")
    assert result.skipped_reason_totals() == {"before-since": 1, "newest-cap-exceeded": 1}


def test_file_limit_skips_without_malformed_finding_and_can_be_raised(tmp_path: Path) -> None:
    path = tmp_path / "input.jsonl"
    data = _session(path)
    small = scan_path(path, max_file_bytes=len(data) - 1)
    assert small.files[0].skipped_reason == "file-too-large"
    assert api.check(path, max_file_bytes=len(data) - 1).limitation.startswith("Skipped:")
    assert not small.files[0].findings
    assert scan_path(path, max_file_bytes=len(data)).totals.healthy == 1
    report = api.check_file(path, max_file_bytes=len(data) - 1)
    assert report.limitation.startswith("Skipped: file-too-large")
    assert not report.findings
    assert report.assurance == "A0"


def test_finding_samples_do_not_change_counts_or_cached_results(tmp_path: Path) -> None:
    root = tmp_path / "sessions"
    _session(root / "input.jsonl", warnings=30)
    options = dict(
        recursive=True, max_findings_per_code=3, incremental=True, cache_dir=tmp_path / "cache"
    )
    first = scan_path(root, **options)
    second = scan_path(root, **options)
    assert first.files[0].warning_count >= 30
    assert second.files[0].cache_hit
    for result in (first, second):
        wire = result.to_dict()["files"][0]
        assert len([f for f in wire["findings"] if f["code"] == "SL009"]) == 3
        assert next(g for g in wire["finding_groups"] if g["code"] == "SL009")["count"] == 30
        summary = aggregate_scan(result.files)
        assert next(row.count for row in summary.by_code if row.code == "SL009") == 30


def test_check_digest_binds_parsed_snapshot_during_write(tmp_path: Path, monkeypatch) -> None:
    from sesslint.adapters import load

    path = tmp_path / "input.jsonl"
    data = _session(path)
    original = load.load_events_for_format

    def racing_load(source, fmt, **kwargs):
        path.write_bytes(b"changed after snapshot\n")
        return original(source, fmt, **kwargs)

    monkeypatch.setattr(load, "load_events_for_format", racing_load)
    report = api.check_file(path)
    assert report.source_fingerprint == hashlib.sha256(data).hexdigest()
    assert not report.findings


@pytest.mark.parametrize("value", [-1, True, 1.5])
def test_bad_timestamp_tolerance_rejected(tmp_path: Path, value) -> None:
    path = tmp_path / "input.jsonl"
    _session(path)
    with pytest.raises(ValueError, match="timestamp_skew_ms"):
        api.check_file(path, timestamp_skew_ms=value)


def test_timestamp_tolerance_configuration(tmp_path: Path, capsys) -> None:
    path = tmp_path / "input.jsonl"
    _session(path)
    config = tmp_path / "pyproject.toml"
    config.write_text("[tool.sesslint]\ntimestamp_skew_ms = 0\nmax_file_bytes = 20\n")
    assert main(["check", str(path), "--config", str(config), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["limitation"].startswith("Skipped: file-too-large")


@pytest.mark.parametrize("command", ["check", "scan"])
def test_stdin_invalid_limit_is_usage_error(command: str, monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(b"synthetic")))
    try:
        status = main([command, "-", "--max-file-bytes", "-1"])
    except SystemExit as error:
        status = error.code
    assert status == 2
    assert "max_file_bytes" in capsys.readouterr().err
