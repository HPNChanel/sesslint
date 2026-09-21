"""Tests for SL402 session-index divergence — scan-layer membership diffs.

Contract (index-reconciliation/T-02): when a vendor session index and the
on-disk session set disagree, the scan emits bounded SL402 warnings —
``file-not-in-index`` on indexable files the index omits (only when the
index parsed completely), ``index-entry-no-file`` per index entry that
provably resolves to nothing, and one ``index-malformed`` /
``index-truncated`` on the index's own FileResult when the index itself is
broken. Single-file ``check`` never emits SL402: a narrower view cannot
prove index absence.
"""

from __future__ import annotations

import json
from pathlib import Path

from sesslint.api import check_file
from sesslint.finding import Severity
from sesslint.scan import scan_path

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"
DIVERGENCE = FIXTURES_DIR / "scan" / "index_divergence"


def _sl402(report, path_suffix: str | None = None):
    out = []
    for fr in report.files:
        for f in fr.findings:
            if f.code == "SL402" and (path_suffix is None or fr.path.endswith(path_suffix)):
                out.append((fr, f))
    return out


def _write_session(path: Path, session_id: str) -> None:
    row = {
        "type": "user",
        "uuid": f"{session_id}-1",
        "sessionId": session_id,
        "timestamp": "2025-01-01T00:00:01Z",
        "message": {"role": "user", "content": "x"},
    }
    path.write_text(json.dumps(row) + "\n", encoding="utf-8", newline="\n")


def _write_index(path: Path, ids: list[str]) -> None:
    doc = {
        "version": 1,
        "originalPath": "/synthetic/project",
        "entries": [{"sessionId": s, "fullPath": f"{s}.jsonl", "isSidechain": False} for s in ids],
    }
    path.write_text(json.dumps(doc) + "\n", encoding="utf-8", newline="\n")


def test_missing_member_flags_unindexed_file():
    rep = scan_path(DIVERGENCE / "missing_member", recursive=True)
    hits = _sl402(rep, "sess-c.jsonl")
    assert len(hits) == 1
    _, f = hits[0]
    assert f.severity is Severity.WARNING
    assert f.evidence["divergence"] == "file-not-in-index"
    assert f.evidence["resolution"] == "missing"
    assert f.evidence["index_entry_count"] == 2
    assert len(f.evidence["session_id_hash8"]) == 8
    # No SL402 anywhere else — indexed members and the sidecar stay clean.
    assert len(_sl402(rep)) == 1


def test_dangling_entry_flags_index():
    rep = scan_path(DIVERGENCE / "dangling", recursive=True)
    hits = _sl402(rep)
    assert len(hits) == 1
    fr, f = hits[0]
    assert fr.path.endswith("sessions-index.json")
    assert f.evidence["divergence"] == "index-entry-no-file"
    assert f.evidence["resolution"] == "dangling"
    assert len(f.evidence["entry_id_hash8"]) == 8


def test_malformed_index_emits_only_malformed():
    rep = scan_path(DIVERGENCE / "malformed", recursive=True)
    hits = _sl402(rep)
    assert len(hits) == 1
    fr, f = hits[0]
    assert fr.path.endswith("sessions-index.json")
    assert f.evidence["divergence"] == "index-malformed"
    assert f.evidence["resolution"] == "unparseable"
    assert f.evidence["error_kind"] == "malformed"


def test_truncated_index_emits_only_truncated():
    rep = scan_path(DIVERGENCE / "truncated", recursive=True)
    hits = _sl402(rep)
    assert len(hits) == 1
    fr, f = hits[0]
    assert fr.path.endswith("sessions-index.json")
    assert f.evidence["divergence"] == "index-truncated"
    assert f.evidence["resolution"] == "truncated"
    assert f.evidence["parsed_entry_count"] == 1


def test_absent_index_is_silent():
    rep = scan_path(DIVERGENCE / "absent", recursive=True)
    assert _sl402(rep) == []


def test_single_file_check_never_emits_sl402():
    # Even a file that *would* be unindexed in a directory scan stays clean
    # under single-file check — index absence is unprovable at that width.
    rep = check_file(DIVERGENCE / "missing_member" / "sess-c.jsonl")
    assert all(f.code != "SL402" for f in rep.findings)


def test_select_and_ignore_gate_sl402():
    rep = scan_path(DIVERGENCE / "missing_member", recursive=True, ignore=["SL402"])
    assert _sl402(rep) == []
    rep = scan_path(DIVERGENCE / "dangling", recursive=True, select=["SL402"])
    hits = _sl402(rep)
    assert len(hits) == 1
    assert hits[0][1].evidence["divergence"] == "index-entry-no-file"


def test_deterministic_across_jobs():
    serial = scan_path(DIVERGENCE / "missing_member", recursive=True, jobs=1)
    parallel = scan_path(DIVERGENCE / "missing_member", recursive=True, jobs=4)
    assert [(f.code, dict(f.evidence or {})) for fr in serial.files for f in fr.findings] == [
        (f.code, dict(f.evidence or {})) for fr in parallel.files for f in fr.findings
    ]


def test_non_session_sidecars_not_members(tmp_path: Path):
    # Sub-agent logs, file-history snapshots, and undetected .jsonl siblings
    # can exist without index membership — they must never be flagged.
    _write_session(tmp_path / "sess-a.jsonl", "sess-a")
    _write_index(tmp_path / "sessions-index.json", ["sess-a"])
    (tmp_path / "file-history").mkdir()
    _write_session(tmp_path / "file-history" / "snap.jsonl", "hist-snap")
    (tmp_path / "subagents").mkdir()
    _write_session(tmp_path / "subagents" / "agent-1.jsonl", "agent-1")
    (tmp_path / "blob.jsonl").write_bytes(b"\x00\xff\xfe binary junk")
    rep = scan_path(tmp_path, recursive=True)
    hits = _sl402(rep)
    assert hits == []


def test_filtered_file_satisfies_index_entry(tmp_path: Path):
    # An --ext-scoped-out session file still exists on disk, so its index
    # entry is not dangling — divergence is about existence, not scan scope.
    _write_session(tmp_path / "sess-a.jsonl", "sess-a")
    _write_session(tmp_path / "sess-b.jsonl", "sess-b")
    _write_index(tmp_path / "sessions-index.json", ["sess-a", "sess-b"])
    rep = scan_path(tmp_path, recursive=True, exclude=["sess-b.jsonl"])
    assert _sl402(rep) == []


def test_renamed_file_member_via_session_id(tmp_path: Path):
    # The index claims ``sess-a``; the file was renamed but still carries the
    # session id — no divergence either direction.
    _write_session(tmp_path / "renamed.jsonl", "sess-a")
    _write_index(tmp_path / "sessions-index.json", ["sess-a"])
    rep = scan_path(tmp_path, recursive=True)
    assert _sl402(rep) == []


def test_idless_entries_block_absence_allow_dangling(tmp_path: Path):
    _write_session(tmp_path / "sess-a.jsonl", "sess-a")
    _write_session(tmp_path / "sess-b.jsonl", "sess-b")
    doc = {
        "version": 1,
        "entries": [
            {"sessionId": "sess-a"},
            {"summary": "no id here"},
            {"sessionId": "sess-ghost"},
        ],
    }
    (tmp_path / "sessions-index.json").write_text(json.dumps(doc), encoding="utf-8", newline="\n")
    rep = scan_path(tmp_path, recursive=True)
    kinds = [f.evidence["divergence"] for _, f in _sl402(rep)]
    # sess-b is unindexed, but an entry with no sessionId could have claimed
    # it — absence is unprovable, so only the provable dangling entry fires.
    assert kinds == ["index-entry-no-file"]


def test_baseline_suppresses_new_findings():
    rep = scan_path(DIVERGENCE / "dangling", recursive=True)
    fps = frozenset(f.fingerprint for _, f in _sl402(rep))
    rep2 = scan_path(DIVERGENCE / "dangling", recursive=True, baseline=fps)
    assert _sl402(rep2) == []


def test_nested_dirs_reconcile_per_index(tmp_path: Path):
    # Root scan over multiple project dirs: each index reconciles against
    # its own siblings only — p1's index must not claim p2's files.
    p1 = tmp_path / "p1"
    p2 = tmp_path / "p2"
    p1.mkdir()
    p2.mkdir()
    _write_session(p1 / "sess-a.jsonl", "sess-a")
    _write_session(p1 / "sess-b.jsonl", "sess-b")
    _write_index(p1 / "sessions-index.json", ["sess-a"])
    _write_session(p2 / "sess-a.jsonl", "sess-a")
    _write_index(p2 / "sessions-index.json", ["sess-a"])
    rep = scan_path(tmp_path, recursive=True)
    hits = _sl402(rep)
    assert len(hits) == 1
    fr, f = hits[0]
    # sess-b exists only under p1 — a single hit on it proves the p2 index
    # did not bleed claims across directory boundaries.
    assert fr.path.endswith("sess-b.jsonl")
    assert f.evidence["divergence"] == "file-not-in-index"


def test_evidence_is_content_free():
    rep = scan_path(DIVERGENCE / "dangling", recursive=True)
    for _, f in _sl402(rep):
        blob = json.dumps(dict(f.evidence or {}))
        assert "sess-ghost" not in blob
        assert "synthetic" not in blob


def _human_output(report) -> str:
    import dataclasses

    from sesslint.cli import format_scan_report_human
    from sesslint.scan import aggregate_scan

    rep = dataclasses.replace(report, summary=aggregate_scan(report.files))
    return format_scan_report_human(rep)


def test_scan_summary_line_file_not_in_index():
    out = _human_output(scan_path(DIVERGENCE / "missing_member", recursive=True))
    assert "index divergence: 1 session file(s) not listed in vendor index" in out
    assert "resumable by explicit id" in out
    assert "docs/codes/SL402.md" in out


def test_scan_summary_line_index_side_kinds():
    out = _human_output(scan_path(DIVERGENCE / "dangling", recursive=True))
    assert "index divergence: 1 dangling index entry" in out
    out = _human_output(scan_path(DIVERGENCE / "malformed", recursive=True))
    assert "index divergence: malformed index" in out
    out = _human_output(scan_path(DIVERGENCE / "truncated", recursive=True))
    assert "index divergence: truncated index" in out


def test_scan_summary_line_absent_when_clean():
    out = _human_output(scan_path(DIVERGENCE / "absent", recursive=True))
    assert "index divergence" not in out
