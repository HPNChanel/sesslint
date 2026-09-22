"""Tests for SL401 cross-file linkage — scan-layer resume-link resolution.

Contract (checks-rules/T-06): adapters surface declared resume pointers as
bounded ``extra_fields``-style metadata; the scan layer resolves each link
against the scanned file set (by ``session_id`` and filename stem for
``session_ref`` links, by tip event id for ``head_ref`` links). A missing
bare-id target is a warning (absence is provable in the enumerated set); an
ambiguous target is a warning; a path-like or head-event target that resolves
to nothing is info-level ``unresolved`` — a narrower scan cannot prove absence
outside its root. Single-file ``check`` never emits SL401.
"""

from __future__ import annotations

import json
from pathlib import Path

from sesslint.api import check_file
from sesslint.finding import Severity
from sesslint.scan import SessionLink, scan_path

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"
LINKAGE = FIXTURES_DIR / "scan" / "linkage"


def _sl401(report, path_suffix: str | None = None):
    out = []
    for fr in report.files:
        for f in fr.findings:
            if f.code == "SL401" and (path_suffix is None or fr.path.endswith(path_suffix)):
                out.append((fr, f))
    return out


def _write_session(path: Path, session_id: str, ids: list[str], extra=None) -> None:
    prev = None
    with open(path, "w", newline="\n") as fh:
        for rid in ids:
            row = {
                "type": "user",
                "uuid": rid,
                "sessionId": session_id,
                "timestamp": "2025-01-01T00:00:01Z",
                "message": {"role": "user", "content": "x"},
            }
            if prev:
                row["parentUuid"] = prev
            if extra:
                row.update(extra)
            fh.write(json.dumps(row) + "\n")
            prev = rid


def test_intact_chain_emits_nothing():
    rep = scan_path(LINKAGE / "chain", recursive=True)
    assert _sl401(rep) == []


def test_missing_middle_warns_on_child():
    rep = scan_path(LINKAGE / "missing", recursive=True)
    hits = _sl401(rep, "sess-c.jsonl")
    assert len(hits) == 1
    _, f = hits[0]
    assert f.severity is Severity.WARNING
    assert f.evidence["resolution"] == "missing"
    assert f.evidence["target"] == "sess-b"
    assert f.evidence["link_kind"] == "session_ref"
    assert f.evidence["candidate_count"] == 0


def test_ambiguous_target_warns():
    rep = scan_path(LINKAGE / "ambiguous", recursive=True)
    hits = _sl401(rep, "sess-c.jsonl")
    assert len(hits) == 1
    _, f = hits[0]
    assert f.severity is Severity.WARNING
    assert f.evidence["resolution"] == "ambiguous"
    assert f.evidence["candidate_count"] == 2


def test_outside_scan_root_is_info_unresolved():
    rep = scan_path(LINKAGE / "outside", recursive=True)
    hits = _sl401(rep, "sess-x.jsonl")
    assert len(hits) == 1
    _, f = hits[0]
    assert f.severity is Severity.INFO
    assert f.evidence["resolution"] == "unresolved"
    # Path-like targets are never echoed verbatim — bounded safe shape only.
    assert f.evidence["target"] != "../elsewhere/sess-q.jsonl"
    assert f.evidence["truncated"] is True


def test_head_ref_resolves_against_tip_only():
    rep = scan_path(LINKAGE / "headref", recursive=True)
    # a2 IS the tip of sess-a -> resolved silently.
    assert _sl401(rep, "sess-h.jsonl") == []
    # a1 exists but is mid-file (not a tip) -> unresolved, never "missing".
    hits = _sl401(rep, "sess-m.jsonl")
    assert len(hits) == 1
    _, f = hits[0]
    assert f.severity is Severity.INFO
    assert f.evidence["resolution"] == "unresolved"
    assert f.evidence["link_kind"] == "head_ref"


def test_check_single_file_never_emits_sl401():
    res = check_file(LINKAGE / "missing" / "sess-c.jsonl")
    assert all(f.code != "SL401" for f in res.findings)


def test_single_file_scan_emits_no_sl401():
    rep = scan_path(LINKAGE / "missing" / "sess-c.jsonl")
    assert _sl401(rep) == []


def test_ignore_gate_suppresses_sl401():
    rep = scan_path(LINKAGE / "missing", recursive=True, ignore=["SL401"])
    assert _sl401(rep) == []


def test_select_gate_suppresses_sl401():
    rep = scan_path(LINKAGE / "missing", recursive=True, select=["SL001", "SL002"])
    assert _sl401(rep) == []


def test_parallel_scan_resolves_links():
    rep = scan_path(LINKAGE / "missing", recursive=True, jobs=4)
    hits = _sl401(rep, "sess-c.jsonl")
    assert len(hits) == 1
    assert hits[0][1].evidence["resolution"] == "missing"


def test_findings_deterministic_order(tmp_path: Path):
    d = tmp_path / "det"
    d.mkdir()
    _write_session(
        d / "sess-z.jsonl",
        "sess-z",
        ["z1", "z2"],
        extra={"parent_session_id": "sess-y", "resume_head_id": "gone-tip"},
    )
    rep1 = scan_path(d, recursive=True)
    rep2 = scan_path(d, recursive=True)
    ev1 = [f.evidence for _, f in _sl401(rep1)]
    ev2 = [f.evidence for _, f in _sl401(rep2)]
    assert ev1 == ev2
    assert [e["link_index"] for e in ev1] == [0, 1]


def test_self_link_is_resolved_not_flagged(tmp_path: Path):
    d = tmp_path / "selflink"
    d.mkdir()
    _write_session(
        d / "sess-s.jsonl", "sess-s", ["s1", "s2"], extra={"parent_session_id": "sess-s"}
    )
    rep = scan_path(d, recursive=True)
    assert _sl401(rep) == []


def test_stem_fallback_resolution(tmp_path: Path):
    """A session_ref naming a filename stem resolves against the scanned set."""
    d = tmp_path / "stemref"
    d.mkdir()
    _write_session(d / "parent-file.jsonl", "opaque-id", ["p1", "p2"])
    _write_session(
        d / "child.jsonl", "child-id", ["c1", "c2"], extra={"parent_session_id": "parent-file"}
    )
    rep = scan_path(d, recursive=True)
    assert _sl401(rep) == []


def test_links_bounded_and_structural():
    """SessionLink wire payloads carry only bounded structural fields."""
    link = SessionLink(kind="session_ref", target="sess-b", record_id="c1", line=1)
    d = link.to_dict()
    assert d == {"kind": "session_ref", "line": 1, "record_id": "c1", "target": "sess-b"}
    back = SessionLink.from_dict(d)
    assert back == link


def test_wire_round_trip_preserves_links(tmp_path: Path):
    d = tmp_path / "wire"
    d.mkdir()
    _write_session(d / "sess-w.jsonl", "sess-w", ["w1"], extra={"parent_session_id": "nowhere"})
    rep = scan_path(d, recursive=True)
    fr = rep.files[0]
    from sesslint.scan import FileResult

    restored = FileResult.from_wire(fr.to_wire())
    assert restored.links == fr.links
    assert restored.session_id == fr.session_id
    assert restored.tip_id == fr.tip_id


def test_codex_forked_from_id_extracted(tmp_path: Path):
    """Codex session_meta forked_from_id surfaces as a session_ref link."""
    d = tmp_path / "codex"
    d.mkdir()
    (d / "rollout-child.jsonl").write_text(
        json.dumps(
            {
                "type": "session_meta",
                "payload": {"id": "thread-child", "forked_from_id": "thread-parent"},
            }
        )
        + "\n"
        + json.dumps(
            {
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": "hi"}],
                },
                "id": "e1",
            }
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    rep = scan_path(d, recursive=True)
    hits = _sl401(rep)
    assert len(hits) == 1
    _, f = hits[0]
    assert f.evidence["link_kind"] == "session_ref"
    assert f.evidence["target"] == "thread-parent"
    assert f.evidence["resolution"] == "missing"


def test_codex_parent_thread_id_resolves_via_meta_id(tmp_path: Path):
    """Codex ``session_meta.id`` is the linkable thread identity — equal to
    the ``rollout-<ts>-<uuid>`` filename suffix and the target of
    ``parent_thread_id`` spawn links. Without it every spawn link
    false-fired ``missing`` (766 findings on a real 799-file corpus)."""
    d = tmp_path / "codex"
    d.mkdir()

    def _write_rollout(name: str, thread_id: str, extra: dict | None = None) -> None:
        payload: dict = {"id": thread_id, "session_id": f"sess-{thread_id}"}
        if extra:
            payload.update(extra)
        (d / name).write_text(
            json.dumps({"type": "session_meta", "payload": payload})
            + "\n"
            + json.dumps(
                {
                    "type": "response_item",
                    "payload": {
                        "type": "message",
                        "role": "user",
                        "content": [{"type": "input_text", "text": "hi"}],
                    },
                    "id": "e1",
                }
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )

    _write_rollout("rollout-2026-01-01T00-00-00-aaaa.jsonl", "thread-parent")
    _write_rollout(
        "rollout-2026-01-01T00-00-01-bbbb.jsonl",
        "thread-child",
        {"parent_thread_id": "thread-parent"},
    )
    rep = scan_path(d, recursive=True)
    assert _sl401(rep) == []


def test_codex_missing_parent_still_fires(tmp_path: Path):
    """A spawn link whose parent rollout is genuinely absent still reports
    ``missing`` — the fix removes false positives, not the check."""
    d = tmp_path / "codex"
    d.mkdir()
    payload = {"id": "thread-child", "session_id": "sess-c", "parent_thread_id": "gone"}
    (d / "rollout-2026-01-01T00-00-02-cccc.jsonl").write_text(
        json.dumps({"type": "session_meta", "payload": payload}) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    rep = scan_path(d, recursive=True)
    hits = _sl401(rep)
    assert len(hits) == 1
    assert hits[0][1].evidence["resolution"] == "missing"


def test_codex_first_session_meta_wins_session_id(tmp_path: Path):
    """A second ``session_meta`` record (inherited parent context on real
    subagent rollouts) must not overwrite the file's own thread identity —
    last-write-wins misindexed 36 files under 6 shared ids on the corpus."""
    d = tmp_path / "codex"
    d.mkdir()

    def _write(name: str, meta_ids: list[str], extra: dict | None = None) -> None:
        lines = []
        for i, tid in enumerate(meta_ids):
            pay: dict = {"id": tid, "session_id": f"sess-{tid}"}
            if i == 0 and extra:
                pay.update(extra)
            lines.append(json.dumps({"type": "session_meta", "payload": pay}))
        (d / name).write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")

    _write("rollout-2026-01-01T00-00-00-aaaa.jsonl", ["thread-parent"])
    # Child carries its own meta first, then the parent's inherited meta —
    # the second must not reindex the file under the parent id.
    _write(
        "rollout-2026-01-01T00-00-01-bbbb.jsonl",
        ["thread-child", "thread-parent"],
        {"parent_thread_id": "thread-parent"},
    )
    rep = scan_path(d, recursive=True)
    assert _sl401(rep) == []
    by_path = {Path(fr.path).name: fr for fr in rep.files}
    child = by_path["rollout-2026-01-01T00-00-01-bbbb.jsonl"]
    assert child.session_id == "thread-child"


def test_codex_link_resolves_via_filename_uuid(tmp_path: Path):
    """A child links to a parent whose ``session_meta`` is torn (no usable
    ``id``): the ``rollout-<ts>-<uuid>`` filename still proves the target —
    resilience independent of session header health."""
    d = tmp_path / "codex"
    d.mkdir()
    # Parent rollout with a corrupt session_meta (no id anywhere).
    (d / "rollout-2026-01-01T00-00-00-019f8b5a-7c3e-4d2f-9a1b-000000000001.jsonl").write_text(
        json.dumps({"type": "session_meta", "payload": {"cwd": "/x"}}) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (d / "rollout-2026-01-01T00-00-01-bbbb.jsonl").write_text(
        json.dumps(
            {
                "type": "session_meta",
                "payload": {
                    "id": "thread-child",
                    "parent_thread_id": "019f8b5a-7c3e-4d2f-9a1b-000000000001",
                },
            }
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    rep = scan_path(d, recursive=True)
    assert _sl401(rep) == []


def test_scan_report_dict_shape_unchanged():
    """Linkage metadata stays internal — report dict has no new top-level keys."""
    rep = scan_path(LINKAGE / "missing", recursive=True)
    for fr in rep.files:
        d = fr.to_dict()
        assert "links" not in d
        assert "session_id" not in d
        assert "tip_id" not in d


def test_missing_fixture_targets_record_coordinates():
    rep = scan_path(LINKAGE / "missing", recursive=True)
    _, f = _sl401(rep, "sess-c.jsonl")[0]
    assert f.source.record_id == "c1"
    assert f.source.line == 1
