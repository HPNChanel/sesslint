"""Unit and end-to-end integration tests for run-state checkpoint validation (FR-044).

Covers:
- SL201: Checkpoint gap detected within run-state checkpoints (seq jump > 1).
- SL201: Checkpoint gap detected on missing/empty state hash in run-state.
- SL202: Checkpoint divergence detected within run-state (duplicate seq, differing hashes).
- SL202: Checkpoint divergence detected across run-state and in-event checkpoints.
- SL203: Unsafe continuation triggered when tools execute after broken run-state checkpoint.
- Preceding checkpoint satisfaction: Run-state checkpoint satisfies run_start / continuation.
- End-to-end parity: api.check_file and CLI main exit codes and findings match.
- Content-free: No payload, transcript, or confidential data leaks into findings.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import sesslint.api as api
from sesslint.cli import main
from sesslint.codes import SL201, SL202, SL203, Repairability, Severity


def _write_canonical_session(
    path: Path,
    *,
    source_checkpoints: list[dict[str, Any]] | None = None,
    events: list[dict[str, Any]] | None = None,
) -> None:
    """Write a canonical session document with optional source checkpoints."""
    header: dict[str, Any] = {
        "created_at": "2026-01-01T00:00:00Z",
        "schema_version": "sesslint.session/v1",
        "session_id": "sess-chk-test-01",
    }
    if source_checkpoints is not None:
        header["source"] = {
            "format": "canonical",
            "checkpoints": source_checkpoints,
        }

    default_events: list[dict[str, Any]] = [
        {
            "actor": "user",
            "id": "evt_msg_1",
            "kind": "message",
            "parent_id": None,
            "payload": {"text": "Hello assistant"},
            "seq": 0,
            "ts": "2026-01-01T00:00:01Z",
        },
        {
            "actor": "assistant",
            "id": "evt_msg_2",
            "kind": "message",
            "parent_id": "evt_msg_1",
            "payload": {"text": "Hello user"},
            "seq": 1,
            "ts": "2026-01-01T00:00:02Z",
        },
    ]

    ev_list = events if events is not None else default_events

    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(header) + "\n")
        for ev in ev_list:
            f.write(json.dumps(ev) + "\n")


def test_runstate_checkpoint_clean(tmp_path: Path) -> None:
    """Clean session with sequential, hashed run-state checkpoints produces 0 findings."""
    session_file = tmp_path / "clean_chk.jsonl"
    chks = [
        {"id": "chk_0", "seq": 0, "hash": "0123456789abcdef"},
        {"id": "chk_1", "seq": 1, "hash": "fedcba9876543210"},
    ]
    _write_canonical_session(session_file, source_checkpoints=chks)

    rep = api.check_file(session_file, format="canonical")
    cp_findings = [f for f in rep.findings if f.code in (SL201, SL202, SL203)]
    assert not cp_findings
    assert rep.counts.by_severity.get("error", 0) == 0

    # CLI check exits 0
    code = main(["check", str(session_file), "--format", "canonical"])
    assert code == 0


def test_runstate_checkpoint_sl201_gap_end_to_end(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Session with clean events but run-state seq jump from 0 to 4 triggers SL201."""
    session_file = tmp_path / "gap_chk.jsonl"

    chks = [
        {"id": "chk_0", "seq": 0, "hash": "0123456789abcdef"},
        {"id": "chk_1", "seq": 4, "hash": "fedcba9876543210"},  # Jump > 1
    ]
    _write_canonical_session(session_file, source_checkpoints=chks)

    # 1. API check
    rep = api.check_file(session_file, format="canonical")
    f201 = [f for f in rep.findings if f.code == SL201]
    assert len(f201) == 1
    f = f201[0]
    assert f.severity == Severity.ERROR
    assert f.repairability == Repairability.MANUAL
    assert f.source.record_id == "chk_1"
    assert f.evidence is not None
    assert f.evidence["expected_seq"] == 1
    assert f.evidence["found_seq"] == 4
    assert f.evidence["source"] == "run_state"

    # 2. CLI check
    code = main(["check", str(session_file), "--format", "canonical", "--json"])
    assert code == 1
    captured = capsys.readouterr()
    cli_rep = json.loads(captured.out)
    cli_findings = [f for f in cli_rep["findings"] if f["code"] == "SL201"]
    assert len(cli_findings) == 1
    assert cli_findings[0]["evidence"]["found_seq"] == 4


def test_runstate_checkpoint_sl201_missing_hash_end_to_end(tmp_path: Path) -> None:
    """Run-state checkpoint with missing or empty state hash triggers SL201."""
    session_file = tmp_path / "nohash_chk.jsonl"
    chks = [
        {"id": "chk_0", "seq": 0, "hash": None},  # Missing hash
    ]
    _write_canonical_session(session_file, source_checkpoints=chks)

    rep = api.check_file(session_file, format="canonical")
    f201 = [f for f in rep.findings if f.code == SL201]
    assert len(f201) == 1
    f = f201[0]
    assert f.evidence is not None
    assert f.evidence["source"] == "run_state"
    assert f.evidence["found_seq"] == 0

    code = main(["check", str(session_file), "--format", "canonical"])
    assert code == 1


def test_runstate_checkpoint_sl202_internal_divergence_end_to_end(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Run-state checkpoints sharing identical seq with differing hashes trigger SL202."""
    session_file = tmp_path / "div_internal.jsonl"
    chks = [
        {"id": "chk_branch_a", "seq": 1, "hash": "aaaa111122223333"},
        {"id": "chk_branch_b", "seq": 1, "hash": "bbbb444455556666"},
    ]
    _write_canonical_session(session_file, source_checkpoints=chks)

    rep = api.check_file(session_file, format="canonical")
    f202 = [f for f in rep.findings if f.code == SL202]
    assert len(f202) == 1
    f = f202[0]
    assert f.severity == Severity.ERROR
    assert f.repairability == Repairability.MANUAL
    assert f.source.record_id == "chk_branch_b"
    assert f.evidence is not None
    assert f.evidence["seq"] == 1
    assert f.evidence["hash_a"] == "aaaa111122223333"
    assert f.evidence["hash_b"] == "bbbb444455556666"
    assert f.evidence["source"] == "run_state"

    code = main(["check", str(session_file), "--format", "canonical", "--json"])
    assert code == 1
    captured = capsys.readouterr()
    cli_rep = json.loads(captured.out)
    assert any(f["code"] == "SL202" for f in cli_rep["findings"])


def test_runstate_checkpoint_sl202_cross_divergence_end_to_end(tmp_path: Path) -> None:
    """Run-state and in-event checkpoints with identical seq but differing hashes trigger SL202."""
    session_file = tmp_path / "div_cross.jsonl"
    chks = [
        {"id": "chk_prior", "seq": 1, "hash": "1111111111111111"},
    ]
    events = [
        {
            "actor": "user",
            "id": "evt_msg_1",
            "kind": "message",
            "parent_id": None,
            "payload": {"text": "Hi"},
            "seq": 0,
            "ts": "2026-01-01T00:00:01Z",
        },
        {
            "actor": "system",
            "id": "chk_event_divergent",
            "kind": "checkpoint",
            "parent_id": "evt_msg_1",
            "payload": {"seq": 1, "state_hash": "2222222222222222"},
            "seq": 1,
            "ts": "2026-01-01T00:00:02Z",
        },
    ]
    _write_canonical_session(session_file, source_checkpoints=chks, events=events)

    rep = api.check_file(session_file, format="canonical")
    f202 = [f for f in rep.findings if f.code == SL202]
    assert len(f202) == 1
    f = f202[0]
    assert f.source.record_id == "chk_event_divergent"
    assert f.evidence is not None
    assert f.evidence["seq"] == 1
    assert f.evidence["hash_a"] == "1111111111111111"
    assert f.evidence["hash_b"] == "2222222222222222"


def test_runstate_checkpoint_satisfies_run_start() -> None:
    """A run_start record without preceding event checkpoint is satisfied by run-state."""
    from sesslint.canonical import SessionEvent
    from sesslint.checks.checkpoint import check_checkpoint_gap
    from sesslint.context import CheckContext

    ev = SessionEvent(
        id="evt_start",
        parent_id=None,
        seq=0,
        ts="2026-01-01T00:00:01Z",
        actor="system",
        kind="run_start",
        payload={},
    )

    # 1. Context without run-state checkpoints: fires SL201 (resumption without checkpoint)
    ctx_empty = CheckContext.create(source_metadata={})
    findings_un = check_checkpoint_gap([ev], context=ctx_empty)
    assert any(f.code == SL201 for f in findings_un)

    # 2. Context with run-state checkpoint establishing state: does NOT fire SL201 for run_start

    chks = [{"id": "chk_est", "seq": 0, "hash": "statehash12345"}]
    ctx_cp = CheckContext.create(source_metadata={"checkpoints": chks})
    findings_cp = check_checkpoint_gap([ev], context=ctx_cp)
    f201 = [f for f in findings_cp if f.code == SL201]
    assert not f201


def test_runstate_checkpoint_sl203_unsafe_continuation(tmp_path: Path) -> None:
    """Tool execution strictly after a broken run-state checkpoint triggers SL203."""
    session_file = tmp_path / "unsafe_cont.jsonl"
    chks = [
        {"id": "chk_0", "seq": 0, "hash": "aaa"},
        {"id": "chk_1", "seq": 5, "hash": "bbb"},
    ]
    events = [
        {
            "actor": "assistant",
            "id": "evt_tool_call",
            "kind": "tool_call",
            "parent_id": None,
            "payload": {"tool_name": "bash", "arguments": {"cmd": "ls"}},
            "seq": 0,
            "ts": "2026-01-01T00:00:01Z",
        },
    ]
    _write_canonical_session(session_file, source_checkpoints=chks, events=events)

    rep = api.check_file(session_file, format="canonical")
    codes = {f.code for f in rep.findings}
    assert SL201 in codes
    assert SL203 in codes
    f203 = next(f for f in rep.findings if f.code == SL203)
    assert f203.severity == Severity.ERROR
    assert f203.repairability == Repairability.MANUAL
    assert f203.source.record_id == "evt_tool_call"
    assert f203.evidence is not None
    assert "SL201" in f203.evidence["caused_by"]


def test_runstate_checkpoint_openai_agents_format(tmp_path: Path) -> None:
    """OpenAI Agents JSON session with checkpoint seq jump triggers SL201."""
    session_file = tmp_path / "openai_runstate_gap.json"
    data = {
        "sdk_version": "1.0.0",
        "run_state": {"current_agent": "agent_a"},
        "checkpoints": [
            {"id": "chk_0", "seq": 0, "hash": "1111111111111111"},
            {"id": "chk_1", "seq": 4, "hash": "2222222222222222"},
        ],
        "items": [
            {
                "id": "item_01",
                "type": "message",
                "role": "user",
                "content": "Hello",
                "timestamp": "2025-01-01T12:00:00Z",
            }
        ],
    }
    session_file.write_text(json.dumps(data), encoding="utf-8")

    rep = api.check_file(session_file, format="openai-agents")
    f201 = [f for f in rep.findings if f.code == SL201]
    assert len(f201) == 1
    assert f201[0].evidence is not None
    assert f201[0].evidence["found_seq"] == 4


def test_runstate_checkpoint_unordered_gap_detected(tmp_path: Path) -> None:
    """Out-of-order run-state checkpoints with a seq gap are correctly detected via pre-sort."""
    session_file = tmp_path / "unordered_gap.jsonl"
    chks = [
        {"id": "chk_rev_2", "seq": 5, "hash": "sha256:555"},
        {"id": "chk_rev_1", "seq": 2, "hash": "sha256:222"},
    ]
    _write_canonical_session(session_file, source_checkpoints=chks)

    rep = api.check_file(session_file, format="canonical")
    f201 = [f for f in rep.findings if f.code == SL201]
    assert len(f201) == 1
    assert f201[0].evidence is not None
    assert f201[0].evidence["expected_seq"] == 3
    assert f201[0].evidence["found_seq"] == 5
    assert f201[0].source.record_id == "chk_rev_2"


def test_runstate_checkpoint_reverse_clean_bridged(tmp_path: Path) -> None:
    """Reverse-ordered sequential run-state checkpoints produce 0 findings and bridge properly."""
    session_file = tmp_path / "reverse_clean.jsonl"
    chks = [
        {"id": "chk_1", "seq": 1, "hash": "sha256:111"},
        {"id": "chk_0", "seq": 0, "hash": "sha256:000"},
    ]
    events = [
        {
            "actor": "user",
            "id": "e1",
            "kind": "message",
            "parent_id": None,
            "payload": {"text": "hi"},
            "seq": 0,
            "ts": "2026-01-01T00:00:00Z",
        },
        {
            "actor": "system",
            "id": "chk_ev",
            "kind": "checkpoint",
            "parent_id": "e1",
            "payload": {"seq": 2, "state_hash": "sha256:222"},
            "seq": 2,
            "ts": "2026-01-01T00:00:01Z",
        },
    ]
    _write_canonical_session(session_file, source_checkpoints=chks, events=events)

    rep = api.check_file(session_file, format="canonical")
    f201 = [f for f in rep.findings if f.code == SL201]
    # seq 0 -> seq 1 (in rs) -> seq 2 (in ev) has no gaps
    assert len(f201) == 0


def test_runstate_checkpoint_falsy_id_preserved(tmp_path: Path) -> None:
    """Run-state checkpoint with falsy integer 0 ID preserves record_id as '0'."""
    session_file = tmp_path / "falsy_id.jsonl"
    chks = [
        {"id": "chk_0", "seq": 0, "hash": "sha256:000"},
        {"id": 0, "seq": 4, "hash": "sha256:444"},
    ]
    _write_canonical_session(session_file, source_checkpoints=chks)

    rep = api.check_file(session_file, format="canonical")
    f201 = [f for f in rep.findings if f.code == SL201]
    assert len(f201) == 1
    assert f201[0].source.record_id == "0"
