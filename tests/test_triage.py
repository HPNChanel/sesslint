"""TRIAGE-001/002: observable guidance, snapshot binding and privacy boundaries."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from sesslint import api
from sesslint.cli import main
from sesslint.discovery import latest_session
from sesslint.triage import TriageReport, triage

ROOT = Path(__file__).resolve().parents[1]
BASE = (ROOT / "fixtures/claude_code/basic.jsonl").read_bytes()
SCHEMA = json.loads((ROOT / "schemas/sesslint.triage.v1.json").read_text())


def session(tmp_path: Path, data: bytes = BASE) -> Path:
    target = tmp_path / "private-session-name.jsonl"
    target.write_bytes(data)
    return target


def canonical(tmp_path: Path, events: list[dict[str, Any]]) -> Path:
    header = {
        "schema_version": "sesslint.session/v1",
        "session_id": "private-id-canary",
        "created_at": "2026-10-08T00:00:00Z",
    }
    return session(
        tmp_path, ("\n".join(json.dumps(row) for row in [header, *events]) + "\n").encode()
    )


def event(eid: str, parent: str | None, seq: int, **extra: Any) -> dict[str, Any]:
    return {
        "id": eid,
        "parent_id": parent,
        "seq": seq,
        "ts": f"2026-10-08T00:00:{seq:02d}Z",
        "actor": "user",
        "kind": "message",
        "payload": {"text": "PRIVATE-PAYLOAD-CANARY"},
        **extra,
    }


def validate(report: TriageReport) -> None:
    jsonschema.Draft202012Validator(SCHEMA).validate(report.to_dict())
    assert len(report.next_actions) <= 3
    assert all(not preview["applied"] for preview in report.previews)


def test_healthy_pure_and_api_parity(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = session(tmp_path)
    before = source.stat()
    report = api.triage(source)
    validate(report)
    assert report.status == "checked"
    assert report.exit_code == 0
    assert report.source_sha256 == hashlib.sha256(BASE).hexdigest()
    assert report.to_json() == triage(source).to_json()
    assert source.read_bytes() == BASE
    assert source.stat().st_mtime_ns == before.st_mtime_ns
    assert list(tmp_path.iterdir()) == [source]
    assert capsys.readouterr() == ("", "")
    assert "TriageReport" in api.__all__ and isinstance(report, api.TriageReport)


@pytest.mark.parametrize(
    "data,status",
    [
        (b"opaque unsupported artifact\n", "unsupported"),
        (b"", "blocked"),
        (b"\x00\xff", "blocked"),
        (BASE + b'{"id":"torn', "needs-attention"),
        (BASE + b'{"broken":}\n' + BASE, "needs-attention"),
    ],
)
def test_states_are_not_silently_healthy(tmp_path: Path, data: bytes, status: str) -> None:
    report = triage(session(tmp_path, data))
    validate(report)
    assert report.status == status
    assert report.exit_code == 1


def test_limit_and_unreadable_are_distinct(tmp_path: Path) -> None:
    limited = triage(session(tmp_path), max_file_bytes=1)
    validate(limited)
    assert (limited.status, limited.source_sha256, limited.previews) == ("skipped", None, ())
    for path in (tmp_path / "missing", tmp_path):
        report = triage(path)
        validate(report)
        assert report.status == "unreadable" and report.exit_code == 2


@pytest.mark.parametrize(
    "reason,status", [("cap-exceeded", "skipped"), ("version-gated", "unsupported")]
)
def test_incomplete_coverage_never_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reason: str, status: str
) -> None:
    import sesslint.triage as triage_module
    from sesslint.assessment import assess_source
    from sesslint.report import CoverageSkip

    source = session(tmp_path)
    assessment = assess_source(source)
    coverage = replace(
        assessment.report.coverage,
        skipped=(*assessment.report.coverage.skipped, CoverageSkip("graph", reason)),
    )
    assessment = replace(assessment, report=replace(assessment.report, coverage=coverage))
    monkeypatch.setattr(triage_module, "assess_source", lambda *a, **kw: assessment)
    report = triage(source)
    validate(report)
    assert report.status == status and report.assurance == "A0"
    assert report.previews == ()
    assert "coverage" in {item["code"] for item in report.missing_evidence}


def test_torn_preview_same_snapshot_and_explicit_comparison(tmp_path: Path) -> None:
    source = session(tmp_path, BASE + b'{"id":"torn')
    report = triage(source, policy="salvage")
    validate(report)
    assert [p["policy"] for p in report.previews] == ["conservative", "salvage"]
    assert all(p["source_sha256"] == report.source_sha256 for p in report.previews)
    assert report.previews[0]["step_count"] > 0
    assert len(triage(source).previews) == 1


def test_only_one_decode_and_no_preview_reopen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sesslint.adapters import load

    source = session(tmp_path)
    original = load.load_events_for_format
    count = 0

    def capture(*args: Any, **kwargs: Any) -> Any:
        nonlocal count
        count += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(load, "load_events_for_format", capture)
    triage(source, policy="salvage")
    assert count == 1


@pytest.mark.parametrize("restore_metadata", [False, True])
def test_source_changed_after_load_withholds_preview(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, restore_metadata: bool
) -> None:
    from sesslint.adapters import load

    source = session(tmp_path)
    previous = source.stat()
    original = load.load_events_for_format

    def race(*args: Any, **kwargs: Any) -> Any:
        result = original(*args, **kwargs)
        changed = BASE.replace(b"Please", b"Change")
        assert changed != BASE and len(changed) == len(BASE)
        source.write_bytes(changed)
        if restore_metadata:
            os.utime(source, ns=(previous.st_atime_ns, previous.st_mtime_ns))
        return result

    monkeypatch.setattr(load, "load_events_for_format", race)
    report = triage(source)
    validate(report)
    assert report.status == "unstable"
    assert report.previews == () and report.assurance == "A0"


def test_graph_impact_and_private_output(tmp_path: Path) -> None:
    source = canonical(
        tmp_path,
        [
            event("secret-e0", None, 0),
            event("secret-e1", "absent-parent", 1),
            event("secret-e2", "secret-e1", 2),
        ],
    )
    report = triage(source)
    validate(report)
    assert "SL004" in report.by_code
    assert report.impact["affected_events"] >= 2
    assert report.impact["outside_mapped_impact"] <= 1
    for output in (report.to_json(), report.render_human()):
        for secret in (
            "PRIVATE-PAYLOAD-CANARY",
            "secret-e",
            "private-id-canary",
            str(tmp_path),
            source.name,
        ):
            assert secret not in output
    assert "safe to replay" in report.impact["limitation"]


@pytest.mark.parametrize("checkpoint_loss", [False, True])
def test_unknown_side_effects_do_not_offer_execution(tmp_path: Path, checkpoint_loss: bool) -> None:
    source = canonical(
        tmp_path,
        [
            event(
                "root",
                None,
                0,
                kind="compaction_boundary" if checkpoint_loss else "message",
            ),
            event(
                "call",
                "root",
                1,
                actor="assistant",
                kind="tool_call",
                correlation_id="call",
                payload={"tool_name": "shell", "arguments": {}},
                execution_state="unknown",
                side_effects="unknown",
            ),
        ],
    )
    report = triage(source, policy="salvage")
    validate(report)
    assert "SL102" in report.by_code
    if checkpoint_loss:
        assert "SL203" in report.by_code
        assert report.status == "blocked"
    else:
        assert report.status == "needs-attention"
    assert not any(p["step_count"] for p in report.previews)
    assert report.next_actions[0]["id"] == "verify-external-state"


@pytest.mark.parametrize("agent", ["codex", "claude"])
def test_latest_excludes_auxiliary_and_subagents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, agent: str
) -> None:
    root = tmp_path / agent
    monkeypatch.setenv("CODEX_HOME" if agent == "codex" else "CLAUDE_CONFIG_DIR", str(root))
    parent = root / ("sessions/2026/10/08" if agent == "codex" else "projects/project")
    parent.mkdir(parents=True)
    filename = "rollout-a.jsonl" if agent == "codex" else "primary.jsonl"
    chosen = parent / filename
    chosen.write_bytes(BASE)
    (parent / "memory.json").write_text("{}")
    subagent = parent / "primary/subagents"
    subagent.mkdir(parents=True)
    (subagent / "agent-child.jsonl").write_bytes(BASE)
    assert latest_session(agent) == chosen
    assert main(["triage", "--agent", agent, "--latest", "--json"]) == 0


def registry(tmp_path: Path, identity: str) -> tuple[Path, Path]:
    source = tmp_path / f"rollout-2026-10-08-{identity}.jsonl"
    source.write_bytes((ROOT / "fixtures/adapters/metadata/codex_retained.jsonl").read_bytes())
    database = tmp_path / "closed-copy.sqlite"
    with sqlite3.connect(database) as con:
        con.execute("CREATE TABLE threads (id TEXT, rollout_path TEXT)")
        con.execute("INSERT INTO threads VALUES (?, ?)", (identity, source.name))
    return source, database


def test_registry_copy_membership_no_writes(tmp_path: Path) -> None:
    source, database = registry(tmp_path, "11111111-1111-4111-8111-111111111111")
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    report = triage(source, state_copy=database)
    validate(report)
    assert report.native_state["status"] == "membership-matches"
    assert before == {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    Path(str(database) + "-wal").write_bytes(b"not-a-consistent-copy")
    assert triage(source, state_copy=database).native_state["status"] == "unverified"


def test_live_registry_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, database = registry(tmp_path, "11111111-1111-4111-8111-111111111111")
    monkeypatch.setenv("CODEX_HOME", str(tmp_path))
    assert triage(source, state_copy=database).native_state["status"] == "unverified"


def test_crosswired_registry_rows_do_not_match(tmp_path: Path) -> None:
    first = "11111111-1111-4111-8111-111111111111"
    second = "22222222-2222-4222-8222-222222222222"
    source, database = registry(tmp_path, first)
    with sqlite3.connect(database) as con:
        con.execute("UPDATE threads SET rollout_path = ?", (f"rollout-{second}.jsonl",))
        con.execute("INSERT INTO threads VALUES (?, ?)", (second, source.name))
    report = triage(source, state_copy=database)
    assert report.native_state["status"] == "membership-mismatch"
    assert report.status != "checked"


def test_registry_hard_link_is_not_a_closed_copy(tmp_path: Path) -> None:
    source, database = registry(tmp_path, "11111111-1111-4111-8111-111111111111")
    alias = tmp_path / "alias.sqlite"
    os.link(database, alias)
    assert triage(source, state_copy=alias).native_state["status"] == "unverified"


def test_registry_query_work_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sesslint import state_db

    _, database = registry(tmp_path, "11111111-1111-4111-8111-111111111111")
    with sqlite3.connect(database) as con:
        con.execute("DROP TABLE threads")
        con.execute(
            "CREATE VIEW threads AS WITH RECURSIVE ids(x) AS "
            "(SELECT 1 UNION ALL SELECT x + 1 FROM ids WHERE x < 100000) "
            "SELECT CAST(sum(x) AS TEXT) AS id, '' AS rollout_path FROM ids"
        )
    monkeypatch.setattr(state_db, "MAX_STATE_QUERY_STEPS", 1000)
    snapshot = state_db.read_codex_state(database, immutable=True)
    assert not snapshot.membership_complete and snapshot.schema_note == "query-limit"


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
@pytest.mark.parametrize("during_read", [False, True])
def test_incomplete_registry_copy_never_verified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, suffix: str, during_read: bool
) -> None:
    from sesslint import state_db

    source, database = registry(tmp_path, "11111111-1111-4111-8111-111111111111")
    sidecar = Path(str(database) + suffix)
    original = state_db.read_codex_state
    if during_read:

        def race(*args: Any, **kwargs: Any) -> Any:
            result = original(*args, **kwargs)
            sidecar.write_bytes(b"incomplete synthetic copy")
            return result

        monkeypatch.setattr(state_db, "read_codex_state", race)
    else:
        sidecar.write_bytes(b"incomplete synthetic copy")
    report = triage(source, state_copy=database)
    assert report.native_state["status"] == "unverified"
    assert report.status != "checked"


@pytest.mark.parametrize("table", ["thread_spawn_edges", "rollout_migration_skipped_rollouts"])
def test_registry_auxiliary_tables_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, table: str
) -> None:
    from sesslint import state_db

    _, database = registry(tmp_path, "11111111-1111-4111-8111-111111111111")
    with sqlite3.connect(database) as con:
        if table == "thread_spawn_edges":
            con.execute(
                "CREATE TABLE thread_spawn_edges (parent_thread_id TEXT, child_thread_id TEXT)"
            )
            con.executemany("INSERT INTO thread_spawn_edges VALUES (?, ?)", [("a", "b")] * 2)
        else:
            con.execute("CREATE TABLE rollout_migration_skipped_rollouts (skip_reason TEXT)")
            con.executemany(
                "INSERT INTO rollout_migration_skipped_rollouts VALUES (?)", [("x",)] * 2
            )
    monkeypatch.setattr(state_db, "MAX_STATE_ROWS", 1)
    snapshot = state_db.read_codex_state(database, immutable=True)
    assert not snapshot.membership_complete and snapshot.schema_note == "oversized"


@pytest.mark.parametrize(
    "argv",
    [
        ["triage"],
        ["triage", "--latest"],
        ["triage", "--agent", "codex"],
        ["triage", "file", "--latest", "--agent", "codex"],
        ["triage", "file", "--include-content"],
    ],
)
def test_cli_usage_refused(argv: list[str]) -> None:
    assert main(argv) == 2


def test_cli_json_parity(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = session(tmp_path)
    assert main(["triage", str(source), "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == triage(source).to_dict()
