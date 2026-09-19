"""Tests for `sesslint diff` structural comparator (ux-reporting T-02)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.cli import main
from sesslint.diff import (
    DIFF_SCHEMA_VERSION,
    DiffInputError,
    diff_events,
    diff_sessions,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "cli"


def _claude_records(n: int) -> list[dict[str, object]]:
    recs: list[dict[str, object]] = []
    for i in range(1, n + 1):
        rec: dict[str, object] = {
            "id": f"m{i}",
            "type": "user_message" if i % 2 else "assistant_message",
            "message": f"text {i}",
            "timestamp": f"2025-01-01T12:00:{i:02d}Z",
        }
        if i > 1:
            rec["parentId"] = f"m{i - 1}"
        recs.append(rec)
    return recs


def _write_jsonl(path: Path, recs: list[dict[str, object]]) -> Path:
    path.write_text("".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")
    return path


def test_diff_identical_exit_0(tmp_path: Path) -> None:
    a = _write_jsonl(tmp_path / "a.jsonl", _claude_records(4))
    b = _write_jsonl(tmp_path / "b.jsonl", _claude_records(4))
    assert main(["diff", str(a), str(b), "--format", "claude-code-jsonl"]) == 0


def test_diff_self_exit_0() -> None:
    fixture = FIXTURES_DIR / "check_basic" / "healthy.jsonl"
    assert main(["diff", str(fixture), str(fixture)]) == 0


def test_diff_removed_event(tmp_path: Path) -> None:
    a = _write_jsonl(tmp_path / "a.jsonl", _claude_records(5))
    b = _write_jsonl(tmp_path / "b.jsonl", _claude_records(4))
    result = diff_sessions(a, b, format_a="claude-code-jsonl", format_b="claude-code-jsonl")
    assert not result.identical
    cats = [d.category for d in result.deltas]
    assert "removed" in cats
    removed = [d for d in result.deltas if d.category == "removed"]
    assert removed[0].event_id == "m5"
    assert removed[0].a_index == 4


def test_diff_added_event(tmp_path: Path) -> None:
    a = _write_jsonl(tmp_path / "a.jsonl", _claude_records(3))
    b = _write_jsonl(tmp_path / "b.jsonl", _claude_records(4))
    result = diff_sessions(a, b, format_a="claude-code-jsonl", format_b="claude-code-jsonl")
    added = [d for d in result.deltas if d.category == "added"]
    assert len(added) == 1
    assert added[0].event_id == "m4"
    assert added[0].b_index == 3


def test_diff_kind_changed() -> None:
    """kind-changed compares canonical kinds (adapter-normalized)."""
    from sesslint.canonical import SessionEvent

    def _ev(i: int, kind: str) -> SessionEvent:
        return SessionEvent(
            id=f"e{i}",
            parent_id=f"e{i - 1}" if i > 1 else None,
            seq=i,
            ts=f"2025-01-01T00:00:{i:02d}Z",
            actor="user",
            kind=kind,  # type: ignore[arg-type]
        )

    deltas = diff_events(
        [_ev(1, "message"), _ev(2, "message")],
        [_ev(1, "message"), _ev(2, "checkpoint")],
    )
    kinds = [d for d in deltas if d.category == "kind-changed"]
    assert len(kinds) == 1
    assert kinds[0].event_id == "e2"
    assert kinds[0].detail["kind_a"] == "message"
    assert kinds[0].detail["kind_b"] == "checkpoint"


def test_diff_parent_relinked(tmp_path: Path) -> None:
    recs_a = _claude_records(4)
    recs_b = [dict(r) for r in recs_a]
    recs_b[3]["parentId"] = "m1"
    a = _write_jsonl(tmp_path / "a.jsonl", recs_a)
    b = _write_jsonl(tmp_path / "b.jsonl", recs_b)
    result = diff_sessions(a, b, format_a="claude-code-jsonl", format_b="claude-code-jsonl")
    relinks = [d for d in result.deltas if d.category == "parent-relinked"]
    assert len(relinks) == 1
    assert relinks[0].event_id == "m4"
    assert relinks[0].detail["parent_a"] == "m3"
    assert relinks[0].detail["parent_b"] == "m1"


def test_diff_seq_reordered(tmp_path: Path) -> None:
    recs_a = _claude_records(4)
    recs_b = [recs_a[0], recs_a[2], recs_a[1], recs_a[3]]  # swap m2/m3
    a = _write_jsonl(tmp_path / "a.jsonl", recs_a)
    b = _write_jsonl(tmp_path / "b.jsonl", recs_b)
    result = diff_sessions(a, b, format_a="claude-code-jsonl", format_b="claude-code-jsonl")
    reorders = [d for d in result.deltas if d.category == "seq-reordered"]
    assert len(reorders) == 1
    # The pair whose B position regresses below the running max is flagged:
    # m3 moved ahead of m2 (B index 1 < m2's B index 2).
    assert reorders[0].event_id == "m3"
    assert reorders[0].b_index == 1


def test_diff_content_changed(tmp_path: Path) -> None:
    recs_a = _claude_records(3)
    recs_b = [dict(r) for r in recs_a]
    recs_b[0]["message"] = "mutated text"
    a = _write_jsonl(tmp_path / "a.jsonl", recs_a)
    b = _write_jsonl(tmp_path / "b.jsonl", recs_b)
    result = diff_sessions(a, b, format_a="claude-code-jsonl", format_b="claude-code-jsonl")
    changed = [d for d in result.deltas if d.category == "content-changed"]
    assert len(changed) == 1
    assert changed[0].event_id == "m1"
    # Hash-only detail — never the payload text.
    assert "mutated text" not in json.dumps(result.to_dict())


def test_diff_json_output_schema(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    a = _write_jsonl(tmp_path / "a.jsonl", _claude_records(3))
    b = _write_jsonl(tmp_path / "b.jsonl", _claude_records(4))
    rc = main(["diff", str(a), str(b), "--format", "claude-code-jsonl", "--json"])
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["schema_version"] == DIFF_SCHEMA_VERSION
    assert out["identical"] is False
    assert out["counts"]["added"] == 1
    assert out["a"]["event_count"] == 3
    assert out["b"]["event_count"] == 4
    assert isinstance(out["deltas"], list)
    for delta in out["deltas"]:
        assert delta["category"] in (
            "added",
            "removed",
            "kind-changed",
            "parent-relinked",
            "seq-reordered",
            "content-changed",
        )


def test_diff_json_validates_against_schema(tmp_path: Path) -> None:
    from sesslint.diff import load_diff_schema

    a = _write_jsonl(tmp_path / "a.jsonl", _claude_records(3))
    b = _write_jsonl(tmp_path / "b.jsonl", _claude_records(3))
    result = diff_sessions(a, b, format_a="claude-code-jsonl", format_b="claude-code-jsonl")
    data = result.to_dict()
    schema = load_diff_schema()
    # Hand-rolled strict validation against the committed schema.
    assert data["schema_version"] == schema["properties"]["schema_version"]["const"]
    for key in schema["required"]:
        assert key in data
    for side in ("a", "b"):
        for req in schema["$defs"]["side"]["required"]:
            assert req in data[side]
    for delta in data["deltas"]:
        assert (
            delta["category"]
            in schema["properties"]["deltas"]["items"]["properties"]["category"]["enum"]
        )


def test_diff_deterministic(tmp_path: Path) -> None:
    recs_a = _claude_records(5)
    recs_b = [recs_a[0], recs_a[2], recs_a[4]]
    a = _write_jsonl(tmp_path / "a.jsonl", recs_a)
    b = _write_jsonl(tmp_path / "b.jsonl", recs_b)
    r1 = diff_sessions(a, b, format_a="claude-code-jsonl", format_b="claude-code-jsonl")
    r2 = diff_sessions(a, b, format_a="claude-code-jsonl", format_b="claude-code-jsonl")
    assert r1.to_json() == r2.to_json()


def test_diff_missing_path_exit_2(tmp_path: Path) -> None:
    a = _write_jsonl(tmp_path / "a.jsonl", _claude_records(2))
    assert main(["diff", str(a), str(tmp_path / "nope.jsonl")]) == 2


def test_diff_undetectable_exit_2(tmp_path: Path) -> None:
    a = _write_jsonl(tmp_path / "a.jsonl", _claude_records(2))
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"totally": "unknown"}\n', encoding="utf-8")
    assert main(["diff", str(a), str(bad)]) == 2


def test_diff_directory_input_exit_2(tmp_path: Path) -> None:
    a = _write_jsonl(tmp_path / "a.jsonl", _claude_records(2))
    assert main(["diff", str(a), str(tmp_path)]) == 2


def test_diff_no_payload_in_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    recs_a = _claude_records(3)
    recs_b = [dict(r, message="SECRET_PAYLOAD_XYZ") for r in recs_a]
    a = _write_jsonl(tmp_path / "a.jsonl", recs_a)
    b = _write_jsonl(tmp_path / "b.jsonl", recs_b)
    main(["diff", str(a), str(b), "--format", "claude-code-jsonl"])
    out = capsys.readouterr().out
    assert "SECRET_PAYLOAD_XYZ" not in out
    assert "text 1" not in out


def test_diff_events_pure() -> None:
    """diff_events on raw event sequences needs no files."""
    from sesslint.canonical import SessionEvent

    def _ev(i: int, parent: str | None = None) -> SessionEvent:
        return SessionEvent(
            id=f"e{i}",
            parent_id=parent,
            seq=i,
            ts=f"2025-01-01T00:00:{i:02d}Z",
            actor="user",
            kind="message",
        )

    assert diff_events([_ev(1), _ev(2)], [_ev(1), _ev(2)]) == ()
    deltas = diff_events([_ev(1), _ev(2)], [_ev(2), _ev(1)])
    assert {d.category for d in deltas} == {"seq-reordered"}


def test_diff_load_side_undetectable_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"x": 1}\n', encoding="utf-8")
    good = _write_jsonl(tmp_path / "good.jsonl", _claude_records(2))
    with pytest.raises(DiffInputError):
        diff_sessions(good, bad)
