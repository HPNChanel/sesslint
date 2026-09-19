"""Tests for `sesslint stats` aggregate statistics (ux-reporting T-03)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.cli import main
from sesslint.stats import STATS_SCHEMA_VERSION, load_stats_schema, stats_paths

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"


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


def test_stats_single_file_exact_counters(tmp_path: Path) -> None:
    f = _write_jsonl(tmp_path / "s.jsonl", _claude_records(4))
    result = stats_paths([f])
    assert result.files_processed == 1
    assert result.files_undetected == 0
    assert result.files_unreadable == 0
    assert result.events_total == 4
    assert result.by_kind.get("message") == 4
    assert result.by_actor.get("user") == 2
    assert result.by_actor.get("assistant") == 2
    assert result.by_adapter.get("claude-code-jsonl") == 1
    assert result.file_bytes["total"] == f.stat().st_size
    assert result.events_per_file["max"] == 4


def test_stats_tool_call_hashing(tmp_path: Path) -> None:
    recs = [
        {
            "id": "a1",
            "type": "assistant_message",
            "message": "t",
            "timestamp": "2025-01-01T00:00:01Z",
        },
        {
            "id": "t1",
            "parentId": "a1",
            "type": "tool_use",
            "name": "Read",
            "input": {"file_path": "x"},
            "timestamp": "2025-01-01T00:00:02Z",
        },
    ]
    f = _write_jsonl(tmp_path / "s.jsonl", recs)
    result = stats_paths([f], format="claude-code-jsonl")
    assert result.tool_calls_total == 1
    assert len(result.by_tool_hash) == 1
    # The raw tool name never appears in any output surface.
    blob = result.to_json() + result.render_human()
    assert "Read" not in blob
    th = next(iter(result.by_tool_hash))
    assert len(th) == 16
    int(th, 16)  # hex only


def test_stats_directory_walk(tmp_path: Path) -> None:
    sub = tmp_path / "sessions"
    sub.mkdir()
    _write_jsonl(sub / "a.jsonl", _claude_records(3))
    _write_jsonl(sub / "b.jsonl", _claude_records(5))
    (sub / "note.txt").write_text("not a session\n", encoding="utf-8")
    result = stats_paths([sub], recursive=True)
    assert result.files_processed == 2
    assert result.files_undetected == 1
    assert result.events_total == 8


def test_stats_dir_without_recursive_raises(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="directory"):
        stats_paths([tmp_path])


def test_stats_missing_path_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        stats_paths([tmp_path / "nope.jsonl"])


def test_stats_unreadable_counts_not_raises(tmp_path: Path) -> None:
    f = tmp_path / "bin.jsonl"
    f.write_bytes(b"\xff\xfe\x00\x01binary")
    result = stats_paths([f])
    assert result.files_processed == 0
    assert result.files_unreadable + result.files_undetected == 1


def test_stats_compaction_and_checkpoint(tmp_path: Path) -> None:
    fixture = FIXTURES_DIR / "checks"
    result = stats_paths([fixture], recursive=True)
    # Known fixture corpus: counters are exact and stable.
    assert result.events_total == 179
    assert result.by_kind.get("checkpoint") == 10
    assert result.by_kind.get("compaction_boundary") == 7
    assert result.checkpoints == 10
    assert result.compaction_boundaries == 7
    assert result.tool_calls_total == 16
    assert result.files_processed == 43


def test_stats_deterministic(tmp_path: Path) -> None:
    _write_jsonl(tmp_path / "a.jsonl", _claude_records(6))
    r1 = stats_paths([tmp_path], recursive=True)
    r2 = stats_paths([tmp_path], recursive=True)
    assert r1.to_json() == r2.to_json()


def test_stats_json_schema(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = _write_jsonl(tmp_path / "s.jsonl", _claude_records(3))
    rc = main(["stats", str(f), "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    schema = load_stats_schema()
    assert out["schema_version"] == schema["properties"]["schema_version"]["const"]
    assert out["schema_version"] == STATS_SCHEMA_VERSION
    for key in schema["required"]:
        assert key in out
    assert out["files"]["total"] == (
        out["files"]["processed"] + out["files"]["undetected"] + out["files"]["unreadable"]
    )
    # No absolute paths leak.
    assert str(tmp_path) not in json.dumps(out)


def test_stats_cli_human_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = _write_jsonl(tmp_path / "s.jsonl", _claude_records(4))
    rc = main(["stats", str(f)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "SessLint corpus statistics" in out
    assert "Events: 4" in out
    assert "text 1" not in out  # payload-free


def test_stats_cli_exit_2_paths(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = _write_jsonl(tmp_path / "s.jsonl", _claude_records(2))
    assert main(["stats"]) == 2
    assert main(["stats", str(tmp_path)]) == 2  # dir without -r
    assert main(["stats", str(f), "--agent", "claude"]) == 2  # conflict
    capsys.readouterr()


def test_stats_no_payload_values(tmp_path: Path) -> None:
    recs = _claude_records(3)
    recs[0]["message"] = "SECRET_BODY_CONTENT"
    f = _write_jsonl(tmp_path / "s.jsonl", recs)
    result = stats_paths([f], format="claude-code-jsonl")
    blob = result.to_json() + result.render_human()
    assert "SECRET_BODY_CONTENT" not in blob
    assert "text 2" not in blob
