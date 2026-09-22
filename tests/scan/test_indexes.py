"""Tests for vendor session-index readers (index-reconciliation T-01).

Readers are bounded, shape-only, and never raise: every failure mode is a
deterministic IndexSnapshot field. All fixtures are synthetic.
"""

from __future__ import annotations

import json
from pathlib import Path

from sesslint.indexes import (
    MAX_INDEX_ENTRIES,
    IndexSnapshot,
    discover_index_files,
    read_index,
)


def _entry(sid: str, **extra: object) -> dict[str, object]:
    e: dict[str, object] = {
        "sessionId": sid,
        "fullPath": f"/proj/{sid}.jsonl",
        "messageCount": 3,
        "summary": "synthetic",
    }
    e.update(extra)
    return e


def _write_index(dirpath: Path, entries: list[dict[str, object]], **top: object) -> Path:
    doc: dict[str, object] = {"version": 1, "originalPath": "/proj", "entries": entries}
    doc.update(top)
    p = dirpath / "sessions-index.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def test_wellformed_index_yields_membership(tmp_path: Path) -> None:
    p = _write_index(tmp_path, [_entry("aaa"), _entry("bbb"), _entry("ccc")])
    snap = read_index(p)
    assert snap.parse_ok and not snap.truncated and snap.schema_note is None
    assert snap.membership_complete
    assert snap.entry_ids == frozenset({"aaa", "bbb", "ccc"})
    assert snap.entry_count == 3
    assert snap.format == "claude-sessions-index"


def test_absent_index_is_not_an_error(tmp_path: Path) -> None:
    snap = read_index(tmp_path / "sessions-index.json")
    assert snap.parse_ok and snap.entry_count == 0
    assert snap.schema_note == "absent"
    assert not snap.membership_complete


def test_empty_entries_membership_complete(tmp_path: Path) -> None:
    p = _write_index(tmp_path, [])
    snap = read_index(p)
    assert snap.membership_complete and snap.entry_count == 0


def test_malformed_binary_index(tmp_path: Path) -> None:
    p = tmp_path / "sessions-index.json"
    p.write_bytes(b"\x00\x01\x02\x89PNG\r\n garbage")
    snap = read_index(p)
    assert not snap.parse_ok and not snap.truncated
    assert snap.schema_note == "malformed"
    assert snap.entry_count == 0


def test_truncated_index_salvages_partial_set(tmp_path: Path) -> None:
    p = tmp_path / "sessions-index.json"
    # Picker-crash signature: valid index prefix cut mid-entry.
    p.write_text(
        '{"version": 1, "originalPath": "/proj", "entries": ['
        '{"sessionId": "aaa", "fullPath": "/proj/aaa.jsonl"}, '
        '{"sessionId": "bbb", "fullPath": "/proj/bbb.jsonl"}, '
        '{"sessionId": "cc',
        encoding="utf-8",
    )
    snap = read_index(p)
    assert not snap.parse_ok and snap.truncated
    assert snap.entry_ids == frozenset({"aaa", "bbb"})
    assert not snap.membership_complete


def test_truncated_index_with_zero_salvaged(tmp_path: Path) -> None:
    p = tmp_path / "sessions-index.json"
    p.write_text('{"version": 1, "entries": [{"sessionId": "aa', encoding="utf-8")
    snap = read_index(p)
    assert not snap.parse_ok and snap.truncated
    assert snap.entry_ids == frozenset()


def test_json_but_not_index_shape_is_malformed_not_truncated(tmp_path: Path) -> None:
    p = tmp_path / "sessions-index.json"
    p.write_text('{"totally": "other", "broken": ', encoding="utf-8")
    snap = read_index(p)
    assert not snap.parse_ok and not snap.truncated
    assert snap.schema_note == "malformed"


def test_schema_drift_entries_missing(tmp_path: Path) -> None:
    p = tmp_path / "sessions-index.json"
    p.write_text('{"version": 2, "sessions": []}', encoding="utf-8")
    snap = read_index(p)
    assert snap.parse_ok and not snap.truncated
    assert snap.schema_note == "unrecognized-shape"
    assert not snap.membership_complete


def test_entries_lacking_session_id_noted(tmp_path: Path) -> None:
    p = _write_index(tmp_path, [_entry("aaa"), {"fullPath": "/proj/x.jsonl"}])
    snap = read_index(p)
    assert snap.parse_ok
    assert snap.entry_ids == frozenset({"aaa"})
    assert snap.schema_note is not None and "lack sessionId" in snap.schema_note
    assert not snap.membership_complete


def test_symlink_index_never_followed(tmp_path: Path) -> None:
    (tmp_path / "real").mkdir()
    real = _write_index(tmp_path / "real", [_entry("aaa")])
    link = tmp_path / "sessions-index.json"
    try:
        link.symlink_to(real)
    except OSError:
        return  # platform without symlink privileges — covered on POSIX CI
    snap = read_index(link)
    assert not snap.parse_ok and snap.schema_note == "symlink"


def test_oversized_index_refused(tmp_path: Path) -> None:
    p = tmp_path / "sessions-index.json"
    p.write_bytes(b'{"entries": [' + b" " * (17 * 1024 * 1024))
    snap = read_index(p)
    assert not snap.parse_ok and snap.schema_note == "oversized"


def test_normalized_ids_bridges_stem_and_path(tmp_path: Path) -> None:
    p = _write_index(tmp_path, [_entry("abc-123")])
    snap = read_index(p)
    assert "abc-123" in snap.normalized_ids
    # fullPath stem resolves to the same id
    assert all(Path(x).stem in snap.normalized_ids for x in snap.entry_paths)


def test_entry_cap(tmp_path: Path) -> None:
    big = [
        {"sessionId": f"id-{i}", "fullPath": f"/p/{i}.jsonl"} for i in range(MAX_INDEX_ENTRIES + 1)
    ]
    p = _write_index(tmp_path, big)
    snap = read_index(p)
    assert not snap.parse_ok and snap.schema_note == "oversized"


def test_discover_index_files_claude_layout(tmp_path: Path) -> None:
    root = tmp_path / "projects"
    (root / "-proj-b").mkdir(parents=True)
    (root / "-proj-a").mkdir(parents=True)
    (root / "-proj-a" / "s1.jsonl").write_text("{}", encoding="utf-8")
    _write_index(root / "-proj-a", [_entry("a1")])
    _write_index(root / "-proj-b", [_entry("b1")])
    found = discover_index_files(root, "claude")
    assert len(found) == 2
    # deterministic order: -proj-a before -proj-b
    assert found[0].parent.name == "-proj-a"
    assert found[1].parent.name == "-proj-b"


def test_discover_index_files_root_direct(tmp_path: Path) -> None:
    # Scan pointed directly at one project dir still finds its index.
    _write_index(tmp_path, [_entry("x")])
    found = discover_index_files(tmp_path, "claude")
    assert len(found) == 1 and found[0].name == "sessions-index.json"


def test_discover_index_files_unknown_agent(tmp_path: Path) -> None:
    assert discover_index_files(tmp_path, "gemini") == ()


def test_discover_index_files_missing_root(tmp_path: Path) -> None:
    assert discover_index_files(tmp_path / "nope", "claude") == ()


def test_verified_matrix_rows_have_readers() -> None:
    """Matrix-vs-code consistency (T-03): runtimes marked 'verified' in
    docs/codes/SL402.md must map to a shipped reader — has_index_format."""
    from sesslint.indexes import has_index_format

    readers = {a for a in ("claude", "codex", "gemini", "copilot") if has_index_format(a)}
    assert readers == {"claude", "codex"}

    doc = Path(__file__).resolve().parent.parent.parent / "docs" / "codes" / "SL402.md"
    text = doc.read_text(encoding="utf-8")
    verified_rows = [ln for ln in text.splitlines() if "verified" in ln and ln.startswith("|")]
    # Rows carrying the bold 'verified' reader marker: Claude + Codex (T-04).
    marked = [ln for ln in verified_rows if "**verified**" in ln]
    assert len(marked) == 2
    assert "Claude" in marked[0]
    assert "Codex" in marked[1]
    for row in verified_rows:
        if "**verified**" not in row:
            assert "research-only" in row


def test_snapshot_is_frozen() -> None:
    import dataclasses

    snap = IndexSnapshot(
        format="claude-sessions-index",
        entries=(),
        parse_ok=True,
        truncated=False,
        schema_note=None,
    )
    import pytest

    with pytest.raises(dataclasses.FrozenInstanceError):
        snap.truncated = True  # type: ignore[misc]


def _write_codex_index(path: Path, lines: list[str]) -> Path:
    p = path / "session_index.jsonl"
    p.write_text(chr(10).join(lines) + chr(10), encoding="utf-8", newline="")
    return p


def test_codex_jsonl_index_reads_ids_only(tmp_path: Path) -> None:
    from sesslint.indexes import read_index

    p = _write_codex_index(
        tmp_path,
        [
            '{"id": "u-a", "thread_name": "secret title", "updated_at": "t"}',
            '{"id": "u-b", "thread_name": "x", "updated_at": "t"}',
            '{"id": "u-a", "thread_name": "y", "updated_at": "t2"}',
        ],
    )
    snap = read_index(p)
    assert snap.parse_ok and snap.membership_complete
    assert snap.format == "codex-session-index"
    assert snap.entry_ids == frozenset({"u-a", "u-b"})  # deduped
    assert snap.entry_count == 2
    # thread_name is content — retained nowhere
    assert "secret title" not in repr(snap)


def test_codex_jsonl_truncated_last_line_salvages(tmp_path: Path) -> None:
    from sesslint.indexes import read_index

    p = tmp_path / "session_index.jsonl"
    p.write_text(
        '{"id": "u-a", "thread_name": "x", "updated_at": "t"}' + chr(10) + '{"id": "u-b", "thr',
        encoding="utf-8",
        newline="",
    )
    snap = read_index(p)
    assert not snap.parse_ok and snap.truncated
    assert snap.entry_ids == frozenset({"u-a"})


def test_codex_jsonl_malformed_mid_line_fails(tmp_path: Path) -> None:
    from sesslint.indexes import read_index

    p = tmp_path / "session_index.jsonl"
    p.write_text(
        '{"id": "u-a"}' + chr(10) + "not-json{{{" + chr(10) + '{"id": "u-b"}' + chr(10),
        encoding="utf-8",
        newline="",
    )
    snap = read_index(p)
    assert not snap.parse_ok and not snap.truncated
    assert snap.schema_note == "malformed"


def test_codex_jsonl_non_index_shape(tmp_path: Path) -> None:
    from sesslint.indexes import read_index

    p = tmp_path / "session_index.jsonl"
    p.write_text('[{"id": "u-a"}]' + chr(10), encoding="utf-8", newline="")
    snap = read_index(p)
    assert not snap.parse_ok and snap.schema_note == "unrecognized-shape"


def test_codex_discover_index_files_parent_probe(tmp_path: Path) -> None:
    from sesslint.indexes import discover_index_files

    home = tmp_path / "codex_home"
    sessions = home / "sessions"
    sessions.mkdir(parents=True)
    _write_codex_index(home, ['{"id": "u-a", "thread_name": "x", "updated_at": "t"}'])
    found = discover_index_files(sessions, "codex")
    assert found == (home / "session_index.jsonl",)
