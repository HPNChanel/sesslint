"""Tests for path minimization in reports and scans (TASK-025)."""

from __future__ import annotations

import hashlib
from pathlib import Path

from sesslint.report import minimize_path
from sesslint.scan import scan_path


def test_minimize_path_under_home() -> None:
    """Verify paths residing inside home directory are minimized to ~/relative/path."""
    fake_home = Path("/home/testuser").resolve()
    target_path = fake_home / "work" / "sessions" / "agent.jsonl"

    res = minimize_path(target_path, home=fake_home)
    assert res == "~/work/sessions/agent.jsonl"


def test_minimize_path_home_itself() -> None:
    """Verify that home directory itself minimizes to ~."""
    fake_home = Path("/home/testuser").resolve()
    res = minimize_path(fake_home, home=fake_home)
    assert res == "~"


def test_minimize_path_outside_home() -> None:
    """Verify paths residing outside home directory are minimized to .._<hash>/basename."""
    fake_home = Path("/home/testuser").resolve()
    target_path = Path("/var/log/agent_runs/output.jsonl")

    res = minimize_path(target_path, home=fake_home)
    parent_str = str(target_path.parent).replace("\\", "/")
    expected_hash = hashlib.sha1(parent_str.encode("utf-8")).hexdigest()[:8]
    assert res == f".._{expected_hash}/output.jsonl"
    assert "/var/log" not in res
    assert "/home/testuser" not in res


def test_minimize_path_with_spaces_and_unicode() -> None:
    """Verify paths containing spaces, special characters, and Unicode minimize safely."""
    fake_home = Path("/Users/dữ liệu người dùng").resolve()
    target_path = fake_home / "thư mục dự án" / "báo cáo session.jsonl"

    res = minimize_path(target_path, home=fake_home)
    assert res == "~/thư mục dự án/báo cáo session.jsonl"
    assert "/Users/" not in res


def test_minimize_path_already_minimized() -> None:
    """Verify already minimized paths are returned as is without double-hashing."""
    assert minimize_path("~/work/file.jsonl") == "~/work/file.jsonl"
    assert minimize_path(".._12345678/file.jsonl") == ".._12345678/file.jsonl"
    assert minimize_path("~") == "~"


def test_scan_path_uses_minimized_paths(tmp_path: Path) -> None:
    """Verify recursive directory scan produces results with minimized paths."""
    session_file = tmp_path / "valid.jsonl"
    session_file.write_text(
        '{"schema_version":"sesslint.session/v1","session_id":"s1","event_count":1}\n'
        '{"id":"e1","type":"user_message","parent_id":null,"text":"hi"}\n',
        encoding="utf-8",
    )

    report = scan_path(tmp_path, recursive=True)
    for f_res in report.files:
        # File paths must be minimized (starting with ~/ or .._)
        assert f_res.path.startswith("~/") or f_res.path.startswith(".._"), (
            f"Path not minimized: {f_res.path}"
        )
        assert "/Users/" not in f_res.path
        assert "/home/" not in f_res.path
