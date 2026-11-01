"""Tests for path minimization in reports and scans (TASK-025)."""

from __future__ import annotations

import hashlib
import io
import os
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from sesslint.cli import main
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
    expected_hash = hashlib.sha256(parent_str.encode("utf-8")).hexdigest()[:8]
    assert res == f".._{expected_hash}/output.jsonl"
    assert "/var/log" not in res
    assert "/home/testuser" not in res


@pytest.mark.parametrize("absolute", [False, True])
def test_minimize_path_without_sha1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, absolute: bool
) -> None:
    """Minimized reports also work when the crypto provider disables SHA-1."""

    def unavailable(*args: object, **kwargs: object) -> None:
        raise ValueError("SHA-1 is unavailable")

    monkeypatch.setattr(hashlib, "sha1", unavailable)
    home = tmp_path / "synthetic-home"
    relative = Path("private folder") / "dữ liệu" / "session.jsonl"
    target = tmp_path / relative if absolute else relative
    expected_hash = hashlib.sha256(target.parent.as_posix().encode("utf-8")).hexdigest()[:8]
    result = minimize_path(target, home=home)
    assert result == f".._{expected_hash}/session.jsonl"
    assert "private folder" not in result and "dữ liệu" not in result
    assert minimize_path(target, home=home) == result
    assert minimize_path(result, home=home) == result


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


@pytest.mark.parametrize(
    "name",
    ["a\x1b[31m\nFORGED.jsonl", "bad\udcff.jsonl", "me@example.com.jsonl", "x‮.jsonl"],
)
def test_hostile_file_names_render_as_hashed_labels(name: str) -> None:
    """CL-16: names failing FR-081 or UTF-8 never reach a display label."""
    shown = minimize_path(f"/outside/home/{name}", home=Path("/home/u"))
    assert shown.startswith(".._") and "/redacted-" in shown
    assert shown == minimize_path(f"/outside/home/{name}", home=Path("/home/u"))
    shown.encode("utf-8")
    assert minimize_path(f"/home/u/proj/{name}", home=Path("/home/u")).startswith(".._")


def test_hostile_file_name_does_not_abort_a_directory_scan(tmp_path: Path) -> None:
    """CL-16: one control-character file name failed the whole scan (exit 2)."""
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "claude_code" / "basic.jsonl"
    (tmp_path / "ok.jsonl").write_bytes(fixture.read_bytes())
    (tmp_path / "a\x1b[31m\nFORGED.jsonl").write_bytes(fixture.read_bytes())
    if os.name != "nt":
        with open(os.path.join(os.fsencode(tmp_path), b"bad\xff.jsonl"), "wb") as fh:
            fh.write(fixture.read_bytes())
    for fmt in ("human", "json"):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(["check", str(tmp_path), "-f", fmt])
        text = out.getvalue()
        assert code in (0, 1), text
        assert "\x1b" not in text and "FORGED" not in text
        assert "ok.jsonl" in text
