"""Tests proving zero network egress and local-only execution (FR-089, AC-018, TASK-025)."""

from __future__ import annotations

import re
import socket
from pathlib import Path

import pytest

from sesslint.cli import main

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_static_audit_no_network_modules_in_core() -> None:
    """Statically verify that report.py and scan.py import zero network/http/subprocess modules."""
    files_to_check = [
        REPO_ROOT / "src" / "sesslint" / "report.py",
        REPO_ROOT / "src" / "sesslint" / "scan.py",
    ]

    forbidden_imports = re.compile(
        r"^\s*(import\s+(socket|urllib|http|requests|subprocess)|from\s+(socket|urllib|http|requests|subprocess)\s+import)",
        re.MULTILINE,
    )

    for file_path in files_to_check:
        content = file_path.read_text(encoding="utf-8")
        match = forbidden_imports.search(content)
        assert match is None, (
            f"Forbidden network/subprocess import found in {file_path.name}: {match.group(0)!r}"
        )


def test_runtime_check_succeeds_with_blocked_sockets(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify that sesslint check runs cleanly when socket creation is disabled."""

    def _block_socket(*args: object, **kwargs: object) -> None:
        raise RuntimeError("Network egress attempted: sockets are strictly disabled")

    monkeypatch.setattr(socket, "socket", _block_socket)

    healthy_fixture = REPO_ROOT / "fixtures" / "cli" / "check_basic" / "healthy.jsonl"
    code = main(["check", str(healthy_fixture), "--json"])
    assert code == 0
    captured = capsys.readouterr()
    assert "sesslint.report/v1" in captured.out
    assert captured.err == ""
