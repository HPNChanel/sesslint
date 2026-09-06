"""Network-isolated full suite test proving zero egress on all commands (TASK-027, FR-089, AC-018).

Guarantees:
- With socket.socket disabled and hostile proxy environment set, check, repair, and verify
  execute fully and produce expected exit codes without ever attempting network connections.
"""

from __future__ import annotations

import socket
from collections.abc import Generator
from pathlib import Path

import pytest

from sesslint.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"
VALID_SESSION = FIXTURES_DIR / "determinism" / "repeat" / "repeat_session.json"
REPAIRABLE_SESSION = FIXTURES_DIR / "repair_cli" / "basic" / "source.jsonl"


@pytest.fixture(autouse=True)
def enforce_network_isolation(monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    """Strictly disable socket creation and point proxies to an unreachable address."""
    # 1. Point proxies to blackhole
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "https://127.0.0.1:9")
    monkeypatch.setenv("ALL_PROXY", "socks5://127.0.0.1:9")

    # 2. Block socket.socket
    def forbidden_socket(*args: object, **kwargs: object) -> None:
        raise RuntimeError("Outbound network access strictly forbidden in offline tests (FR-089)")

    monkeypatch.setattr(socket, "socket", forbidden_socket)
    yield


def test_offline_check_command() -> None:
    """sesslint check operates completely offline."""
    # Healthy fixture exits 0
    exit_code = main(["check", str(VALID_SESSION)])
    assert exit_code == 0

    # JSON output operates completely offline
    exit_json = main(["check", str(VALID_SESSION), "--json"])
    assert exit_json == 0


def test_offline_repair_and_verify_commands(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """sesslint repair and sesslint verify operate completely offline."""
    out_file = tmp_path / "repaired_offline.jsonl"
    manifest_file = tmp_path / "repaired_offline.jsonl.manifest.json"
    plan_file = tmp_path / "plan.json"

    # 1. Plan in dry-run mode
    plan_exit = main(
        [
            "repair",
            str(REPAIRABLE_SESSION),
            "--dry-run",
            "--json",
        ]
    )
    assert plan_exit == 0
    captured_plan = capsys.readouterr().out
    plan_file.write_text(captured_plan, encoding="utf-8")

    # 2. repair command with plan
    repair_exit = main(
        [
            "repair",
            str(REPAIRABLE_SESSION),
            "--plan",
            str(plan_file),
            "--output",
            str(out_file),
        ]
    )
    assert repair_exit == 0
    assert out_file.exists()
    assert manifest_file.exists()

    # 3. verify command
    verify_exit = main(
        [
            "verify",
            "--source",
            str(REPAIRABLE_SESSION),
            "--plan",
            str(plan_file),
            "--output",
            str(out_file),
            "--manifest",
            str(manifest_file),
        ]
    )
    assert verify_exit == 0
