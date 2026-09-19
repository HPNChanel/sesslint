"""Stdin input (`-` PATH) coverage — ux-reporting T-06.

``sesslint check -`` / ``scan -`` / ``repair -`` read one session artifact
from stdin. The bytes run through the identical probe → detect → load →
check pipeline as a file, so findings/verdicts match modulo the virtual
``<stdin>`` display path.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from sesslint.api import check_bytes, check_file
from sesslint.cli import main
from sesslint.scan import scan_bytes, scan_path
from sesslint.source import fingerprint_bytes, fingerprint_file

FIXTURES = Path(__file__).resolve().parent.parent.parent / "fixtures"
CODEX_HEALTHY = FIXTURES / "adapters" / "codex" / "healthy_min.jsonl"
SCAN_HEALTHY = FIXTURES / "scan" / "mixed" / "healthy.jsonl"
REPAIR_BASIC = FIXTURES / "repair" / "exec_basic" / "source.jsonl"
REPAIR_EXPECTED = FIXTURES / "repair" / "exec_basic" / "expected_output.jsonl"


class _FakeStdin:
    """Minimal sys.stdin stand-in exposing only the binary buffer."""

    def __init__(self, data: bytes) -> None:
        self.buffer = io.BytesIO(data)


def _feed_stdin(monkeypatch: pytest.MonkeyPatch, data: bytes) -> None:
    monkeypatch.setattr(sys, "stdin", _FakeStdin(data))


# --- API-level parity -------------------------------------------------------


def test_check_bytes_matches_check_file() -> None:
    data = CODEX_HEALTHY.read_bytes()
    file_report = check_file(CODEX_HEALTHY)
    bytes_report = check_bytes(data)
    assert [f.code for f in bytes_report.findings] == [f.code for f in file_report.findings]
    assert bytes_report.assurance == file_report.assurance
    # Same bytes → same content fingerprint regardless of source kind.
    assert bytes_report.source_fingerprint == file_report.source_fingerprint


def test_scan_bytes_matches_scan_path() -> None:
    data = SCAN_HEALTHY.read_bytes()
    file_rep = scan_path(SCAN_HEALTHY)
    bytes_rep = scan_bytes(data)
    assert bytes_rep.files[0].verdict == file_rep.files[0].verdict
    assert [f.code for f in bytes_rep.files[0].findings] == [
        f.code for f in file_rep.files[0].findings
    ]
    assert bytes_rep.files[0].path == "<stdin>"
    assert bytes_rep.root_path == "<stdin>"


def test_fingerprint_bytes_matches_file(tmp_path: Path) -> None:
    data = b'{"schema_version":"sesslint.session/v1"}\n'
    p = tmp_path / "s.jsonl"
    p.write_bytes(data)
    assert fingerprint_bytes(data) == fingerprint_file(p)


def test_check_bytes_fail_closed_variants() -> None:
    assert [f.code for f in check_bytes(b"garbage").findings] == ["SL302"]
    assert [f.code for f in check_bytes(b'{"a":1}\x00more').findings] == ["SL001"]
    assert [f.code for f in check_bytes(b"").findings] == ["SL001"]
    assert [f.code for f in check_bytes(b"   \n  ").findings] == ["SL001"]


def test_check_bytes_oversize_structured_result() -> None:
    report = check_bytes(b"x" * 128, max_input_bytes=64)
    codes = [f.code for f in report.findings]
    assert codes == ["SL001"]
    assert report.assurance == "A0"


def test_scan_bytes_oversize_unreadable() -> None:
    rep = scan_bytes(b"x" * 128, max_input_bytes=64)
    assert rep.files[0].verdict == "unreadable"
    assert rep.totals.unreadable == 1
    assert [f.code for f in rep.files[0].findings] == ["SL001"]


def test_check_bytes_virtual_path_in_findings() -> None:
    report = check_bytes(b"garbage", virtual_path="<pipe>")
    assert report.findings[0].source.path == "<pipe>"


# --- CLI: check - -----------------------------------------------------------


def test_cli_check_stdin_healthy(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _feed_stdin(monkeypatch, CODEX_HEALTHY.read_bytes())
    code = main(["check", "-"])
    out = capsys.readouterr().out
    assert code == 0
    assert "Valid Codex rollout session" in out


def test_cli_check_stdin_json_matches_file(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data = CODEX_HEALTHY.read_bytes()
    file_code = main(["check", str(CODEX_HEALTHY), "--json"])
    file_out = capsys.readouterr().out
    _feed_stdin(monkeypatch, data)
    stdin_code = main(["check", "-", "--json"])
    stdin_out = capsys.readouterr().out
    assert file_code == stdin_code == 0
    file_doc = json.loads(file_out)
    stdin_doc = json.loads(stdin_out)
    assert [f["code"] for f in stdin_doc["findings"]] == [f["code"] for f in file_doc["findings"]]
    assert stdin_doc["source_fingerprint"] == file_doc["source_fingerprint"]


def test_cli_check_stdin_garbage_fails_closed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _feed_stdin(monkeypatch, b"garbage")
    _feed_stdin(monkeypatch, b"garbage")
    code = main(["check", "-", "--json"])
    captured = capsys.readouterr()
    doc = json.loads(captured.out)
    assert code == 1
    assert [f["code"] for f in doc["findings"]] == ["SL302"]
    # The bundle hint adapts to piped input (stdin has no bundle-able path).
    assert "save the stream to a file" in captured.err


def test_cli_check_stdin_mixed_paths_rejected(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _feed_stdin(monkeypatch, b"x")
    code = main(["check", "-", str(SCAN_HEALTHY)])
    assert code == 2
    assert "stdin" in capsys.readouterr().err.lower()


def test_cli_check_stdin_skip_undetected_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _feed_stdin(monkeypatch, b"garbage")
    code = main(["check", "-", "--skip-undetected", "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert code == 0
    assert doc["skipped"] is True
    assert doc["path"] == "<stdin>"


def test_cli_check_stdin_format_override(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _feed_stdin(monkeypatch, CODEX_HEALTHY.read_bytes())
    code = main(["check", "-", "--format", "codex-rollout"])
    assert code == 0
    assert "Valid Codex rollout session" in capsys.readouterr().out


def test_cli_check_stdin_oversize_structured(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Oversized stdin yields an SL001 finding payload, never a traceback."""
    import sesslint.io as sesslint_io

    monkeypatch.setattr(sesslint_io, "DEFAULT_MAX_FILE_BYTES", 64)
    _feed_stdin(monkeypatch, b"x" * 128)
    code = main(["check", "-", "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert code == 1
    assert [f["code"] for f in doc["findings"]] == ["SL001"]


# --- CLI: scan - ------------------------------------------------------------


def test_cli_scan_stdin_healthy(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _feed_stdin(monkeypatch, SCAN_HEALTHY.read_bytes())
    code = main(["scan", "-"])
    out = capsys.readouterr().out
    assert code == 0
    assert "<stdin>" in out
    assert "healthy=1" in out


def test_cli_scan_stdin_garbage(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _feed_stdin(monkeypatch, b"garbage")
    code = main(["scan", "-", "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert code == 1
    assert doc["root_path"] == "<stdin>"
    assert doc["totals"]["invalid"] == 1


# --- CLI: repair - ----------------------------------------------------------


def test_cli_repair_stdin_roundtrip(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    data = REPAIR_BASIC.read_bytes()
    _feed_stdin(monkeypatch, data)
    out_path = tmp_path / "out.jsonl"
    code = main(["repair", "-", "--output", str(out_path)])
    assert code == 0
    assert out_path.exists()
    assert Path(f"{out_path}.manifest.json").exists()
    # Byte-identical to repairing the same bytes as a file.
    file_out = tmp_path / "file_out.jsonl"
    code2 = main(["repair", str(REPAIR_BASIC), "--output", str(file_out)])
    assert code2 == 0
    assert out_path.read_bytes() == file_out.read_bytes()


def test_cli_repair_stdin_requires_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _feed_stdin(monkeypatch, b"x")
    code = main(["repair", "-"])
    assert code == 2
    assert "--output" in capsys.readouterr().err


def test_cli_repair_stdin_dry_run(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _feed_stdin(monkeypatch, REPAIR_BASIC.read_bytes())
    code = main(["repair", "-", "--dry-run"])
    out = capsys.readouterr().out
    assert code == 0
    assert "Plan fingerprint:" in out
