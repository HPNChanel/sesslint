"""CLI empty-input refusal.

``check`` on a zero-length, whitespace-only or BOM-only file exits 1 and names
the input as empty rather than malformed. It suggests no repair command: the
per-line salvage recipe has no record to excise there. ``--json`` stays a
valid report.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from sesslint.cli import main
from sesslint.report import EMPTY_INPUT_MESSAGE

FIXTURES = Path(__file__).resolve().parent.parent.parent / "fixtures"
REPAIR_BASIC = FIXTURES / "repair" / "exec_basic" / "source.jsonl"
EMPTY_INPUTS = {"empty": b"", "blank": b" \n\t\r\n  \n", "bom": b"\xef\xbb\xbf"}


class _FakeStdin:
    """Minimal sys.stdin stand-in exposing only the binary buffer."""

    def __init__(self, data: bytes) -> None:
        self.buffer = io.BytesIO(data)


def _run(capsys: pytest.CaptureFixture[str], argv: list[str]) -> tuple[int, str, str]:
    code = main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _next_action(text: str) -> str:
    return next(line for line in text.splitlines() if line.startswith("Next Action:"))


@pytest.mark.parametrize("kind", sorted(EMPTY_INPUTS))
def test_empty_input_exits_1_without_a_repair_hint(
    kind: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    src = tmp_path / f"{kind}.jsonl"
    src.write_bytes(EMPTY_INPUTS[kind])
    code, out, err = _run(capsys, ["check", str(src)])
    assert code == 1
    assert _next_action(out) == (
        f"Next Action: {EMPTY_INPUT_MESSAGE}; check that the path names the session file."
    )
    assert f"Fix:         {EMPTY_INPUT_MESSAGE}; automated repair refused" in out
    assert "sesslint repair" not in out + err
    assert "--policy salvage" not in out + err


def test_empty_message_differs_from_malformed_content(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A torn record between valid ones keeps its own finding and salvage path."""
    empty = tmp_path / "empty.jsonl"
    empty.write_bytes(b"")
    lines = REPAIR_BASIC.read_bytes().splitlines(keepends=True)
    bad = tmp_path / "bad.jsonl"
    bad.write_bytes(lines[0] + lines[1] + b'{"broken": \n' + b"".join(lines[2:]))

    empty_code, empty_out, _ = _run(capsys, ["check", str(empty)])
    bad_code, bad_out, _ = _run(capsys, ["check", str(bad)])

    assert empty_code == bad_code == 1
    assert EMPTY_INPUT_MESSAGE in empty_out
    assert EMPTY_INPUT_MESSAGE not in bad_out
    assert "Session input is empty" not in bad_out
    assert "--policy salvage --acknowledge-side-effects" in _next_action(bad_out)
    assert "sesslint repair" not in empty_out


@pytest.mark.parametrize("kind", sorted(EMPTY_INPUTS))
def test_empty_input_json_is_a_valid_report(
    kind: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    src = tmp_path / f"{kind}.jsonl"
    src.write_bytes(EMPTY_INPUTS[kind])
    code, out, err = _run(capsys, ["check", str(src), "--json"])
    assert code == 1
    assert err == ""
    payload = json.loads(out)
    assert payload["schema_version"] == "sesslint.report/v1"
    assert payload["counts"]["by_severity"]["error"] == 1
    assert [f["remediation"] for f in payload["findings"]] == [
        f"{EMPTY_INPUT_MESSAGE}; automated repair refused"
    ]
    assert "sesslint repair" not in out


def test_empty_stdin_takes_the_same_refusal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stdin", _FakeStdin(b""))
    code, out, err = _run(capsys, ["check", "-"])
    assert code == 1
    assert EMPTY_INPUT_MESSAGE in _next_action(out)
    assert "sesslint repair" not in out + err


def test_empty_input_next_action_is_color_free(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Forced color styles the banner, never the Next Action line."""
    monkeypatch.delenv("NO_COLOR", raising=False)
    empty = tmp_path / "empty.jsonl"
    empty.write_bytes(b"")
    code, out, _ = _run(capsys, ["--color", "always", "check", str(empty)])
    assert code == 1
    assert "\033[" in out.splitlines()[0]
    assert "\033" not in _next_action(out)
    assert EMPTY_INPUT_MESSAGE in _next_action(out)
