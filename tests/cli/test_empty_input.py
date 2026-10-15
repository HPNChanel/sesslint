"""CLI empty-input refusal.

``check`` on a zero-length or whitespace-only file exits 1 with a standalone
message that is distinct from the malformed-content report, and it does not
suggest a repair command that itself exits 2. ``--json`` stays valid JSON.
"""

from __future__ import annotations

import io
import json
import re
import sys
from pathlib import Path

import pytest

from sesslint.cli import main

EMPTY_MESSAGE = "Empty input: file contains no session records"
MALFORMED_MESSAGE = "Malformed record on line"
_SUGGESTED_REPAIR = re.compile(r"sesslint repair [^'\n]+")


class _FakeStdin:
    """Minimal sys.stdin stand-in exposing only the binary buffer."""

    def __init__(self, data: bytes) -> None:
        self.buffer = io.BytesIO(data)


def _combined(capsys: pytest.CaptureFixture[str]) -> tuple[str, str, str]:
    captured = capsys.readouterr()
    return captured.out, captured.err, captured.out + captured.err


def _assert_suggested_repairs_do_not_exit_2(text: str) -> None:
    """Run every suggested repair exactly as printed. Absence is success."""
    for raw in _SUGGESTED_REPAIR.findall(text):
        argv = raw.split()
        assert argv[0] == "sesslint"
        code = main(argv[1:])
        assert code != 2, raw


def test_empty_file_exits_1_with_distinct_message(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Zero-length input exits 1 and names empty input, not a malformed record."""
    empty = tmp_path / "empty.jsonl"
    empty.write_bytes(b"")
    code = main(["check", str(empty)])
    out, err, text = _combined(capsys)
    assert code == 1
    assert EMPTY_MESSAGE in text
    assert MALFORMED_MESSAGE not in text
    assert "sesslint repair" not in text
    assert err == ""
    assert out.count(EMPTY_MESSAGE) == 1


def test_whitespace_only_file_exits_1_with_distinct_message(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Whitespace-only input takes the same empty-input branch."""
    blank = tmp_path / "blank.jsonl"
    blank.write_bytes(b" \n\t\r\n  \n")
    code = main(["check", str(blank)])
    _out, _err, text = _combined(capsys)
    assert code == 1
    assert EMPTY_MESSAGE in text
    assert MALFORMED_MESSAGE not in text
    assert "sesslint repair" not in text


def test_bom_only_file_exits_1_with_distinct_message(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A UTF-8 BOM with no records is empty input, not malformed content."""
    bom = tmp_path / "bom.jsonl"
    bom.write_bytes(b"\xef\xbb\xbf")
    code = main(["check", str(bom)])
    _out, _err, text = _combined(capsys)
    assert code == 1
    assert EMPTY_MESSAGE in text
    assert "sesslint repair" not in text


def test_empty_message_differs_from_malformed_content(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Malformed content keeps its own message and its repair hint."""
    empty = tmp_path / "empty.jsonl"
    empty.write_bytes(b"")
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{not json\n{"id":"evt_ok"}\n', encoding="utf-8")

    empty_code = main(["check", str(empty), "--format", "canonical"])
    empty_out, empty_err, empty_text = _combined(capsys)
    bad_code = main(["check", str(bad), "--format", "canonical"])
    bad_out, _bad_err, bad_text = _combined(capsys)

    assert empty_code == 1
    assert bad_code == 1
    assert EMPTY_MESSAGE in empty_text
    assert EMPTY_MESSAGE not in bad_text
    assert MALFORMED_MESSAGE in bad_text
    assert MALFORMED_MESSAGE not in empty_text
    assert empty_text != bad_text
    assert "sesslint repair" in bad_out
    assert "sesslint repair" not in empty_out
    assert "sesslint repair" not in empty_err


def test_empty_input_suggests_no_repair_that_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Any repair command printed for empty input must not exit 2."""
    empty = tmp_path / "empty.jsonl"
    empty.write_bytes(b"")
    code = main(["check", str(empty)])
    _out, _err, text = _combined(capsys)
    assert code == 1
    _assert_suggested_repairs_do_not_exit_2(text)
    assert _SUGGESTED_REPAIR.findall(text) == []


def test_empty_file_json_is_valid(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """``--json`` on an empty file is one JSON document and suggests no repair."""
    empty = tmp_path / "empty.jsonl"
    empty.write_bytes(b"")
    code = main(["check", str(empty), "--json"])
    out, err, text = _combined(capsys)
    assert code == 1
    assert err == ""
    payload = json.loads(out)
    assert isinstance(payload, dict)
    assert payload["schema_version"] == "sesslint.report/v1"
    assert payload["counts"]["by_severity"]["error"] >= 1
    assert "sesslint repair" not in text
    _assert_suggested_repairs_do_not_exit_2(text)


def test_whitespace_only_json_is_valid(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """``--json`` on whitespace-only input stays a parseable report."""
    blank = tmp_path / "blank.jsonl"
    blank.write_text("\n\n   \n", encoding="utf-8")
    code = main(["check", str(blank), "--json"])
    out, _err, text = _combined(capsys)
    assert code == 1
    payload = json.loads(out)
    assert payload["schema_version"] == "sesslint.report/v1"
    assert "sesslint repair" not in text


def test_empty_stdin_exits_1_with_distinct_message(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Piped empty stdin uses the same refusal as an empty file."""
    monkeypatch.setattr(sys, "stdin", _FakeStdin(b""))
    code = main(["check", "-"])
    _out, _err, text = _combined(capsys)
    assert code == 1
    assert EMPTY_MESSAGE in text
    assert "sesslint repair" not in text


def test_empty_message_is_color_free(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The empty-input line has no ANSI codes with or without color forced on."""
    empty = tmp_path / "empty.jsonl"
    empty.write_bytes(b"")
    monkeypatch.delenv("NO_COLOR", raising=False)
    code = main(["check", str(empty), "--color", "always"])
    out, _err, _text = _combined(capsys)
    assert code == 1
    assert out == f"{EMPTY_MESSAGE}\n"
    assert "\033" not in out

    monkeypatch.setenv("NO_COLOR", "1")
    code_nc = main(["check", str(empty), "--color", "always"])
    out_nc, _err_nc, _text_nc = _combined(capsys)
    assert code_nc == 1
    assert out_nc == out


def test_malformed_color_and_repair_hint_unchanged(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Malformed content still renders a colored finding and a repair hint."""
    monkeypatch.delenv("NO_COLOR", raising=False)
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{not json\n{"id":"evt_ok"}\n', encoding="utf-8")
    code = main(["check", str(bad), "--format", "canonical", "--color", "always"])
    out, _err, _text = _combined(capsys)
    assert code == 1
    assert "\033" in out
    assert MALFORMED_MESSAGE in out
    assert EMPTY_MESSAGE not in out
    assert "sesslint repair" in out
