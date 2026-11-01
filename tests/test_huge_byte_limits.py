"""CL-16: byte-limit flags larger than ``sys.maxsize`` never overflow ``read``.

``--max-file-bytes`` is an unbounded integer; ``stream.read(limit + 1)``
raised ``OverflowError`` past ``sys.maxsize`` and surfaced as an internal error.
"""

from __future__ import annotations

import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from sesslint import api
from sesslint.cli import main
from sesslint.io import read_limit_plus_one
from sesslint.triage import triage

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "claude_code" / "basic.jsonl"
HUGE = 10**23


def test_read_limit_plus_one_clamps() -> None:
    assert read_limit_plus_one(io.BytesIO(b"abc"), HUGE) == b"abc"
    assert read_limit_plus_one(io.BytesIO(b"abc"), 1) == b"ab"


def test_library_entry_points_accept_huge_limits() -> None:
    assert api.check_file(FIXTURE, max_file_bytes=HUGE).findings == ()
    assert triage(FIXTURE, max_file_bytes=HUGE).status == "checked"


@pytest.mark.parametrize("command", ["check", "triage"])
def test_cli_huge_max_file_bytes_is_not_an_internal_error(command: str) -> None:
    out = io.StringIO()
    with redirect_stdout(out):
        code = main([command, str(FIXTURE), "--max-file-bytes", str(HUGE), "-f", "json"])
    assert code == 0
    assert "INTERNAL_ERROR" not in out.getvalue()
    json.loads(out.getvalue())


def test_cli_stdin_huge_max_file_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    stdin = io.TextIOWrapper(io.BytesIO(FIXTURE.read_bytes()), encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", stdin)
    out = io.StringIO()
    with redirect_stdout(out):
        code = main(["check", "-", "--max-file-bytes", str(HUGE), "-f", "json"])
    assert code == 0
    assert "INTERNAL_ERROR" not in out.getvalue()
