"""Regression (CL-17): a single-file check with a hostile file name must not abort.

A name with control characters used to reach ``SourceRef`` raw and exit 2 with a
usage message. It now degrades to the same redacted label the scan path uses.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from sesslint import api
from sesslint.cli import main

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "cli" / "check_basic" / "healthy.jsonl"
NAMES = ["a\x1bb.jsonl", "a\nFORGED.jsonl", "a\x01b.jsonl", "a‮b.jsonl"]


@pytest.mark.parametrize("name", NAMES)
def test_check_file_with_hostile_name_succeeds(tmp_path: Path, name: str) -> None:
    target = tmp_path / name
    try:
        target.write_bytes(FIXTURE.read_bytes())
    except OSError:
        pytest.skip("file system rejects the name")
    report = api.check_file(target)
    assert not report.findings
    assert name not in json.dumps(report.to_dict())

    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(["check", str(target), "-f", "json"])
    assert code == 0, err.getvalue()
    assert "\x1b" not in out.getvalue() + err.getvalue()


def test_baseline_error_does_not_echo_entry_content(tmp_path: Path) -> None:
    """Regression (CL-17): a rejected baseline value is described, never echoed."""
    secret = "Bearer QWERTYUIOPASDFGHJKLZXCVBNM123456"
    for doc in (
        {"schema_version": "sesslint.baseline/v1", "fingerprints": [secret]},
        {"schema_version": "sesslint.baseline/v2", "entries": [secret]},
        {"schema_version": "sesslint.baseline/v2", "entries": [{"key": secret}]},
    ):
        baseline = tmp_path / "bl.json"
        baseline.write_text(json.dumps(doc), encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["check", str(FIXTURE), "--baseline", str(baseline), "-f", "json"])
        text = out.getvalue() + err.getvalue()
        assert code == 2
        assert "QWERTYUIOP" not in text
        assert "got str of length" in text or "got dict" in text
