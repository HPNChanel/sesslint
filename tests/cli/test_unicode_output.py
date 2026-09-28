"""T-12: native Windows pipe encodings must not break Unicode paths."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("output_format", ["human", "json", "sarif", "html"])
def test_unicode_filename_with_legacy_stdout(tmp_path: Path, output_format: str) -> None:
    source = tmp_path / "phiên kiểm thử.jsonl"
    original = (ROOT / "fixtures/repair_cli/basic/source.jsonl").read_bytes()
    source.write_bytes(original)
    env = dict(os.environ, PYTHONIOENCODING="cp1252", PYTHONPATH=str(ROOT / "src"))
    result = subprocess.run(
        [
            sys.executable,
            "-X",
            "utf8=0",
            "-m",
            "sesslint",
            "check",
            str(source),
            "--output-format",
            output_format,
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8")
    output = result.stdout.decode("utf-8", errors="strict")
    assert "SL003" in output
    assert "INTERNAL_ERROR" not in output
    assert not result.stderr
    assert source.read_bytes() == original


def test_unicode_missing_path_diagnostic(tmp_path: Path) -> None:
    env = dict(os.environ, PYTHONIOENCODING="cp1252", PYTHONPATH=str(ROOT / "src"))
    result = subprocess.run(
        [sys.executable, "-X", "utf8=0", "-m", "sesslint", "check", "không tồn tại.jsonl"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 2
    assert "không tồn tại.jsonl" in result.stderr.decode("utf-8", errors="strict")
    assert b"Traceback" not in result.stderr
