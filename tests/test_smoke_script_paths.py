"""Smoke scripts must keep venv interpreter symlinks unresolved."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from scripts.installed_smoke import absolute


@pytest.mark.skipif(os.name == "nt", reason="symlink creation needs privileges on Windows")
def test_absolute_does_not_follow_interpreter_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = tmp_path / "base" / "python"
    base.parent.mkdir()
    base.write_text("", encoding="utf-8")
    link = tmp_path / "venv" / "bin" / "python"
    link.parent.mkdir(parents=True)
    link.symlink_to(base)
    monkeypatch.chdir(tmp_path)
    result = absolute(Path("venv/bin/python"))
    assert result == link
    assert result.is_absolute()
    assert result.is_symlink()
