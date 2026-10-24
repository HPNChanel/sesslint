"""Path aliases must preserve venv identity and smoke archive containment."""

from __future__ import annotations

import os
import zipfile
from contextlib import nullcontext
from pathlib import Path

import pytest
from scripts import installed_smoke
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


@pytest.mark.skipif(os.name == "nt", reason="symlink creation needs privileges on Windows")
@pytest.mark.parametrize("member", ["safe.txt", "../escape.txt"])
def test_archive_containment_under_aliased_temp_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, member: str
) -> None:
    """Accept an aliased temp root while still refusing an escaping member."""
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    kit = tmp_path / "kit.zip"
    with zipfile.ZipFile(kit, "w") as archive:
        archive.writestr(member, "synthetic")
    artifact = tmp_path / "unused-python"
    artifact.write_bytes(b"synthetic; must not execute")
    monkeypatch.setattr(
        installed_smoke.tempfile, "TemporaryDirectory", lambda **kwargs: nullcontext(str(alias))
    )

    def stop_before_execution(self: zipfile.ZipFile, path: Path) -> None:
        assert path == real
        raise RuntimeError("safe extraction reached")

    monkeypatch.setattr(zipfile.ZipFile, "extractall", stop_before_execution)
    if member == "safe.txt":
        with pytest.raises(RuntimeError, match="safe extraction reached"):
            installed_smoke.run(artifact, kit, python=True, version="0.5.0")
    else:
        with pytest.raises(ValueError, match="Unsafe starter kit path"):
            installed_smoke.run(artifact, kit, python=True, version="0.5.0")
    assert not (tmp_path / "escape.txt").exists()
