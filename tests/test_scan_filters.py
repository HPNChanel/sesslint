"""Tests for scan scope filters: ``--exclude`` globs and ``--ext`` allowlists.

Filters only apply during directory walks — an explicitly named path is
always inspected. Excluded entries emit no result at all (out of scope).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.cli import main
from sesslint.scan import scan_path

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
CORRUPT = FIXTURES / "adapters" / "codex" / "orphan_output.jsonl"  # SL101


def _tree(tmp_path: Path) -> Path:
    import shutil

    root = tmp_path / "tree"
    (root / "nested").mkdir(parents=True)
    shutil.copy(CORRUPT, root / "rollout.jsonl")
    shutil.copy(CORRUPT, root / "nested" / "deep.jsonl")
    (root / "data.json").write_text('{"x":1}', encoding="utf-8")
    (root / "notes.txt").write_text("hello", encoding="utf-8")
    return root


def test_no_filter_scans_everything(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    rep = scan_path(root, recursive=True)
    assert rep.totals.total == 4


def test_ext_allowlist(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    rep = scan_path(root, recursive=True, ext=[".jsonl"])
    assert rep.totals.total == 2
    assert rep.totals.invalid == 2


def test_ext_accepts_bare_names(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    rep = scan_path(root, recursive=True, ext=["jsonl"])
    assert rep.totals.total == 2


def test_exclude_dir(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    rep = scan_path(root, recursive=True, exclude=["nested"])
    assert rep.totals.total == 3
    assert all("nested" not in f.path for f in rep.files)


def test_exclude_glob(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    rep = scan_path(root, recursive=True, exclude=["*.jsonl"])
    assert rep.totals.total == 2
    assert all(not f.path.endswith(".jsonl") for f in rep.files)


def test_exclude_relative_path(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    rep = scan_path(root, recursive=True, exclude=["nested/deep.jsonl"])
    assert rep.totals.total == 3
    assert not any(f.path.endswith("deep.jsonl") for f in rep.files)


def test_cli_exclude_and_ext(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _tree(tmp_path)
    code = main(["scan", str(root), "--ext", ".jsonl", "--exclude", "nested", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["totals"]["total"] == 1
    assert data["totals"]["invalid"] == 1
    assert code == 1


def test_config_exclude_and_ext(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _tree(tmp_path)
    (tmp_path / "sesslint.toml").write_text(
        'ext = [".jsonl"]\nexclude = ["nested"]\n', encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    code = main(["scan", str(root), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["totals"]["total"] == 1
    assert code == 1
