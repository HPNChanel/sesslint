"""Tests for multi-path ``sesslint check`` and ``--skip-undetected``.

The pre-commit hook appends every staged filename to one invocation, so check
accepts N paths and emits one aggregated ScanReport. ``--skip-undetected``
reclassifies format-undetected files (e.g. package.json) as ``skipped``
instead of ``invalid`` so non-session JSON does not fail hooks.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.cli import main

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
HEALTHY = FIXTURES / "canonical" / "minimal.json"
CORRUPT = FIXTURES / "adapters" / "codex" / "orphan_output.jsonl"


def _write_json(path: Path, obj: dict) -> None:
    path.write_text(json.dumps(obj), encoding="utf-8")


def test_multi_path_aggregates_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    plain = tmp_path / "package.json"
    _write_json(plain, {"name": "pkg", "version": "1.0.0"})
    code = main(
        [
            "check",
            "--skip-undetected",
            str(HEALTHY),
            str(plain),
            str(CORRUPT),
            "--json",
        ]
    )
    data = json.loads(capsys.readouterr().out)
    assert data["schema_version"] == "sesslint.scan-report/v1"
    assert data["totals"]["healthy"] == 1
    assert data["totals"]["invalid"] == 1
    assert data["totals"]["skipped"] == 1
    assert data["totals"]["total"] == 3
    assert code == 1


def test_multi_path_all_clean(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    plain = tmp_path / "other.json"
    _write_json(plain, {"x": 1})
    code = main(["check", "--skip-undetected", str(HEALTHY), str(plain)])
    out = capsys.readouterr().out
    assert "skipped" in out.lower() or "HEALTHY" in out
    assert code == 0


def test_multi_path_missing_path_fails(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["check", str(HEALTHY), "does-not-exist.jsonl"])
    assert code == 2
    assert "not found" in capsys.readouterr().err.lower()


def test_multi_path_dir_requires_recursive(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["check", str(HEALTHY), str(tmp_path)])
    assert code == 2
    assert "directory" in capsys.readouterr().err.lower()


def test_multi_path_dir_with_recursive(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["check", "-r", str(HEALTHY), str(tmp_path), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["totals"]["total"] >= 1
    assert code in (0, 1)


def test_single_path_skip_undetected(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    plain = tmp_path / "plain.json"
    _write_json(plain, {"unrelated": True})
    code = main(["check", "--skip-undetected", str(plain)])
    assert code == 0
    assert "skipped" in capsys.readouterr().err.lower()


def test_single_path_undetected_fails_without_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plain = tmp_path / "plain.json"
    _write_json(plain, {"unrelated": True})
    code = main(["check", str(plain)])
    assert code == 1


def test_scan_skip_undetected_mixed_tree(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plain = tmp_path / "data.json"
    _write_json(plain, {"a": 1})
    code = main(["scan", str(tmp_path), "--skip-undetected", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["totals"]["skipped"] == 1
    assert data["totals"]["invalid"] == 0
    assert code == 0


def test_scan_undetected_invalid_by_default(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plain = tmp_path / "data.json"
    _write_json(plain, {"a": 1})
    code = main(["scan", str(tmp_path), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["totals"]["invalid"] == 1
    assert code == 1
