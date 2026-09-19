"""Tests for batch repair driven by per-file plan eligibility (repair-engine T-02)."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from sesslint import api
from sesslint.batch import (
    repair_many,
    resolve_scan_report_files,
)
from sesslint.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "repair_cli"
BASIC_SRC = FIXTURES_DIR / "basic" / "source.jsonl"
CLEAN_SRC = FIXTURES_DIR.parent / "repair" / "exec_basic" / "expected_output.jsonl"


def _tree(tmp_path: Path) -> Path:
    """Synthetic tree: 2 repairable, 1 clean, 1 undetectable."""
    tree = tmp_path / "in"
    (tree / "sub").mkdir(parents=True)
    shutil.copyfile(BASIC_SRC, tree / "a.jsonl")
    shutil.copyfile(BASIC_SRC, tree / "sub" / "b.jsonl")
    shutil.copyfile(CLEAN_SRC, tree / "clean.jsonl")
    (tree / "garbage.jsonl").write_bytes(b"not json at all\n{{{")
    return tree


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def test_batch_dir_repairs_only_eligible(tmp_path: Path) -> None:
    """Mixed-eligibility tree: deterministic files repaired, rest skipped."""
    tree = _tree(tmp_path)
    out_dir = tmp_path / "out"
    report = repair_many(
        [tree / "a.jsonl", tree / "sub" / "b.jsonl", tree / "clean.jsonl", tree / "garbage.jsonl"],
        output_dir=out_dir,
        common_root=tree,
    )
    assert report.repaired == 2
    assert report.skipped == 2
    # Mirrored structure preserved.
    assert (out_dir / "a.repaired.jsonl").is_file()
    assert (out_dir / "sub" / "b.repaired.jsonl").is_file()
    # Skipped rows carry reasons.
    by_outcome = {r.outcome for r in report.rows}
    assert by_outcome == {"repaired", "skipped"}


def test_batch_cli_mirrors_structure_and_manifest_dir(tmp_path: Path) -> None:
    """--batch mirrors input tree; --manifest-dir gets sha8-named manifests."""
    tree = _tree(tmp_path)
    out_dir, man_dir = tmp_path / "out", tmp_path / "man"
    code = main(
        [
            "repair",
            "--batch",
            str(tree),
            "--output-dir",
            str(out_dir),
            "--manifest-dir",
            str(man_dir),
        ]
    )
    assert code == 1  # skipped files -> honest partial
    assert (out_dir / "a.repaired.jsonl").is_file()
    assert (out_dir / "sub" / "b.repaired.jsonl").is_file()
    mans = list(man_dir.glob("*.manifest.json"))
    assert len(mans) == 2
    for m in mans:
        doc = json.loads(m.read_text(encoding="utf-8"))
        assert "output_fingerprint" in doc


def test_batch_cli_all_eligible_exit_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """All-eligible batch exits 0."""
    tree = tmp_path / "in"
    tree.mkdir()
    shutil.copyfile(BASIC_SRC, tree / "a.jsonl")
    code = main(["repair", "--batch", str(tree), "--output-dir", str(tmp_path / "out")])
    assert code == 0
    out = capsys.readouterr().out
    assert "1 repaired" in out


def test_batch_files_mode_flat(tmp_path: Path) -> None:
    """--files writes flat outputs with adjacent manifests by default."""
    tree = _tree(tmp_path)
    out_dir = tmp_path / "of"
    code = main(
        [
            "repair",
            "--files",
            str(tree / "a.jsonl"),
            str(tree / "sub" / "b.jsonl"),
            "--output-dir",
            str(out_dir),
        ]
    )
    assert code == 0
    assert (out_dir / "a.repaired.jsonl").is_file()
    assert (out_dir / "b.repaired.jsonl").is_file()
    assert (out_dir / "a.repaired.jsonl.manifest.json").is_file()


def test_batch_dry_run_preview_no_writes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """--batch --dry-run reports eligibility without writing anything."""
    tree = _tree(tmp_path)
    out_dir = tmp_path / "od"
    code = main(["repair", "--batch", str(tree), "--output-dir", str(out_dir), "--dry-run"])
    assert code == 1  # clean+garbage skipped -> partial
    assert not out_dir.exists()
    out = capsys.readouterr().out
    assert "eligible" in out


def test_batch_from_scan_report(tmp_path: Path) -> None:
    """--from-scan resolves ~/ paths; unresolvable minimized entries are skipped."""
    tree = _tree(tmp_path)
    rep = tmp_path / "scan.json"
    code = (
        main(
            ["scan", str(tree), "--json", "--output-format", "json"],
        )
        if False
        else None
    )
    # Build a synthetic scan report: one resolvable absolute path + one .._hash entry.
    rep.write_text(
        json.dumps(
            {
                "files": [
                    {"path": str(tree / "a.jsonl"), "verdict": "invalid", "findings": []},
                    {"path": ".._deadbeef/ghost.jsonl", "verdict": "invalid", "findings": []},
                ]
            }
        ),
        encoding="utf-8",
    )
    code = main(["repair", "--from-scan", str(rep), "--output-dir", str(tmp_path / "os")])
    assert code == 1  # unresolvable entry -> skipped -> partial
    assert (tmp_path / "os" / "a.repaired.jsonl").is_file()


def test_resolve_scan_report_files(tmp_path: Path) -> None:
    """Resolution: ~/, absolute -> Path; .._hash -> unresolvable."""
    rep = tmp_path / "r.json"
    rep.write_text(
        json.dumps(
            {
                "files": [
                    {"path": "~/sess/x.jsonl"},
                    {"path": str(tmp_path / "y.jsonl")},
                    {"path": ".._aabbccdd/z.jsonl"},
                ]
            }
        ),
        encoding="utf-8",
    )
    files, unresolvable = resolve_scan_report_files(rep)
    assert len(files) == 2
    assert unresolvable == [".._aabbccdd/z.jsonl"]


def test_batch_deterministic(tmp_path: Path) -> None:
    """Two identical batch runs produce identical tree bytes and summaries."""
    tree = _tree(tmp_path)
    r1 = repair_many(
        [tree / "a.jsonl", tree / "sub" / "b.jsonl"],
        output_dir=tmp_path / "d1",
        common_root=tree,
    )
    r2 = repair_many(
        [tree / "a.jsonl", tree / "sub" / "b.jsonl"],
        output_dir=tmp_path / "d2",
        common_root=tree,
    )
    # Rows agree on path/outcome/codes/reason; output+manifest fields embed
    # the (deliberately different) destination dirs, so compare modulo those.
    strip = ("output", "manifest")
    rows1 = [{k: v for k, v in r.items() if k not in strip} for r in r1.to_dict()["rows"]]
    rows2 = [{k: v for k, v in r.items() if k not in strip} for r in r2.to_dict()["rows"]]
    assert rows1 == rows2
    t1 = {p.name: _sha(p) for p in (tmp_path / "d1").rglob("*") if p.is_file()}
    t2 = {p.name: _sha(p) for p in (tmp_path / "d2").rglob("*") if p.is_file()}
    assert t1 == t2


def test_batch_json_summary_shape(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """--json emits sesslint.batch-repair/v1 with counts and rows."""
    tree = _tree(tmp_path)
    code = main(["repair", "--batch", str(tree), "--output-dir", str(tmp_path / "oj"), "--json"])
    assert code == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "sesslint.batch-repair/v1"
    assert doc["counts"] == {"attempted": 2, "repaired": 2, "refused": 0, "skipped": 2}
    for row in doc["rows"]:
        assert row["outcome"] in {"repaired", "skipped"}
        assert "payload" not in json.dumps(row)


@pytest.mark.parametrize(
    "argv,frag",
    [
        (["repair", "--batch", "d", "--files", "f", "--output-dir", "o"], "mutually exclusive"),
        (["repair", "--files", "f", "--output-dir", "o", "--output", "x"], "--output-dir"),
        (["repair", "--batch", "d"], "--output-dir"),
        (["repair", "--batch", "d", "--output-dir", "o", "--plan-out", "p"], "single-file"),
    ],
)
def test_batch_usage_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], argv: list[str], frag: str
) -> None:
    """Batch mode conflicts are usage errors (exit 2)."""
    code = main(argv)
    assert code == 2
    assert frag in capsys.readouterr().err


def test_repair_no_source_is_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    """Bare `repair` with neither path nor batch source is a usage error."""
    assert main(["repair"]) == 2
    assert "source path" in capsys.readouterr().err


def test_batch_report_counts(tmp_path: Path) -> None:
    """BatchRepairReport counts are derived from rows deterministically."""
    report = repair_many(
        [tmp_path / "missing.jsonl"],
        output_dir=tmp_path / "o",
    )
    assert report.skipped == 1
    assert report.attempted == 0

    d = report.to_dict()
    assert d["rows"][0]["reason"] == "source-missing"


def test_api_repair_many_exported() -> None:
    """api.repair_many is the public batch entry point."""
    assert api.repair_many is not None
    assert "repair_many" in api.__all__
    assert "BatchRepairReport" in api.__all__
