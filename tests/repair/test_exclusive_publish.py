"""B23: publish complete repair artifacts without overwriting competing files."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import shutil
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

from sesslint import api
from sesslint.atomic import atomic_write_bytes
from sesslint.batch import repair_many
from sesslint.errors import AtomicWriteError
from sesslint.repair.errors import ManifestCollision, OutputInvalid, RepairRefused
from sesslint.repair.executor import execute

SOURCE = Path(__file__).resolve().parents[2] / "fixtures/repair/exec_basic/source.jsonl"


def _stage(tmp_path: Path) -> Path:
    src = tmp_path / "source.jsonl"
    shutil.copyfile(SOURCE, src)
    return src


def test_exclusive_atomic_write_preserves_racing_destination(tmp_path: Path) -> None:
    out = tmp_path / "output.jsonl"
    with pytest.raises(AtomicWriteError):
        atomic_write_bytes(
            out,
            b"ours",
            overwrite=False,
            pre_rename_hook=lambda _tmp: out.write_bytes(b"competing-writer"),
        )
    assert out.read_bytes() == b"competing-writer"
    assert not list(tmp_path.glob(".sesslint*"))


def test_repair_preserves_racing_output_and_removes_own_receipt(tmp_path: Path) -> None:
    src = _stage(tmp_path)
    before = src.read_bytes()
    out = tmp_path / "out.jsonl"
    with pytest.raises(OutputInvalid):
        execute(
            source_path=src,
            plan=api.plan_repair(src),
            output_path=out,
            pre_rename_hook=lambda _tmp: out.write_bytes(b"competing-writer"),
        )
    assert out.read_bytes() == b"competing-writer"
    assert src.read_bytes() == before
    assert not Path(f"{out}.manifest.json").exists()
    assert not list(tmp_path.glob(".sesslint*"))


@pytest.mark.parametrize("sidecar", [False, True], ids=["output", "manifest"])
def test_dangling_symlink_is_an_existing_destination(tmp_path: Path, sidecar: bool) -> None:
    src = _stage(tmp_path)
    out = tmp_path / "out.jsonl"
    target = Path(f"{out}.manifest.json") if sidecar else out
    try:
        target.symlink_to(tmp_path / "missing.jsonl")
    except OSError:
        pytest.skip("This host does not grant symlink creation")
    with pytest.raises(ManifestCollision if sidecar else RepairRefused):
        api.repair(src, out)
    assert target.is_symlink()
    assert not (tmp_path / "missing.jsonl").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows no-replace rename fallback")
def test_windows_repair_works_without_hardlinks(tmp_path: Path) -> None:
    src = _stage(tmp_path)
    out = tmp_path / "out.jsonl"
    with patch("os.link", side_effect=OSError(errno.ENOTSUP, "No hard links")):
        _, manifest = api.repair(src, out)
    assert out.is_file()
    assert manifest is not None
    assert Path(f"{out}.manifest.json").is_file()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_repair_preserves_source_permissions(tmp_path: Path) -> None:
    src = _stage(tmp_path)
    src.chmod(0o640)
    out = tmp_path / "out.jsonl"
    api.repair(src, out)
    assert stat.S_IMODE(out.stat().st_mode) == 0o640


def test_batch_existing_relocated_receipt_is_preserved(tmp_path: Path) -> None:
    src = _stage(tmp_path)
    receipts = tmp_path / "receipts"
    receipts.mkdir()
    digest = hashlib.sha256(str(src.resolve()).encode()).hexdigest()
    existing = receipts / f"{digest}.manifest.json"
    existing.write_bytes(b"previous-receipt")
    out_dir = tmp_path / "outputs"
    report = repair_many([src], output_dir=out_dir, manifest_dir=receipts)
    assert report.repaired == 1
    assert report.rows[0].reason == "manifest-relocation-refused"
    assert existing.read_bytes() == b"previous-receipt"
    assert (out_dir / "source.repaired.jsonl.manifest.json").is_file()


def test_vendor_canonical_header_uses_source_event_timestamp(tmp_path: Path) -> None:
    src = tmp_path / "vendor.jsonl"
    record = {
        "type": "user",
        "uuid": "u1",
        "timestamp": "2030-04-05T06:07:08Z",
        "message": {"role": "user", "content": "synthetic"},
    }
    src.write_bytes((json.dumps(record) + "\n").encode())
    out = tmp_path / "canonical.jsonl"
    api.repair(src, out, format="claude-code-jsonl", emit="canonical")
    header = json.loads(out.read_bytes().split(b"\n")[0])
    assert header["created_at"] == record["timestamp"]
    assert header["metadata"]["created_at_source"] == "first_event"
