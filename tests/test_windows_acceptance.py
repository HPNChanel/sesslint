"""T-12: portable package integrity and failure before executable startup."""

import hashlib
import json
import subprocess
import sys
import zipfile

import pytest
from scripts.build_starter_kit import build as build_kit
from scripts.build_windows_acceptance import build


def package(tmp_path):
    binary = tmp_path / "sesslint-0.4.1-windows-x86_64.exe"
    binary.write_bytes(b"Synthetic bytes: never executable")
    kit = tmp_path / "sesslint-0.4.1-starter-kit.zip"
    build_kit(kit, "0.4.1")
    return binary, kit


def test_portable_build_reproducibility_and_bound_members(tmp_path):
    binary, kit = package(tmp_path)
    left, right = tmp_path / "left.zip", tmp_path / "right.zip"
    build(binary, kit, left, "0.4.1", "synthetic-commit")
    build(binary, kit, right, "0.4.1", "synthetic-commit")
    assert left.read_bytes() == right.read_bytes()
    with zipfile.ZipFile(left) as archive:
        manifest = json.loads(archive.read("windows-acceptance.json"))
        for name, expected in manifest["files"].items():
            assert hashlib.sha256(archive.read(name)).hexdigest() == expected
        contract = json.loads(archive.read("kit/smoke-contract.json"))
        assert len(contract["cases"]) == len({case["id"] for case in contract["cases"]}) == 32
        assert archive.read("kit/NOTICE") and archive.read("kit/LICENSE")
    with pytest.raises(FileExistsError):
        build(binary, kit, left, "0.4.1", "synthetic-commit")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell acceptance")
@pytest.mark.parametrize("mutation", ["corrupt", "missing", "missing-checksum", "version"])
def test_powershell_refuses_package_before_running_binary(mutation, tmp_path):
    import os
    from pathlib import Path

    binary, kit = package(tmp_path)
    output = tmp_path / "package.zip"
    build(binary, kit, output, "0.4.1", "synthetic-commit")
    root = tmp_path / "portable"
    with zipfile.ZipFile(output) as archive:
        archive.extractall(root)
    target = root / binary.name
    if mutation == "corrupt":
        target.write_bytes(b"changed")
    elif mutation == "missing":
        target.unlink()
    else:
        manifest_path = root / "windows-acceptance.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if mutation == "missing-checksum":
            del manifest["files"][binary.name]
        else:
            manifest["version"] = "0.4.2"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    receipt = tmp_path / "result.json"
    powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    result = subprocess.run(
        [
            str(powershell),
            "-NoProfile",
            "-File",
            str(root / "Test-SessLint.ps1"),
            "-PackageRoot",
            str(root),
            "-ReceiptPath",
            str(receipt),
        ],
        capture_output=True,
        timeout=60,
    )
    assert result.returncode != 0
    data = json.loads(receipt.read_text(encoding="utf-8"))
    assert data["status"] == "FAIL" and data["checks"] == []
    assert "work_directory" not in data  # Failed integrity check precedes relocation/startup.
