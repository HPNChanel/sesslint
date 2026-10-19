"""T-12: portable package integrity and failure before executable startup."""

import hashlib
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

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
        assert len(contract["cases"]) == len({case["id"] for case in contract["cases"]}) == 40
        assert archive.read("kit/NOTICE") and archive.read("kit/LICENSE")
        assert archive.read("kit/TRIAGE.md")
        assert archive.read("kit/schemas/sesslint.triage.v1.json")
        provenance = json.loads(archive.read("kit/examples/PROVENANCE.json"))
        assert provenance["contains_real_data"] is False
        assert archive.read("kit/examples/unsupported.txt").startswith(b"Synthetic")
    with pytest.raises(FileExistsError):
        build(binary, kit, left, "0.4.1", "synthetic-commit")


def test_starter_kit_triage_contract_is_read_only_and_deterministic(tmp_path, monkeypatch):
    """Exercise shipped fixtures and assertions through the source CLI; no install claim."""
    _, kit = package(tmp_path)
    work = tmp_path / "synthetic work"
    with zipfile.ZipFile(kit) as archive:
        archive.extractall(work)
    contract = json.loads((work / "smoke-contract.json").read_text(encoding="utf-8"))
    cases = [case for case in contract["cases"] if case["id"].startswith("triage-")]
    assert len(cases) == 8
    assert {case["id"] for case in cases} == {
        f"triage-{name}{suffix}"
        for name in ("healthy", "repairable", "refused", "unsupported")
        for suffix in ("", "-repeat")
    }
    monkeypatch.setenv("SESSLINT_CONFIG", str(tmp_path / "must-not-read.toml"))
    monkeypatch.setenv("SESSLINT_PROFILE", "must-not-use-host-profile")
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("PYTHON", "COVERAGE", "SESSLINT_"))
    }
    env["PYTHONUTF8"] = "1"
    for key in (
        "HOME",
        "USERPROFILE",
        "CODEX_HOME",
        "CLAUDE_CONFIG_DIR",
        "APPDATA",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
        "XDG_CACHE_HOME",
    ):
        isolated = work / "isolated" / key
        isolated.mkdir(parents=True)
        env[key] = str(isolated)

    def snapshot():
        return {
            path.relative_to(work): (path.read_bytes(), path.stat().st_mtime_ns)
            if path.is_file()
            else None
            for path in work.rglob("*")
        }

    before = snapshot()
    outputs = {}
    for case in cases:
        assert case["no_writes"] is True
        result = subprocess.run(
            [sys.executable, "-m", "sesslint", *case["args"]],
            cwd=work,
            env=env,
            capture_output=True,
            encoding="utf-8",
            timeout=30,
        )
        assert result.returncode in case["exit_codes"], result.stderr
        document = json.loads(result.stdout)
        for field, expected in case.get("json_equals", {}).items():
            value = document
            for part in field.split("."):
                value = value[int(part)] if isinstance(value, list) else value[part]
            assert value == expected, (case["id"], field)
        if "stdout_equals" in case:
            assert result.stdout == outputs[case["stdout_equals"]]
        outputs[case["id"]] = result.stdout
        assert snapshot() == before, case["id"]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell acceptance")
@pytest.mark.parametrize("mutation", ["corrupt", "missing", "missing-checksum", "version"])
def test_powershell_refuses_package_before_running_binary(mutation, tmp_path):
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
