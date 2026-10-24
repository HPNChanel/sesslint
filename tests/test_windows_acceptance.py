"""T-12: portable package integrity and failure before executable startup."""

import hashlib
import json
import os
import shutil
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
        assert len(contract["cases"]) == len({case["id"] for case in contract["cases"]}) == 42
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


# ---------------------------------------------------------------------------
# PowerShell driver: contract dates stay strings; paths resolve against $PWD
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[1]
DRIVER = REPO_ROOT / "scripts" / "Test-SessLint.ps1"
CONTRACT = REPO_ROOT / "scripts" / "smoke_contract.json"

JSON_PROBE = r"""
function Json($Value) { return ConvertTo-Json -InputObject $Value -Depth 100 -Compress }
$contract = [IO.File]::ReadAllText($args[0], [Text.Encoding]::UTF8) | ConvertFrom-Json @JsonParams
$original = @($contract.cases | Where-Object { $_.id -eq 'outcome' })[0]
$case = (Json $original).Replace('{work}', 'W') | ConvertFrom-Json @JsonParams
$at = @($case.args)[[array]::IndexOf(@($case.args), '--as-of') + 1]
Write-Output ('as_of=' + $at.GetType().Name + ':' + $at)
"""


def _shell(name: str) -> str:
    if name == "powershell":
        windows = Path(os.environ.get("SystemRoot", "C:/Windows"))
        found = windows / "System32/WindowsPowerShell/v1.0/powershell.exe"
        path = str(found) if found.is_file() else None
    else:
        path = shutil.which("pwsh")
    if path is None:
        pytest.skip(f"{name} is not installed")
    return path


def _driver_text() -> str:
    return DRIVER.read_text(encoding="utf-8")


def _guard_block() -> str:
    text = _driver_text()
    return text[text.index("# BEGIN json-date-guard") : text.index("# END json-date-guard")]


def test_every_driver_json_read_goes_through_the_date_guard() -> None:
    text = _driver_text()
    body = text[text.index("# END json-date-guard") :]
    reads = [
        line
        for line in body.splitlines()
        if "ConvertFrom-Json" in line and not line.lstrip().startswith("#")
    ]
    assert len(reads) >= 4
    assert all("ConvertFrom-Json @JsonParams" in line for line in reads), reads
    assert "-DateKind" not in body  # supplied only through the guarded splat
    assert "'DateKind'" in _guard_block() and "exit 2" in _guard_block()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell and pwsh probes")
@pytest.mark.parametrize("shell", ["powershell", "pwsh"])
def test_driver_keeps_contract_dates_as_strings(shell, tmp_path):
    expected = next(
        case["args"][case["args"].index("--as-of") + 1]
        for case in json.loads(CONTRACT.read_text(encoding="utf-8"))["cases"]
        if case["id"] == "outcome"
    )
    probe = tmp_path / "probe.ps1"
    probe.write_text(_guard_block() + JSON_PROBE, encoding="utf-8", newline="\n")
    result = subprocess.run(
        [_shell(shell), "-NoProfile", "-NonInteractive", "-File", str(probe), str(CONTRACT)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode == 2 and "cannot run on PowerShell" in result.stderr:
        pytest.skip("PowerShell 6.0 to 7.4: the driver refuses to run (checked below)")
    assert result.returncode == 0, result.stderr
    assert f"as_of=String:{expected}" in result.stdout, result.stdout


@pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell and pwsh probes")
@pytest.mark.parametrize("shell", ["powershell", "pwsh"])
def test_driver_refuses_powershell_that_cannot_keep_dates(shell, tmp_path):
    # Simulate PowerShell 6.0-7.4 (ConvertFrom-Json without -DateKind) by renaming the probed
    # parameter: Core must refuse with exit 2 and never reach the JSON reads; 5.1 never converts.
    guard = _guard_block()
    assert guard.count("ContainsKey('DateKind')") == 1
    probe = tmp_path / "probe.ps1"
    probe.write_text(
        guard.replace("ContainsKey('DateKind')", "ContainsKey('NoSuchParameter')") + JSON_PROBE,
        encoding="utf-8",
        newline="\n",
    )
    result = subprocess.run(
        [_shell(shell), "-NoProfile", "-NonInteractive", "-File", str(probe), str(CONTRACT)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if shell == "powershell":
        assert result.returncode == 0, result.stderr
        assert "as_of=String:" in result.stdout
    else:
        assert result.returncode == 2, (result.returncode, result.stderr)
        assert "5.1" in result.stderr and "7.5" in result.stderr
        assert "as_of=" not in result.stdout


@pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell and pwsh probes")
@pytest.mark.parametrize("shell", ["powershell", "pwsh"])
def test_driver_resolves_relative_paths_against_the_callers_location(shell, tmp_path):
    # Set-Location changes $PWD but not the process directory ([IO.Path]::GetFullPath uses that).
    process_dir = tmp_path / "process dir"
    caller_dir = tmp_path / "caller dir"
    process_dir.mkdir()
    caller_dir.mkdir()
    command = (
        f"Set-Location -LiteralPath '{caller_dir}'; "
        f"& '{DRIVER}' -PackageRoot . -ReceiptPath 'receipt.json'"
    )
    result = subprocess.run(
        [_shell(shell), "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=process_dir,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode == 2 and "cannot run on PowerShell" in result.stderr:
        pytest.skip("PowerShell 6.0 to 7.4: the driver refuses to run")
    assert (caller_dir / "receipt.json").is_file(), result.stderr
    assert not (process_dir / "receipt.json").exists()
    data = json.loads((caller_dir / "receipt.json").read_text(encoding="utf-8"))
    assert data["status"] == "FAIL" and data["checks"] == []  # empty folder: no manifest
