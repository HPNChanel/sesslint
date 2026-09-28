"""T-12: deterministic transferable acceptance ZIP; build-time only."""

import argparse
import hashlib
import json
import zipfile
from pathlib import Path


def build(binary: Path, kit: Path, target: Path, version: str, commit: str) -> None:
    if not binary.name.startswith(f"sesslint-{version}-windows-") or binary.suffix != ".exe":
        raise ValueError("Wrong Windows binary identity")
    files = {
        binary.name: binary.read_bytes(),
        kit.name: kit.read_bytes(),
        "Test-SessLint.ps1": Path(__file__).with_name("Test-SessLint.ps1").read_bytes(),
        "START_HERE.md": (
            "# SessLint portable Windows acceptance\n\n"
            f"Version: {version}. Source identity: {commit}.\n\n"
            "Verify this ZIP's SHA-256 against the delivery checksum before extracting.\n"
            "Open Windows PowerShell 5.1+ in the extracted folder and run:\n\n"
            "```powershell\n"
            '.\\Test-SessLint.ps1 -PackageRoot . -ReceiptPath "$PWD\\acceptance.json"\n'
            "```\n\n"
            "The runner needs no Python, administrator rights, network or system changes.\n"
            "It verifies files, relocates the EXE into a Unicode/spaced temporary folder,\n"
            "isolates agent roots, then runs the same 32 cases as the Python smoke.\n"
            "Each run needs a new receipt path; logs and synthetic work files are retained.\n"
            "See kit/QUICKSTART.md for check -> plan -> repair -> verify and refusal guidance.\n\n"
            "To run the walkthrough manually from this extracted folder:\n\n"
            "```powershell\n"
            f"$SessLint = Join-Path $PWD '{binary.name}'\n"
            "Set-Location kit\n"
            "function sesslint { & $SessLint @args }\n"
            "sesslint check examples/healthy.jsonl --json\n"
            "```\n\n"
            "A functional PASS is not proof that the host is a clean Windows installation.\n"
            "For clean-host acceptance, run this exact ZIP on a known clean machine/VM\n"
            "without Python, retain its provisioning/image evidence and these receipts.\n"
            "No Python on PATH alone does not qualify. Any changed EXE hash requires retesting.\n"
            "Return acceptance.json and acceptance.json.logs for review;\n"
            "no real sessions are needed.\n"
        ).encode(),
    }
    with zipfile.ZipFile(kit) as archive:
        for member in archive.infolist():
            if member.is_dir():
                continue
            name = member.filename
            if ".." in Path(name).parts or name.startswith(("/", "\\")) or ":" in name:
                raise ValueError("Unsafe starter-kit path")
            files["kit/" + name] = archive.read(member)
    if files["kit/VERSION"].decode().strip() != version:
        raise ValueError("Starter-kit version mismatch")
    manifest = {
        "schema_version": 1,
        "version": version,
        "commit": commit,
        "binary": binary.name,
        "starter_kit": kit.name,
        "files": {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())},
    }
    files["windows-acceptance.json"] = (
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    ).encode()
    files["SHA256SUMS"] = "".join(
        f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in sorted(files.items())
    ).encode()
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "x") as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "kit", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    build(args.binary, args.kit, args.output, args.version, args.commit)
