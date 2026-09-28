#!/usr/bin/env python3
"""T-11 release-only artifact validation; never imported by the offline runtime.

Exact distribution names AND embedded metadata bind publication to a version.
Auxiliary archives are intentionally not Python distributions. Retries compare
bytes before reusing an existing file; no operation overwrites a different asset.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import tarfile
import zipfile
from email.parser import BytesParser
from pathlib import Path


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _metadata(raw: bytes, version: str) -> None:
    metadata = BytesParser().parsebytes(raw)
    if metadata.get_all("Name") != ["sesslint"] or metadata.get_all("Version") != [version]:
        raise ValueError("Distribution name/version metadata mismatch")
    if metadata.get_all("Requires-Python") != [">=3.11"]:
        raise ValueError("Requires-Python metadata mismatch")
    # Extras may have dependencies; the base install must have none.
    for requirement in metadata.get_all("Requires-Dist", []):
        marker = requirement.split(";", 1)[1].strip() if ";" in requirement else ""
        if not re.fullmatch(r"extra\s*==\s*(['\"])(dev|packaging|mutation|docs)\1", marker):
            raise ValueError("Unexpected runtime dependency")


def distributions(directory: Path, version: str) -> tuple[Path, Path]:
    """Return exactly the validated universal wheel and sdist for this version."""
    wheel = directory / f"sesslint-{version}-py3-none-any.whl"
    sdist = directory / f"sesslint-{version}.tar.gz"
    if not wheel.is_file() or not sdist.is_file():
        raise ValueError("Expected wheel and sdist are both required")
    wheels = list(directory.glob("*.whl"))
    if wheels != [wheel]:
        raise ValueError("Unexpected wheel in release set")
    with zipfile.ZipFile(wheel) as archive:
        name = f"sesslint-{version}.dist-info/METADATA"
        if archive.namelist().count(name) != 1:
            raise ValueError("Missing or duplicated wheel METADATA")
        _metadata(archive.read(name), version)
    with tarfile.open(sdist, "r:gz") as archive:
        name = f"sesslint-{version}/PKG-INFO"
        entries = [entry for entry in archive.getmembers() if entry.name == name]
        if len(entries) != 1 or not entries[0].isfile():
            raise ValueError("Missing or duplicated sdist PKG-INFO")
        stream = archive.extractfile(entries[0])
        assert stream is not None
        _metadata(stream.read(), version)
    return wheel, sdist


def immutable_copy(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if digest(source) != digest(target):
            raise ValueError(f"Refusing to replace different bytes: {target.name}")
        return
    with source.open("rb") as src, target.open("xb") as dst:
        shutil.copyfileobj(src, dst)


def stage(directory: Path, target: Path, version: str) -> None:
    selected = distributions(directory, version)
    if target.exists() and any(p.name not in {f.name for f in selected} for p in target.iterdir()):
        raise ValueError("PyPI staging directory contains auxiliary assets")
    for path in selected:
        immutable_copy(path, target / path.name)


def manifest(directory: Path, version: str, commit: str, epoch: int) -> dict:
    distributions(directory, version)
    # Path ordering folds case on Windows; release ordering must be identical
    # to canonical JSON/checksum ordering on every host.
    files = sorted((p for p in directory.iterdir() if p.is_file()), key=lambda p: p.name)
    return {
        "schema_version": 1,
        "version": version,
        "commit": commit,
        "source_date_epoch": epoch,
        "artifacts": {
            p.name: digest(p)
            for p in files
            if p.name not in {"artifact-manifest.json", "sha256sums.txt"}
            and not p.name.endswith(".sigstore.json")
        },
    }


def validate_smoke_contract(receipt: dict, raw: bytes) -> None:
    """Require every observed CLI result from the shipped shared contract."""
    contract = json.loads(raw)
    cases = contract["cases"]
    checks = receipt.get("checks", [])
    if (
        contract.get("schema_version") != 1
        or len(cases) != 32
        or len({case["id"] for case in cases}) != 32
        or receipt.get("contract_sha256") != hashlib.sha256(raw).hexdigest()
        or [row.get("id") for row in checks] != [case["id"] for case in cases]
        or any(
            row.get("command") != case["args"] or row.get("exit_code") not in case["exit_codes"]
            for row, case in zip(checks, cases, strict=True)
        )
    ):
        raise ValueError("Installed receipt does not cover the shared 32-case contract")


def verify(directory: Path, *, complete: bool = False) -> dict:
    data = json.loads((directory / "artifact-manifest.json").read_text(encoding="utf-8"))
    for name, expected in data["artifacts"].items():
        if Path(name).name != name or digest(directory / name) != expected:
            raise ValueError("Artifact manifest hash mismatch")
    expected_sums = "".join(
        f"{value}  {name}\n" for name, value in sorted(data["artifacts"].items())
    )
    if (directory / "sha256sums.txt").read_text(encoding="utf-8") != expected_sums:
        raise ValueError("Checksum file does not match artifact manifest")
    version = data["version"]
    distributions(directory, version)
    if complete:
        names = set(data["artifacts"])
        if f"sesslint-{version}-starter-kit.zip" not in names:
            raise ValueError("Missing user delivery archive")
        with zipfile.ZipFile(directory / f"sesslint-{version}-starter-kit.zip") as kit:
            contract_raw = kit.read("smoke-contract.json")
        for os_name in ("windows", "macos", "linux"):
            binaries = [
                name
                for name in names
                if name.startswith(f"sesslint-{version}-{os_name}-") and not name.endswith(".asc")
            ]
            if len(binaries) != 1:
                raise ValueError(f"Missing {os_name} binary")
            if f"smoke-{os_name}.json" not in names:
                raise ValueError(f"Missing {os_name} installed smoke receipt")
            receipt = json.loads((directory / f"smoke-{os_name}.json").read_text(encoding="utf-8"))
            validate_smoke_contract(receipt, contract_raw)
            expected_platform = {"windows": "Windows", "macos": "Darwin", "linux": "Linux"}[os_name]
            if (
                receipt.get("status") != "PASS"
                or receipt.get("version") != version
                or receipt.get("platform") != expected_platform
                or receipt.get("artifact") != binaries[0]
                or receipt.get("artifact_sha256") != data["artifacts"][binaries[0]]
                or receipt.get("source_immutable") is not True
                or receipt.get("starter_kit_sha256")
                != data["artifacts"].get(f"sesslint-{version}-starter-kit.zip")
                or not {"check", "repair", "verify", "hook", "mcp"}.issubset(
                    row["command"][0] for row in receipt.get("checks", [])
                )
            ):
                raise ValueError(f"Invalid {os_name} installed smoke receipt")
        portable_name = f"sesslint-{version}-acceptance-windows.zip"
        if portable_name not in names or "smoke-windows-powershell.json" not in names:
            raise ValueError("Missing transferable Windows acceptance")
        ps = json.loads((directory / "smoke-windows-powershell.json").read_text(encoding="utf-8"))
        validate_smoke_contract(ps, contract_raw)
        win = json.loads((directory / "smoke-windows.json").read_text(encoding="utf-8"))
        if (
            ps.get("status") != "PASS"
            or ps.get("version") != version
            or ps.get("platform") != "Windows"
            or ps.get("source_immutable") is not True
            or ps.get("commit") != data["commit"]
            or ps.get("artifact") != win["artifact"]
            or ps.get("artifact_sha256") != win["artifact_sha256"]
            or ps.get("starter_kit_sha256") != win["starter_kit_sha256"]
        ):
            raise ValueError("Invalid PowerShell installed receipt")
        with zipfile.ZipFile(directory / portable_name) as portable:
            portable_raw = portable.read("windows-acceptance.json")
            portable_manifest = json.loads(portable_raw)
            for name, expected in portable_manifest.get("files", {}).items():
                if (
                    portable.namelist().count(name) != 1
                    or hashlib.sha256(portable.read(name)).hexdigest() != expected
                ):
                    raise ValueError("Portable Windows member checksum mismatch")
        if (
            portable_manifest.get("commit") != data["commit"]
            or portable_manifest.get("version") != version
            or portable_manifest.get("binary") != win["artifact"]
            or portable_manifest.get("files", {}).get(win["artifact"]) != win["artifact_sha256"]
            or portable_manifest.get("files", {}).get(f"sesslint-{version}-starter-kit.zip")
            != win["starter_kit_sha256"]
            or ps.get("package_manifest_sha256") != hashlib.sha256(portable_raw).hexdigest()
        ):
            raise ValueError("Portable Windows package differs from signed candidate")
        for name in (f"sesslint-{version}-man.tar.gz", f"sesslint-{version}-starter-kit.zip"):
            if name not in names:
                raise ValueError("Missing user delivery archive")
        for kind, package in zip(
            ("wheel", "sdist"), distributions(directory, version), strict=True
        ):
            receipts = [name for name in names if name.startswith(f"smoke-{kind}-")]
            if not receipts:
                raise ValueError(f"Missing installed {kind} receipt")
            for name in receipts:
                receipt = json.loads((directory / name).read_text(encoding="utf-8"))
                validate_smoke_contract(receipt, contract_raw)
                if (
                    receipt.get("status") != "PASS"
                    or receipt.get("version") != version
                    or receipt.get("artifact") != package.name
                    or receipt.get("artifact_sha256") != data["artifacts"][package.name]
                    or receipt.get("source_immutable") is not True
                    or receipt.get("starter_kit_sha256")
                    != data["artifacts"][f"sesslint-{version}-starter-kit.zip"]
                    or receipt.get("api", {}).get("api") != "PASS"
                ):
                    raise ValueError(f"Invalid installed {kind} receipt")
        for name in names | {"artifact-manifest.json", "sha256sums.txt"}:
            if not (directory / f"{name}.sigstore.json").is_file():
                raise ValueError(f"Missing signature bundle for {name}")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("stage", "manifest", "verify", "compare"))
    parser.add_argument("--directory", type=Path, default=Path("dist"))
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", type=Path)
    parser.add_argument("--commit", default="")
    parser.add_argument("--epoch", type=int, default=0)
    parser.add_argument("--complete", action="store_true")
    args = parser.parse_args()
    if args.action == "stage":
        if args.target is None:
            parser.error("--target is required")
        stage(args.directory, args.target, args.version)
    elif args.action == "compare":
        if args.target is None:
            parser.error("--target is required")
        left = distributions(args.directory, args.version)
        right = distributions(args.target, args.version)
        if [digest(p) for p in left] != [digest(p) for p in right]:
            raise ValueError("Reproducible build hash mismatch")
    elif args.action == "manifest":
        data = manifest(args.directory, args.version, args.commit, args.epoch)
        (args.directory / "artifact-manifest.json").write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
        )
        (args.directory / "sha256sums.txt").write_text(
            "".join(f"{value}  {name}\n" for name, value in data["artifacts"].items()),
            encoding="utf-8",
            newline="\n",
        )
    else:
        data = verify(args.directory, complete=args.complete)
        if data["version"] != args.version:
            raise ValueError("Manifest version mismatch")
        if args.commit and data["commit"] != args.commit:
            raise ValueError("Manifest commit mismatch")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
