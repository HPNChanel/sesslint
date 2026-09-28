"""T-11: PyPI selection uses package metadata, not a tarball wildcard."""

import hashlib
import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest
from scripts.release_artifacts import (
    _metadata,
    digest,
    distributions,
    immutable_copy,
    manifest,
    stage,
    verify,
)


def _packages(root: Path, *, version: str = "0.4.1", metadata_version: str = "0.4.1") -> None:
    metadata = (
        f"Metadata-Version: 2.4\nName: sesslint\nVersion: {metadata_version}\n"
        "Requires-Python: >=3.11\nRequires-Dist: pytest>=8; extra == 'dev'\n"
    ).encode()
    with zipfile.ZipFile(root / f"sesslint-{version}-py3-none-any.whl", "w") as archive:
        archive.writestr(f"sesslint-{version}.dist-info/METADATA", metadata)
    with tarfile.open(root / f"sesslint-{version}.tar.gz", "w:gz") as archive:
        info = tarfile.TarInfo(f"sesslint-{version}/PKG-INFO")
        info.size = len(metadata)
        archive.addfile(info, io.BytesIO(metadata))


def test_auxiliary_archives_never_reach_pypi(tmp_path: Path) -> None:
    _packages(tmp_path)
    for name in (
        "sesslint-0.4.1-acceptance-windows.zip",
        "sesslint-0.4.1-man.tar.gz",
        "sesslint-0.4.1-starter-kit.zip",
    ):
        (tmp_path / name).write_bytes(b"synthetic auxiliary")
    target = tmp_path / "pypi"
    stage(tmp_path, target, "0.4.1")
    stage(tmp_path, target, "0.4.1")  # byte-identical retry
    assert sorted(p.name for p in target.iterdir()) == [
        "sesslint-0.4.1-py3-none-any.whl",
        "sesslint-0.4.1.tar.gz",
    ]


def test_metadata_mismatch_refuses_before_staging(tmp_path: Path) -> None:
    _packages(tmp_path, metadata_version="0.4.0")
    with pytest.raises(ValueError, match="metadata mismatch"):
        stage(tmp_path, tmp_path / "pypi", "0.4.1")
    assert not (tmp_path / "pypi").exists()


def test_unexpected_wheel_refused(tmp_path: Path) -> None:
    _packages(tmp_path)
    (tmp_path / "other.whl").write_bytes(b"x")
    with pytest.raises(ValueError, match="Unexpected wheel"):
        distributions(tmp_path, "0.4.1")
    # A marker mentioning an extra may still activate for the base install.
    metadata = (
        "Name: sesslint\nVersion: 0.4.1\nRequires-Python: >=3.11\n"
        "Requires-Dist: unexpected; python_version >= '3.11' or extra == 'dev'\n"
    )
    with pytest.raises(ValueError, match="runtime dependency"):
        _metadata(metadata.encode(), "0.4.1")


def test_retry_cannot_replace_an_artifact(tmp_path: Path) -> None:
    source, target = tmp_path / "new", tmp_path / "existing"
    source.write_bytes(b"new")
    target.write_bytes(b"verified")
    with pytest.raises(ValueError, match="Refusing to replace"):
        immutable_copy(source, target)
    assert target.read_bytes() == b"verified"


def test_manifest_detects_tampered_bytes_and_checksum_file(tmp_path: Path) -> None:
    _packages(tmp_path)
    (tmp_path / "SHA256SUMS-windows").write_bytes(b"synthetic binary checksum")
    data = manifest(tmp_path, "0.4.1", "synthetic-commit", 123)
    assert list(data["artifacts"]) == sorted(data["artifacts"])
    (tmp_path / "artifact-manifest.json").write_text(json.dumps(data), encoding="utf-8")
    sums = "".join(f"{value}  {name}\n" for name, value in data["artifacts"].items())
    (tmp_path / "sha256sums.txt").write_text(sums, encoding="utf-8")
    assert verify(tmp_path)["version"] == "0.4.1"
    with pytest.raises(ValueError, match="delivery archive"):
        verify(tmp_path, complete=True)
    (tmp_path / "sha256sums.txt").write_text("wrong", encoding="utf-8")
    with pytest.raises(ValueError, match="Checksum"):
        verify(tmp_path)
    (tmp_path / "sesslint-0.4.1.tar.gz").write_bytes(b"changed")
    with pytest.raises(ValueError, match="hash mismatch"):
        verify(tmp_path)


@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "kit",
        "platform",
        "wheel",
        "signature",
        "powershell",
        "portable",
        "portable-bytes",
        "binary-case",
        "wheel-case",
    ],
)
def test_complete_set_requires_bound_installed_receipts(
    tmp_path: Path, mutation: str | None
) -> None:
    """Signature presence is structural here; CI cosign verifies cryptography."""
    _packages(tmp_path)
    kit = tmp_path / "sesslint-0.4.1-starter-kit.zip"
    contract_raw = (Path(__file__).parents[1] / "scripts/smoke_contract.json").read_bytes()
    contract = json.loads(contract_raw)
    smoke_fields = {
        "contract_sha256": hashlib.sha256(contract_raw).hexdigest(),
        "checks": [
            {"id": row["id"], "command": row["args"], "exit_code": row["exit_codes"][0]}
            for row in contract["cases"]
        ],
    }
    with zipfile.ZipFile(kit, "w") as archive:
        archive.writestr("smoke-contract.json", contract_raw)
    (tmp_path / "sesslint-0.4.1-man.tar.gz").write_bytes(b"synthetic man")
    for os_name, platform in (("windows", "Windows"), ("macos", "Darwin"), ("linux", "Linux")):
        artifact = tmp_path / f"sesslint-0.4.1-{os_name}-synthetic"
        artifact.write_bytes(b"synthetic binary")
        receipt = {
            "status": "PASS",
            "version": "0.4.1",
            "platform": platform,
            "artifact": artifact.name,
            "artifact_sha256": digest(artifact),
            "source_immutable": True,
            "starter_kit_sha256": digest(kit),
            **smoke_fields,
        }
        if mutation == "binary-case":
            receipt["checks"] = receipt["checks"][:-1]
        if mutation == "kit":
            receipt["starter_kit_sha256"] = "wrong"
        if mutation == "platform":
            receipt["platform"] = "WrongOS"
        (tmp_path / f"smoke-{os_name}.json").write_text(json.dumps(receipt), encoding="utf-8")
    for kind, package in zip(("wheel", "sdist"), distributions(tmp_path, "0.4.1"), strict=True):
        if kind == "wheel" and mutation == "wheel":
            continue
        (tmp_path / f"smoke-{kind}-synthetic.json").write_text(
            json.dumps(
                {
                    "status": "PASS",
                    "version": "0.4.1",
                    "artifact": package.name,
                    "artifact_sha256": digest(package),
                    "source_immutable": True,
                    "starter_kit_sha256": digest(kit),
                    "api": {"api": "PASS"},
                    **smoke_fields,
                    "checks": smoke_fields["checks"][:-1]
                    if mutation == "wheel-case"
                    else smoke_fields["checks"],
                }
            ),
            encoding="utf-8",
        )
    win = json.loads((tmp_path / "smoke-windows.json").read_text(encoding="utf-8"))
    ps = dict(
        win,
        commit="synthetic-commit",
        contract_sha256=hashlib.sha256(contract_raw).hexdigest(),
        checks=[
            {"id": row["id"], "command": row["args"], "exit_code": row["exit_codes"][0]}
            for row in contract["cases"]
        ],
    )
    if mutation == "powershell":
        ps["checks"].pop()
    portable_raw = json.dumps(
        {
            "commit": "other" if mutation == "portable" else "synthetic-commit",
            "version": "0.4.1",
            "binary": win["artifact"],
            "files": {
                win["artifact"]: win["artifact_sha256"],
                "sesslint-0.4.1-starter-kit.zip": digest(kit),
            },
        }
    ).encode()
    ps["package_manifest_sha256"] = hashlib.sha256(portable_raw).hexdigest()
    (tmp_path / "smoke-windows-powershell.json").write_text(json.dumps(ps), encoding="utf-8")
    with zipfile.ZipFile(tmp_path / "sesslint-0.4.1-acceptance-windows.zip", "w") as archive:
        archive.writestr("windows-acceptance.json", portable_raw)
        archive.writestr(kit.name, kit.read_bytes())
        archive.writestr(
            win["artifact"],
            b"changed" if mutation == "portable-bytes" else b"synthetic binary",
        )
    data = manifest(tmp_path, "0.4.1", "synthetic-commit", 123)
    (tmp_path / "artifact-manifest.json").write_text(json.dumps(data), encoding="utf-8")
    (tmp_path / "sha256sums.txt").write_text(
        "".join(f"{value}  {name}\n" for name, value in data["artifacts"].items()), encoding="utf-8"
    )
    for name in set(data["artifacts"]) | {"artifact-manifest.json", "sha256sums.txt"}:
        if mutation != "signature":
            (tmp_path / f"{name}.sigstore.json").write_bytes(b"synthetic presence only")
    if mutation is None:
        assert verify(tmp_path, complete=True)["version"] == "0.4.1"
    else:
        with pytest.raises(ValueError):
            verify(tmp_path, complete=True)
