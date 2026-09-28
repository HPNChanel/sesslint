"""T-11: restore immutable IDs; absence alone never permits a rebuild."""

import argparse
import hashlib
import json
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path

try:
    from .release_artifacts import digest, immutable_copy, verify
except ImportError:
    from release_artifacts import digest, immutable_copy, verify


def pages(endpoint: str) -> list[dict]:
    result = subprocess.run(
        ["gh", "api", "--paginate", "--slurp", endpoint], check=True, capture_output=True, text=True
    )
    data = json.loads(result.stdout)
    if not isinstance(data, list) or not data or not all(isinstance(p, dict) for p in data):
        raise ValueError("Incomplete GitHub history")
    return data


def never_started(repo, run_id, attempt, job, step, commit):
    if attempt < 2:
        raise ValueError("Restore requires a retry attempt")
    for previous in range(1, attempt):
        history = pages(f"repos/{repo}/actions/runs/{run_id}/attempts/{previous}/jobs")
        jobs = [entry for page in history for entry in page["jobs"] if entry["name"] == job]
        if len(jobs) != 1 or jobs[0].get("head_sha") != commit:
            raise ValueError("Stage history or commit is missing/ambiguous")
        entry = jobs[0]
        if entry.get("status") != "completed":
            raise ValueError("Previous attempt is not completed")
        if entry.get("conclusion") == "skipped":
            continue
        steps = [item for item in entry.get("steps", []) if item.get("name") == step]
        if len(steps) != 1:
            raise ValueError("Creation step history is unknown")
        if steps[0].get("status") != "completed" or steps[0].get("conclusion") != "skipped":
            return False
    return True


def verify_stage(directory: Path, name: str, commit: str, version: str) -> None:
    if name.startswith("binary-"):
        os_name = name.removeprefix("binary-")
        receipt = json.loads((directory / f"smoke-{os_name}.json").read_text(encoding="utf-8"))
        artifact = receipt.get("artifact", "")
        if (
            Path(artifact).name != artifact
            or not artifact.startswith(f"sesslint-{version}-{os_name}-")
            or receipt.get("status") != "PASS"
            or receipt.get("version") != version
            or receipt.get("platform")
            != {"windows": "Windows", "linux": "Linux", "macos": "Darwin"}.get(os_name)
            or receipt.get("source_immutable") is not True
            or digest(directory / artifact) != receipt.get("artifact_sha256")
        ):
            raise ValueError("Restored binary does not match its installed receipt")
        checksum = (directory / f"SHA256SUMS-{os_name}").read_text(encoding="utf-8")
        if f"{digest(directory / artifact)}  {artifact}" not in checksum.splitlines():
            raise ValueError("Restored binary checksum mismatch")
    else:
        if name not in {"python-assets", "release-dist"}:
            raise ValueError("Unknown release stage")
        manifest = verify(directory, complete=name == "release-dist")
        if manifest.get("commit") != commit or manifest.get("version") != version:
            raise ValueError("Restored release identity mismatch")


def restore(repo, run_id, name, target, *, attempt, job, step, commit, version):
    listing = pages(f"repos/{repo}/actions/runs/{run_id}/artifacts")
    matches = [a for page in listing for a in page["artifacts"] if a["name"] == name]
    if not matches:
        if never_started(repo, run_id, attempt, job, step, commit):
            return False
        raise ValueError("Created artifact is lost; refuse to rebuild this version")
    if len(matches) != 1 or matches[0].get("expired") is not False:
        raise ValueError("Verified artifact unavailable; refuse to rebuild this version")
    artifact = matches[0]
    if artifact.get("workflow_run", {}).get("head_sha") != commit:
        raise ValueError("Artifact belongs to another commit")
    artifact_id, expected = artifact.get("id"), artifact.get("digest", "")
    if type(artifact_id) is not int or not expected.startswith("sha256:") or len(expected) != 71:
        raise ValueError("Artifact identity/digest is unavailable")
    with tempfile.TemporaryDirectory(prefix="sesslint restore ") as raw:
        scratch = Path(raw)
        archive_path = scratch / "artifact.zip"
        with archive_path.open("xb") as stream:
            subprocess.run(
                ["gh", "api", f"repos/{repo}/actions/artifacts/{artifact_id}/zip"],
                check=True,
                stdout=stream,
                stderr=subprocess.PIPE,
            )
        if "sha256:" + hashlib.sha256(archive_path.read_bytes()).hexdigest() != expected:
            raise ValueError("Downloaded artifact digest mismatch")
        extracted = scratch / "files"
        extracted.mkdir()
        with zipfile.ZipFile(archive_path) as archive:
            names = set()
            for item in archive.infolist():
                if (
                    not item.filename
                    or Path(item.filename).name != item.filename
                    or "\\" in item.filename
                    or ":" in item.filename
                    or item.filename.casefold() in names
                    or stat.S_ISLNK(item.external_attr >> 16)
                ):
                    raise ValueError("Unsafe artifact archive member")
                names.add(item.filename.casefold())
            archive.extractall(extracted)
        verify_stage(extracted, name, commit, version)
        for path in sorted(extracted.iterdir()):
            immutable_copy(path, target / path.name)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("repo", "run-id", "name", "job", "step", "commit", "version"):
        parser.add_argument("--" + field, required=True)
    parser.add_argument("--attempt", required=True, type=int)
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    receipt = {
        "status": "FAIL",
        "name": args.name,
        "commit": args.commit,
        "version": args.version,
        "attempt": args.attempt,
        "run_id": args.run_id,
    }
    try:
        restored = restore(
            args.repo,
            args.run_id,
            args.name,
            args.target,
            attempt=args.attempt,
            job=args.job,
            step=args.step,
            commit=args.commit,
            version=args.version,
        )
        receipt.update(status="PASS", restored=restored)
        print(f"restored={str(restored).lower()}")
        return 0
    except Exception as error:
        receipt["error_type"] = type(error).__name__
        raise
    finally:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        with args.receipt.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(receipt, stream, indent=2)
            stream.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
