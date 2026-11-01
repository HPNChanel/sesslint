#!/usr/bin/env python3
"""T-11 immutable draft staging/retry. Run only in the authorized release workflow."""

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

try:
    from .release_artifacts import digest, verify
    from .release_notes import CHANGELOG, release_notes
except ImportError:
    from release_artifacts import digest, verify
    from release_notes import CHANGELOG, release_notes


def gh(*args: str) -> str:
    return subprocess.run(["gh", *args], capture_output=True, text=True, check=True).stdout


def stage(directory: Path, repo: str, tag: str, commit: str, changelog: Path = CHANGELOG) -> None:
    manifest = verify(directory, complete=True)
    if manifest["commit"] != commit or tag != "v" + manifest["version"]:
        raise ValueError("Release identity mismatch")
    # B35: the body is the tracked CHANGELOG section of the verified version,
    # extracted before any remote call so a missing section fails closed.
    notes = release_notes(manifest["version"], changelog)
    try:
        release = json.loads(gh("api", f"repos/{repo}/releases/tags/{tag}"))
    except subprocess.CalledProcessError as error:
        if "HTTP 404" not in error.stderr:
            raise
        with tempfile.TemporaryDirectory() as raw:
            notes_file = Path(raw) / "release-notes.md"
            notes_file.write_bytes(notes.encode("utf-8"))
            gh(
                "release",
                "create",
                tag,
                "--repo",
                repo,
                "--draft",
                "--target",
                commit,
                "--title",
                f"SessLint {tag}",
                "--notes-file",
                str(notes_file),
            )
        release = json.loads(gh("api", f"repos/{repo}/releases/tags/{tag}"))
    if release["target_commitish"] != commit:
        raise ValueError("Existing release targets another commit")
    existing = {item["name"] for item in release["assets"]}
    with tempfile.TemporaryDirectory() as raw:
        temp = Path(raw)
        for path in sorted(directory.iterdir()):
            if not path.is_file():
                continue
            if path.name in existing:
                gh(
                    "release",
                    "download",
                    tag,
                    "--repo",
                    repo,
                    "--pattern",
                    path.name,
                    "--dir",
                    str(temp),
                )
                if digest(temp / path.name) != digest(path):
                    raise ValueError("Existing release bytes differ; never overwrite")
            else:
                if not release["draft"]:
                    raise ValueError("Cannot add a missing artifact to a public release")
                gh("release", "upload", tag, str(path), "--repo", repo)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("dist"))
    parser.add_argument("--repo", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    stage(args.directory, args.repo, args.tag, args.commit)
