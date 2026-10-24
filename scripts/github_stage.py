#!/usr/bin/env python3
"""T-11 immutable draft staging/retry. Run only in the authorized release workflow."""

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path

try:
    from .release_artifacts import digest, verify
except ImportError:
    from release_artifacts import digest, verify


REPO_ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = REPO_ROOT / "CHANGELOG.md"


def gh(*args: str) -> str:
    return subprocess.run(["gh", *args], capture_output=True, text=True, check=True).stdout


def changelog_notes(changelog: Path, version: str) -> str:
    """Return exactly one released-version section from the tracked changelog.

    ``Unreleased`` cannot be substituted for a versioned release: that would
    make a draft's notes depend on whatever happens to be merged later.
    """
    try:
        content = changelog.read_text(encoding="utf-8")
    except OSError as error:
        raise ValueError(f"Cannot read changelog for release notes: {changelog}") from error

    heading = re.compile(rf"^## \[{re.escape(version)}\](?:\s+-\s+.+)?\s*$", re.MULTILINE)
    match = heading.search(content)
    if match is None:
        raise ValueError(f"No versioned changelog section for release {version}")
    next_heading = re.search(r"^## \[", content[match.end() :], re.MULTILINE)
    end = match.end() + next_heading.start() if next_heading is not None else len(content)
    notes = content[match.start() : end].strip()
    if notes == match.group(0):
        raise ValueError(f"Empty changelog section for release {version}")
    return notes + "\n"


def stage(
    directory: Path,
    repo: str,
    tag: str,
    commit: str,
    *,
    changelog: Path = CHANGELOG,
    generate_notes: bool = False,
) -> None:
    manifest = verify(directory, complete=True)
    if manifest["commit"] != commit or tag != "v" + manifest["version"]:
        raise ValueError("Release identity mismatch")
    with tempfile.TemporaryDirectory() as raw:
        temp = Path(raw)
        try:
            release = json.loads(gh("api", f"repos/{repo}/releases/tags/{tag}"))
        except subprocess.CalledProcessError as error:
            if "HTTP 404" not in error.stderr:
                raise
            create_args = (
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
            )
            if generate_notes:
                gh(*create_args, "--generate-notes")
            else:
                notes_path = temp / "release-notes.md"
                notes = changelog_notes(changelog, manifest["version"])
                notes_path.write_text(notes, encoding="utf-8")
                gh(*create_args, "--notes-file", str(notes_path))
            release = json.loads(gh("api", f"repos/{repo}/releases/tags/{tag}"))
        if release["target_commitish"] != commit:
            raise ValueError("Existing release targets another commit")
        existing = {item["name"] for item in release["assets"]}
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
    parser.add_argument(
        "--generate-notes",
        action="store_true",
        help="Ask GitHub to generate notes instead of extracting a versioned CHANGELOG.md section.",
    )
    args = parser.parse_args()
    stage(args.directory, args.repo, args.tag, args.commit, generate_notes=args.generate_notes)
