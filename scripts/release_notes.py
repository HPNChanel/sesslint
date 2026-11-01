#!/usr/bin/env python3
"""B35 release notes from CHANGELOG.md; release-only, never shipped as runtime code.

The GitHub release body is the ``## [X.Y.Z]`` section of the tracked
``CHANGELOG.md`` for the version being released -- never a separate,
version-named notes file that can be git-ignored or untracked and so absent
from the tagged checkout. Extraction is deterministic (same bytes in, same
bytes out, LF endings) and fails closed: a missing, duplicated or empty
section raises ``ReleaseNotesError`` before any remote call.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHANGELOG = ROOT / "CHANGELOG.md"

_HEADING = re.compile(r"^## \[(?P<name>[^\]]+)\]")
_SECTION_END = re.compile(r"^#{1,2} ")
_FENCE = re.compile(r"^\s*(```|~~~)")
_LINK_DEFINITION = re.compile(r"^\[[^\]]+\]:\s*\S")
_VERSION = re.compile(r"\d+\.\d+\.\d+[0-9A-Za-z.+-]*")


class ReleaseNotesError(ValueError):
    """CHANGELOG.md cannot provide release notes for the requested version."""


def extract(version: str, text: str) -> str:
    """Return the body of the ``## [version]`` section of a Keep a Changelog text."""
    if not _VERSION.fullmatch(version):
        raise ReleaseNotesError(f"Not a release version: {version!r}")
    lines = text.replace("\r\n", "\n").split("\n")
    starts = [
        index
        for index, line in enumerate(lines)
        if (match := _HEADING.match(line)) and match["name"] == version
    ]
    if not starts:
        raise ReleaseNotesError(f"CHANGELOG.md has no '## [{version}]' section")
    if len(starts) > 1:
        raise ReleaseNotesError(f"CHANGELOG.md has {len(starts)} '## [{version}]' sections")
    body: list[str] = []
    in_fence = False
    for line in lines[starts[0] + 1 :]:
        if _FENCE.match(line):
            in_fence = not in_fence
        elif not in_fence and (_SECTION_END.match(line) or _LINK_DEFINITION.match(line)):
            break
        body.append(line)
    if in_fence:
        raise ReleaseNotesError(f"CHANGELOG.md section '## [{version}]' has an unclosed code fence")
    notes = "\n".join(body).strip("\n")
    if not notes.strip():
        raise ReleaseNotesError(f"CHANGELOG.md section '## [{version}]' is empty")
    return notes + "\n"


def release_notes(version: str, changelog: Path = CHANGELOG) -> str:
    """Read ``changelog`` (UTF-8) and extract the notes for ``version``."""
    try:
        text = changelog.read_text(encoding="utf-8")
    except OSError as error:
        raise ReleaseNotesError(f"Cannot read {changelog.name}: {error.strerror}") from error
    return extract(version, text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="release version without the 'v'")
    parser.add_argument("--changelog", type=Path, default=CHANGELOG)
    parser.add_argument("--output", type=Path, help="write notes here instead of stdout")
    args = parser.parse_args(argv)
    try:
        notes = release_notes(args.version, args.changelog)
    except ReleaseNotesError as error:
        print(f"release notes: {error}", file=sys.stderr)
        return 1
    if args.output is None:
        sys.stdout.buffer.write(notes.encode("utf-8"))
    else:
        args.output.write_bytes(notes.encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
