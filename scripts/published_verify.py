#!/usr/bin/env python3
"""T-11 release-only public-channel hash checks, never shipped as runtime code.

PyPI retry stages only missing files after verifying every existing name/hash.
No overwrite/skip-existing shortcut can hide conflicting bytes. Downloads are
restricted to the public PyPI file host and verified against local signed inputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

try:
    from .release_artifacts import distributions, immutable_copy
except ImportError:
    from release_artifacts import distributions, immutable_copy


def pypi_files(version: str) -> dict:
    try:
        with urllib.request.urlopen(
            f"https://pypi.org/pypi/sesslint/{version}/json", timeout=60
        ) as response:
            data = json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return {}
        raise
    if data["info"]["name"] != "sesslint" or data["info"]["version"] != version:
        raise ValueError("Public package identity mismatch")
    return {entry["filename"]: entry for entry in data["urls"]}


def verify_pypi(directory: Path, version: str, target: Path, *, allow_missing: bool) -> int:
    files = pypi_files(version)
    expected = distributions(directory, version)
    if set(files) - {p.name for p in expected}:
        raise ValueError("Unexpected public distribution for version")
    missing = 0
    for path in expected:
        entry = files.get(path.name)
        if entry is None:
            if not allow_missing:
                raise ValueError("Distribution is not visible on PyPI")
            immutable_copy(path, target / path.name)
            missing += 1
            continue
        url = urllib.parse.urlparse(entry["url"])
        if url.scheme != "https" or url.hostname != "files.pythonhosted.org":
            raise ValueError("Unexpected PyPI download host")
        with urllib.request.urlopen(entry["url"], timeout=120) as response:
            raw = response.read(64 * 1024 * 1024 + 1)
        if len(raw) > 64 * 1024 * 1024:
            raise ValueError("Distribution exceeds download bound")
        actual = hashlib.sha256(raw).hexdigest()
        if (
            actual != entry["digests"]["sha256"]
            or actual != hashlib.sha256(path.read_bytes()).hexdigest()
        ):
            raise ValueError("Published bytes differ from verified release artifact")
        if not allow_missing:
            target.mkdir(parents=True, exist_ok=True)
            downloaded = target / path.name
            if downloaded.exists() and downloaded.read_bytes() != raw:
                raise ValueError("Existing download hash mismatch")
            if not downloaded.exists():
                with downloaded.open("xb") as stream:
                    stream.write(raw)
    return missing


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("dist"))
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--stage-missing", action="store_true")
    args = parser.parse_args()
    missing = verify_pypi(
        args.directory, args.version, args.target, allow_missing=args.stage_missing
    )
    print(f"missing={missing}")
