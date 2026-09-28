#!/usr/bin/env python3
"""T-12: install both Python distributions outside checkout and run the same journey."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

from installed_smoke import run
from release_artifacts import digest, distributions


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("dist"))
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    directory = args.directory.resolve()
    kit = directory / f"sesslint-{args.version}-starter-kit.zip"
    for package in distributions(directory, args.version):
        kind = "wheel" if package.suffix == ".whl" else "sdist"
        with tempfile.TemporaryDirectory(prefix="sesslint installed \u0111 ") as raw:
            root = Path(raw)
            venv.EnvBuilder(with_pip=True).create(root / "environment")
            interpreter = (
                root / "environment" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            )
            env = dict(os.environ, PIP_DISABLE_PIP_VERSION_CHECK="1")
            if kind == "sdist":
                subprocess.run(
                    [str(interpreter), "-m", "pip", "install", "hatchling==1.27.0"],
                    cwd=root,
                    env=env,
                    check=True,
                )
            subprocess.run(
                [
                    str(interpreter),
                    "-m",
                    "pip",
                    "install",
                    "--no-deps",
                    "--no-build-isolation",
                    str(package),
                ],
                cwd=root,
                env=env,
                check=True,
            )
            receipt = run(interpreter, kit, python=True, version=args.version)
            receipt.update(kind=kind, artifact=package.name, artifact_sha256=digest(package))
            target = directory / f"smoke-{kind}-{sys.platform}.json"
            target.write_text(
                json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
            )
            print(f"PASS installed {kind}: {package.name}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
