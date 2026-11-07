#!/usr/bin/env python3
"""Parity stub: delegate to pinned sesslint (Rust stand-in for RX-P1.3d). Stdlib only."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def sesslint_exe(work: Path) -> Path | None:
    venv = work / ".venv"
    if os.name == "nt":
        names = ("sesslint.exe", "sesslint")
        folder = venv / "Scripts"
    else:
        names = ("sesslint",)
        folder = venv / "bin"
    for name in names:
        path = folder / name
        if path.is_file():
            return path
    return None


def main() -> int:
    work = Path.cwd()
    exe = sesslint_exe(work)
    if exe is None:
        sys.stderr.write("reason=stub_sesslint_missing\n")
        return 2
    try:
        proc = subprocess.run(
            [str(exe), *sys.argv[1:]],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        sys.stderr.write("reason=stub_run_failed\n")
        return 2
    sys.stdout.buffer.write(proc.stdout)
    sys.stderr.buffer.write(proc.stderr)
    return proc.returncode if proc.returncode is not None else 2


if __name__ == "__main__":
    raise SystemExit(main())
