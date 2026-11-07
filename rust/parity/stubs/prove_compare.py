#!/usr/bin/env python3
"""Run compare.py on Python vs stub captures (RX-P1.3d self-proof). Stdlib only."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PARITY = HERE.parent
WORK = PARITY / "run-work"
FIXTURE = "fixtures/sessions/minimal-valid.jsonl"
COMMAND = ["check", FIXTURE]


def load_compare():
    path = PARITY / "compare.py"
    spec = importlib.util.spec_from_file_location("_parity_compare", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("compare_load_failed")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def sesslint_exe(work: Path) -> Path:
    venv = work / ".venv"
    if os.name == "nt":
        folder = venv / "Scripts"
        for name in ("sesslint.exe", "sesslint"):
            path = folder / name
            if path.is_file():
                return path
    else:
        path = venv / "bin" / "sesslint"
        if path.is_file():
            return path
    raise RuntimeError("sesslint_missing")


def capture(command: list[str], cwd: Path) -> tuple[int, bytes, bytes]:
    proc = subprocess.run(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=120,
    )
    code = proc.returncode if proc.returncode is not None else 2
    return code, proc.stdout, proc.stderr


def stub_cmd(name: str) -> list[str]:
    if os.name == "nt":
        path = HERE / f"{name}.cmd"
    else:
        path = HERE / f"{name}.py"
    if not path.is_file():
        raise RuntimeError(f"stub_missing:{path}")
    if os.name == "nt":
        return [str(path), *COMMAND]
    return [sys.executable, str(path), *COMMAND]


def main() -> int:
    if not WORK.is_dir():
        sys.stderr.write("reason=run_work_missing\n")
        return 2
    cmp_mod = load_compare()
    py_exe = sesslint_exe(WORK)
    py_code, py_out, py_err = capture([str(py_exe), *COMMAND], WORK)
    left = cmp_mod.Capture(py_out, py_err, py_code)

    fail = 0
    for label, stub in (("mismatch", "mismatch"), ("mirror", "mirror")):
        rust_code, rust_out, rust_err = capture(stub_cmd(stub), WORK)
        right = cmp_mod.Capture(rust_out, rust_err, rust_code)
        diff = cmp_mod.compare(left, right)
        status = cmp_mod.status_code(diff)
        equal = diff.equal
        sys.stdout.write(f"stub={label}\n")
        sys.stdout.write(f"equal={'true' if equal else 'false'}\n")
        sys.stdout.write(f"compare_exit={status}\n")
        if label == "mismatch":
            if equal or status == 0:
                sys.stdout.write("expect=mismatch\n")
                fail = 1
        elif label == "mirror":
            if not equal or status != 0:
                sys.stdout.write("expect=match\n")
                fail = 1
    sys.stdout.write(f"prove_compare={'pass' if fail == 0 else 'fail'}\n")
    return fail


if __name__ == "__main__":
    raise SystemExit(main())
