"""T-10: verify installed wheel bytes, then time fresh untraced CLI processes."""

import argparse
import hashlib
import json
import math
import os
import platform
import subprocess
import sys
import time
import tracemalloc
import zipfile
from pathlib import Path

INPUT_SHA256 = "38406debf39ce2f161a2ad7af382593519e179e71fe580ff7b96871aef3eebeb"
INPUT_BYTES = 104277879


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def within_budget(seconds, peak):
    return (
        type(seconds) in (int, float)
        and type(peak) in (int, float)
        and math.isfinite(seconds)
        and math.isfinite(peak)
        and 0 <= seconds <= 15
        and 0 <= peak < 512
    )


def get_rss_mb() -> float | None:
    """Retrieve process RSS/WorkingSet in megabytes cross-platform (Linux, macOS, Windows)."""
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes

            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            k32 = ctypes.windll.kernel32
            psapi = ctypes.windll.psapi
            k32.GetCurrentProcess.restype = wintypes.HANDLE
            psapi.GetProcessMemoryInfo.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
                wintypes.DWORD,
            ]
            psapi.GetProcessMemoryInfo.restype = wintypes.BOOL

            pmc = PROCESS_MEMORY_COUNTERS()
            pmc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            if psapi.GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(pmc), pmc.cb):
                return float(pmc.PeakWorkingSetSize) / (1024 * 1024)
        except Exception:
            return None
    else:
        try:
            import resource

            raw_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            if sys.platform == "darwin":
                return raw_rss / (1024 * 1024)
            return raw_rss / 1024  # Linux KiB to MiB
        except Exception:
            return None
    return None


def child(args):
    import sesslint
    from sesslint.cli import main as cli

    package = Path(sesslint.__file__).resolve()
    if not package.is_relative_to(Path(sys.prefix).resolve()):
        raise ValueError("Installed measurement imported checkout source")
    if digest(args.input) != INPUT_SHA256 or args.input.stat().st_size != INPUT_BYTES:
        raise ValueError("Input differs from the protected 250k fixture")
    files = {}
    with zipfile.ZipFile(args.artifact) as archive:
        for name in archive.namelist():
            if name.startswith("sesslint/") and not name.endswith("/"):
                expected = hashlib.sha256(archive.read(name)).hexdigest()
                if digest(package.parent.parent / name) != expected:
                    raise ValueError("Installed runtime differs from wheel")
                files[name] = expected
    traced = sys.gettrace() is not None or sys.getprofile() is not None or tracemalloc.is_tracing()
    if traced:
        raise ValueError("Tracing is active in timed child")
    start, cpu = time.perf_counter(), time.process_time()
    code = cli(["check", str(args.input), "--json"])
    elapsed, cpu_s, peak = time.perf_counter() - start, time.process_time() - cpu, get_rss_mb()
    row = {
        "schema_version": 1,
        "status": "PASS" if code == 0 and within_budget(elapsed, peak) else "FAIL",
        "kind": "installed-wheel",
        "artifact": args.artifact.name,
        "artifact_sha256": digest(args.artifact),
        "source_sha256": hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest(),
        "input_sha256": INPUT_SHA256,
        "input_bytes": INPUT_BYTES,
        "records": 250000,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "module": str(package),
        "wall_s": elapsed,
        "cpu_s": cpu_s,
        "peak_rss_mb": peak,
        "tracing": traced,
        "exit_code": code,
    }
    with args.receipt.open("x", encoding="utf-8") as stream:
        json.dump(row, stream, indent=2)
    return 0 if row["status"] == "PASS" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path)
    for name in ("artifact", "input", "receipt"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--runs", type=int, choices=(3,), default=3)
    parser.add_argument("--child", action="store_true")
    args = parser.parse_args()
    if args.child:
        return child(args)
    if args.python is None or args.runs < 1:
        parser.error("--python and positive --runs required")
    if args.receipt.exists():
        raise ValueError("Receipt exists")
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PYTHON", "COVERAGE"))}
    rows = []
    for index in range(args.runs):
        receipt = args.receipt.with_name(args.receipt.stem + f"-{index + 1}.json").resolve()
        command = [
            str(args.python.resolve()),
            "-I",
            str(Path(__file__).resolve()),
            "--child",
            "--artifact",
            str(args.artifact.resolve()),
            "--input",
            str(args.input.resolve()),
            "--receipt",
            str(receipt),
        ]
        with (
            receipt.with_suffix(".stdout.log").open("xb") as out,
            receipt.with_suffix(".stderr.log").open("xb") as err,
        ):
            try:
                result = subprocess.run(command, env=env, stdout=out, stderr=err, timeout=600)
                returncode = result.returncode
            except (OSError, subprocess.TimeoutExpired) as error:
                err.write((type(error).__name__ + "\n").encode())
                returncode = -1
        row = (
            json.loads(receipt.read_text(encoding="utf-8"))
            if receipt.exists()
            else {"status": "FAIL", "reason": "measurement unavailable"}
        )
        if returncode != 0:
            row["status"] = "FAIL"
        if not receipt.exists():
            row.update(
                artifact=args.artifact.name,
                artifact_sha256=digest(args.artifact) if args.artifact.is_file() else None,
                input_sha256=digest(args.input) if args.input.is_file() else None,
                python=str(args.python.resolve()),
                platform=platform.platform(),
                exit_code=returncode,
            )
            with receipt.open("x", encoding="utf-8") as stream:
                json.dump(row, stream, indent=2)
        rows.append(row)
        print(json.dumps(row), flush=True)
    summary = {
        "status": "PASS" if all(row["status"] == "PASS" for row in rows) else "FAIL",
        "runs": rows,
    }
    with args.receipt.open("x", encoding="utf-8") as stream:
        json.dump(summary, stream, indent=2)
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
