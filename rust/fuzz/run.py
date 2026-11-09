"""Bounded, seeded Python/Rust differential campaigns; no automatic cloud launch."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

from cases import MAX_CASES, MAX_LINE, encoded, iter_cases

PIN = "02694d537104659df66cdd084354739f3cccc440"
HERE = Path(__file__).resolve().parent
TIMEOUT = 120
MAX_OUTPUT = 134_217_728
MAX_CORPUS = 16_777_216


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def export_source(repo: Path, destination: Path) -> str:
    archive = subprocess.run(
        ["git", "archive", "--format=zip", PIN, "src/sesslint"],
        cwd=repo,
        check=True,
        capture_output=True,
        timeout=30,
    ).stdout
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        for member in bundle.infolist():
            path = Path(member.filename)
            if path.is_absolute() or ".." in path.parts or path.parts[:2] != ("src", "sesslint"):
                # git archive also includes the harmless parent directory entry.
                if member.filename == "src/":
                    continue
                raise ValueError("source_archive_path")
            if member.is_dir():
                continue
            target = destination / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(bundle.read(member))
    return digest(archive)


def batch(command: list[str], corpus: bytes, temporary: Path, name: str, deadline: float) -> bytes:
    """Read at most the cap plus one byte; kill the direct child on overflow."""
    input_path = temporary / "input.jsonl"
    input_path.write_bytes(corpus)
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONHASHSEED"] = "0"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    timeout = min(TIMEOUT, deadline - time.monotonic())
    if timeout <= 0:
        raise ValueError("campaign_deadline")
    captured: list[bytes] = []
    with input_path.open("rb") as stdin:
        process = subprocess.Popen(
            command,
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
        )

        def capture() -> None:
            assert process.stdout is not None
            with process.stdout as stream:
                data = stream.read(MAX_OUTPUT + 1)
                captured.append(data)
                if len(data) > MAX_OUTPUT:
                    process.kill()

        reader = threading.Thread(target=capture, daemon=True)
        reader.start()
        try:
            process.wait(timeout=timeout)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            reader.join(timeout=5)
    if reader.is_alive() or len(captured) != 1:
        raise ValueError("output_reader_failed")
    if len(captured[0]) > MAX_OUTPUT:
        raise ValueError("output_budget")
    if process.returncode:
        raise ValueError(f"{name}_exit_{process.returncode}")
    return captured[0]


def corpus_for(seed: int, count: int) -> tuple[list[dict[str, Any]], bytes]:
    data = bytearray()
    metadata = []
    for case in iter_cases(seed, count):
        line = encoded(case)
        if len(data) + len(line) > MAX_CORPUS:
            raise ValueError("corpus_budget")
        data.extend(line)
        metadata.append({"id": case["id"], "op": case["op"], "input_sha256": digest(line)})
    repeated_hash = hashlib.sha256()
    repeated_size = 0
    for case in iter_cases(seed, count):
        line = encoded(case)
        repeated_size += len(line)
        if repeated_size > MAX_CORPUS:
            raise ValueError("corpus_budget")
        repeated_hash.update(line)
    if repeated_hash.hexdigest() != digest(data):
        raise ValueError("generator_nondeterminism")
    return metadata, bytes(data)


def responses(raw: bytes, count: int) -> list[dict[str, Any]]:
    if not raw.endswith(b"\n") or len(raw) > MAX_OUTPUT:
        raise ValueError("output_framing")
    lines = raw.splitlines()
    if len(lines) != count:
        raise ValueError("output_count")
    result = []
    for index, line in enumerate(lines):
        if len(line) > MAX_LINE:
            raise ValueError("output_line_budget")
        row = json.loads(line)
        if not isinstance(row, dict) or type(row.get("id")) is not int or row["id"] != index:
            raise ValueError("output_order")
        if type(row.get("ok")) is not bool:
            raise ValueError("output_status")
        result.append(row)
    return result


def compare(cases: list[dict[str, Any]], left: bytes, right: bytes) -> list[dict[str, Any]]:
    python = responses(left, len(cases))
    rust = responses(right, len(cases))
    mismatches = []
    for case, expected, actual in zip(cases, python, rust, strict=True):
        # Canonical JSON comparison preserves JSON type distinctions (True != 1).
        if encoded(expected) != encoded(actual):
            mismatches.append(
                {
                    "id": case["id"],
                    "op": case["op"],
                    "input_sha256": case.get("input_sha256", digest(encoded(case))),
                    "python_sha256": digest(encoded(expected)),
                    "rust_sha256": digest(encoded(actual)),
                }
            )
    return mismatches


def campaign(repo: Path, probe: Path, seed: int, count: int) -> dict[str, Any]:
    deadline = time.monotonic() + 240
    cases, corpus = corpus_for(seed, count)
    with tempfile.TemporaryDirectory(prefix="sesslint-fuzz-") as temporary_name:
        temporary = Path(temporary_name)
        source_hash = export_source(repo, temporary / "source")
        python_command = [
            sys.executable,
            "-B",
            str(HERE / "oracle.py"),
            "--source",
            str(temporary / "source"),
        ]
        left = batch(python_command, corpus, temporary, "python", deadline)
        right = batch([str(probe)], corpus, temporary, "rust", deadline)
        if left != batch(python_command, corpus, temporary, "python_repeat", deadline):
            raise ValueError("backend_nondeterminism")
        if right != batch([str(probe)], corpus, temporary, "rust_repeat", deadline):
            raise ValueError("backend_nondeterminism")
    mismatches = compare(cases, left, right)
    return {
        "schema_version": 1,
        "status": "FAIL" if mismatches else "PASS",
        "contains_real_data": False,
        "python_pin": PIN,
        "source_archive_sha256": source_hash,
        "seed": seed,
        "cases": count,
        "operations": dict(sorted(Counter(case["op"] for case in cases).items())),
        "corpus_sha256": digest(corpus),
        "python_output_sha256": digest(left),
        "rust_output_sha256": digest(right),
        "probe_sha256": digest(probe.read_bytes()),
        "generator_sha256": digest((HERE / "cases.py").read_bytes()),
        "oracle_sha256": digest((HERE / "oracle.py").read_bytes()),
        "runner_sha256": digest(Path(__file__).read_bytes()),
        "repeated_batches_identical": True,
        "mismatches": mismatches,
        "claim_limit": "codec typed domain and three adapter helpers; not full adapter/CLI parity",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=HERE.parents[1])
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20261109)
    parser.add_argument("--cases", type=int, default=10_000)
    args = parser.parse_args()
    if not 1 <= args.cases <= MAX_CASES:
        parser.error("case count outside budget")
    # Exclusive creation prevents overwriting input or a previous receipt.
    with args.receipt.open("xb") as target:
        try:
            report = campaign(args.repo.resolve(), args.probe.resolve(), args.seed, args.cases)
        except (ValueError, OSError, subprocess.SubprocessError, zipfile.BadZipFile):
            report = {
                "schema_version": 1,
                "status": "INFRA_ERROR",
                "seed": args.seed,
                "cases": args.cases,
            }
        target.write(encoded(report))
    print(f"status={report['status']} cases={args.cases}")
    return {"PASS": 0, "FAIL": 1, "INFRA_ERROR": 2}[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
