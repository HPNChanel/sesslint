#!/usr/bin/env python3
"""T-12 shared installed-artifact acceptance outside checkout, with Unicode paths.

Use --python with a non-editable wheel/sdist installation, or --binary with a
native executable. Receipts bind tested artifact bytes and platform; they never
claim evidence from an OS this process did not run on.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


API_PROGRAM = """
import importlib, json
from pathlib import Path
from sesslint import api
from sesslint.canonical import get_session_schema_path
import sesslint
assert not Path(sesslint.__file__).resolve().is_relative_to(Path({repository!r}))
loaded = []
for module, names in {{
    "canonical": ["session"], "finding": ["finding"],
    "report": ["report", "manifest"], "scan": ["scan"],
    "repair.planner": ["plan"], "bundle": ["bundle"], "diff": ["diff"],
    "doctor": ["doctor"], "stats": ["stats"], "seal": ["seal"],
    "preview": ["preview"], "batch": ["batch"],
}}.items():
    m = importlib.import_module("sesslint." + module)
    for name in names:
        schema = getattr(m, "load_" + name + "_schema")()
        assert schema["$schema"] and schema["$id"]
        loaded.append(name)
schema_files = sorted(get_session_schema_path().parent.glob("*.json"))
assert len(schema_files) == 16
assert all(isinstance(json.loads(p.read_text(encoding="utf-8")), dict) for p in schema_files)
source = Path("examples/repairable.jsonl")
plan = api.plan_repair(source)
assert plan.steps and not plan.blocked
_, manifest = api.apply_plan(source, plan.to_dict(), output_path="api-output.jsonl")
assert manifest is not None
verdict = api.verify(source, "api-output.jsonl", "api-output.jsonl.manifest.json")
assert verdict.ok
print(json.dumps({{
    "schemas": loaded, "schema_files": [p.name for p in schema_files], "api": "PASS"
}}))
"""


def run(artifact: Path, kit: Path, *, python: bool, version: str) -> dict:
    artifact, kit = artifact.resolve(), kit.resolve()
    receipt: dict = {
        "schema_version": 1,
        "version": version,
        "platform": platform.system(),
        "architecture": platform.machine(),
        "python_driver": platform.python_version(),
        "artifact": artifact.name,
        "artifact_sha256": sha(artifact),
        "starter_kit_sha256": sha(kit),
        "kind": "installed-python" if python else "binary",
        "checks": [],
    }
    with tempfile.TemporaryDirectory(
        prefix="sesslint handoff \u0111\u01b0\u1eddng d\u1eabn "
    ) as raw:
        cwd = Path(raw)
        with zipfile.ZipFile(kit) as archive:
            for member in archive.namelist():
                target = (cwd / member).resolve()
                if not target.is_relative_to(cwd):
                    raise ValueError("Unsafe starter kit path")
            archive.extractall(cwd)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("PYTHON", "COVERAGE"))}
        env.update(PYTHONUTF8="1", NO_COLOR="1")
        if python:
            command = [str(artifact), "-I", "-m", "sesslint"]
        else:
            # Relocate executable too; no Python interpreter on PATH.
            relocated = cwd / artifact.name
            shutil.copy2(artifact, relocated)
            command = [str(relocated)]
            env["PATH"] = (
                str(Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32")
                if os.name == "nt"
                else "/usr/bin:/bin"
            )
        # One declarative contract is consumed by Python and PowerShell (T-12).
        contract = json.loads((cwd / "smoke-contract.json").read_text(encoding="utf-8"))
        assert contract["schema_version"] == 1 and len(contract["cases"]) == 32
        assert len({case["id"] for case in contract["cases"]}) == 32
        for source, destination in contract["copies"]:
            target = cwd / destination
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(cwd / source, target)
        before = {p.name: sha(p) for p in (cwd / "examples").iterdir() if p.is_file()}
        for key in (
            "HOME",
            "USERPROFILE",
            "CODEX_HOME",
            "CLAUDE_CONFIG_DIR",
            "APPDATA",
            "LOCALAPPDATA",
            "TEMP",
            "TMP",
            "XDG_CACHE_HOME",
        ):
            isolated = cwd / "isolated" / key
            isolated.mkdir(parents=True, exist_ok=True)
            env[key] = str(isolated)

        def expand(value):
            if isinstance(value, str):
                return value.replace("{work}", cwd.as_posix()).replace("{version}", version)
            if isinstance(value, list):
                return [expand(item) for item in value]
            if isinstance(value, dict):
                return {key: expand(item) for key, item in value.items()}
            return value

        def field(value, key):
            for part in key.split("."):
                value = value[part]
            return value

        outputs = {}
        for original in contract["cases"]:
            case = expand(original)
            stdin = "".join(json.dumps(item) + "\n" for item in case.get("stdin_jsonl", []))
            completed = subprocess.run(
                command + case["args"],
                cwd=cwd,
                env=env,
                input=stdin,
                encoding="utf-8",
                errors="strict",
                capture_output=True,
                timeout=120,
            )
            if completed.returncode not in case["exit_codes"]:
                raise AssertionError(
                    f"{case['id']}: exit {completed.returncode}: {completed.stderr}"
                )
            output = completed.stdout
            for literal in case.get("contains", []):
                assert literal in output, case["id"]
            if "stdout_equals" in case:
                assert output == outputs[case["stdout_equals"]], case["id"]
            if "json_equals" in case or "json_sets" in case:
                data = json.loads(output)
                for key, expected in case.get("json_equals", {}).items():
                    assert field(data, key) == expected, (case["id"], key)
                for key, expected in case.get("json_sets", {}).items():
                    assert set(field(data, key)) == set(expected), (case["id"], key)
            for path in case.get("files_exist", []):
                assert (cwd / path).is_file(), case["id"]
            for path in case.get("files_absent", []):
                assert not (cwd / path).exists(), case["id"]
            for pattern in case.get("absent_globs", []):
                assert not list(cwd.glob(pattern)), case["id"]
            for left, right in case.get("equal_files", []):
                assert sha(cwd / left) == sha(cwd / right), case["id"]
            if "jsonl_success" in case:
                responses = [json.loads(line) for line in output.splitlines()]
                assert len(responses) == case["jsonl_success"]
                assert all("result" in item and "error" not in item for item in responses)
                assert responses[-1]["result"]["isError"] is False
            outputs[case["id"]] = output
            receipt["checks"].append(
                {"id": case["id"], "command": case["args"], "exit_code": completed.returncode}
            )
        receipt["contract_sha256"] = sha(cwd / "smoke-contract.json")
        if python:
            program = API_PROGRAM.format(repository=str(Path(__file__).resolve().parents[1]))
            completed = subprocess.run(
                [str(artifact), "-I", "-c", program],
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=120,
            )
            assert completed.returncode == 0, completed.stderr
            receipt["api"] = json.loads(completed.stdout)
        assert before == {p.name: sha(p) for p in (cwd / "examples").iterdir() if p.is_file()}
        receipt["source_immutable"] = True
        receipt["status"] = "PASS"
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--python", type=Path)
    group.add_argument("--binary", type=Path)
    parser.add_argument("--kit", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    result = run(
        args.python or args.binary, args.kit, python=bool(args.python), version=args.version
    )
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    print(f"PASS: {result['kind']} on {result['platform']}; {len(result['checks'])} CLI checks")
