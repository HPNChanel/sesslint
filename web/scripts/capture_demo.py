"""Capture real SessLint CLI output for the landing-page replay.

Runs the installed CLI against synthetic fixtures (PROVENANCE.json says
``contains_real_data: false``) in a temp directory and writes
``web/src/data/demo.json``. The site never fakes terminal output: rerun this
after CLI changes (CI does) and commit the result so local builds work
without Python.

Build-time tooling only; never shipped. Usage (from ``web/``)::

    uv run --project .. python scripts/capture_demo.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

WEB = Path(__file__).resolve().parents[1]
REPO = WEB.parent
OUT = WEB / "src" / "data" / "demo.json"

FIXTURES = {
    "session.jsonl": REPO / "fixtures" / "repair" / "exec_basic" / "source.jsonl",
    "blocked.jsonl": REPO / "fixtures" / "repair" / "exec_refuse_sl203" / "source.jsonl",
}

STEPS: dict[str, list[str]] = {
    "check": ["check", "session.jsonl"],
    "triage": ["triage", "session.jsonl"],
    "repair": ["repair", "session.jsonl", "-o", "session.repaired.jsonl", "--seal", "ledger.jsonl"],
    "verify": [
        "verify",
        "session.jsonl",
        "session.repaired.jsonl",
        "--manifest",
        "session.repaired.jsonl.manifest.json",
    ],
    "seal": ["seal", "--verify", "ledger.jsonl"],
    "refuse": ["triage", "blocked.jsonl"],
}


def provenance_ok(path: Path) -> bool:
    prov = json.loads((path.parent / "PROVENANCE.json").read_text(encoding="utf-8"))
    return prov.get("contains_real_data") is False


def structure(path: Path) -> list[dict[str, object]]:
    """Graph shape only (ids, parents, kinds); payloads are never copied."""
    events: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        rec = json.loads(line)
        if "id" not in rec:
            continue
        events.append(
            {
                "id": rec["id"],
                "parent": rec.get("parent_id"),
                "kind": rec.get("kind"),
                "actor": rec.get("actor"),
                "seq": rec.get("seq"),
            }
        )
    return events


def run(cwd: Path, args: list[str]) -> dict[str, object]:
    exe = shutil.which("sesslint")
    cmd = [exe, *args] if exe else [sys.executable, "-m", "sesslint", *args]
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "NO_COLOR": "1"},
    )
    out = (proc.stdout + proc.stderr).replace(str(cwd), ".").replace("\r\n", "\n").rstrip()
    return {"cmd": "sesslint " + " ".join(args), "exit": proc.returncode, "out": out}


def main() -> int:
    for src in FIXTURES.values():
        if not provenance_ok(src):
            print(f"refusing non-synthetic fixture: {src}", file=sys.stderr)
            return 2
    with tempfile.TemporaryDirectory(prefix="sesslint-demo-") as tmp:
        work = Path(tmp)
        for name, src in FIXTURES.items():
            shutil.copyfile(src, work / name)
        steps = {key: run(work, args) for key, args in STEPS.items()}
    version = run(REPO, ["version"])["out"]
    data = {
        "generated_by": "web/scripts/capture_demo.py",
        "version": str(version).splitlines()[0] if version else "",
        "graph": structure(FIXTURES["session.jsonl"]),
        "steps": steps,
    }
    OUT.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {OUT.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
