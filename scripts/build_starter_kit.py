#!/usr/bin/env python3
"""T-12: deterministic, synthetic, offline user handoff archive (build-time only)."""

from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = {
    "healthy.jsonl": "fixtures/cli/check_basic/healthy.jsonl",
    "repairable.jsonl": "fixtures/repair_cli/basic/source.jsonl",
    "refused.json": "fixtures/checks/sl203_continuation.json",
    "claude.jsonl": "fixtures/claude_code/basic.jsonl",
    "codex.jsonl": "fixtures/adapters/codex/healthy_min.jsonl",
    "openai.json": "fixtures/openai_agents/items_basic.json",
}


def build(target: Path, version: str) -> None:
    files: dict[str, bytes] = {
        "QUICKSTART.md": (ROOT / "docs/STARTER_KIT.md").read_bytes(),
        "VERIFYING.md": (ROOT / "docs/VERIFYING.md").read_bytes(),
        "LICENSE": (ROOT / "LICENSE").read_bytes(),
        "NOTICE": (ROOT / "NOTICE").read_bytes(),
        "smoke-contract.json": (ROOT / "scripts/smoke_contract.json").read_bytes(),
        "VERSION": (version + "\n").encode(),
        "examples/PROVENANCE.json": json.dumps(
            {
                "origin": "synthetic",
                "contains_real_data": False,
                "generator": "SessLint committed synthetic fixtures",
                "seed": 41,
            },
            sort_keys=True,
        ).encode()
        + b"\n",
        "examples/expected.json": json.dumps(
            {
                "healthy.jsonl": {"check_exit": 0, "findings": []},
                "repairable.jsonl": {"check_code": "SL003", "repair_exit": 0},
                "refused.json": {"check_code": "SL203", "repair_creates_output": False},
            },
            indent=2,
            sort_keys=True,
        ).encode()
        + b"\n",
    }
    files.update(
        {f"examples/{name}": (ROOT / source).read_bytes() for name, source in EXAMPLES.items()}
    )
    for folder in ("schemas", "docs/codes", "docs/recipes"):
        for path in sorted((ROOT / folder).glob("*")):
            if path.is_file():
                files[path.relative_to(ROOT).as_posix()] = path.read_bytes()
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    build(args.output, args.version)
