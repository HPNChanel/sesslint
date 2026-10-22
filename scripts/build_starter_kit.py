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
# Synthetic OutcomeGuard orders-to-shipments example (see docs/OUTCOME.md); the
# smoke contract's ``outcome`` cases run it with an explicit ``--as-of``. The kit ships only
# these files; the repository fixture also has a raw JSONL target and an expected report.
OUTCOME_EXAMPLES = ("contract.json", "source.csv", "target_complete.json")
OUTCOME_FIXTURE = "fixtures/outcome/orders"
OUTCOME_PROVENANCE_DESCRIPTION = (
    "Synthetic OutcomeGuard orders-to-shipments scenario: one contract, a CSV source of "
    "invented order ids, and the invented shipment records as a complete "
    "sesslint.snapshot/v1 envelope."
)


def outcome_provenance() -> bytes:
    """Kit provenance for ``examples/outcome``: the fixture's, describing only shipped files."""
    provenance = json.loads((ROOT / OUTCOME_FIXTURE / "PROVENANCE.json").read_bytes())
    if provenance.get("contains_real_data") is not False:
        raise ValueError("Outcome example provenance must explicitly exclude real data")
    provenance["description"] = OUTCOME_PROVENANCE_DESCRIPTION
    return json.dumps(provenance, indent=2, sort_keys=True).encode() + b"\n"


def build(target: Path, version: str) -> None:
    files: dict[str, bytes] = {
        "QUICKSTART.md": (ROOT / "docs/STARTER_KIT.md").read_bytes(),
        "VERIFYING.md": (ROOT / "docs/VERIFYING.md").read_bytes(),
        "TRIAGE.md": (ROOT / "docs/TRIAGE.md").read_bytes(),
        "OUTCOME.md": (ROOT / "docs/OUTCOME.md").read_bytes(),
        "LICENSE": (ROOT / "LICENSE").read_bytes(),
        "NOTICE": (ROOT / "NOTICE").read_bytes(),
        "smoke-contract.json": (ROOT / "scripts/smoke_contract.json").read_bytes(),
        "VERSION": (version + "\n").encode(),
        "examples/unsupported.txt": b"Synthetic unsupported artifact for offline triage.\n",
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
                "healthy.jsonl": {
                    "check_exit": 0,
                    "findings": [],
                    "triage_status": "checked",
                    "triage_exit": 0,
                },
                "repairable.jsonl": {
                    "check_code": "SL003",
                    "repair_exit": 0,
                    "triage_status": "checked",
                    "triage_exit": 0,
                },
                "refused.json": {
                    "check_code": "SL203",
                    "repair_creates_output": False,
                    "triage_status": "blocked",
                    "triage_exit": 1,
                },
                "unsupported.txt": {"triage_status": "unsupported", "triage_exit": 1},
            },
            indent=2,
            sort_keys=True,
        ).encode()
        + b"\n",
    }
    files.update(
        {f"examples/{name}": (ROOT / source).read_bytes() for name, source in EXAMPLES.items()}
    )
    files.update(
        {
            f"examples/outcome/{name}": (ROOT / OUTCOME_FIXTURE / name).read_bytes()
            for name in OUTCOME_EXAMPLES
        }
    )
    files["examples/outcome/PROVENANCE.json"] = outcome_provenance()
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
