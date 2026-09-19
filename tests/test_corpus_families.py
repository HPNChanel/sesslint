"""Real-shape corpus family evaluation (qa-infra T-05).

Walks ``fixtures/corpus/<family>/EXPECTATIONS.json`` and evaluates every
fixture through the public API + CLI, asserting:

- exact finding-code set equality (stronger than the hostile corpus' subset
  check — these families pin *field-observed* shapes, so extra codes are as
  interesting as missing ones);
- exact assurance level;
- CLI exit code parity;
- clean files produce zero error/fatal findings;
- every fixture directory carries ``PROVENANCE.json`` with
  ``contains_real_data: false`` (the provenance gate also enforces this
  globally — asserted here per family for clarity).

Families (all synthetic, shapes re-authored from observed structure):

- ``codex-telemetry``: additive drift shapes seen in the real baseline
  (token_count, task_started/complete, item_completed, turn_aborted,
  thread_settings_applied, metadata envelope key, world_state,
  token_usage_record, inter_agent_communication_metadata).
- ``claude-2x``: Claude Code 2.x semver versions, summary compaction
  records, isSidechain subtrees, queue-operation records.
- ``big-lines``: legitimate ~1.5 MiB single-line payloads.
- ``compaction-chains``: compaction boundaries + post-boundary tool calls
  (SL203 unsafe-continuation shapes + coverage-pointer gaps).
- ``mixed-integrity``: files combining 2+ corruption classes.

Regression rule (FIXTURES.md): every future real-data finding becomes a
synthetic fixture family here before the fix lands.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.api import check_file
from sesslint.cli import main

CORPUS_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "corpus"

FAMILIES = sorted(p.name for p in CORPUS_DIR.iterdir() if p.is_dir())


def _load_expectations(family: str) -> dict[str, dict[str, object]]:
    path = CORPUS_DIR / family / "EXPECTATIONS.json"
    assert path.is_file(), f"Missing {path}"
    return json.loads(path.read_text(encoding="utf-8"))


def test_families_present() -> None:
    """All five field-observed families exist."""
    assert set(FAMILIES) == {
        "big-lines",
        "claude-2x",
        "codex-telemetry",
        "compaction-chains",
        "mixed-integrity",
    }


@pytest.mark.parametrize("family", FAMILIES)
def test_family_provenance(family: str) -> None:
    prov = json.loads((CORPUS_DIR / family / "PROVENANCE.json").read_text(encoding="utf-8"))
    assert prov.get("contains_real_data") is False, (
        f"{family}: corpus fixtures must be synthetic-only"
    )
    assert prov.get("origin") == "synthetic"


@pytest.mark.parametrize("family", FAMILIES)
def test_corpus_family_expectations(family: str) -> None:
    """Every corpus fixture matches its EXPECTATIONS.json row exactly."""
    expectations = _load_expectations(family)
    assert expectations, f"{family}: EXPECTATIONS.json must not be empty"

    for rel_path, spec in expectations.items():
        fixture_file = CORPUS_DIR / family / rel_path
        assert fixture_file.exists(), f"{family}: fixture missing {rel_path}"

        report = check_file(fixture_file)

        # Exact assurance (same rigor as the hostile corpus).
        assert report.assurance == spec["expected_assurance"], (
            f"{family}/{rel_path}: assurance {report.assurance} != {spec['expected_assurance']}"
        )
        assert report.limitation, f"{family}/{rel_path}: limitation must be non-empty"

        # Exact finding-code SET — the field-shape regression guard.
        got_codes = sorted({f.code for f in report.findings})
        want_codes = sorted(spec["codes"])  # type: ignore[arg-type]
        assert got_codes == want_codes, f"{family}/{rel_path}: codes {got_codes} != {want_codes}"

        # CLI exit parity.
        cli_exit = main(["check", str(fixture_file)])
        assert cli_exit == int(str(spec["exit"])), (
            f"{family}/{rel_path}: CLI exit {cli_exit} != {spec['exit']}"
        )

        # Clean expectations really are clean.
        if int(str(spec["exit"])) == 0:
            assert report.counts.by_severity.get("error", 0) == 0
            assert report.counts.by_severity.get("fatal", 0) == 0


def test_expectations_cover_all_fixture_files() -> None:
    """Every data file in corpus/ has an EXPECTATIONS row (no orphans)."""
    for family in FAMILIES:
        expectations = _load_expectations(family)
        data_files = {
            p.name
            for p in (CORPUS_DIR / family).iterdir()
            if p.suffix in (".json", ".jsonl")
            and p.name not in ("EXPECTATIONS.json", "PROVENANCE.json")
            and p.name not in expectations
        }
        assert not data_files, f"{family}: fixtures lacking expectations: {data_files}"
