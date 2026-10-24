"""Release-rehearsal pins: counts quoted in docs/scripts must follow their sources of truth.

Covers the 0.5.0 rehearsal findings: stale detector-code counts (registry size),
the shared smoke-contract case count, and installed schema resources vs ``schemas/``.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from scripts.build_starter_kit import build as build_kit

from sesslint.codes import ALL_CODES

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "scripts" / "smoke_contract.json"


def _text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("relative", "pattern"),
    [
        ("README.md", r"\*\*(\d+) registered diagnostic codes\*\*"),
        ("docs/README.md", r"all (\d+) diagnostic reason codes"),
        ("RELEASING.md", r"all (\d+) detector codes and all 13"),
        ("RELEASING.md", r"All (\d+) detector codes have actual golden"),
        ("tests/MATRIX.md", r"The (\d+)-code public detection goldens"),
        ("fixtures/INDEX.md", r"cover all (\d+) codes"),
    ],
)
def test_documented_code_counts_equal_registry_size(relative: str, pattern: str) -> None:
    match = re.search(pattern, _text(relative))
    assert match, f"{relative}: statement {pattern!r} not found"
    assert int(match.group(1)) == len(ALL_CODES), relative


def test_detector_goldens_cover_exactly_the_registry() -> None:
    covered: set[str] = set()
    for path in (ROOT / "fixtures/conformance/detectors").glob("*.expected.json"):
        covered.update(f["code"] for f in json.loads(path.read_text(encoding="utf-8"))["findings"])
    assert covered == set(ALL_CODES)


def test_sandbox_acceptance_derives_its_code_set_instead_of_pinning_a_count() -> None:
    source = _text("scripts/sandbox_acceptance.py")
    assert "len(observed) ==" not in source
    assert "observed == documented" in source


@pytest.mark.parametrize(
    ("relative", "pattern"),
    [
        ("scripts/installed_smoke.py", r'len\(contract\["cases"\]\) == (\d+)'),
        ("scripts/installed_smoke.py", r'for case in contract\["cases"\]\}\) == (\d+)'),
        ("scripts/release_artifacts.py", r"len\(cases\) != (\d+)"),
        ("scripts/release_artifacts.py", r"for case in cases\}\) != (\d+)"),
        ("scripts/release_artifacts.py", r"shared (\d+)-case contract"),
        ("scripts/Test-SessLint.ps1", r"cases\.Count -eq (\d+)"),
        ("scripts/Test-SessLint.ps1", r"Unique\)\.Count -eq (\d+)"),
        ("scripts/Test-SessLint.ps1", r"PASS: (\d+) CLI cases"),
        ("scripts/build_windows_acceptance.py", r"runs the same (\d+) cases"),
        ("RELEASING.md", r"shared contract has (\d+) CLI cases"),
        ("RELEASING.md", r"and (\d+)-case"),
        ("docs/STARTER_KIT.md", r"All (\d+) CLI cases must pass"),
        ("docs/MIGRATING_0_5.md", r"contract has (\d+) CLI cases"),
        ("tests/test_windows_acceptance.py", r"for case in contract\[\"cases\"\]\}\) == (\d+)"),
    ],
)
def test_smoke_case_count_pins_match_the_contract(relative: str, pattern: str) -> None:
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    ids = [case["id"] for case in contract["cases"]]
    assert len(ids) == len(set(ids))
    match = re.search(pattern, _text(relative))
    assert match, f"{relative}: pin {pattern!r} not found"
    assert int(match.group(1)) == len(ids), relative


def test_installed_smoke_has_no_hard_coded_schema_count() -> None:
    source = _text("scripts/installed_smoke.py")
    assert "len(schema_files) ==" not in source
    assert 'Path("schemas").glob("*.json")' in source


def test_starter_kit_ships_every_schema_and_the_outcome_example(tmp_path: Path) -> None:
    kit = tmp_path / "kit.zip"
    build_kit(kit, "0.0.0")
    with zipfile.ZipFile(kit) as archive:
        names = set(archive.namelist())
        shipped = {n.split("/", 1)[1] for n in names if n.startswith("schemas/")}
        assert shipped == {p.name for p in (ROOT / "schemas").iterdir() if p.is_file()}
        assert {"sesslint.outcome-contract.v1.json", "sesslint.outcome-report.v1.json"} <= shipped
        assert "OUTCOME.md" in names
        assert archive.read("OUTCOME.md") == (ROOT / "docs/OUTCOME.md").read_bytes()
        provenance = json.loads(archive.read("examples/outcome/PROVENANCE.json"))
        assert provenance["contains_real_data"] is False
        for name in ("contract.json", "source.csv", "target_complete.json"):
            assert f"examples/outcome/{name}" in names
        # The kit's provenance describes the files the kit ships, not the repository fixture.
        shipped_outcome = {n for n in names if n.startswith("examples/outcome/")}
        assert shipped_outcome == {
            "examples/outcome/" + n
            for n in ("contract.json", "source.csv", "target_complete.json", "PROVENANCE.json")
        }
        assert "jsonl" not in provenance["description"].lower()
        assert "target_complete" not in provenance["description"]  # described by kind, not name
        assert "complete sesslint.snapshot/v1 envelope" in provenance["description"]


def test_kit_outcome_guide_points_at_the_shipped_example() -> None:
    guide = _text("docs/OUTCOME.md")
    assert "`examples/outcome/`" in guide
    # The repository fixture stays linked for readers of the GitHub copy.
    assert "fixtures/outcome/orders" in guide


def test_source_immutability_check_covers_nested_example_files() -> None:
    powershell = _text("scripts/Test-SessLint.ps1")
    assert "Get-ChildItem -LiteralPath $Root -File -Recurse" in powershell
    assert "$before = Example-Hash $examples" in powershell
    assert "ContainsKey($name)" in powershell
    assert "-File | ForEach-Object { $before[$_.Name]" not in powershell
    python_runner = _text("scripts/installed_smoke.py")
    assert (
        'root.rglob("*")' in python_runner and "assert before == example_hashes()" in python_runner
    )
    assert ".iterdir() if p.is_file()}" not in python_runner


def test_starter_kit_build_is_byte_reproducible(tmp_path: Path) -> None:
    left, right = tmp_path / "left.zip", tmp_path / "right.zip"
    build_kit(left, "0.0.0")
    build_kit(right, "0.0.0")
    assert left.read_bytes() == right.read_bytes()


def test_outcome_smoke_cases_are_read_only_and_deterministic(tmp_path: Path) -> None:
    """Run the shipped outcome cases through the source CLI; no install claim."""
    kit = tmp_path / "kit.zip"
    build_kit(kit, "0.0.0")
    work = tmp_path / "synthetic work"
    with zipfile.ZipFile(kit) as archive:
        archive.extractall(work)
    contract = json.loads((work / "smoke-contract.json").read_text(encoding="utf-8"))
    cases = [case for case in contract["cases"] if case["id"].startswith("outcome")]
    assert [case["id"] for case in cases] == ["outcome", "outcome-repeat"]
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("PYTHON", "COVERAGE", "SESSLINT_"))
    }
    env["PYTHONUTF8"] = "1"
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
        isolated = work / "isolated" / key
        isolated.mkdir(parents=True)
        env[key] = str(isolated)

    def snapshot() -> dict[Path, tuple[bytes, int] | None]:
        return {
            path.relative_to(work): (path.read_bytes(), path.stat().st_mtime_ns)
            if path.is_file()
            else None
            for path in work.rglob("*")
        }

    before = snapshot()
    outputs: dict[str, str] = {}
    for case in cases:
        assert case["no_writes"] is True and "--as-of" in case["args"]
        result = subprocess.run(
            [sys.executable, "-m", "sesslint", *case["args"]],
            cwd=work,
            env=env,
            capture_output=True,
            encoding="utf-8",
            timeout=60,
        )
        assert result.returncode in case["exit_codes"], result.stderr
        if "json_equals" in case:
            document = json.loads(result.stdout)
            for field, expected in case["json_equals"].items():
                value = document
                for part in field.split("."):
                    value = value[part]
                assert value == expected, (case["id"], field)
        if "stdout_equals" in case:
            assert result.stdout == outputs[case["stdout_equals"]]
        outputs[case["id"]] = result.stdout
        assert snapshot() == before, case["id"]
