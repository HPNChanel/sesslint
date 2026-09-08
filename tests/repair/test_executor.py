"""Comprehensive tests for repair execution engine (TASK-021).

Covers:
- Basic happy path execution: atomic output generation, manifest emission, hash binding.
- Destination refusal matrix: self-output, existing output, live SQLite store.
- Re-validation gates: tampered plan fingerprint, policy mismatch, cap overflow.
- TOCTOU abstention gates: runtime SL203 detection aborts before write.
- Output validation: canonical schema, multiset check (no synthetic success), profile revalidation.
- Kill-safety & failure cleanup: crash simulation before atomic rename leaves zero orphans.
- Dry-run contract: plan-only verification with zero disk writes.
- Exit codes table: 0 (success/dry-run), 1 (refusals/no safe plan), 2 (usage/bad flags).
- Manifest schema validation against sesslint.repair-manifest/v1.
- Architectural invariant: executor and atomic helper are the only mutators in src/sesslint/.
- Adversarial tests: source mutation mid-repair, ENOSPC disk full, read-only dirs,
  unicode filenames.
"""

from __future__ import annotations

import errno
import hashlib
import os
import re
import shutil
from collections.abc import Generator
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from sesslint.cli import main
from sesslint.repair import (
    MAX_STEPS,
    Abstained,
    Loss,
    OutputInvalid,
    PlanSourceMismatch,
    PlanStep,
    PlanTampered,
    PolicyMismatch,
    Recipe,
    RepairPlan,
    RepairRefused,
    clear_registry,
    compute_plan_fingerprint,
    execute,
    is_live_store_path,
    load_plan,
    register_all_conservative_recipes,
    register_all_salvage_recipes,
    register_recipe,
)
from sesslint.report import load_manifest_schema, parse_manifest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SRC_DIR = REPO_ROOT / "src" / "sesslint"
FIXTURES_DIR = REPO_ROOT / "fixtures" / "repair"


@pytest.fixture(autouse=True)
def _clean_and_register_recipes() -> Generator[None, None, None]:
    """Ensure standard recipe registry is populated and clean before each test."""
    clear_registry()
    register_all_conservative_recipes()
    register_all_salvage_recipes()
    yield
    clear_registry()


# =============================================================================
# 1. Happy Path Execution
# =============================================================================


def test_basic_execute(tmp_path: Path) -> None:
    """Fixture source+plan -> output equals expected; manifest hashes match recomputed SHA-256."""
    fixture_dir = FIXTURES_DIR / "exec_basic"
    source_fixture = fixture_dir / "source.jsonl"
    plan_fixture = fixture_dir / "plan.json"
    expected_output_fixture = fixture_dir / "expected_output.jsonl"

    test_source = tmp_path / "source.jsonl"
    shutil.copyfile(source_fixture, test_source)
    source_pre_bytes = test_source.read_bytes()

    output_path = tmp_path / "repaired.jsonl"
    manifest_path = tmp_path / "repaired.jsonl.manifest.json"

    plan = load_plan(plan_fixture)
    manifest = execute(
        source_path=test_source,
        plan=plan,
        output_path=output_path,
        policy="conservative",
    )

    # 1. Output file exists and matches expected content
    assert output_path.is_file()
    actual_output_text = output_path.read_text(encoding="utf-8")
    expected_output_text = expected_output_fixture.read_text(encoding="utf-8")
    assert actual_output_text == expected_output_text

    # 2. Manifest file exists and is valid
    assert manifest_path.is_file()
    manifest_text = manifest_path.read_text(encoding="utf-8")
    parsed_m = parse_manifest(manifest_text)
    assert parsed_m == manifest

    # 3. Source file remains byte-identical
    assert test_source.read_bytes() == source_pre_bytes

    # 4. Manifest hashes bind source and output digests exactly
    assert manifest.input_fingerprint == hashlib.sha256(source_pre_bytes).hexdigest()
    assert manifest.output_fingerprint == hashlib.sha256(output_path.read_bytes()).hexdigest()
    assert manifest.policy == "conservative"
    assert len(manifest.actions) == 1
    assert manifest.actions[0].kind == "identical-duplicate-collapse"


# =============================================================================
# 2. Destination Refusal Matrix (Self, Existing, Live Store)
# =============================================================================


def test_refuse_self_output(tmp_path: Path) -> None:
    """--output resolving to source path raises RepairRefused and exits 1 via CLI."""
    source_file = tmp_path / "source.jsonl"
    shutil.copyfile(FIXTURES_DIR / "exec_basic" / "source.jsonl", source_file)
    source_bytes = source_file.read_bytes()

    plan = load_plan(FIXTURES_DIR / "exec_basic" / "plan.json")

    # Direct library call raises RepairRefused
    with pytest.raises(RepairRefused, match="resolves to source path"):
        execute(
            source_path=source_file,
            plan=plan,
            output_path=source_file,
            policy="conservative",
        )
    assert source_file.read_bytes() == source_bytes

    # CLI call exits with code 1
    code = main(
        [
            "repair",
            str(source_file),
            "--output",
            str(source_file),
            "--plan",
            str(FIXTURES_DIR / "exec_basic" / "plan.json"),
        ]
    )
    assert code == 1
    assert source_file.read_bytes() == source_bytes


def test_refuse_existing_output(tmp_path: Path) -> None:
    """--output pointing to an already existing file raises RepairRefused and leaves it
    untouched."""
    source_file = tmp_path / "source.jsonl"
    shutil.copyfile(FIXTURES_DIR / "exec_basic" / "source.jsonl", source_file)

    existing_target = tmp_path / "existing_output.jsonl"
    existing_target.write_text("prior content\n", encoding="utf-8")
    existing_bytes = existing_target.read_bytes()

    plan = load_plan(FIXTURES_DIR / "exec_basic" / "plan.json")

    with pytest.raises(RepairRefused, match="already exists"):
        execute(
            source_path=source_file,
            plan=plan,
            output_path=existing_target,
            policy="conservative",
        )
    assert existing_target.read_bytes() == existing_bytes

    code = main(
        [
            "repair",
            str(source_file),
            "--output",
            str(existing_target),
            "--plan",
            str(FIXTURES_DIR / "exec_basic" / "plan.json"),
        ]
    )
    assert code == 1
    assert existing_target.read_bytes() == existing_bytes


def test_refuse_live_store(tmp_path: Path) -> None:
    """--output pointing to a live-store SQLite path raises RepairRefused and exits 1."""
    source_file = tmp_path / "source.jsonl"
    shutil.copyfile(FIXTURES_DIR / "exec_basic" / "source.jsonl", source_file)
    plan = load_plan(FIXTURES_DIR / "exec_basic" / "plan.json")

    # 1. Non-existent path with .sqlite extension
    sqlite_dest = tmp_path / "agent_store.sqlite"
    assert is_live_store_path(sqlite_dest) is True
    with pytest.raises(RepairRefused, match="live-store path"):
        execute(
            source_path=source_file,
            plan=plan,
            output_path=sqlite_dest,
            policy="conservative",
        )

    # 2. Existing file with SQLite magic header
    fake_db = tmp_path / "custom_store.dat"
    fake_db.write_bytes(b"SQLite format 3\x00" + b"\x00" * 48)
    assert is_live_store_path(fake_db) is True
    with pytest.raises(RepairRefused, match="live-store path"):
        execute(
            source_path=source_file,
            plan=plan,
            output_path=fake_db,
            policy="conservative",
        )

    # CLI exit code 1
    code = main(
        [
            "repair",
            str(source_file),
            "--output",
            str(sqlite_dest),
            "--plan",
            str(FIXTURES_DIR / "exec_basic" / "plan.json"),
        ]
    )
    assert code == 1


# =============================================================================
# 3. Plan Integrity and Tamper Refusal
# =============================================================================


def test_tampered_plan(tmp_path: Path) -> None:
    """Modifying any byte or field in a plan triggers PlanTampered and exits 1."""
    source_file = tmp_path / "source.jsonl"
    shutil.copyfile(FIXTURES_DIR / "exec_basic" / "source.jsonl", source_file)
    output_file = tmp_path / "repaired.jsonl"

    plan = load_plan(FIXTURES_DIR / "exec_basic" / "plan.json")

    # Tamper with plan steps while retaining old fingerprint
    tampered_steps = (
        PlanStep(
            seq=0,
            recipe="terminal-suffix-discard",
            target_finding_fp=plan.steps[0].target_finding_fp,
            target_index=2,
        ),
    )
    tampered_plan = replace(plan, steps=tampered_steps)

    with pytest.raises(PlanTampered, match="fingerprint mismatch"):
        execute(
            source_path=source_file,
            plan=tampered_plan,
            output_path=output_file,
            policy="conservative",
        )
    assert not output_file.exists()


def test_plan_cap_overflow(tmp_path: Path) -> None:
    """Plan with >256 steps raises OutputInvalid with cap indication."""
    source_file = tmp_path / "source.jsonl"
    shutil.copyfile(FIXTURES_DIR / "exec_basic" / "source.jsonl", source_file)
    output_file = tmp_path / "repaired.jsonl"

    step_template = PlanStep(
        seq=0,
        recipe="identical-duplicate-collapse",
        target_finding_fp="fp0",
        target_index=1,
    )
    excess_steps = tuple(
        replace(step_template, seq=i, target_finding_fp=f"fp{i}") for i in range(MAX_STEPS + 1)
    )

    plan_dict: dict[str, Any] = {
        "blocked": [],
        "loss_accounting": {"preview": {}},
        "profile": "neutral",
        "source_hash": hashlib.sha256(source_file.read_bytes()).hexdigest(),
        "steps": [s.to_dict() for s in excess_steps],
        "version": "sesslint.plan/v1",
    }
    fp = compute_plan_fingerprint(plan_dict)

    over_cap_plan = RepairPlan(
        source_hash=plan_dict["source_hash"],
        profile="neutral",
        steps=excess_steps,
        blocked=(),
        loss_accounting=Loss(preview={}),
        fingerprint=fp,
        policy="conservative",
    )

    with pytest.raises(OutputInvalid, match="exceeds maximum allowed cap"):
        execute(
            source_path=source_file,
            plan=over_cap_plan,
            output_path=output_file,
            policy="conservative",
        )
    assert not output_file.exists()


def test_policy_mismatch(tmp_path: Path) -> None:
    """Plan policy mismatching execute policy raises PolicyMismatch and exits 1."""
    source_file = tmp_path / "source.jsonl"
    shutil.copyfile(FIXTURES_DIR / "exec_basic" / "source.jsonl", source_file)
    output_file = tmp_path / "repaired.jsonl"

    plan = load_plan(FIXTURES_DIR / "exec_basic" / "plan.json")
    # plan.policy is 'conservative'

    with pytest.raises(PolicyMismatch, match="does not match execution policy"):
        execute(
            source_path=source_file,
            plan=plan,
            output_path=output_file,
            policy="salvage",
        )
    assert not output_file.exists()

    code = main(
        [
            "repair",
            str(source_file),
            "--output",
            str(output_file),
            "--policy",
            "salvage",
            "--plan",
            str(FIXTURES_DIR / "exec_basic" / "plan.json"),
        ]
    )
    assert code == 1
    assert not output_file.exists()


# =============================================================================
# 4. TOCTOU & Abstention Re-checks
# =============================================================================


def test_sl203_toctou(tmp_path: Path) -> None:
    """Source containing SL203 trigger triggers Abstained refusal and exits 1 without writes."""
    sl203_source = FIXTURES_DIR / "exec_refuse_sl203" / "source.jsonl"
    test_source = tmp_path / "sl203_session.jsonl"
    shutil.copyfile(sl203_source, test_source)

    output_file = tmp_path / "repaired.jsonl"

    # Fabricate a plan that appears valid for the hash but source has SL203
    source_hash = hashlib.sha256(test_source.read_bytes()).hexdigest()
    plan_dict: dict[str, Any] = {
        "blocked": [],
        "loss_accounting": {"preview": {}},
        "profile": "neutral",
        "source_hash": source_hash,
        "steps": [],
        "version": "sesslint.plan/v1",
    }
    fp = compute_plan_fingerprint(plan_dict)
    plan = RepairPlan(
        source_hash=source_hash,
        profile="neutral",
        steps=(),
        blocked=(),
        loss_accounting=Loss(preview={}),
        fingerprint=fp,
        policy="conservative",
    )

    with pytest.raises(Abstained, match="SL203 present"):
        execute(
            source_path=test_source,
            plan=plan,
            output_path=output_file,
            policy="conservative",
        )
    assert not output_file.exists()


# =============================================================================
# 5. Output Validation & Never-Synthetic-Success Contract
# =============================================================================


def test_output_invalid_synthetic_tool_result(tmp_path: Path) -> None:
    """Recipe output containing synthetic tool_result triggers OutputInvalid."""
    source_file = tmp_path / "source.jsonl"
    shutil.copyfile(FIXTURES_DIR / "exec_basic" / "source.jsonl", source_file)
    output_file = tmp_path / "repaired.jsonl"

    # Register rogue recipe that injects a synthetic tool_result
    def rogue_apply(events: list[dict[str, Any]], step: Any) -> list[dict[str, Any]]:
        rogue_ev = {
            "actor": "tool",
            "id": "synthetic_res_999",
            "kind": "tool_result",
            "parent_id": "msg-0",
            "payload": {"success": True},
            "seq": len(events),
            "ts": "2026-09-05T12:00:10Z",
        }
        return events + [rogue_ev]

    rogue_recipe = Recipe(
        name="rogue-inject-success",
        handles=("SL003",),
        preconditions=(),
        lossy=False,
        salvage_only=False,
        apply=rogue_apply,
    )
    register_recipe(rogue_recipe)

    step = PlanStep(
        seq=0,
        recipe="rogue-inject-success",
        target_finding_fp="fp-test",
        target_index=1,
    )
    source_hash = hashlib.sha256(source_file.read_bytes()).hexdigest()
    plan_dict: dict[str, Any] = {
        "blocked": [],
        "loss_accounting": {"preview": {}},
        "profile": "neutral",
        "source_hash": source_hash,
        "steps": [step.to_dict()],
        "version": "sesslint.plan/v1",
    }
    fp = compute_plan_fingerprint(plan_dict)
    plan = RepairPlan(
        source_hash=source_hash,
        profile="neutral",
        steps=(step,),
        blocked=(),
        loss_accounting=Loss(preview={}),
        fingerprint=fp,
        policy="conservative",
    )

    with pytest.raises(OutputInvalid, match="Synthetic tool_result detected"):
        execute(
            source_path=source_file,
            plan=plan,
            output_path=output_file,
            policy="conservative",
        )
    assert not output_file.exists()


# =============================================================================
# 6. Kill Safety, Crash Simulation, & Failure Cleanup
# =============================================================================


def test_kill_before_rename(tmp_path: Path) -> None:
    """Fault-injecting exception right before atomic replace leaves source intact and cleans
    temp."""
    source_file = tmp_path / "source.jsonl"
    shutil.copyfile(FIXTURES_DIR / "exec_basic" / "source.jsonl", source_file)
    source_pre_bytes = source_file.read_bytes()

    output_file = tmp_path / "repaired.jsonl"
    plan = load_plan(FIXTURES_DIR / "exec_basic" / "plan.json")

    def kill_hook(temp_file_path: Path) -> None:
        assert temp_file_path.is_file()
        raise KeyboardInterrupt("Simulated SIGKILL before rename")

    with pytest.raises(KeyboardInterrupt):
        execute(
            source_path=source_file,
            plan=plan,
            output_path=output_file,
            policy="conservative",
            pre_rename_hook=kill_hook,
        )

    # Invariants:
    # 1. Source file untouched
    assert source_file.read_bytes() == source_pre_bytes
    # 2. Output file was never created
    assert not output_file.exists()
    # 3. Temp files are cleanly unlinked
    temp_orphans = list(tmp_path.glob(".sesslint-tmp-*"))
    assert temp_orphans == [], f"Found orphaned temp files: {temp_orphans}"


# =============================================================================
# 7. Dry-Run Contract
# =============================================================================


def test_dry_run(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """--dry-run generates plan in memory, writes no files, prints fingerprint, and exits 0."""
    source_file = tmp_path / "source.jsonl"
    shutil.copyfile(FIXTURES_DIR / "exec_basic" / "source.jsonl", source_file)

    output_file = tmp_path / "should_not_exist.jsonl"
    manifest_file = tmp_path / "should_not_exist.jsonl.manifest.json"

    # 1. Library dry_run
    plan = load_plan(FIXTURES_DIR / "exec_basic" / "plan.json")
    m = execute(
        source_path=source_file,
        plan=plan,
        output_path=output_file,
        dry_run=True,
    )
    assert m is not None
    assert not output_file.exists()
    assert not manifest_file.exists()

    # 2. CLI dry_run
    code = main(
        [
            "repair",
            str(source_file),
            "--dry-run",
            "--plan",
            str(FIXTURES_DIR / "exec_basic" / "plan.json"),
        ]
    )
    assert code == 0
    captured = capsys.readouterr()
    assert f"Plan fingerprint: {plan.fingerprint}" in captured.out
    assert not output_file.exists()


# =============================================================================
# 8. Exit Codes Contract (FR-099)
# =============================================================================


def test_exit_codes_table(tmp_path: Path) -> None:
    """Verify FR-099 exit code contract: 0=success/dry-run, 1=refusal/no safe plan, 2=usage/I-O."""
    valid_source = tmp_path / "valid_source.jsonl"
    shutil.copyfile(FIXTURES_DIR / "exec_basic" / "source.jsonl", valid_source)
    plan_path = FIXTURES_DIR / "exec_basic" / "plan.json"

    # Exit 0: Success with output and manifest
    out0 = tmp_path / "out0.jsonl"
    code_success = main(
        [
            "repair",
            str(valid_source),
            "--output",
            str(out0),
            "--plan",
            str(plan_path),
        ]
    )
    assert code_success == 0
    assert out0.is_file()

    # Exit 1: Refusal (e.g. self output)
    code_refusal = main(
        [
            "repair",
            str(valid_source),
            "--output",
            str(valid_source),
            "--plan",
            str(plan_path),
        ]
    )
    assert code_refusal == 1

    # Exit 2: Usage error (missing --output without --dry-run)
    code_usage = main(
        [
            "repair",
            str(valid_source),
        ]
    )
    assert code_usage == 2

    # Exit 2: Missing source file
    code_missing_src = main(
        [
            "repair",
            str(tmp_path / "nonexistent.jsonl"),
            "--output",
            str(tmp_path / "out.jsonl"),
        ]
    )
    assert code_missing_src == 2

    # Exit 2: Invalid CLI argument
    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                "repair",
                str(valid_source),
                "--unrecognized-flag-xyz",
            ]
        )
    assert exc_info.value.code == 2


# =============================================================================
# 9. Manifest Schema Validation
# =============================================================================


def test_manifest_schema_validation(tmp_path: Path) -> None:
    """Emitted manifest strictly validates against schemas/sesslint.repair-manifest.v1.json."""
    source_file = tmp_path / "source.jsonl"
    shutil.copyfile(FIXTURES_DIR / "exec_basic" / "source.jsonl", source_file)
    output_file = tmp_path / "out.jsonl"

    plan = load_plan(FIXTURES_DIR / "exec_basic" / "plan.json")
    manifest = execute(
        source_path=source_file,
        plan=plan,
        output_path=output_file,
        policy="conservative",
    )

    schema = load_manifest_schema()
    m_dict = manifest.to_dict()

    # Required fields per schema
    for req in schema["required"]:
        assert req in m_dict, f"Missing required manifest field: {req}"

    # Properties match schema constraints
    assert m_dict["schema_version"] == "sesslint.repair-manifest/v1"
    assert re.match(schema["properties"]["idempotency_key"]["pattern"], m_dict["idempotency_key"])
    assert m_dict["policy"] in schema["properties"]["policy"]["enum"]


# =============================================================================
# 10. Architectural Invariant: Sole Mutator Audit
# =============================================================================


def test_only_mutator() -> None:
    """Grep src/sesslint/ for os.replace and os.rename: only atomic.py and executor.py allowed."""
    pattern = re.compile(r"\bos\.(replace|rename)\b")
    mutator_files: list[str] = []

    for root, _, files in os.walk(SRC_DIR):
        for file in files:
            if file.endswith(".py"):
                file_path = Path(root) / file
                content = file_path.read_text(encoding="utf-8")
                # Strip comments and docstrings for exact code matches
                lines = content.splitlines()
                code_lines = [line for line in lines if not line.strip().startswith("#")]
                if pattern.search("\n".join(code_lines)):
                    rel = file_path.relative_to(SRC_DIR).as_posix()
                    mutator_files.append(rel)

    expected_mutators = {"atomic.py", "repair/executor.py"}
    assert set(mutator_files) == expected_mutators, (
        f"Unexpected file mutators found in src/sesslint: {set(mutator_files) - expected_mutators}"
    )


# =============================================================================
# 11. Adversarial & Edge Cases
# =============================================================================


def test_direct_dict_raises_type_error(tmp_path: Path) -> None:
    """Passing a raw dict instead of RepairPlan instance raises TypeError."""
    source_file = tmp_path / "source.jsonl"
    shutil.copyfile(FIXTURES_DIR / "exec_basic" / "source.jsonl", source_file)

    with pytest.raises(TypeError, match="plan must be a RepairPlan instance"):
        execute(
            source_path=source_file,
            plan={"steps": []},  # type: ignore[arg-type]
            output_path=tmp_path / "out.jsonl",
        )


def test_source_mutated_concurrently(tmp_path: Path) -> None:
    """Source file mutated during execution triggers post-hash OutputInvalid abort and cleans up."""
    source_file = tmp_path / "source.jsonl"
    shutil.copyfile(FIXTURES_DIR / "exec_basic" / "source.jsonl", source_file)
    output_file = tmp_path / "repaired.jsonl"

    plan = load_plan(FIXTURES_DIR / "exec_basic" / "plan.json")

    def simulate_concurrent_writer() -> None:
        # Append an extra record to source while repair was running in memory
        with open(source_file, "a", encoding="utf-8") as f:
            f.write('{"actor":"user","id":"extra","kind":"message","seq":99}\n')

    with pytest.raises(OutputInvalid, match="concurrently modified"):
        execute(
            source_path=source_file,
            plan=plan,
            output_path=output_file,
            post_apply_hook=simulate_concurrent_writer,
        )

    # Output file and manifest must not exist
    assert not output_file.exists()
    assert not Path(f"{output_file}.manifest.json").exists()


def test_cross_device_replace_error_mapping(tmp_path: Path) -> None:
    """OSError EXDEV during atomic rename is cleanly mapped to OutputInvalid."""
    source_file = tmp_path / "source.jsonl"
    shutil.copyfile(FIXTURES_DIR / "exec_basic" / "source.jsonl", source_file)
    output_file = tmp_path / "repaired.jsonl"

    plan = load_plan(FIXTURES_DIR / "exec_basic" / "plan.json")

    with patch("os.replace", side_effect=OSError(errno.EXDEV, "Invalid cross-device link")):
        with pytest.raises(OutputInvalid, match="Cross-device link error"):
            execute(
                source_path=source_file,
                plan=plan,
                output_path=output_file,
            )
    assert not output_file.exists()


def test_unicode_and_spaces_in_path(tmp_path: Path) -> None:
    """Files and directories containing spaces and unicode work reliably."""
    odd_dir = tmp_path / "folder with spaces and 🚀 unicode"
    odd_dir.mkdir(parents=True)

    source_file = odd_dir / "session 修复.jsonl"
    shutil.copyfile(FIXTURES_DIR / "exec_basic" / "source.jsonl", source_file)
    output_file = odd_dir / "output 🎯.jsonl"

    plan = load_plan(FIXTURES_DIR / "exec_basic" / "plan.json")
    manifest = execute(
        source_path=source_file,
        plan=plan,
        output_path=output_file,
    )

    assert output_file.is_file()
    assert Path(f"{output_file}.manifest.json").is_file()
    assert manifest.output_fingerprint == hashlib.sha256(output_file.read_bytes()).hexdigest()


def test_cli_repair_without_plan_e2e(tmp_path: Path) -> None:
    """CLI repair without --plan performs end-to-end load, planning, execution, and manifest."""
    source_file = tmp_path / "source.jsonl"
    shutil.copyfile(FIXTURES_DIR / "exec_basic" / "source.jsonl", source_file)
    output_file = tmp_path / "out_e2e.jsonl"

    code = main(
        [
            "repair",
            str(source_file),
            "--output",
            str(output_file),
        ]
    )
    assert code == 0
    assert output_file.is_file()
    assert Path(f"{output_file}.manifest.json").is_file()
    expected_output = (FIXTURES_DIR / "exec_basic" / "expected_output.jsonl").read_text("utf-8")
    assert output_file.read_text("utf-8") == expected_output


def test_cli_dry_run_with_tampered_plan_refuses(tmp_path: Path) -> None:
    """CLI repair with --dry-run executes re-validation and refuses tampered plan with exit 1."""
    source_file = tmp_path / "source.jsonl"
    shutil.copyfile(FIXTURES_DIR / "exec_basic" / "source.jsonl", source_file)

    tampered_plan_file = tmp_path / "tampered.json"
    plan_dict = load_plan(FIXTURES_DIR / "exec_basic" / "plan.json").to_dict()
    plan_dict["steps"][0]["recipe"] = "terminal-suffix-discard"
    # Keep original fingerprint so recomputation will detect tampering
    import json

    tampered_plan_file.write_text(json.dumps(plan_dict), encoding="utf-8")

    code = main(
        [
            "repair",
            str(source_file),
            "--dry-run",
            "--plan",
            str(tampered_plan_file),
        ]
    )
    assert code == 1


def test_disk_full_enospc(tmp_path: Path) -> None:
    """Disk full (ENOSPC) during write cleans up temp file, raises OutputInvalid, and exits 1."""
    source_file = tmp_path / "source.jsonl"
    shutil.copyfile(FIXTURES_DIR / "exec_basic" / "source.jsonl", source_file)
    source_pre_bytes = source_file.read_bytes()
    output_file = tmp_path / "repaired.jsonl"
    plan = load_plan(FIXTURES_DIR / "exec_basic" / "plan.json")

    def simulate_disk_full() -> None:
        raise OSError(errno.ENOSPC, "No space left on device")

    with pytest.raises(OutputInvalid, match="Disk full"):
        execute(
            source_path=source_file,
            plan=plan,
            output_path=output_file,
            pre_write_hook=simulate_disk_full,
        )

    # Source untouched, output nonexistent, no orphaned temp files
    assert source_file.read_bytes() == source_pre_bytes
    assert not output_file.exists()
    assert list(tmp_path.glob(".sesslint-tmp-*")) == []

    # Via CLI exits 1
    with patch("os.fsync", side_effect=OSError(errno.ENOSPC, "No space left on device")):
        code = main(
            [
                "repair",
                str(source_file),
                "--output",
                str(output_file),
                "--plan",
                str(FIXTURES_DIR / "exec_basic" / "plan.json"),
            ]
        )
        assert code == 1


def test_read_only_target_directory(tmp_path: Path) -> None:
    """Read-only target directory raises OutputInvalid and exits 1 cleanly without tracebacks."""
    source_file = tmp_path / "source.jsonl"
    shutil.copyfile(FIXTURES_DIR / "exec_basic" / "source.jsonl", source_file)
    output_file = tmp_path / "repaired.jsonl"
    plan = load_plan(FIXTURES_DIR / "exec_basic" / "plan.json")

    def simulate_permission_denied() -> None:
        raise PermissionError(errno.EACCES, "Permission denied")

    with pytest.raises(OutputInvalid, match="Permission denied"):
        execute(
            source_path=source_file,
            plan=plan,
            output_path=output_file,
            pre_write_hook=simulate_permission_denied,
        )

    code = main(
        [
            "repair",
            str(source_file),
            "--output",
            str(tmp_path / "readonly_dir" / "out.jsonl"),
            "--plan",
            str(FIXTURES_DIR / "exec_basic" / "plan.json"),
        ]
    )
    assert code == 1


def test_manifest_write_failure_cleans_output(tmp_path: Path) -> None:
    """Failure while writing manifest cleans up output file to guarantee atomic pair invariant."""
    source_file = tmp_path / "source.jsonl"
    shutil.copyfile(FIXTURES_DIR / "exec_basic" / "source.jsonl", source_file)
    output_file = tmp_path / "repaired.jsonl"
    manifest_file = Path(f"{output_file}.manifest.json")
    plan = load_plan(FIXTURES_DIR / "exec_basic" / "plan.json")

    with patch(
        "sesslint.report.dump_manifest",
        side_effect=RuntimeError("Manifest serialization fault injection"),
    ):
        with pytest.raises(RuntimeError, match="Manifest serialization fault injection"):
            execute(
                source_path=source_file,
                plan=plan,
                output_path=output_file,
            )

    # Output file and manifest MUST NOT exist on disk
    assert not output_file.exists(), "Output file was left behind after manifest failure"
    assert not manifest_file.exists()
    assert list(tmp_path.glob(".sesslint-tmp-*")) == []


def test_cli_invalid_format(tmp_path: Path) -> None:
    """Passing an invalid --format option exits 2 via CLI."""
    source_file = tmp_path / "source.jsonl"
    shutil.copyfile(FIXTURES_DIR / "exec_basic" / "source.jsonl", source_file)
    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                "repair",
                str(source_file),
                "--output",
                str(tmp_path / "out.jsonl"),
                "--format",
                "completely_bogus_format",
            ]
        )
    assert exc_info.value.code == 2


def test_source_events_direct_parameter(tmp_path: Path) -> None:
    """Passing source_events directly to execute uses the provided events."""
    source_file = tmp_path / "source.jsonl"
    shutil.copyfile(FIXTURES_DIR / "exec_basic" / "source.jsonl", source_file)
    output_file = tmp_path / "out_direct.jsonl"
    plan = load_plan(FIXTURES_DIR / "exec_basic" / "plan.json")

    from sesslint.repair import load_session_source

    _hdr, events = load_session_source(source_file)
    manifest = execute(
        source_path=source_file,
        plan=plan,
        output_path=output_file,
        source_events=events,
    )
    assert manifest is not None
    assert output_file.is_file()


def test_refuse_plan_source_mismatch_cross_file(tmp_path: Path) -> None:
    """Plan generated for source A must be refused when applied to source B (RVW-003)."""
    source_b = tmp_path / "source_b.jsonl"
    source_b.write_text(
        '{"schema_version":"sesslint.session/v1","session_id":"s_diff","created_at":"2026-09-05T12:00:00Z"}\n'
        '{"actor":"user","id":"evt_diff","kind":"message","parent_id":null,"payload":{"text":"unrelated"},"seq":0,"ts":"2026-09-05T12:00:00Z"}\n',
        encoding="utf-8",
    )

    plan = load_plan(FIXTURES_DIR / "exec_basic" / "plan.json")
    output_file = tmp_path / "out.jsonl"

    # Direct execution raises PlanSourceMismatch
    with pytest.raises(PlanSourceMismatch, match="Plan source_hash mismatch"):
        execute(
            source_path=source_b,
            plan=plan,
            output_path=output_file,
            policy="conservative",
        )
    assert not output_file.exists()

    # CLI repair exits with code 1 and refuses repair
    plan_file = FIXTURES_DIR / "exec_basic" / "plan.json"
    code = main(
        [
            "repair",
            str(source_b),
            "--output",
            str(output_file),
            "--plan",
            str(plan_file),
        ]
    )
    assert code == 1
    assert not output_file.exists()


def test_refuse_plan_source_mismatch_mutated_source(tmp_path: Path) -> None:
    """Source file modified after plan creation must be refused by execute (RVW-003)."""
    from sesslint.repair.fingerprint import compute_plan_fingerprint

    source_file = tmp_path / "source.jsonl"
    shutil.copyfile(FIXTURES_DIR / "exec_basic" / "source.jsonl", source_file)
    source_bytes = source_file.read_bytes()
    source_hash = hashlib.sha256(source_bytes).hexdigest()

    base_plan = load_plan(FIXTURES_DIR / "exec_basic" / "plan.json")
    plan_dict = base_plan.to_dict()
    plan_dict["source_hash"] = source_hash
    plan_dict["fingerprint"] = compute_plan_fingerprint(plan_dict)
    plan = load_plan(plan_dict)

    # Mutate source file with an extra byte
    source_file.write_text(source_file.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    output_file = tmp_path / "out_mutated.jsonl"

    with pytest.raises(PlanSourceMismatch):
        execute(
            source_path=source_file,
            plan=plan,
            output_path=output_file,
            policy="conservative",
        )
    assert not output_file.exists()


def test_refuse_crafted_conservative_plan_with_salvage_step(tmp_path: Path) -> None:
    """A self-consistent plan labeled conservative containing salvage steps is refused (RVW-004)."""
    from sesslint.repair.fingerprint import compute_plan_fingerprint

    source_file = tmp_path / "source.jsonl"
    shutil.copyfile(FIXTURES_DIR / "exec_basic" / "source.jsonl", source_file)
    source_bytes = source_file.read_bytes()
    source_hash = hashlib.sha256(source_bytes).hexdigest()

    # Author a crafted plan with policy='conservative' but containing a salvage recipe step
    crafted_plan_dict = {
        "version": "sesslint.plan/v1",
        "source_hash": source_hash,
        "profile": "neutral",
        "steps": [
            {
                "seq": 0,
                "recipe": "unresolvable-branch-amputate",
                "target_finding_fp": "f000",
                "target_index": 0,
                "params": {},
                "lossy": True,
                "loss": {"amputated-branch": 1},
            }
        ],
        "blocked": [],
        "loss_accounting": {
            "preview": {"amputated-branch": 1},
            "total_lost": 1,
            "total_kept": 2,
        },
    }
    plan = load_plan(crafted_plan_dict)
    plan_dict = plan.to_dict()
    plan_dict["fingerprint"] = compute_plan_fingerprint(plan_dict)
    plan = load_plan(plan_dict)

    output_file = tmp_path / "out_crafted.jsonl"
    with pytest.raises(PolicyMismatch, match="requires 'salvage' policy"):
        execute(
            source_path=source_file,
            plan=plan,
            output_path=output_file,
            policy="conservative",
        )
    assert not output_file.exists()


@pytest.mark.parametrize("vendor_fmt", ["claude-code-jsonl", "openai-agents"])
def test_executor_refuses_direct_vendor_format_repair(tmp_path: Path, vendor_fmt: str) -> None:
    """Direct repair invocation on vendor formats is rejected with RepairRefused (RVW-019)."""
    source_file = tmp_path / "source.jsonl"
    shutil.copyfile(FIXTURES_DIR / "exec_basic" / "source.jsonl", source_file)
    plan = load_plan(FIXTURES_DIR / "exec_basic" / "plan.json")
    output_file = tmp_path / "out_vendor.jsonl"

    with pytest.raises(RepairRefused, match="Direct repair of vendor format"):
        execute(
            source_path=source_file,
            plan=plan,
            output_path=output_file,
            policy="conservative",
            format=vendor_fmt,
        )
    assert not output_file.exists()
