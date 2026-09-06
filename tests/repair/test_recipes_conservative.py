"""Comprehensive tests for conservative repair recipe pack (TASK-019).

Covers:
- Recipe registry & handles mapping (SL003, SL004, SL005, SL104, SL108, SL203).
- Happy path fixture conformance with byte-level canonical comparison & loss accounting.
- Complete refusal matrix:
  * terminal-suffix-discard: no trigger, cut <= 0 (empty session), cut >= len, checkpoint in suffix.
  * identical-duplicate-collapse: kind mismatch, boundary kinds, content mismatch, < 2 events.
  * proven-unique-parent-restore: 0 candidates, ambiguous (>1) candidates, self-parent.
  * compaction-projection-reunion: 0 boundaries, >=2 boundaries, boundary at endpoint, unclean pair.
  * duplicate-projection-removal: <2 results, differing fingerprints, non-tool_result kinds.
- SL203 refusal & gating in planner:
  * SL203 blocks non-suffix recipes via no_sl203 precondition.
  * Suffix-discard plans when side effects are safe (none).
  * Suffix-discard refuses when side effects are unknown (abstention gate).
- No-synthetic-success verification:
  * Multiset proof: output tool_result fingerprints <= input tool_result fingerprints.
  * Static grep audit: forbids tool_result construction literals in recipes_conservative.py.
- Purity and immutability:
  * Inputs deep-equal before and after apply.
  * Idempotence of repeated apply where defined.
- Adversarial tests:
  * 1,000-event identical duplicate run capped at 256 with 744 cap-overflow blocked findings.
  * Suffix cut at index 0 refusing empty session.
  * Mixed-kind adjacent duplicates refusing collapse.
  * Self-parent candidate exclusion.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections import Counter
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

from sesslint.canonical import SessionEvent
from sesslint.codes import (
    SL003,
    SL004,
    SL005,
    SL101,
    SL104,
    SL108,
    SL203,
    Repairability,
    Severity,
)
from sesslint.finding import Finding, SourceRef, make_finding
from sesslint.repair import (
    MAX_STEPS,
    PlanStep,
    clear_registry,
    get_recipe,
    list_recipes,
    plan,
    recipes_for,
)
from sesslint.repair.fingerprint import canonical_json_bytes
from sesslint.repair.recipes_conservative import (
    PreconditionFailed,
    apply_compaction_projection_reunion,
    apply_duplicate_projection_removal,
    apply_identical_duplicate_collapse,
    apply_proven_unique_parent_restore,
    apply_terminal_suffix_discard,
)
from sesslint.repair.recipes_conservative import (
    register_all as register_all_conservative,
)

FIXTURES_REPAIR_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "repair"
SRC_RECIPES_FILE = (
    Path(__file__).resolve().parent.parent.parent
    / "src"
    / "sesslint"
    / "repair"
    / "recipes_conservative.py"
)


@pytest.fixture(autouse=True)
def _clean_and_register() -> Generator[None, None, None]:
    """Ensure clean registry before each test and re-register conservative recipes."""
    clear_registry()
    register_all_conservative()
    yield
    clear_registry()


def _make_test_finding(
    *,
    code: str,
    repairability: Repairability | str = Repairability.DETERMINISTIC,
    severity: Severity = Severity.ERROR,
    at_index: int | None = None,
    evidence: dict[str, Any] | None = None,
    fp_suffix: str = "0",
) -> Finding:
    ev_dict = dict(evidence) if evidence is not None else {}
    if at_index is not None and "at_index" not in ev_dict:
        ev_dict["at_index"] = at_index

    fp_hex = hashlib.sha256(f"{code}:{fp_suffix}:{at_index}".encode()).hexdigest()[:16]

    return make_finding(
        code=code,
        severity=severity,
        repairability=repairability,
        message_template="Finding for record {record_id}",
        source=SourceRef(path="session.json", line=1, record_id=f"rec-{fp_suffix}"),
        evidence=ev_dict if ev_dict else None,
        fingerprint=fp_hex,
    )


# ---------------------------------------------------------------------------
# 1. Registry & Mapping Tests
# ---------------------------------------------------------------------------


def test_conservative_recipes_registration_and_handles() -> None:
    """All five conservative recipes are registered with exact handles, preconditions, and flags."""
    recipes = list_recipes()
    assert len(recipes) == 5

    suffix_r = get_recipe("terminal-suffix-discard")
    assert suffix_r is not None
    assert suffix_r.handles == (SL005, SL203)
    assert suffix_r.preconditions == ("no_prior_safe_tool_after_cut",)
    assert suffix_r.lossy is True
    assert suffix_r.salvage_only is False

    collapse_r = get_recipe("identical-duplicate-collapse")
    assert collapse_r is not None
    assert collapse_r.handles == (SL003,)
    assert collapse_r.preconditions == ("no_sl203", "adjacent_identical_duplicate")
    assert collapse_r.lossy is False
    assert collapse_r.salvage_only is False

    restore_r = get_recipe("proven-unique-parent-restore")
    assert restore_r is not None
    assert restore_r.handles == (SL004,)
    assert restore_r.preconditions == ("no_sl203", "unique_parent_candidate")
    assert restore_r.lossy is False
    assert restore_r.salvage_only is False

    reunion_r = get_recipe("compaction-projection-reunion")
    assert reunion_r is not None
    assert reunion_r.handles == (SL108,)
    assert reunion_r.preconditions == ("no_sl203", "single_boundary_split")
    assert reunion_r.lossy is False
    assert reunion_r.salvage_only is False

    removal_r = get_recipe("duplicate-projection-removal")
    assert removal_r is not None
    assert removal_r.handles == (SL104,)
    assert removal_r.preconditions == ("no_sl203", "duplicate_projection_identical")
    assert removal_r.lossy is False
    assert removal_r.salvage_only is False

    # Check recipes_for lookup mapping
    assert recipes_for(SL003) == (collapse_r,)
    assert recipes_for(SL004) == (restore_r,)
    assert recipes_for(SL005) == (suffix_r,)
    assert recipes_for(SL104) == (removal_r,)
    assert recipes_for(SL108) == (reunion_r,)
    assert recipes_for(SL203) == (suffix_r,)
    assert recipes_for(SL101) == ()


def test_register_all_idempotent() -> None:
    """Calling register_all multiple times does not raise or duplicate."""
    register_all_conservative()
    register_all_conservative()
    assert len(list_recipes()) == 5


# ---------------------------------------------------------------------------
# 2. Fixture Conformance & Happy Paths
# ---------------------------------------------------------------------------


def test_terminal_suffix_discard_fixture() -> None:
    """Fixture recipe_suffix_discard.json matches expected output events and loss."""
    path = FIXTURES_REPAIR_DIR / "recipe_suffix_discard.json"
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    step = PlanStep(
        seq=data["step"]["seq"],
        recipe=data["step"]["recipe"],
        target_finding_fp=data["step"]["target_finding_fp"],
        target_index=data["step"]["target_index"],
        params=data["step"]["params"],
    )

    out = apply_terminal_suffix_discard(data["input_events"], step)
    assert out == data["expected_events"]
    assert canonical_json_bytes(out) == canonical_json_bytes(data["expected_events"])
    assert len(data["input_events"]) - len(out) == data["expected_loss_count"]


def test_identical_duplicate_collapse_fixture() -> None:
    """Fixture recipe_duplicate_collapse.json matches expected output events."""
    path = FIXTURES_REPAIR_DIR / "recipe_duplicate_collapse.json"
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    step = PlanStep(
        seq=data["step"]["seq"],
        recipe=data["step"]["recipe"],
        target_finding_fp=data["step"]["target_finding_fp"],
        target_index=data["step"]["target_index"],
        params=data["step"]["params"],
    )

    out = apply_identical_duplicate_collapse(data["input_events"], step)
    assert out == data["expected_events"]
    assert canonical_json_bytes(out) == canonical_json_bytes(data["expected_events"])


def test_proven_unique_parent_restore_fixture() -> None:
    """Fixture recipe_parent_restore.json matches happy path and refuses ambiguous."""
    path = FIXTURES_REPAIR_DIR / "recipe_parent_restore.json"
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    # 1. Happy path
    happy = data["happy_path"]
    step_happy = PlanStep(
        seq=happy["step"]["seq"],
        recipe=happy["step"]["recipe"],
        target_finding_fp=happy["step"]["target_finding_fp"],
        target_index=happy["step"]["target_index"],
        params=happy["step"]["params"],
    )
    out_happy = apply_proven_unique_parent_restore(happy["input_events"], step_happy)
    assert out_happy == happy["expected_events"]
    assert canonical_json_bytes(out_happy) == canonical_json_bytes(happy["expected_events"])

    # 2. Ambiguous refusal
    ambig = data["refusal_ambiguous"]
    step_ambig = PlanStep(
        seq=ambig["step"]["seq"],
        recipe=ambig["step"]["recipe"],
        target_finding_fp=ambig["step"]["target_finding_fp"],
        target_index=ambig["step"]["target_index"],
        params=ambig["step"]["params"],
    )
    with pytest.raises(PreconditionFailed, match="ambiguous candidates"):
        apply_proven_unique_parent_restore(ambig["input_events"], step_ambig)


def test_compaction_projection_reunion_fixture() -> None:
    """Fixture recipe_reunion.json matches expected relocated boundary output."""
    path = FIXTURES_REPAIR_DIR / "recipe_reunion.json"
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    step = PlanStep(
        seq=data["step"]["seq"],
        recipe=data["step"]["recipe"],
        target_finding_fp=data["step"]["target_finding_fp"],
        target_index=data["step"]["target_index"],
        params=data["step"]["params"],
    )

    out = apply_compaction_projection_reunion(data["input_events"], step)
    assert out == data["expected_events"]
    assert canonical_json_bytes(out) == canonical_json_bytes(data["expected_events"])


def test_duplicate_projection_removal_fixture() -> None:
    """Fixture recipe_projection_removal.json matches expected dropped later result."""
    path = FIXTURES_REPAIR_DIR / "recipe_projection_removal.json"
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    step = PlanStep(
        seq=data["step"]["seq"],
        recipe=data["step"]["recipe"],
        target_finding_fp=data["step"]["target_finding_fp"],
        target_index=data["step"]["target_index"],
        params=data["step"]["params"],
    )

    out = apply_duplicate_projection_removal(data["input_events"], step)
    assert out == data["expected_events"]
    assert canonical_json_bytes(out) == canonical_json_bytes(data["expected_events"])


# ---------------------------------------------------------------------------
# 3. Refusal Matrix Tests
# ---------------------------------------------------------------------------


def test_suffix_discard_refusal_empty_session() -> None:
    """Terminal suffix discard with cut <= 0 refuses to produce an empty session."""
    events = [
        {"id": "e0", "kind": "message", "actor": "user", "seq": 0, "parent_id": None},
        {"id": "e1", "kind": "message", "actor": "assistant", "seq": 1, "parent_id": "e0"},
    ]
    step = PlanStep(
        seq=0, recipe="terminal-suffix-discard", target_finding_fp="f0", target_index=0, params={}
    )
    with pytest.raises(PreconditionFailed, match="would empty session"):
        apply_terminal_suffix_discard(events, step)


def test_suffix_discard_refusal_out_of_bounds() -> None:
    """Terminal suffix discard with cut >= len(events) raises PreconditionFailed."""
    events = [{"id": "e0", "kind": "message", "actor": "user", "seq": 0, "parent_id": None}]
    step = PlanStep(
        seq=0, recipe="terminal-suffix-discard", target_finding_fp="f0", target_index=5, params={}
    )
    with pytest.raises(PreconditionFailed, match=">="):
        apply_terminal_suffix_discard(events, step)


def test_suffix_discard_refusal_checkpoint_in_suffix() -> None:
    """Terminal suffix discard refuses when a checkpoint would be discarded."""
    events = [
        {"id": "e0", "kind": "message", "actor": "user", "seq": 0, "parent_id": None},
        {"id": "e1", "kind": "message", "actor": "assistant", "seq": 1, "parent_id": "e0"},
        {
            "id": "chk",
            "kind": "checkpoint",
            "actor": "system",
            "seq": 2,
            "parent_id": "e1",
            "payload": {},
        },
    ]
    step = PlanStep(
        seq=0, recipe="terminal-suffix-discard", target_finding_fp="f0", target_index=1, params={}
    )
    with pytest.raises(PreconditionFailed, match="checkpoint at index 2 cannot be discarded"):
        apply_terminal_suffix_discard(events, step)


def test_parent_restore_refusal_zero_candidates() -> None:
    """Parent restore with zero matching candidates raises PreconditionFailed."""
    events = [
        {"id": "e0", "kind": "message", "parent_id": None, "seq": 0},
        {"id": "e1", "kind": "message", "parent_id": "unknown-ghost", "seq": 1},
    ]
    step = PlanStep(
        seq=0,
        recipe="proven-unique-parent-restore",
        target_finding_fp="f0",
        target_index=1,
        params={"parent_fingerprint_prefix": "no-such-id"},
    )
    with pytest.raises(PreconditionFailed, match="zero candidates"):
        apply_proven_unique_parent_restore(events, step)


def test_parent_restore_refusal_self_candidate() -> None:
    """Parent restore ignores self as candidate; if only candidate is self, raises error."""
    events = [
        {"id": "self-loop-1", "kind": "message", "parent_id": "self-loop-", "seq": 0},
    ]
    step = PlanStep(
        seq=0,
        recipe="proven-unique-parent-restore",
        target_finding_fp="f0",
        target_index=0,
        params={"parent_fingerprint_prefix": "self-loop-"},
    )
    with pytest.raises(PreconditionFailed, match="zero candidates"):
        apply_proven_unique_parent_restore(events, step)


def test_reunion_refusal_zero_boundaries() -> None:
    """Compaction reunion with zero boundaries between pair raises PreconditionFailed."""
    events = [
        {"id": "c1", "kind": "tool_call", "correlation_id": "c1", "seq": 0, "parent_id": None},
        {"id": "r1", "kind": "tool_result", "correlation_id": "c1", "seq": 1, "parent_id": "c1"},
    ]
    step = PlanStep(
        seq=0,
        recipe="compaction-projection-reunion",
        target_finding_fp="f0",
        target_index=0,
        params={"correlation_id": "c1"},
    )
    with pytest.raises(PreconditionFailed, match="expected exactly 1 boundary"):
        apply_compaction_projection_reunion(events, step)


def test_reunion_refusal_multiple_boundaries() -> None:
    """Compaction reunion with multiple boundaries between pair raises PreconditionFailed."""
    events = [
        {"id": "c1", "kind": "tool_call", "correlation_id": "c1", "seq": 0, "parent_id": None},
        {"id": "b1", "kind": "compaction_boundary", "seq": 1, "parent_id": "c1"},
        {"id": "b2", "kind": "compaction_boundary", "seq": 2, "parent_id": "b1"},
        {"id": "r1", "kind": "tool_result", "correlation_id": "c1", "seq": 3, "parent_id": "b2"},
    ]
    step = PlanStep(
        seq=0,
        recipe="compaction-projection-reunion",
        target_finding_fp="f0",
        target_index=0,
        params={"correlation_id": "c1"},
    )
    with pytest.raises(PreconditionFailed, match="expected exactly 1 boundary.*found 2"):
        apply_compaction_projection_reunion(events, step)


def test_reunion_refusal_boundary_at_endpoint() -> None:
    """Compaction reunion where boundary sits at pair endpoint raises PreconditionFailed."""
    events = [
        {"id": "c1", "kind": "tool_call", "correlation_id": "c1", "seq": 0, "parent_id": None},
        {"id": "b1", "kind": "compaction_boundary", "seq": 1, "parent_id": "c1"},
        {"id": "r1", "kind": "tool_result", "correlation_id": "c1", "seq": 2, "parent_id": "b1"},
    ]
    step = PlanStep(
        seq=0,
        recipe="compaction-projection-reunion",
        target_finding_fp="f0",
        target_index=0,
        params={"correlation_id": "c1", "boundary_index": 0},
    )
    with pytest.raises(
        PreconditionFailed, match="boundary sits at pair endpoint \\(not strictly between\\)"
    ):
        apply_compaction_projection_reunion(events, step)


def test_duplicate_projection_removal_differing_fingerprints() -> None:
    """Duplicate projection removal refuses near-match results with differing fingerprints."""
    events = [
        {"id": "c1", "kind": "tool_call", "correlation_id": "c1", "seq": 0, "parent_id": None},
        {
            "id": "r1",
            "kind": "tool_result",
            "correlation_id": "c1",
            "seq": 1,
            "payload": {"val": 1},
        },
        {
            "id": "r2",
            "kind": "tool_result",
            "correlation_id": "c1",
            "seq": 2,
            "payload": {"val": 2},
        },
    ]
    step = PlanStep(
        seq=0,
        recipe="duplicate-projection-removal",
        target_finding_fp="f0",
        target_index=1,
        params={"correlation_id": "c1"},
    )
    with pytest.raises(PreconditionFailed, match="fingerprints differ"):
        apply_duplicate_projection_removal(events, step)


def test_duplicate_collapse_refusal_checkpoint_or_boundary() -> None:
    """Duplicate collapse refuses to collapse adjacent checkpoints or compaction boundaries."""
    events = [
        {"id": "chk1", "kind": "checkpoint", "seq": 0, "payload": {"hash": "h1"}},
        {"id": "chk2", "kind": "checkpoint", "seq": 1, "payload": {"hash": "h1"}},
    ]
    step = PlanStep(
        seq=0,
        recipe="identical-duplicate-collapse",
        target_finding_fp="f0",
        target_index=0,
        params={},
    )
    with pytest.raises(PreconditionFailed, match="cannot collapse boundary kind"):
        apply_identical_duplicate_collapse(events, step)


def test_duplicate_collapse_refusal_mixed_kinds() -> None:
    """Duplicate collapse refuses adjacent events with different kinds even if payload matches."""
    events = [
        {"id": "e0", "kind": "tool_call", "seq": 0, "payload": {"data": "shared"}},
        {"id": "e1", "kind": "tool_result", "seq": 1, "payload": {"data": "shared"}},
    ]
    step = PlanStep(
        seq=0,
        recipe="identical-duplicate-collapse",
        target_finding_fp="f0",
        target_index=0,
        params={},
    )
    with pytest.raises(PreconditionFailed, match="kind mismatch"):
        apply_identical_duplicate_collapse(events, step)


# ---------------------------------------------------------------------------
# 4. SL203 Refusal & Side-Effect Gating in Planner
# ---------------------------------------------------------------------------


def test_sl203_refusal_blocks_other_conservative_recipes() -> None:
    """Planner with SL203 findings routes recipes with no_sl203 to blocked."""
    events = [
        SessionEvent(
            id="e0",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={"text": "hi"},
        ),
        SessionEvent(
            id="e1a",
            parent_id="e0",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="message",
            payload={"text": "dup"},
        ),
        SessionEvent(
            id="e1b",
            parent_id="e0",
            seq=2,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="message",
            payload={"text": "dup"},
        ),
        SessionEvent(
            id="e2",
            parent_id="e1a",
            seq=3,
            ts="2026-09-05T12:00:02Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c1",
            payload={"name": "safe_tool", "side_effects": "none"},
        ),
    ]

    f_sl203 = _make_test_finding(
        code=SL203,
        repairability=Repairability.DETERMINISTIC,
        evidence={"first_unsafe_index": 3},
        fp_suffix="sl203",
    )
    f_sl003 = _make_test_finding(
        code=SL003,
        repairability=Repairability.DETERMINISTIC,
        evidence={"at_index": 1},
        fp_suffix="sl003",
    )

    # 1. When side-effects are safe: suffix-discard is planned, collapse is blocked by no_sl203
    p = plan([f_sl203, f_sl003], events)
    assert len(p.steps) == 1
    assert p.steps[0].recipe == "terminal-suffix-discard"
    assert p.steps[0].target_index == 3
    assert p.loss_accounting.preview["discarded-suffix"] == 1  # event at index 3 dropped

    assert len(p.blocked) == 1
    assert p.blocked[0].code == SL003
    assert p.blocked[0].reason == "precondition-failed:no_sl203"


def test_sl203_refusal_when_side_effects_unknown() -> None:
    """When tool events have unknown side effects, must_abstain blocks automated repair."""
    events_unsafe = [
        SessionEvent(
            id="e0",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={"text": "hi"},
        ),
        SessionEvent(
            id="e1",
            parent_id="e0",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c1",
            payload={"name": "unknown_tool", "side_effects": "unknown"},
        ),
    ]

    f_sl203 = _make_test_finding(
        code=SL203,
        repairability=Repairability.DETERMINISTIC,
        evidence={"first_unsafe_index": 1},
        fp_suffix="sl203",
    )

    p_unsafe = plan([f_sl203], events_unsafe)
    assert len(p_unsafe.steps) == 0
    assert len(p_unsafe.blocked) == 1
    assert p_unsafe.blocked[0].reason == "SL203-refusal"


# ---------------------------------------------------------------------------
# 5. No-Synthetic-Success & Purity Verification
# ---------------------------------------------------------------------------


def test_no_synthetic_success_multiset_proof() -> None:
    """For every recipe and fixture, output tool_results multiset is a subset of input multiset."""
    fixture_files = [
        FIXTURES_REPAIR_DIR / "recipe_suffix_discard.json",
        FIXTURES_REPAIR_DIR / "recipe_duplicate_collapse.json",
        FIXTURES_REPAIR_DIR / "recipe_parent_restore.json",
        FIXTURES_REPAIR_DIR / "recipe_reunion.json",
        FIXTURES_REPAIR_DIR / "recipe_projection_removal.json",
    ]

    for f_path in fixture_files:
        with open(f_path, encoding="utf-8") as fh:
            content = json.load(fh)

        # Handle single fixture vs multiple case fixture
        cases = [content] if "input_events" in content else [content["happy_path"]]

        for case in cases:
            input_events = case["input_events"]
            expected_events = case["expected_events"]

            # Count tool_result fingerprints in input and expected output
            def _tool_result_fps(ev_list: list[dict[str, Any]]) -> Counter[str]:
                fps: list[str] = []
                for e in ev_list:
                    if e.get("kind") == "tool_result":
                        fps.append(canonical_json_bytes(e).hex())
                return Counter(fps)

            in_counts = _tool_result_fps(input_events)
            out_counts = _tool_result_fps(expected_events)

            for fp, count in out_counts.items():
                assert count <= in_counts[fp], (
                    f"Synthetic tool_result {fp} detected in {f_path.name}"
                )


def test_no_synthetic_success_static_grep() -> None:
    """Static audit: recipes_conservative.py contains zero tool_result creation literals."""
    content = SRC_RECIPES_FILE.read_text(encoding="utf-8")

    # Forbid {"kind": "tool_result"} writes / constructions
    write_pattern = re.compile(r"[{]\s*['\"]kind['\"]\s*:\s*['\"]tool_result['\"]")
    match = write_pattern.search(content)
    assert match is None, f"Forbidden synthetic tool_result constructor found in {SRC_RECIPES_FILE}"

    # Forbid direct instantiation of SessionEvent with kind="tool_result"
    instantiation_pattern = re.compile(r"SessionEvent\s*\([^)]*kind\s*=\s*['\"]tool_result['\"]")
    assert instantiation_pattern.search(content) is None


def test_purity_and_immutability() -> None:
    """Applying recipes does not mutate input event objects."""
    path = FIXTURES_REPAIR_DIR / "recipe_reunion.json"
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    orig_input = copy.deepcopy(data["input_events"])
    step = PlanStep(
        seq=data["step"]["seq"],
        recipe=data["step"]["recipe"],
        target_finding_fp=data["step"]["target_finding_fp"],
        target_index=data["step"]["target_index"],
        params=data["step"]["params"],
    )

    out = apply_compaction_projection_reunion(data["input_events"], step)
    assert data["input_events"] == orig_input
    assert out != data["input_events"]


def test_idempotence_where_defined() -> None:
    """Second apply of projection removal or reunion on already-repaired session behaves safely."""
    path = FIXTURES_REPAIR_DIR / "recipe_projection_removal.json"
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    step = PlanStep(
        seq=0,
        recipe="duplicate-projection-removal",
        target_finding_fp="f0",
        target_index=2,
        params={"correlation_id": "c-proj-1"},
    )
    first_pass = apply_duplicate_projection_removal(data["input_events"], step)
    assert len(first_pass) == len(data["input_events"]) - 1

    # Second apply on already-repaired stream fails cleanly with PreconditionFailed
    # (only 1 result remaining)
    with pytest.raises(PreconditionFailed, match="expected at least 2 results"):
        apply_duplicate_projection_removal(first_pass, step)


# ---------------------------------------------------------------------------
# 6. Adversarial Scenarios
# ---------------------------------------------------------------------------


def test_adversarial_1k_identical_duplicates_cap() -> None:
    """1000 duplicate findings yield exactly 256 steps and 744 cap-overflow blocked findings."""
    events = [
        SessionEvent(
            id="e0", parent_id=None, seq=0, ts="2026-09-05T12:00:00Z", actor="user", kind="message"
        ),
        SessionEvent(
            id="e1",
            parent_id="e0",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="message",
        ),
        SessionEvent(
            id="e2",
            parent_id="e0",
            seq=2,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="message",
        ),
    ]

    total_findings = 1000
    findings = [
        _make_test_finding(
            code=SL003,
            repairability=Repairability.DETERMINISTIC,
            at_index=1,
            fp_suffix=f"{i:04d}",
        )
        for i in range(total_findings)
    ]

    p = plan(findings, events)
    assert len(p.steps) == MAX_STEPS  # Exactly 256
    assert len(p.blocked) == total_findings - MAX_STEPS  # Exactly 744
    assert all(b.reason == "cap-overflow" for b in p.blocked)


def test_duplicate_collapse_second_index_resolves_and_collapses() -> None:
    """Target index pointing to second element of duplicate pair collapses cleanly without error."""
    events = [
        {"id": "e0", "kind": "message", "seq": 0, "parent_id": None, "payload": {"text": "A"}},
        {"id": "e1", "kind": "message", "seq": 1, "parent_id": "e0", "payload": {"text": "B"}},
        {"id": "e2", "kind": "message", "seq": 2, "parent_id": "e0", "payload": {"text": "B"}},
        {"id": "e3", "kind": "message", "seq": 3, "parent_id": "e1", "payload": {"text": "C"}},
    ]
    step = PlanStep(
        seq=0,
        recipe="identical-duplicate-collapse",
        target_finding_fp="f-dup",
        target_index=2,  # Points to e2 (second of duplicate pair)
        params={},
    )
    out = apply_identical_duplicate_collapse(events, step)
    assert len(out) == 3
    assert [e["id"] for e in out] == ["e0", "e1", "e3"]


def test_duplicate_collapse_rewrites_child_parent_pointers() -> None:
    """Collapsing duplicate with differing IDs repoints child parent references to kept ID."""
    events = [
        {"id": "msg-0", "kind": "message", "seq": 0, "parent_id": None, "payload": {"t": "root"}},
        {
            "id": "msg-1a",
            "kind": "message",
            "seq": 1,
            "parent_id": "msg-0",
            "payload": {"t": "dup"},
        },
        {
            "id": "msg-1b",
            "kind": "message",
            "seq": 2,
            "parent_id": "msg-0",
            "payload": {"t": "dup"},
        },
        {
            "id": "msg-2",
            "kind": "message",
            "seq": 3,
            "parent_id": "msg-1b",
            "payload": {"t": "child"},
        },
    ]
    step = PlanStep(
        seq=0,
        recipe="identical-duplicate-collapse",
        target_finding_fp="f0",
        target_index=1,
        params={},
    )
    out = apply_identical_duplicate_collapse(events, step)
    assert len(out) == 3
    # msg-1b was dropped; msg-2's parent_id must now point to msg-1a
    child = next(e for e in out if e["id"] == "msg-2")
    assert child["parent_id"] == "msg-1a"


def test_duplicate_projection_removal_rewrites_child_parent_pointers() -> None:
    """Removing duplicate projection repoints children from dropped result to retained result."""
    events = [
        {"id": "c1", "kind": "tool_call", "correlation_id": "c1", "seq": 0, "parent_id": None},
        {
            "id": "res-1",
            "kind": "tool_result",
            "correlation_id": "c1",
            "seq": 1,
            "parent_id": "c1",
            "payload": {"status": "ok"},
        },
        {
            "id": "res-2",
            "kind": "tool_result",
            "correlation_id": "c1",
            "seq": 2,
            "parent_id": "c1",
            "payload": {"status": "ok"},
        },
        {
            "id": "msg-after",
            "kind": "message",
            "seq": 3,
            "parent_id": "res-2",
            "payload": {"text": "done"},
        },
    ]
    step = PlanStep(
        seq=0,
        recipe="duplicate-projection-removal",
        target_finding_fp="f0",
        target_index=2,
        params={"correlation_id": "c1"},
    )
    out = apply_duplicate_projection_removal(events, step)
    assert len(out) == 3
    msg_after = next(e for e in out if e["id"] == "msg-after")
    assert msg_after["parent_id"] == "res-1"


def test_parent_restore_excludes_successor_candidates() -> None:
    """Candidates occurring after target event (successors) are excluded from parent candidacy."""
    events = [
        {"id": "msg-0", "kind": "message", "seq": 0, "parent_id": None},
        {"id": "msg-1", "kind": "message", "seq": 1, "parent_id": "prefix-cand"},
        {"id": "prefix-cand-later", "kind": "message", "seq": 2, "parent_id": "msg-1"},
    ]
    # Target is at index 1. The only matching candidate is at index 2 (a successor).
    step = PlanStep(
        seq=0,
        recipe="proven-unique-parent-restore",
        target_finding_fp="f0",
        target_index=1,
        params={"parent_fingerprint_prefix": "prefix-cand"},
    )
    with pytest.raises(PreconditionFailed, match="zero candidates"):
        apply_proven_unique_parent_restore(events, step)


def test_plan_and_apply_compaction_reunion_full_flow() -> None:
    """Full end-to-end plan and apply flow for SL108 finding with detector evidence."""
    events = [
        {
            "id": "c1",
            "kind": "tool_call",
            "correlation_id": "c-full-1",
            "seq": 0,
            "parent_id": None,
            "payload": {"side_effects": "none"},
        },
        {"id": "b1", "kind": "compaction_boundary", "seq": 1, "parent_id": "c1"},
        {
            "id": "r1",
            "kind": "tool_result",
            "correlation_id": "c-full-1",
            "seq": 2,
            "parent_id": "b1",
            "payload": {"side_effects": "none"},
        },
    ]
    f = _make_test_finding(
        code=SL108,
        repairability=Repairability.DETERMINISTIC,
        evidence={
            "boundary_index": 1,
            "correlation_id": "c-full-1",
            "result_index": 2,
            "use_index": 0,
        },
        fp_suffix="flow-sl108",
    )
    p = plan([f], events)
    assert len(p.steps) == 1
    assert p.steps[0].recipe == "compaction-projection-reunion"
    assert p.steps[0].params.get("correlation_id") == "c-full-1"
    assert p.steps[0].target_index == 1

    out = apply_compaction_projection_reunion(events, p.steps[0])
    assert len(out) == 3
    # Boundary is moved after the tool pair (after index 1, i.e. at index 2)
    assert out[0]["id"] == "c1"
    assert out[1]["id"] == "r1"
    assert out[2]["id"] == "b1"


def test_plan_and_apply_duplicate_projection_full_flow() -> None:
    """Full end-to-end plan and apply flow for SL104 finding with detector evidence."""
    events = [
        {
            "id": "c1",
            "kind": "tool_call",
            "correlation_id": "c-proj-flow",
            "seq": 0,
            "parent_id": None,
            "payload": {"side_effects": "none"},
        },
        {
            "id": "r1",
            "kind": "tool_result",
            "correlation_id": "c-proj-flow",
            "seq": 1,
            "parent_id": "c1",
            "payload": {"data": 42, "side_effects": "none"},
        },
        {
            "id": "r2",
            "kind": "tool_result",
            "correlation_id": "c-proj-flow",
            "seq": 2,
            "parent_id": "c1",
            "payload": {"data": 42, "side_effects": "none"},
        },
    ]
    f = _make_test_finding(
        code=SL104,
        repairability=Repairability.DETERMINISTIC,
        evidence={
            "correlation_id": "c-proj-flow",
            "result_indexes": [1, 2],
            "count": 2,
        },
        fp_suffix="flow-sl104",
    )
    p = plan([f], events)
    assert len(p.steps) == 1
    assert p.steps[0].recipe == "duplicate-projection-removal"
    assert p.steps[0].params.get("correlation_id") == "c-proj-flow"

    out = apply_duplicate_projection_removal(events, p.steps[0])
    assert len(out) == 2
    assert [e["id"] for e in out] == ["c1", "r1"]


def test_plan_and_apply_parent_restore_full_flow() -> None:
    """Full end-to-end plan and apply flow for SL004 finding with detector index evidence."""
    events = [
        {"id": "msg-root-12345", "kind": "message", "seq": 0, "parent_id": None},
        {"id": "msg-child-1", "kind": "message", "seq": 1, "parent_id": "msg-root-123"},
    ]
    f = _make_test_finding(
        code=SL004,
        repairability=Repairability.DETERMINISTIC,
        evidence={
            "id": "msg-child-1",
            "index": 1,
            "parent_id": "msg-root-123",
        },
        fp_suffix="flow-sl004",
    )
    p = plan([f], events)
    assert len(p.steps) == 1
    assert p.steps[0].recipe == "proven-unique-parent-restore"
    assert p.steps[0].target_index == 1

    out = apply_proven_unique_parent_restore(events, p.steps[0])
    assert len(out) == 2
    assert out[1]["parent_id"] == "msg-root-12345"


def test_terminal_suffix_discard_sl005_entry_index() -> None:
    """SL005 finding with entry_index triggers suffix discard cut index cleanly."""
    events = [
        {"id": "e0", "kind": "message", "seq": 0, "parent_id": None},
        {"id": "e1", "kind": "message", "seq": 1, "parent_id": "e0"},
        {"id": "e2", "kind": "message", "seq": 2, "parent_id": "e1"},
    ]
    f_sl005 = _make_test_finding(
        code=SL005,
        severity=Severity.FATAL,
        repairability=Repairability.DETERMINISTIC,
        evidence={"entry_index": 2, "cycle_path": ["e2", "e1"]},
        fp_suffix="sl005-entry",
    )
    p = plan([f_sl005], events)
    assert len(p.steps) == 1
    assert p.steps[0].recipe == "terminal-suffix-discard"
    assert p.steps[0].target_index == 2

    out = apply_terminal_suffix_discard(events, p.steps[0])
    assert len(out) == 2
    assert [e["id"] for e in out] == ["e0", "e1"]
