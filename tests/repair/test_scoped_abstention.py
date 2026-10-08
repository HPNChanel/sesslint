"""Comprehensive tests for transformation-scoped abstention gate (DEV-013).

Covers:
1. Ambiguity oracle matrix:
   - Completed mutating tool call (paired success result, not SL203) -> not ambiguous
   - Dangling tool call (no tool_result) -> ambiguous
   - Tool call with unknown side_effects -> ambiguous
   - Unpaired correlation_id (missing or orphan) -> ambiguous
   - Reused correlation_id (SL103) -> ambiguous
   - Multiple results (SL104) -> ambiguous
   - Read-only tool call -> safe / not ambiguous
   - SL203 finding direct subject -> ambiguous
2. Region totality property tests:
   - All 5 conservative recipes declare total affected_region functions
   - Zero unhandled exceptions on random/fuzzed PlanStep inputs and events
3. Doubt rule tests:
   - Missing region function -> abstain (side-effect-scope-unproven)
   - Forced exception in region function -> fail-closed abstain
   - unproven=True region -> fail-closed abstain
4. Adversarial matrix (5 scenarios end-to-end at both planner and executor):
   - Scenario 1: Completed mutating call elsewhere + disjoint defect (must repair)
   - Scenario 2: Dangling call in truncated region (must refuse)
   - Scenario 3: Unknown side_effects ON relink target (must refuse)
   - Scenario 4: Ambiguous call adjacent-but-outside region (must repair + boundary pin)
   - Scenario 5: SL203 anywhere (global refusal unchanged)
5. Realistic tool session with mutating bash and write calls undergoing conservative repair.
6. Crafted plan safety: executor independently recomputes and refuses bypass attempts.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import random
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

from sesslint.canonical import SessionEvent
from sesslint.checks.runner import run_all_checks
from sesslint.codes import SL002, SL004, SL203, Repairability, Severity
from sesslint.finding import SourceRef, make_finding
from sesslint.policy.abstention import (
    AffectedRegion,
    check_step_scope,
    find_ambiguous_events,
)
from sesslint.repair import (
    Abstained,
    PlanStep,
    RepairPlan,
    execute,
    plan,
)
from sesslint.repair.errors import RepairRefused
from sesslint.repair.executor import load_source_for_format
from sesslint.repair.fingerprint import compute_plan_fingerprint
from sesslint.repair.planner import (
    PLAN_VERSION,
    Loss,
)
from sesslint.repair.recipes_conservative import (
    affected_region_compaction_projection_reunion,
    affected_region_duplicate_projection_removal,
    affected_region_identical_duplicate_collapse,
    affected_region_proven_unique_parent_restore,
)
from sesslint.repair.recipes_conservative import (
    register_all as register_all_conservative,
)
from sesslint.repair.recipes_sl002 import (
    affected_region_torn_terminal_record_discard,
)
from sesslint.repair.recipes_sl002 import (
    register_all as register_all_sl002,
)
from sesslint.repair.registry import Recipe, clear_registry, register_recipe


@pytest.fixture(autouse=True)
def _ensure_recipes_registered() -> Generator[None, None, None]:
    """Register needed packs per test and restore a clean registry afterwards."""
    clear_registry()
    register_all_conservative()
    register_all_sl002()
    yield
    clear_registry()


def _write_session_file(tmp_path: Path, filename: str, events: list[SessionEvent]) -> Path:
    target = tmp_path / filename
    with open(target, "w", encoding="utf-8") as fh:
        header = {
            "schema_version": "sesslint.session/v1",
            "session_id": "scoped_test",
            "created_at": "2026-09-05T12:00:00Z",
        }
        fh.write(json.dumps(header) + "\n")
        for ev in events:
            fh.write(json.dumps(ev.to_canonical_dict()) + "\n")
    return target


def _source_derived_plan(source_path: Path, *, policy: str = "conservative") -> RepairPlan:
    """Plan from the exact canonical bytes the public executor will re-check."""
    source_bytes = source_path.read_bytes()
    _, loaded_events, stream_findings = load_source_for_format(
        source_path, "canonical", data=source_bytes
    )
    findings = list(stream_findings) + list(
        run_all_checks(
            loaded_events,
            profile="neutral",
            source_path=source_path.name,
            adapter="canonical",
        )
    )
    return plan(
        findings,
        loaded_events,
        policy=policy,
        source_hash=hashlib.sha256(source_bytes).hexdigest(),
        input_format="canonical",
    )


def _append_torn_terminal_record(source_path: Path, prefix: bytes) -> None:
    """Append a proven torn JSON object prefix without a terminating newline."""
    with source_path.open("ab") as fh:
        fh.write(prefix)


# ===========================================================================
# 1. Ambiguity Oracle Unit Tests
# ===========================================================================


def test_oracle_completed_mutating_call_not_ambiguous() -> None:
    """A tool call with side_effects='possible' and a paired tool_result is not ambiguous."""
    events = [
        SessionEvent(
            id="call-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c1",
            payload={"name": "bash", "side_effects": "possible"},
        ),
        SessionEvent(
            id="res-1",
            parent_id="call-1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="tool",
            kind="tool_result",
            correlation_id="c1",
            payload={"output": "success", "side_effects": "possible"},
        ),
    ]
    oracle = find_ambiguous_events(events)
    assert len(oracle.indices) == 0
    assert len(oracle.ids) == 0


def test_oracle_dangling_tool_call_is_ambiguous() -> None:
    """A tool call with no paired tool_result is ambiguous (unresolved execution)."""
    events = [
        SessionEvent(
            id="call-dangle",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c-dangle",
            payload={"name": "bash", "side_effects": "possible"},
        ),
    ]
    oracle = find_ambiguous_events(events)
    assert 0 in oracle.indices
    assert "call-dangle" in oracle.ids


def test_oracle_unknown_side_effects_is_ambiguous() -> None:
    """A tool call with side_effects='unknown' is ambiguous even if paired."""
    events = [
        SessionEvent(
            id="call-unk",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c-unk",
            payload={"name": "custom_plugin", "side_effects": "unknown"},
        ),
        SessionEvent(
            id="res-unk",
            parent_id="call-unk",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="tool",
            kind="tool_result",
            correlation_id="c-unk",
            payload={"output": "ok"},
        ),
    ]
    oracle = find_ambiguous_events(events)
    assert 0 in oracle.indices
    assert 1 in oracle.indices
    assert "call-unk" in oracle.ids
    assert "res-unk" in oracle.ids


def test_oracle_unpaired_correlation_id_is_ambiguous() -> None:
    """Tool events lacking a correlation_id entirely are ambiguous."""
    events = [
        SessionEvent(
            id="call-nocorr",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id=None,
            payload={"name": "bash", "side_effects": "none"},
        ),
        SessionEvent(
            id="res-nocorr",
            parent_id=None,
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="tool",
            kind="tool_result",
            correlation_id=None,
            payload={"output": "ok"},
        ),
    ]
    oracle = find_ambiguous_events(events)
    assert 0 in oracle.indices
    assert 1 in oracle.indices
    assert "call-nocorr" in oracle.ids
    assert "res-nocorr" in oracle.ids


def test_oracle_reused_tool_call_id_is_ambiguous() -> None:
    """Multiple tool calls sharing a correlation identifier (SL103) are all ambiguous."""
    events = [
        SessionEvent(
            id="call-reused-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c-reused",
            payload={"name": "bash", "side_effects": "none"},
        ),
        SessionEvent(
            id="call-reused-2",
            parent_id=None,
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c-reused",
            payload={"name": "bash", "side_effects": "none"},
        ),
        SessionEvent(
            id="res-reused",
            parent_id=None,
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="tool",
            kind="tool_result",
            correlation_id="c-reused",
            payload={"output": "ok"},
        ),
    ]
    oracle = find_ambiguous_events(events)
    assert {0, 1, 2}.issubset(oracle.indices)
    assert {"call-reused-1", "call-reused-2", "res-reused"}.issubset(oracle.ids)


def test_oracle_multiple_tool_results_is_ambiguous() -> None:
    """Multiple tool results for one call (SL104) are ambiguous."""
    events = [
        SessionEvent(
            id="call-1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c1",
            payload={"name": "bash", "side_effects": "none"},
        ),
        SessionEvent(
            id="res-1a",
            parent_id="call-1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="tool",
            kind="tool_result",
            correlation_id="c1",
            payload={"output": "v1"},
        ),
        SessionEvent(
            id="res-1b",
            parent_id="call-1",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="tool",
            kind="tool_result",
            correlation_id="c1",
            payload={"output": "v2"},
        ),
    ]
    oracle = find_ambiguous_events(events)
    assert {0, 1, 2}.issubset(oracle.indices)


def test_oracle_sl203_subject_is_ambiguous() -> None:
    """Direct subjects of SL203 findings are marked ambiguous."""
    events = [
        SessionEvent(
            id="evt-0",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
        ),
        SessionEvent(
            id="call-sl203",
            parent_id="evt-0",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c-sl203",
            payload={"side_effects": "none"},
        ),
    ]
    finding = make_finding(
        code=SL203,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Unsafe continuation",
        source=SourceRef(path="session.json", line=2, record_id="call-sl203"),
        evidence={"first_unsafe_index": 1, "record_ordinal": 1},
    )
    oracle = find_ambiguous_events(events, findings=[finding])
    assert 1 in oracle.indices
    assert "call-sl203" in oracle.ids


# ===========================================================================
# 2. Totality Property Tests for all 5 Conservative Recipes
# ===========================================================================


@pytest.mark.parametrize(
    "region_fn",
    [
        affected_region_identical_duplicate_collapse,
        affected_region_proven_unique_parent_restore,
        affected_region_compaction_projection_reunion,
        affected_region_duplicate_projection_removal,
        affected_region_torn_terminal_record_discard,
    ],
)
def test_region_functions_totality_fuzz(region_fn: Any) -> None:
    """Property test: Region functions are total and never raise on arbitrary inputs."""
    rng = random.Random(42)

    # Test empty, malformed, or garbage events
    test_event_streams: list[list[Any]] = [
        [],
        [None],
        ["garbage string"],
        [{"not": "a real event"}],
        [
            SessionEvent(
                id="1",
                parent_id=None,
                seq=0,
                ts="2026-09-05T12:00:00Z",
                actor="user",
                kind="message",
            )
        ],
    ]

    for stream in test_event_streams:
        for _ in range(25):
            t_idx = rng.choice([None, -5, 0, 1, 9999, "not-int", False, True])
            params: dict[str, Any] = {
                "index": rng.choice([None, -1, 0, 5, "str"]),
                "at_index": rng.choice([None, 0, 10]),
                "cut_index": rng.choice([None, -1, 0, 10]),
                "correlation_id": rng.choice([None, "c1", 123]),
                "parent_id": rng.choice([None, "p1", 456]),
            }
            step = PlanStep(
                seq=0,
                recipe="stub-recipe",
                target_finding_fp="stub-fp",
                target_index=(
                    t_idx if isinstance(t_idx, int) and not isinstance(t_idx, bool) else None
                ),
                params=params,
            )

            # Execution must NEVER raise
            region = region_fn(step, stream)
            assert isinstance(region, AffectedRegion)
            # all_indices must also never raise
            _ = region.all_indices(total_len=len(stream))


# ===========================================================================
# 3. Doubt Rule Tests
# ===========================================================================


def test_doubt_rule_missing_region_function() -> None:
    """Missing region function -> unproven -> fails closed."""
    step = PlanStep(
        seq=0,
        recipe="unknown-recipe",
        target_finding_fp="fp",
        target_index=0,
    )
    events = [
        SessionEvent(
            id="1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
        )
    ]

    is_disjoint, reason = check_step_scope(step, events, recipe_region_fn=None)
    assert is_disjoint is False
    assert reason == "side-effect-scope-unproven"


def test_doubt_rule_forced_exception_in_region_function() -> None:
    """A region function raising an unhandled exception causes fail-closed abstention."""

    def _exploding_region_fn(s: Any, ev: Any) -> AffectedRegion:
        raise RuntimeError("Forced explosion in region computation")

    step = PlanStep(
        seq=0,
        recipe="exploding-recipe",
        target_finding_fp="fp",
        target_index=0,
    )
    events = [
        SessionEvent(
            id="1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
        )
    ]

    is_disjoint, reason = check_step_scope(step, events, recipe_region_fn=_exploding_region_fn)
    assert is_disjoint is False
    assert reason == "side-effect-scope-unproven"


def test_doubt_rule_unproven_region_flag() -> None:
    """A region explicitly returning unproven=True fails closed."""

    def _unproven_region_fn(s: Any, ev: Any) -> AffectedRegion:
        return AffectedRegion(unproven=True)

    step = PlanStep(
        seq=0,
        recipe="unproven-recipe",
        target_finding_fp="fp",
        target_index=0,
    )
    events = [
        SessionEvent(
            id="1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
        )
    ]

    is_disjoint, reason = check_step_scope(step, events, recipe_region_fn=_unproven_region_fn)
    assert is_disjoint is False
    assert reason == "side-effect-scope-unproven"


# ===========================================================================
# 4. Adversarial Matrix End-to-End Tests (Scenarios 1–5)
# ===========================================================================


def test_scenario_1_completed_mutating_call_elsewhere_disjoint_repair(tmp_path: Path) -> None:
    """Scenario 1: Completed mutating call elsewhere + disjoint defect must repair cleanly."""
    events = [
        SessionEvent(
            id="m0",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={"text": "start"},
        ),
        SessionEvent(
            id="c-bash",
            parent_id="m0",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="call-bash-1",
            payload={"name": "bash", "side_effects": "possible"},
        ),
        SessionEvent(
            id="r-bash",
            parent_id="c-bash",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="tool",
            kind="tool_result",
            correlation_id="call-bash-1",
            payload={"output": "files", "side_effects": "possible"},
        ),
        SessionEvent(
            id="m1",
            parent_id="r-bash",
            seq=3,
            ts="2026-09-05T12:00:03Z",
            actor="assistant",
            kind="message",
            payload={"text": "hello"},
        ),
        SessionEvent(
            id="m1",
            parent_id="r-bash",
            seq=4,
            ts="2026-09-05T12:00:03Z",
            actor="assistant",
            kind="message",
            payload={"text": "hello"},
        ),
    ]
    source_p = _write_session_file(tmp_path, "scen1_source.jsonl", events)
    output_p = tmp_path / "scen1_output.jsonl"

    # Planner must use the current source findings, including the actual SL003.
    p = _source_derived_plan(source_p)
    assert [step.recipe for step in p.steps] == [
        "identical-duplicate-collapse",
        "seq-renumber",
    ]

    assert len(p.blocked) == 0

    # Executor must succeed
    manifest = execute(
        source_path=source_p,
        plan=p,
        output_path=output_p,
        policy="conservative",
    )
    assert output_p.is_file()
    assert manifest.input_fingerprint == p.source_hash
    assert [action.kind for action in manifest.actions] == [
        "identical-duplicate-collapse",
        "seq-renumber",
    ]


def test_scenario_2_dangling_call_in_truncated_region(tmp_path: Path) -> None:
    """Scenario 2: Dangling call in truncated region must refuse at both planner and executor."""
    events = [
        SessionEvent(
            id="m0",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
        ),
        SessionEvent(
            id="c-ok",
            parent_id="m0",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="call-ok",
            payload={"name": "bash", "side_effects": "possible"},
        ),
        SessionEvent(
            id="r-ok",
            parent_id="c-ok",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="tool",
            kind="tool_result",
            correlation_id="call-ok",
            payload={"output": "ok", "side_effects": "possible"},
        ),
        SessionEvent(
            id="c-dangle",
            parent_id="r-ok",
            seq=3,
            ts="2026-09-05T12:00:03Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="call-dangling",
            payload={"name": "write_file", "side_effects": "possible"},
        ),
    ]
    findings = [
        make_finding(
            code=SL002,
            severity=Severity.ERROR,
            repairability=Repairability.DETERMINISTIC,
            message_template="Torn terminal record at index 3",
            source=SourceRef(path="session.json", line=4, record_id="c-dangle"),
            evidence={"cut_index": 3, "target_index": 3, "unterminated": True},
        )
    ]

    source_p = _write_session_file(tmp_path, "scen2_source.jsonl", events)
    output_p = tmp_path / "scen2_output.jsonl"
    source_h = hashlib.sha256(source_p.read_bytes()).hexdigest()

    # Planner must refuse and record 'side-effect-scope-unproven'
    p = plan(findings, events, policy="conservative", source_hash=source_h)
    assert len(p.steps) == 0
    assert len(p.blocked) == 1
    assert p.blocked[0].reason == "side-effect-scope-unproven"

    # Public executor must reject the fabricated plan; a matching digest is
    # insufficient when the current source has no derivable SL002 step.
    crafted_step = PlanStep(
        seq=0,
        recipe="torn-terminal-record-discard",
        target_finding_fp=findings[0].fingerprint,
        target_index=3,
        params={"cut_index": 3},
    )
    crafted_plan = RepairPlan(
        version=PLAN_VERSION,
        source_hash=source_h,
        profile="neutral",
        steps=(crafted_step,),
        blocked=(),
        loss_accounting=Loss(preview={"none": 0}, total_lost=0, total_kept=len(events)),
        fingerprint="",
        policy="conservative",
    )
    crafted_plan = dataclasses.replace(
        crafted_plan,
        fingerprint=compute_plan_fingerprint(crafted_plan.to_dict()),
    )

    with pytest.raises(RepairRefused, match="derives for this source now"):
        execute(
            source_path=source_p,
            plan=crafted_plan,
            output_path=output_p,
            policy="conservative",
        )
    assert not output_p.exists()


def test_scenario_3_unknown_side_effects_on_relink_target(tmp_path: Path) -> None:
    """Scenario 3: Unknown side_effects on the relink target must refuse."""
    events = [
        SessionEvent(
            id="m0",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
        ),
        SessionEvent(
            id="c-unk-target",
            parent_id="m0",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c-unk-1",
            payload={"name": "mystery_tool", "side_effects": "unknown"},
        ),
        SessionEvent(
            id="r-unk-target",
            parent_id="c-unk-target",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="tool",
            kind="tool_result",
            correlation_id="c-unk-1",
            payload={"output": "ok"},
        ),
        SessionEvent(
            id="m-child",
            parent_id="c-unk-target",
            seq=3,
            ts="2026-09-05T12:00:03Z",
            actor="assistant",
            kind="message",
            payload={"text": "continuing"},
        ),
    ]
    findings = [
        make_finding(
            code=SL004,
            severity=Severity.ERROR,
            repairability=Repairability.DETERMINISTIC,
            message_template="Missing parent link on m-child",
            source=SourceRef(path="session.json", line=4, record_id="m-child"),
            evidence={"at_index": 3, "parent_id": "c-unk-target"},
        )
    ]

    source_p = _write_session_file(tmp_path, "scen3_source.jsonl", events)
    output_p = tmp_path / "scen3_output.jsonl"
    source_h = hashlib.sha256(source_p.read_bytes()).hexdigest()

    # Planner must block with side-effect-scope-unproven
    p = plan(findings, events, policy="conservative", source_hash=source_h)
    assert len(p.steps) == 0
    assert len(p.blocked) == 1
    assert p.blocked[0].reason == "side-effect-scope-unproven"

    # Public executor must reject the fabricated plan before recipe application.
    crafted_step = PlanStep(
        seq=0,
        recipe="proven-unique-parent-restore",
        target_finding_fp=findings[0].fingerprint,
        target_index=3,
        params={"parent_id": "c-unk-target"},
    )
    crafted_plan = RepairPlan(
        version=PLAN_VERSION,
        source_hash=source_h,
        profile="neutral",
        steps=(crafted_step,),
        blocked=(),
        loss_accounting=Loss(preview={"none": 0}, total_lost=0, total_kept=len(events)),
        fingerprint="",
        policy="conservative",
    )
    crafted_plan = dataclasses.replace(
        crafted_plan,
        fingerprint=compute_plan_fingerprint(crafted_plan.to_dict()),
    )

    with pytest.raises(RepairRefused, match="derives for this source now"):
        execute(
            source_path=source_p,
            plan=crafted_plan,
            output_path=output_p,
            policy="conservative",
        )
    assert not output_p.exists()


def test_scenario_4_ambiguous_call_adjacent_but_outside_region_boundary_pin(tmp_path: Path) -> None:
    """Scenario 4: Ambiguous call strictly outside region repairs; test pins boundary."""
    # Event 0: user message
    # Event 1: tool call with side_effects="unknown" (ambiguous!)
    # Event 2: tool result matching Event 1
    # Event 3: message A
    # Event 4: message A (duplicate of Event 3, SL003)
    # The affected region of SL003 is {3, 4}. Event 1/2 are strictly adjacent-outside.
    events = [
        SessionEvent(
            id="m0",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
        ),
        SessionEvent(
            id="c-unk-outside",
            parent_id="m0",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c-outside",
            payload={"name": "mystery_tool", "side_effects": "unknown"},
        ),
        SessionEvent(
            id="r-unk-outside",
            parent_id="c-unk-outside",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="tool",
            kind="tool_result",
            correlation_id="c-outside",
            payload={"output": "ok"},
        ),
        SessionEvent(
            id="m-dup",
            parent_id="r-unk-outside",
            seq=3,
            ts="2026-09-05T12:00:03Z",
            actor="assistant",
            kind="message",
            payload={"text": "repeat"},
        ),
        SessionEvent(
            id="m-dup",
            parent_id="r-unk-outside",
            seq=4,
            ts="2026-09-05T12:00:03Z",
            actor="assistant",
            kind="message",
            payload={"text": "repeat"},
        ),
    ]
    source_p = _write_session_file(tmp_path, "scen4_source.jsonl", events)
    output_p = tmp_path / "scen4_output.jsonl"

    # Step A: Outside boundary -> must repair!
    p = _source_derived_plan(source_p)
    assert [step.recipe for step in p.steps] == [
        "identical-duplicate-collapse",
        "seq-renumber",
    ]

    execute(
        source_path=source_p,
        plan=p,
        output_path=output_p,
        policy="conservative",
    )
    assert output_p.is_file()

    # Step B: Boundary pin - if the defect includes index 1 (the ambiguous event), it must refuse!
    finding_boundary = make_finding(
        code=SL002,
        severity=Severity.ERROR,
        repairability=Repairability.DETERMINISTIC,
        message_template="Torn terminal record including index 1",
        source=SourceRef(path="session.json", line=2, record_id="c-unk-outside"),
        evidence={"cut_index": 1, "target_index": 1, "unterminated": True},
    )
    p_pin = plan(
        [finding_boundary],
        events,
        policy="conservative",
        source_hash=hashlib.sha256(source_p.read_bytes()).hexdigest(),
    )
    assert len(p_pin.steps) == 0
    assert p_pin.blocked[0].reason == "side-effect-scope-unproven"


def test_scenario_5_sl203_anywhere_global_refusal_unchanged(tmp_path: Path) -> None:
    """Scenario 5: SL203 anywhere keeps global refusal under conservative policy."""
    events = [
        SessionEvent(
            id="m0",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
        ),
        SessionEvent(
            id="comp0",
            parent_id="m0",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="system",
            kind="compaction_boundary",
            payload={},
        ),
        SessionEvent(
            id="c1",
            parent_id="comp0",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c1",
            payload={"name": "safe_tool", "side_effects": "none"},
        ),
        SessionEvent(
            id="r1",
            parent_id="c1",
            seq=3,
            ts="2026-09-05T12:00:03Z",
            actor="tool",
            kind="tool_result",
            correlation_id="c1",
            payload={"output": "ok", "side_effects": "none"},
        ),
        SessionEvent(
            id="m-dup",
            parent_id="r1",
            seq=4,
            ts="2026-09-05T12:00:04Z",
            actor="assistant",
            kind="message",
            payload={"text": "repeat"},
        ),
        SessionEvent(
            id="m-dup",
            parent_id="r1",
            seq=5,
            ts="2026-09-05T12:00:04Z",
            actor="assistant",
            kind="message",
            payload={"text": "repeat"},
        ),
    ]
    source_p = _write_session_file(tmp_path, "scen5_source.jsonl", events)
    output_p = tmp_path / "scen5_output.jsonl"
    p = _source_derived_plan(source_p)

    # Planner must block ALL findings with SL203-refusal globally
    assert len(p.steps) == 0
    assert all(b.reason == "SL203-refusal" for b in p.blocked)

    with pytest.raises(Abstained, match="SL203 present"):
        execute(
            source_path=source_p,
            plan=p,
            output_path=output_p,
            policy="conservative",
        )
    assert not output_p.exists()


# ===========================================================================
# 5. Positive E2E: Realistic Tool Session with Bash & File Edits
# ===========================================================================


def test_positive_e2e_realistic_tool_session_repaired(tmp_path: Path) -> None:
    """Flagship usefulness test for UC-04:

    A real-world session containing bash tool calls and file edits is safely
    repaired for a disjoint terminal defect (SL002), emitting a valid manifest.
    """
    events = [
        SessionEvent(
            id="msg-init",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={"text": "Please run the test suite and fix any broken tests."},
        ),
        # Bash call: pytest
        SessionEvent(
            id="call-pytest",
            parent_id="msg-init",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="call-pytest-1",
            payload={"name": "bash", "command": "pytest", "side_effects": "possible"},
        ),
        SessionEvent(
            id="res-pytest",
            parent_id="call-pytest",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="tool",
            kind="tool_result",
            correlation_id="call-pytest-1",
            payload={"output": "1 failed, 15 passed", "exit_code": 1, "side_effects": "possible"},
        ),
        # File edit call: write_file
        SessionEvent(
            id="call-edit",
            parent_id="res-pytest",
            seq=3,
            ts="2026-09-05T12:00:03Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="call-edit-1",
            payload={"name": "write_file", "path": "test_app.py", "side_effects": "possible"},
        ),
        SessionEvent(
            id="res-edit",
            parent_id="call-edit",
            seq=4,
            ts="2026-09-05T12:00:04Z",
            actor="tool",
            kind="tool_result",
            correlation_id="call-edit-1",
            payload={"output": "File written successfully", "side_effects": "possible"},
        ),
        # Follow-up message
        SessionEvent(
            id="msg-summary",
            parent_id="res-edit",
            seq=5,
            ts="2026-09-05T12:00:05Z",
            actor="assistant",
            kind="message",
            payload={"text": "I have patched test_app.py."},
        ),
    ]

    source_p = _write_session_file(tmp_path, "tool_session_source.jsonl", events)
    _append_torn_terminal_record(source_p, b'{"id":"msg-torn"')
    output_p = tmp_path / "tool_session_repaired.jsonl"

    # Plan under default conservative policy
    plan_result = _source_derived_plan(source_p)
    assert [step.recipe for step in plan_result.steps] == [
        "torn-terminal-record-discard",
        "seq-renumber",
    ]
    assert len(plan_result.blocked) == 0

    # Execute repair
    manifest = execute(
        source_path=source_p,
        plan=plan_result,
        output_path=output_p,
        policy="conservative",
    )

    assert output_p.is_file()
    assert (tmp_path / "tool_session_repaired.jsonl.manifest.json").is_file()
    assert manifest.input_fingerprint == hashlib.sha256(source_p.read_bytes()).hexdigest()
    assert manifest.policy == "conservative"
    assert sorted(action.kind for action in manifest.actions) == sorted(
        [
            "torn-terminal-record-discard",
            "seq-renumber",
        ]
    )

    # Repaired output has exactly 6 events (torn record discarded, bash and write_file preserved)
    output_lines = [
        line for line in output_p.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    # Header + 6 events = 7 lines
    assert len(output_lines) == 7
    final_event = json.loads(output_lines[-1])
    assert final_event["id"] == "msg-summary"


# ===========================================================================
# 6. Deep Verification & Edge Case Hardening Tests
# ===========================================================================


def test_parent_restore_disjoint_from_intermediate_mutating_tool(tmp_path: Path) -> None:
    """SL004 parent restore explicitly covers both endpoints without sweeping intermediate tools."""
    events = [
        SessionEvent(
            id="m_parent",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={"text": "start session"},
        ),
        SessionEvent(
            id="c_bash",
            parent_id="m_parent",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c_bash_1",
            payload={"name": "bash", "side_effects": "possible"},
        ),
        SessionEvent(
            id="r_bash",
            parent_id="c_bash",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="tool",
            kind="tool_result",
            correlation_id="c_bash_1",
            payload={"output": "ok", "side_effects": "possible"},
        ),
        SessionEvent(
            id="m_child",
            parent_id=None,
            seq=3,
            ts="2026-09-05T12:00:03Z",
            actor="assistant",
            kind="message",
            payload={"text": "responding"},
        ),
    ]
    finding = make_finding(
        code=SL004,
        severity=Severity.ERROR,
        repairability=Repairability.DETERMINISTIC,
        message_template="Missing parent pointer on m_child",
        source=SourceRef(path="session.json", line=4, record_id="m_child"),
        evidence={"at_index": 3, "parent_id": "m_parent"},
    )

    source_p = _write_session_file(tmp_path, "parent_restore_inter_source.jsonl", events)
    output_p = tmp_path / "parent_restore_inter_out.jsonl"
    source_h = hashlib.sha256(source_p.read_bytes()).hexdigest()

    # Planner must succeed because region covers only {0, 3}
    p = plan([finding], events, policy="conservative", source_hash=source_h)
    assert len(p.steps) == 1
    assert p.steps[0].recipe == "proven-unique-parent-restore"
    assert len(p.blocked) == 0

    # This intentionally unreachable SL004 recipe path remains a planner/scope
    # unit test. The public executor must refuse its fabricated plan.
    with pytest.raises(RepairRefused, match="derives for this source now"):
        execute(
            source_path=source_p,
            plan=p,
            output_path=output_p,
            policy="conservative",
        )
    assert not output_p.exists()


def test_duplicate_projection_removal_disjoint_from_intermediate_mutating_tool(
    tmp_path: Path,
) -> None:
    """SL104 duplicate projection removal covers discrete projection records, not sweep ranges."""
    events = [
        SessionEvent(
            id="c_read",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="corr-read",
            payload={"name": "read_file", "side_effects": "none"},
        ),
        SessionEvent(
            id="r1_kept",
            parent_id="c_read",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="tool",
            kind="tool_result",
            correlation_id="corr-read",
            payload={"output": "file_data"},
        ),
        SessionEvent(
            id="c_mutating",
            parent_id="r1_kept",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="corr-mut",
            payload={"name": "bash", "side_effects": "possible"},
        ),
        SessionEvent(
            id="r_mutating",
            parent_id="c_mutating",
            seq=3,
            ts="2026-09-05T12:00:03Z",
            actor="tool",
            kind="tool_result",
            correlation_id="corr-mut",
            payload={"output": "done", "side_effects": "possible"},
        ),
        SessionEvent(
            id="r1_dup",
            parent_id="c_read",
            seq=4,
            ts="2026-09-05T12:00:04Z",
            actor="tool",
            kind="tool_result",
            correlation_id="corr-read",
            payload={"output": "file_data"},
        ),
    ]
    source_p = _write_session_file(tmp_path, "dup_proj_inter_source.jsonl", events)
    output_p = tmp_path / "dup_proj_inter_out.jsonl"

    p = _source_derived_plan(source_p)
    assert [step.recipe for step in p.steps] == [
        "duplicate-projection-removal",
        "seq-renumber",
    ]
    assert all(blocked.code == "SL007" for blocked in p.blocked)

    manifest = execute(
        source_path=source_p,
        plan=p,
        output_path=output_p,
        policy="conservative",
    )
    assert output_p.is_file()
    assert manifest.actions[0].kind == "duplicate-projection-removal"


def test_multistep_conservative_repair_no_index_drift_in_executor(tmp_path: Path) -> None:
    """Sequential conservative repair steps execute cleanly without coordinate drift."""
    events = [
        SessionEvent(
            id="dup1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={"text": "dup1"},
        ),
        SessionEvent(
            id="dup1",
            parent_id=None,
            seq=1,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={"text": "dup1"},
        ),
        SessionEvent(
            id="m_safe",
            parent_id="dup1",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="assistant",
            kind="message",
            payload={"text": "inter"},
        ),
        SessionEvent(
            id="c1",
            parent_id="m_safe",
            seq=3,
            ts="2026-09-05T12:00:03Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c1",
            payload={"name": "bash", "side_effects": "possible"},
        ),
        SessionEvent(
            id="r1",
            parent_id="c1",
            seq=4,
            ts="2026-09-05T12:00:04Z",
            actor="tool",
            kind="tool_result",
            correlation_id="c1",
            payload={"output": "ok", "side_effects": "possible"},
        ),
        SessionEvent(
            id="dup2",
            parent_id="r1",
            seq=5,
            ts="2026-09-05T12:00:05Z",
            actor="assistant",
            kind="message",
            payload={"text": "dup2"},
        ),
        SessionEvent(
            id="dup2",
            parent_id="r1",
            seq=6,
            ts="2026-09-05T12:00:05Z",
            actor="assistant",
            kind="message",
            payload={"text": "dup2"},
        ),
    ]

    source_p = _write_session_file(tmp_path, "multistep_drift_source.jsonl", events)
    output_p = tmp_path / "multistep_drift_out.jsonl"

    p = _source_derived_plan(source_p)
    assert [step.recipe for step in p.steps] == [
        "identical-duplicate-collapse",
        "identical-duplicate-collapse",
        "seq-renumber",
    ]

    manifest = execute(
        source_path=source_p,
        plan=p,
        output_path=output_p,
        policy="conservative",
    )
    assert output_p.is_file()
    assert len(manifest.actions) == 3


def test_recipe_without_affected_region_keeps_global_gating(tmp_path: Path) -> None:
    """A conservative recipe without affected_region falls back to global gating."""
    dummy_recipe = Recipe(
        name="dummy-unproven-recipe",
        handles=("SL001",),
        preconditions=(),
        lossy=False,
        salvage_only=False,
        min_policy="conservative",
        affected_region=None,
        apply=lambda ev, st: list(ev),
    )
    register_recipe(dummy_recipe)

    # Session with mutating tool call
    events_with_tools = [
        SessionEvent(
            id="m0",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
        ),
        SessionEvent(
            id="c1",
            parent_id="m0",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c1",
            payload={"name": "bash", "side_effects": "possible"},
        ),
        SessionEvent(
            id="r1",
            parent_id="c1",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="tool",
            kind="tool_result",
            correlation_id="c1",
            payload={"output": "ok", "side_effects": "possible"},
        ),
    ]
    finding = make_finding(
        code="SL001",
        severity=Severity.WARNING,
        repairability=Repairability.DETERMINISTIC,
        message_template="Dummy finding for {record_id}",
        source=SourceRef(path="session.json", line=1, record_id="m0"),
        evidence={"index": 0},
    )

    # Planner must block with side-effect-abstention under global gating
    p = plan([finding], events_with_tools, policy="conservative")
    assert len(p.steps) == 0
    assert len(p.blocked) == 1
    assert p.blocked[0].reason == "side-effect-abstention"

    # B20 rejects the fabricated step before a recipe can rely on global gating.
    source_p = _write_session_file(tmp_path, "unproven_source.jsonl", events_with_tools)
    output_p = tmp_path / "unproven_out.jsonl"
    source_h = hashlib.sha256(source_p.read_bytes()).hexdigest()

    crafted_step = PlanStep(
        seq=0,
        recipe="dummy-unproven-recipe",
        target_finding_fp=finding.fingerprint,
        target_index=0,
    )
    crafted_plan = RepairPlan(
        version=PLAN_VERSION,
        source_hash=source_h,
        profile="neutral",
        steps=(crafted_step,),
        blocked=(),
        loss_accounting=Loss(preview={"none": 0}, total_lost=0, total_kept=len(events_with_tools)),
        fingerprint="",
        policy="conservative",
    )
    crafted_plan = dataclasses.replace(
        crafted_plan,
        fingerprint=compute_plan_fingerprint(crafted_plan.to_dict()),
    )

    with pytest.raises(RepairRefused, match="derives for this source now"):
        execute(
            source_path=source_p,
            plan=crafted_plan,
            output_path=output_p,
            policy="conservative",
        )
    assert not output_p.exists()


def test_reversed_tool_pairing_marked_ambiguous() -> None:
    """SL105 reversed tool pairing (tool_result precedes tool_call) is marked ambiguous."""
    events = [
        SessionEvent(
            id="r1",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="tool",
            kind="tool_result",
            correlation_id="c_rev",
            payload={"output": "premature"},
        ),
        SessionEvent(
            id="c1",
            parent_id="r1",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c_rev",
            payload={"name": "bash", "side_effects": "possible"},
        ),
    ]
    amb = find_ambiguous_events(events)
    assert 0 in amb.indices
    assert 1 in amb.indices
    assert "r1" in amb.ids
    assert "c1" in amb.ids
    assert any("reversed-pairing" in r for r in amb.reasons)


def test_check_step_scope_syncs_ids_to_indices_for_side_effect_check() -> None:
    """If region specifies only IDs, check_step_scope resolves indices to detect effects."""
    events = [
        SessionEvent(
            id="call-mutating",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="assistant",
            kind="tool_call",
            correlation_id="c1",
            payload={"name": "bash", "side_effects": "possible"},
        ),
        SessionEvent(
            id="res-mutating",
            parent_id="call-mutating",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="tool",
            kind="tool_result",
            correlation_id="c1",
            payload={"output": "done"},
        ),
    ]

    def _id_only_region(s: Any, ev: Any) -> AffectedRegion:
        # Deliberately omit indices and provide only the event ID
        return AffectedRegion(indices=frozenset(), ids=frozenset({"call-mutating"}), ranges=())

    step = PlanStep(0, "recipe", "fp", target_index=0)
    is_disjoint, reason = check_step_scope(step, events, recipe_region_fn=_id_only_region)
    assert is_disjoint is False
    assert reason == "side-effect-scope-unproven"
