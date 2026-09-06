"""Tests for salvage repair pack, policy gating, loss accounting, and assurance cap (TASK-020).

Validates:
- Conservative default policy blocks salvage findings with 'needs-salvage-policy'.
- Explicit opt-in '--policy salvage' unlocks the 3 lossy salvage recipes.
- Exact CLI flag validation: no shorthand '-s', exact lowercase match.
- Operator acknowledgement gating for side-effect truncation ('needs-acknowledgement').
- Full 12-cell assurance lattice matrix across lossy, lossless, and blocked plans.
- Cryptographic plan fingerprints are policy-sensitive.
- Amputation component size cap (10,000 events) blocks with 'component-too-large'.
- Loss accounting invariants (sum of step deltas = total_lost, total_kept = max(0, len - lost)).
- Hard SL203 refusal gate cannot be bypassed by salvage opt-in.
- Loss class key allowlist enforcement against injection.
- Zero-length event sequence stability (no division by zero).
- In-memory immutability, determinism, and vendor-free compliance.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sesslint.canonical import SessionEvent
from sesslint.cli import create_parser
from sesslint.codes import SL006, SL203
from sesslint.finding import Repairability, Severity, SourceRef, make_finding
from sesslint.repair.assurance import cap_assurance
from sesslint.repair.planner import (
    PlanStep,
    plan,
)
from sesslint.repair.recipes_conservative import (
    PreconditionFailed,
)
from sesslint.repair.recipes_conservative import (
    register_all as register_conservative,
)
from sesslint.repair.recipes_salvage import (
    MAX_COMPONENT_SIZE,
    apply_side_effect_unknown_truncate,
    apply_side_effect_unknown_truncate_with_loss,
    apply_torn_compaction_project,
    apply_torn_compaction_project_with_loss,
    apply_unresolvable_branch_amputate,
    apply_unresolvable_branch_amputate_with_loss,
)
from sesslint.repair.recipes_salvage import (
    register_all as register_salvage,
)
from sesslint.repair.registry import clear_registry

FIXTURES_REPAIR_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "repair"


@pytest.fixture(autouse=True)
def setup_recipe_registry() -> None:
    """Ensure both conservative and salvage recipe packs are registered before each test."""
    clear_registry()
    register_conservative()
    register_salvage()


# ---------------------------------------------------------------------------
# 1. Gating & Fixture Conformance
# ---------------------------------------------------------------------------


def test_conservative_default_blocks_salvage() -> None:
    """All salvage fixtures under policy='conservative' yield 0 steps and 'needs-salvage-policy'."""
    fixture_files = [
        "salvage_branch.json",
        "salvage_project.json",
        "salvage_truncate.json",
    ]
    for fname in fixture_files:
        path = FIXTURES_REPAIR_DIR / fname
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)

        events = [SessionEvent(**e) for e in data["events"]]
        findings = [
            make_finding(
                code=f["code"],
                severity=f["severity"],
                repairability=f["repairability"],
                message_template=f["message"],
                source=SourceRef(**f["source"]),
                evidence=f.get("evidence"),
            )
            for f in data["findings"]
        ]

        # Default policy is conservative
        p_default = plan(findings, events)
        assert len(p_default.steps) == 0, f"Expected 0 steps under conservative for {fname}"
        assert len(p_default.blocked) == len(findings)
        assert p_default.blocked[0].reason == "needs-salvage-policy"
        assert p_default.policy == "conservative"
        assert p_default.fingerprint == data["expected_conservative_plan"]["fingerprint"]

        # Explicit policy='conservative' matches
        p_explicit = plan(findings, events, policy="conservative")
        assert p_explicit.fingerprint == p_default.fingerprint


def test_salvage_opt_in() -> None:
    """Salvage fixtures under policy='salvage' match expected steps, loss, and fingerprints."""
    # 1. Branch amputation
    path_b = FIXTURES_REPAIR_DIR / "salvage_branch.json"
    with open(path_b, encoding="utf-8") as fh:
        data_b = json.load(fh)
    events_b = [SessionEvent(**e) for e in data_b["events"]]
    findings_b = [
        make_finding(
            code=f["code"],
            severity=f["severity"],
            repairability=f["repairability"],
            message_template=f["message"],
            source=SourceRef(**f["source"]),
            evidence=f.get("evidence"),
        )
        for f in data_b["findings"]
    ]
    p_b = plan(findings_b, events_b, policy="salvage")
    exp_b = data_b["expected_plan"]
    assert p_b.fingerprint == exp_b["fingerprint"]
    assert len(p_b.steps) == 1
    assert p_b.steps[0].recipe == "unresolvable-branch-amputate"
    assert p_b.steps[0].lossy is True
    assert p_b.steps[0].loss == {"amputated-branch": 2}
    assert p_b.total_lost == 2
    assert p_b.total_kept == 3
    assert p_b.to_dict() == exp_b

    # 2. Compaction projection
    path_p = FIXTURES_REPAIR_DIR / "salvage_project.json"
    with open(path_p, encoding="utf-8") as fh:
        data_p = json.load(fh)
    events_p = [SessionEvent(**e) for e in data_p["events"]]
    findings_p = [
        make_finding(
            code=f["code"],
            severity=f["severity"],
            repairability=f["repairability"],
            message_template=f["message"],
            source=SourceRef(**f["source"]),
            evidence=f.get("evidence"),
        )
        for f in data_p["findings"]
    ]
    p_p = plan(findings_p, events_p, policy="salvage")
    exp_p = data_p["expected_plan"]
    assert p_p.fingerprint == exp_p["fingerprint"]
    assert len(p_p.steps) == 1
    assert p_p.steps[0].recipe == "torn-compaction-project"
    assert p_p.steps[0].lossy is True
    assert p_p.steps[0].loss == {"projected-orphans": 2}
    assert p_p.total_lost == 2
    assert p_p.total_kept == 3
    assert p_p.to_dict() == exp_p

    # 3. Truncation (with acknowledgement)
    path_t = FIXTURES_REPAIR_DIR / "salvage_truncate.json"
    with open(path_t, encoding="utf-8") as fh:
        data_t = json.load(fh)
    events_t = [SessionEvent(**e) for e in data_t["events"]]
    findings_t = [
        make_finding(
            code=f["code"],
            severity=f["severity"],
            repairability=f["repairability"],
            message_template=f["message"],
            source=SourceRef(**f["source"]),
            evidence=f.get("evidence"),
        )
        for f in data_t["findings"]
    ]
    p_t = plan(findings_t, events_t, policy="salvage", acknowledge_side_effects=True)
    exp_t = data_t["expected_plan"]
    assert p_t.fingerprint == exp_t["fingerprint"]
    assert len(p_t.steps) == 1
    assert p_t.steps[0].recipe == "side-effect-unknown-truncate"
    assert p_t.steps[0].lossy is True
    assert p_t.steps[0].loss == {"truncated-side-effects": 2}
    assert p_t.total_lost == 2
    assert p_t.total_kept == 2
    assert p_t.to_dict() == exp_t


# ---------------------------------------------------------------------------
# 2. Operator Acknowledgement & Gating
# ---------------------------------------------------------------------------


def test_acknowledgement() -> None:
    """side-effect-unknown-truncate requires acknowledge_side_effects=True."""
    path_t = FIXTURES_REPAIR_DIR / "salvage_truncate.json"
    with open(path_t, encoding="utf-8") as fh:
        data_t = json.load(fh)

    events_t = [SessionEvent(**e) for e in data_t["events"]]
    findings_t = [
        make_finding(
            code=f["code"],
            severity=f["severity"],
            repairability=f["repairability"],
            message_template=f["message"],
            source=SourceRef(**f["source"]),
            evidence=f.get("evidence"),
        )
        for f in data_t["findings"]
    ]

    # Without acknowledgement: blocked needs-acknowledgement
    p_no_ack = plan(findings_t, events_t, policy="salvage", acknowledge_side_effects=False)
    assert len(p_no_ack.steps) == 0
    assert len(p_no_ack.blocked) == 1
    assert p_no_ack.blocked[0].reason == "needs-acknowledgement"
    assert p_no_ack.to_dict() == data_t["expected_plan_without_acknowledgement"]

    # With acknowledgement: step planned
    p_ack = plan(findings_t, events_t, policy="salvage", acknowledge_side_effects=True)
    assert len(p_ack.steps) == 1
    assert p_ack.steps[0].recipe == "side-effect-unknown-truncate"


# ---------------------------------------------------------------------------
# 3. CLI Policy Flag & No Shorthand
# ---------------------------------------------------------------------------


def test_no_shorthand() -> None:
    """CLI accepts exact '--policy salvage', but rejects '-s' or unrecognized flags."""
    parser = create_parser()

    # Valid explicit flag
    args = parser.parse_args(["--policy", "salvage"])
    assert args.policy == "salvage"

    # Default is conservative
    args_def = parser.parse_args([])
    assert args_def.policy == "conservative"

    # Reject shorthand '-s'
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["-s", "salvage"])
    assert exc_info.value.code == 2

    # Reject capitalization
    with pytest.raises(SystemExit) as exc_info_cap:
        parser.parse_args(["--policy", "Salvage"])
    assert exc_info_cap.value.code == 2

    # Reject arbitrary string
    with pytest.raises(SystemExit) as exc_info_inv:
        parser.parse_args(["--policy", "aggressive"])
    assert exc_info_inv.value.code == 2


# ---------------------------------------------------------------------------
# 4. Assurance Lattice 12-Cell Table Test
# ---------------------------------------------------------------------------


def test_assurance_lattice() -> None:
    """Validate full 4x3 matrix across all assurance and plan variants."""
    step_lossy = PlanStep(
        seq=0,
        recipe="unresolvable-branch-amputate",
        target_finding_fp="fp1",
        target_index=1,
        lossy=True,
    )
    step_lossless = PlanStep(
        seq=0,
        recipe="identical-duplicate-collapse",
        target_finding_fp="fp2",
        target_index=1,
        lossy=False,
    )

    plan_lossy: dict[str, Any] = {"steps": [step_lossy]}
    plan_lossless: dict[str, Any] = {"steps": [step_lossless]}
    plan_blocked: dict[str, Any] = {"steps": []}

    # Matrix specification:
    # Base \ Plan           Lossy               Lossless             Blocked
    # clean                 salvaged            repaired-lossless    clean
    # repaired-lossless     salvaged            repaired-lossless    repaired-lossless
    # salvaged              salvaged            salvaged             salvaged
    # unrepairable          unrepairable        unrepairable         unrepairable

    matrix: list[tuple[str, dict[str, Any], str]] = [
        # Base: clean
        ("clean", plan_lossy, "salvaged"),
        ("clean", plan_lossless, "repaired-lossless"),
        ("clean", plan_blocked, "clean"),
        # Base: repaired-lossless
        ("repaired-lossless", plan_lossy, "salvaged"),
        ("repaired-lossless", plan_lossless, "repaired-lossless"),
        ("repaired-lossless", plan_blocked, "repaired-lossless"),
        # Base: salvaged
        ("salvaged", plan_lossy, "salvaged"),
        ("salvaged", plan_lossless, "salvaged"),
        ("salvaged", plan_blocked, "salvaged"),
        # Base: unrepairable
        ("unrepairable", plan_lossy, "unrepairable"),
        ("unrepairable", plan_lossless, "unrepairable"),
        ("unrepairable", plan_blocked, "unrepairable"),
    ]

    for base, plan_obj, expected in matrix:
        capped = cap_assurance(base, plan_obj)
        assert capped == expected, (
            f"Failed lattice cap: base={base}, plan={plan_obj} -> got {capped}, expected {expected}"
        )

    # Verify invalid base level raises ValueError
    with pytest.raises(ValueError, match="Unknown base assurance"):
        cap_assurance("invalid-level", plan_lossy)


# ---------------------------------------------------------------------------
# 5. Fingerprint Sensitivity to Policy
# ---------------------------------------------------------------------------


def test_fingerprint_differs_by_policy() -> None:
    """Same input session planned under conservative vs salvage produces different fingerprints."""
    path_b = FIXTURES_REPAIR_DIR / "salvage_branch.json"
    with open(path_b, encoding="utf-8") as fh:
        data_b = json.load(fh)

    events_b = [SessionEvent(**e) for e in data_b["events"]]
    findings_b = [
        make_finding(
            code=f["code"],
            severity=f["severity"],
            repairability=f["repairability"],
            message_template=f["message"],
            source=SourceRef(**f["source"]),
            evidence=f.get("evidence"),
        )
        for f in data_b["findings"]
    ]

    p_cons1 = plan(findings_b, events_b, policy="conservative")
    p_cons2 = plan(findings_b, events_b, policy="conservative")
    p_salv1 = plan(findings_b, events_b, policy="salvage")
    p_salv2 = plan(findings_b, events_b, policy="salvage")

    # Repeatability
    assert p_cons1.fingerprint == p_cons2.fingerprint
    assert p_salv1.fingerprint == p_salv2.fingerprint

    # Divergence across policies
    assert p_cons1.fingerprint != p_salv1.fingerprint


# ---------------------------------------------------------------------------
# 6. Component Size Cap & Loss Sums
# ---------------------------------------------------------------------------


def test_component_too_large() -> None:
    """Amputation of a component exceeding 10k events refuses with 'component-too-large'."""
    # Synthesize root + 10,001 connected chain events in disconnected component
    count = MAX_COMPONENT_SIZE + 5
    events: list[SessionEvent] = [
        SessionEvent(
            id="trunk-0",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={"text": "trunk"},
        ),
        SessionEvent(
            id="branch-0",
            parent_id=None,
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="user",
            kind="message",
            payload={"text": "branch root"},
        ),
    ]

    for i in range(1, count):
        events.append(
            SessionEvent(
                id=f"branch-{i}",
                parent_id=f"branch-{i - 1}",
                seq=i + 1,
                ts="2026-09-05T12:00:02Z",
                actor="assistant",
                kind="message",
                payload={"text": f"item {i}"},
            )
        )

    f_large = make_finding(
        code=SL006,
        severity=Severity.WARNING,
        repairability=Repairability.LOSSY_EXPLICIT,
        message_template="Oversized branch",
        source=SourceRef(path="session.json", line=2, record_id="branch-0"),
        evidence={"at_index": 1, "index": 1},
    )

    p = plan([f_large], events, policy="salvage")
    assert len(p.steps) == 0
    assert len(p.blocked) == 1
    assert p.blocked[0].reason == "component-too-large"


def test_loss_sums() -> None:
    """Asserts plan total_lost equals sum of step deltas and total_kept consistency helper."""
    path_b = FIXTURES_REPAIR_DIR / "salvage_branch.json"
    with open(path_b, encoding="utf-8") as fh:
        data_b = json.load(fh)

    events = [SessionEvent(**e) for e in data_b["events"]]
    findings = [
        make_finding(
            code=f["code"],
            severity=f["severity"],
            repairability=f["repairability"],
            message_template=f["message"],
            source=SourceRef(**f["source"]),
            evidence=f.get("evidence"),
        )
        for f in data_b["findings"]
    ]

    p = plan(findings, events, policy="salvage")
    step_delta_sum = sum(sum(s.loss.values()) for s in p.steps)

    assert p.total_lost == step_delta_sum
    assert p.total_kept == len(events) - p.total_lost
    assert p.loss_accounting.total_lost == step_delta_sum
    assert p.loss_accounting.total_kept == len(events) - p.total_lost


# ---------------------------------------------------------------------------
# 7. Adversarial Scenarios
# ---------------------------------------------------------------------------


def test_sl203_refusal_beats_salvage() -> None:
    """SL203 finding present causes unconditional refusal even under policy='salvage'."""
    ev = SessionEvent(
        id="call-0",
        parent_id=None,
        seq=0,
        ts="2026-09-05T12:00:00Z",
        actor="assistant",
        kind="tool_call",
        payload={"name": "unsafe_call", "side_effects": "unknown"},
    )
    f_sl203 = make_finding(
        code=SL203,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Unsafe continuation",
        source=SourceRef(path="session.json", line=1, record_id="call-0"),
    )

    # Under conservative: SL203-refusal
    p_cons = plan([f_sl203], [ev], policy="conservative")
    assert len(p_cons.steps) == 0
    assert p_cons.blocked[0].reason == "SL203-refusal"

    # Under salvage: SL203-refusal still wins
    p_salv = plan([f_sl203], [ev], policy="salvage")
    assert len(p_salv.steps) == 0
    assert p_salv.blocked[0].reason == "SL203-refusal"


def test_empty_events_salvage_policy() -> None:
    """Empty events under salvage policy produces clean empty plan with no div-by-zero."""
    p = plan([], [], policy="salvage")
    assert len(p.steps) == 0
    assert len(p.blocked) == 0
    assert p.total_lost == 0
    assert p.total_kept == 0
    assert len(p.fingerprint) == 64


def test_loss_key_injection_rejected() -> None:
    """Invalid loss class outside allowlist raises ValueError."""
    with pytest.raises(ValueError, match="Invalid loss class"):
        PlanStep(
            seq=0,
            recipe="test",
            target_finding_fp="fp",
            target_index=0,
            lossy=True,
            loss={"; rm -rf /": 1},  # Injected key
        )


def test_invalid_policy_string_rejected() -> None:
    """Direct plan call with unknown policy string raises ValueError."""
    ev = SessionEvent(
        id="m0",
        parent_id=None,
        seq=0,
        ts="2026-09-05T12:00:00Z",
        actor="user",
        kind="message",
    )
    with pytest.raises(ValueError, match="Invalid repair policy"):
        plan([], [ev], policy="Aggressive")


# ---------------------------------------------------------------------------
# 8. Pure Transform Edge Cases & PreconditionFailed Verification
# ---------------------------------------------------------------------------


def test_amputate_direct_apply_validation() -> None:
    """apply_unresolvable_branch_amputate raises PreconditionFailed on bad input."""
    step = PlanStep(
        seq=0,
        recipe="unresolvable-branch-amputate",
        target_finding_fp="fp",
        target_index=0,
        lossy=True,
    )

    # Empty session
    with pytest.raises(PreconditionFailed, match="empty session"):
        apply_unresolvable_branch_amputate([], step)

    # Out of bounds target index
    ev = SessionEvent(
        id="m0", parent_id=None, seq=0, ts="2026-09-05T12:00:00Z", actor="user", kind="message"
    )
    bad_step = PlanStep(
        seq=0,
        recipe="unresolvable-branch-amputate",
        target_finding_fp="fp",
        target_index=99,
        lossy=True,
    )
    with pytest.raises(PreconditionFailed, match="Invalid target_index"):
        apply_unresolvable_branch_amputate([ev], bad_step)

    # Checkpoint in branch
    ev_cp = SessionEvent(
        id="cp1",
        parent_id=None,
        seq=0,
        ts="2026-09-05T12:00:00Z",
        actor="system",
        kind="checkpoint",
    )
    ev_ch = SessionEvent(
        id="ch1", parent_id="cp1", seq=1, ts="2026-09-05T12:00:01Z", actor="user", kind="message"
    )
    cp_step = PlanStep(
        seq=0,
        recipe="unresolvable-branch-amputate",
        target_finding_fp="fp",
        target_index=1,
        lossy=True,
    )
    with pytest.raises(PreconditionFailed, match="checkpoint"):
        apply_unresolvable_branch_amputate([ev_cp, ev_ch], cp_step)

    # Amputating entire session is forbidden
    ev_single = SessionEvent(
        id="s1", parent_id=None, seq=0, ts="2026-09-05T12:00:00Z", actor="user", kind="message"
    )
    with pytest.raises(PreconditionFailed, match="entire session"):
        apply_unresolvable_branch_amputate([ev_single], step)


def test_torn_compaction_direct_apply_validation() -> None:
    """apply_torn_compaction_project revalidates preconditions."""
    step = PlanStep(
        seq=0,
        recipe="torn-compaction-project",
        target_finding_fp="fp",
        target_index=0,
        lossy=True,
    )

    with pytest.raises(PreconditionFailed, match="empty session"):
        apply_torn_compaction_project([], step)

    ev_msg = SessionEvent(
        id="m0", parent_id=None, seq=0, ts="2026-09-05T12:00:00Z", actor="user", kind="message"
    )
    with pytest.raises(PreconditionFailed, match="not a compaction_boundary"):
        apply_torn_compaction_project([ev_msg], step)

    # Compaction boundary with no split pairs or orphans
    ev_cb = SessionEvent(
        id="cb0",
        parent_id="m0",
        seq=1,
        ts="2026-09-05T12:00:01Z",
        actor="system",
        kind="compaction_boundary",
    )
    step_cb = PlanStep(
        seq=0,
        recipe="torn-compaction-project",
        target_finding_fp="fp",
        target_index=1,
        lossy=True,
    )
    with pytest.raises(PreconditionFailed, match="no split pairs or orphaned"):
        apply_torn_compaction_project([ev_msg, ev_cb], step_cb)


def test_truncate_direct_apply_validation() -> None:
    """apply_side_effect_unknown_truncate revalidates preconditions."""
    step = PlanStep(
        seq=0,
        recipe="side-effect-unknown-truncate",
        target_finding_fp="fp",
        target_index=0,
        lossy=True,
    )

    with pytest.raises(PreconditionFailed, match="empty session"):
        apply_side_effect_unknown_truncate([], step)

    ev = SessionEvent(
        id="m0", parent_id=None, seq=0, ts="2026-09-05T12:00:00Z", actor="user", kind="message"
    )
    with pytest.raises(PreconditionFailed, match="index 0"):
        apply_side_effect_unknown_truncate([ev], step)

    bad_step = PlanStep(
        seq=0,
        recipe="side-effect-unknown-truncate",
        target_finding_fp="fp",
        target_index=5,
        lossy=True,
    )
    with pytest.raises(PreconditionFailed, match="out of bounds"):
        apply_side_effect_unknown_truncate([ev], bad_step)


# ---------------------------------------------------------------------------
# 9. Vendor-Free & Determinism Standards
# ---------------------------------------------------------------------------


def test_salvage_vendor_free() -> None:
    """Audit recipes_salvage.py and assurance.py for vendor terminology."""
    repair_dir = Path(__file__).resolve().parent.parent.parent / "src" / "sesslint" / "repair"
    target_files = [repair_dir / "recipes_salvage.py", repair_dir / "assurance.py"]

    forbidden = ["claude", "openai", "anthropic", "chatgpt", "toolUse", "call_id"]
    for path in target_files:
        assert path.is_file()
        content = path.read_text(encoding="utf-8").lower()
        for word in forbidden:
            assert word not in content, f"Forbidden vendor keyword '{word}' found in {path}"


# ---------------------------------------------------------------------------
# 10. Recipe Applications & Edge Cases
# ---------------------------------------------------------------------------


def test_salvage_recipe_applications() -> None:
    """Verify that applying salvage recipes matches planned loss and kept counts."""
    # 1. Branch amputation
    path_b = FIXTURES_REPAIR_DIR / "salvage_branch.json"
    with open(path_b, encoding="utf-8") as fh:
        data_b = json.load(fh)
    events_b = [SessionEvent(**e) for e in data_b["events"]]
    findings_b = [
        make_finding(
            code=f["code"],
            severity=f["severity"],
            repairability=f["repairability"],
            message_template=f["message"],
            source=SourceRef(**f["source"]),
            evidence=f.get("evidence"),
        )
        for f in data_b["findings"]
    ]
    p_b = plan(findings_b, events_b, policy="salvage")
    out_b, loss_b = apply_unresolvable_branch_amputate_with_loss(events_b, p_b.steps[0])
    assert len(out_b) == p_b.total_kept == 3
    assert loss_b == p_b.steps[0].loss == {"amputated-branch": 2}
    assert [e["id"] for e in out_b] == ["c1-1", "c1-2", "c1-3"]

    # 2. Torn compaction projection
    path_p = FIXTURES_REPAIR_DIR / "salvage_project.json"
    with open(path_p, encoding="utf-8") as fh:
        data_p = json.load(fh)
    events_p = [SessionEvent(**e) for e in data_p["events"]]
    findings_p = [
        make_finding(
            code=f["code"],
            severity=f["severity"],
            repairability=f["repairability"],
            message_template=f["message"],
            source=SourceRef(**f["source"]),
            evidence=f.get("evidence"),
        )
        for f in data_p["findings"]
    ]
    p_p = plan(findings_p, events_p, policy="salvage")
    out_p, loss_p = apply_torn_compaction_project_with_loss(events_p, p_p.steps[0])
    assert len(out_p) == p_p.total_kept == 3
    assert loss_p == p_p.steps[0].loss == {"projected-orphans": 2}
    assert [e["id"] for e in out_p] == ["m0", "tc1", "m1"]

    # 3. Truncation
    path_t = FIXTURES_REPAIR_DIR / "salvage_truncate.json"
    with open(path_t, encoding="utf-8") as fh:
        data_t = json.load(fh)
    events_t = [SessionEvent(**e) for e in data_t["events"]]
    findings_t = [
        make_finding(
            code=f["code"],
            severity=f["severity"],
            repairability=f["repairability"],
            message_template=f["message"],
            source=SourceRef(**f["source"]),
            evidence=f.get("evidence"),
        )
        for f in data_t["findings"]
    ]
    p_t = plan(findings_t, events_t, policy="salvage", acknowledge_side_effects=True)
    out_t, loss_t = apply_side_effect_unknown_truncate_with_loss(events_t, p_t.steps[0])
    assert len(out_t) == p_t.total_kept == 2
    assert loss_t == p_t.steps[0].loss == {"truncated-side-effects": 2}
    assert [e["id"] for e in out_t] == ["m0", "m1"]


def test_amputate_resolves_index_from_root_id() -> None:
    """SL006 finding without at_index in evidence resolves target index from root_id."""
    path_b = FIXTURES_REPAIR_DIR / "salvage_branch.json"
    with open(path_b, encoding="utf-8") as fh:
        data_b = json.load(fh)
    events_b = [SessionEvent(**e) for e in data_b["events"]]
    # Finding matches real check_disconnected_components (only root_id and size, no at_index/index)
    f_real = make_finding(
        code=SL006,
        severity=Severity.WARNING,
        repairability=Repairability.LOSSY_EXPLICIT,
        message_template="Disconnected branch",
        source=SourceRef(path="session.json", line=4, record_id="c2-1"),
        evidence={"root_id": "c2-1", "size": 2},
    )
    p = plan([f_real], events_b, policy="salvage")
    assert len(p.steps) == 1
    assert p.steps[0].target_index == 3
    assert p.steps[0].loss == {"amputated-branch": 2}
    out, loss = apply_unresolvable_branch_amputate_with_loss(events_b, p.steps[0])
    assert len(out) == 3
    assert loss == {"amputated-branch": 2}


def test_dual_policy_plan_merge_attempt() -> None:
    """Dual-policy plan merge attempt produces fingerprint mismatch detectable by verify."""
    path_b = FIXTURES_REPAIR_DIR / "salvage_branch.json"
    with open(path_b, encoding="utf-8") as fh:
        data_b = json.load(fh)
    events = [SessionEvent(**e) for e in data_b["events"]]
    findings = [
        make_finding(
            code=f["code"],
            severity=f["severity"],
            repairability=f["repairability"],
            message_template=f["message"],
            source=SourceRef(**f["source"]),
            evidence=f.get("evidence"),
        )
        for f in data_b["findings"]
    ]
    p_cons = plan(findings, events, policy="conservative")
    p_salv = plan(findings, events, policy="salvage")

    assert p_cons.fingerprint != p_salv.fingerprint

    # Tampering: injecting salvage steps into conservative plan dictionary
    merged_dict = p_cons.to_dict()
    merged_dict["steps"] = [s.to_dict() for s in p_salv.steps]
    from sesslint.repair.fingerprint import compute_plan_fingerprint

    merged_fp = compute_plan_fingerprint(merged_dict)
    assert merged_fp != p_cons.fingerprint
    assert merged_fp != p_salv.fingerprint


def test_interacting_multi_fault_session() -> None:
    """Multi-fault session with both unresolvable branch (SL006) and dangling tool call (SL102)."""
    # Trunk: m0 -> m1 -> tc_unsafe (dangling call with unknown side effects)
    # Branch: b0 -> b1 (disconnected branch)
    events: list[SessionEvent] = [
        SessionEvent(
            id="m0",
            parent_id=None,
            seq=0,
            ts="2026-09-05T12:00:00Z",
            actor="user",
            kind="message",
            payload={"text": "root"},
        ),
        SessionEvent(
            id="m1",
            parent_id="m0",
            seq=1,
            ts="2026-09-05T12:00:01Z",
            actor="assistant",
            kind="message",
            payload={"text": "step 1"},
        ),
        SessionEvent(
            id="tc_unsafe",
            parent_id="m1",
            seq=2,
            ts="2026-09-05T12:00:02Z",
            actor="assistant",
            kind="tool_call",
            payload={"name": "ext", "side_effects": "unknown"},
        ),
        SessionEvent(
            id="b0",
            parent_id=None,
            seq=3,
            ts="2026-09-05T12:00:03Z",
            actor="user",
            kind="message",
            payload={"text": "branch root"},
        ),
        SessionEvent(
            id="b1",
            parent_id="b0",
            seq=4,
            ts="2026-09-05T12:00:04Z",
            actor="assistant",
            kind="message",
            payload={"text": "branch leaf"},
        ),
    ]
    f_branch = make_finding(
        code=SL006,
        severity=Severity.WARNING,
        repairability=Repairability.LOSSY_EXPLICIT,
        message_template="Disconnected branch",
        source=SourceRef(path="session.json", line=4, record_id="b0"),
        evidence={"at_index": 3, "root_id": "b0", "size": 2},
    )
    f_dangling = make_finding(
        code="SL102",
        severity=Severity.ERROR,
        repairability=Repairability.LOSSY_EXPLICIT,
        message_template="Dangling tool call",
        source=SourceRef(path="session.json", line=3, record_id="tc_unsafe"),
        evidence={"at_index": 2, "first_unsafe_index": 2},
    )

    # 1. Conservative policy: both blocked with needs-salvage-policy
    p_cons = plan([f_branch, f_dangling], events, policy="conservative")
    assert len(p_cons.steps) == 0
    assert len(p_cons.blocked) == 2
    assert all(b.reason == "needs-salvage-policy" for b in p_cons.blocked)

    # 2. Salvage policy without acknowledgement:
    # branch planned, dangling blocked with needs-acknowledgement
    p_salv_no_ack = plan(
        [f_branch, f_dangling], events, policy="salvage", acknowledge_side_effects=False
    )
    assert len(p_salv_no_ack.steps) == 1
    assert p_salv_no_ack.steps[0].recipe == "unresolvable-branch-amputate"
    assert len(p_salv_no_ack.blocked) == 1
    assert p_salv_no_ack.blocked[0].reason == "needs-acknowledgement"

    # 3. Salvage policy with acknowledgement: both planned
    p_salv_ack = plan(
        [f_branch, f_dangling], events, policy="salvage", acknowledge_side_effects=True
    )
    assert len(p_salv_ack.steps) == 2
    assert len(p_salv_ack.blocked) == 0
    recipes = {s.recipe for s in p_salv_ack.steps}
    assert recipes == {"unresolvable-branch-amputate", "side-effect-unknown-truncate"}
