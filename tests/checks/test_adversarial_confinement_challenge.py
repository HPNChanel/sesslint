"""Adversarial stress-testing suite for DEV-002 parent-restore confinement and exact-match logic.

Challenger test matrix covering:
1. Compaction boundaries: endpoint boundaries (c.seq or child.seq), multiple
   intervening boundaries, negative sequence numbers, gaps, duplicate sequence numbers.
2. Branch confinement: None vs string, string vs None, both None, empty string vs None,
   both empty string, unicode branches, casing, whitespace, and non-string branch types.
3. ID matching & anti-guessing: prefix collisions (shorter/longer), casing differences,
   whitespace, hash vs ID mixups, self-candidate rejection, empty candidate ID.
4. Duplicate candidates: multiple candidates in same segment, disambiguation by branch,
   disambiguation by compaction boundary, all-decoy rejections.
5. Inverted sequence orders: candidate after child in list order or inverted seq numbers.
6. Zero-trust cross-layer verification (detector, precondition, apply, executor).
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from sesslint.checks.graph import (
    find_qualifying_parent_candidates,
    is_qualifying_parent_candidate,
    same_compaction_segment,
)
from sesslint.codes import SL004, Repairability, Severity
from sesslint.finding import SourceRef, make_finding
from sesslint.repair.errors import OutputInvalid
from sesslint.repair.executor import execute
from sesslint.repair.fingerprint import compute_plan_fingerprint
from sesslint.repair.planner import Loss, PlanStep, RepairPlan
from sesslint.repair.preconditions import PreconditionContext, unique_parent_candidate
from sesslint.repair.recipes_conservative import (
    PreconditionFailed,
    apply_proven_unique_parent_restore,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(
    ev_id: str,
    parent_id: str | None = None,
    seq: int = 0,
    branch_id: Any = "main",
    kind: str = "message",
    hash_val: str | None = None,
) -> dict[str, Any]:
    ev: dict[str, Any] = {
        "id": ev_id,
        "parent_id": parent_id,
        "seq": seq,
        "branch_id": branch_id,
        "kind": kind,
        "actor": "user" if kind == "message" else "system",
        "payload": {"content": f"data-{ev_id}"},
        "ts": "2026-09-09T12:00:00Z",
    }
    if hash_val is not None:
        ev["hash"] = hash_val
    return ev


# ---------------------------------------------------------------------------
# 1. Compaction Boundaries: Stress & Edge Cases
# ---------------------------------------------------------------------------


class TestCompactionBoundariesAdversarial:
    """Stress-test compaction boundaries under tricky edge conditions."""

    def test_boundary_endpoint_at_candidate_seq(self) -> None:
        """Compaction boundary at candidate seq does NOT violate confinement."""
        events = [
            _make_event("cand", parent_id=None, seq=10),
            _make_event("b_endpoint", parent_id=None, seq=10, kind="compaction_boundary"),
            _make_event("child", parent_id="cand", seq=20),
        ]
        # min(10, 20) < 10 < max(10, 20) is False -> endpoint is not strictly between
        assert same_compaction_segment(events, events[0], events[2]) is True

    def test_boundary_endpoint_at_child_seq(self) -> None:
        """Boundary with identical seq to child is at endpoint; does not violate confinement."""
        events = [
            _make_event("cand", parent_id=None, seq=10),
            _make_event("b_endpoint", parent_id=None, seq=20, kind="compaction_boundary"),
            _make_event("child", parent_id="cand", seq=20),
        ]
        assert same_compaction_segment(events, events[0], events[2]) is True

    def test_boundary_endpoint_at_both_candidate_and_child_seq(self) -> None:
        """Boundaries at both candidate and child endpoints do NOT violate confinement."""
        events = [
            _make_event("b1", parent_id=None, seq=5, kind="compaction_boundary"),
            _make_event("cand", parent_id=None, seq=5),
            _make_event("child", parent_id="cand", seq=15),
            _make_event("b2", parent_id=None, seq=15, kind="compaction_boundary"),
        ]
        assert same_compaction_segment(events, events[1], events[2]) is True

    def test_multiple_intervening_boundaries(self) -> None:
        """Multiple compaction boundaries strictly between candidate and child violate."""
        events = [
            _make_event("cand", parent_id=None, seq=0),
            _make_event("b1", parent_id=None, seq=1, kind="compaction_boundary"),
            _make_event("b2", parent_id=None, seq=2, kind="compaction_boundary"),
            _make_event("b3", parent_id=None, seq=3, kind="compaction_boundary"),
            _make_event("child", parent_id="cand", seq=4),
        ]
        assert same_compaction_segment(events, events[0], events[4]) is False
        qualifies, reason = is_qualifying_parent_candidate(
            events[0], events[4], events, missing_parent_id="cand"
        )
        assert qualifies is False
        assert reason == "cross_segment"

    def test_boundary_negative_sequence_numbers(self) -> None:
        """Compaction boundary strictly between negative seq numbers violates confinement."""
        events = [
            _make_event("cand", parent_id=None, seq=-50),
            _make_event("b1", parent_id=None, seq=-20, kind="compaction_boundary"),
            _make_event("child", parent_id="cand", seq=-5),
        ]
        # -50 < -20 < -5 is True -> violates confinement
        assert same_compaction_segment(events, events[0], events[2]) is False

        # Endpoint boundary at negative seq does not violate
        events_endpoint = [
            _make_event("cand", parent_id=None, seq=-50),
            _make_event("b1", parent_id=None, seq=-50, kind="compaction_boundary"),
            _make_event("child", parent_id="cand", seq=-5),
        ]
        assert (
            same_compaction_segment(events_endpoint, events_endpoint[0], events_endpoint[2]) is True
        )

    def test_boundary_large_sequence_gaps(self) -> None:
        """Gaps in sequence numbers with boundary strictly between violate confinement."""
        events = [
            _make_event("cand", parent_id=None, seq=1),
            _make_event("b1", parent_id=None, seq=500_000, kind="compaction_boundary"),
            _make_event("child", parent_id="cand", seq=1_000_000),
        ]
        assert same_compaction_segment(events, events[0], events[2]) is False

    def test_boundary_out_of_list_order(self) -> None:
        """Boundary later in list but with sequence strictly between breaks confinement."""
        # Note: b1 is at list index 2, after child at index 1, but its seq=15 is between 10 and 20
        events = [
            _make_event("cand", parent_id=None, seq=10),
            _make_event("child", parent_id="cand", seq=20),
            _make_event("b1", parent_id=None, seq=15, kind="compaction_boundary"),
        ]
        assert same_compaction_segment(events, events[0], events[1]) is False

    def test_non_compaction_boundary_events_do_not_break_segment(self) -> None:
        """Intervening events with other kinds (e.g. checkpoint, message) do NOT break segment."""
        events = [
            _make_event("cand", parent_id=None, seq=0),
            _make_event("chk", parent_id=None, seq=1, kind="checkpoint"),
            _make_event("msg", parent_id=None, seq=2, kind="message"),
            _make_event("tc", parent_id=None, seq=3, kind="tool_call"),
            _make_event("tr", parent_id=None, seq=4, kind="tool_result"),
            _make_event("child", parent_id="cand", seq=5),
        ]
        assert same_compaction_segment(events, events[0], events[5]) is True


# ---------------------------------------------------------------------------
# 2. Branch Confinement: Stress & Edge Cases
# ---------------------------------------------------------------------------


class TestBranchConfinementAdversarial:
    """Stress-test branch confinement across None, empty string, unicode, and types."""

    def test_branch_none_vs_string(self) -> None:
        """Candidate with branch=None and child with branch='main' violates confinement."""
        events = [
            _make_event("cand", parent_id=None, seq=0, branch_id=None),
            _make_event("child", parent_id="cand", seq=1, branch_id="main"),
        ]
        qualifies, reason = is_qualifying_parent_candidate(
            events[0], events[1], events, missing_parent_id="cand"
        )
        assert qualifies is False
        assert reason == "cross_branch"

    def test_branch_string_vs_none(self) -> None:
        """Candidate with branch='main' and child with branch=None violates confinement."""
        events = [
            _make_event("cand", parent_id=None, seq=0, branch_id="main"),
            _make_event("child", parent_id="cand", seq=1, branch_id=None),
        ]
        qualifies, reason = is_qualifying_parent_candidate(
            events[0], events[1], events, missing_parent_id="cand"
        )
        assert qualifies is False
        assert reason == "cross_branch"

    def test_branch_both_none_is_same_group(self) -> None:
        """Both events having branch=None are in the same unbranched group and qualify."""
        events = [
            _make_event("cand", parent_id=None, seq=0, branch_id=None),
            _make_event("child", parent_id="cand", seq=1, branch_id=None),
        ]
        qualifies, reason = is_qualifying_parent_candidate(
            events[0], events[1], events, missing_parent_id="cand"
        )
        assert qualifies is True
        assert reason == "ok"

    def test_branch_empty_string_vs_none(self) -> None:
        """Branch='' is distinct from branch=None; cross-branch must reject."""
        events = [
            _make_event("cand", parent_id=None, seq=0, branch_id=""),
            _make_event("child", parent_id="cand", seq=1, branch_id=None),
        ]
        qualifies, reason = is_qualifying_parent_candidate(
            events[0], events[1], events, missing_parent_id="cand"
        )
        assert qualifies is False
        assert reason == "cross_branch"

    def test_branch_both_empty_string(self) -> None:
        """Both events having branch='' are identical strings and qualify."""
        events = [
            _make_event("cand", parent_id=None, seq=0, branch_id=""),
            _make_event("child", parent_id="cand", seq=1, branch_id=""),
        ]
        qualifies, reason = is_qualifying_parent_candidate(
            events[0], events[1], events, missing_parent_id="cand"
        )
        assert qualifies is True
        assert reason == "ok"

    def test_branch_unicode_matching(self) -> None:
        """Identical unicode branch names qualify."""
        branch_name = "ветка-фича-🚀-日本語"
        events = [
            _make_event("cand", parent_id=None, seq=0, branch_id=branch_name),
            _make_event("child", parent_id="cand", seq=1, branch_id=branch_name),
        ]
        qualifies, reason = is_qualifying_parent_candidate(
            events[0], events[1], events, missing_parent_id="cand"
        )
        assert qualifies is True
        assert reason == "ok"

    def test_branch_unicode_mismatch(self) -> None:
        """Conflicting unicode branch names violate confinement."""
        events = [
            _make_event("cand", parent_id=None, seq=0, branch_id="ветка-фича-🚀"),
            _make_event("child", parent_id="cand", seq=1, branch_id="ветка-фича-🛸"),
        ]
        qualifies, reason = is_qualifying_parent_candidate(
            events[0], events[1], events, missing_parent_id="cand"
        )
        assert qualifies is False
        assert reason == "cross_branch"

    def test_branch_casing_sensitivity(self) -> None:
        """Branch IDs are case-sensitive; 'Main' != 'main'."""
        events = [
            _make_event("cand", parent_id=None, seq=0, branch_id="Main"),
            _make_event("child", parent_id="cand", seq=1, branch_id="main"),
        ]
        qualifies, reason = is_qualifying_parent_candidate(
            events[0], events[1], events, missing_parent_id="cand"
        )
        assert qualifies is False
        assert reason == "cross_branch"

    def test_branch_whitespace_sensitivity(self) -> None:
        """Branch IDs preserve whitespace; 'main ' != 'main'."""
        events = [
            _make_event("cand", parent_id=None, seq=0, branch_id="main "),
            _make_event("child", parent_id="cand", seq=1, branch_id="main"),
        ]
        qualifies, reason = is_qualifying_parent_candidate(
            events[0], events[1], events, missing_parent_id="cand"
        )
        assert qualifies is False
        assert reason == "cross_branch"

    def test_branch_non_string_types(self) -> None:
        """Integer branch ID 100 coerced to '100' matches '100', rejects 200."""
        events = [
            _make_event("cand", parent_id=None, seq=0, branch_id=100),
            _make_event("child", parent_id="cand", seq=1, branch_id="100"),
            _make_event("other", parent_id="cand", seq=2, branch_id=200),
        ]
        assert is_qualifying_parent_candidate(events[0], events[1], events, "cand")[0] is True
        assert is_qualifying_parent_candidate(events[0], events[2], events, "cand")[0] is False


# ---------------------------------------------------------------------------
# 3. ID Matching & Anti-Guessing: Stress & Edge Cases
# ---------------------------------------------------------------------------


class TestIdMatchingAntiGuessingAdversarial:
    """Stress-test exact ID matching to verify elimination of prefix/heuristic guessing."""

    def test_prefix_collision_candidate_shorter_than_missing(self) -> None:
        """Candidate 'msg-1' must NOT match missing parent 'msg-10'."""
        events = [
            _make_event("msg-1", parent_id=None, seq=0),
            _make_event("child", parent_id="msg-10", seq=1),
        ]
        qualifies, reason = is_qualifying_parent_candidate(
            events[0], events[1], events, missing_parent_id="msg-10"
        )
        assert qualifies is False
        assert reason == "no_full_match"

    def test_prefix_collision_candidate_longer_than_missing(self) -> None:
        """Candidate 'msg-10' must NOT match missing parent 'msg-1' (former startswith bug)."""
        events = [
            _make_event("msg-10", parent_id=None, seq=0),
            _make_event("child", parent_id="msg-1", seq=1),
        ]
        qualifies, reason = is_qualifying_parent_candidate(
            events[0], events[1], events, missing_parent_id="msg-1"
        )
        assert qualifies is False
        assert reason == "no_full_match"

    def test_id_casing_sensitivity(self) -> None:
        """IDs are case-sensitive; 'EVT-ROOT' != 'evt-root'."""
        events = [
            _make_event("EVT-ROOT", parent_id=None, seq=0),
            _make_event("child", parent_id="evt-root", seq=1),
        ]
        qualifies, reason = is_qualifying_parent_candidate(
            events[0], events[1], events, missing_parent_id="evt-root"
        )
        assert qualifies is False
        assert reason == "no_full_match"

    def test_id_whitespace_padding(self) -> None:
        """Whitespace in IDs is not trimmed in matching; 'evt-root ' != 'evt-root'."""
        events = [
            _make_event("evt-root ", parent_id=None, seq=0),
            _make_event("child", parent_id="evt-root", seq=1),
        ]
        qualifies, reason = is_qualifying_parent_candidate(
            events[0], events[1], events, missing_parent_id="evt-root"
        )
        assert qualifies is False
        assert reason == "no_full_match"

    def test_hash_vs_id_mixup_rejected(self) -> None:
        """Missing parent equal to candidate's hash (not candidate ID) is strictly rejected."""
        events = [
            _make_event("evt-id-999", parent_id=None, seq=0, hash_val="deadbeefcafe1234"),
            _make_event("child", parent_id="deadbeefcafe1234", seq=1),
        ]
        # In old code, c_hash.startswith(prefix) matched; now only c_id == missing_parent_id
        qualifies, reason = is_qualifying_parent_candidate(
            events[0], events[1], events, missing_parent_id="deadbeefcafe1234"
        )
        assert qualifies is False
        assert reason == "no_full_match"

    def test_hash_prefix_mixup_rejected(self) -> None:
        """Candidate hash prefix is never matched as a parent ID."""
        events = [
            _make_event("evt-1", parent_id=None, seq=0, hash_val="deadbeefcafe1234"),
            _make_event("child", parent_id="deadbeef", seq=1),
        ]
        qualifies, reason = is_qualifying_parent_candidate(
            events[0], events[1], events, missing_parent_id="deadbeef"
        )
        assert qualifies is False
        assert reason == "no_full_match"

    def test_self_candidate_rejected(self) -> None:
        """Child event cannot be its own parent candidate."""
        child = _make_event("self-loop-node", parent_id="self-loop-node", seq=0)
        events = [child]
        qualifies, reason = is_qualifying_parent_candidate(
            child, child, events, missing_parent_id="self-loop-node"
        )
        assert qualifies is False
        assert reason == "self_candidate"

    def test_empty_or_none_candidate_id_rejected(self) -> None:
        """Candidate with empty or None ID is rejected."""
        events = [
            _make_event("", parent_id=None, seq=0),
            _make_event("child", parent_id="", seq=1),
        ]
        qualifies, reason = is_qualifying_parent_candidate(
            events[0], events[1], events, missing_parent_id=""
        )
        assert qualifies is False
        assert reason == "empty_candidate_id"

    def test_special_characters_in_ids(self) -> None:
        """IDs with special characters, colons, slashes match on exact string equality only."""
        special_id = "urn:uuid:1234-5678/node#sub?key=val&flag=1"
        events = [
            _make_event(special_id, parent_id=None, seq=0),
            _make_event("child", parent_id=special_id, seq=1),
        ]
        qualifies, reason = is_qualifying_parent_candidate(
            events[0], events[1], events, missing_parent_id=special_id
        )
        assert qualifies is True
        assert reason == "ok"

        # Prefix fails
        prefix_id = "urn:uuid:1234-5678/node"
        qualifies_prefix, reason_prefix = is_qualifying_parent_candidate(
            events[0], events[1], events, missing_parent_id=prefix_id
        )
        assert qualifies_prefix is False
        assert reason_prefix == "no_full_match"


# ---------------------------------------------------------------------------
# 4. Duplicate Candidates: Ambiguity Handling
# ---------------------------------------------------------------------------


class TestDuplicateCandidatesAdversarial:
    """Stress-test handling of duplicate candidate events and disambiguation."""

    def test_multiple_identical_candidates_in_same_segment(self) -> None:
        """Multiple identical candidates in the same segment yield ambiguous reason and MANUAL."""
        events = [
            _make_event("parent-dup", parent_id=None, seq=0),
            _make_event("parent-dup", parent_id=None, seq=1),
            _make_event("parent-dup", parent_id=None, seq=2),
            _make_event("child", parent_id="parent-dup", seq=3),
        ]
        qualifying, rejected, conf, reason = find_qualifying_parent_candidates(
            events=events,
            child=events[3],
            target_idx=3,
            missing_parent_id="parent-dup",
        )
        assert len(qualifying) == 3
        assert reason == "ambiguous"

    def test_duplicate_disambiguated_by_branch(self) -> None:
        """Two candidates with same ID, one on another branch: 1 qualifies -> DETERMINISTIC."""
        events = [
            _make_event("target-p", parent_id=None, seq=0, branch_id="main"),
            _make_event("target-p", parent_id=None, seq=1, branch_id="feature-x"),
            _make_event("child", parent_id="target-p", seq=2, branch_id="main"),
        ]
        qualifying, rejected, conf, reason = find_qualifying_parent_candidates(
            events=events,
            child=events[2],
            target_idx=2,
            missing_parent_id="target-p",
        )
        assert len(qualifying) == 1
        assert qualifying[0] == 0
        assert conf["branch"] is True
        assert conf["segment"] is True
        assert reason == "ok"

        # Cross-branch candidate was rejected
        assert len(rejected) == 1
        assert rejected[0]["reason"] == "cross_branch"

    def test_duplicate_disambiguated_by_compaction_segment(self) -> None:
        """Two candidates with same ID, one across compaction: 1 qualifies -> DETERMINISTIC."""
        events = [
            _make_event("target-p", parent_id=None, seq=0),
            _make_event("boundary", parent_id=None, seq=1, kind="compaction_boundary"),
            _make_event("target-p", parent_id=None, seq=2),
            _make_event("child", parent_id="target-p", seq=3),
        ]
        qualifying, rejected, conf, reason = find_qualifying_parent_candidates(
            events=events,
            child=events[3],
            target_idx=3,
            missing_parent_id="target-p",
        )
        assert len(qualifying) == 1
        assert qualifying[0] == 2
        assert conf["segment"] is True
        assert reason == "ok"

        # Pre-boundary candidate was rejected with cross_segment
        assert any(d["reason"] == "cross_segment" for d in rejected)

    def test_duplicate_candidates_both_cross_branch(self) -> None:
        """All candidates cross-branch: candidate_count=0, reason='cross_branch'."""
        events = [
            _make_event("target-p", parent_id=None, seq=0, branch_id="branch-a"),
            _make_event("target-p", parent_id=None, seq=1, branch_id="branch-b"),
            _make_event("child", parent_id="target-p", seq=2, branch_id="main"),
        ]
        qualifying, rejected, conf, reason = find_qualifying_parent_candidates(
            events=events,
            child=events[2],
            target_idx=2,
            missing_parent_id="target-p",
        )
        assert len(qualifying) == 0
        assert conf["branch"] is False
        assert reason == "cross_branch"


# ---------------------------------------------------------------------------
# 5. Inverted Sequence Orders & Non-Standard Layouts
# ---------------------------------------------------------------------------


class TestInvertedSequenceOrdersAdversarial:
    """Stress-test behavior when candidate appears after child in list or has inverted sequence."""

    def test_candidate_after_child_in_event_list(self) -> None:
        """Candidate appearing after child in list order (target_idx=0) is NEVER considered."""
        events = [
            _make_event("child", parent_id="cand-forward", seq=0),
            _make_event("cand-forward", parent_id=None, seq=1),
        ]
        qualifying, rejected, conf, reason = find_qualifying_parent_candidates(
            events=events,
            child=events[0],
            target_idx=0,
            missing_parent_id="cand-forward",
        )
        assert len(qualifying) == 0
        assert len(rejected) == 0
        assert reason == "no_full_match"

    def test_candidate_before_child_in_list_with_inverted_seq(self) -> None:
        """Candidate at list index 0, child at list index 1, but cand.seq > child.seq.

        Verifies that compaction boundaries between cand.seq and child.seq are checked
        using min/max regardless of sequence direction.
        """
        events_with_boundary = [
            _make_event("cand", parent_id=None, seq=100),
            _make_event("b1", parent_id=None, seq=50, kind="compaction_boundary"),
            _make_event("child", parent_id="cand", seq=10),
        ]
        # min(100, 10) < 50 < max(100, 10) -> 10 < 50 < 100 is True -> breaks confinement
        assert (
            same_compaction_segment(
                events_with_boundary, events_with_boundary[0], events_with_boundary[2]
            )
            is False
        )
        qualifies, reason = is_qualifying_parent_candidate(
            events_with_boundary[0],
            events_with_boundary[2],
            events_with_boundary,
            missing_parent_id="cand",
        )
        assert qualifies is False
        assert reason == "cross_segment"


# ---------------------------------------------------------------------------
# 6. Defense-in-Depth Cross-Layer Coercion Attacks
# ---------------------------------------------------------------------------


class TestCrossLayerCoercionAttacks:
    """Verify neither Precondition nor Apply can be tricked into relinking invalid candidates."""

    def test_apply_refuses_cross_branch_tampered_step(self) -> None:
        """Craft PlanStep pointing to cross-branch parent; apply must raise PreconditionFailed."""
        events = [
            _make_event("target-p", parent_id=None, seq=0, branch_id="branch-other"),
            _make_event("child", parent_id="fake-parent", seq=1, branch_id="branch-main"),
        ]
        step = PlanStep(
            seq=0,
            recipe="proven-unique-parent-restore",
            target_finding_fp="fp-test",
            target_index=1,
            params={"parent_id": "target-p"},
        )
        with pytest.raises(
            PreconditionFailed, match="zero candidates matching 'target-p' \\(cross_branch\\)"
        ):
            apply_proven_unique_parent_restore(events, step)

    def test_apply_refuses_cross_segment_tampered_step(self) -> None:
        """Craft PlanStep pointing to cross-segment parent; apply must raise PreconditionFailed."""
        events = [
            _make_event("target-p", parent_id=None, seq=0),
            _make_event("boundary", parent_id=None, seq=1, kind="compaction_boundary"),
            _make_event("child", parent_id="fake-parent", seq=2),
        ]
        step = PlanStep(
            seq=0,
            recipe="proven-unique-parent-restore",
            target_finding_fp="fp-test",
            target_index=2,
            params={"parent_id": "target-p"},
        )
        with pytest.raises(
            PreconditionFailed, match="zero candidates matching 'target-p' \\(cross_segment\\)"
        ):
            apply_proven_unique_parent_restore(events, step)

    def test_apply_refuses_prefix_tampered_step(self) -> None:
        """Attacker crafts a PlanStep with prefix parent_id; apply must raise PreconditionFailed."""
        events = [
            _make_event("target-parent-full", parent_id=None, seq=0),
            _make_event("child", parent_id="fake-parent", seq=1),
        ]
        step = PlanStep(
            seq=0,
            recipe="proven-unique-parent-restore",
            target_finding_fp="fp-test",
            target_index=1,
            params={"parent_id": "target-parent"},
        )
        with pytest.raises(
            PreconditionFailed, match="zero candidates matching 'target-parent' \\(no_full_match\\)"
        ):
            apply_proven_unique_parent_restore(events, step)

    def test_apply_refuses_ambiguous_tampered_step(self) -> None:
        """Craft PlanStep with 2 identical candidates; apply must raise PreconditionFailed."""
        events = [
            _make_event("target-p", parent_id=None, seq=0),
            _make_event("target-p", parent_id=None, seq=1),
            _make_event("child", parent_id="fake-parent", seq=2),
        ]
        step = PlanStep(
            seq=0,
            recipe="proven-unique-parent-restore",
            target_finding_fp="fp-test",
            target_index=2,
            params={"parent_id": "target-p"},
        )
        with pytest.raises(PreconditionFailed, match="ambiguous candidates \\(2\\)"):
            apply_proven_unique_parent_restore(events, step)

    def test_apply_refuses_out_of_bounds_target_index(self) -> None:
        """Negative or out-of-bounds target_index in PlanStep raises PreconditionFailed."""
        events = [
            _make_event("cand", parent_id=None, seq=0),
            _make_event("child", parent_id="cand", seq=1),
        ]
        for invalid_idx in [-1, 2, 999]:
            step = PlanStep(
                seq=0,
                recipe="proven-unique-parent-restore",
                target_finding_fp="fp-test",
                target_index=invalid_idx,
                params={"parent_id": "cand"},
            )
            with pytest.raises(PreconditionFailed, match="missing or invalid target_index"):
                apply_proven_unique_parent_restore(events, step)

    def test_precondition_refuses_when_no_parent_id_in_evidence_or_child(self) -> None:
        """Precondition returns False when parent_id is missing from finding evidence and child."""
        events = [
            _make_event("cand", parent_id=None, seq=0),
            _make_event("child", parent_id=None, seq=1),
        ]
        f = make_finding(
            code=SL004,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message_template="Missing parent",
            source=SourceRef(path="<canonical>", line=None, record_id="child"),
            evidence={"id": "child", "index": 1, "parent_id": None},
        )
        ctx = PreconditionContext(
            findings=[f],
            events=events,
            profile="neutral",
            source_hash="",
            finding=f,
        )
        assert unique_parent_candidate(ctx) is False

    def test_e2e_executor_fails_closed_on_coercion_attempt(self) -> None:
        """Full executor run on an adversarial PlanStep fails closed; does not corrupt file."""
        events = [
            _make_event("cand", parent_id=None, seq=0, branch_id="branch-a"),
            _make_event("child", parent_id="broken", seq=1, branch_id="branch-b"),
        ]
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            session_file = tmp_path / "adversarial_session.jsonl"
            with open(session_file, "w", encoding="utf-8") as fh:
                fh.write(
                    json.dumps(
                        {
                            "schema_version": "sesslint.session/v1",
                            "session_id": "s1",
                            "created_at": "2026-09-09T00:00:00Z",
                        }
                    )
                    + "\n"
                )
                for ev in events:
                    fh.write(json.dumps(ev) + "\n")

            # Plan with invalid cross-branch step
            bad_step = PlanStep(
                seq=0,
                recipe="proven-unique-parent-restore",
                target_finding_fp="0123456789abcdef",
                target_index=1,
                params={"parent_id": "cand"},
            )

            source_bytes = session_file.read_bytes()
            source_hash = hashlib.sha256(source_bytes).hexdigest()
            malicious_plan = RepairPlan(
                source_hash=source_hash,
                profile="neutral",
                steps=(bad_step,),
                blocked=(),
                loss_accounting=Loss(),
                fingerprint="",
            )
            fp = compute_plan_fingerprint(malicious_plan.to_dict())
            malicious_plan = RepairPlan(
                source_hash=source_hash,
                profile="neutral",
                steps=(bad_step,),
                blocked=(),
                loss_accounting=Loss(),
                fingerprint=fp,
            )

            out_file = tmp_path / "repaired.jsonl"
            with pytest.raises((OutputInvalid, PreconditionFailed)):
                execute(
                    source_path=session_file,
                    plan=malicious_plan,
                    output_path=out_file,
                    policy="conservative",
                )
            # Verify output file was not committed
            assert not out_file.exists()


# ---------------------------------------------------------------------------
# 7. Hypothesis Property-Based Fuzzing of Invariants
# ---------------------------------------------------------------------------


class TestHypothesisConfinementFuzzing:
    """Property-based fuzz testing of candidate qualification invariants."""

    @given(
        cand_id=st.text(max_size=30),
        child_id=st.text(max_size=30),
        missing_pid=st.text(max_size=30),
        cand_branch=st.one_of(st.none(), st.text(max_size=20)),
        child_branch=st.one_of(st.none(), st.text(max_size=20)),
        cand_seq=st.integers(min_value=-1000, max_value=1000),
        child_seq=st.integers(min_value=-1000, max_value=1000),
        boundary_seq=st.integers(min_value=-1000, max_value=1000),
        has_boundary=st.booleans(),
    )
    @settings(max_examples=300, deadline=None)
    def test_hypothesis_candidate_qualification_oracle(
        self,
        cand_id: str,
        child_id: str,
        missing_pid: str,
        cand_branch: str | None,
        child_branch: str | None,
        cand_seq: int,
        child_seq: int,
        boundary_seq: int,
        has_boundary: bool,
    ) -> None:
        """Exhaustive oracle check: candidate qualifies iff all 4 confinement predicates hold."""
        events: list[dict[str, Any]] = [
            _make_event(cand_id, parent_id=None, seq=cand_seq, branch_id=cand_branch),
            _make_event(child_id, parent_id=missing_pid, seq=child_seq, branch_id=child_branch),
        ]
        if has_boundary:
            events.append(
                _make_event(
                    "boundary", parent_id=None, seq=boundary_seq, kind="compaction_boundary"
                )
            )

        qualifies, reason = is_qualifying_parent_candidate(
            events[0], events[1], events, missing_parent_id=missing_pid
        )

        # Oracle evaluation
        c_id_safe = str(cand_id) if cand_id is not None else None
        expected_id_match = bool(
            c_id_safe and c_id_safe != child_id and c_id_safe == str(missing_pid)
        )

        c_br = str(cand_branch) if cand_branch is not None else None
        ch_br = str(child_branch) if child_branch is not None else None
        expected_branch_match = c_br == ch_br

        low_seq = min(cand_seq, child_seq)
        high_seq = max(cand_seq, child_seq)
        intervening_boundary = has_boundary and (low_seq < boundary_seq < high_seq)
        expected_segment_match = not intervening_boundary

        expected_qualifies = expected_id_match and expected_branch_match and expected_segment_match

        assert qualifies == expected_qualifies, (
            f"Oracle mismatch! Got qualifies={qualifies}, expected={expected_qualifies}\n"
            f"cand_id={cand_id!r}, child_id={child_id!r}, missing={missing_pid!r}\n"
            f"cand_branch={cand_branch!r}, child_branch={child_branch!r}\n"
            f"cand_seq={cand_seq}, child_seq={child_seq}, b_seq={boundary_seq}, "
            f"has_b={has_boundary}\n"
            f"reason={reason}"
        )
