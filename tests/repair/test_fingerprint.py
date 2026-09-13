"""Tests for repair plan fingerprinting and policy binding (P0-03, TASK-018)."""

from __future__ import annotations

from pathlib import Path

import pytest

from sesslint.repair.errors import PolicyMismatch
from sesslint.repair.executor import execute, load_plan
from sesslint.repair.fingerprint import compute_plan_fingerprint


def test_plan_fingerprint_determinism() -> None:
    """Same plan content produces identical 64-char SHA-256 fingerprint regardless of key order."""
    plan_a = {
        "version": "sesslint.plan/v1",
        "source_hash": "a" * 64,
        "profile": "neutral",
        "steps": [],
        "blocked": [],
        "loss_accounting": {"preview": {"none": 0}, "total_lost": 0, "total_kept": 5},
    }
    plan_b = {
        "loss_accounting": {"total_kept": 5, "total_lost": 0, "preview": {"none": 0}},
        "profile": "neutral",
        "blocked": [],
        "steps": [],
        "source_hash": "a" * 64,
        "version": "sesslint.plan/v1",
    }
    fp_a = compute_plan_fingerprint(plan_a)
    fp_b = compute_plan_fingerprint(plan_b)

    assert fp_a == fp_b
    assert len(fp_a) == 64


def test_plan_fingerprint_policy_binding() -> None:
    """Fingerprint domain binds policy: changing policy changes the digest (P0-03)."""
    base_plan = {
        "version": "sesslint.plan/v1",
        "source_hash": "b" * 64,
        "profile": "neutral",
        "steps": [],
        "blocked": [],
        "loss_accounting": {"preview": {"none": 0}, "total_lost": 0, "total_kept": 10},
    }

    plan_conservative = dict(base_plan, policy="conservative")
    plan_salvage = dict(base_plan, policy="salvage")

    fp_cons = compute_plan_fingerprint(plan_conservative)
    fp_salv = compute_plan_fingerprint(plan_salvage)

    # Digests must be strictly distinct when policy changes
    assert fp_cons != fp_salv

    # Passing policy keyword argument binds policy when omitted from dict
    fp_keyword_salv = compute_plan_fingerprint(base_plan, policy="salvage")
    assert fp_keyword_salv == fp_salv


def test_plan_fingerprint_excludes_fingerprint_key() -> None:
    """The 'fingerprint' key is strictly excluded to prevent self-referential hashing."""
    plan_without_fp = {
        "version": "sesslint.plan/v1",
        "source_hash": "c" * 64,
        "profile": "neutral",
        "steps": [],
        "blocked": [],
        "loss_accounting": {"preview": {"none": 0}, "total_lost": 0, "total_kept": 5},
    }
    fp = compute_plan_fingerprint(plan_without_fp)
    plan_with_fp = dict(plan_without_fp, fingerprint=fp)

    assert compute_plan_fingerprint(plan_with_fp) == fp


def test_load_plan_refuses_salvage_under_conservative_policy() -> None:
    """load_plan refuses salvage steps or declared loss under conservative policy (P0-03)."""
    crafted_salvage_plan = {
        "version": "sesslint.plan/v1",
        "source_hash": "d" * 64,
        "profile": "neutral",
        "steps": [
            {
                "seq": 0,
                "recipe": "unresolvable-branch-amputate",
                "target_finding_fp": "f001",
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
        "policy": "salvage",
    }

    # Loading with policy="conservative" must raise PolicyMismatch
    with pytest.raises(PolicyMismatch, match="requires 'salvage' policy"):
        load_plan(crafted_salvage_plan, policy="conservative")

    # Loading with policy="salvage" succeeds
    plan_obj = load_plan(crafted_salvage_plan, policy="salvage")
    assert plan_obj.policy == "salvage"


def test_execute_refuses_salvage_plan_under_conservative_policy(tmp_path: Path) -> None:
    """execute refuses any salvage plan under conservative policy (P0-03)."""
    import hashlib

    source_file = tmp_path / "test_session.jsonl"
    header = (
        '{"schema_version":"sesslint.session/v1","session_id":"s1",'
        '"created_at":"2026-09-05T12:00:00Z"}\n'
    )
    event = (
        '{"id":"e1","parent_id":null,"seq":0,"ts":"2026-09-05T12:00:00Z",'
        '"actor":"user","kind":"message","payload":{"content":"hi"}}\n'
    )
    source_file.write_text(header + event, encoding="utf-8")
    source_hash = hashlib.sha256(source_file.read_bytes()).hexdigest()

    crafted_plan_dict = {
        "version": "sesslint.plan/v1",
        "source_hash": source_hash,
        "profile": "neutral",
        "steps": [
            {
                "seq": 0,
                "recipe": "unresolvable-branch-amputate",
                "target_finding_fp": "f001",
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
            "total_kept": 0,
        },
    }
    plan = load_plan(crafted_plan_dict)
    plan_dict = plan.to_dict()
    plan_dict["fingerprint"] = compute_plan_fingerprint(plan_dict)
    plan_obj = load_plan(plan_dict)

    out_file = tmp_path / "out.jsonl"
    with pytest.raises(PolicyMismatch, match="requires 'salvage' policy"):
        execute(
            source_path=source_file,
            plan=plan_obj,
            output_path=out_file,
            policy="conservative",
        )
