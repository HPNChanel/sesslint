"""Unit and integration tests for repair planner core (TASK-018).

Covers:
- Recipe registry: registration, duplicate name rejection, unknown precondition rejection.
- Preconditions engine: built-in predicates, failure reporting, custom registration.
- Repairability classification enforcement: safe-auto, salvage, manual, unknown.
- Deterministic plan planning: step ordering, deduplication, capacity capping at 256.
- Fixture matching: plan_basic, plan_blocked, plan_empty with exact fingerprints.
- Pure dry-run verification: static source code scan and runtime no-write proof.
- Vendor token isolation: zero vendor imports or identifiers.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

from sesslint.canonical import SessionEvent
from sesslint.codes import SL101, SL201, SL203, Repairability, Severity
from sesslint.finding import Finding, SourceRef, make_finding
from sesslint.repair import (
    EMPTY_EVENTS_HASH,
    MAX_STEPS,
    PLAN_VERSION,
    PreconditionContext,
    Recipe,
    clear_registry,
    compute_plan_fingerprint,
    get_recipe,
    list_recipes,
    no_sl203,
    plan,
    recipes_for,
    register_precondition,
    register_recipe,
    repairability_is_safe_auto,
    repairability_is_salvage,
    side_effects_known,
    source_hash_pinned,
)

FIXTURES_REPAIR_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "repair"
REPAIR_SRC_DIR = Path(__file__).resolve().parent.parent.parent / "src" / "sesslint" / "repair"


@pytest.fixture(autouse=True)
def _clean_registry_state() -> Generator[None, None, None]:
    """Ensure clean registry before and after every test."""
    clear_registry()
    yield
    clear_registry()


def _make_finding(
    *,
    code: str = SL101,
    repairability: Repairability | str = Repairability.DETERMINISTIC,
    at_index: int | None = 0,
    fp_suffix: str = "0",
) -> Finding:
    """Helper to create valid test findings."""
    evidence = {"at_index": at_index} if at_index is not None else None
    return make_finding(
        code=code,
        severity=Severity.ERROR,
        repairability=repairability,
        message_template=f"Test finding {code} #{fp_suffix}",
        source=SourceRef(path="session.json", line=1, record_id=f"rec-{fp_suffix}"),
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# 1. Registry & Preconditions Tests
# ---------------------------------------------------------------------------


def test_registry_registration_and_lookup() -> None:
    """Register recipes and lookup by name or finding code."""
    r1 = Recipe(
        name="stub-clean-1",
        handles=(SL101,),
        preconditions=("no_sl203",),
        lossy=False,
        salvage_only=False,
    )
    register_recipe(r1)

    assert get_recipe("stub-clean-1") == r1
    assert get_recipe("non-existent") is None
    assert recipes_for(SL101) == (r1,)
    assert recipes_for(SL201) == ()
    assert list_recipes() == (r1,)


def test_registry_duplicate_name_rejected() -> None:
    """Registering two recipes with the identical name raises ValueError."""
    r1 = Recipe(
        name="duplicate-stub",
        handles=(SL101,),
        preconditions=("no_sl203",),
        lossy=False,
        salvage_only=False,
    )
    register_recipe(r1)

    r2 = Recipe(
        name="duplicate-stub",
        handles=(SL201,),
        preconditions=(),
        lossy=True,
        salvage_only=True,
    )
    with pytest.raises(ValueError, match="Duplicate recipe name"):
        register_recipe(r2)


def test_registry_unknown_precondition_rejected() -> None:
    """Registering a recipe referencing an unknown precondition raises ValueError."""
    r = Recipe(
        name="bad-precondition-stub",
        handles=(SL101,),
        preconditions=("non_existent_precondition",),
        lossy=False,
        salvage_only=False,
    )
    with pytest.raises(ValueError, match="unknown precondition"):
        register_recipe(r)


def test_custom_precondition_registration() -> None:
    """Registering a custom precondition predicate succeeds and evaluates."""
    register_precondition("custom_test_flag", lambda ctx: ctx.profile == "strict")

    r = Recipe(
        name="custom-prec-stub",
        handles=(SL101,),
        preconditions=("custom_test_flag",),
        lossy=False,
        salvage_only=False,
    )
    register_recipe(r)

    f = _make_finding(code=SL101)
    ev = SessionEvent(
        id="e1", parent_id=None, seq=0, ts="2026-09-05T12:00:00Z", actor="user", kind="message"
    )

    p_fail = plan([f], [ev], profile="neutral")
    assert len(p_fail.steps) == 0
    assert p_fail.blocked[0].reason == "precondition-failed:custom_test_flag"

    p_pass = plan([f], [ev], profile="strict")
    assert len(p_pass.steps) == 1
    assert p_pass.steps[0].recipe == "custom-prec-stub"


def test_built_in_predicates() -> None:
    """Verify built-in predicate functions directly."""
    f_clean = _make_finding(code=SL101, repairability=Repairability.DETERMINISTIC)
    f_sl203 = _make_finding(code=SL203, repairability=Repairability.MANUAL)

    ev_safe = SessionEvent(
        id="c1",
        parent_id=None,
        seq=0,
        ts="2026-09-05T12:00:00Z",
        actor="assistant",
        kind="tool_call",
        payload={"side_effects": "none"},
    )
    ev_unsafe = SessionEvent(
        id="c2",
        parent_id=None,
        seq=1,
        ts="2026-09-05T12:00:01Z",
        actor="assistant",
        kind="tool_call",
        payload={"side_effects": "unknown"},
    )

    ctx_clean = PreconditionContext(
        findings=[f_clean],
        events=[ev_safe],
        profile="neutral",
        source_hash="a" * 64,
        finding=f_clean,
    )
    assert no_sl203(ctx_clean) is True
    assert side_effects_known(ctx_clean) is True
    assert repairability_is_safe_auto(ctx_clean) is True
    assert repairability_is_salvage(ctx_clean) is False
    assert source_hash_pinned(ctx_clean) is True

    ctx_loss = PreconditionContext(
        findings=[f_sl203],
        events=[ev_unsafe],
        profile="neutral",
        source_hash="",
        finding=f_sl203,
    )
    assert no_sl203(ctx_loss) is False
    assert side_effects_known(ctx_loss) is False
    assert repairability_is_safe_auto(ctx_loss) is False
    assert source_hash_pinned(ctx_loss) is False


# ---------------------------------------------------------------------------
# 2. Fixture Conformance & Determinism
# ---------------------------------------------------------------------------


def test_basic_plan_fixture() -> None:
    """plan_basic.json matches expected steps and stable fingerprint."""
    fixture_path = FIXTURES_REPAIR_DIR / "plan_basic.json"
    with open(fixture_path, encoding="utf-8") as fh:
        data = json.load(fh)

    register_recipe(
        Recipe(
            name="stub-strip-call",
            handles=(SL101,),
            preconditions=("no_sl203", "repairability_is_safe_auto"),
            lossy=False,
            salvage_only=False,
        )
    )

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

    p = plan(findings, events, profile="neutral")
    expected = data["expected_plan"]

    assert p.fingerprint == expected["fingerprint"]
    assert p.source_hash == expected["source_hash"]
    assert len(p.steps) == len(expected["steps"])
    assert p.to_dict() == expected

    # Re-plan determinism: repeated execution yields exact identical fingerprint
    p2 = plan(findings, events, profile="neutral")
    assert p2.fingerprint == p.fingerprint


def test_blocked_plan_fixture() -> None:
    """plan_blocked.json produces 0 steps and all blocked entries on SL203."""
    fixture_path = FIXTURES_REPAIR_DIR / "plan_blocked.json"
    with open(fixture_path, encoding="utf-8") as fh:
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

    p = plan(findings, events, profile="neutral")
    expected = data["expected_plan"]

    assert p.fingerprint == expected["fingerprint"]
    assert len(p.steps) == 0
    assert len(p.blocked) == 1
    assert p.blocked[0].reason == "SL203-refusal"
    assert p.to_dict() == expected


def test_empty_plan_fixture() -> None:
    """plan_empty.json produces 0 steps, 0 blocked, and stable empty hash."""
    fixture_path = FIXTURES_REPAIR_DIR / "plan_empty.json"
    with open(fixture_path, encoding="utf-8") as fh:
        data = json.load(fh)

    p = plan([], [], profile="neutral")
    expected = data["expected_plan"]

    assert p.source_hash == EMPTY_EVENTS_HASH
    assert p.fingerprint == expected["fingerprint"]
    assert len(p.steps) == 0
    assert len(p.blocked) == 0
    assert p.to_dict() == expected


def test_fingerprint_stability() -> None:
    """Key reordering and serialization round-trip yield identical fingerprint."""
    plan_dict: dict[str, Any] = {
        "version": PLAN_VERSION,
        "source_hash": "abc123",
        "profile": "neutral",
        "steps": [
            {
                "params": {},
                "recipe": "stub-1",
                "seq": 0,
                "target_finding_fp": "fp1",
                "target_index": 1,
            }
        ],
        "blocked": [],
        "loss_accounting": {
            "preview": {
                "discarded-suffix": 0,
                "none": 0,
                "truncated-projection": 0,
            }
        },
    }

    fp1 = compute_plan_fingerprint(plan_dict)

    # Reorder dictionary keys
    reversed_dict = {k: plan_dict[k] for k in reversed(list(plan_dict.keys()))}
    fp2 = compute_plan_fingerprint(reversed_dict)

    assert fp1 == fp2

    # Excludes existing 'fingerprint' key if present
    dict_with_fp = dict(plan_dict)
    dict_with_fp["fingerprint"] = "dummy_ignored_hash"
    assert compute_plan_fingerprint(dict_with_fp) == fp1


# ---------------------------------------------------------------------------
# 3. Planning Rules & Adversarial Scenarios
# ---------------------------------------------------------------------------


def test_first_match_wins() -> None:
    """When multiple recipes handle a code, the registration-order-first match is chosen."""
    register_recipe(
        Recipe(
            name="stub-first",
            handles=(SL101,),
            preconditions=("no_sl203",),
            lossy=False,
            salvage_only=False,
        )
    )
    register_recipe(
        Recipe(
            name="stub-second",
            handles=(SL101,),
            preconditions=("no_sl203",),
            lossy=False,
            salvage_only=False,
        )
    )

    ev = SessionEvent(
        id="e1", parent_id=None, seq=0, ts="2026-09-05T12:00:00Z", actor="user", kind="message"
    )
    f = _make_finding(code=SL101)

    p = plan([f], [ev])
    assert len(p.steps) == 1
    assert p.steps[0].recipe == "stub-first"


def test_cap_overflow() -> None:
    """More than MAX_STEPS (256) plannable findings results in cap-overflow blocked entries."""
    register_recipe(
        Recipe(
            name="stub-cap",
            handles=(SL101,),
            preconditions=("no_sl203",),
            lossy=False,
            salvage_only=False,
        )
    )

    ev = SessionEvent(
        id="e1", parent_id=None, seq=0, ts="2026-09-05T12:00:00Z", actor="user", kind="message"
    )

    # Generate 300 distinct findings
    total_findings = 300
    findings = [
        _make_finding(code=SL101, at_index=0, fp_suffix=str(i)) for i in range(total_findings)
    ]

    p = plan(findings, [ev])
    assert len(p.steps) == MAX_STEPS  # Exactly 256
    assert len(p.blocked) == total_findings - MAX_STEPS  # 44 blocked

    overflow_reasons = {b.reason for b in p.blocked}
    assert overflow_reasons == {"cap-overflow"}


def test_duplicate_finding_fingerprint_deduped() -> None:
    """Findings with identical fingerprints are deduplicated to a single candidate."""
    register_recipe(
        Recipe(
            name="stub-dedupe",
            handles=(SL101,),
            preconditions=("no_sl203",),
            lossy=False,
            salvage_only=False,
        )
    )

    ev = SessionEvent(
        id="e1", parent_id=None, seq=0, ts="2026-09-05T12:00:00Z", actor="user", kind="message"
    )
    f1 = _make_finding(code=SL101, fp_suffix="duplicate")
    f2 = _make_finding(code=SL101, fp_suffix="duplicate")
    assert f1.fingerprint == f2.fingerprint

    p = plan([f1, f2], [ev])
    assert len(p.steps) == 1
    assert len(p.blocked) == 0


def test_target_missing_event_index() -> None:
    """A finding referencing an out-of-bounds target index is blocked as 'target-missing'."""
    register_recipe(
        Recipe(
            name="stub-bounds",
            handles=(SL101,),
            preconditions=("no_sl203",),
            lossy=False,
            salvage_only=False,
        )
    )

    ev = SessionEvent(
        id="e1", parent_id=None, seq=0, ts="2026-09-05T12:00:00Z", actor="user", kind="message"
    )
    # Target index 99 is invalid for 1 event
    f_missing = _make_finding(code=SL101, at_index=99)

    p = plan([f_missing], [ev])
    assert len(p.steps) == 0
    assert len(p.blocked) == 1
    assert p.blocked[0].reason == "target-missing"


def test_manual_and_unknown_repairability_blocked() -> None:
    """Findings marked manual, unsupported, or unknown repairability are blocked."""
    register_recipe(
        Recipe(
            name="stub-all",
            handles=(SL101, SL201),
            preconditions=(),
            lossy=False,
            salvage_only=False,
        )
    )

    ev = SessionEvent(
        id="e1", parent_id=None, seq=0, ts="2026-09-05T12:00:00Z", actor="user", kind="message"
    )
    f_manual = _make_finding(code=SL101, repairability=Repairability.MANUAL, fp_suffix="man")
    f_unsupported = _make_finding(
        code=SL201, repairability=Repairability.UNSUPPORTED, fp_suffix="unsup"
    )
    # Adversarial unknown repairability object
    f_unknown = _make_finding(code=SL201, repairability=Repairability.UNSUPPORTED, fp_suffix="unk")
    object.__setattr__(f_unknown, "repairability", "unknown")

    p = plan([f_manual, f_unsupported, f_unknown], [ev])
    assert len(p.steps) == 0
    assert len(p.blocked) == 3

    reasons = {b.reason for b in p.blocked}
    assert "repairability-manual" in reasons
    assert "repairability-unsupported" in reasons
    assert "repairability-unknown" in reasons


def test_no_recipe_available_blocked() -> None:
    """A finding without any registered recipes is blocked with reason 'no-recipe'."""
    ev = SessionEvent(
        id="e1", parent_id=None, seq=0, ts="2026-09-05T12:00:00Z", actor="user", kind="message"
    )
    f = _make_finding(code=SL101)

    p = plan([f], [ev])
    assert len(p.steps) == 0
    assert len(p.blocked) == 1
    assert p.blocked[0].reason == "no-recipe"


# ---------------------------------------------------------------------------
# 4. Pure Dry-Run Proofs & Isolation
# ---------------------------------------------------------------------------


def test_no_writes_static_audit() -> None:
    """Static AST/regex audit: src/sesslint/repair contains zero file-writing primitives."""
    # All planning modules in src/sesslint/repair must have zero file-writing primitives.
    # executor.py (M5) is the sole authorized mutator in SessLint.
    py_files = [p for p in REPAIR_SRC_DIR.glob("*.py") if p.name != "executor.py"]
    assert py_files, f"No python source files found in {REPAIR_SRC_DIR}"

    write_patterns = [
        re.compile(r"\bopen\s*\([^)]*['\"][wWaA\+]"),
        re.compile(r"\bos\.(replace|rename|remove|unlink|rmdir|mkdir|makedirs)\b"),
        re.compile(r"\bshutil\b"),
        re.compile(r"\.write_(text|bytes)\s*\("),
    ]

    for py_file in py_files:
        content = py_file.read_text(encoding="utf-8")
        for pattern in write_patterns:
            match = pattern.search(content)
            assert match is None, f"Forbidden write primitive '{match.group(0)}' found in {py_file}"


def test_no_writes_runtime_read_only_proof() -> None:
    """Runtime execution proof: running planner with mocked writes succeeds with 0 disk touches."""
    register_recipe(
        Recipe(
            name="stub-safe",
            handles=(SL101,),
            preconditions=("no_sl203",),
            lossy=False,
            salvage_only=False,
        )
    )
    ev = SessionEvent(
        id="e1", parent_id=None, seq=0, ts="2026-09-05T12:00:00Z", actor="user", kind="message"
    )
    f = _make_finding(code=SL101)

    # Monkeypatch builtins.open to disallow write modes
    original_open = open

    def guarded_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if any(w in mode for w in ("w", "a", "+", "x")):
            raise PermissionError(f"Attempted disk write to {file} in mode {mode}")
        return original_open(file, mode, *args, **kwargs)

    import builtins

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(builtins, "open", guarded_open)
        p = plan([f], [ev])
        assert len(p.steps) == 1


def test_vendor_free() -> None:
    """Module must be strictly vendor-free with no vendor imports or keywords."""
    py_files = list(REPAIR_SRC_DIR.glob("*.py"))
    forbidden_patterns = [
        re.compile(r"\bclaude\b", re.IGNORECASE),
        re.compile(r"\bopenai\b", re.IGNORECASE),
        re.compile(r"\banthropic\b", re.IGNORECASE),
        re.compile(r"\bchatgpt\b", re.IGNORECASE),
        re.compile(r"\btoolUse\b"),
        re.compile(r"\bcall_id\b"),
    ]

    for py_file in py_files:
        content = py_file.read_text(encoding="utf-8")
        for pattern in forbidden_patterns:
            match = pattern.search(content)
            assert match is None, f"Forbidden vendor keyword '{match.group(0)}' found in {py_file}"


def test_perf_10k_findings() -> None:
    """Adversarial performance: planning over 10,000 findings finishes well under 2.0s."""
    register_recipe(
        Recipe(
            name="stub-perf",
            handles=(SL101,),
            preconditions=(),
            lossy=False,
            salvage_only=False,
        )
    )
    ev = SessionEvent(
        id="e1", parent_id=None, seq=0, ts="2026-09-05T12:00:00Z", actor="user", kind="message"
    )

    count = 10_000
    findings = [_make_finding(code=SL101, at_index=0, fp_suffix=str(i)) for i in range(count)]

    start = time.perf_counter()
    p = plan(findings, [ev])
    duration = time.perf_counter() - start

    assert len(p.steps) == MAX_STEPS
    assert len(p.blocked) == count - MAX_STEPS
    assert duration < 2.0, f"Planner exceeded 2.0s threshold: took {duration:.3f}s"
