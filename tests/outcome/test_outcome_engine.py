"""OutcomeGuard reconciliation acceptance tests (OutcomeGuard spec AT-06…AT-48)."""

from __future__ import annotations

import json
import random
import re
from pathlib import Path
from typing import Any

import pytest

from sesslint.outcome import (
    REASONS,
    Contract,
    EvaluationError,
    OutcomeReport,
    Snapshot,
    evaluate,
    load_contract,
    load_snapshot,
    session_dimension,
    verify_outcome,
)
from sesslint.outcome.snapshot import EMPTY_NESTED, NonScalar
from tests.outcome.helpers import (
    DEADLINE,
    LATER,
    ORDERS,
    ROOT,
    T0,
    at,
    cond,
    contract,
    digit_limit,
    due,
    item,
    run,
    snapshot,
)
from tests.utils.schema import assert_schema

EXISTS = {"id": "exists", "type": "exists"}
ONE = {"id": "one", "type": "count", "min": 1, "max": 1}
ON_TIME = {"id": "on-time", "type": "on_time", "basis": "target_time", "field": "done_at"}


def _src(*ids: str, **fields: Any) -> list[dict[str, Any]]:
    return [{"id": i, "at": T0, **fields} for i in ids]


def _reasons_in(doc: dict[str, Any]) -> set[str]:
    found = set(doc["outcome_reasons"])

    def walk(conditions: list[dict[str, Any]]) -> None:
        for c in conditions:
            found.add(c["reason"])
            walk(c.get("branches", []))

    for entry in doc["items"]:
        found.add(entry["reason"])
        walk(entry["conditions"])
    return found


def test_orders_fixture_end_to_end_against_golden() -> None:
    report = verify_outcome(
        ORDERS / "contract.json",
        load_snapshot(ORDERS / "source.csv", role="source", completeness="complete"),
        ORDERS / "target_complete.json",
    )
    doc = report.to_dict()
    assert_schema(doc, "sesslint.outcome-report.v1.json")
    doc.pop("tool_version")
    golden = json.loads((ORDERS / "expected_report.json").read_text(encoding="utf-8"))
    assert doc == golden
    statuses = {tuple(e["key"]): e["status"] for e in doc["items"]}
    assert statuses == {
        ("0001",): "VERIFIED",
        ("0002",): "VIOLATED",
        ("0003",): "NOT_APPLICABLE",
        ("0004",): "VIOLATED",
        ("0005",): "VIOLATED",
        ("0006",): "PENDING",
        ("0007",): "VERIFIED",
        ("0008",): "VIOLATED",
    }
    assert report.exit_code == 1


def test_at06_missing_and_duplicate_per_id_not_totals(tmp_path: Path) -> None:
    """Three items, three records: totals match, but one id is missing and one doubled."""
    report = run(
        tmp_path,
        contract(EXISTS, ONE),
        _src("a", "b", "c"),
        [{"ref": "a"}, {"ref": "a"}, {"ref": "b"}],
    )
    assert cond(item(report, "a"), "one") == ("VIOLATED", "too_many")
    assert cond(item(report, "c"), "exists") == ("VIOLATED", "missing")
    assert item(report, "b")["status"] == "VERIFIED"
    assert report.outcome == "VIOLATED"


def test_at07_ineligible_items_are_not_applicable(tmp_path: Path) -> None:
    spec = contract(EXISTS, eligibility=[{"field": "kind", "op": "in", "values": ["paid"]}])
    report = run(
        tmp_path, spec, [{"id": "a", "kind": "free"}, {"id": "b", "kind": "paid"}], [{"ref": "b"}]
    )
    assert item(report, "a")["status"] == "NOT_APPLICABLE"
    assert item(report, "a")["reason"] == "not_eligible"
    assert report.to_dict()["coverage"]["excluded_items"] == 1


def test_eligibility_on_missing_field_is_undecidable(tmp_path: Path) -> None:
    spec = contract(EXISTS, eligibility=[{"field": "amount", "op": "gt", "value": 1}])
    report = run(tmp_path, spec, [{"id": "a"}], [{"ref": "a"}])
    assert item(report, "a")["reason"] == "eligibility_undecidable"


def test_at08_before_deadline_is_pending(tmp_path: Path) -> None:
    report = run(
        tmp_path,
        contract(EXISTS, due=due()),
        _src("a"),
        [],
        as_of="2026-10-20T08:30:00Z",
        source_meta={"observed_at": "2026-10-20T08:30:00Z"},
        target_meta={"observed_at": "2026-10-20T08:30:00Z"},
    )
    assert cond(item(report, "a"), "exists") == ("PENDING", "awaiting_due")
    assert report.outcome == "PENDING"


def test_at09_missing_after_deadline_in_complete_target_is_violated(tmp_path: Path) -> None:
    report = run(tmp_path, contract(EXISTS, due=due()), _src("a"), [])
    assert cond(item(report, "a"), "exists") == ("VIOLATED", "missing")


@pytest.mark.parametrize(
    ("meta", "reason"),
    [
        ({"completeness": "unavailable"}, "target_unavailable"),
        ({"completeness": "partial"}, "target_incomplete"),
        ({"completeness": None}, "target_incomplete"),
        ({"observed_at": None}, "target_observed_at_unknown"),
        ({"observed_at": "2026-10-20T08:30:00Z"}, "target_stale"),
    ],
)
def test_at10_11_22_absence_needs_complete_current_target(
    tmp_path: Path, meta: dict[str, Any], reason: str
) -> None:
    report = run(tmp_path, contract(EXISTS, due=due()), _src("a"), [], target_meta=meta)
    assert cond(item(report, "a"), "exists") == ("INCONCLUSIVE", reason)
    assert report.outcome == "INCONCLUSIVE"


def test_unkeyed_target_rows_block_absence(tmp_path: Path) -> None:
    report = run(tmp_path, contract(EXISTS), _src("a"), [{"ref": None}, {"other": 1}])
    assert cond(item(report, "a"), "exists") == ("INCONCLUSIVE", "target_unkeyed_rows")
    assert report.to_dict()["coverage"]["unkeyed_target_rows"] == 2


def test_at12_late_arrival_exists_but_on_time_violated(tmp_path: Path) -> None:
    spec = contract(EXISTS, ON_TIME, due=due())
    target = [{"ref": "a", "done_at": "2026-10-20T09:30:00Z"}]
    report = run(tmp_path, spec, _src("a"), target)
    entry = item(report, "a")
    assert cond(entry, "exists") == ("VERIFIED", "present")
    assert cond(entry, "on-time") == ("VIOLATED", "late")
    late = next(c for c in entry["conditions"] if c["id"] == "on-time")
    assert late["detail"]["late_by_seconds"] == 1800
    partial = run(tmp_path, spec, _src("a"), target, target_meta={"completeness": "partial"})
    assert cond(item(partial, "a"), "on-time") == ("INCONCLUSIVE", "late_unconfirmed")


def test_on_time_uses_earliest_valid_completion(tmp_path: Path) -> None:
    spec = contract(EXISTS, ON_TIME, due=due())
    target = [
        {"ref": "a", "done_at": "2026-10-20T10:00:00Z"},
        {"ref": "a", "done_at": "2026-10-20T08:10:00Z"},
        {"ref": "b", "done_at": "2026-10-20T08:10:00"},
    ]
    report = run(tmp_path, spec, _src("a", "b"), target)
    assert cond(item(report, "a"), "on-time") == ("VERIFIED", "completed_on_time")
    assert cond(item(report, "b"), "on-time") == ("INCONCLUSIVE", "completion_time_unusable")


@pytest.mark.parametrize(
    ("observed", "expected"),
    [
        ("2026-10-20T08:59:00Z", ("VERIFIED", "observed_on_time")),
        ("2026-10-20T09:01:00Z", ("INCONCLUSIVE", "first_seen_after_deadline")),
    ],
)
def test_at46_47_observation_basis(
    tmp_path: Path, observed: str, expected: tuple[str, str]
) -> None:
    spec = contract(EXISTS, {"id": "seen", "type": "on_time", "basis": "observation"}, due=due())
    report = run(
        tmp_path,
        spec,
        _src("a"),
        [{"ref": "a"}],
        as_of=observed,
        source_meta={"observed_at": observed},
        target_meta={"observed_at": observed},
    )
    assert cond(item(report, "a"), "seen") == expected


def test_at13_17_keys_match_exactly(tmp_path: Path) -> None:
    report = run(
        tmp_path,
        contract(EXISTS),
        _src("0001", "A1", "x"),
        [{"ref": "1"}, {"ref": "a1"}, {"ref": "x "}],
    )
    for key in ("0001", "A1", "x"):
        assert cond(item(report, key), "exists") == ("VIOLATED", "missing")
    assert len(report.to_dict()["unmatched_target_keys"]) == 3


def test_integer_and_string_keys_compare_as_text(tmp_path: Path) -> None:
    report = run(tmp_path, contract(EXISTS), [{"id": 7}], [{"ref": "7"}])
    assert item(report, "7")["status"] == "VERIFIED"


@pytest.mark.parametrize("bad", [True, 1.5, {"x": 1}, ""])
def test_invalid_keys_are_inconclusive_not_dropped(tmp_path: Path, bad: Any) -> None:
    report = run(tmp_path, contract(EXISTS), [{"id": bad}], [])
    entry = report.to_dict()["items"][0]
    assert entry["key"] is None
    assert entry["status"] == "INCONCLUSIVE"
    assert entry["reason"] in {"key_missing", "key_invalid"}


def test_at14_composite_namespaced_keys(tmp_path: Path) -> None:
    spec = contract(EXISTS, key={"source": ["tenant", "id"], "target": ["org", "ref"]})
    source = [{"tenant": "t1", "id": "1"}, {"tenant": "t2", "id": "1"}]
    report = run(tmp_path, spec, source, [{"org": "t1", "ref": "1"}])
    assert item(report, "t1", "1")["status"] == "VERIFIED"
    assert cond(item(report, "t2", "1"), "exists") == ("VIOLATED", "missing")


def test_at15_identical_retries_merge_and_conflicts_do_not(tmp_path: Path) -> None:
    spec = contract(EXISTS, {"id": "eq", "type": "equals", "field": "sku", "source_field": "sku"})
    source = [
        {"id": "a", "sku": "s1", "note": "first"},
        {"id": "a", "sku": "s1", "note": "retry"},
        {"id": "b", "sku": "s1"},
        {"id": "b", "sku": "s2"},
    ]
    report = run(tmp_path, spec, source, [{"ref": "a", "sku": "s1"}, {"ref": "b", "sku": "s1"}])
    merged = item(report, "a")
    assert (merged["status"], merged["source_rows"]) == ("VERIFIED", 2)
    assert item(report, "b")["reason"] == "source_conflict"
    assert report.to_dict()["coverage"]["retried_items"] == 2


def test_at16_route_is_separate_from_existence(tmp_path: Path) -> None:
    route = {
        "id": "route",
        "type": "route",
        "field": "queue",
        "values": ["eu"],
        "when": [{"field": "region", "op": "eq", "value": "EU"}],
    }
    source = [{"id": "a", "region": "EU"}, {"id": "b", "region": "US"}, {"id": "c"}]
    target = [{"ref": "a", "queue": "us"}, {"ref": "b", "queue": "us"}, {"ref": "c", "queue": "eu"}]
    report = run(tmp_path, contract(EXISTS, route), source, target)
    assert cond(item(report, "a"), "exists") == ("VERIFIED", "present")
    assert cond(item(report, "a"), "route") == ("VIOLATED", "wrong_route")
    assert cond(item(report, "b"), "route") == ("NOT_APPLICABLE", "route_not_applicable")
    assert cond(item(report, "c"), "route") == ("INCONCLUSIVE", "route_undecidable")


def test_at18_19_session_integrity_is_a_separate_dimension(tmp_path: Path) -> None:
    session = ROOT / "fixtures" / "sessions" / "minimal-valid.jsonl"
    report = OutcomeReport(
        run(tmp_path, contract(EXISTS), _src("a"), []).evaluation,
        session_dimension(session),
    )
    dims = report.to_dict()["dimensions"]
    assert dims["session_integrity"]["status"] in {"no_findings", "findings"}
    assert dims["session_integrity"]["link"] == "user_asserted"
    assert dims["outcome_verification"]["status"] == "VIOLATED"
    assert dims["monitoring_health"]["status"] == "not_configured"
    assert dims["incident_handling"]["status"] == "not_tracked"
    assert session_dimension(tmp_path / "absent.jsonl")["status"] == "unreadable"
    assert session_dimension(None) == {"status": "not_linked"}


def test_at21_unproven_source_coverage_never_verifies(tmp_path: Path) -> None:
    report = run(
        tmp_path,
        contract(EXISTS),
        _src("a"),
        [{"ref": "a"}],
        source_meta={"completeness": "partial"},
    )
    assert item(report, "a")["status"] == "VERIFIED"
    assert report.outcome == "INCONCLUSIVE"
    assert "source_coverage_unproven" in report.to_dict()["outcome_reasons"]
    full = run(tmp_path, contract(EXISTS), _src("a"), [{"ref": "a"}])
    assert (full.outcome, full.exit_code) == ("VERIFIED", 0)


def test_at23_mapping_problems_surface(tmp_path: Path) -> None:
    spec = contract(EXISTS, {"id": "st", "type": "required", "field": "status"})
    report = run(tmp_path, spec, _src("a"), [{"ref": "a", "state": "done"}])
    assert cond(item(report, "a"), "st") == ("INCONCLUSIVE", "field_not_in_snapshot")
    wrong_key = run(tmp_path, contract(EXISTS), _src("a"), [{"reference": "a"}])
    assert "target_key_field_absent" in wrong_key.to_dict()["outcome_reasons"]
    assert wrong_key.outcome != "VERIFIED"


def test_field_conditions_and_typing(tmp_path: Path) -> None:
    spec = contract(
        EXISTS,
        {"id": "req", "type": "required", "field": "status"},
        {"id": "kind", "type": "type", "field": "n", "kind": "integer"},
        {"id": "range", "type": "range", "field": "n", "min": 0, "max": 10},
        {
            "id": "one",
            "type": "one_of",
            "field": "status",
            "values": ["done"],
            "normalize": ["casefold"],
        },
    )
    target = [
        {"ref": "ok", "status": "DONE", "n": 5},
        {"ref": "str", "status": "done", "n": "5"},
        {"ref": "big", "status": "", "n": 11},
        {"ref": "bool", "status": None, "n": True},
    ]
    report = run(tmp_path, spec, _src("ok", "str", "big", "bool"), target)
    assert item(report, "ok")["status"] == "VERIFIED"
    assert cond(item(report, "str"), "kind") == ("VIOLATED", "type_mismatch")
    assert cond(item(report, "str"), "range") == ("VIOLATED", "not_a_number")
    assert cond(item(report, "big"), "range") == ("VIOLATED", "out_of_range")
    assert cond(item(report, "big"), "req") == ("VIOLATED", "field_empty")
    assert cond(item(report, "bool"), "req") == ("VIOLATED", "field_null")
    assert cond(item(report, "bool"), "kind") == ("VIOLATED", "type_mismatch")


def test_csv_values_coerce_strictly(tmp_path: Path) -> None:
    spec = contract(EXISTS, {"id": "range", "type": "range", "field": "n", "min": 0, "max": 10})
    src = tmp_path / "s.csv"
    src.write_bytes(b"id\na\nb\n")
    tgt = tmp_path / "t.csv"
    tgt.write_bytes(b"ref,n\na,5\nb,five\n")
    evaluation = evaluate(
        spec,
        load_snapshot(src, role="source", completeness="complete"),
        load_snapshot(tgt, role="target", completeness="complete", observed_at=at(LATER)),
        as_of=at(LATER),
    )
    report = OutcomeReport(evaluation, all_conditions=True)
    assert cond(item(report, "a"), "range") == ("VERIFIED", "in_range")
    assert cond(item(report, "b"), "range") == ("VIOLATED", "not_a_number")


def test_any_of_advisory_and_disabled(tmp_path: Path) -> None:
    spec = contract(
        EXISTS,
        {
            "id": "either",
            "type": "any_of",
            "conditions": [
                {"id": "x", "type": "required", "field": "x"},
                {"id": "y", "type": "required", "field": "y"},
            ],
        },
        {"id": "adv", "type": "required", "field": "z", "advisory": True},
        {"id": "off", "type": "required", "field": "w", "disabled": "pending field rollout"},
    )
    report = run(
        tmp_path, spec, _src("a"), [{"ref": "a", "y": "1", "x": None, "z": None, "w": None}]
    )
    entry = item(report, "a")
    assert cond(entry, "either") == ("VERIFIED", "any_branch_verified")
    assert cond(entry, "adv") == ("VIOLATED", "field_null")
    assert cond(entry, "off") == ("NOT_EVALUATED", "disabled")
    assert entry["status"] == "VERIFIED"


def test_at41_violations_and_inconclusive_items_are_both_reported(tmp_path: Path) -> None:
    spec = contract(EXISTS, due=due())
    report = run(tmp_path, spec, [{"id": "a", "at": T0}, {"id": "b", "at": "not-a-time"}], [])
    counts = report.to_dict()["coverage"]["counts"]
    assert (counts["VIOLATED"], counts["INCONCLUSIVE"]) == (1, 1)
    assert report.outcome == "VIOLATED"
    human = report.render_human()
    assert "VIOLATED" in human and "INCONCLUSIVE" in human


def test_at42_naive_source_time_is_inconclusive(tmp_path: Path) -> None:
    report = run(
        tmp_path, contract(EXISTS, due=due()), [{"id": "a", "at": "2026-10-20T08:00:00"}], []
    )
    assert cond(item(report, "a"), "exists") == ("INCONCLUSIVE", "due_unknown")


def test_at45_run_status_is_not_the_outcome(tmp_path: Path) -> None:
    report = run(tmp_path, contract(EXISTS), _src("a"), [])
    doc = report.to_dict()
    assert (doc["run_status"], doc["outcome"], report.exit_code) == ("completed", "VIOLATED", 1)


def test_empty_or_unavailable_source(tmp_path: Path) -> None:
    empty = run(tmp_path, contract(EXISTS), [], [])
    assert (empty.outcome, empty.to_dict()["outcome_reasons"][0]) == (
        "NOT_EVALUATED",
        "no_source_items",
    )
    gone = run(tmp_path, contract(EXISTS), [], [], source_meta={"completeness": "unavailable"})
    assert (gone.outcome, gone.to_dict()["outcome_reasons"][0]) == (
        "INCONCLUSIVE",
        "source_unavailable",
    )


def test_evaluation_instant_is_never_the_wall_clock(tmp_path: Path) -> None:
    src = snapshot(tmp_path, "source", _src("a"))
    tgt = snapshot(tmp_path, "target", [], observed_at=None)
    with pytest.raises(EvaluationError, match="instant is required"):
        verify_outcome(contract(EXISTS), src, tgt)
    later = snapshot(tmp_path, "target", [], observed_at=LATER)
    with pytest.raises(EvaluationError, match="precedes"):
        evaluate(contract(EXISTS), src, later, as_of=at(DEADLINE))


def test_at38_deterministic_regardless_of_record_order(tmp_path: Path) -> None:
    spec = load_contract(ORDERS / "contract.json")
    source = load_snapshot(ORDERS / "source.csv", role="source", completeness="complete")
    target = load_snapshot(ORDERS / "target_complete.json", role="target")
    first = OutcomeReport(evaluate(spec, source, target, as_of=at(LATER)))
    assert (
        first.to_json() == OutcomeReport(evaluate(spec, source, target, as_of=at(LATER))).to_json()
    )
    # Shuffle the file's own records: loaded values hold exact Decimal numbers.
    records = json.loads((ORDERS / "target_complete.json").read_text(encoding="utf-8"))["records"]
    assert len(records) == len(target.records)
    random.Random(7).shuffle(records)
    path = tmp_path / "shuffled.jsonl"
    path.write_bytes("".join(json.dumps(r) + "\n" for r in records).encode("utf-8"))
    shuffled = load_snapshot(path, role="target", completeness="complete", observed_at=at(LATER))
    second = OutcomeReport(evaluate(spec, source, shuffled, as_of=at(LATER)))
    assert first.to_dict()["items"] == second.to_dict()["items"]
    assert first.outcome == second.outcome


def test_hash_keys_hide_plain_keys(tmp_path: Path) -> None:
    report = run(tmp_path, contract(EXISTS), _src("secret-order-42"), [{"ref": "other-99"}])
    hashed = OutcomeReport(report.evaluation, hash_keys=True)
    text = hashed.to_json() + hashed.render_human()
    assert "secret-order-42" not in text and "other-99" not in text
    assert re.search(r"sha256:[0-9a-f]{16}", text)
    assert hashed.to_dict()["key_display"] == "sha256"
    assert any("pseudonym" in line.lower() for line in hashed.to_dict()["limitations"])


def test_reports_are_content_free(tmp_path: Path) -> None:
    spec = contract(EXISTS, {"id": "st", "type": "one_of", "field": "status", "values": ["ok"]})
    payload = {"ref": "a", "status": "PAYLOAD-VALUE-xyz", "secret": "token-SHOULD-NOT-LEAK"}
    report = run(tmp_path, spec, [{"id": "a", "note": "SOURCE-PAYLOAD-abc"}], [payload])
    text = report.to_json() + report.render_human()
    for leaked in ("PAYLOAD-VALUE-xyz", "token-SHOULD-NOT-LEAK", "SOURCE-PAYLOAD-abc"):
        assert leaked not in text


def test_demo_snapshots_are_flagged(tmp_path: Path) -> None:
    report = run(tmp_path, contract(EXISTS), _src("a"), [{"ref": "a"}], target_meta={"demo": True})
    assert report.to_dict()["demo"] is True
    assert "DEMO DATA" in report.render_human()


def test_every_emitted_reason_is_documented(tmp_path: Path) -> None:
    report = verify_outcome(
        ORDERS / "contract.json",
        ORDERS / "source.csv",
        load_snapshot(ORDERS / "target.jsonl", role="target", completeness="partial"),
        as_of=at(LATER),
    )
    assert _reasons_in(report.to_dict()) <= set(REASONS)
    doc = (ROOT / "docs" / "OUTCOME.md").read_text(encoding="utf-8")
    missing = sorted(code for code in REASONS if f"`{code}`" not in doc)
    assert not missing, f"docs/OUTCOME.md lacks reason codes {missing}"


def test_unevaluated_items_never_roll_up_to_verified(tmp_path: Path) -> None:
    """Review regression: NOT_EVALUATED must not hide behind VERIFIED items."""
    spec = contract({"id": "st", "type": "required", "field": "x"})
    report = run(tmp_path, spec, _src("a", "b"), [{"ref": "a", "x": "1"}])
    assert item(report, "a")["status"] == "VERIFIED"
    assert item(report, "b")["status"] == "NOT_EVALUATED"
    assert report.outcome == "INCONCLUSIVE"
    assert report.to_dict()["outcome_reasons"][0] == "some_items_not_evaluated"
    assert report.exit_code == 1


def test_extreme_numbers_and_times_do_not_crash(tmp_path: Path) -> None:
    spec = contract(
        EXISTS,
        {"id": "range", "type": "range", "field": "n", "max": 50},
        due=due(7200),
        eligibility=[{"field": "size", "op": "lt", "value": 10**400}],
    )
    source = [
        {"id": "a", "at": T0, "size": 10**400 - 1},
        {"id": "b", "at": "9999-12-31T23:30:00Z", "size": 1},
        {"id": "c", "at": "0001-01-01T00:00:00+05:00", "size": 1},
    ]
    target = [{"ref": "a", "n": 10**400}]
    report = run(tmp_path, spec, source, target)
    assert cond(item(report, "a"), "range") == ("VIOLATED", "out_of_range")
    assert cond(item(report, "b"), "exists") == ("INCONCLUSIVE", "due_unknown")
    assert cond(item(report, "c"), "exists") == ("INCONCLUSIVE", "due_unknown")


def test_equals_compares_json_numbers_numerically(tmp_path: Path) -> None:
    spec = contract(EXISTS, {"id": "eq", "type": "equals", "field": "amt", "source_field": "amt"})
    src = tmp_path / "s.csv"
    src.write_bytes(b"id,amt\na,12.50\nb,0012\nc,7\n")
    tgt = tmp_path / "t.json"
    tgt.write_bytes(
        b'[{"ref": "a", "amt": 12.5}, {"ref": "b", "amt": "12"}, {"ref": "c", "amt": 8}]'
    )
    report = OutcomeReport(
        evaluate(
            spec,
            load_snapshot(src, role="source", completeness="complete"),
            load_snapshot(tgt, role="target", completeness="complete", observed_at=at(LATER)),
            as_of=at(LATER),
        ),
        all_conditions=True,
    )
    assert cond(item(report, "a"), "eq") == ("VERIFIED", "values_match")
    assert cond(item(report, "b"), "eq") == ("VIOLATED", "values_differ")
    assert cond(item(report, "c"), "eq") == ("VIOLATED", "values_differ")


def test_hashed_output_order_does_not_follow_plain_keys(tmp_path: Path) -> None:
    ids = [f"k{i:03d}" for i in range(40)]
    report = run(tmp_path, contract(EXISTS), _src(*ids), [{"ref": f"u{i}"} for i in range(40)])
    hashed = OutcomeReport(report.evaluation, hash_keys=True).to_dict()
    keys = [entry["key"] for entry in hashed["items"]]
    assert keys == sorted(keys)
    assert hashed["unmatched_target_keys"] == sorted(hashed["unmatched_target_keys"])


def test_default_detail_lists_only_non_passing_conditions(tmp_path: Path) -> None:
    spec = contract(EXISTS, {"id": "adv", "type": "required", "field": "z", "advisory": True})
    lean = OutcomeReport(
        run(tmp_path, spec, _src("a", "b"), [{"ref": "a", "z": "1"}, {"ref": "b"}]).evaluation
    )
    doc = lean.to_dict()
    assert doc["condition_detail"] == "non_passing"
    by_key = {tuple(e["key"]): e for e in doc["items"]}
    assert by_key[("a",)]["conditions"] == []
    assert [c["id"] for c in by_key[("b",)]["conditions"]] == ["adv"]
    assert doc["condition_summary"]["exists"]["VERIFIED"] == 2
    assert doc["condition_summary"]["adv"]["VIOLATED"] == 1
    assert_schema(doc, "sesslint.outcome-report.v1.json")


# Review regressions before 0.5.0: presence, exact numbers, keyless rows, timeliness.


def _csv(tmp_path: Path, role: str, text: str) -> Snapshot:
    path = tmp_path / f"{role}.csv"
    path.write_bytes(text.encode("utf-8"))
    return load_snapshot(path, role=role, completeness="complete", observed_at=at(LATER))


def _verbatim(tmp_path: Path, role: str, records: str) -> Snapshot:
    """A complete envelope written as typed, so number literals reach the reader unchanged."""
    path = tmp_path / f"{role}.json"
    path.write_bytes(
        (
            '{"schema_version": "sesslint.snapshot/v1", "completeness": "complete", '
            f'"observed_at": "{LATER}", "records": {records}}}'
        ).encode()
    )
    return load_snapshot(path, role=role)


def _report(spec: Contract, source: Snapshot, target: Snapshot) -> OutcomeReport:
    return OutcomeReport(evaluate(spec, source, target, as_of=at(LATER)), all_conditions=True)


@pytest.mark.parametrize("op", ["present", "absent"])
def test_presence_of_an_unknown_field_is_undecidable(tmp_path: Path, op: str) -> None:
    """A renamed or misspelled field never reads as "absent" (RULE-08, REC-07)."""
    source = _src("a", tier="gold", region="EU")
    target = [{"ref": "a", "queue": "vip"}]
    route = {
        "id": "route",
        "type": "route",
        "field": "queue",
        "values": ["vip"],
        "when": [{"field": "tierr", "op": op}],
    }
    report = run(tmp_path, contract(EXISTS, route), source, target)
    assert cond(item(report, "a"), "route") == ("INCONCLUSIVE", "route_undecidable")
    assert report.outcome == "INCONCLUSIVE"
    gated = contract(EXISTS, eligibility=[{"field": "regionn", "op": op}])
    entry = item(run(tmp_path, gated, source, target), "a")
    assert (entry["status"], entry["reason"]) == ("INCONCLUSIVE", "eligibility_undecidable")


@pytest.mark.parametrize(
    ("fields", "present"),
    [
        ({}, False),
        ({"tags": None}, False),
        ({"tags": ""}, False),
        ({"tags": []}, False),
        ({"tags": {}}, False),
        ({"tags": "x"}, True),
        ({"tags": ["x"]}, True),
        ({"tags": {"k": None}}, True),
        ({"tags": 0}, True),
        ({"tags": False}, True),
    ],
)
def test_presence_treats_null_and_empty_values_as_absent(
    tmp_path: Path, fields: dict[str, Any], present: bool
) -> None:
    """``present``/``absent`` agree with ``required``: empty text, list or object is empty."""
    source = [*_src("a", **fields), *_src("b", tags=["y"])]
    target = [{"ref": "a"}, {"ref": "b"}]
    for op, eligible in (("present", present), ("absent", not present)):
        spec = contract(EXISTS, eligibility=[{"field": "tags", "op": op}])
        status = item(run(tmp_path, spec, source, target), "a")["status"]
        assert status == ("VERIFIED" if eligible else "NOT_APPLICABLE"), op


def test_eligibility_compares_large_integers_exactly(tmp_path: Path) -> None:
    """2**53 + 1 is greater than 2**53; a float comparison calls them equal (RULE-06)."""
    spec = contract(EXISTS, eligibility=[{"field": "n", "op": "gt", "value": 2**53}])
    source = _csv(tmp_path, "source", f"id,n\na,{2**53 + 1}\nb,{2**53}\n")
    report = _report(spec, source, _verbatim(tmp_path, "target", "[]"))
    assert cond(item(report, "a"), "exists") == ("VIOLATED", "missing")
    assert item(report, "b")["reason"] == "not_eligible"


@pytest.mark.parametrize(
    ("csv_text", "json_text", "reason"),
    [
        ("9007199254740993", "9007199254740992", "values_differ"),
        ("1234567890123456789", "1234567890123456789", "values_match"),
        ("0.1", "0.1", "values_match"),
        ("12.50", "12.5", "values_match"),
        ("1e2", "100", "values_match"),
        ("-0", "0.0", "values_match"),
        ("0.1000000000000000001", "0.1", "values_differ"),
        ("100000000000000000000", "1e20", "values_match"),
        ("100000000000000000001", "1e20", "values_differ"),
    ],
)
def test_equals_is_exact_across_csv_and_json(
    tmp_path: Path, csv_text: str, json_text: str, reason: str
) -> None:
    """RULE-05: CSV text and JSON numbers compare by exact value, never through a float."""
    spec = contract(EXISTS, {"id": "eq", "type": "equals", "field": "amt", "source_field": "amt"})
    source = _csv(tmp_path, "source", f"id,amt\na,{csv_text}\n")
    target = _verbatim(tmp_path, "target", f'[{{"ref": "a", "amt": {json_text}}}]')
    assert cond(item(_report(spec, source, target), "a"), "eq")[1] == reason


def test_range_bounds_compare_exactly(tmp_path: Path) -> None:
    big = 2**53 + 1
    spec = contract(
        {"id": "big", "type": "range", "field": "n", "min": big, "max": big},
        {"id": "tenth", "type": "range", "field": "x", "max": 0.3},
    )
    target = _verbatim(
        tmp_path,
        "target",
        f'[{{"ref": "a", "n": {big}, "x": 0.3}},'
        f' {{"ref": "b", "n": {2**53}, "x": 0.30000000000000001}}]',
    )
    report = _report(spec, _csv(tmp_path, "source", "id\na\nb\n"), target)
    assert cond(item(report, "a"), "big") == ("VERIFIED", "in_range")
    assert cond(item(report, "a"), "tenth") == ("VERIFIED", "in_range")
    assert cond(item(report, "b"), "big") == ("VIOLATED", "out_of_range")
    assert cond(item(report, "b"), "tenth") == ("VIOLATED", "out_of_range")


def test_one_of_matches_numbers_by_value_not_spelling(tmp_path: Path) -> None:
    spec = contract({"id": "pick", "type": "one_of", "field": "v", "values": [1.5, 100]})
    target = _verbatim(
        tmp_path,
        "target",
        '[{"ref": "a", "v": 1.50}, {"ref": "b", "v": 1E2}, {"ref": "c", "v": "1.50"},'
        ' {"ref": "d", "v": 100.0000000000000001}]',
    )
    report = _report(spec, _csv(tmp_path, "source", "id\na\nb\nc\nd\n"), target)
    reasons = [cond(item(report, key), "pick")[1] for key in "abcd"]
    assert reasons == ["value_allowed", "value_allowed", "value_not_allowed", "value_not_allowed"]


def test_in_predicate_uses_one_spelling_per_number(tmp_path: Path) -> None:
    spec = contract(EXISTS, eligibility=[{"field": "n", "op": "in", "values": [1e100, 0.1, -0.0]}])
    source = _verbatim(
        tmp_path,
        "source",
        '[{"id": "a", "n": 1E+100}, {"id": "b", "n": 0.10}, {"id": "c", "n": 0},'
        ' {"id": "d", "n": 0.1000000000000000001}]',
    )
    target = _verbatim(
        tmp_path, "target", '[{"ref": "a"}, {"ref": "b"}, {"ref": "c"}, {"ref": "d"}]'
    )
    statuses = [item(_report(spec, source, target), key)["status"] for key in "abcd"]
    assert statuses == ["VERIFIED", "VERIFIED", "VERIFIED", "NOT_APPLICABLE"]


def test_count_upper_bound_needs_every_target_row_keyed(tmp_path: Path) -> None:
    """A keyless target row may be one more record for this item (RULE-02, REC-07)."""
    keyless = [{"ref": "a"}, {"ref": None}, {"ref": ""}]
    report = run(tmp_path, contract(ONE), _src("a"), keyless)
    assert cond(item(report, "a"), "one") == ("INCONCLUSIVE", "target_unkeyed_rows")
    assert report.outcome == "INCONCLUSIVE"
    keyed = run(tmp_path, contract(ONE), _src("a"), [{"ref": "a"}, {"ref": "b"}])
    assert cond(item(keyed, "a"), "one") == ("VERIFIED", "count_within")
    # A lower bound alone is still proven by the keyed record.
    floor = {"id": "floor", "type": "count", "min": 1}
    report = run(tmp_path, contract(floor), _src("a"), keyless)
    assert cond(item(report, "a"), "floor") == ("VERIFIED", "present")


@pytest.mark.parametrize(
    ("done_at", "expected"),
    [
        ("2026-10-19T08:30:00Z", ("INCONCLUSIVE", "completion_before_event")),
        (T0, ("VERIFIED", "completed_on_time")),
        ("2026-10-20T08:30:00Z", ("VERIFIED", "completed_on_time")),
        (DEADLINE, ("VERIFIED", "completed_on_time")),
        ("2026-10-20T10:00:00Z", ("VIOLATED", "late")),
        ("2026-10-20T13:00:00Z", ("INCONCLUSIVE", "completion_after_observation")),
        ("soon", ("INCONCLUSIVE", "completion_time_unusable")),
    ],
)
def test_on_time_counts_only_completions_that_could_be_observed(
    tmp_path: Path, done_at: str, expected: tuple[str, str]
) -> None:
    """RULE-07: a completion counts only between the source event and the observation."""
    spec = contract(EXISTS, ON_TIME, due=due())
    report = run(tmp_path, spec, _src("a"), [{"ref": "a", "done_at": done_at}])
    assert cond(item(report, "a"), "on-time") == expected
    assert_schema(report.to_dict(), "sesslint.outcome-report.v1.json")


def test_completion_after_the_target_observation_proves_nothing(tmp_path: Path) -> None:
    spec = contract(EXISTS, ON_TIME, due=due())
    target = [{"ref": "a", "done_at": "2026-10-20T11:00:00Z"}]
    meta = {"observed_at": "2026-10-20T10:00:00Z"}
    report = run(tmp_path, spec, _src("a"), target, target_meta=meta)
    assert cond(item(report, "a"), "on-time") == ("INCONCLUSIVE", "completion_after_observation")


@pytest.mark.parametrize(
    ("done_at", "expected"),
    [
        ("2026-10-20T10:00:00Z", ("PENDING", "awaiting_due")),
        ("2026-10-20T08:15:00Z", ("VERIFIED", "completed_on_time")),
    ],
)
def test_lateness_is_never_judged_before_the_deadline(
    tmp_path: Path, done_at: str, expected: tuple[str, str]
) -> None:
    early = "2026-10-20T08:30:00Z"
    report = run(
        tmp_path,
        contract(EXISTS, ON_TIME, due=due()),
        _src("a"),
        [{"ref": "a", "done_at": done_at}],
        as_of=early,
        source_meta={"observed_at": early},
        target_meta={"observed_at": early},
    )
    assert cond(item(report, "a"), "on-time") == expected


@pytest.mark.parametrize(
    ("times", "expected"),
    [
        (
            ("2026-10-19T08:30:00Z", "2026-10-20T08:30:00Z"),
            ("VERIFIED", "completed_on_time"),
        ),
        (
            ("2026-10-19T08:30:00Z", "2026-10-20T10:00:00Z"),
            ("INCONCLUSIVE", "completion_before_event"),
        ),
        (
            ("2026-10-20T10:00:00Z", "2026-10-20T13:00:00Z"),
            ("INCONCLUSIVE", "completion_after_observation"),
        ),
        (
            ("2026-10-20T11:00:00Z", "2026-10-20T10:00:00Z"),
            ("VIOLATED", "late"),
        ),
    ],
)
def test_on_time_with_several_target_records(
    tmp_path: Path, times: tuple[str, str], expected: tuple[str, str]
) -> None:
    spec = contract(EXISTS, ON_TIME, due=due())
    report = run(tmp_path, spec, _src("a"), [{"ref": "a", "done_at": t} for t in times])
    entry = item(report, "a")
    assert cond(entry, "on-time") == expected
    if expected[1] == "late":
        detail = next(c["detail"] for c in entry["conditions"] if c["id"] == "on-time")
        assert detail["late_by_seconds"] == 3600


@pytest.mark.parametrize(
    ("observed", "expected"),
    [
        ("2026-10-20T07:00:00Z", ("INCONCLUSIVE", "completion_before_event")),
        (T0, ("VERIFIED", "observed_on_time")),
        (DEADLINE, ("VERIFIED", "observed_on_time")),
        ("2026-10-20T10:00:00Z", ("INCONCLUSIVE", "first_seen_after_deadline")),
    ],
)
def test_observation_basis_needs_a_snapshot_taken_after_the_event(
    tmp_path: Path, observed: str, expected: tuple[str, str]
) -> None:
    seen = {"id": "seen", "type": "on_time", "basis": "observation"}
    report = run(
        tmp_path,
        contract(EXISTS, seen, due=due()),
        _src("a"),
        [{"ref": "a"}],
        target_meta={"observed_at": observed},
    )
    assert cond(item(report, "a"), "seen") == expected


_NUMERIC_CHECKS = (
    {"id": "int", "type": "type", "field": "n", "kind": "integer"},
    {"id": "num", "type": "type", "field": "n", "kind": "number"},
    {"id": "rng", "type": "range", "field": "n", "min": -1},
)


@pytest.mark.parametrize(
    "cell",
    [
        chr(0x0665),
        chr(0xFF15),
        '"5\n"',
        "5 ",
        "1_000",
        "0x10",
        "1.2.3",
        "NaN",
        "Infinity",
        "1" * 101,
        "9" * 400,
        "1e9999999",
    ],
)
def test_csv_text_that_is_not_a_plain_number_is_never_numeric(tmp_path: Path, cell: str) -> None:
    """One ASCII reader and one length cap decide type, range and predicates alike."""
    target = _csv(tmp_path, "target", f"ref,n\na,{cell}\n")
    source = _csv(tmp_path, "source", "id\na\n")
    entry = item(_report(contract(*_NUMERIC_CHECKS), source, target), "a")
    assert cond(entry, "int") == ("VIOLATED", "type_mismatch")
    assert cond(entry, "num") == ("VIOLATED", "type_mismatch")
    assert cond(entry, "rng") == ("VIOLATED", "not_a_number")


@pytest.mark.parametrize("cell", ["9" * 400, chr(0x0665), "1_000"])
def test_csv_predicates_use_the_same_number_reader(tmp_path: Path, cell: str) -> None:
    spec = contract(EXISTS, eligibility=[{"field": "n", "op": "gte", "value": 0}])
    source = _csv(tmp_path, "source", f"id,n\na,{cell}\n")
    entry = item(_report(spec, source, _verbatim(tmp_path, "target", '[{"ref": "a"}]')), "a")
    assert (entry["status"], entry["reason"]) == ("INCONCLUSIVE", "eligibility_undecidable")


@pytest.mark.parametrize(
    ("cell", "integer"),
    [
        ("+5", True),
        ("007", True),
        ("-0", True),
        ("1" * 100, True),
        ("1.5", False),
        (".5", False),
        ("5.", False),
        ("1e3", False),
        ("-2.5E-3", False),
    ],
)
def test_csv_plain_numbers_are_numeric(tmp_path: Path, cell: str, integer: bool) -> None:
    target = _csv(tmp_path, "target", f"ref,n\na,{cell}\n")
    source = _csv(tmp_path, "source", "id\na\n")
    entry = item(_report(contract(*_NUMERIC_CHECKS), source, target), "a")
    assert cond(entry, "int")[0] == ("VERIFIED" if integer else "VIOLATED")
    assert cond(entry, "num") == ("VERIFIED", "type_ok")
    assert cond(entry, "rng") == ("VERIFIED", "in_range")


@pytest.mark.parametrize(
    ("value", "allow_empty", "expected"),
    [
        ([], False, ("VIOLATED", "field_empty")),
        ({}, False, ("VIOLATED", "field_empty")),
        ("", False, ("VIOLATED", "field_empty")),
        ([], True, ("VERIFIED", "field_present")),
        ({}, True, ("VERIFIED", "field_present")),
        (["x"], False, ("VERIFIED", "field_present")),
        ({"k": None}, False, ("VERIFIED", "field_present")),
    ],
)
def test_required_treats_empty_lists_and_objects_as_empty(
    tmp_path: Path, value: Any, allow_empty: bool, expected: tuple[str, str]
) -> None:
    spec = contract({"id": "tags", "type": "required", "field": "tags", "allow_empty": allow_empty})
    report = run(tmp_path, spec, _src("a"), [{"ref": "a", "tags": value}])
    assert cond(item(report, "a"), "tags") == expected


# Equality outside `equals` follows the same rule: a contract number matches a value
# that reads as a number by exact value; a contract string always compares as text.
# CSV text that only looks like a number (padded, over 100 characters, a 7-digit
# exponent) is undecided (None) against a contract number: unequal text proves nothing.
_MATCHES = pytest.mark.parametrize(
    ("cell", "value", "match"),
    [
        ("12.50", 12.5, True),
        ("0012", 12, True),
        ("0012", "12", False),
        (str(2**53 + 1), 2**53, False),
        ("0.1", 0.1, True),
        ("1e1", 10, True),
        ("12.5", "12.5", True),
        ("12.50", "12.5", False),
        (" 12", 12, None),
        ("12 ", 12.0, None),
        ("1." + "0" * 99, 1, None),
        ("0e9999999", 0, None),
        (" 12", " 12", True),
        (" 12", "12", False),
    ],
)


@_MATCHES
def test_eligibility_equality_matches_numbers_by_value(
    tmp_path: Path, cell: str, value: Any, match: bool | None
) -> None:
    """RULE-05, REC-06: CSV text that reads as a number meets a contract number exactly."""
    source = _csv(tmp_path, "source", f"id,code\na,{cell}\n")
    target = _verbatim(tmp_path, "target", '[{"ref": "a"}]')
    for op, wanted in (("eq", value), ("ne", value), ("in", [value]), ("not_in", [value])):
        key = "values" if op.endswith("in") else "value"
        spec = contract(EXISTS, eligibility=[{"field": "code", "op": op, key: wanted}])
        entry = item(_report(spec, source, target), "a")
        if match is None:
            assert (entry["status"], entry["reason"]) == (
                "INCONCLUSIVE",
                "eligibility_undecidable",
            ), op
            continue
        eligible = match if op in ("eq", "in") else not match
        assert entry["status"] == ("VERIFIED" if eligible else "NOT_APPLICABLE"), op


@_MATCHES
def test_route_matches_numbers_by_value(
    tmp_path: Path, cell: str, value: Any, match: bool | None
) -> None:
    """RULE-08: both the ``when`` predicates and the routed ``values`` use the rule."""
    spec = contract(
        {
            "id": "when",
            "type": "route",
            "field": "queue",
            "values": ["vip"],
            "when": [{"field": "tier", "op": "eq", "value": value}],
        },
        {
            "id": "values",
            "type": "route",
            "field": "code",
            "values": [value],
            "when": [{"field": "tier", "op": "present"}],
        },
    )
    source = _csv(tmp_path, "source", f"id,tier\na,{cell}\n")
    target = _csv(tmp_path, "target", f"ref,queue,code\na,vip,{cell}\n")
    entry = item(_report(spec, source, target), "a")
    if match is None:
        assert cond(entry, "when") == ("INCONCLUSIVE", "route_undecidable")
        assert cond(entry, "values") == ("INCONCLUSIVE", "value_undecidable")
        return
    assert cond(entry, "when") == (
        ("VERIFIED", "route_ok") if match else ("NOT_APPLICABLE", "route_not_applicable")
    )
    assert cond(entry, "values") == (
        ("VERIFIED", "route_ok") if match else ("VIOLATED", "wrong_route")
    )


@_MATCHES
def test_one_of_matches_numbers_by_value(
    tmp_path: Path, cell: str, value: Any, match: bool | None
) -> None:
    """RULE-04: an allowed value list holds numbers by value and strings as text."""
    spec = contract({"id": "pick", "type": "one_of", "field": "code", "values": ["n/a", value]})
    target = _csv(tmp_path, "target", f"ref,code\na,{cell}\n")
    entry = item(_report(spec, _csv(tmp_path, "source", "id\na\n"), target), "a")
    if match is None:
        assert cond(entry, "pick") == ("INCONCLUSIVE", "value_undecidable")
        return
    assert cond(entry, "pick") == (
        ("VERIFIED", "value_allowed") if match else ("VIOLATED", "value_not_allowed")
    )


def test_csv_text_that_only_looks_like_a_number_is_never_excluded(tmp_path: Path) -> None:
    """REC-06, REC-07: refused number text never fails ``eq`` silently and excludes an item.

    Before, ``a`` and ``c`` were NOT_APPLICABLE, their missing target records went
    unreported and the run was VERIFIED (exit 0).
    """
    spec = contract(EXISTS, eligibility=[{"field": "v", "op": "eq", "value": 1}])
    long_one = "1." + "0" * 99
    source = _csv(tmp_path, "source", f"id,v\na,{long_one}\nb,1\nc, 1\nd,0e9999999\n")
    target = _verbatim(tmp_path, "target", '[{"ref": "b"}]')
    report = _report(spec, source, target)
    for key in "acd":
        entry = item(report, key)
        assert (entry["status"], entry["reason"]) == ("INCONCLUSIVE", "eligibility_undecidable")
    assert item(report, "b")["status"] == "VERIFIED"
    assert (report.outcome, report.exit_code) == ("INCONCLUSIVE", 1)


# 101 characters: numerically 1, but too long to read as a CSV number.
_LONG_ONE = "1." + "0" * 99
# The route verdict that matches each one_of verdict on the same value.
_ROUTED = {
    "value_allowed": ("VERIFIED", "route_ok"),
    "value_not_allowed": ("VIOLATED", "wrong_route"),
}


@pytest.mark.parametrize(
    ("cell", "values", "normalize", "expected"),
    [
        (" 3", [1, 2], ["trim"], ("VIOLATED", "value_not_allowed")),
        (" 1.0", [1], ["trim"], ("VERIFIED", "value_allowed")),
        (" 1", [1], ["trim"], ("VERIFIED", "value_allowed")),
        (" 0012", [12], ["trim"], ("VERIFIED", "value_allowed")),
        (" 0012", ["12"], ["trim"], ("VIOLATED", "value_not_allowed")),
        (" 1", [1], [], ("INCONCLUSIVE", "value_undecidable")),
        (" 3", [1, 2], ["casefold"], ("INCONCLUSIVE", "value_undecidable")),
        (" " + _LONG_ONE, [1], ["trim"], ("INCONCLUSIVE", "value_undecidable")),
        (" 1e9999999", [1], ["trim"], ("INCONCLUSIVE", "value_undecidable")),
    ],
)
def test_declared_trim_reads_padded_csv_numbers(
    tmp_path: Path,
    cell: str,
    values: list[Any],
    normalize: list[str],
    expected: tuple[str, str],
) -> None:
    """RULE-04, RULE-08, REC-07: ``trim`` strips CSV text before it is read as a number.

    So padded numbers are decided. Without ``trim`` padded number text stays
    undecided, and a contract string still compares as text.
    """
    pick: dict[str, Any] = {"id": "pick", "type": "one_of", "field": "code", "values": values}
    route = {**pick, "id": "route", "type": "route", "when": [{"field": "id", "op": "present"}]}
    spec = contract({**pick, "normalize": normalize}, {**route, "normalize": normalize})
    target = _csv(tmp_path, "target", f"ref,code\na,{cell}\n")
    entry = item(_report(spec, _csv(tmp_path, "source", "id\na\n"), target), "a")
    assert cond(entry, "pick") == expected
    assert cond(entry, "route") == _ROUTED.get(expected[1], expected)


def test_trim_never_reads_a_json_string_as_a_number(tmp_path: Path) -> None:
    """RULE-04: in a typed snapshot a JSON string compares as text, ``trim`` or not."""
    spec = contract(
        {"id": "pick", "type": "one_of", "field": "code", "values": [1], "normalize": ["trim"]}
    )
    target = _verbatim(tmp_path, "target", '[{"ref": "a", "code": " 1.0"}]')
    report = _report(spec, _verbatim(tmp_path, "source", '[{"id": "a"}]'), target)
    assert cond(item(report, "a"), "pick") == ("VIOLATED", "value_not_allowed")


def test_json_strings_never_read_as_numbers(tmp_path: Path) -> None:
    """In a typed snapshot only JSON numbers are numbers; a JSON string compares as text."""
    spec = contract(EXISTS, eligibility=[{"field": "code", "op": "eq", "value": 12.5}])
    source = _verbatim(
        tmp_path,
        "source",
        '[{"id": "a", "code": 12.50}, {"id": "b", "code": "12.50"}, {"id": "c", "code": "12.5"}]',
    )
    target = _verbatim(tmp_path, "target", '[{"ref": "a"}, {"ref": "b"}, {"ref": "c"}]')
    report = _report(spec, source, target)
    assert [item(report, key)["status"] for key in "abc"] == [
        "VERIFIED",
        "NOT_APPLICABLE",
        "VERIFIED",
    ]


def _one_value(tmp_path: Path, role: str, kind: str, literal: str) -> Snapshot:
    """Item ``a`` with field ``v`` written as a CSV cell or a JSON literal, unchanged."""
    key = "id" if role == "source" else "ref"
    if kind == "csv":
        return _csv(tmp_path, role, f"{key},v\na,{literal}\n")
    return _verbatim(tmp_path, role, f'[{{"{key}": "a", "v": {literal}}}]')


# 102 digits, so its one exact spelling is over 100 characters and no CSV number.
_BIG = "123456789" * 11 + "123"
_EQUALS = {"id": "same", "type": "equals", "field": "v", "source_field": "v"}


@pytest.mark.parametrize(
    ("source", "target", "normalize", "expected"),
    [
        (("csv", "0012"), ("json", "12"), [], ("VERIFIED", "values_match")),
        (("csv", "abc"), ("json", "1"), [], ("VIOLATED", "values_differ")),
        (("csv", "0012"), ("csv", "12"), [], ("VIOLATED", "values_differ")),
        (("json", '"0012"'), ("json", '"12"'), [], ("VIOLATED", "values_differ")),
        (("json", "12.5"), ("json", "12.50"), [], ("VERIFIED", "values_match")),
        (("json", "1"), ("json", "2"), [], ("VIOLATED", "values_differ")),
        (("csv", _LONG_ONE), ("json", "1"), [], ("INCONCLUSIVE", "value_undecidable")),
        (("json", "1"), ("csv", _LONG_ONE), [], ("INCONCLUSIVE", "value_undecidable")),
        (("csv", _LONG_ONE), ("json", "2"), [], ("INCONCLUSIVE", "value_undecidable")),
        (("csv", "1e9999999"), ("json", "1"), [], ("INCONCLUSIVE", "value_undecidable")),
        (("csv", " 1"), ("json", "1"), [], ("INCONCLUSIVE", "value_undecidable")),
        (("csv", " 1.0"), ("json", "1"), ["trim"], ("VERIFIED", "values_match")),
        (("csv", " 2"), ("json", "1"), ["trim"], ("VIOLATED", "values_differ")),
        (("csv", " " + _LONG_ONE), ("json", "1"), ["trim"], ("INCONCLUSIVE", "value_undecidable")),
        (("json", '" 1"'), ("json", "1"), [], ("VIOLATED", "values_differ")),
        (("json", '"1"'), ("json", "1"), [], ("VERIFIED", "values_match")),
        (("json", '"1.0"'), ("json", "1"), [], ("VIOLATED", "values_differ")),
        (("csv", f"{_BIG[0]}.{_BIG[1:]}e+101"), ("json", _BIG), [], ("VERIFIED", "values_match")),
    ],
)
def test_equals_never_claims_a_difference_it_cannot_read(
    tmp_path: Path,
    source: tuple[str, str],
    target: tuple[str, str],
    normalize: list[str],
    expected: tuple[str, str],
) -> None:
    """RULE-05, REC-07: CSV number text that cannot be read never differs from a JSON number.

    A declared ``trim`` strips CSV text before the number read. Text that
    still looks like a number but does not read as one is undecided, unless
    it equals the JSON number's exact spelling. A JSON string is never read
    as a number, and two strings still compare as text.
    """
    spec = contract(EXISTS, {**_EQUALS, "normalize": normalize})
    report = _report(
        spec, _one_value(tmp_path, "source", *source), _one_value(tmp_path, "target", *target)
    )
    assert cond(item(report, "a"), "same") == expected


@pytest.mark.parametrize(("allowed", "rc"), [("y", 1), ("x", 0)])
def test_an_undecidable_equals_branch_never_changes_the_exit_code(
    tmp_path: Path, allowed: str, rc: int
) -> None:
    """RULE-05, REC-07: an ``any_of`` with an ``equals`` branch keeps its exit code.

    VIOLATED and INCONCLUSIVE both exit 1, so CSV text that cannot be read
    exits exactly as text that differs: 1 when the other branch fails, and 0
    when it verifies.
    """
    other = {"id": "code", "type": "one_of", "field": "code", "values": [allowed]}
    spec = contract(EXISTS, {"id": "either", "type": "any_of", "conditions": [_EQUALS, other]})
    target = _verbatim(tmp_path, "target", '[{"ref": "a", "v": 1, "code": "x"}]')
    unread = _report(spec, _csv(tmp_path, "source", f"id,v\na,{_LONG_ONE}\n"), target)
    differs = _report(spec, _csv(tmp_path, "source", "id,v\na,abc\n"), target)
    if rc:
        assert cond(item(unread, "a"), "either") == ("INCONCLUSIVE", "branches_undecided")
        assert cond(item(differs, "a"), "either") == ("VIOLATED", "all_branches_violated")
    else:
        assert cond(item(unread, "a"), "either") == ("VERIFIED", "any_branch_verified")
        assert cond(item(differs, "a"), "either") == ("VERIFIED", "any_branch_verified")
    assert unread.exit_code == differs.exit_code == rc


def _canonical(report: OutcomeReport) -> str:
    """The report as canonical JSON, minus the source file hash (row order changes it)."""
    doc = report.to_dict()
    doc["observations"]["source"].pop("sha256")
    return json.dumps(doc, sort_keys=True)


@pytest.mark.parametrize(("text", "number"), [('"1"', "1"), ('"100"', "1E2")])
def test_rows_that_differ_only_in_json_type_conflict_in_either_order(
    tmp_path: Path, text: str, number: str
) -> None:
    """REC-04, AT-38: a JSON string never reads as a number, so the rows really differ.

    Before, one order was INCONCLUSIVE and the reversed order VERIFIED (exit 0).
    """
    spec = contract(EXISTS, eligibility=[{"field": "v", "op": "gt", "value": 0}])
    target = _verbatim(tmp_path, "target", '[{"ref": "a"}]')
    rendered = []
    for first, second in ((text, number), (number, text)):
        rows = f'[{{"id": "a", "v": {first}}}, {{"id": "a", "v": {second}}}]'
        report = _report(spec, _verbatim(tmp_path, "source", rows), target)
        entry = item(report, "a")
        assert (entry["status"], entry["reason"]) == ("INCONCLUSIVE", "source_conflict")
        assert (report.outcome, report.exit_code) == ("INCONCLUSIVE", 1)
        rendered.append(_canonical(report))
    assert rendered[0] == rendered[1]


@pytest.mark.parametrize(
    ("first", "second", "status"),
    [
        ("1", "1.0", "VERIFIED"),
        ("100", "1E2", "VERIFIED"),
        ('"x"', '"x"', "VERIFIED"),
        ("true", "true", "VERIFIED"),
        ("[1]", '{"k": 2}', "VERIFIED"),
        ("[]", "{}", "NOT_APPLICABLE"),
    ],
)
def test_rows_with_the_same_kind_and_value_still_merge(
    tmp_path: Path, first: str, second: str, status: str
) -> None:
    """REC-04: equal numbers, and nested values alike in emptiness, are one retried item."""
    spec = contract(EXISTS, eligibility=[{"field": "v", "op": "present"}])
    target = _verbatim(tmp_path, "target", '[{"ref": "a"}]')
    for one, two in ((first, second), (second, first)):
        rows = f'[{{"id": "a", "v": {one}}}, {{"id": "a", "v": {two}}}]'
        entry = item(_report(spec, _verbatim(tmp_path, "source", rows), target), "a")
        assert (entry["status"], entry["source_rows"]) == (status, 2), (one, two)


@pytest.mark.parametrize(
    ("first", "second"),
    [("true", '"true"'), ("null", '""'), ("[]", '""'), ("[]", "[1]"), ("null", "[]")],
)
def test_rows_that_judge_differently_conflict(tmp_path: Path, first: str, second: str) -> None:
    """REC-04: a boolean and its text, null and an empty value, empty and non-empty nesting."""
    spec = contract(EXISTS, eligibility=[{"field": "v", "op": "present"}])
    target = _verbatim(tmp_path, "target", '[{"ref": "a"}]')
    for one, two in ((first, second), (second, first)):
        rows = f'[{{"id": "a", "v": {one}}}, {{"id": "a", "v": {two}}}]'
        entry = item(_report(spec, _verbatim(tmp_path, "source", rows), target), "a")
        assert entry["reason"] == "source_conflict", (one, two)


def test_integer_and_text_keys_still_name_one_item(tmp_path: Path) -> None:
    """REC-01, REC-04: keys match as text, so ``7`` and ``"7"`` are one retried item."""
    source = _verbatim(tmp_path, "source", '[{"id": 7}, {"id": "7"}]')
    target = _verbatim(tmp_path, "target", '[{"ref": "7"}]')
    entry = item(_report(contract(EXISTS), source, target), "7")
    assert (entry["status"], entry["source_rows"]) == ("VERIFIED", 2)
    # A key field that is also judged keeps its kind: "7" is no number for gt.
    gated = contract(EXISTS, eligibility=[{"field": "id", "op": "gt", "value": 0}])
    assert item(_report(gated, source, target), "7")["reason"] == "source_conflict"


def _library_snapshot(role: str, records: list[dict[str, Any]]) -> Snapshot:
    """A snapshot built in code, as a library caller may, not read from a file."""
    return Snapshot(
        role=role,
        name=f"{role}.json",
        sha256="0" * 64,
        input_format="json",
        records=tuple(records),
        fields=frozenset(name for record in records for name in record),
        observed_at=at(LATER),
        completeness="complete",
        origin="user_file",
        demo=False,
    )


def test_empty_nesting_is_judged_by_its_flag_not_by_identity() -> None:
    """RULE-03, REC-06: any empty NonScalar is empty for required, present and absent."""
    fresh = NonScalar(empty=True)
    assert fresh is not EMPTY_NESTED
    spec = contract(
        EXISTS,
        {"id": "req", "type": "required", "field": "tags"},
        eligibility=[{"field": "tags", "op": "absent"}],
    )
    rows = [{"id": "a", "tags": fresh}, {"id": "a", "tags": EMPTY_NESTED}]
    source = _library_snapshot("source", rows)
    target = _library_snapshot("target", [{"ref": "a", "tags": fresh}])
    entry = item(_report(spec, source, target), "a")
    # Both rows are empty: one retried item, eligible because "absent" holds.
    assert (entry["status"], entry["source_rows"]) == ("VIOLATED", 2)
    assert cond(entry, "req") == ("VIOLATED", "field_empty")


@pytest.mark.parametrize("limit", [0, 640])
def test_reports_do_not_depend_on_pythons_digit_limit(tmp_path: Path, limit: int) -> None:
    """AT-38: 4300-character numbers read and compare alike under any int/str digit limit.

    The key, the bound check and the duplicate-row check all handle integers
    far past a lowered limit; ``v`` is one number spelled two ways (4298 digits
    and the same plus ``.0``), so the two rows merge instead of conflicting.
    """
    digit = "7" if limit else "8"
    digits = digit * 4300
    spec = contract(
        EXISTS,
        {"id": "rng", "type": "range", "field": "n", "min": 0},
        eligibility=[{"field": "v", "op": "gt", "value": 0}],
    )

    def render() -> str:
        v = digit * 4298
        rows = f'[{{"id": {digits}, "v": {v}}}, {{"id": {digits}, "v": {v}.0}}]'
        source = _verbatim(tmp_path, "source", rows)
        target = _verbatim(tmp_path, "target", f'[{{"ref": "{digits}", "n": -{digits}}}]')
        report = _report(spec, source, target)
        entry = item(report, digits)
        assert (entry["status"], entry["source_rows"]) == ("VIOLATED", 2)
        assert cond(entry, "rng") == ("VIOLATED", "out_of_range")
        return report.to_json()

    with digit_limit(limit):
        lowered = render()
    with digit_limit(4300):
        assert lowered == render()
