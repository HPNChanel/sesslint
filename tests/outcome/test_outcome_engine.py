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
    EvaluationError,
    OutcomeReport,
    evaluate,
    load_contract,
    load_snapshot,
    session_dimension,
    verify_outcome,
)
from tests.outcome.helpers import (
    DEADLINE,
    LATER,
    ORDERS,
    ROOT,
    T0,
    at,
    cond,
    contract,
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
    records = list(target.records)
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
