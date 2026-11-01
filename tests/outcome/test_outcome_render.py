"""Exact bytes of ``OutcomeReport.render_human`` (ITF-02): sections, ordering, truncation."""

from __future__ import annotations

from pathlib import Path

from sesslint.outcome import OutcomeReport
from sesslint.outcome.engine import HASHED_KEY_LIMITATION, LIMITATIONS

from .helpers import LATER, T0, contract, due, run

_LIMITS = "\n".join(f"  - {text}" for text in LIMITATIONS)


def test_violated_report_is_byte_exact(tmp_path: Path) -> None:
    spec = contract(
        {"id": "exists", "type": "exists"},
        {"id": "st", "type": "one_of", "field": "status", "values": ["ok"]},
        {"id": "adv", "type": "required", "field": "note", "advisory": True},
        due=due(),
    )
    src = [{"id": "1", "at": T0}, {"id": "2", "at": T0}, {"id": "3", "at": T0}, {"id": "4"}]
    tgt = [{"ref": "1", "status": "ok", "note": "n"}, {"ref": "2", "status": "bad"}, {"ref": "9"}]
    text = run(tmp_path, spec, src, tgt).render_human()
    assert text == (
        "SessLint outcome: VIOLATED  (contract synthetic v1, evaluated at 2026-10-20T12:00:00Z)\n"
        "Dimensions:\n"
        "  session integrity:    not linked (no session supplied)\n"
        "  outcome verification: VIOLATED\n"
        "  monitoring health:    not configured (snapshot evaluation)\n"
        "  incident handling:    not tracked\n"
        "Observations:\n"
        f"  source: 4 records, complete, observed {LATER} (user_file, envelope)\n"
        f"  target: 3 records, complete, observed {LATER} (user_file, envelope)\n"
        "Items: 4 work items from 4 source rows; VERIFIED 1, VIOLATED 2, INCONCLUSIVE 1\n"
        "  1 target record(s) match no source item\n"
        "Items needing attention (first 50):\n"
        '  VIOLATED      "2"\n'
        "      st: value_not_allowed - the value is not in the allowed set\n"
        '  VIOLATED      "3"\n'
        "      exists: missing - no matching target record in a complete snapshot observed at "
        "or after the deadline\n"
        '  INCONCLUSIVE  "4"\n'
        "      exists, st: due_unknown - the source event time is absent or has no UTC offset, "
        "so the deadline is unknown\n"
        "Outcome reasons:\n"
        "  - some_items_violated: at least one item is violated\n"
        "Limitations:\n"
        f"{_LIMITS}"
    )


def test_hashed_keys_session_label_and_limitation(tmp_path: Path) -> None:
    spec = contract({"id": "exists", "type": "exists"}, due=due())
    report = run(tmp_path, spec, [{"id": "7", "at": T0}], [])
    hashed = OutcomeReport(report.evaluation, session={"status": "findings"}, hash_keys=True)
    lines = hashed.render_human().split("\n")
    assert "  session integrity:    findings present" in lines
    row = next(ln for ln in lines if ln.startswith("  VIOLATED"))
    assert row.startswith("  VIOLATED      sha256:") and len(row) == len("  VIOLATED      ") + 23
    assert "7" not in row
    assert lines[-1] == f"  - {HASHED_KEY_LIMITATION}"
    assert lines[-2] == f"  - {LIMITATIONS[-1]}"


def test_unknown_session_status_prints_verbatim_and_each_known_label(tmp_path: Path) -> None:
    spec = contract({"id": "exists", "type": "exists"})
    base = run(tmp_path, spec, [{"id": "1"}], [{"ref": "1"}])
    expected = {
        "not_linked": "not linked (no session supplied)",
        "no_findings": "no findings in the checks run",
        "findings": "findings present",
        "unreadable": "unreadable or unsupported format",
        "mystery": "mystery",
    }
    for status, label in expected.items():
        text = OutcomeReport(base.evaluation, session={"status": status}).render_human()
        assert f"\n  session integrity:    {label}\n" in text
    # A session mapping without a status falls back to "not linked".
    assert (
        "session integrity:    not linked (no session supplied)\n"
        in OutcomeReport(base.evaluation, session={}).render_human()
    )


def test_demo_banner_unknown_time_keyless_item_and_warnings(tmp_path: Path) -> None:
    spec = contract({"id": "st", "type": "required", "field": "status"})
    report = run(
        tmp_path,
        spec,
        [{"id": "1"}, {"x": 1}],
        [{"ref": "1", "status": "a"}],
        source_meta={"observed_at": None, "demo": True},
        target_meta={"observed_at": None, "completeness": "partial"},
    )
    assert report.render_human() == (
        "SessLint outcome: INCONCLUSIVE  (contract synthetic v1, evaluated at "
        "2026-10-20T12:00:00Z)\n"
        "  DEMO DATA - not a verification of real work\n"
        "Dimensions:\n"
        "  session integrity:    not linked (no session supplied)\n"
        "  outcome verification: INCONCLUSIVE\n"
        "  monitoring health:    not configured (snapshot evaluation)\n"
        "  incident handling:    not tracked\n"
        "Observations:\n"
        "  source: 2 records, complete, observed time unknown (user_file, envelope)\n"
        "  target: 1 records, partial, observed time unknown (user_file, envelope)\n"
        "Items: 2 work items from 2 source rows; VERIFIED 1, INCONCLUSIVE 1\n"
        "Items needing attention (first 50):\n"
        "  INCONCLUSIVE  (source record 2, no key)\n"
        "      the source record has no value for a key field\n"
        "Outcome reasons:\n"
        "  - some_items_inconclusive: at least one item could not be decided\n"
        "Contract warnings:\n"
        "  - no active exists/count condition: a missing target record cannot be reported "
        "as a violation\n"
        "  - no due window declared: absence is judged at the evaluation instant\n"
        "Limitations:\n"
        f"{_LIMITS}"
    )


def test_verified_report_has_no_attention_section_or_warnings(tmp_path: Path) -> None:
    spec = contract({"id": "exists", "type": "exists"}, due=due())
    report = run(tmp_path, spec, [{"id": "1", "at": T0}], [{"ref": "1"}])
    text = report.render_human()
    assert text.startswith("SessLint outcome: VERIFIED  (")
    assert "DEMO" not in text
    assert "Items needing attention" not in text
    assert "Contract warnings" not in text
    assert "match no source item" not in text
    assert "Items: 1 work items from 1 source rows; VERIFIED 1\n" in text
    assert "  - all_items_verified:" in text


def test_attention_list_is_capped_at_fifty(tmp_path: Path) -> None:
    spec = contract({"id": "exists", "type": "exists"}, due=due())
    report = run(tmp_path, spec, [{"id": str(n), "at": T0} for n in range(53)], [])
    lines = report.render_human().split("\n")
    assert sum(1 for ln in lines if ln.startswith("  VIOLATED      ")) == 50
    assert "Items needing attention (first 50):" in lines
    assert "  ... 3 more (use --json)" in lines
    exactly = run(tmp_path, spec, [{"id": str(n), "at": T0} for n in range(50)], [])
    assert "more (use --json)" not in exactly.render_human()
    assert sum(ln.startswith("  VIOLATED      ") for ln in exactly.render_human().split("\n")) == 50
