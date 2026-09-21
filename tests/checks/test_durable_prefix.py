"""Tests for SL206 durable-prefix boundary (detector-depth T-03).

Codex-rollout-scoped: the paginated resume path expects a contiguous
durable record sequence through the inherited-prefix ordinal. Three
divergence kinds, ≤ one finding each per file: ``trailing-non-durable``
(#40747 tail), ``durable-gap`` (hole inside the durable range),
``missing-required-field`` (#19661 reasoning/encrypted_content mix).
Non-codex adapters skip via coverage ``adapter-not-applicable``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sesslint.adapters.codex_rollout import load_codex_rollout
from sesslint.api import check_file
from sesslint.canonical import SessionEvent
from sesslint.checks.durable_prefix import check_durable_prefix
from sesslint.checks.runner import run_all_checks
from sesslint.context import CheckContext
from sesslint.finding import Severity

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"
CODEX = FIXTURES_DIR / "adapters" / "codex"
CONFORMANCE_HEALTHY = FIXTURES_DIR / "conformance" / "codex_rollout" / "healthy.jsonl"

TRAILING = CODEX / "sl206_trailing_nondurable.jsonl"
GAP = CODEX / "sl206_durable_gap.jsonl"
FIELD = CODEX / "sl206_missing_field.jsonl"
HEALTHY_MIN = CODEX / "healthy_min.jsonl"


def _ev(
    eid: str,
    line: int,
    *,
    codex: dict[str, Any] | None = None,
    loc: str = "t.jsonl",
) -> SessionEvent:
    extra: dict[str, Any] = {"codex": codex} if codex is not None else {}
    return SessionEvent(
        id=eid,
        parent_id=None,
        seq=0,
        ts="",
        actor="assistant",
        kind="message",
        source_line=line,
        source_adapter="codex-rollout",
        source_location=loc,
        extra_fields=extra,
    )


def _ctx() -> CheckContext:
    return CheckContext(
        adapter_id="codex-rollout",
        adapter_version="1.0.0",
        profile_id="neutral",
        profile_version="1.0.0",
    )


def _rollout(tmp_path: Path, rows: list[tuple[int, str, dict[str, Any]]]) -> Path:
    p = tmp_path / "rollout-t.jsonl"
    with open(p, "w", newline="\n") as fh:
        for ordinal, etype, payload in rows:
            fh.write(
                json.dumps(
                    {
                        "ordinal": ordinal,
                        "type": etype,
                        "timestamp": "2026-09-17T10:00:00Z",
                        "payload": payload,
                    }
                )
                + "\n"
            )
    return p


def _msg(mid: str, role: str = "assistant") -> dict[str, Any]:
    return {
        "type": "message",
        "role": role,
        "id": mid,
        "content": [{"type": "output_text", "text": "x"}],
    }


# --- Positive quadrant: healthy rollouts stay clean ---------------------


def test_conformance_healthy_stays_clean() -> None:
    report = check_file(CONFORMANCE_HEALTHY, format="codex-rollout")
    assert [f.code for f in report.findings if f.code == "SL206"] == []


def test_healthy_min_stays_clean() -> None:
    report = check_file(HEALTHY_MIN, format="codex-rollout")
    assert [f.code for f in report.findings if f.code == "SL206"] == []


def test_nondurable_interleave_is_legitimate(tmp_path: Path) -> None:
    # event_msg mid-file inside the durable range is normal telemetry
    # interleave, not a durable hole.
    p = _rollout(
        tmp_path,
        [
            (0, "session_meta", {"session_id": "s"}),
            (1, "response_item", _msg("m1", "user")),
            (2, "event_msg", {"type": "task_started"}),
            (3, "response_item", _msg("m3")),
            (4, "turn_context", {"turn_id": "t1"}),
            (5, "response_item", _msg("m5")),
        ],
    )
    report = check_file(p, format="codex-rollout")
    assert [f.code for f in report.findings if f.code == "SL206"] == []


# --- Negative quadrant: each divergence fires once ----------------------


def test_trailing_nondurable_fires_once_with_ordinals() -> None:
    report = check_file(TRAILING, format="codex-rollout")
    sl = [f for f in report.findings if f.code == "SL206"]
    assert len(sl) == 1
    f = sl[0]
    assert f.severity == Severity.WARNING
    assert f.source.line == 6
    assert f.evidence["divergence"] == "trailing-non-durable"
    assert f.evidence["expected_durable_ordinal"] == 5
    assert f.evidence["last_durable_ordinal"] == 4
    assert f.evidence["tail_ordinal"] == 5
    assert f.evidence["tail_envelope_family"] == "event_msg"
    assert f.evidence["inherited_prefix_ordinal"] == 5


def test_trailing_requires_inherited_prefix_claim(tmp_path: Path) -> None:
    # #40747 shape: the claim itself sits on the non-durable tail record.
    p = _rollout(
        tmp_path,
        [
            (
                0,
                "session_meta",
                {"session_id": "s", "subagent_history_start_ordinal": 4},
            ),
            (1, "response_item", _msg("m1", "user")),
            (2, "response_item", _msg("m2")),
            (3, "response_item", _msg("m3")),
            (4, "event_msg", {"type": "token_count", "usage": {}}),
        ],
    )
    report = check_file(p, format="codex-rollout")
    sl = [f for f in report.findings if f.code == "SL206"]
    assert len(sl) == 1
    assert sl[0].evidence["inherited_prefix_ordinal"] == 4
    assert sl[0].evidence["expected_durable_ordinal"] == 4


def test_bare_telemetry_tail_without_claim_silent(tmp_path: Path) -> None:
    # Normal rollout shape: telemetry records trail the durable prefix but
    # no inherited-prefix claim exists — nothing provably breaks.
    p = _rollout(
        tmp_path,
        [
            (0, "session_meta", {"session_id": "s"}),
            (1, "response_item", _msg("m1", "user")),
            (2, "response_item", _msg("m2")),
            (3, "event_msg", {"type": "token_count", "usage": {}}),
            (4, "token_usage_record", {"input": 1, "output": 2}),
        ],
    )
    report = check_file(p, format="codex-rollout")
    assert [f.code for f in report.findings if f.code == "SL206"] == []


def test_claim_within_durable_coverage_silent(tmp_path: Path) -> None:
    # Claim satisfied by the durable prefix even though telemetry trails.
    p = _rollout(
        tmp_path,
        [
            (
                0,
                "session_meta",
                {"session_id": "s", "subagent_history_start_ordinal": 2},
            ),
            (1, "response_item", _msg("m1", "user")),
            (2, "response_item", _msg("m2")),
            (3, "event_msg", {"type": "token_count", "usage": {}}),
        ],
    )
    report = check_file(p, format="codex-rollout")
    assert [f.code for f in report.findings if f.code == "SL206"] == []


def test_durable_gap_fires_once() -> None:
    report = check_file(GAP, format="codex-rollout")
    sl = [f for f in report.findings if f.code == "SL206"]
    assert len(sl) == 1
    assert sl[0].source.line == 3
    assert sl[0].evidence["divergence"] == "durable-gap"
    assert sl[0].evidence["missing_ordinal"] == 2
    assert sl[0].evidence["last_durable_ordinal"] == 4


def test_missing_required_field_mixed_fires() -> None:
    report = check_file(FIELD, format="codex-rollout")
    sl = [f for f in report.findings if f.code == "SL206"]
    assert len(sl) == 1
    ev = sl[0].evidence
    assert ev["divergence"] == "missing-required-field"
    assert ev["field"] == "encrypted_content"
    assert ev["item_family"] == "reasoning"
    assert ev["missing_count"] == 1
    assert ev["present_count"] == 1
    assert ev["first_missing_ordinal"] == 2


def test_uniform_absence_of_field_silent(tmp_path: Path) -> None:
    # No sibling carries encrypted_content — cannot prove it is required.
    p = _rollout(
        tmp_path,
        [
            (0, "session_meta", {"session_id": "s"}),
            (1, "response_item", {"type": "reasoning", "id": "r1", "summary": []}),
            (2, "response_item", {"type": "reasoning", "id": "r2", "summary": []}),
        ],
    )
    report = check_file(p, format="codex-rollout")
    assert [f.code for f in report.findings if f.code == "SL206"] == []


# --- Boundary quadrant ---------------------------------------------------


def test_gap_beyond_durable_range_not_a_hole(tmp_path: Path) -> None:
    # Ordinal missing *after* the last durable record is covered by the
    # trailing rule's domain, not durable-gap.
    p = _rollout(
        tmp_path,
        [
            (0, "session_meta", {"session_id": "s"}),
            (1, "response_item", _msg("m1", "user")),
            (3, "event_msg", {"type": "token_count", "usage": {}}),
        ],
    )
    events, _ = load_codex_rollout(p)
    findings = check_durable_prefix(events, source_path=str(p), context=_ctx())
    divergences = {f.evidence["divergence"] for f in findings}
    assert "durable-gap" not in divergences


def test_no_ordinals_no_markers_silent() -> None:
    events = [_ev("a", 1), _ev("b", 2)]
    assert check_durable_prefix(events, source_path="t", context=_ctx()) == []


def test_zero_durable_records_silent() -> None:
    events = [
        _ev("a", 1, codex={"durable": False, "ordinal": 0, "envelope_type": "event_msg"}),
        _ev("b", 2, codex={"durable": False, "ordinal": 1, "envelope_type": "event_msg"}),
    ]
    assert check_durable_prefix(events, source_path="t", context=_ctx()) == []


# --- Malformed quadrant: garbage marker shapes ignored -------------------


def test_malformed_codex_markers_ignored() -> None:
    events = [
        _ev("a", 1, codex="not-a-mapping"),  # type: ignore[arg-type]
        _ev("b", 2, codex={"durable": "yes", "ordinal": "x"}),
        _ev("c", 3, codex={"durable": True, "ordinal": True}),  # bool ordinal
        _ev("d", 4, codex={"durable": True, "ordinal": 2, "envelope_type": "response_item"}),
    ]
    # Only ordinal 2 usable; no tail/gap provable.
    assert check_durable_prefix(events, source_path="t", context=_ctx()) == []


# --- Adapter scope, selection, determinism, privacy ----------------------


def test_non_codex_adapter_skips_rule() -> None:
    events = [_ev("a", 1), _ev("b", 2)]
    ctx = CheckContext(
        adapter_id="claude-code-jsonl",
        adapter_version="1.0.0",
        profile_id="neutral",
        profile_version="1.0.0",
    )
    findings, cov = run_all_checks(
        events,
        profile="neutral",
        source_path="t.jsonl",
        context=ctx,
        adapter="claude-code-jsonl",
        return_coverage=True,
    )
    assert [f.code for f in findings if f.code == "SL206"] == []
    assert "SL206" not in cov.performed
    assert ("SL206", "adapter-not-applicable") in {(s.check, s.reason) for s in cov.skipped}


def test_select_sl206_runs() -> None:
    report = check_file(TRAILING, format="codex-rollout", select=["SL206"])
    assert [f.code for f in report.findings] == ["SL206"]


def test_ignore_sl206_suppresses() -> None:
    report = check_file(TRAILING, format="codex-rollout", ignore=["SL206"])
    assert [f.code for f in report.findings] == []


def test_determinism_replay_identical() -> None:
    r1 = check_file(TRAILING, format="codex-rollout")
    r2 = check_file(TRAILING, format="codex-rollout")
    f1 = [f for f in r1.findings if f.code == "SL206"][0]
    f2 = [f for f in r2.findings if f.code == "SL206"][0]
    assert f1 == f2
    assert f1.fingerprint == f2.fingerprint


def test_content_free_evidence() -> None:
    report = check_file(TRAILING, format="codex-rollout")
    blob = json.dumps(report.to_dict(), sort_keys=True)
    for f in report.findings:
        if f.code == "SL206":
            ev = f.evidence
            # Structural values only: ints, enum labels, no payload text.
            for k, v in ev.items():
                assert isinstance(v, (int, str, type(None)))
                if isinstance(v, str):
                    assert v in (
                        "trailing-non-durable",
                        "durable-gap",
                        "missing-required-field",
                        "encrypted_content",
                        "reasoning",
                        "event_msg",
                        "response_item",
                        "session_meta",
                        "compacted",
                        "turn_context",
                        "world_state",
                        "token_usage_record",
                        "inter_agent_communication_metadata",
                    ), f"unexpected evidence string {v!r} at {k}"
    assert "token_count" not in blob or '"event_msg"' in blob


# --- Adapter marker extraction -------------------------------------------


def test_adapter_populates_codex_extra(tmp_path: Path) -> None:
    p = _rollout(
        tmp_path,
        [
            (0, "session_meta", {"session_id": "s", "subagent_history_start_ordinal": 2}),
            (1, "response_item", {"type": "reasoning", "id": "r1", "summary": []}),
            (2, "event_msg", {"type": "token_count", "usage": {}}),
        ],
    )
    events, _ = load_codex_rollout(p)
    m0 = events[0].extra_fields["codex"]
    assert m0["durable"] is True
    assert m0["ordinal"] == 0
    assert m0["envelope_type"] == "session_meta"
    assert m0["subagent_history_start_ordinal"] == 2
    m1 = events[1].extra_fields["codex"]
    assert m1["durable"] is True
    assert m1["item_type"] == "reasoning"
    assert m1["has_encrypted_content"] is False
    m2 = events[2].extra_fields["codex"]
    assert m2["durable"] is False
    assert m2["envelope_type"] == "event_msg"


@pytest.mark.parametrize("name", ["sl206_durable_gap", "sl206_missing_field"])
def test_violation_fixtures_fire_via_api(name: str) -> None:
    report = check_file(CODEX / f"{name}.jsonl", format="codex-rollout")
    assert [f.code for f in report.findings if f.code == "SL206"]
