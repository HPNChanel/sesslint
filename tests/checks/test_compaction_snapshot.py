"""Tests for SL208 compaction-snapshot divergence (detector-depth T-04).

Codex-rollout-scoped: ``compacted`` records embed the vendor's own
pre-compaction snapshot (``guardian_history``). For item ids shared with
the durable stream the snapshot's declared type, correlator, and ordering
must agree — divergence is provable on disk. Snapshot-only ids,
intra-snapshot pairing, and items absent from the snapshot are all
deliberately unprovable and stay silent. Non-codex adapters skip via
coverage ``adapter-not-applicable``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sesslint.adapters.codex_rollout import load_codex_rollout
from sesslint.api import check_file
from sesslint.canonical import SessionEvent
from sesslint.checks.compaction_snapshot import check_compaction_snapshot
from sesslint.checks.runner import run_all_checks
from sesslint.context import CheckContext
from sesslint.profiles.builtin import NEUTRAL_PROFILE
from sesslint.profiles.profile import apply_rule_selection

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"
CODEX = FIXTURES_DIR / "adapters" / "codex"

TYPE_MISMATCH = CODEX / "sl208_type_mismatch.jsonl"
CORR_MISMATCH = CODEX / "sl208_correlation_mismatch.jsonl"
FUTURE_ITEM = CODEX / "sl208_future_item.jsonl"
HEALTHY_SNAPSHOT = CODEX / "sl208_healthy.jsonl"


def _ev(
    eid: str,
    line: int,
    *,
    kind: str = "message",
    codex: dict[str, Any] | None = None,
    loc: str = "t.jsonl",
) -> SessionEvent:
    extra: dict[str, Any] = {"codex": codex} if codex is not None else {}
    return SessionEvent(
        id=eid,
        parent_id=None,
        seq=line,
        ts="",
        actor="assistant",
        kind=kind,
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


def _boundary(line: int, items: list[dict[str, Any]]) -> SessionEvent:
    return _ev(
        f"cmp_{line}",
        line,
        kind="compaction_boundary",
        codex={"guardian_items": items, "guardian_items_total": len(items)},
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


# --- unit-level: matching snapshot stays silent ----------------------------


def test_agreeing_snapshot_silent() -> None:
    events = [
        _ev("msg_a", 1, codex={"item_type": "message"}),
        _ev("fc_1", 2, kind="tool_call", codex={"item_type": "function_call", "call_id": "c1"}),
        _boundary(
            3,
            [
                {"id": "msg_a", "type": "message", "call_id": None},
                {"id": "fc_1", "type": "function_call", "call_id": "c1"},
            ],
        ),
    ]
    assert check_compaction_snapshot(events, context=_ctx()) == []


def test_snapshot_only_ids_silent() -> None:
    # Snapshot cites ids absent from this file's stream — may be inherited
    # parent context; absence from one representation is never proof.
    events = [
        _ev("msg_a", 1, codex={"item_type": "message"}),
        _boundary(
            2,
            [
                {"id": "msg_a", "type": "message", "call_id": None},
                {"id": "inherited_x", "type": "reasoning", "call_id": None},
                {"id": "inherited_y", "type": "function_call", "call_id": "zz"},
            ],
        ),
    ]
    assert check_compaction_snapshot(events, context=_ctx()) == []


def test_intra_snapshot_orphan_silent() -> None:
    # An output inside the snapshot without its call is a rolling-window
    # edge, not corruption — the check never pairs inside the snapshot.
    events = [
        _ev("msg_a", 1, codex={"item_type": "message"}),
        _boundary(
            2,
            [
                {"id": "out_edge", "type": "function_call_output", "call_id": "call_gone"},
            ],
        ),
    ]
    assert check_compaction_snapshot(events, context=_ctx()) == []


def test_no_snapshot_marker_silent() -> None:
    events = [
        _ev("msg_a", 1, codex={"item_type": "message"}),
        _ev("cmp_2", 2, kind="compaction_boundary", codex={"durable": True}),
    ]
    assert check_compaction_snapshot(events, context=_ctx()) == []


def test_empty_snapshot_silent() -> None:
    events = [
        _ev("msg_a", 1, codex={"item_type": "message"}),
        _boundary(2, []),
    ]
    assert check_compaction_snapshot(events, context=_ctx()) == []


# --- unit-level: divergence kinds fire once each ---------------------------


def test_type_mismatch_fires_once() -> None:
    events = [
        _ev("msg_a", 1, codex={"item_type": "message"}),
        _boundary(
            2,
            [
                {"id": "msg_a", "type": "reasoning", "call_id": None},
                {"id": "msg_a", "type": "reasoning", "call_id": None},
            ],
        ),
    ]
    findings = check_compaction_snapshot(events, context=_ctx())
    assert len(findings) == 1
    f = findings[0]
    assert f.code == "SL208"
    assert f.severity.value == "warning"
    assert f.evidence["divergence"] == "type-mismatch"
    assert f.evidence["item_id"] == "msg_a"
    assert f.evidence["occurrences"] == 2
    assert f.evidence["snapshot_item_type"] == "reasoning"
    assert f.evidence["stream_item_type"] == "message"


def test_correlation_mismatch_fires() -> None:
    events = [
        _ev("fc_1", 1, kind="tool_call", codex={"item_type": "function_call", "call_id": "c1"}),
        _boundary(2, [{"id": "fc_1", "type": "function_call", "call_id": "c9"}]),
    ]
    findings = check_compaction_snapshot(events, context=_ctx())
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["divergence"] == "correlation-mismatch"
    assert f.evidence["snapshot_correlator"] == "c9"
    assert f.evidence["stream_correlator"] == "c1"


def test_correlation_presence_mismatch_fires() -> None:
    # Stream declares no correlator; snapshot declares one — presence
    # disagreement is still a contradiction between vendor claims.
    events = [
        _ev("msg_a", 1, codex={"item_type": "message"}),
        _boundary(2, [{"id": "msg_a", "type": "message", "call_id": "c9"}]),
    ]
    findings = check_compaction_snapshot(events, context=_ctx())
    assert len(findings) == 1
    assert findings[0].evidence["divergence"] == "correlation-mismatch"
    assert findings[0].evidence["snapshot_correlator"] == "c9"
    assert findings[0].evidence["stream_correlator"] is None


def test_future_item_fires() -> None:
    # Boundary at index 0 cites an item first written at index 2 — the
    # snapshot claims history the stream had not yet written.
    events = [
        _boundary(1, [{"id": "msg_late", "type": "message", "call_id": None}]),
        _ev("msg_late", 2, codex={"item_type": "message"}),
    ]
    findings = check_compaction_snapshot(events, context=_ctx())
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["divergence"] == "future-item"
    assert f.evidence["item_id"] == "msg_late"
    assert f.evidence["boundary_index"] == 0
    assert f.evidence["item_index"] == 1


def test_id_reuse_does_not_mask_or_false_flag() -> None:
    # The earliest durable claim wins: an item present pre-boundary that is
    # rewritten post-boundary under the same id is ambiguous — silent.
    events = [
        _ev("msg_a", 1, codex={"item_type": "message"}),
        _boundary(2, [{"id": "msg_a", "type": "message", "call_id": None}]),
        _ev("msg_a", 3, codex={"item_type": "message"}),
    ]
    assert check_compaction_snapshot(events, context=_ctx()) == []


def test_all_three_kinds_emit_together() -> None:
    events = [
        _boundary(
            1,
            [
                {"id": "a", "type": "reasoning", "call_id": None},
                {"id": "b", "type": "function_call", "call_id": "x"},
                {"id": "c", "type": "message", "call_id": None},
            ],
        ),
        _ev("a", 2, codex={"item_type": "message"}),
        _ev("b", 3, codex={"item_type": "function_call", "call_id": "y"}),
        # "c" only appears after the boundary -> future-item
        _ev("c", 4, codex={"item_type": "message"}),
    ]
    findings = check_compaction_snapshot(events, context=_ctx())
    kinds = {f.evidence["divergence"] for f in findings}
    assert kinds == {"type-mismatch", "correlation-mismatch", "future-item"}
    assert len(findings) == 3


def test_malformed_markers_ignored() -> None:
    events = [
        _ev("msg_a", 1, codex={"item_type": "message"}),
        _ev("cmp_2", 2, kind="compaction_boundary", codex={"guardian_items": "not-a-list"}),
        _ev("cmp_3", 3, kind="compaction_boundary", codex={"guardian_items": [42, None, "x"]}),
        _boundary(4, [{"id": 7, "type": "message"}, {"type": "message"}]),
    ]
    assert check_compaction_snapshot(events, context=_ctx()) == []


def test_no_markers_at_all_silent() -> None:
    events = [_ev("a", 1), _ev("b", 2, kind="compaction_boundary")]
    assert check_compaction_snapshot(events, context=_ctx()) == []


def test_empty_events_silent() -> None:
    assert check_compaction_snapshot([], context=_ctx()) == []


# --- runner gating ----------------------------------------------------------


def test_runner_skips_on_non_codex_adapter() -> None:
    events = [
        _ev("msg_a", 1, codex={"item_type": "message"}),
        _boundary(2, [{"id": "msg_a", "type": "reasoning", "call_id": None}]),
    ]
    findings, cov = run_all_checks(events, adapter="canonical", return_coverage=True)
    assert not [f for f in findings if f.code == "SL208"]
    skips = {s.check: s.reason for s in cov.skipped}
    assert skips.get("SL208") == "adapter-not-applicable"


def test_runner_performs_on_codex() -> None:
    events = [
        _ev("msg_a", 1, codex={"item_type": "message"}),
        _boundary(2, [{"id": "msg_a", "type": "reasoning", "call_id": None}]),
    ]
    findings, cov = run_all_checks(events, adapter="codex-rollout", return_coverage=True)
    assert "SL208" in cov.performed
    assert [f for f in findings if f.code == "SL208"]


def test_deselected_sl208_marks_deselected_skip() -> None:
    # Deselection is applied to the profile's enabled_rules by the caller;
    # deselected_rules marks the skip reason honestly in coverage.
    prof = apply_rule_selection(NEUTRAL_PROFILE, ignore=["SL208"])
    events = [
        _ev("msg_a", 1, codex={"item_type": "message"}),
        _boundary(2, [{"id": "msg_a", "type": "reasoning", "call_id": None}]),
    ]
    findings, cov = run_all_checks(
        events,
        profile=prof,
        adapter="codex-rollout",
        deselected_rules={"SL208"},
        return_coverage=True,
    )
    assert not [f for f in findings if f.code == "SL208"]
    skips = {s.check: s.reason for s in cov.skipped}
    assert skips.get("SL208") == "deselected"


# --- adapter marker projection (e2e over raw rollout bytes) -----------------


def test_adapter_projects_guardian_items(tmp_path: Path) -> None:
    p = _rollout(
        tmp_path,
        [
            (0, "session_meta", {"session_id": "s1", "cli_version": "0.42.0"}),
            (
                1,
                "response_item",
                {"type": "function_call", "id": "fc_1", "call_id": "c1", "name": "sh"},
            ),
            (
                2,
                "compacted",
                {
                    "message": "x",
                    "guardian_history": [
                        {"type": "function_call", "id": "fc_1", "call_id": "c1"},
                        {"type": "reasoning", "id": "rs_9", "summary": []},
                        "not-a-dict",
                    ],
                },
            ),
        ],
    )
    events, _ = load_codex_rollout(p)
    boundary = [e for e in events if e.kind == "compaction_boundary"][0]
    marker = boundary.extra_fields["codex"]
    assert marker["guardian_items_total"] == 3
    assert marker["guardian_items"] == [
        {"id": "fc_1", "type": "function_call", "call_id": "c1"},
        {"id": "rs_9", "type": "reasoning", "call_id": None},
    ]
    call_ev = [e for e in events if e.id == "fc_1"][0]
    assert call_ev.extra_fields["codex"]["call_id"] == "c1"


def test_adapter_never_projects_snapshot_content(tmp_path: Path) -> None:
    secret_text = "super-sensitive-payload-body-xyzzy"
    p = _rollout(
        tmp_path,
        [
            (0, "session_meta", {"session_id": "s1", "cli_version": "0.42.0"}),
            (
                1,
                "compacted",
                {
                    "message": "x",
                    "guardian_history": [
                        {
                            "type": "message",
                            "id": "msg_a",
                            "role": "user",
                            "content": [{"type": "input_text", "text": secret_text}],
                            "output": secret_text,
                        }
                    ],
                },
            ),
        ],
    )
    events, _ = load_codex_rollout(p)
    boundary = [e for e in events if e.kind == "compaction_boundary"][0]
    marker = boundary.extra_fields["codex"]
    projected = json.dumps(marker["guardian_items"])
    assert secret_text not in projected
    assert marker["guardian_items"] == [{"id": "msg_a", "type": "message", "call_id": None}]


def test_snapshot_cap_bounds_projection(tmp_path: Path) -> None:
    big = [{"type": "message", "id": f"m{i}"} for i in range(600)]
    p = _rollout(
        tmp_path,
        [
            (0, "session_meta", {"session_id": "s1", "cli_version": "0.42.0"}),
            (1, "compacted", {"message": "x", "guardian_history": big}),
        ],
    )
    events, _ = load_codex_rollout(p)
    marker = [e for e in events if e.kind == "compaction_boundary"][0].extra_fields["codex"]
    assert len(marker["guardian_items"]) == 512
    assert marker["guardian_items_total"] == 600
    assert marker["guardian_items_truncated"] is True


def test_e2e_fixture_fires_via_check_file() -> None:
    report = check_file(TYPE_MISMATCH, format="codex-rollout")
    assert [f for f in report.findings if f.code == "SL208"]


def test_e2e_healthy_fixture_silent() -> None:
    report = check_file(HEALTHY_SNAPSHOT, format="codex-rollout")
    assert not [f for f in report.findings if f.code == "SL208"]


def test_fixture_files_exist() -> None:
    for f in (TYPE_MISMATCH, CORR_MISMATCH, FUTURE_ITEM, HEALTHY_SNAPSHOT):
        assert f.is_file(), f"missing fixture {f}"
