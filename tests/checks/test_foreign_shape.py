"""Tests for SL305 provider-incompatible record shape (detector-depth T-05).

Codex-rollout-scoped shape-vocabulary check (evidence-assurance T-02
memo — GO verdict): ``reasoning`` items carrying a non-null ``content``
value are outside the official replay vocabulary (openai/codex#36551 —
official shape is ``content: null`` or absent, "Expected maximum length
0"). The detector never claims provider provenance; it proves only that
a cited foreign shape is present. Non-codex adapters skip via coverage
``adapter-not-applicable``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sesslint.adapters.codex_rollout import load_codex_rollout
from sesslint.api import check_file
from sesslint.canonical import SessionEvent
from sesslint.checks.foreign_shape import check_foreign_shape
from sesslint.checks.runner import run_all_checks
from sesslint.context import CheckContext
from sesslint.finding import Severity

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"
CODEX = FIXTURES_DIR / "adapters" / "codex"
CONFORMANCE_HEALTHY = FIXTURES_DIR / "conformance" / "codex_rollout" / "healthy.jsonl"

FOREIGN = CODEX / "sl305_foreign_reasoning.jsonl"
NULL_CONTENT = CODEX / "sl305_null_content.jsonl"
MIXED = CODEX / "sl305_mixed_splice.jsonl"


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
                        "timestamp": "2026-09-21T10:00:00Z",
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


def _reasoning(rid: str, **kw: Any) -> dict[str, Any]:
    return {"type": "reasoning", "id": rid, **kw}


# --- Positive quadrant: official shapes stay clean -----------------------


def test_conformance_healthy_stays_clean() -> None:
    report = check_file(CONFORMANCE_HEALTHY, format="codex-rollout")
    assert [f.code for f in report.findings if f.code == "SL305"] == []


def test_null_content_fixture_clean() -> None:
    report = check_file(NULL_CONTENT, format="codex-rollout")
    assert [f.code for f in report.findings if f.code == "SL305"] == []


def test_absent_and_null_content_silent(tmp_path: Path) -> None:
    # Official vocabulary: content absent or null — never fires.
    p = _rollout(
        tmp_path,
        [
            (0, "session_meta", {"session_id": "s"}),
            (1, "response_item", _reasoning("r1", content=None, encrypted_content="e")),
            (2, "response_item", _reasoning("r2", encrypted_content="e")),
        ],
    )
    report = check_file(p, format="codex-rollout")
    assert [f.code for f in report.findings if f.code == "SL305"] == []


def test_non_reasoning_content_ignored(tmp_path: Path) -> None:
    # message items legitimately carry content arrays — never foreign.
    p = _rollout(
        tmp_path,
        [
            (0, "session_meta", {"session_id": "s"}),
            (1, "response_item", _msg("m1", "user")),
            (2, "response_item", _msg("m2")),
        ],
    )
    report = check_file(p, format="codex-rollout")
    assert [f.code for f in report.findings if f.code == "SL305"] == []


# --- Negative quadrant: foreign shape fires once -------------------------


def test_foreign_reasoning_fires_once() -> None:
    report = check_file(FOREIGN, format="codex-rollout")
    sl = [f for f in report.findings if f.code == "SL305"]
    assert len(sl) == 1
    f = sl[0]
    assert f.severity == Severity.WARNING
    assert f.source.line == 3
    ev = f.evidence
    assert ev["shape_violation"] == "reasoning-content-non-null"
    assert ev["item_family"] == "reasoning"
    assert ev["item_count"] == 2
    assert ev["first_ordinal"] == 2


def test_declared_provider_context_in_evidence() -> None:
    report = check_file(FOREIGN, format="codex-rollout")
    ev = [f for f in report.findings if f.code == "SL305"][0].evidence
    # sha256-8 hash, never the raw provider string.
    assert isinstance(ev["declared_provider_hash"], str)
    assert len(ev["declared_provider_hash"]) == 8
    assert ev["declared_originator_present"] is True


def test_non_dict_content_shape_fires(tmp_path: Path) -> None:
    # "other" shape class (non-null, non-list) is equally foreign.
    p = _rollout(
        tmp_path,
        [
            (0, "session_meta", {"session_id": "s"}),
            (1, "response_item", _reasoning("r1", content="raw-string")),
        ],
    )
    report = check_file(p, format="codex-rollout")
    sl = [f for f in report.findings if f.code == "SL305"]
    assert len(sl) == 1


def test_no_session_meta_no_provider_keys(tmp_path: Path) -> None:
    p = _rollout(
        tmp_path,
        [
            (0, "response_item", _msg("m1", "user")),
            (1, "response_item", _reasoning("r1", content=[{"type": "x"}])),
        ],
    )
    report = check_file(p, format="codex-rollout")
    sl = [f for f in report.findings if f.code == "SL305"]
    assert len(sl) == 1
    assert "declared_provider_hash" not in sl[0].evidence
    assert "declared_originator_present" not in sl[0].evidence


# --- Boundary quadrant ---------------------------------------------------


def test_mixed_splice_fires_alongside_sl206(tmp_path: Path) -> None:
    # Mixed encrypted_content presence → SL206 missing-required-field AND
    # SL305 foreign shape — complementary, not overlapping.
    report = check_file(MIXED, format="codex-rollout")
    codes = [f.code for f in report.findings]
    assert "SL305" in codes
    assert "SL206" in codes
    sl305 = [f for f in report.findings if f.code == "SL305"][0]
    assert sl305.evidence["item_count"] == 1
    sl206 = [f for f in report.findings if f.code == "SL206"][0]
    assert sl206.evidence["divergence"] == "missing-required-field"


def test_uniform_foreign_without_encrypted_silent_sl206(tmp_path: Path) -> None:
    # Uniform-foreign file: SL206 stays silent (uniform absence of
    # encrypted_content is unprovable) — SL305 carries the signal.
    p = _rollout(
        tmp_path,
        [
            (0, "session_meta", {"session_id": "s"}),
            (1, "response_item", _reasoning("r1", content=[{"type": "x"}])),
            (2, "response_item", _reasoning("r2", content=[{"type": "x"}])),
        ],
    )
    report = check_file(p, format="codex-rollout")
    assert [f.code for f in report.findings if f.code == "SL305"] == ["SL305"]
    assert [f.code for f in report.findings if f.code == "SL206"] == []


def test_no_markers_silent() -> None:
    events = [_ev("a", 1), _ev("b", 2)]
    assert check_foreign_shape(events, source_path="t", context=_ctx()) == []


# --- Malformed quadrant: garbage marker shapes ignored -------------------


def test_malformed_markers_ignored() -> None:
    events = [
        _ev("a", 1, codex="not-a-mapping"),  # type: ignore[arg-type]
        _ev("b", 2, codex={"item_type": 5, "reasoning_content_shape": "array"}),
        _ev("c", 3, codex={"item_type": "reasoning", "reasoning_content_shape": True}),
        _ev("d", 4, codex={"item_type": "reasoning", "reasoning_content_shape": "alien"}),
        _ev("e", 5, codex={"item_type": "reasoning"}),  # no shape key
    ]
    assert check_foreign_shape(events, source_path="t", context=_ctx()) == []


# --- Adapter scope, selection, determinism, privacy -----------------------


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
    assert [f.code for f in findings if f.code == "SL305"] == []
    assert "SL305" not in cov.performed
    assert ("SL305", "adapter-not-applicable") in {(s.check, s.reason) for s in cov.skipped}
    assert ("shape", "adapter-not-applicable") in {(s.check, s.reason) for s in cov.skipped}


def test_select_sl305_runs() -> None:
    report = check_file(FOREIGN, format="codex-rollout", select=["SL305"])
    assert [f.code for f in report.findings] == ["SL305"]


def test_ignore_sl305_suppresses() -> None:
    report = check_file(FOREIGN, format="codex-rollout", ignore=["SL305"])
    assert [f.code for f in report.findings] == []


def test_determinism_replay_identical() -> None:
    r1 = check_file(FOREIGN, format="codex-rollout")
    r2 = check_file(FOREIGN, format="codex-rollout")
    f1 = [f for f in r1.findings if f.code == "SL305"][0]
    f2 = [f for f in r2.findings if f.code == "SL305"][0]
    assert f1 == f2
    assert f1.fingerprint == f2.fingerprint


def test_content_free_evidence() -> None:
    report = check_file(FOREIGN, format="codex-rollout")
    blob = json.dumps(report.to_dict(), sort_keys=True)
    # Payload text and raw provider name must never appear.
    assert "reasoning_text" not in blob
    assert "third-party-syn" not in blob
    for f in report.findings:
        if f.code == "SL305":
            for k, v in f.evidence.items():
                assert isinstance(v, (int, str, bool))
                if isinstance(v, str) and k != "declared_provider_hash":
                    assert v in (
                        "reasoning-content-non-null",
                        "reasoning",
                    ), f"unexpected evidence string {v!r} at {k}"


def test_adapter_populates_shape_marker(tmp_path: Path) -> None:
    p = _rollout(
        tmp_path,
        [
            (0, "session_meta", {"session_id": "s"}),
            (1, "response_item", _reasoning("r1", content=[{"type": "x"}])),
            (2, "response_item", _reasoning("r2", content=None)),
            (3, "response_item", _reasoning("r3")),
        ],
    )
    events, _findings = load_codex_rollout(p)
    shapes = [ev.extra_fields["codex"].get("reasoning_content_shape") for ev in events[1:]]
    assert shapes == ["array", "null", "absent"]
