"""Unit and adversarial tests for the SL304 mid-file schema drift detector.

Drift = a schema-version marker changes between individually supported
values, or a record's envelope ``type`` is discriminative for a different
vendor format. SL301 firing anywhere in the file suppresses all SL304
output (documented precedence). Evidence is structural only.
"""

from __future__ import annotations

from pathlib import Path

from sesslint.adapters.drift import FOREIGN_SIGNATURE_TYPES, MAX_DRIFT_TRANSITIONS, DriftTracker
from sesslint.api import check_file
from sesslint.codes import SL301, SL304, Severity
from sesslint.profiles.profile import apply_rule_selection, get_profile

FIXTURES_CHECKS_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "checks"


def _sl304(findings: list) -> list:
    return [f for f in findings if f.code == SL304]


def _load(fixture: str):
    from sesslint.adapters.claude_code import load_claude_code

    return load_claude_code(FIXTURES_CHECKS_DIR / fixture)


# --- DriftTracker unit semantics -----------------------------------------


def test_tracker_version_chain() -> None:
    """First supported marker baselines; each differing marker transitions."""
    t = DriftTracker("claude-code-jsonl")
    t.observe_version("1", supported=True, field="schemaVersion")
    t.observe_version("1", supported=True, field="schemaVersion")  # same → silent
    t.observe_version("0.1", supported=True, field="schemaVersion")
    out = t.into_findings(path_str="x")
    assert len(out) == 1
    ev = out[0].evidence
    assert ev["drift_kind"] == "version"
    assert ev["previous_marker"] == "1"
    assert ev["observed_marker"] == "0.1"


def test_tracker_unsupported_suppresses_all() -> None:
    """An unsupported marker suppresses every buffered transition."""
    t = DriftTracker("codex-rollout")
    t.observe_version("1", supported=True, field="version")
    t.observe_version("2", supported=True, field="version")
    t.observe_signature("summary")
    t.observe_version("9.9", supported=False, field="version")
    assert t.into_findings(path_str="x") == []


def test_tracker_signature_foreign_only() -> None:
    """Foreign discriminative types fire; own/shared/unknown types don't."""
    t = DriftTracker("claude-code-jsonl")
    t.observe_signature("turn_context")  # codex → fire
    t.observe_signature("summary")  # own format → silent
    t.observe_signature("user")  # shared vocabulary → silent
    t.observe_signature("nonsense-xyz")  # unknown → silent
    t.observe_signature(123)  # non-string → silent
    out = t.into_findings(path_str="x")
    assert len(out) == 1
    ev = out[0].evidence
    assert ev["drift_kind"] == "signature"
    assert ev["observed_marker"] == "turn_context"
    assert ev["observed_format"] == "codex-rollout"


def test_tracker_signature_dedupes_and_caps() -> None:
    """Identical transitions collapse; total stays under the cap."""
    t = DriftTracker("canonical")
    for _ in range(3):
        t.observe_signature("turn_context")
    for raw_type in sorted(FOREIGN_SIGNATURE_TYPES):
        t.observe_signature(raw_type)
    out = t.into_findings(path_str="x")
    sig = [f for f in out if f.evidence["drift_kind"] == "signature"]
    assert len(sig) == min(len(FOREIGN_SIGNATURE_TYPES), MAX_DRIFT_TRANSITIONS)
    assert len(out) <= MAX_DRIFT_TRANSITIONS


def test_evidence_is_structural() -> None:
    """Evidence keys stay bounded/content-free; no payload text leaks."""
    t = DriftTracker("claude-code-jsonl")
    t.observe_signature("turn_context", line=3, record_id="r1", record_ordinal=3)
    [f] = t.into_findings(path_str="x")
    assert set(f.evidence) <= {
        "drift_kind",
        "previous_marker",
        "observed_marker",
        "observed_format",
        "field",
        "record_index",
        "byte_offset",
        "byte_end",
    }
    assert f.severity == Severity.WARNING


# --- Adapter-level fixtures ----------------------------------------------


def test_fixture_foreign_splice() -> None:
    """turn_context inside a claude stream → exactly one signature SL304."""
    _events, findings = _load("sl304_foreign_splice.jsonl")
    hits = _sl304(findings)
    assert len(hits) == 1
    assert hits[0].evidence["drift_kind"] == "signature"
    assert hits[0].evidence["observed_format"] == "codex-rollout"
    assert hits[0].severity == Severity.WARNING


def test_fixture_version_drift() -> None:
    """schemaVersion 1 → 0.1 mid-file → exactly one version SL304."""
    _events, findings = _load("sl304_version_drift.jsonl")
    hits = _sl304(findings)
    assert len(hits) == 1
    assert hits[0].evidence["drift_kind"] == "version"
    assert hits[0].evidence["previous_marker"] == "1"
    assert hits[0].evidence["observed_marker"] == "0.1"


def test_fixture_compatible_bump_clean() -> None:
    """Application-version bumps (2.0.30 → 2.1.0) never fire."""
    _events, findings = _load("sl304_compatible_bump.jsonl")
    assert _sl304(findings) == []


def test_fixture_unsupported_precedence() -> None:
    """Unsupported schema marker → SL301 only; SL304 suppressed."""
    _events, findings = _load("sl304_unsupported_version.jsonl")
    assert _sl304(findings) == []
    assert any(f.code == SL301 for f in findings)


def test_fixture_multi_transition_cap() -> None:
    """Nine distinct transitions → exactly MAX_DRIFT_TRANSITIONS findings."""
    _events, findings = _load("sl304_multi_transition.jsonl")
    assert len(_sl304(findings)) == MAX_DRIFT_TRANSITIONS


def test_codex_version_drift(tmp_path: Path) -> None:
    """Codex rollout_version markers drift → one version SL304."""
    from sesslint.adapters.codex_rollout import load_codex_rollout

    f = tmp_path / "roll.jsonl"
    f.write_text(
        '{"timestamp":"2024-01-01T10:00:00Z","type":"session_meta","rollout_version":"1","payload":{"id":"s1"}}\n'
        '{"timestamp":"2024-01-01T10:01:00Z","type":"response_item","rollout_version":"codex-rollout-v1","payload":{"id":"e1","type":"message","role":"user","content":[{"type":"text","text":"hi"}]}}\n',
        encoding="utf-8",
    )
    _events, findings = load_codex_rollout(f)
    hits = _sl304(findings)
    assert len(hits) == 1
    assert hits[0].evidence["drift_kind"] == "version"
    assert hits[0].evidence["field"] == "rollout_version"


# --- Gating + determinism -------------------------------------------------


def test_gating_via_rule_selection() -> None:
    """Deselecting SL304 filters its findings out of the report."""
    report = check_file(
        FIXTURES_CHECKS_DIR / "sl304_foreign_splice.jsonl", format="claude-code-jsonl"
    )
    assert _sl304(report.findings), "precondition: SL304 should fire unfiltered"
    profile = get_profile("neutral")
    selected = apply_rule_selection(profile, ignore={SL304})
    report2 = check_file(
        FIXTURES_CHECKS_DIR / "sl304_foreign_splice.jsonl",
        format="claude-code-jsonl",
        profile=selected,
    )
    assert _sl304(report2.findings) == []


def test_determinism() -> None:
    """Same input → identical findings (fingerprint-stable)."""
    a = check_file(FIXTURES_CHECKS_DIR / "sl304_multi_transition.jsonl", format="claude-code-jsonl")
    b = check_file(FIXTURES_CHECKS_DIR / "sl304_multi_transition.jsonl", format="claude-code-jsonl")
    assert [f.fingerprint for f in a.findings] == [f.fingerprint for f in b.findings]
