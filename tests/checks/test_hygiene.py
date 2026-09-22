"""Tests for the SL009 persisted-secret-shape detector (transcript-hygiene T-01).

Contract under test:
- Raw persisted record bytes are scanned during the adapter's existing pass
  (no second read), including records that later fail JSON validation.
- Findings are content-free: family label + coordinates + occurrence count +
  SHA-256 digests of matched spans. The secret value is never emitted.
- Aggregation is one finding per (record, family); ordering is deterministic.
- Severity is WARNING / repairability MANUAL: default exit stays 0 and
  automated repair is refused (credentials must be rotated, not redacted).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from tests.utils.privacy import assert_no_pii

from sesslint.adapters.canonical import load_canonical
from sesslint.adapters.claude_code import load_claude_code
from sesslint.adapters.codex_rollout import load_codex_rollout
from sesslint.adapters.openai_agents import load_openai_agents
from sesslint.api import check_bytes, check_file
from sesslint.checks.hygiene import (
    MAX_DIGESTS_PER_FINDING,
    MAX_SECRET_FINDINGS_PER_FILE,
    SECRET_FAMILY_SET_VERSION,
    SecretScanTracker,
)
from sesslint.cli import main
from sesslint.codes import SL009, Repairability, Severity
from sesslint.finding import Finding
from sesslint.io import iter_events

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "checks" / "secret_seed"
CONFORMANCE_DIR = (
    Path(__file__).resolve().parent.parent.parent / "fixtures" / "conformance" / "secret_seed"
)

# Synthetic canaries — generated non-functional shapes only, never real tokens.
CANARY_GHP = "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB"
CANARY_AKIA = "AKIAQ7SYNTHETIC99XYZ"

ALLOWED_EVIDENCE_KEYS = frozenset(
    {
        "secret_family",
        "secret_family_set",
        "occurrence_count",
        "match_sha256",
        "match_len",
        "record_ordinal",
        "byte_offset",
        "byte_end",
        "truncated",
        "overflow",
    }
)


def _sl009(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.code == SL009]


def _serialized(f: Finding) -> str:
    return json.dumps(f.to_dict(), sort_keys=True)


# ---------------------------------------------------------------------------
# Fixture-driven detection
# ---------------------------------------------------------------------------


def test_seeded_fixture_fires_all_families() -> None:
    """The seeded canonical fixture carries one member of every registered family."""
    _events, findings = load_canonical(FIXTURES_DIR / "sl009_seeded.jsonl")
    hits = _sl009(findings)
    families = {f.evidence["secret_family"] for f in hits}
    expected = {
        "anthropic-api-key",
        "openai-api-key",
        "openrouter-api-key",
        "github-pat-classic",
        "github-pat-fine-grained",
        "github-oauth-token",
        "stripe-webhook-secret",
        "stripe-key",
        "aws-access-key",
        "supabase-pat",
        "telegram-bot-token",
        "jwt",
        "private-key-block",
        "generic-credential-assignment",
    }
    assert expected <= families, f"missing families: {expected - families}"
    for f in hits:
        assert f.severity == Severity.WARNING
        assert f.repairability == Repairability.MANUAL


def test_aggregation_same_family_one_record() -> None:
    """Three AWS keys in one record aggregate into a single finding."""
    _events, findings = load_canonical(FIXTURES_DIR / "sl009_seeded.jsonl")
    aws = [f for f in _sl009(findings) if f.evidence["secret_family"] == "aws-access-key"]
    assert len(aws) == 1
    assert aws[0].evidence["occurrence_count"] == 3
    assert len(aws[0].evidence["match_sha256"]) == 3


def test_clean_and_near_miss_fixtures_silent() -> None:
    """Healthy records and near-miss shapes produce zero SL009 findings."""
    for name in ("sl009_clean.jsonl", "sl009_near_miss.jsonl"):
        _events, findings = load_canonical(FIXTURES_DIR / name)
        assert _sl009(findings) == [], f"{name} emitted unexpected SL009"


def test_malformed_line_still_scanned() -> None:
    """A record that fails JSON validation is still scanned for secret shapes."""
    _events, findings = load_canonical(FIXTURES_DIR / "sl009_malformed_secret.jsonl")
    codes = {f.code for f in findings}
    assert "SL001" in codes
    sl009 = _sl009(findings)
    assert any(f.source.line == 2 for f in sl009), "malformed line 2 was not scanned"


def test_secret_bytes_never_in_finding() -> None:
    """No finding surface may contain the matched secret value."""
    _events, findings = load_canonical(FIXTURES_DIR / "sl009_seeded.jsonl")
    for f in _sl009(findings):
        blob = _serialized(f)
        for token in (CANARY_GHP, CANARY_AKIA, "sk-ant-api03-SYNTHE7IC9K3Y-N0T-R34L"):
            assert token not in blob
        assert_no_pii(f.to_dict())


def test_digest_present_and_discriminates() -> None:
    """Digests prove persistence: same value -> same digest, different -> different."""
    tracker = SecretScanTracker()
    secret_a = CANARY_GHP.encode()
    secret_b = b"ghp_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ9"
    tracker.feed(
        secret_a + b" " + secret_a, line_number=1, byte_offset=0, byte_end=80, record_ordinal=0
    )
    tracker.feed(secret_b, line_number=2, byte_offset=80, byte_end=160, record_ordinal=1)
    findings = tracker.into_findings(path_str="t.jsonl")
    f1, f2 = findings
    assert f1.evidence["occurrence_count"] == 2
    assert f1.evidence["match_sha256"] == [hashlib.sha256(secret_a).hexdigest()]
    assert f2.evidence["match_sha256"] == [hashlib.sha256(secret_b).hexdigest()]


def test_escaped_quote_assignment_fires() -> None:
    """JSON-escaped assignments (``api_key = \\"v\\"`` inside a payload) match."""
    tracker = SecretScanTracker()
    raw = rb'{"text":"config api_key = \"xK9mP2vQ7nL4wR8jF3hG6sD1aB5cE9\" done"}'
    tracker.feed(raw, line_number=1, byte_offset=0, byte_end=len(raw), record_ordinal=0)
    findings = tracker.into_findings(path_str="t.jsonl")
    fams = [f.evidence["secret_family"] for f in findings]
    assert "generic-credential-assignment" in fams


def test_escaped_json_key_assignment_fires() -> None:
    """``\"api_key\": \"v\"`` (escaped quotes around the key) also matches."""
    tracker = SecretScanTracker()
    raw = rb'{"text":"blob \"api_key\": \"xK9mP2vQ7nL4wR8jF3hG6sD1aB5cE9\""}'
    tracker.feed(raw, line_number=1, byte_offset=0, byte_end=len(raw), record_ordinal=0)
    findings = tracker.into_findings(path_str="t.jsonl")
    assert any(f.evidence["secret_family"] == "generic-credential-assignment" for f in findings)


def test_placeholder_assignments_silent() -> None:
    """Documentation placeholder shapes do not fire."""
    tracker = SecretScanTracker()
    raw = (
        b'token: null, api_key = "xxxxxxxx", password: ${PASSWORD},'
        b' secret = <YOUR_KEY>, token_endpoint: "https://x.example",'
        b' secretary = "acme-corp-123", token_count: 5000'
    )
    tracker.feed(raw, line_number=1, byte_offset=0, byte_end=len(raw), record_ordinal=0)
    assert tracker.into_findings(path_str="t.jsonl") == []


def test_evidence_keys_bounded_to_allowlist() -> None:
    """Every emitted evidence key is in the content-free allowlist."""
    _events, findings = load_canonical(FIXTURES_DIR / "sl009_seeded.jsonl")
    for f in _sl009(findings):
        assert set(f.evidence) <= ALLOWED_EVIDENCE_KEYS, set(f.evidence) - ALLOWED_EVIDENCE_KEYS
        ev = f.evidence
        assert ev["secret_family_set"] == SECRET_FAMILY_SET_VERSION
        assert isinstance(ev["occurrence_count"], int) and ev["occurrence_count"] >= 1
        assert isinstance(ev["match_sha256"], list) and len(ev["match_sha256"]) >= 1
        assert ev["byte_end"] > ev["byte_offset"] >= 0


def test_findings_deterministic_across_runs() -> None:
    """Same input -> byte-identical findings and fingerprints."""
    _e1, f1 = load_canonical(FIXTURES_DIR / "sl009_seeded.jsonl")
    _e2, f2 = load_canonical(FIXTURES_DIR / "sl009_seeded.jsonl")
    assert [f.to_dict() for f in f1] == [f.to_dict() for f in f2]
    assert [f.fingerprint for f in f1] == [f.fingerprint for f in f2]


# ---------------------------------------------------------------------------
# Caps and ordering
# ---------------------------------------------------------------------------


def test_digest_cap_marks_truncated() -> None:
    """More than MAX_DIGESTS_PER_FINDING distinct values truncates digest output."""
    tracker = SecretScanTracker()
    parts = [f"ghp_{i:040d}".encode() for i in range(MAX_DIGESTS_PER_FINDING + 3)]
    raw = b" ".join(parts)
    tracker.feed(raw, line_number=1, byte_offset=0, byte_end=len(raw), record_ordinal=0)
    findings = tracker.into_findings(path_str="t.jsonl")
    assert len(findings) == 1
    ev = findings[0].evidence
    assert ev["occurrence_count"] == MAX_DIGESTS_PER_FINDING + 3
    assert len(ev["match_sha256"]) == MAX_DIGESTS_PER_FINDING
    assert ev["truncated"] is True


def test_finding_cap_marks_overflow() -> None:
    """Beyond MAX_SECRET_FINDINGS_PER_FILE (record, family) pairs the last
    finding records the suppressed count."""
    tracker = SecretScanTracker()
    total_pairs = MAX_SECRET_FINDINGS_PER_FILE + 5
    for i in range(total_pairs):
        raw = f'{{"i":{i},"t":"ghp_{i:040d}"}}'.encode()
        tracker.feed(raw, line_number=i + 1, byte_offset=0, byte_end=len(raw), record_ordinal=i)
    findings = tracker.into_findings(path_str="t.jsonl")
    assert len(findings) == MAX_SECRET_FINDINGS_PER_FILE
    assert findings[-1].evidence["overflow"] == 5
    assert findings[-1].evidence["truncated"] is True


def test_findings_ordered_by_line() -> None:
    """Emitted findings sort by (line, ordinal, family) deterministically."""
    tracker = SecretScanTracker()
    tracker.feed(
        b"ghp_0000000000000000000000000000000000000005",
        line_number=9,
        byte_offset=0,
        byte_end=50,
        record_ordinal=2,
    )
    tracker.feed(
        b"whsec_0123456789abcdefABCDEF0123",
        line_number=3,
        byte_offset=0,
        byte_end=40,
        record_ordinal=1,
    )
    tracker.feed(
        b"AKIAQ7SYNTHETIC99XYZ", line_number=3, byte_offset=40, byte_end=60, record_ordinal=1
    )
    findings = tracker.into_findings(path_str="t.jsonl")
    lines = [f.source.line for f in findings]
    assert lines == sorted(lines)


# ---------------------------------------------------------------------------
# Pipeline integration (adapters, api, cli, iter_events)
# ---------------------------------------------------------------------------


def test_iter_events_emits_sl009() -> None:
    """The generic canonical reader surfaces SL009 alongside events."""
    yielded = list(iter_events(FIXTURES_DIR / "sl009_seeded.jsonl"))
    assert any(isinstance(x, Finding) and x.code == SL009 for x in yielded)


def test_vendor_adapters_emit_sl009() -> None:
    """Each vendor adapter scans its raw persisted bytes in the same pass."""
    cases = (
        (load_claude_code, CONFORMANCE_DIR / "claude_secret.jsonl"),
        (load_codex_rollout, CONFORMANCE_DIR / "codex_secret.jsonl"),
        (load_openai_agents, CONFORMANCE_DIR / "openai_secret.json"),
    )
    for load_fn, path in cases:
        _events, findings = load_fn(path)
        assert _sl009(findings), f"{load_fn.__name__} produced no SL009"


def test_openai_single_doc_coordinates() -> None:
    """Single-document JSON reports exact line/byte coords, no record_ordinal."""
    _events, findings = load_openai_agents(CONFORMANCE_DIR / "openai_secret.json")
    hits = _sl009(findings)
    assert hits
    for f in hits:
        assert "record_ordinal" not in f.evidence
        assert f.evidence["byte_end"] > f.evidence["byte_offset"] >= 0
        assert f.source.line is not None and f.source.line >= 1


def test_check_file_report_is_secret_free() -> None:
    """A serialized report on a seeded file contains no canary or secret shape."""
    report = check_file(CONFORMANCE_DIR / "canonical_secret.jsonl", format="canonical")
    report_json = json.dumps(report.to_dict())
    for token in (
        "sk-ant-api03-SECRET-CANARY-TOKEN-XYZ123",
        "sk-live-OPENAI-SECRET-TOKEN-51Nz888",
    ):
        assert token not in report_json
    assert_no_pii(report.to_dict())
    assert any(f.code == SL009 for f in report.findings)


def test_cli_default_exit_zero_and_select(capsys: pytest.CaptureFixture[str]) -> None:
    """SL009 warnings keep default exit 0; --select isolates, --ignore drops."""
    fixture = str(CONFORMANCE_DIR / "canonical_secret.jsonl")

    code = main(["check", fixture, "--format", "canonical", "--json"])
    out = capsys.readouterr().out
    assert code == 0
    assert SL009 in {f["code"] for f in json.loads(out)["findings"]}

    capsys.readouterr()
    code = main(["check", fixture, "--format", "canonical", "--json", "--select", "SL009"])
    out = capsys.readouterr().out
    assert code == 0
    assert {f["code"] for f in json.loads(out)["findings"]} == {SL009}

    code = main(["check", fixture, "--format", "canonical", "--json", "--ignore", "SL009"])
    out = capsys.readouterr().out
    assert code == 0
    assert SL009 not in {f["code"] for f in json.loads(out)["findings"]}


def test_cli_output_never_contains_secret(capsys: pytest.CaptureFixture[str]) -> None:
    """Human and JSON CLI output never embed the matched secret bytes."""
    fixture = str(CONFORMANCE_DIR / "canonical_secret.jsonl")
    for extra in ([], ["--json"]):
        main(["check", fixture, "--format", "canonical", *extra])
        captured = capsys.readouterr()
        for token in (
            "sk-ant-api03-SECRET-CANARY-TOKEN-XYZ123",
            "sk-live-OPENAI-SECRET-TOKEN-51Nz888",
        ):
            assert token not in captured.out
            assert token not in captured.err


def test_coverage_marks_sl009_performed() -> None:
    """Report coverage records SL009 among performed checks by default."""
    report = check_file(CONFORMANCE_DIR / "canonical_secret.jsonl", format="canonical")
    assert SL009 in {c for c in report.coverage.performed}


def test_bytes_stream_input() -> None:
    """check_bytes on in-memory data still scans raw persisted bytes."""
    raw = (FIXTURES_DIR / "sl009_seeded.jsonl").read_bytes()
    report = check_bytes(raw, format="canonical")
    assert any(f.code == SL009 for f in report.findings)


# --- T-02: surface wiring ---------------------------------------------------


def test_render_human_sl009_rollup_line() -> None:
    """Human render carries the content-free SL009 aggregate line."""
    from sesslint.report import render_human

    report = check_file(CONFORMANCE_DIR / "canonical_secret.jsonl", format="canonical")
    text = render_human(report, adapter="canonical")
    assert "SL009 warning" in text
    assert "secret-shaped material" in text
    assert "families:" in text
    for token in (
        "sk-ant-api03-SECRET-CANARY-TOKEN-XYZ123",
        "sk-live-OPENAI-SECRET-TOKEN-51Nz888",
    ):
        assert token not in text


def test_renderers_never_leak_secret() -> None:
    """JSON, SARIF, and HTML renders contain digests/labels but no secret bytes."""
    from sesslint.html_report import render_html
    from sesslint.report import render_json
    from sesslint.sarif import render_sarif

    report = check_file(CONFORMANCE_DIR / "canonical_secret.jsonl", format="canonical")
    canaries = (
        "sk-ant-api03-SECRET-CANARY-TOKEN-XYZ123",
        "sk-live-OPENAI-SECRET-TOKEN-51Nz888",
    )
    outputs = (
        render_json(report),
        render_sarif(report.findings, tool_version="0.0.0-test"),
        render_html(report),
    )
    for out in outputs:
        for token in canaries:
            assert token not in out
    # SARIF carries the rotation-token fingerprint set for SL009 findings.
    sarif = render_sarif(report.findings, tool_version="0.0.0-test")
    sarif_doc = json.loads(sarif)
    sl009_results = [r for r in sarif_doc["runs"][0]["results"] if r["ruleId"] == SL009]
    assert sl009_results
    for r in sl009_results:
        assert r["level"] == "warning"
        assert "sesslint/secret-match-sha256" in r["partialFingerprints"]


def test_scan_human_summary_line(tmp_path: Path) -> None:
    """scan on a tree with one seeded file prints the secret-material line."""
    import dataclasses

    from sesslint.api import check_dir
    from sesslint.cli import format_scan_report_human
    from sesslint.scan import aggregate_scan

    target = tmp_path / "seeded.jsonl"
    target.write_bytes((FIXTURES_DIR / "sl009_seeded.jsonl").read_bytes())
    (tmp_path / "clean.jsonl").write_bytes((FIXTURES_DIR / "sl009_clean.jsonl").read_bytes())
    base = check_dir(tmp_path, format="canonical")
    report = dataclasses.replace(base, summary=aggregate_scan(base.files))
    text = format_scan_report_human(report)
    assert "secret-shaped material: 1 file(s)" in text
    assert "SL009" in text
    assert "sk-ant" not in text


def test_scan_json_by_code_lists_sl009(tmp_path: Path) -> None:
    """Scan aggregation puts SL009 in by_code with the right file count."""
    from sesslint.api import check_dir
    from sesslint.scan import aggregate_scan

    (tmp_path / "seeded.jsonl").write_bytes((FIXTURES_DIR / "sl009_seeded.jsonl").read_bytes())
    summary = aggregate_scan(check_dir(tmp_path, format="canonical").files)
    rows = {r.code: r for r in summary.by_code}
    assert SL009 in rows
    assert rows[SL009].severity == "warning"
    assert rows[SL009].files == 1


def test_generic_assignment_no_catastrophic_backtracking() -> None:
    """Perf regression: the generic-credential pattern must stay linear on
    keyword-dense giant records (real Codex rollouts carry 14MB+ lines full
    of ``token_count``/``key``/``secret`` shapes — the old lazy-prefix
    pattern spent seconds per megabyte there)."""
    import time

    from sesslint.checks.hygiene import SecretScanTracker

    # 2MB of keyword-dense JSON-ish noise: no real assignment values.
    noise = (
        b'{"token_count": 1, "key": "v", "secret_name": "x", '
        b'"id_token_hint": null, "api_key_label": "y"},'
    ) * 40_000
    assert len(noise) > 1_000_000
    tracker = SecretScanTracker()
    t = time.monotonic()
    tracker.feed(
        noise,
        line_number=1,
        byte_offset=0,
        byte_end=len(noise),
        record_ordinal=0,
    )
    findings = tracker.into_findings(path_str="perf.jsonl")
    elapsed = time.monotonic() - t
    assert findings == []  # keyword shapes without credential values
    assert elapsed < 10.0, f"secret scan took {elapsed:.1f}s on 2MB dense line"
