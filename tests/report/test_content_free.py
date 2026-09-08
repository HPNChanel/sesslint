"""Tests for content-free reporting defaults and --include-content gate (TASK-025)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.cli import main
from sesslint.codes import SL001, Repairability, Severity
from sesslint.errors import OperationalError
from sesslint.finding import SourceRef, make_finding
from sesslint.report import (
    REPORT_DEFAULT_FINDING_KEYS,
    REPORT_FORBIDDEN_FINDING_KEYS,
    REPORT_ROOT_KEYS,
    build_report,
    render_json,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "report" / "secret_seed"
TOKEN_FILE = FIXTURES_DIR / "token.txt"


def _get_token() -> str:
    return TOKEN_FILE.read_text(encoding="utf-8").strip()


def test_default_mode_never_leaks_seeded_secret(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify that default human and JSON check reports contain zero occurrences of secret token."""
    token = _get_token()
    claude_fixture = FIXTURES_DIR / "claude_secret.jsonl"

    # 1. Human check mode
    code = main(["check", str(claude_fixture), "--format", "claude-code-jsonl"])
    assert code == 0
    captured = capsys.readouterr()
    assert token not in captured.out
    assert token not in captured.err

    # 2. JSON check mode
    code_json = main(["check", str(claude_fixture), "--format", "claude-code-jsonl", "--json"])
    assert code_json == 0
    captured_json = capsys.readouterr()
    assert token not in captured_json.out
    assert token not in captured_json.err


def test_json_keys_subset_of_allowlist() -> None:
    """Verify JSON report keys strictly conform to approved allowlists and forbid content keys."""
    f = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Malformed syntax at line {line}",
        template_args={"line": "5"},
        source=SourceRef(path="session.jsonl", line=5),
    )
    rep = build_report(
        session_id="sess_allowlist",
        source_fingerprint="fp_1234567890abcdef",
        tool_version="0.1.0",
        findings=[f],
        assurance="A0",
        limitation="No structural conclusion.",
    )

    rendered_str = render_json(rep, include_content=False)
    data = json.loads(rendered_str)

    # Root keys ⊆ allowlist
    assert set(data.keys()).issubset(REPORT_ROOT_KEYS)
    assert "content_warning" not in data
    assert "included_content" not in data

    # Findings keys ⊆ allowlist
    findings = data["findings"]
    assert len(findings) == 1
    finding_keys = set(findings[0].keys())
    assert finding_keys.issubset(REPORT_DEFAULT_FINDING_KEYS)

    # Strictly no forbidden keys in default mode
    for forbidden_key in REPORT_FORBIDDEN_FINDING_KEYS:
        msg = f"Forbidden key {forbidden_key!r} found in finding"
        assert forbidden_key not in finding_keys, msg


def test_fail_closed_on_crafted_content_key() -> None:
    """Verify that a crafted dictionary with unapproved key raises OperationalError."""
    crafted_finding = {
        "code": "SL001",
        "severity": "error",
        "repairability": "manual",
        "fingerprint": "1234567890abcdef",
        "span": {"path": "session.jsonl", "line": 1, "byte": None},
        "evidence": None,
        "remediation": "manual fix",
        "content": "UNAUTHORIZED_PAYLOAD_LEAK",
    }
    crafted_report = {
        "schema_version": "sesslint.report/v1",
        "session_id": "sess-test",
        "source_fingerprint": "0" * 64,
        "tool_version": "0.1.0",
        "assurance": "A0",
        "limitation": "Test limitation",
        "counts": {
            "by_severity": {"fatal": 0, "error": 1, "warning": 0, "info": 0},
            "by_code": {"SL001": 1},
            "total": 1,
        },
        "findings": [crafted_finding],
    }

    with pytest.raises(OperationalError, match="forbidden content key violation"):
        render_json(crafted_report, include_content=False)

    # Also test extra rogue root key
    rogue_root_report = dict(crafted_report)
    rogue_root_report["findings"] = []
    rogue_root_report["rogue_key"] = "leak"
    with pytest.raises(OperationalError, match="root key allowlist violation"):
        render_json(rogue_root_report, include_content=False)


def test_include_content_embeds_token_and_adds_warnings(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify --include-content adds warning keys to JSON and emits stderr warning banner."""
    claude_fixture = FIXTURES_DIR / "claude_secret.jsonl"

    code = main(
        [
            "check",
            str(claude_fixture),
            "--format",
            "claude-code-jsonl",
            "--json",
            "--include-content",
        ]
    )
    assert code == 0
    captured = capsys.readouterr()

    # Stderr must contain warning banner
    warn_banner = "WARNING: --include-content embeds raw transcript content; do not share output"
    assert warn_banner in captured.err

    # JSON output must have warning keys
    data = json.loads(captured.out)
    assert data.get("content_warning") is True
    assert data.get("included_content") is True


def test_shorthand_flag_c_is_refused(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify shorthand -c is rejected with exit code 2 (spelled-out only requirement)."""
    claude_fixture = FIXTURES_DIR / "claude_secret.jsonl"
    with pytest.raises(SystemExit) as exc_info:
        main(["check", str(claude_fixture), "-c"])
    assert exc_info.value.code == 2
    captured = capsys.readouterr()
    assert "unrecognized arguments" in captured.err or "-c" in captured.err


def test_failing_fixture_with_unknown_critical_secret_does_not_leak(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify unknown-critical secret fields never leak into evidence or output (RVW-005)."""
    secret_token = "sk-ant-api03-SECRET-CANARY-TOKEN-XYZ123"
    fixture = tmp_path / "failing_secret.jsonl"
    # Write Claude JSONL line with an unknown critical field containing the secret token
    record = {
        "id": "evt_secret_01",
        "parent_id": None,
        "type": "user",
        "unknown_critical_auth": secret_token,
        "ts": "2026-09-05T12:00:00Z",
    }
    fixture.write_text(json.dumps(record) + "\n", encoding="utf-8")

    code = main(["check", str(fixture), "--format", "claude-code-jsonl", "--json"])
    assert code == 1  # Failing session
    captured = capsys.readouterr()

    # Secret token must NOT appear anywhere in stdout or stderr
    assert secret_token not in captured.out
    assert secret_token not in captured.err

    data = json.loads(captured.out)
    assert len(data.get("findings", [])) >= 1
    for f in data["findings"]:
        ev = f.get("evidence") or {}
        if "type_value" in ev:
            # type_value must be type/length descriptor, not raw secret
            assert secret_token not in ev["type_value"]
            assert ev["type_value"].startswith("<") and ev["type_value"].endswith(">")


def test_remediation_and_span_path_minimize_absolute_paths_on_failing_fixture(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify default reports minimize paths and never leak raw absolute paths (RVW-005)."""
    abs_fixture = (tmp_path / "failing_path_leak.jsonl").resolve()
    # Write an invalid record causing SL001
    abs_fixture.write_text('{"invalid_json": true\n', encoding="utf-8")

    code = main(["check", str(abs_fixture), "--format", "canonical", "--json"])
    assert code == 1
    captured = capsys.readouterr()

    data = json.loads(captured.out)
    findings = data.get("findings", [])
    assert len(findings) >= 1

    abs_str = str(abs_fixture).replace("\\", "/")
    # Raw absolute path must not appear in remediation
    for f in findings:
        remediation = f.get("remediation", "")
        assert abs_str not in remediation
        span_path = f.get("span", {}).get("path", "")
        # span path must be minimized (basename or relative)
        assert span_path == abs_fixture.name or not span_path.startswith(str(tmp_path))


def test_secret_seed_zero_leak_on_failing_openai(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify zero secret token leakage on failing OpenAI fixture (human & JSON modes)."""
    secret_token = "sk-live-OPENAI-SECRET-TOKEN-51Nz888"
    fixture = tmp_path / "failing_openai_secret.json"
    content = {
        "session_id": "sess_openai_sec",
        "created_at": "2026-09-08T12:00:00Z",
        "items": [
            {
                "id": "item_0",
                "type": "message",
                "role": "user",
                "content": [{"type": "text", "text": "hello"}],
                "unknown_critical_auth": secret_token,
            }
        ],
    }
    fixture.write_text(json.dumps(content), encoding="utf-8")

    # 1. JSON check mode
    code_json = main(["check", str(fixture), "--format", "openai-agents", "--json"])
    assert code_json == 1
    captured_json = capsys.readouterr()
    assert secret_token not in captured_json.out
    assert secret_token not in captured_json.err

    # 2. Human check mode
    code_human = main(["check", str(fixture), "--format", "openai-agents"])
    assert code_human == 1
    captured_human = capsys.readouterr()
    assert secret_token not in captured_human.out
    assert secret_token not in captured_human.err


def test_secret_seed_zero_leak_on_failing_canonical(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify zero secret token leakage on failing Canonical fixture (human & JSON modes)."""
    secret_token = "sk-live-CANONICAL-SECRET-TOKEN-42"
    fixture = tmp_path / "failing_canonical_secret.jsonl"
    lines = [
        '{"created_at":"2026-09-08T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"sess_can_sec"}',
        json.dumps(
            {
                "actor": "user",
                "id": "evt_001",
                "kind": "message",
                "parent_id": None,
                "payload": {"text": "hi"},
                "seq": 0,
                "ts": "2026-09-08T12:00:00Z",
                "unknown_critical_env": secret_token,
            }
        ),
    ]
    fixture.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # 1. JSON check mode
    code_json = main(["check", str(fixture), "--format", "canonical", "--json"])
    assert code_json == 1
    captured_json = capsys.readouterr()
    assert secret_token not in captured_json.out
    assert secret_token not in captured_json.err

    # 2. Human check mode
    code_human = main(["check", str(fixture), "--format", "canonical"])
    assert code_human == 1
    captured_human = capsys.readouterr()
    assert secret_token not in captured_human.out
    assert secret_token not in captured_human.err


def test_secret_seed_zero_leak_in_scan_directory(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify recursive directory scan on failing fixtures leaks zero secrets (RVW-005)."""
    scan_dir = tmp_path / "scan_secrets"
    scan_dir.mkdir()
    secret_token = "sk-live-SCAN-SECRET-TOKEN-777xyz"

    f1 = scan_dir / "failing1.jsonl"
    f1.write_text(
        json.dumps(
            {
                "id": "rec_01",
                "type": "user",
                "parent_id": None,
                "secret_key": secret_token,
                "unknown_critical_flag": secret_token,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    f2 = scan_dir / "failing2.jsonl"
    f2.write_text(f'{{"invalid": "{secret_token}"\n', encoding="utf-8")

    # 1. JSON scan mode
    code_json = main(["check", str(scan_dir), "--recursive", "--json"])
    assert code_json == 1
    captured_json = capsys.readouterr()
    assert secret_token not in captured_json.out
    assert secret_token not in captured_json.err

    # 2. Human scan mode
    code_human = main(["check", str(scan_dir), "--recursive"])
    assert code_human == 1
    captured_human = capsys.readouterr()
    assert secret_token not in captured_human.out
    assert secret_token not in captured_human.err


def test_secret_seed_zero_leak_in_repair_manifest(tmp_path: Path) -> None:
    """Verify repair manifest never leaks payload secrets when repairing sessions."""
    secret_token = "sk-live-REPAIR-MANIFEST-SECRET-999"
    src_file = tmp_path / "src_secret.jsonl"
    out_file = tmp_path / "out_repaired.jsonl"

    lines = [
        '{"created_at":"2026-09-08T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"sess_rep_sec"}',
        json.dumps(
            {
                "actor": "user",
                "id": "evt_001",
                "kind": "message",
                "parent_id": None,
                "payload": {"text": f"secret token is {secret_token}"},
                "seq": 0,
                "ts": "2026-09-08T12:00:00Z",
            }
        ),
        # Duplicate identical record triggers SL003 repair
        json.dumps(
            {
                "actor": "user",
                "id": "evt_001",
                "kind": "message",
                "parent_id": None,
                "payload": {"text": f"secret token is {secret_token}"},
                "seq": 0,
                "ts": "2026-09-08T12:00:00Z",
            }
        ),
    ]
    src_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    exit_code = main(["repair", str(src_file), "--output", str(out_file)])
    assert exit_code == 0
    assert out_file.is_file()

    manifest_file = tmp_path / "out_repaired.jsonl.manifest.json"
    assert manifest_file.is_file()
    manifest_content = manifest_file.read_text(encoding="utf-8")

    # Manifest must be content-free: must not leak the payload secret
    assert secret_token not in manifest_content
