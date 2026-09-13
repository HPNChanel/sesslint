"""Privacy red-team adversarial test suite for diagnostic bundles (DEV-014, US-016, UC-07).

Executes comprehensive privacy red-teaming across:
- Canonical sessions
- Claude Code sessions
- OpenAI Agents SDK sessions
- Format detection failure / ambiguous sessions
- Unsupported version sessions (SL301)

Asserts:
- ZERO API keys or secrets (SECRET_PATTERNS: sk-ant-*, sk-live-*, bearer tokens, passwords)
- ZERO personal identifiable information (PII names, emails, SSNs, addresses)
- ZERO raw message content / prompt texts / tool payloads
- ZERO absolute paths (Unix or Windows)
- ZERO hostnames or usernames
- ZERO hostile type discriminator strings
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from sesslint import api
from sesslint.cli import main
from tests.utils.privacy import assert_no_pii

FIXTURES_ROOT = Path(__file__).resolve().parent.parent.parent / "fixtures"
HOSTILE_FIXTURE = FIXTURES_ROOT / "bundle" / "hostile_pii.jsonl"

SECRET_PATTERNS = [
    re.compile(r"sk-ant-[a-zA-Z0-9_-]+"),
    re.compile(r"sk-live-[a-zA-Z0-9_-]+"),
    re.compile(r"sk-[a-zA-Z0-9_-]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(r"glpat-[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"bearer\s+[a-zA-Z0-9_-]+", re.IGNORECASE),
    re.compile(r"password=[a-zA-Z0-9_!@#$%^&*]+", re.IGNORECASE),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),  # Email
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # SSN
]

FORBIDDEN_STRINGS = [
    "sk-ant-api03-SECRET-CANARY-TOKEN-XYZ123",
    "sk-live-OPENAI-SECRET-TOKEN-51Nz888",
    "super-secret-bearer-token-9999",
    "SuperSecretPassword123!",
    "Jane Doe",
    "jane.doe@confidential-corp.internal",
    "999-00-1234",
    "742 Evergreen Terrace",
    "/Users/janedoe/confidential_project",
    "C:\\Users\\JaneDoe\\Documents\\SecretRepo",
    "janedoe@workstation-alpha-99.corp.internal",
    "Confidential prompt",
    "Swiss bank account",
    "Private database query result",
]


def assert_bundle_is_privacy_clean(bundle_json_str: str) -> None:
    """Assert that a serialized bundle JSON string is strictly free of sensitive data."""
    # 1. Exact string matches
    for s in FORBIDDEN_STRINGS:
        assert s not in bundle_json_str, f"Found forbidden secret/PII string in bundle: {s!r}"

    # 2. Secret regex patterns
    for pat in SECRET_PATTERNS:
        match = pat.search(bundle_json_str)
        assert match is None, f"Found secret matching pattern {pat.pattern}: {match.group(0)!r}"

    # 3. No absolute directory paths
    parsed = json.loads(bundle_json_str)
    source_path = parsed.get("source", {}).get("path", "")
    assert "/" not in source_path and "\\" not in source_path, (
        f"source.path must be basename-only, got: {source_path!r}"
    )

    # 4. Check findings paths inside report
    findings = parsed.get("report", {}).get("findings", [])
    for f in findings:
        span_path = f.get("span", {}).get("path", "")
        assert "/" not in span_path and "\\" not in span_path, (
            f"finding.span.path must be basename-only, got: {span_path!r}"
        )
        rem = f.get("remediation", "")
        assert "/" not in rem and "\\" not in rem, (
            f"finding.remediation must not contain directory paths, got: {rem!r}"
        )

    # 5. Full repository-standard PII and credential recursive scan
    assert_no_pii(parsed, path="bundle")


class TestBundlePrivacyRedTeam:
    """Red-team adversarial privacy tests against diagnostic bundle generation."""

    def test_bundle_hostile_pii_fixture_api(self) -> None:
        """Building a bundle from hostile_pii.jsonl via API contains zero secrets or PII."""
        bundle = api.build_bundle(HOSTILE_FIXTURE)
        bundle_str = bundle.to_json()
        assert_bundle_is_privacy_clean(bundle_str)

    def test_bundle_hostile_pii_fixture_cli(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Building a bundle from hostile_pii.jsonl via CLI contains zero secrets or PII."""
        code = main(["bundle", str(HOSTILE_FIXTURE)])
        assert code == 0
        captured = capsys.readouterr()
        assert_bundle_is_privacy_clean(captured.out)

    def test_bundle_claude_hostile_secrets(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Claude Code format with hostile secrets and absolute paths is redacted in bundle."""
        secret_canary = "sk-ant-api03-CLAUDE-REDTEAM-CANARY-999"
        fixture = tmp_path / "hostile_claude.jsonl"
        fixture.write_text(
            json.dumps(
                {
                    "type": "user",
                    "id": "evt_claude_001_very_long_secret_id",
                    "parent_id": None,
                    "unknown_auth_key": secret_canary,
                    "message": "Secret Claude prompt with confidential source code",
                    "path_leak": "/home/developer/secrets/claude_session.jsonl",
                    "ts": "2026-09-13T10:00:00Z",
                }
            )
            + "\n",
            encoding="utf-8",
        )

        code = main(["bundle", str(fixture), "--format", "claude-code-jsonl"])
        assert code == 0
        captured = capsys.readouterr()

        assert secret_canary not in captured.out
        assert "/home/developer" not in captured.out
        assert "Secret Claude prompt" not in captured.out
        assert "evt_claude_001_very_long_secret_id" not in captured.out

        data = json.loads(captured.out)
        assert data["source"]["path"] == fixture.name

    def test_bundle_openai_hostile_secrets(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """OpenAI Agents SDK export with secret tokens and checkpoints is redacted in bundle."""
        secret_canary = "sk-live-OPENAI-AGENT-REDTEAM-CANARY-42"
        fixture = tmp_path / "hostile_openai.json"
        content = {
            "session_id": "sess_openai_secret_token_session_id",
            "created_at": "2026-09-13T10:00:00Z",
            "items": [
                {
                    "id": "item_secret_token_1234567890",
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "text", "text": "Secret prompt with API key"}],
                    "unknown_auth": secret_canary,
                }
            ],
        }
        fixture.write_text(json.dumps(content), encoding="utf-8")

        bundle = api.build_bundle(fixture, format="openai-agents")
        bundle_str = bundle.to_json()

        assert secret_canary not in bundle_str
        assert "Secret prompt with API key" not in bundle_str
        assert "item_secret_token_1234567890" not in bundle_str

        data = json.loads(bundle_str)
        assert data["source"]["path"] == fixture.name

    def test_bundle_unsupported_version_sl301_privacy(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Unsupported format version session produces bundle with safe version evidence only."""
        secret_version = "sk-ant-api03-VERSION-SECRET-INJECTION-TOKEN"
        fixture = tmp_path / "sl301_hostile.jsonl"
        fixture.write_text(
            json.dumps(
                {
                    "type": "user",
                    "id": "evt_sl301",
                    "parent_id": None,
                    "version": secret_version,
                    "ts": "2026-09-13T10:00:00Z",
                }
            )
            + "\n",
            encoding="utf-8",
        )

        code = main(["bundle", str(fixture)])
        assert code == 0
        captured = capsys.readouterr()

        # Secret injected via version field must NOT appear raw in bundle
        assert secret_version not in captured.out
        data = json.loads(captured.out)
        assert "detection" in data
        assert data["source"]["path"] == fixture.name

    def test_bundle_hostile_type_discriminator_bounded(self, tmp_path: Path) -> None:
        """Hostile type values exceeding length limits are bounded to shape descriptors."""
        hostile_type = "hostile_type_with_secret_sk-ant-api03-LEAK-OVERFLOW" * 4
        fixture = tmp_path / "hostile_type.jsonl"
        fixture.write_text(
            json.dumps(
                {
                    "type": hostile_type,
                    "id": "evt_type_test",
                    "parent_id": None,
                    "ts": "2026-09-13T10:00:00Z",
                }
            )
            + "\n",
            encoding="utf-8",
        )

        bundle = api.build_bundle(fixture, format="claude-code-jsonl")
        bundle_str = bundle.to_json()

        assert hostile_type not in bundle_str
        assert "sk-ant-api03-LEAK-OVERFLOW" not in bundle_str

    def test_bundle_hostile_critical_key_secrets_across_adapters(self, tmp_path: Path) -> None:
        """Hostile critical field keys containing API keys are bounded and do not leak or crash."""
        secret_canary = "sk-ant-api03-CRITICAL-KEY-SECRET-CANARY-777"
        hostile_key = f"critical_{secret_canary}"

        # 1. Canonical adapter
        can_fixture = tmp_path / "hostile_key_canonical.jsonl"
        can_fixture.write_text(
            json.dumps(
                {
                    "type": "user",
                    "id": "evt_key_test",
                    "parent_id": None,
                    hostile_key: "some_value",
                    "ts": "2026-09-13T10:00:00Z",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        can_bundle = api.build_bundle(can_fixture, format="canonical")
        can_bundle_str = can_bundle.to_json()
        assert secret_canary not in can_bundle_str
        assert_bundle_is_privacy_clean(can_bundle_str)

        # 2. Claude Code adapter
        claude_fixture = tmp_path / "hostile_key_claude.jsonl"
        claude_fixture.write_text(
            json.dumps(
                {
                    "type": "user",
                    "id": "evt_key_claude",
                    "parent_id": None,
                    hostile_key: "some_value",
                    "ts": "2026-09-13T10:00:00Z",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        claude_bundle = api.build_bundle(claude_fixture, format="claude-code-jsonl")
        claude_bundle_str = claude_bundle.to_json()
        assert secret_canary not in claude_bundle_str
        assert_bundle_is_privacy_clean(claude_bundle_str)

        # 3. OpenAI Agents adapter
        openai_fixture = tmp_path / "hostile_key_openai.json"
        openai_fixture.write_text(
            json.dumps(
                {
                    "session_id": "sess_key_openai",
                    "created_at": "2026-09-13T10:00:00Z",
                    "items": [
                        {
                            "id": "item_key_openai",
                            "type": "message",
                            "role": "user",
                            "content": [{"type": "text", "text": "test"}],
                            hostile_key: "value",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        openai_bundle = api.build_bundle(openai_fixture, format="openai-agents")
        openai_bundle_str = openai_bundle.to_json()
        assert secret_canary not in openai_bundle_str
        assert_bundle_is_privacy_clean(openai_bundle_str)

    def test_bundle_cross_platform_path_sanitization(self, tmp_path: Path) -> None:
        """Paths with backslashes or nested directory structures are stripped to basename only."""
        fixture = tmp_path / "session_for_path_test.jsonl"
        fixture.write_text(
            json.dumps(
                {
                    "created_at": "2026-09-13T10:00:00Z",
                    "schema_version": "sesslint.session/v1",
                    "session_id": "sess_path_test",
                }
            )
            + "\n",
            encoding="utf-8",
        )

        bundle = api.build_bundle(fixture)
        assert "/" not in bundle.source["path"]
        assert "\\" not in bundle.source["path"]
        assert bundle.source["path"] == fixture.name

    def test_bundle_detection_failure_hostile_content_privacy(self, tmp_path: Path) -> None:
        """Completely unrecognized format with hostile secrets produces clean bundle."""
        secret_canary = "sk-ant-api03-UNRECOGNIZED-FORMAT-SECRET-CANARY"
        fixture = tmp_path / "unrecognized_hostile.unknown"
        pii_email = "jane.doe@confidential-corp.internal"
        fixture.write_text(
            f"# UNRECOGNIZED FORMAT HEADER with secret: {secret_canary}\n"
            f'{{"unrecognized_kind": "custom_event", "secret": "{secret_canary}"}}\n'
            f'{{"unrecognized_kind": "custom_event", "user": "{pii_email}"}}\n',
            encoding="utf-8",
        )

        bundle = api.build_bundle(fixture)
        bundle_str = bundle.to_json()
        assert secret_canary not in bundle_str
        assert "jane.doe@confidential-corp.internal" not in bundle_str
        assert_bundle_is_privacy_clean(bundle_str)
