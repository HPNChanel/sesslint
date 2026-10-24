"""Wave 1 hook protocol boundaries (W1-7, B11)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.hook_event import MAX_FAST_HOOK_TRANSCRIPT_BYTES, run_hook
from sesslint.hooks import init_hooks_doc


def _payload(path: Path, event: str = "SessionStart") -> bytes:
    return json.dumps(
        {
            "session_id": "wave1-hook-session",
            "transcript_path": str(path),
            "cwd": str(path.parent),
            "hook_event_name": event,
        }
    ).encode("utf-8")


def test_claude_output_is_a_content_free_system_message(tmp_path: Path) -> None:
    transcript = tmp_path / "clean.jsonl"
    transcript.write_text(
        '{"schema_version":"sesslint.session/v1","session_id":"wave1","created_at":"2026-10-08T00:00:00Z"}\n',
        encoding="utf-8",
        newline="\n",
    )

    result = run_hook("SessionStart", _payload(transcript))
    envelope = json.loads(result.to_claude_json())

    assert envelope == {"systemMessage": "SessLint: session integrity check passed."}
    assert str(transcript) not in envelope["systemMessage"]
    assert "wave1-hook-session" not in envelope["systemMessage"]


def test_malformed_hook_event_skips_without_disclosing_paths(tmp_path: Path) -> None:
    transcript = tmp_path / "private-transcript.jsonl"
    payload = json.loads(_payload(transcript))
    payload["hook_event_name"] = 42
    result = run_hook("SessionStart", json.dumps(payload).encode("utf-8"))

    assert result.verdict == "skipped"
    assert result.reason == "malformed-payload"
    assert str(transcript) not in result.to_claude_json()


def test_fast_events_skip_oversize_transcript_without_running_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    transcript = tmp_path / "large.jsonl"
    transcript.write_bytes(b"x" * (MAX_FAST_HOOK_TRANSCRIPT_BYTES + 1))

    import sesslint.api

    def unexpected_check(*args: object, **kwargs: object) -> object:
        raise AssertionError("fast hook should not inspect an over-budget transcript")

    monkeypatch.setattr(sesslint.api, "check_file", unexpected_check)

    result = run_hook("SessionStart", _payload(transcript))
    assert result.verdict == "skipped"
    assert result.reason == "budget-exceeded"


def test_hook_check_never_writes_or_creates_a_loopback_artifact(tmp_path: Path) -> None:
    transcript = tmp_path / "clean.jsonl"
    original = (
        b'{"schema_version":"sesslint.session/v1","session_id":"wave1",'
        b'"created_at":"2026-10-08T00:00:00Z"}\n'
    )
    transcript.write_bytes(original)

    result = run_hook("SessionStart", _payload(transcript))

    assert result.verdict == "ok"
    assert transcript.read_bytes() == original
    assert list(tmp_path.iterdir()) == [transcript]


def test_hook_templates_have_no_write_or_loopback_shell_constructs() -> None:
    doc = init_hooks_doc("all")
    commands = [
        hook[key]
        for file in doc.files
        if file.merge_block is not None
        for entries in file.merge_block["hooks"].values()
        for entry in entries
        for hook in entry["hooks"]
        for key in ("command", "commandWindows")
        if key in hook
    ]

    assert any("--event SessionStart --format claude-json" in command for command in commands)
    assert sum("--event SessionStart" in command for command in commands) == 3
    assert all(
        ">" not in command and "tee " not in command and "--output-file" not in command
        for command in commands
    )
