"""Tests for ``sesslint hook`` (agent-hooks T-01).

The subcommand reads one Claude Code or Codex hook payload from stdin,
resolves ``transcript_path``, and runs the event-appropriate check. Contract under
test: advisory exit codes only (never 2), skip-not-crash on every bad
input, content-free output, and the SessionEnd -> SL009 event map.
"""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from sesslint.hook_event import (
    HOOK_RESULT_SCHEMA,
    MAX_HOOK_PAYLOAD_BYTES,
    run_hook,
)
from sesslint.hooks import init_hooks_doc

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES_ROOT = REPO_ROOT / "fixtures"
SEEDED = FIXTURES_ROOT / "checks" / "secret_seed" / "sl009_seeded.jsonl"
CLEAN = FIXTURES_ROOT / "checks" / "secret_seed" / "sl009_clean.jsonl"
CORRUPT = FIXTURES_ROOT / "checks" / "sl011_outlier.jsonl"
CODEX = FIXTURES_ROOT / "adapters" / "codex"
CODEX_SECRET = FIXTURES_ROOT / "conformance" / "secret_seed" / "codex_secret.jsonl"


def _payload(path: Path | None = None, event: str = "SessionStart", **extra: object) -> bytes:
    obj: dict[str, object] = {
        "session_id": "sess-hook-test-9f31",
        "cwd": str(REPO_ROOT),
        "hook_event_name": event,
    }
    if path is not None:
        obj["transcript_path"] = str(path.resolve())
    obj.update(extra)
    return json.dumps(obj).encode("utf-8")


def _run_cli(*argv: str, stdin: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-m", "sesslint", *argv],
        input=stdin,
        capture_output=True,
        cwd=REPO_ROOT,
    )


def test_claude_json_cli_envelope() -> None:
    result = _run_cli(
        "hook", "--event", "SessionStart", "--format", "claude-json", stdin=_payload(CLEAN)
    )
    assert result.returncode == 0
    message = json.loads(result.stdout)
    assert set(message) == {"systemMessage"}
    assert "SessLint:" in message["systemMessage"]
    assert str(CLEAN) not in result.stdout.decode()


class TestPayloadHandling:
    """Malformed/thin payloads degrade to a skip line, never a crash."""

    def test_malformed_json_skips(self) -> None:
        r = run_hook("SessionStart", b"this is not json")
        assert r.verdict == "skipped"
        assert r.reason == "malformed-payload"
        assert r.exit_code == 0

    def test_non_object_payload_skips(self) -> None:
        r = run_hook("SessionStart", b'["array", "is", "wrong"]')
        assert r.verdict == "skipped"
        assert r.reason == "malformed-payload"

    def test_missing_transcript_path_skips(self) -> None:
        r = run_hook("SessionEnd", _payload(None))
        assert r.verdict == "skipped"
        assert r.reason == "no-transcript-path"

    def test_wrong_typed_transcript_path_skips(self) -> None:
        r = run_hook("SessionEnd", _payload(None, transcript_path=42))
        assert r.verdict == "skipped"
        assert r.reason == "no-transcript-path"

    def test_nonexistent_transcript_skips(self, tmp_path: Path) -> None:
        r = run_hook("SessionStart", _payload(tmp_path / "missing.jsonl"))
        assert r.verdict == "skipped"
        assert r.reason == "transcript-not-found"

    def test_directory_transcript_skips(self) -> None:
        r = run_hook("SessionStart", _payload(FIXTURES_ROOT))
        assert r.verdict == "skipped"
        assert r.reason == "transcript-not-found"

    def test_oversized_payload_skips(self) -> None:
        r = run_hook("SessionStart", b" " * (MAX_HOOK_PAYLOAD_BYTES + 1))
        assert r.verdict == "skipped"
        assert r.reason == "payload-too-large"

    def test_empty_stdin_skips(self) -> None:
        r = run_hook("SessionStart", b"")
        assert r.verdict == "skipped"
        assert r.exit_code == 0


class TestEventMap:
    """Each event maps to the documented check surface."""

    def test_sessionstart_clean_ok(self) -> None:
        r = run_hook("SessionStart", _payload(CLEAN))
        assert r.verdict == "ok"
        assert r.reason == "clean"
        assert r.exit_code == 0
        assert r.line() == "sesslint hook[SessionStart]: ok"

    def test_sessionstart_over_budget_skips_without_reading_transcript(self) -> None:
        r = run_hook("SessionStart", _payload(CORRUPT))
        assert r.verdict == "skipped"
        assert r.reason == "budget-exceeded"
        assert r.exit_code == 0

    def test_sessionend_runs_sl009_only(self) -> None:
        """SessionEnd sweeps persisted secrets — the seeded fixture has 14."""
        r = run_hook("SessionEnd", _payload(SEEDED))
        assert r.verdict == "findings"
        assert r.findings_by_code == {"SL009": 14}
        assert r.top_code == "SL009"
        assert r.exit_code == 0

    def test_sessionend_clean_transcript_ok(self) -> None:
        r = run_hook("SessionEnd", _payload(CLEAN))
        assert r.verdict == "ok"

    def test_unknown_event_runs_generic_check(self) -> None:
        """Forward-compat: unrecognized event names still check."""
        r = run_hook("UserPromptSubmit", _payload(CORRUPT))
        assert r.verdict == "findings"
        assert "SL011" in r.findings_by_code

    def test_fail_on_warning_exits_1_on_findings(self) -> None:
        r = run_hook("SessionEnd", _payload(SEEDED), fail_on="warning")
        assert r.verdict == "findings"
        assert r.exit_code == 1

    def test_fail_on_error_ignores_warnings(self) -> None:
        """SL009 is warning-severity: --fail-on error stays advisory."""
        r = run_hook("SessionEnd", _payload(SEEDED), fail_on="error")
        assert r.verdict == "findings"
        assert r.exit_code == 0
        # …but fires on error-severity findings (SL303 is error-class).
        r_err = run_hook(
            "SessionStart",
            _payload(FIXTURES_ROOT / "checks" / "sl303_critical_dup.jsonl"),
            fail_on="error",
        )
        assert r_err.exit_code == 1

    def test_fail_on_never_is_default(self) -> None:
        r = run_hook("SessionEnd", _payload(SEEDED), fail_on="never")
        assert r.exit_code == 0

    def test_fail_on_skipped_still_0(self) -> None:
        """A gate never turns a skip into a block."""
        r = run_hook("SessionStart", b"garbage", fail_on="warning")
        assert r.exit_code == 0


class TestCodexPayload:
    """Codex payloads add ``model`` plus per-event fields and name a rollout file."""

    def test_sessionstart_resume_clean_rollout_ok(self) -> None:
        r = run_hook(
            "SessionStart",
            _payload(CODEX / "healthy_min.jsonl", model="synthetic-model", source="resume"),
        )
        assert r.verdict == "ok"
        assert r.exit_code == 0

    def test_compaction_events_flag_dangling_call(self) -> None:
        for event in ("PreCompact", "PostCompact"):
            r = run_hook(
                event,
                _payload(
                    CODEX / "dangling_call.jsonl",
                    event,
                    model="synthetic-model",
                    turn_id="turn-syn-1",
                    trigger="auto",
                ),
            )
            assert r.verdict == "findings"
            assert r.top_code == "SL102"
            assert r.exit_code == 0

    def test_sessionend_sweeps_rollout_secrets_only(self) -> None:
        r = run_hook("SessionEnd", _payload(CODEX_SECRET, "SessionEnd", reason="other"))
        assert r.findings_by_code == {"SL009": 2}
        # A dangling call is structural, not a secret: SessionEnd stays narrowed.
        r = run_hook("SessionEnd", _payload(CODEX / "dangling_call.jsonl", "SessionEnd"))
        assert r.verdict == "ok"

    def test_null_transcript_path_skips(self) -> None:
        r = run_hook("SessionEnd", _payload(None, "SessionEnd", transcript_path=None))
        assert r.verdict == "skipped"
        assert r.reason == "no-transcript-path"

    @pytest.mark.parametrize("transcript", ["dangling_call.jsonl", None])
    def test_cli_runs_every_emitted_windows_command(self, transcript: str | None) -> None:
        """Each emitted commandWindows string must exit 0 on its own (no '|| true').

        Codex reads hook stdout only on exit 0 and rejects JSON with unknown
        keys, so the claude-json recipes must print a lone systemMessage.
        """
        for f in init_hooks_doc("codex").files:
            assert f.merge_block is not None
            for event, entries in f.merge_block["hooks"].items():
                for entry in entries:
                    for hook in entry["hooks"]:
                        argv = shlex.split(hook["commandWindows"])
                        assert argv[0] == "sesslint"
                        if transcript is None:
                            stdin = _payload(None, event, transcript_path=None)
                        else:
                            stdin = _payload(CODEX / transcript, event)
                        res = _run_cli(*argv[1:], stdin=stdin)
                        assert res.returncode == 0, (event, res.stderr)
                        out = res.stdout.decode("utf-8")
                        assert "dangling_call" not in out
                        if "claude-json" in argv:
                            assert set(json.loads(out)) == {"systemMessage"}
                        else:
                            assert out.startswith(f"sesslint hook[{event}]: ")


class TestOutputShape:
    """Line and JSON forms stay content-free and deterministic."""

    def test_json_shape_and_schema(self) -> None:
        r = run_hook("SessionEnd", _payload(SEEDED))
        d = r.to_dict()
        assert d["schema"] == HOOK_RESULT_SCHEMA == "sesslint.hook-result/v1"
        assert d["event"] == "SessionEnd"
        assert d["verdict"] == "findings"
        assert d["findings_by_code"] == {"SL009": 14}
        assert d["top_code"] == "SL009"
        assert d["reason"] == "findings-present"
        # session_id is hash-truncated to 8 hex chars, never the raw value
        assert d["session_id"] != "sess-hook-test-9f31"
        assert len(d["session_id"]) == 8

    def test_skipped_json_shape(self) -> None:
        r = run_hook("SessionStart", b"{}")
        d = r.to_dict()
        assert d["verdict"] == "skipped"
        assert d["findings_by_code"] == {}
        assert "top_code" not in d

    def test_no_secret_values_in_output(self) -> None:
        r = run_hook("SessionEnd", _payload(SEEDED))
        for surface in (r.line(), r.to_json()):
            assert "sk-ant" not in surface
            assert "sk-live" not in surface
            assert "AKIA" not in surface

    def test_determinism(self) -> None:
        p = _payload(SEEDED)
        assert run_hook("SessionEnd", p).to_json() == run_hook("SessionEnd", p).to_json()


class TestCliSurface:
    """End-to-end subprocess coverage of the ``sesslint hook`` command."""

    def test_cli_sessionend_findings_line(self) -> None:
        res = _run_cli("hook", "--event", "SessionEnd", stdin=_payload(SEEDED, "SessionEnd"))
        assert res.returncode == 0
        assert b"sesslint hook[SessionEnd]: findings=14 top=SL009" in res.stdout

    def test_cli_fail_on_warning_exits_1(self) -> None:
        res = _run_cli(
            "hook", "--event", "SessionEnd", "--fail-on", "warning", stdin=_payload(SEEDED)
        )
        assert res.returncode == 1

    def test_cli_json_output(self) -> None:
        res = _run_cli("hook", "--event", "SessionEnd", "--json", stdin=_payload(SEEDED))
        assert res.returncode == 0
        doc = json.loads(res.stdout)
        assert doc["schema"] == "sesslint.hook-result/v1"
        assert doc["verdict"] == "findings"

    def test_cli_garbage_stdin_skips_exit_0(self) -> None:
        res = _run_cli("hook", "--event", "SessionStart", stdin=b"\x00\xff not json")
        assert res.returncode == 0
        assert b"skipped" in res.stdout

    def test_cli_never_exits_2(self) -> None:
        """Blocking codes must never reach the agent — every path stays <2."""
        for stdin in (b"", b"garbage", _payload(None), _payload(SEEDED)):
            res = _run_cli("hook", "--event", "PreCompact", stdin=stdin)
            assert res.returncode in (0, 1)
            assert res.returncode != 2


class TestSchemaFile:
    """The shipped hook-result schema validates live output."""

    def test_result_validates_against_schema(self) -> None:
        schema_path = REPO_ROOT / "schemas" / "sesslint.hook-result.v1.json"
        assert schema_path.is_file()
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        assert schema["$id"] == "https://sesslint.dev/schemas/sesslint.hook-result/v1"

        for result in (
            run_hook("SessionEnd", _payload(SEEDED)),
            run_hook("SessionStart", _payload(CLEAN)),
            run_hook("SessionStart", b"{}"),
        ):
            d = result.to_dict()
            for req in schema["required"]:
                assert req in d, f"missing {req}"
            assert d["schema"] == schema["properties"]["schema"]["const"]
            assert d["verdict"] in schema["properties"]["verdict"]["enum"]
            assert isinstance(d["findings_by_code"], dict)
