"""Tests for ``sesslint hook`` (agent-hooks T-01).

The subcommand reads one Claude Code hook payload from stdin, resolves
``transcript_path``, and runs the event-appropriate check. Contract under
test: advisory exit codes only (never 2), skip-not-crash on every bad
input, content-free output, and the SessionEnd -> SL009 event map.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from sesslint.hook_event import (
    HOOK_RESULT_SCHEMA,
    MAX_HOOK_PAYLOAD_BYTES,
    run_hook,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES_ROOT = REPO_ROOT / "fixtures"
SEEDED = FIXTURES_ROOT / "checks" / "secret_seed" / "sl009_seeded.jsonl"
CLEAN = FIXTURES_ROOT / "checks" / "secret_seed" / "sl009_clean.jsonl"
CORRUPT = FIXTURES_ROOT / "checks" / "sl011_outlier.jsonl"


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

    def test_sessionstart_corrupt_reports_findings(self) -> None:
        r = run_hook("SessionStart", _payload(CORRUPT))
        assert r.verdict == "findings"
        assert r.top_code == "SL011"
        assert r.findings_by_code == {"SL011": 1}
        assert r.exit_code == 0  # advisory: findings never block

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
