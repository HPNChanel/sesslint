"""AC-03: lone UTF-16 surrogates are findings, and --json errors stay valid JSON.

A JSONL line containing the escape ``\\ud800`` must produce a finding and must
not abort the process. With ``--json`` (or ``--output-format json``), stdout
on every error exit parses with ``json.loads``, including a missing file.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from sesslint.api import check_file
from sesslint.cli import main
from sesslint.errors import SchemaError
from sesslint.io import _DuplicateAwareDecoder, decode_json_dupaware

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "cli" / "check_basic"
HEALTHY = FIXTURES / "healthy.jsonl"
SENTINEL = "SENTINEL_ALPHA_UD800"


def _run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    try:
        code = main(argv)
    except SystemExit as exc:
        status = exc.code
        code = status if isinstance(status, int) else 1
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _claude_line(message: str, *, record_id: str = "msg_01", parent: str | None = None) -> str:
    record: dict[str, object] = {
        "id": record_id,
        "type": "user_message" if parent is None else "assistant_message",
        "message": message,
        "timestamp": "2025-01-01T12:00:00Z",
    }
    if parent is not None:
        record["parentId"] = parent
        record["type"] = "assistant_message"
    return json.dumps(record, ensure_ascii=True)


def test_decode_rejects_lone_surrogate_and_keeps_pairs() -> None:
    """The strict decoder rejects unpaired surrogates and accepts real pairs."""
    with pytest.raises(ValueError, match="lone surrogate"):
        decode_json_dupaware('{"text":"\\ud800"}')
    with pytest.raises(ValueError, match="lone surrogate"):
        decode_json_dupaware('{"text":"\\udc00"}')
    with pytest.raises(ValueError, match="lone surrogate"):
        _DuplicateAwareDecoder().decode('{"text":"\\udfff"}')

    paired, _dups, _trunc = decode_json_dupaware('{"text":"\\ud83d\\ude00"}')
    assert paired["text"] == "\U0001f600"

    literal, _dups, _trunc = decode_json_dupaware('{"text":"\\\\ud800"}')
    assert literal["text"] == "\\ud800"


def test_lone_surrogate_line_is_a_finding(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A nonterminal ``\\ud800`` line is SL001; the check does not abort."""
    path = tmp_path / "lone.jsonl"
    bad = _claude_line(f"{SENTINEL} \ud800")
    good = _claude_line("ok", record_id="msg_02", parent="msg_01")
    # ensure_ascii left the surrogate escape intact inside the message string.
    assert "\\ud800" in bad
    path.write_text(bad + "\n" + good + "\n", encoding="utf-8")

    report = check_file(path)
    assert any(f.code == "SL001" for f in report.findings)
    assert all(SENTINEL not in f.message for f in report.findings)

    code, out, err = _run(["check", str(path)], capsys)
    assert code == 1
    assert "Traceback" not in out
    assert "Traceback" not in err
    assert "Canonical serialization" not in err
    assert "Validation error" not in err
    assert "Malformed record" in out
    assert SENTINEL not in out
    assert SENTINEL not in err
    assert "\\ud800" not in out


def test_terminal_lone_surrogate_is_a_finding(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A file whose only line contains ``\\ud800`` still yields a finding."""
    path = tmp_path / "only.jsonl"
    path.write_text(_claude_line(f"{SENTINEL} \ud800") + "\n", encoding="utf-8")
    code, out, err = _run(["check", str(path), "--json"], capsys)
    assert code == 1
    data = json.loads(out)
    assert data["schema_version"] == "sesslint.report/v1"
    assert any(f["code"] in {"SL001", "SL002"} for f in data["findings"])
    assert SENTINEL not in out
    assert "Traceback" not in err


def test_canonical_event_lone_surrogate(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Canonical JSONL reports the bad event instead of raising SchemaError."""
    path = tmp_path / "canon.jsonl"
    header = (
        '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1",'
        '"session_id":"ac03"}\n'
    )
    bad = (
        '{"actor":"user","id":"evt_bad","kind":"message","parent_id":null,'
        '"payload":{"text":"' + SENTINEL + ' \\ud800"},"seq":0,'
        '"ts":"2026-09-05T12:00:00Z"}\n'
    )
    good = (
        '{"actor":"assistant","id":"evt_ok","kind":"message","parent_id":"evt_bad",'
        '"payload":{"text":"ok"},"seq":1,"ts":"2026-09-05T12:00:01Z"}\n'
    )
    path.write_text(header + bad + good, encoding="utf-8")
    code, out, err = _run(["check", str(path), "--format", "canonical", "--json"], capsys)
    assert code == 1
    data = json.loads(out)
    assert any(f["code"] == "SL001" for f in data["findings"])
    assert SENTINEL not in out
    assert "Canonical serialization" not in err


def test_paired_surrogate_and_literal_escape_stay_healthy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A real surrogate pair and a literal backslash-u sequence are not malformed."""
    emoji = tmp_path / "emoji.jsonl"
    emoji.write_text(_claude_line("hi \U0001f600") + "\n", encoding="utf-8")
    code, out, _err = _run(["check", str(emoji), "--json"], capsys)
    assert code == 0
    assert json.loads(out)["counts"]["total"] == 0

    literal = tmp_path / "literal.jsonl"
    literal.write_text(_claude_line("see \\\\ud800") + "\n", encoding="utf-8")
    code, out, _err = _run(["check", str(literal), "--json"], capsys)
    assert code == 0
    data = json.loads(out)
    assert data["counts"]["total"] == 0
    assert "ud800" not in out


def test_surrogate_human_color_respects_no_color(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--color always`` is ANSI; ``NO_COLOR=1`` strips it. The finding stays."""
    path = tmp_path / "lone.jsonl"
    path.write_text(_claude_line(f"{SENTINEL} \ud800") + "\n", encoding="utf-8")
    monkeypatch.delenv("NO_COLOR", raising=False)
    code, colored, _err = _run(["check", str(path), "--color", "always"], capsys)
    assert code == 1
    assert "\033[" in colored
    assert "Integrity check failed" in colored

    monkeypatch.setenv("NO_COLOR", "1")
    code, plain, _err = _run(["check", str(path), "--color", "always"], capsys)
    assert code == 1
    assert "\033[" not in plain
    assert "Integrity check failed" in plain
    assert SENTINEL not in plain


def test_missing_file_json_is_parseable(capsys: pytest.CaptureFixture[str]) -> None:
    """``check --json /nope.jsonl`` writes one JSON object and exits 2."""
    code, out, err = _run(["check", "--json", "/nope.jsonl"], capsys)
    assert code == 2
    data = json.loads(out)
    assert data["verdict"] == "error"
    assert data["code"] == "ERROR"
    assert "/nope.jsonl" in data["message"]
    assert "not found" in data["message"].lower()
    assert "Traceback" not in err


def test_missing_file_json_ignores_no_color(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The error document is the same with and without ``NO_COLOR``."""
    monkeypatch.delenv("NO_COLOR", raising=False)
    code_a, out_a, _err = _run(["check", "--json", "/nope.jsonl"], capsys)
    monkeypatch.setenv("NO_COLOR", "1")
    code_b, out_b, _err = _run(["check", "--json", "/nope.jsonl"], capsys)
    assert code_a == code_b == 2
    assert json.loads(out_a) == json.loads(out_b)


def test_missing_file_human_stdout_stays_empty(capsys: pytest.CaptureFixture[str]) -> None:
    """Without ``--json``, a missing file still reports on stderr only."""
    code, out, err = _run(["check", "/nope.jsonl"], capsys)
    assert code == 2
    assert out == ""
    assert "not found" in err.lower()


def test_json_error_branches(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Every --json failure path prints one object ``json.loads`` accepts."""
    healthy = HEALTHY
    bad_cfg = tmp_path / "bad.toml"
    bad_cfg.write_text("[[[", encoding="utf-8")
    bad_base = tmp_path / "bad-baseline.json"
    bad_base.write_text("{", encoding="utf-8")
    missing = tmp_path / "missing.jsonl"
    ledger = tmp_path / "ledger.jsonl"
    out_file = tmp_path / "out.jsonl"
    cases: list[tuple[str, list[str]]] = [
        ("check-missing", ["check", "--json", "/nope.jsonl"]),
        ("check-output-format-json-missing", ["check", "--output-format", "json", str(missing)]),
        ("check-directory", ["check", "--json", str(tmp_path)]),
        ("check-policy", ["check", "--json", "--policy", "salvage", str(healthy)]),
        ("check-profile", ["check", "--json", "--profile", "bogus_profile", str(healthy)]),
        ("check-stdin-combo", ["check", "--json", "-", str(healthy)]),
        ("check-multi-missing", ["check", "--json", str(healthy), str(missing)]),
        ("check-multi-directory", ["check", "--json", str(healthy), str(tmp_path)]),
        (
            "check-seal-multi",
            ["check", "--json", "--seal", str(ledger), str(healthy), str(healthy)],
        ),
        (
            "check-seal-directory",
            ["check", "--json", "--recursive", "--seal", str(ledger), str(tmp_path)],
        ),
        ("check-config", ["check", "--json", "--config", str(bad_cfg), str(healthy)]),
        ("check-baseline", ["check", "--json", "--baseline", str(bad_base), str(healthy)]),
        ("check-no-path", ["check", "--json"]),
        ("check-max-files", ["check", "--json", "--max-files", "0", str(healthy)]),
        ("check-confidence", ["check", "--json", "--confidence-min", "2", str(healthy)]),
        ("check-format", ["check", "--json", "--format", "nope", str(healthy)]),
        (
            "check-select-ignore",
            ["check", "--json", "--select", "SL101", "--ignore", "SL102", str(healthy)],
        ),
        ("check-unknown-code", ["check", "--json", "--ignore", "SL999", str(healthy)]),
        (
            "check-json-and-format",
            ["check", "--json", "--output-format", "sarif", str(healthy)],
        ),
        ("scan-no-path", ["scan", "--json"]),
        ("scan-missing", ["scan", "--json", str(missing)]),
        ("scan-output-format-json-missing", ["scan", "--output-format", "json", str(missing)]),
        ("scan-jobs", ["scan", "--json", "--jobs", "nope", str(tmp_path)]),
        ("scan-top", ["scan", "--json", "--top", "-1", str(tmp_path)]),
        ("scan-agent", ["scan", "--json", "--agent", "nope"]),
        ("repair-no-path", ["repair", "--json"]),
        ("repair-missing", ["repair", "--json", "--dry-run", str(missing)]),
        ("repair-directory", ["repair", "--json", "--dry-run", str(tmp_path)]),
        ("repair-profile", ["repair", "--json", "--dry-run", "--profile", "bogus", str(healthy)]),
        ("repair-no-output", ["repair", "--json", str(healthy)]),
        (
            "repair-salvage-flag",
            ["repair", "--json", "--dry-run", "--salvage-unsupported", str(healthy)],
        ),
        (
            "repair-preview-output",
            ["repair", "--json", "--preview", "--output", str(out_file), str(healthy)],
        ),
        (
            "repair-seal-dry-run",
            ["repair", "--json", "--dry-run", "--seal", str(ledger), str(healthy)],
        ),
        (
            "repair-plan-policy",
            [
                "repair",
                "--json",
                "--apply-plan",
                str(tmp_path / "plan.json"),
                "--policy",
                "salvage",
                "--dry-run",
                str(healthy),
            ],
        ),
        ("repair-bad-policy", ["repair", "--json", "--policy", "nope", str(healthy)]),
        ("verify-no-args", ["verify", "--json"]),
        ("verify-no-paths", ["verify", "--json", "--manifest", str(missing)]),
        (
            "verify-missing-manifest",
            ["verify", "--json", str(healthy), str(healthy), "--manifest", str(missing)],
        ),
        ("bundle-missing", ["bundle", "--json", str(missing)]),
        ("bundle-no-path", ["bundle", "--json"]),
        ("bundle-directory", ["bundle", "--json", str(tmp_path)]),
        ("export-no-output", ["export", "--json", str(healthy)]),
        ("export-no-path", ["export", "--json"]),
        ("export-missing", ["export", "--json", str(missing), "--output", str(out_file)]),
        ("diff-missing", ["diff", "--json", str(missing), str(tmp_path / "b.jsonl")]),
        ("diff-no-args", ["diff", "--json"]),
        ("stats-no-path", ["stats", "--json"]),
        ("stats-missing", ["stats", "--json", str(missing)]),
        ("stats-agent-and-path", ["stats", "--json", "--agent", "claude", str(healthy)]),
        ("seal-missing", ["seal", "--json", "--verify", str(missing)]),
        ("seal-no-ledger", ["seal", "--json"]),
        ("watch-no-path", ["watch", "--json"]),
        ("watch-missing", ["watch", "--json", str(missing)]),
        ("watch-interval", ["watch", "--json", "--interval", "0", str(tmp_path)]),
    ]
    for name, argv in cases:
        code, out, err = _run(argv, capsys)
        try:
            data = json.loads(out)
        except json.JSONDecodeError as exc:
            raise AssertionError(
                f"{name}: stdout is not JSON (exit {code})\nstdout={out!r}\nstderr={err!r}"
            ) from exc
        assert isinstance(data, dict), name
        assert data.get("verdict") == "error", (name, data)
        assert data.get("code") == "ERROR", name
        assert isinstance(data.get("message"), str) and data["message"], name
        assert code not in (0, 130), (name, code)
        assert "Traceback" not in out
        assert "Traceback" not in err


def test_json_schema_error_branch(capsys: pytest.CaptureFixture[str]) -> None:
    """A SchemaError during check --json is an error object, not a traceback."""
    with patch("sesslint.api.check_file", side_effect=SchemaError("schema boom")):
        code, out, err = _run(["check", "--json", str(HEALTHY)], capsys)
    assert code == 1
    data = json.loads(out)
    assert data["verdict"] == "error"
    assert "schema boom" in data["message"]
    assert "Traceback" not in err


def test_json_top_level_file_not_found(capsys: pytest.CaptureFixture[str]) -> None:
    """FileNotFoundError escaping dispatch still yields JSON in --json mode."""
    with patch("sesslint.cli._dispatch_command", side_effect=FileNotFoundError("gone")):
        code, out, _err = _run(["version", "--json"], capsys)
    assert code == 2
    data = json.loads(out)
    assert data["verdict"] == "error"
    assert "gone" in data["message"]
