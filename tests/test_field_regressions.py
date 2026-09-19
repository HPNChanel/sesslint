"""Regression tests for real-world field-test fixes (waves A3–A6).

Covers defects discovered when SessLint was exercised against real Claude Code
and Codex session artifacts rather than synthetic fixtures:

- SL003 classified byte-identical vendor duplicates as "conflicting" because
  the comparison hash included the positional ``seq`` ordinal.
- ``orphan-result-drop`` failed with "invalid target index" because plan-time
  indices went stale after earlier steps shrank the event list; identity
  anchors are now threaded through step params.
- ``check`` reported SL302 on non-UTF-8/binary files while ``scan`` reported
  unreadable; both paths now share ``io.probe_text_encoding``.
- ``check --format X`` on empty files reported healthy.
- Single-file ``check --json --skip-undetected`` printed text to stdout,
  breaking JSON consumers.
- Recursive scans descended into ``.git`` and re-flagged SessLint's own
  manifest/config files.
- ``reparse_identity_hashes`` normalizes synthetic IDs and sequence drift so
  vendor write-back outputs verify.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from sesslint.api import check_file
from sesslint.cli import main
from sesslint.io import probe_text_encoding

_HDR = (
    '{"created_at":"2026-09-13T00:00:00Z","schema_version":"sesslint.session/v1",'
    '"session_id":"field-reg","source":{"format":"canonical"},"version":1}'
)


def _ev(
    id_: str,
    kind: str,
    parent: str | None,
    seq: int,
    *,
    actor: str = "assistant",
    corr: str | None = None,
) -> str:
    e: dict[str, object] = {
        "actor": actor,
        "id": id_,
        "kind": kind,
        "parent_id": parent,
        "payload": {},
        "seq": seq,
        "ts": f"2026-09-13T00:00:{seq:02d}Z",
    }
    if corr is not None:
        e["correlation_id"] = corr
    return json.dumps(e)


# ---------------------------------------------------------------------------
# SL003: positional seq must not turn identical duplicates into "conflicting"
# ---------------------------------------------------------------------------


def test_sl003_identical_when_only_seq_differs(tmp_path: Path) -> None:
    """Same-id records whose only difference is seq classify identical, not conflicting."""
    e2 = json.loads(_ev("e2", "message", "e1", 1))
    e2b = dict(e2)
    e2b["seq"] = 2
    f = tmp_path / "dup.jsonl"
    f.write_text(
        "\n".join(
            [
                _HDR,
                _ev("e1", "message", None, 0, actor="user"),
                json.dumps(e2),
                json.dumps(e2b),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    report = check_file(f, format="canonical")
    sl003 = [x for x in report.findings if x.code == "SL003"]
    assert len(sl003) == 1
    assert sl003[0].severity.value == "warning"
    assert sl003[0].evidence is not None
    assert sl003[0].evidence.get("variant") == "identical-duplicate"


def test_sl003_vendor_byte_identical_lines(tmp_path: Path) -> None:
    """Byte-identical vendor lines (real duplicate) classify identical-duplicate."""
    line1 = {
        "type": "user",
        "uuid": "u1",
        "sessionId": "s1",
        "timestamp": "2026-01-01T00:00:00Z",
        "version": "2.0.30",
        "message": {"role": "user", "content": [{"type": "text", "text": "hi"}]},
    }
    line2 = {
        "type": "assistant",
        "uuid": "u2",
        "sessionId": "s1",
        "parentUuid": "u1",
        "timestamp": "2026-01-01T00:00:01Z",
        "version": "2.0.30",
        "message": {
            "role": "assistant",
            "model": "claude",
            "content": [{"type": "text", "text": "yo"}],
        },
    }
    f = tmp_path / "cldup.jsonl"
    f.write_text("\n".join(json.dumps(r) for r in (line1, line2, dict(line2))) + "\n")
    report = check_file(f)
    sl003 = [x for x in report.findings if x.code == "SL003"]
    assert len(sl003) == 1
    assert sl003[0].evidence is not None
    assert sl003[0].evidence.get("variant") == "identical-duplicate"
    assert sl003[0].severity.value == "warning"


def test_sl003_conflicting_still_fires(tmp_path: Path) -> None:
    """Records differing in real content still classify conflicting (error)."""
    e2 = json.loads(_ev("e2", "message", "e1", 1))
    e2b = dict(e2)
    e2b["payload"] = {"different": True}
    f = tmp_path / "conf.jsonl"
    f.write_text(
        "\n".join(
            [
                _HDR,
                _ev("e1", "message", None, 0, actor="user"),
                json.dumps(e2),
                json.dumps(e2b),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    report = check_file(f, format="canonical")
    sl003 = [x for x in report.findings if x.code == "SL003"]
    assert len(sl003) == 1
    assert sl003[0].severity.value == "error"
    assert sl003[0].evidence is not None
    assert sl003[0].evidence.get("variant") == "conflicting-duplicate"


# ---------------------------------------------------------------------------
# orphan-result-drop: identity anchors survive earlier index shifts
# ---------------------------------------------------------------------------


def test_orphan_result_drop_resolves_by_id(tmp_path: Path) -> None:
    """Two orphan drops in one plan resolve by result_id, not stale indices."""
    f = tmp_path / "orphans.jsonl"
    f.write_text(
        "\n".join(
            [
                _HDR,
                _ev("m1", "message", None, 0, actor="user"),
                _ev("c1", "tool_call", "m1", 1, corr="k1"),
                _ev("r9", "tool_result", "c1", 2, actor="tool", corr="k9"),
                _ev("r8", "tool_result", "c1", 3, actor="tool", corr="k8"),
                _ev("r1", "tool_result", "c1", 4, actor="tool", corr="k1"),
                _ev("m2", "message", "r1", 5),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "fixed.jsonl"
    rc = main(
        [
            "repair",
            str(f),
            "--output",
            str(out),
            "--policy",
            "salvage",
            "--acknowledge-side-effects",
        ]
    )
    assert rc == 0
    ids = [
        json.loads(line).get("id")
        for line in out.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert "r8" not in ids
    assert "r9" not in ids
    assert ids == [None, "m1", "c1", "r1", "m2"]  # header + kept events


# ---------------------------------------------------------------------------
# Encoding probe: check agrees with scan on binary/non-UTF-8 input
# ---------------------------------------------------------------------------


def test_check_non_utf8_is_sl001_not_sl302(tmp_path: Path) -> None:
    """A file with undecodable bytes reports SL001, not format-ambiguity SL302."""
    f = tmp_path / "nonutf8.jsonl"
    f.write_bytes(b'{"id":"e1","seq":0,"kind":"message","ts":0,"role":"user"}\n\xff\xfe invalid\n')
    report = check_file(f)
    codes = {x.code for x in report.findings}
    assert "SL001" in codes
    assert "SL302" not in codes


def test_check_nul_byte_is_sl001(tmp_path: Path) -> None:
    f = tmp_path / "nul.jsonl"
    f.write_bytes(b'{"id":"e1"}\n{"id":"e\x002"}\n')
    report = check_file(f)
    codes = {x.code for x in report.findings}
    assert "SL001" in codes
    assert "SL302" not in codes


def test_probe_text_encoding(tmp_path: Path) -> None:
    clean = tmp_path / "clean.jsonl"
    clean.write_text('{"a":1}\n', encoding="utf-8")
    nul = tmp_path / "nul.bin"
    nul.write_bytes(b'{"a":1}\n{"b":\x002}\n')
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b'{"a":1}\n\xff\xfe\n')
    assert probe_text_encoding(clean) is None
    assert probe_text_encoding(nul) == "nul"
    assert probe_text_encoding(bad) == "utf8"


# ---------------------------------------------------------------------------
# Empty input: forced --format must not report healthy
# ---------------------------------------------------------------------------


def test_empty_file_with_forced_format_is_invalid(tmp_path: Path) -> None:
    f = tmp_path / "empty.jsonl"
    f.write_bytes(b"")
    report = check_file(f, format="claude-code-jsonl")
    codes = {x.code for x in report.findings}
    assert "SL001" in codes
    assert report.counts.by_severity.get("error", 0) >= 1


def test_whitespace_only_with_forced_format_is_invalid(tmp_path: Path) -> None:
    f = tmp_path / "ws.jsonl"
    f.write_text("   \n\n  \n", encoding="utf-8")
    report = check_file(f, format="claude-code-jsonl")
    codes = {x.code for x in report.findings}
    assert "SL001" in codes


# ---------------------------------------------------------------------------
# Single-file skipped: --json/--sarif emit valid payloads, not empty stdout
# ---------------------------------------------------------------------------


def test_check_json_skip_undetected_emits_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    f = tmp_path / "package.json"
    f.write_text('{"name":"x"}\n', encoding="utf-8")
    rc = main(["check", str(f), "--json", "--skip-undetected"])
    out = capsys.readouterr().out
    payload = json.loads(out)  # must be valid JSON, not empty or human text
    assert payload["ok"] is True
    assert payload["skipped"] is True
    assert payload["skipped_reason"] == "format-undetected"
    assert payload["findings"] == []
    assert rc == 0


def test_check_sarif_skip_undetected_emits_sarif(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    f = tmp_path / "package.json"
    f.write_text('{"name":"x"}\n', encoding="utf-8")
    rc = main(["check", str(f), "--output-format", "sarif", "--skip-undetected"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["version"] == "2.1.0"
    assert "runs" in payload
    assert rc == 0


# ---------------------------------------------------------------------------
# Recursive scan: VCS dirs + own artifacts are excluded
# ---------------------------------------------------------------------------


def test_scan_excludes_git_dir_and_own_artifacts(tmp_path: Path) -> None:
    sess = tmp_path / "sess.jsonl"
    sess.write_text(_HDR + "\n" + _ev("e1", "message", None, 0, actor="user") + "\n")
    git_dir = tmp_path / ".git" / "objects"
    git_dir.mkdir(parents=True)
    (git_dir / "abc123").write_text("gitobject", encoding="utf-8")
    (tmp_path / "sesslint.toml").write_text("[tool.sesslint]\nprofile='neutral'\n")
    (tmp_path / "out.manifest.json").write_text(
        '{"schema_version":"sesslint.repair-manifest/v1"}', encoding="utf-8"
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        main(["scan", str(tmp_path), "--json"])
    report = json.loads(buf.getvalue())
    paths = [f["path"] for f in report.get("files", [])]
    assert len(paths) == 1
    assert paths[0].endswith("sess.jsonl")


# ---------------------------------------------------------------------------
# reparse_identity_hashes: synthetic ids + seq drift normalize away
# ---------------------------------------------------------------------------


def test_reparse_identity_hashes_normalizes_synthetic_ids() -> None:
    """Same surviving events re-parsed under different source hints hash identically."""
    from sesslint.canonical import SessionEvent, reparse_identity_hashes

    def _mk(id_: str, parent: str | None, seq: int) -> SessionEvent:
        return SessionEvent(
            id=id_,
            parent_id=parent,
            seq=seq,
            ts="2026-09-13T00:00:00Z",
            actor="user",
            kind="message",
            payload={"text": "x"},
        )

    # Source parse: synthetic ids derived from source path + ordinals.
    original = [
        _mk("sesslint:synthetic:claude_code:0:aaaa", None, 0),
        _mk("real-id-1", "sesslint:synthetic:claude_code:0:aaaa", 1),
        _mk("sesslint:synthetic:claude_code:2:bbbb", "real-id-1", 2),
    ]
    # Emitted-artifact re-parse: same surviving records, but the synthetic ids
    # re-derived under the output path hint and compacted ordinals — the
    # parent reference re-points at the same logical event via position.
    reparsed = [
        _mk("sesslint:synthetic:claude_code:0:zzzz", None, 0),
        _mk("real-id-1", "sesslint:synthetic:claude_code:0:zzzz", 1),
        _mk("sesslint:synthetic:claude_code:1:qqqq", "real-id-1", 2),
    ]
    assert reparse_identity_hashes(original) == reparse_identity_hashes(reparsed)


def test_codex_vendor_writeback_e2e(tmp_path: Path) -> None:
    """Codex rollout auto repair emits vendor write-back and verifies."""
    meta = {
        "ordinal": 0,
        "payload": {"cli_version": "0.154.0", "session_id": "sess-x"},
        "timestamp": "2026-09-17T10:00:00Z",
        "type": "session_meta",
    }
    msg = {
        "ordinal": 1,
        "payload": {
            "content": [{"text": "hi", "type": "input_text"}],
            "role": "user",
            "type": "message",
        },
        "timestamp": "2026-09-17T10:01:00Z",
        "type": "response_item",
    }
    f = tmp_path / "rollout.jsonl"
    f.write_text(
        "\n".join(json.dumps(r) for r in (meta, msg))
        + "\n"
        + '{"ordinal": 2, "payload":',  # torn tail
        encoding="utf-8",
    )
    out = tmp_path / "rollout_fixed.jsonl"
    rc = main(["repair", str(f), "--output", str(out)])
    assert rc == 0
    manifest = json.loads((tmp_path / "rollout_fixed.jsonl.manifest.json").read_text())
    assert manifest["adapter_id"] == "codex-rollout"
    # Output is vendor bytes (JSONL with ordinal/type), not canonical schema
    first = json.loads(out.read_text(encoding="utf-8").splitlines()[0])
    assert first["type"] == "session_meta"
    # Verify end-to-end
    rc_v = main(
        [
            "verify",
            str(f),
            str(out),
            "--manifest",
            str(tmp_path / "rollout_fixed.jsonl.manifest.json"),
        ]
    )
    assert rc_v == 0
