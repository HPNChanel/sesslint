"""Tests for the seal hash-chain evidence ledger (evidence-assurance T-01).

Coverage: entry determinism (same inputs -> identical line modulo
``sealed_at``), chain verification (ok / every tamper vector), fail-closed
append (a divergent ledger is never extended), CLI wiring for
``--seal``/``--seal-no-path``/``--seal-genesis-of`` and ``seal --verify``,
and content-free guarantees (no transcript bytes in ledger lines).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sesslint import seal
from sesslint.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
CODEX = FIXTURES_DIR / "adapters" / "codex"
HEALTHY = CODEX / "healthy_min.jsonl"
DANGLING = CODEX / "dangling_call.jsonl"

NOW = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)


def _entry(**kw: object) -> dict[str, object]:
    base: dict[str, object] = {
        "seq": 1,
        "prev_sha256": seal.GENESIS,
        "file_sha256": "a" * 64,
        "path": "sess.jsonl",
        "tool": "check",
        "verdict": "healthy",
        "codes": {"SL101": 2},
        "report_sha256": "b" * 64,
        "now": NOW,
    }
    base.update(kw)
    return seal.build_entry(**base)  # type: ignore[arg-type]


def _lines(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# --- unit: entry construction -----------------------------------------------


def test_entry_hash_binds_all_fields() -> None:
    e = _entry()
    assert e["schema"] == seal.SEAL_SCHEMA_ID
    preimage = {k: v for k, v in e.items() if k != "entry_sha256"}
    assert e["entry_sha256"] == seal.sha256_bytes(seal.canonical_json_bytes(preimage))


def test_entry_deterministic_given_clock() -> None:
    assert _entry() == _entry()


def test_entry_field_validation() -> None:
    with pytest.raises(seal.SealError):
        _entry(seq=0)
    with pytest.raises(seal.SealError):
        _entry(file_sha256="not-hex")
    with pytest.raises(seal.SealError):
        _entry(tool="scan")
    with pytest.raises(seal.SealError):
        _entry(codes={"SL001": -1})
    with pytest.raises(seal.SealError):
        _entry(prev_sha256="z" * 64)


def test_sealed_at_format() -> None:
    e = _entry()
    assert isinstance(e["sealed_at"], str)
    assert str(e["sealed_at"]).endswith("Z")


# --- unit: append + verify ---------------------------------------------------


def test_append_and_verify_clean(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    for i in range(3):
        seal.append_seal(
            ledger,
            tool="check",
            file_sha256=f"{i:064x}",
            path="s.jsonl",
            verdict="healthy",
            codes={},
            report_sha256="b" * 64,
            now=NOW,
        )
    entries = _lines(ledger)
    assert [e["seq"] for e in entries] == [1, 2, 3]
    assert entries[0]["prev_sha256"] == seal.GENESIS
    assert entries[1]["prev_sha256"] == entries[0]["entry_sha256"]
    assert entries[2]["prev_sha256"] == entries[1]["entry_sha256"]
    count, div = seal.verify_ledger(ledger)
    assert div is None and count == 3


def test_verify_edit_detected(tmp_path: Path) -> None:
    ledger = tmp_path / "l.jsonl"
    for i in range(3):
        seal.append_seal(
            ledger,
            tool="check",
            file_sha256=f"{i:064x}",
            path=None,
            verdict="healthy",
            codes={},
            report_sha256="b" * 64,
            now=NOW,
        )
    raw = ledger.read_text().splitlines()
    raw[1] = raw[1].replace("healthy", "invalid")
    ledger.write_text("\n".join(raw) + "\n")
    count, div = seal.verify_ledger(ledger)
    assert div is not None
    assert div["kind"] == "hash-mismatch" and div["line"] == 2
    assert count == 1


def test_verify_dropped_line_detected(tmp_path: Path) -> None:
    ledger = tmp_path / "l.jsonl"
    for i in range(3):
        seal.append_seal(
            ledger,
            tool="check",
            file_sha256=f"{i:064x}",
            path=None,
            verdict="healthy",
            codes={},
            report_sha256="b" * 64,
            now=NOW,
        )
    raw = ledger.read_text().splitlines()
    del raw[1]
    ledger.write_text("\n".join(raw) + "\n")
    _count, div = seal.verify_ledger(ledger)
    assert div is not None
    # seq of surviving line 3 is 3 but expected 2 -> seq-gap fires first.
    assert div["kind"] == "seq-gap"


def test_verify_reorder_detected(tmp_path: Path) -> None:
    ledger = tmp_path / "l.jsonl"
    for i in range(3):
        seal.append_seal(
            ledger,
            tool="check",
            file_sha256=f"{i:064x}",
            path=None,
            verdict="healthy",
            codes={},
            report_sha256="b" * 64,
            now=NOW,
        )
    raw = ledger.read_text().splitlines()
    raw[1], raw[2] = raw[2], raw[1]
    ledger.write_text("\n".join(raw) + "\n")
    _count, div = seal.verify_ledger(ledger)
    assert div is not None and div["kind"] in ("seq-gap", "chain-break")


def test_verify_truncated_tail_detected(tmp_path: Path) -> None:
    ledger = tmp_path / "l.jsonl"
    seal.append_seal(
        ledger,
        tool="check",
        file_sha256="a" * 64,
        path=None,
        verdict="healthy",
        codes={},
        report_sha256="b" * 64,
        now=NOW,
    )
    raw = ledger.read_text()
    ledger.write_text(raw[: len(raw) - 30])
    _count, div = seal.verify_ledger(ledger)
    assert div is not None and div["kind"] == "malformed-line"


def test_append_refuses_divergent_ledger(tmp_path: Path) -> None:
    ledger = tmp_path / "l.jsonl"
    seal.append_seal(
        ledger,
        tool="check",
        file_sha256="a" * 64,
        path=None,
        verdict="healthy",
        codes={},
        report_sha256="b" * 64,
        now=NOW,
    )
    raw = ledger.read_text().replace("healthy", "invalid")
    ledger.write_text(raw)
    with pytest.raises(seal.SealError, match="divergent"):
        seal.append_seal(
            ledger,
            tool="check",
            file_sha256="c" * 64,
            path=None,
            verdict="healthy",
            codes={},
            report_sha256="b" * 64,
            now=NOW,
        )


def test_genesis_of_binds_first_line_only(tmp_path: Path) -> None:
    ledger = tmp_path / "l.jsonl"
    prev_tail = "f" * 64
    seal.append_seal(
        ledger,
        tool="check",
        file_sha256="a" * 64,
        path=None,
        verdict="healthy",
        codes={},
        report_sha256="b" * 64,
        genesis_of=prev_tail,
        now=NOW,
    )
    assert _lines(ledger)[0]["genesis_of"] == prev_tail
    with pytest.raises(seal.SealError, match="first line"):
        seal.append_seal(
            ledger,
            tool="check",
            file_sha256="a" * 64,
            path=None,
            verdict="healthy",
            codes={},
            report_sha256="b" * 64,
            genesis_of=prev_tail,
            now=NOW,
        )


def test_verify_missing_ledger_raises(tmp_path: Path) -> None:
    with pytest.raises(seal.SealError):
        seal.verify_ledger(tmp_path / "absent.jsonl")


def test_empty_ledger_verifies_zero(tmp_path: Path) -> None:
    ledger = tmp_path / "l.jsonl"
    ledger.write_text("")
    count, div = seal.verify_ledger(ledger)
    assert count == 0 and div is None


# --- CLI: check --seal --------------------------------------------------------


def test_cli_check_seal_appends(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    ledger = tmp_path / "ledger.jsonl"
    code = main(["check", str(HEALTHY), "--format", "codex-rollout", "--seal", str(ledger)])
    assert code == 0
    assert "sealed: seq 1" in capsys.readouterr().err
    entries = _lines(ledger)
    assert len(entries) == 1
    e = entries[0]
    assert e["tool"] == "check"
    assert e["verdict"] == "healthy"
    assert e["file_sha256"] == seal.sha256_file(HEALTHY)
    assert "healthy_min.jsonl" in str(e["path"])


def test_cli_check_seal_invalid_verdict(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    code = main(["check", str(DANGLING), "--format", "codex-rollout", "--seal", str(ledger)])
    assert code == 1  # finding still fails the command
    e = _lines(ledger)[0]
    assert e["verdict"] == "invalid"
    assert e["codes"].get("SL102") == 1


def test_cli_check_seal_chain_grows(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    for _ in range(2):
        main(["check", str(HEALTHY), "--format", "codex-rollout", "--seal", str(ledger)])
    entries = _lines(ledger)
    assert [e["seq"] for e in entries] == [1, 2]
    assert entries[1]["prev_sha256"] == entries[0]["entry_sha256"]


def test_cli_check_seal_no_path(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    main(
        [
            "check",
            str(HEALTHY),
            "--format",
            "codex-rollout",
            "--seal",
            str(ledger),
            "--seal-no-path",
        ]
    )
    assert "path" not in _lines(ledger)[0]


def test_cli_check_seal_refuses_dir(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    code = main(
        [
            "check",
            str(CODEX),
            "-r",
            "--format",
            "codex-rollout",
            "--seal",
            str(ledger),
        ]
    )
    assert code == 2
    assert not ledger.exists()


def test_cli_check_seal_refuses_multi_path(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    code = main(
        [
            "check",
            str(HEALTHY),
            str(DANGLING),
            "--format",
            "codex-rollout",
            "--seal",
            str(ledger),
        ]
    )
    assert code == 2
    assert not ledger.exists()


def test_cli_check_seal_refuses_divergent_ledger(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    main(["check", str(HEALTHY), "--format", "codex-rollout", "--seal", str(ledger)])
    ledger.write_text(ledger.read_text().replace("healthy", "invalid"))
    code = main(["check", str(HEALTHY), "--format", "codex-rollout", "--seal", str(ledger)])
    assert code == 2
    assert len(_lines(ledger)) == 1  # never extended


def test_cli_check_seal_deterministic_modulo_clock(tmp_path: Path) -> None:
    a = tmp_path / "a.jsonl"
    b = tmp_path / "b.jsonl"
    for led in (a, b):
        main(["check", str(HEALTHY), "--format", "codex-rollout", "--seal", str(led)])
    ea, eb = _lines(a)[0], _lines(b)[0]
    for k in set(ea) | set(eb):
        if k != "sealed_at":
            assert ea[k] == eb[k], k


def test_cli_check_seal_stdin_omits_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import io
    import sys

    data = HEALTHY.read_bytes()

    class _FakeStdin:
        buffer = io.BytesIO(data)

    monkeypatch.setattr(sys, "stdin", _FakeStdin())
    ledger = tmp_path / "ledger.jsonl"
    code = main(["check", "-", "--format", "codex-rollout", "--seal", str(ledger)])
    assert code == 0
    e = _lines(ledger)[0]
    assert e["file_sha256"] == seal.sha256_bytes(data)
    assert "path" not in e  # stdin has no artifact path


def test_cli_check_seal_content_free(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    secret = "super-sensitive-payload-body-xyzzy"
    bad = tmp_path / "s.jsonl"
    bad.write_text(
        '{"actor":"user","id":"e1","kind":"message","parent_id":null,'
        f'"payload":{{"text":"{secret}"}},"seq":0,"ts":"2026-09-06T00:00:00Z"}}\n'
    )
    main(["check", str(bad), "--format", "canonical", "--seal", str(ledger)])
    text = ledger.read_text()
    assert secret not in text
    assert "healthy_min" not in text  # unrelated paths never leak


# --- CLI: seal --verify -------------------------------------------------------


def test_cli_seal_verify_ok(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    ledger = tmp_path / "ledger.jsonl"
    main(["check", str(HEALTHY), "--format", "codex-rollout", "--seal", str(ledger)])
    capsys.readouterr()
    code = main(["seal", "--verify", str(ledger)])
    assert code == 0
    assert "ok: 1 sealed entries" in capsys.readouterr().out


def test_cli_seal_verify_divergence(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    ledger = tmp_path / "ledger.jsonl"
    main(["check", str(HEALTHY), "--format", "codex-rollout", "--seal", str(ledger)])
    ledger.write_text(ledger.read_text().replace("healthy", "invalid"))
    code = main(["seal", "--verify", str(ledger)])
    assert code == 1
    assert "divergence at line 1" in capsys.readouterr().err


def test_cli_seal_verify_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    ledger = tmp_path / "ledger.jsonl"
    main(["check", str(HEALTHY), "--format", "codex-rollout", "--seal", str(ledger)])
    capsys.readouterr()
    code = main(["seal", "--verify", str(ledger), "--json"])
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out == {"entries": 1, "ok": True, "divergence": None}


def test_cli_seal_verify_missing(tmp_path: Path) -> None:
    assert main(["seal", "--verify", str(tmp_path / "none.jsonl")]) == 2


# --- CLI: verify --seal -------------------------------------------------------


def test_cli_verify_seal(tmp_path: Path) -> None:
    d = FIXTURES_DIR / "verify" / "ok"
    ledger = tmp_path / "ledger.jsonl"
    code = main(
        [
            "verify",
            "--source",
            str(d / "source.jsonl"),
            "--plan",
            str(d / "plan.json"),
            "--output",
            str(d / "output.jsonl"),
            "--manifest",
            str(d / "manifest.json"),
            "--seal",
            str(ledger),
        ]
    )
    assert code == 0
    e = _lines(ledger)[0]
    assert e["tool"] == "verify" and e["verdict"] == "ok"
    assert e["file_sha256"] == seal.sha256_file(d / "output.jsonl")


# --- CLI: repair --seal -------------------------------------------------------

REPAIR_FIXTURES = FIXTURES_DIR / "repair_cli"


def test_cli_repair_seal(tmp_path: Path) -> None:
    src = REPAIR_FIXTURES / "basic" / "source.jsonl"
    out = tmp_path / "repaired.jsonl"
    ledger = tmp_path / "ledger.jsonl"
    code = main(["repair", str(src), "--out", str(out), "--seal", str(ledger)])
    assert code == 0
    e = _lines(ledger)[0]
    assert e["tool"] == "repair" and e["verdict"] == "repaired"
    assert e["codes"] == {}
    # The sealed artifact is the produced output, not the source.
    assert e["file_sha256"] == seal.sha256_file(out)
    assert e["file_sha256"] != seal.sha256_file(src)


def test_cli_repair_seal_refuses_dry_run(tmp_path: Path) -> None:
    src = REPAIR_FIXTURES / "basic" / "source.jsonl"
    ledger = tmp_path / "ledger.jsonl"
    code = main(
        [
            "repair",
            str(src),
            "--out",
            str(tmp_path / "out.jsonl"),
            "--dry-run",
            "--seal",
            str(ledger),
        ]
    )
    assert code == 2
    assert not ledger.exists()


def test_cli_repair_seal_refuses_preview(tmp_path: Path) -> None:
    src = REPAIR_FIXTURES / "basic" / "source.jsonl"
    ledger = tmp_path / "ledger.jsonl"
    code = main(["repair", str(src), "--preview", "--seal", str(ledger)])
    assert code == 2
    assert not ledger.exists()


def test_cli_repair_seal_refuses_plan_only(tmp_path: Path) -> None:
    src = REPAIR_FIXTURES / "basic" / "source.jsonl"
    ledger = tmp_path / "ledger.jsonl"
    code = main(
        [
            "repair",
            str(src),
            "--plan-out",
            str(tmp_path / "plan.json"),
            "--seal",
            str(ledger),
        ]
    )
    assert code == 2
    assert not ledger.exists()


def test_cli_repair_seal_refuses_batch(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    code = main(
        [
            "repair",
            "--batch",
            str(REPAIR_FIXTURES / "basic"),
            "--output-dir",
            str(tmp_path / "out"),
            "--seal",
            str(ledger),
        ]
    )
    assert code == 2
    assert not ledger.exists()


# --- CLI: repair --seal -------------------------------------------------------

REPAIR_FIXTURES = FIXTURES_DIR / "repair_cli"


def test_cli_repair_seal(tmp_path: Path) -> None:
    src = REPAIR_FIXTURES / "basic" / "source.jsonl"
    out = tmp_path / "repaired.jsonl"
    ledger = tmp_path / "ledger.jsonl"
    code = main(["repair", str(src), "--out", str(out), "--seal", str(ledger)])
    assert code == 0
    e = _lines(ledger)[0]
    assert e["tool"] == "repair" and e["verdict"] == "repaired"
    assert e["codes"] == {}
    # The sealed artifact is the produced output, not the source.
    assert e["file_sha256"] == seal.sha256_file(out)
    assert e["file_sha256"] != seal.sha256_file(src)


def test_cli_repair_seal_refuses_dry_run(tmp_path: Path) -> None:
    src = REPAIR_FIXTURES / "basic" / "source.jsonl"
    ledger = tmp_path / "ledger.jsonl"
    code = main(
        [
            "repair",
            str(src),
            "--out",
            str(tmp_path / "out.jsonl"),
            "--dry-run",
            "--seal",
            str(ledger),
        ]
    )
    assert code == 2
    assert not ledger.exists()


def test_cli_repair_seal_refuses_preview(tmp_path: Path) -> None:
    src = REPAIR_FIXTURES / "basic" / "source.jsonl"
    ledger = tmp_path / "ledger.jsonl"
    code = main(["repair", str(src), "--preview", "--seal", str(ledger)])
    assert code == 2
    assert not ledger.exists()


def test_cli_repair_seal_refuses_plan_only(tmp_path: Path) -> None:
    src = REPAIR_FIXTURES / "basic" / "source.jsonl"
    ledger = tmp_path / "ledger.jsonl"
    code = main(
        [
            "repair",
            str(src),
            "--plan-out",
            str(tmp_path / "plan.json"),
            "--seal",
            str(ledger),
        ]
    )
    assert code == 2
    assert not ledger.exists()


def test_cli_repair_seal_refuses_batch(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    code = main(
        [
            "repair",
            "--batch",
            str(REPAIR_FIXTURES / "basic"),
            "--output-dir",
            str(tmp_path / "out"),
            "--seal",
            str(ledger),
        ]
    )
    assert code == 2
    assert not ledger.exists()


# --- schema -------------------------------------------------------------------


def test_seal_schema_self_consistent() -> None:
    schema = seal.load_seal_schema()
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["properties"]["schema"]["const"] == seal.SEAL_SCHEMA_ID
    assert set(schema["required"]).issubset(set(schema["properties"]))
    # every emitted entry satisfies required keys
    e = _entry(path=None)
    assert set(schema["required"]).issubset(set(e))
    allowed = set(schema["properties"])
    assert set(e).issubset(allowed)
