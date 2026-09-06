"""Empirical adversarial stress test harness for TASK-022 Verify Command.

Authored by Challenger 1.
Covers:
1. Malformed JSON across each input file (source, plan, output, manifest)
2. Non-dict root JSON across plan and manifest (list, int, str, bool, null)
3. Corrupted declared_loss and loss_totals (None, int, invalid string values)
4. Empty files (0 bytes individually and all 4 simultaneously)
5. Inaccessible paths and directories (nonexistent files, directory-as-file, CLI exit code 2)
6. Permuted event order vs permuted dictionary keys
7. Tampered manifest hashes, altered plan fingerprints, modified loss, falsified assurance
8. Non-short-circuiting reporting when checks 1, 2, 3, 4 (and 1-7) fail simultaneously
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from sesslint.cli import main
from sesslint.repair.fingerprint import compute_plan_fingerprint
from sesslint.verify import Verdict, verify

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = REPO_ROOT / "fixtures" / "verify"


def _make_base_bundle(dest_dir: Path) -> tuple[Path, Path, Path, Path]:
    """Create a completely valid baseline bundle."""
    dest_dir.mkdir(parents=True, exist_ok=True)

    src_content = (
        '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"adv-sess"}\n'
        '{"actor":"user","id":"m0","kind":"message","parent_id":null,"payload":{"text":"a"},"seq":0,"ts":"2026-09-05T12:00:00Z"}\n'
        '{"actor":"assistant","id":"m1","kind":"message","parent_id":"m0","payload":{"text":"b"},"seq":1,"ts":"2026-09-05T12:00:01Z"}\n'
        '{"actor":"assistant","id":"m1","kind":"message","parent_id":"m0","payload":{"text":"b"},"seq":1,"ts":"2026-09-05T12:00:01Z"}\n'
        '{"actor":"user","id":"m2","kind":"message","parent_id":"m1","payload":{"text":"c"},"seq":2,"ts":"2026-09-05T12:00:02Z"}\n'
    )
    src_bytes = src_content.encode("utf-8")
    src_path = dest_dir / "source.jsonl"
    src_path.write_bytes(src_bytes)
    src_hash = hashlib.sha256(src_bytes).hexdigest()

    out_content = (
        '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"adv-sess"}\n'
        '{"actor":"user","id":"m0","kind":"message","parent_id":null,"payload":{"text":"a"},"seq":0,"ts":"2026-09-05T12:00:00Z"}\n'
        '{"actor":"assistant","id":"m1","kind":"message","parent_id":"m0","payload":{"text":"b"},"seq":1,"ts":"2026-09-05T12:00:01Z"}\n'
        '{"actor":"user","id":"m2","kind":"message","parent_id":"m1","payload":{"text":"c"},"seq":2,"ts":"2026-09-05T12:00:02Z"}\n'
    )
    out_bytes = out_content.encode("utf-8")
    out_path = dest_dir / "output.jsonl"
    out_path.write_bytes(out_bytes)
    out_hash = hashlib.sha256(out_bytes).hexdigest()

    plan_dict: dict[str, Any] = {
        "blocked": [],
        "loss_accounting": {
            "preview": {
                "discarded-suffix": 0,
                "none": 0,
                "truncated-projection": 0,
            }
        },
        "policy": "conservative",
        "profile": "neutral",
        "source_hash": src_hash,
        "steps": [
            {
                "loss": {},
                "lossy": False,
                "params": {},
                "recipe": "identical-duplicate-collapse",
                "seq": 0,
                "target_finding_fp": "adv_fp_0",
                "target_index": 1,
            }
        ],
        "version": "sesslint.plan/v1",
    }
    plan_fp = compute_plan_fingerprint(plan_dict)
    plan_dict["fingerprint"] = plan_fp
    plan_path = dest_dir / "plan.json"
    plan_path.write_text(json.dumps(plan_dict, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    manifest_dict: dict[str, Any] = {
        "actions": [
            {
                "detail": "step 0",
                "kind": "identical-duplicate-collapse",
                "record_id": "adv_fp_0",
            }
        ],
        "assurance": "repaired-lossless",
        "declared_loss": [],
        "idempotency_key": "9" * 64,
        "input_fingerprint": src_hash,
        "output_fingerprint": out_hash,
        "plan_fingerprint": plan_fp,
        "policy": "conservative",
        "revalidate_report": None,
        "schema_version": "sesslint.repair-manifest/v1",
    }
    manifest_path = dest_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest_dict, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    return src_path, plan_path, out_path, manifest_path


def test_cli_declared_loss_null_exits_2_instead_of_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """CLI regression: TypeError causes exit code 2 instead of exit code 1 with JSON."""
    src, pln, out, man = _make_base_bundle(tmp_path)
    m_dict = json.loads(man.read_text(encoding="utf-8"))
    m_dict["declared_loss"] = None
    man.write_text(json.dumps(m_dict), encoding="utf-8")

    cmd = [
        "verify",
        "--source",
        str(src),
        "--plan",
        str(pln),
        "--output",
        str(out),
        "--manifest",
        str(man),
    ]
    exit_code = main(cmd)
    captured = capsys.readouterr()

    # Spec requires exit code 1 with JSON verdict on stdout for audit failure
    # But currently it exits with code 2 and prints "Verify error: ..." to stderr
    assert exit_code == 1, f"Expected exit code 1, but got {exit_code} (stderr: {captured.err})"


def test_simultaneous_failure_checks_1_2_3_4(tmp_path: Path) -> None:
    """When checks 1, 2, 3, 4 fail simultaneously, all 4 must be recorded as ok=False."""
    src, pln, out, man = _make_base_bundle(tmp_path)

    # 1. Alter source -> Check 1 fails
    src.write_bytes(b'{"bad_source": true}\n')

    # 2. Corrupt plan fingerprint -> Check 2 fails
    p_dict = json.loads(pln.read_text(encoding="utf-8"))
    p_dict["fingerprint"] = "corrupted_fp_1234"
    pln.write_text(json.dumps(p_dict), encoding="utf-8")

    # 3. Alter output -> Check 3 fails
    out.write_bytes(b'{"bad_output": true}\n')

    # 4. Check 4 (transformation_audit) will fail because replay of plan on bad source != bad output

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    assert verdict.ok is False
    assert len(verdict.checks) == 7

    c_map = {c.name: c for c in verdict.checks}
    assert c_map["source_hash"].ok is False, "Check 1 source_hash must be False"
    assert c_map["plan_fingerprint"].ok is False, "Check 2 plan_fingerprint must be False"
    assert c_map["output_hash"].ok is False, "Check 3 output_hash must be False"
    assert c_map["transformation_audit"].ok is False, "Check 4 transformation_audit must be False"

    # Checks 5, 6, 7 are still evaluated
    assert "loss_audit" in c_map
    assert "assurance_audit" in c_map
    assert "idempotence" in c_map


def test_simultaneous_failure_all_7_checks(tmp_path: Path) -> None:
    """All 7 checks fail simultaneously and all 7 are recorded as ok=False without crashing."""
    src, pln, out, man = _make_base_bundle(tmp_path)

    # 1. Bad source -> Check 1 fails
    src.write_bytes(b'{"corrupt": 1}\n')

    # 2. Tampered plan fingerprint -> Check 2 fails
    p_dict = json.loads(pln.read_text(encoding="utf-8"))
    p_dict["fingerprint"] = "bad"
    pln.write_text(json.dumps(p_dict), encoding="utf-8")

    # 3. Bad output with an un-repaired duplicate -> Check 3 fails
    # Use non_idempotent output fixture which contains an un-repaired duplicate msg-1
    non_idemp_bytes = (FIXTURES_DIR / "non_idempotent" / "output.jsonl").read_bytes()
    out.write_bytes(non_idemp_bytes)

    # 4. Check 4 will fail because replay of plan on corrupt source != unrepaired_dup

    # 5. Tamper declared loss in manifest -> Check 5 fails
    m_dict = json.loads(man.read_text(encoding="utf-8"))
    m_dict["declared_loss"] = ["falsified-loss:999"]

    # 6. Falsify assurance in manifest -> Check 6 fails
    m_dict["assurance"] = "clean"  # Recomputed will be repaired-lossless

    # 7. unrepaired_dup in output causes fresh planner to produce steps -> Check 7 fails
    man.write_text(json.dumps(m_dict), encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    assert verdict.ok is False
    assert len(verdict.checks) == 7

    c_map = {c.name: c for c in verdict.checks}
    assert c_map["source_hash"].ok is False, "Check 1 failed"
    assert c_map["plan_fingerprint"].ok is False, "Check 2 failed"
    assert c_map["output_hash"].ok is False, "Check 3 failed"
    assert c_map["transformation_audit"].ok is False, "Check 4 failed"
    assert c_map["loss_audit"].ok is False, "Check 5 failed"
    assert c_map["assurance_audit"].ok is False, "Check 6 failed"
    assert c_map["idempotence"].ok is False, "Check 7 failed"


# ===========================================================================
# 2. Malformed JSON and Root Types across each file
# ===========================================================================


@pytest.mark.parametrize("corrupt_file", ["source", "plan", "output", "manifest"])
def test_malformed_syntax_in_each_file(tmp_path: Path, corrupt_file: str) -> None:
    """Malformed syntax (truncated JSON, syntax errors) in any file must never crash verify()."""
    src, pln, out, man = _make_base_bundle(tmp_path)
    file_map = {"source": src, "plan": pln, "output": out, "manifest": man}
    file_map[corrupt_file].write_bytes(b'{"unclosed_brace": true, [syntax error')

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    assert isinstance(verdict, Verdict)
    assert verdict.ok is False
    assert len(verdict.checks) == 7


@pytest.mark.parametrize(
    "bad_root",
    [
        "[]",
        '"a string"',
        "12345",
        "true",
        "null",
    ],
)
def test_non_dict_root_in_manifest(tmp_path: Path, bad_root: str) -> None:
    """Non-dictionary root in manifest.json must not crash verify()."""
    src, pln, out, man = _make_base_bundle(tmp_path)
    man.write_text(bad_root, encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    assert isinstance(verdict, Verdict)
    assert verdict.ok is False


@pytest.mark.parametrize(
    "bad_root",
    [
        "[]",
        '"a string"',
        "12345",
        "true",
        "null",
    ],
)
def test_non_dict_root_in_plan(tmp_path: Path, bad_root: str) -> None:
    """Non-dictionary root in plan.json must not crash verify()."""
    src, pln, out, man = _make_base_bundle(tmp_path)
    pln.write_text(bad_root, encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    assert isinstance(verdict, Verdict)
    assert verdict.ok is False


# ===========================================================================
# 3. Empty files (0-byte files)
# ===========================================================================


@pytest.mark.parametrize("empty_target", ["source", "plan", "output", "manifest", "all"])
def test_empty_files_total_function(tmp_path: Path, empty_target: str) -> None:
    """0-byte files (individually or all) must return a Verdict without crashing."""
    src, pln, out, man = _make_base_bundle(tmp_path)
    if empty_target == "all":
        src.write_bytes(b"")
        pln.write_bytes(b"")
        out.write_bytes(b"")
        man.write_bytes(b"")
    else:
        file_map = {"source": src, "plan": pln, "output": out, "manifest": man}
        file_map[empty_target].write_bytes(b"")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    assert isinstance(verdict, Verdict)
    assert verdict.ok is False
    assert len(verdict.checks) == 7


# ===========================================================================
# 4. Inaccessible paths and directories
# ===========================================================================


def test_inaccessible_file_raises_filenotfound(tmp_path: Path) -> None:
    """Nonexistent paths raise FileNotFoundError."""
    src, pln, out, man = _make_base_bundle(tmp_path)
    nonexistent = tmp_path / "nonexistent.file"

    with pytest.raises(FileNotFoundError):
        verify(source_path=nonexistent, plan_path=pln, output_path=out, manifest_path=man)

    with pytest.raises(FileNotFoundError):
        verify(source_path=src, plan_path=nonexistent, output_path=out, manifest_path=man)

    with pytest.raises(FileNotFoundError):
        verify(source_path=src, plan_path=pln, output_path=nonexistent, manifest_path=man)

    with pytest.raises(FileNotFoundError):
        verify(source_path=src, plan_path=pln, output_path=out, manifest_path=nonexistent)


def test_directory_passed_as_file_raises_isadirectoryerror(tmp_path: Path) -> None:
    """Directories passed as arguments raise IsADirectoryError."""
    src, pln, out, man = _make_base_bundle(tmp_path)
    sub_dir = tmp_path / "sub_dir"
    sub_dir.mkdir()

    with pytest.raises(IsADirectoryError):
        verify(source_path=sub_dir, plan_path=pln, output_path=out, manifest_path=man)


# ===========================================================================
# 5. Permuted event orders vs permuted dictionary keys
# ===========================================================================


def test_permuted_dict_keys_passes_audit(tmp_path: Path) -> None:
    """Reordering JSON object keys does NOT break transformation_audit (canonical JSON proof)."""
    src, pln, out, man = _make_base_bundle(tmp_path)

    # Read output and reverse every JSON object's keys
    lines = out.read_text(encoding="utf-8").splitlines()
    reordered_lines: list[str] = [lines[0]]
    for line in lines[1:]:
        obj = json.loads(line)
        reversed_obj = {k: obj[k] for k in reversed(list(obj.keys()))}
        reordered_lines.append(json.dumps(reversed_obj))

    reordered_bytes = ("\n".join(reordered_lines) + "\n").encode("utf-8")
    out.write_bytes(reordered_bytes)

    # Update manifest output_fingerprint so Check 3 passes, isolating Check 4
    m_data = json.loads(man.read_text(encoding="utf-8"))
    m_data["output_fingerprint"] = hashlib.sha256(reordered_bytes).hexdigest()
    man.write_text(json.dumps(m_data), encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["transformation_audit"].ok is True
    assert verdict.ok is True


def test_permuted_event_order_fails_audit(tmp_path: Path) -> None:
    """Permuting event sequence order MUST fail transformation_audit."""
    src, pln, out, man = _make_base_bundle(tmp_path)

    lines = out.read_text(encoding="utf-8").splitlines()
    # Swap event 1 and event 2 (lines 1 and 2 after header line 0)
    lines[1], lines[2] = lines[2], lines[1]
    swapped_bytes = ("\n".join(lines) + "\n").encode("utf-8")
    out.write_bytes(swapped_bytes)

    # Update manifest output hash so Check 3 passes, isolating Check 4
    m_data = json.loads(man.read_text(encoding="utf-8"))
    m_data["output_fingerprint"] = hashlib.sha256(swapped_bytes).hexdigest()
    man.write_text(json.dumps(m_data), encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["transformation_audit"].ok is False
    assert "events-mismatch" in c_map["transformation_audit"].detail


# ===========================================================================
# 6. Tampered manifest hashes, altered fingerprints, loss totals, assurance
# ===========================================================================


def test_tampered_manifest_source_hash(tmp_path: Path) -> None:
    """Tampered input_fingerprint fails Check 1."""
    src, pln, out, man = _make_base_bundle(tmp_path)
    m_data = json.loads(man.read_text(encoding="utf-8"))
    m_data["input_fingerprint"] = "0" * 64
    man.write_text(json.dumps(m_data), encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["source_hash"].ok is False
    assert "mismatch" in c_map["source_hash"].detail


def test_tampered_plan_fingerprint(tmp_path: Path) -> None:
    """Plan with falsified fingerprint fails Check 2."""
    src, pln, out, man = _make_base_bundle(tmp_path)
    p_data = json.loads(pln.read_text(encoding="utf-8"))
    p_data["fingerprint"] = "1" * 64
    pln.write_text(json.dumps(p_data), encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["plan_fingerprint"].ok is False
    assert "plan-tampered" in c_map["plan_fingerprint"].detail


def test_tampered_output_hash(tmp_path: Path) -> None:
    """Tampered output_fingerprint in manifest fails Check 3."""
    src, pln, out, man = _make_base_bundle(tmp_path)
    m_data = json.loads(man.read_text(encoding="utf-8"))
    m_data["output_fingerprint"] = "2" * 64
    man.write_text(json.dumps(m_data), encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["output_hash"].ok is False
    assert "mismatch" in c_map["output_hash"].detail


def test_modified_loss_totals_fails_check_5(tmp_path: Path) -> None:
    """Manifest claiming different loss totals fails Check 5."""
    src, pln, out, man = _make_base_bundle(tmp_path)
    m_data = json.loads(man.read_text(encoding="utf-8"))
    m_data["declared_loss"] = ["discarded-suffix:5"]
    man.write_text(json.dumps(m_data), encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["loss_audit"].ok is False
    assert "mismatch" in c_map["loss_audit"].detail


def test_falsified_assurance_level_fails_check_6(tmp_path: Path) -> None:
    """Manifest claiming 'clean' on repaired session fails Check 6."""
    src, pln, out, man = _make_base_bundle(tmp_path)
    m_data = json.loads(man.read_text(encoding="utf-8"))
    m_data["assurance"] = "clean"
    man.write_text(json.dumps(m_data), encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["assurance_audit"].ok is False
    assert "mismatch" in c_map["assurance_audit"].detail


# ===========================================================================
# 7. Total Function Hardening: Corrupted Fields that must not crash
# ===========================================================================


def test_manifest_declared_loss_null_must_not_crash(tmp_path: Path) -> None:
    """Manifest with declared_loss=null must evaluate to ok=False without crashing."""
    src, pln, out, man = _make_base_bundle(tmp_path)
    m_data = json.loads(man.read_text(encoding="utf-8"))
    m_data["declared_loss"] = None
    man.write_text(json.dumps(m_data), encoding="utf-8")

    # verify() must return a Verdict, NOT crash with TypeError
    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    assert verdict.ok is False
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["loss_audit"].ok is False


def test_manifest_declared_loss_integer_must_not_crash(tmp_path: Path) -> None:
    """Manifest with declared_loss=123 must evaluate to ok=False without crashing."""
    src, pln, out, man = _make_base_bundle(tmp_path)
    m_data = json.loads(man.read_text(encoding="utf-8"))
    m_data["declared_loss"] = 123
    man.write_text(json.dumps(m_data), encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    assert verdict.ok is False
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["loss_audit"].ok is False


def test_manifest_loss_totals_invalid_values_must_not_crash(tmp_path: Path) -> None:
    """Manifest with loss_totals containing non-integer values must not crash with ValueError."""
    src, pln, out, man = _make_base_bundle(tmp_path)
    m_data = json.loads(man.read_text(encoding="utf-8"))
    del m_data["declared_loss"]
    m_data["loss_totals"] = {"discarded-suffix": "not_an_int"}
    man.write_text(json.dumps(m_data), encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    assert verdict.ok is False
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["loss_audit"].ok is False


def test_indented_single_document_session_parsing() -> None:
    """Indented single-document session JSON must be parsed without JSONDecodeError."""
    from sesslint.verify import _parse_session_events

    doc = """{
  "schema_version": "sesslint.session/v1",
  "session_id": "test-session",
  "events": [
    {
      "actor": "user",
      "id": "m0",
      "kind": "message",
      "parent_id": null,
      "payload": {"text": "hi"},
      "seq": 0,
      "ts": "2026-09-05T12:00:00Z"
    }
  ]
}"""
    header, events = _parse_session_events(doc.encode("utf-8"))
    assert header is not None, "Failed to parse header from indented single-document JSON"
    assert header.session_id == "test-session"
    assert len(events) == 1


def test_idempotence_falsely_converged_when_check4_skipped(tmp_path: Path) -> None:
    """Bug: when Check 4 fails early, recipes are not registered, causing Check 7 to pass."""
    import sesslint.repair.registry as reg

    # Reset registry to simulate fresh process
    reg._REGISTRY.clear()

    src, pln, out, man = _make_base_bundle(tmp_path)

    # Broken source causes Check 4 to fail at source parse
    src.write_bytes(b'{"broken_json: true\n')

    # Output contains un-repaired duplicate msg-1
    non_idemp_bytes = (FIXTURES_DIR / "non_idempotent" / "output.jsonl").read_bytes()
    out.write_bytes(non_idemp_bytes)

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    c_map = {c.name: c for c in verdict.checks}

    assert c_map["transformation_audit"].ok is False
    # Check 7 should fail because output is not converged
    assert c_map["idempotence"].ok is False, (
        f"BUG: Check 7 falsely passed with {c_map['idempotence']} "
        "because recipe registration was hidden inside Check 4 else block!"
    )
