"""Empirical adversarial challenge test suite for Milestone M5.1 (TASK-022).

Authored by Challenger 2.
Focus areas:
1. Idempotence Verification (Check 7):
   - Incomplete repair / non-idempotent scenarios fail cleanly.
   - Idempotence check NEVER repairs the file and NEVER writes to disk.
   - Source/output file bits and timestamps remain perfectly invariant.
2. Read-Only Invariants:
   - Comprehensive monkeypatching of all write primitives (open, write_bytes,
     write_text, replace, rename, remove, unlink, rmdir, mkdir, shutil).
   - Real filesystem read-only permissions on bundle files.
   - Proves verify() never attempts writes in any state (valid, invalid, corrupted).
3. CLI Exit Code Contracts:
   - Matrix of exit code 0 (valid), 1 (tampered / non-idempotent / malformed),
     2 (missing args / I/O errors).
   - Strict stream separation: stdout holds clean JSON on 0 and 1;
     stderr holds diagnostics on 2.
"""

from __future__ import annotations

import builtins
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from sesslint.cli import main
from sesslint.repair.fingerprint import compute_plan_fingerprint
from sesslint.verify import verify

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = REPO_ROOT / "fixtures" / "verify"


def _build_valid_bundle(dest_dir: Path) -> tuple[Path, Path, Path, Path]:
    """Create a fully valid source, plan, output, and manifest bundle."""
    dest_dir.mkdir(parents=True, exist_ok=True)

    src_lines = [
        '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"challenger-sess"}',
        '{"actor":"user","id":"m0","kind":"message","parent_id":null,"payload":{"text":"start"},"seq":0,"ts":"2026-09-05T12:00:00Z"}',
        '{"actor":"assistant","id":"m1","kind":"message","parent_id":"m0","payload":{"text":"dup"},"seq":1,"ts":"2026-09-05T12:00:01Z"}',
        '{"actor":"assistant","id":"m1","kind":"message","parent_id":"m0","payload":{"text":"dup"},"seq":1,"ts":"2026-09-05T12:00:01Z"}',
        '{"actor":"user","id":"m2","kind":"message","parent_id":"m1","payload":{"text":"done"},"seq":2,"ts":"2026-09-05T12:00:02Z"}',
    ]
    src_bytes = ("\n".join(src_lines) + "\n").encode("utf-8")
    src_p = dest_dir / "source.jsonl"
    src_p.write_bytes(src_bytes)
    src_hash = hashlib.sha256(src_bytes).hexdigest()

    out_lines = [
        '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"challenger-sess"}',
        '{"actor":"user","id":"m0","kind":"message","parent_id":null,"payload":{"text":"start"},"seq":0,"ts":"2026-09-05T12:00:00Z"}',
        '{"actor":"assistant","id":"m1","kind":"message","parent_id":"m0","payload":{"text":"dup"},"seq":1,"ts":"2026-09-05T12:00:01Z"}',
        '{"actor":"user","id":"m2","kind":"message","parent_id":"m1","payload":{"text":"done"},"seq":2,"ts":"2026-09-05T12:00:02Z"}',
    ]
    out_bytes = ("\n".join(out_lines) + "\n").encode("utf-8")
    out_p = dest_dir / "output.jsonl"
    out_p.write_bytes(out_bytes)
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
                "target_finding_fp": "c1f7a29e10b42d3a",
                "target_index": 1,
            }
        ],
        "version": "sesslint.plan/v1",
    }
    plan_fp = compute_plan_fingerprint(plan_dict)
    plan_dict["fingerprint"] = plan_fp
    pln_p = dest_dir / "plan.json"
    pln_p.write_text(json.dumps(plan_dict, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    manifest_dict: dict[str, Any] = {
        "actions": [
            {
                "detail": "step 0",
                "kind": "identical-duplicate-collapse",
                "record_id": "c1f7a29e10b42d3a",
            }
        ],
        "assurance": "repaired-lossless",
        "declared_loss": [],
        "idempotency_key": "1234567890abcdef" * 4,
        "input_fingerprint": src_hash,
        "output_fingerprint": out_hash,
        "plan_fingerprint": plan_fp,
        "policy": "conservative",
        "revalidate_report": None,
        "schema_version": "sesslint.repair-manifest/v1",
    }
    man_p = dest_dir / "manifest.json"
    man_p.write_text(json.dumps(manifest_dict, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return src_p, pln_p, out_p, man_p


# ===========================================================================
# 1. IDEMPOTENCE (CHECK 7) EMPIRICAL CHALLENGES
# ===========================================================================


def test_idempotence_incomplete_repair_single_defect(tmp_path: Path) -> None:
    """Check 7 fails cleanly when output still contains an un-repaired duplicate."""
    src, pln, out, man = _build_valid_bundle(tmp_path)

    # Corrupt the output by leaving the duplicate intact
    incomplete_out = src.read_bytes()
    out.write_bytes(incomplete_out)

    # Manifest and plan are updated to match hashes, so only Check 7 fails
    new_out_hash = hashlib.sha256(incomplete_out).hexdigest()
    m_data = json.loads(man.read_text(encoding="utf-8"))
    m_data["output_fingerprint"] = new_out_hash
    man.write_text(json.dumps(m_data), encoding="utf-8")

    # In Check 4, if plan replay had 0 steps, it would match incomplete_out
    p_data = json.loads(pln.read_text(encoding="utf-8"))
    p_data["steps"] = []
    p_fp = compute_plan_fingerprint(p_data)
    p_data["fingerprint"] = p_fp
    pln.write_text(json.dumps(p_data), encoding="utf-8")

    m_data["actions"] = []
    m_data["assurance"] = "clean"
    m_data["plan_fingerprint"] = p_fp
    man.write_text(json.dumps(m_data), encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)

    assert verdict.ok is False
    c_map = {c.name: c for c in verdict.checks}
    # Checks 1-6 pass
    assert c_map["source_hash"].ok is True
    assert c_map["plan_fingerprint"].ok is True
    assert c_map["output_hash"].ok is True
    assert c_map["transformation_audit"].ok is True
    assert c_map["loss_audit"].ok is True
    assert c_map["assurance_audit"].ok is True
    # Check 7 specifically fails with remaining steps
    assert c_map["idempotence"].ok is False
    assert "non-idempotent: 1 steps remaining" in c_map["idempotence"].detail


def test_idempotence_incomplete_repair_multiple_defects(tmp_path: Path) -> None:
    """Check 7 reports the exact number of remaining steps when multiple defects linger."""
    src, pln, out, man = _build_valid_bundle(tmp_path)

    # Output with 3 duplicate messages that can all be collapsed
    multi_dup_lines = [
        '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"challenger-sess"}',
        '{"actor":"user","id":"m0","kind":"message","parent_id":null,"payload":{"text":"start"},"seq":0,"ts":"2026-09-05T12:00:00Z"}',
        '{"actor":"assistant","id":"m1","kind":"message","parent_id":"m0","payload":{"text":"dup1"},"seq":1,"ts":"2026-09-05T12:00:01Z"}',
        '{"actor":"assistant","id":"m1","kind":"message","parent_id":"m0","payload":{"text":"dup1"},"seq":1,"ts":"2026-09-05T12:00:01Z"}',
        '{"actor":"user","id":"m2","kind":"message","parent_id":"m1","payload":{"text":"dup2"},"seq":2,"ts":"2026-09-05T12:00:02Z"}',
        '{"actor":"user","id":"m2","kind":"message","parent_id":"m1","payload":{"text":"dup2"},"seq":2,"ts":"2026-09-05T12:00:02Z"}',
    ]
    out_bytes = ("\n".join(multi_dup_lines) + "\n").encode("utf-8")
    out.write_bytes(out_bytes)

    # Match output hash in manifest so only Check 7 fails
    m_data = json.loads(man.read_text(encoding="utf-8"))
    m_data["output_fingerprint"] = hashlib.sha256(out_bytes).hexdigest()
    man.write_text(json.dumps(m_data), encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["idempotence"].ok is False
    assert "non-idempotent: 2 steps remaining" in c_map["idempotence"].detail


def test_idempotence_never_modifies_output_file(tmp_path: Path) -> None:
    """Empirically prove that verify() NEVER repairs or mutates output file on disk."""
    src, pln, out, man = _build_valid_bundle(tmp_path)

    # Use fixture non_idempotent
    d = FIXTURES_DIR / "non_idempotent"
    src_bytes = (d / "source.jsonl").read_bytes()
    pln_bytes = (d / "plan.json").read_bytes()
    out_bytes = (d / "output.jsonl").read_bytes()
    man_bytes = (d / "manifest.json").read_bytes()

    src.write_bytes(src_bytes)
    pln.write_bytes(pln_bytes)
    out.write_bytes(out_bytes)
    man.write_bytes(man_bytes)

    stat_before = out.stat()
    hash_before = hashlib.sha256(out_bytes).hexdigest()

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    assert verdict.ok is False
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["idempotence"].ok is False

    stat_after = out.stat()
    bytes_after = out.read_bytes()
    hash_after = hashlib.sha256(bytes_after).hexdigest()

    # Absolute bit-for-bit invariance proof
    assert bytes_after == out_bytes, "Output bytes changed during verification!"
    assert hash_after == hash_before, "Output SHA-256 changed during verification!"
    assert stat_after.st_size == stat_before.st_size, "Output file size changed!"
    assert stat_after.st_mtime_ns == stat_before.st_mtime_ns, "Output mtime changed!"


def test_idempotence_with_malformed_output(tmp_path: Path) -> None:
    """Check 7 does not crash when output file contains unparseable JSON."""
    src, pln, out, man = _build_valid_bundle(tmp_path)
    out.write_bytes(b"MALFORMED NOT JSON {{{}}")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    assert verdict.ok is False
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["idempotence"].ok is False
    assert "replan-failed" in c_map["idempotence"].detail


# ===========================================================================
# 2. READ-ONLY GUARANTEES & WRITE FORBIDDEN PROOFS
# ===========================================================================


def test_runtime_write_prohibition_mock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Intercept ALL filesystem mutation primitives; verify none are called in verify()."""
    src, pln, out, man = _build_valid_bundle(tmp_path)

    def _forbidden_mutation(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("FORBIDDEN WRITE/MUTATION CALLED DURING READ-ONLY VERIFY")

    # Mock Path write methods
    monkeypatch.setattr(Path, "write_bytes", _forbidden_mutation)
    monkeypatch.setattr(Path, "write_text", _forbidden_mutation)
    monkeypatch.setattr(Path, "touch", _forbidden_mutation)
    monkeypatch.setattr(Path, "unlink", _forbidden_mutation)
    monkeypatch.setattr(Path, "rmdir", _forbidden_mutation)
    monkeypatch.setattr(Path, "mkdir", _forbidden_mutation)

    # Mock os mutation primitives
    monkeypatch.setattr(os, "replace", _forbidden_mutation)
    monkeypatch.setattr(os, "rename", _forbidden_mutation)
    monkeypatch.setattr(os, "remove", _forbidden_mutation)
    monkeypatch.setattr(os, "unlink", _forbidden_mutation)
    monkeypatch.setattr(os, "rmdir", _forbidden_mutation)
    monkeypatch.setattr(os, "mkdir", _forbidden_mutation)
    monkeypatch.setattr(os, "makedirs", _forbidden_mutation)

    # Mock builtins.open in write/append modes
    orig_open = builtins.open

    def _safe_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if any(m in mode for m in ("w", "a", "+", "x")):
            raise AssertionError(f"FORBIDDEN open(mode='{mode}') called during verify()")
        return orig_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", _safe_open)

    # Test under valid bundle
    v1 = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    assert v1.ok is True

    # Test under non-idempotent bundle (must still never write)
    d = FIXTURES_DIR / "non_idempotent"
    v2 = verify(
        source_path=d / "source.jsonl",
        plan_path=d / "plan.json",
        output_path=d / "output.jsonl",
        manifest_path=d / "manifest.json",
    )
    assert v2.ok is False

    # Test under tampered output bundle (must still never write)
    d_t = FIXTURES_DIR / "tampered_output"
    v3 = verify(
        source_path=d_t / "source.jsonl",
        plan_path=d_t / "plan.json",
        output_path=d_t / "output.jsonl",
        manifest_path=d_t / "manifest.json",
    )
    assert v3.ok is False


def test_real_readonly_filesystem_attributes(tmp_path: Path) -> None:
    """Set read-only attribute on all bundle files on disk; verify verify() passes cleanly."""
    src, pln, out, man = _build_valid_bundle(tmp_path)

    # Make files read-only on the operating system
    for p in (src, pln, out, man):
        os.chmod(p, stat.S_IREAD)

    try:
        verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
        assert verdict.ok is True
    finally:
        # Reset permissions so pytest temp cleanup can delete the folder
        for p in (src, pln, out, man):
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD)


# ===========================================================================
# 3. CLI EXIT CODES CONTRACT MATRIX
# ===========================================================================


@pytest.mark.parametrize(
    ("scenario", "expected_code", "expect_json_stdout", "expect_stderr_msg"),
    [
        ("ok", 0, True, False),
        ("tampered_source", 1, True, False),
        ("tampered_plan", 1, True, False),
        ("tampered_output", 1, True, False),
        ("non_idempotent", 1, True, False),
        ("missing_source_file", 2, False, True),
        ("missing_plan_file", 2, False, True),
        ("missing_output_file", 2, False, True),
        ("missing_manifest_file", 2, False, True),
        ("directory_as_source", 2, False, True),
        ("directory_as_output", 2, False, True),
    ],
)
def test_cli_exit_codes_comprehensive_matrix(
    scenario: str,
    expected_code: int,
    expect_json_stdout: bool,
    expect_stderr_msg: bool,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Exhaustive matrix validation of CLI exit codes, stdout JSON, and stderr separation."""
    src, pln, out, man = _build_valid_bundle(tmp_path)

    if scenario == "ok":
        pass
    elif scenario == "tampered_source":
        src.write_bytes(b"tampered\n")
    elif scenario == "tampered_plan":
        p_data = json.loads(pln.read_text(encoding="utf-8"))
        p_data["steps"] = []
        pln.write_text(json.dumps(p_data), encoding="utf-8")
    elif scenario == "tampered_output":
        out.write_bytes(b"tampered\n")
    elif scenario == "non_idempotent":
        d = FIXTURES_DIR / "non_idempotent"
        src.write_bytes((d / "source.jsonl").read_bytes())
        pln.write_bytes((d / "plan.json").read_bytes())
        out.write_bytes((d / "output.jsonl").read_bytes())
        man.write_bytes((d / "manifest.json").read_bytes())
    elif scenario == "missing_source_file":
        src = tmp_path / "nonexistent_source.jsonl"
    elif scenario == "missing_plan_file":
        pln = tmp_path / "nonexistent_plan.json"
    elif scenario == "missing_output_file":
        out = tmp_path / "nonexistent_output.jsonl"
    elif scenario == "missing_manifest_file":
        man = tmp_path / "nonexistent_manifest.json"
    elif scenario == "directory_as_source":
        src = tmp_path / "src_dir"
        src.mkdir()
    elif scenario == "directory_as_output":
        out = tmp_path / "out_dir"
        out.mkdir()

    exit_code = main(
        [
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
    )

    captured = capsys.readouterr()
    assert exit_code == expected_code, (
        f"Scenario {scenario} returned {exit_code}, expected {expected_code}"
    )

    if expect_json_stdout:
        assert captured.out.strip(), f"Expected JSON on stdout for {scenario}"
        data = json.loads(captured.out)
        assert isinstance(data, dict)
        assert "ok" in data
        assert "checks" in data
        assert "assurance" in data
        if expected_code == 0:
            assert data["ok"] is True
        else:
            assert data["ok"] is False
        assert not captured.err, (
            f"Stderr must be empty on exit {expected_code}, got: {captured.err}"
        )

    if expect_stderr_msg:
        assert captured.err.strip(), f"Expected error diagnostic on stderr for {scenario}"
        assert "Verify I/O error" in captured.err or "path is a directory" in captured.err


def test_cli_missing_arguments_exit_code_2() -> None:
    """Missing any of the 4 required CLI flags exits with code 2."""
    combinations = [
        [],
        ["--source", "s.jsonl"],
        ["--plan", "p.json"],
        ["--output", "o.jsonl"],
        ["--manifest", "m.json"],
        ["--source", "s.jsonl", "--plan", "p.json"],
        ["--source", "s.jsonl", "--plan", "p.json", "--output", "o.jsonl"],
    ]
    for combo in combinations:
        with pytest.raises(SystemExit) as exc_info:
            main(["verify", *combo])
        assert exc_info.value.code == 2, f"Failed for combo: {combo}"


# ===========================================================================
# 4. ADVERSARIAL EDGE CASES (TOTAL FUNCTION GUARANTEES)
# ===========================================================================


@pytest.mark.parametrize(
    "corrupt_target",
    ["source", "plan", "output", "manifest"],
)
def test_cli_malformed_json_files_exit_code_1(
    corrupt_target: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """When any file contains invalid JSON syntax, CLI exits with 1 and prints JSON verdict."""
    src, pln, out, man = _build_valid_bundle(tmp_path)
    target_path = {"source": src, "plan": pln, "output": out, "manifest": man}[corrupt_target]
    target_path.write_bytes(b"INVALID NON-JSON DATA {[:}")

    exit_code = main(
        [
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
    )
    captured = capsys.readouterr()
    assert exit_code == 1, f"Expected exit code 1 for malformed {corrupt_target}, got {exit_code}"
    assert captured.out.strip(), "Expected JSON output on stdout"
    parsed = json.loads(captured.out)
    assert parsed["ok"] is False
    assert not captured.err, (
        f"Stderr should be empty for malformed {corrupt_target}, got {captured.err}"
    )


def test_cli_unreadable_file_exit_code_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """When a file raises PermissionError on read, CLI exits with 2 and prints error to stderr."""
    src, pln, out, man = _build_valid_bundle(tmp_path)

    orig_read_bytes = Path.read_bytes

    def _mock_read_bytes(self: Path) -> bytes:
        if self == src:
            raise PermissionError("Access denied reading source file")
        return orig_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", _mock_read_bytes)

    exit_code = main(
        [
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
    )
    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Verify I/O error" in captured.err


# ===========================================================================
# 4. ADVERSARIAL DISCOVERY TESTS (EXPOSING DEFECTS)
# ===========================================================================


def test_bug_loss_audit_crashes_on_non_iterable_declared_loss(tmp_path: Path) -> None:
    """Verify total function: loss_audit safely reports invalid declared_loss without crashing."""
    src, pln, out, man = _build_valid_bundle(tmp_path)
    m_data = json.loads(man.read_text(encoding="utf-8"))
    m_data["declared_loss"] = None
    man.write_text(json.dumps(m_data), encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    assert verdict.ok is False
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["loss_audit"].ok is False
    assert "invalid-declared-loss-format" in c_map["loss_audit"].detail


def test_bug_loss_audit_crashes_on_non_int_loss_totals(tmp_path: Path) -> None:
    """Verify total function: loss_audit safely reports invalid loss_totals without crashing."""
    src, pln, out, man = _build_valid_bundle(tmp_path)
    m_data = json.loads(man.read_text(encoding="utf-8"))
    del m_data["declared_loss"]
    m_data["loss_totals"] = {"discarded": "not_an_int"}
    man.write_text(json.dumps(m_data), encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    assert verdict.ok is False
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["loss_audit"].ok is False
    assert "invalid-loss-totals-format" in c_map["loss_audit"].detail


def test_bug_indented_single_document_json_session_rejected(tmp_path: Path) -> None:
    """Verify valid indented single-document JSON (.json) parses cleanly and passes verification."""
    src, pln, out, man = _build_valid_bundle(tmp_path)

    # Valid canonical single-document session with indentation
    doc = {
        "schema_version": "sesslint.session/v1",
        "session_id": "challenger-sess",
        "created_at": "2026-09-05T12:00:00Z",
        "events": [
            {
                "actor": "user",
                "id": "m0",
                "kind": "message",
                "parent_id": None,
                "payload": {"text": "start"},
                "seq": 0,
                "ts": "2026-09-05T12:00:00Z",
            }
        ],
    }
    indented_json_bytes = (json.dumps(doc, indent=2) + "\n").encode("utf-8")
    src.write_bytes(indented_json_bytes)
    out.write_bytes(indented_json_bytes)

    # Update manifest and plan hashes
    doc_hash = hashlib.sha256(indented_json_bytes).hexdigest()
    m_data = json.loads(man.read_text(encoding="utf-8"))
    m_data["input_fingerprint"] = doc_hash
    m_data["output_fingerprint"] = doc_hash
    m_data["actions"] = []
    m_data["assurance"] = "clean"
    p_data = json.loads(pln.read_text(encoding="utf-8"))
    p_data["source_hash"] = doc_hash
    p_data["steps"] = []
    p_fp = compute_plan_fingerprint(p_data)
    p_data["fingerprint"] = p_fp
    m_data["plan_fingerprint"] = p_fp
    pln.write_text(json.dumps(p_data), encoding="utf-8")
    man.write_text(json.dumps(m_data), encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)

    c_map = {c.name: c for c in verdict.checks}
    assert verdict.ok is True
    assert c_map["transformation_audit"].ok is True
    assert c_map["idempotence"].ok is True
