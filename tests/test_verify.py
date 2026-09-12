"""Comprehensive tests for sesslint verify command and audit replay (TASK-022).

Covers:
- All 7 verification checks evaluated independently (pass & fail branches).
- Non-short-circuiting: multiple failures are simultaneously recorded in Verdict.
- Canonical JSON comparison: key-order-insensitive and event-order-sensitive proofs.
- In-place manifest post-hash binding.
- Total function guarantees: corrupted JSON, truncated manifests, empty files.
- Safety invariants: static grep proofs for zero write primitives and zero mutator imports.
- CLI exit codes: 0 (verified), 1 (audit failed), 2 (usage / IO error).
- Determinism and performance guard: 50-step plan replay completes in < 2 seconds.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any

import pytest

from sesslint.canonical import to_canonical_json
from sesslint.cli import main
from sesslint.repair.fingerprint import compute_plan_fingerprint
from sesslint.verify import Check, Verdict, verify

REPO_ROOT = Path(__file__).resolve().parent.parent
VERIFY_SRC = REPO_ROOT / "src" / "sesslint" / "verify.py"
FIXTURES_DIR = REPO_ROOT / "fixtures" / "verify"


# ---------------------------------------------------------------------------
# Test Helpers & Fixtures
# ---------------------------------------------------------------------------


def _write_ok_bundle(dest_dir: Path) -> tuple[Path, Path, Path, Path]:
    """Write a self-contained, valid source/plan/output/manifest bundle to dest_dir."""
    dest_dir.mkdir(parents=True, exist_ok=True)

    src_lines = [
        '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"test-verify-sess"}',
        '{"actor":"user","id":"msg-0","kind":"message","parent_id":null,"payload":{"text":"hello"},"seq":0,"ts":"2026-09-05T12:00:00Z"}',
        '{"actor":"assistant","id":"msg-1","kind":"message","parent_id":"msg-0","payload":{"text":"ack"},"seq":1,"ts":"2026-09-05T12:00:01Z"}',
        '{"actor":"assistant","id":"msg-1","kind":"message","parent_id":"msg-0","payload":{"text":"ack"},"seq":1,"ts":"2026-09-05T12:00:01Z"}',
        '{"actor":"user","id":"msg-2","kind":"message","parent_id":"msg-1","payload":{"text":"next"},"seq":2,"ts":"2026-09-05T12:00:02Z"}',
    ]
    src_bytes = ("\n".join(src_lines) + "\n").encode("utf-8")
    src_path = dest_dir / "source.jsonl"
    src_path.write_bytes(src_bytes)
    src_hash = hashlib.sha256(src_bytes).hexdigest()

    out_lines = [
        '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"test-verify-sess"}',
        '{"actor":"user","id":"msg-0","kind":"message","parent_id":null,"payload":{"text":"hello"},"seq":0,"ts":"2026-09-05T12:00:00Z"}',
        '{"actor":"assistant","id":"msg-1","kind":"message","parent_id":"msg-0","payload":{"text":"ack"},"seq":1,"ts":"2026-09-05T12:00:01Z"}',
        '{"actor":"user","id":"msg-2","kind":"message","parent_id":"msg-1","payload":{"text":"next"},"seq":2,"ts":"2026-09-05T12:00:02Z"}',
    ]
    out_bytes = ("\n".join(out_lines) + "\n").encode("utf-8")
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
        "profile": "neutral",
        "source_hash": src_hash,
        "steps": [
            {
                "params": {},
                "recipe": "identical-duplicate-collapse",
                "seq": 0,
                "target_finding_fp": "070ceee4b3954eb0",
                "target_index": 1,
            }
        ],
        "version": "sesslint.plan/v1",
    }
    plan_fp = compute_plan_fingerprint(plan_dict)
    plan_dict["fingerprint"] = plan_fp
    plan_path = dest_dir / "plan.json"
    plan_path.write_bytes((json.dumps(plan_dict, indent=2, sort_keys=True) + "\n").encode("utf-8"))

    manifest_dict: dict[str, Any] = {
        "actions": [
            {
                "detail": "step 0",
                "kind": "identical-duplicate-collapse",
                "record_id": "070ceee4b3954eb0",
            }
        ],
        "assurance": "repaired-lossless",
        "declared_loss": [],
        "idempotency_key": "d74db087f9461f8565b339e59f0d24ded18aa5c99a7b8478926d6cfdf5808987",
        "input_fingerprint": src_hash,
        "output_fingerprint": out_hash,
        "plan_fingerprint": plan_fp,
        "policy": "conservative",
        "revalidate_report": None,
        "revalidation": {
            "assurance": "A3",
            "error_count": 0,
            "warning_count": 0,
            "profile_id": "neutral",
            "profile_version": "1.0.0",
            "report_fingerprint": None,
        },
        "assurance_ceiling": "A3",
        "schema_version": "sesslint.repair-manifest/v1",
    }
    manifest_path = dest_dir / "manifest.json"
    manifest_path.write_bytes(
        (json.dumps(manifest_dict, indent=2, sort_keys=True) + "\n").encode("utf-8")
    )

    return src_path, plan_path, out_path, manifest_path


# ---------------------------------------------------------------------------
# 1. Verification of Canonical Fixture Directories
# ---------------------------------------------------------------------------


def test_fixture_ok() -> None:
    """Validate fixtures/verify/ok passes all 7 checks cleanly."""
    d = FIXTURES_DIR / "ok"
    verdict = verify(
        source_path=d / "source.jsonl",
        plan_path=d / "plan.json",
        output_path=d / "output.jsonl",
        manifest_path=d / "manifest.json",
    )
    assert verdict.ok is True
    assert verdict.assurance == "repaired-lossless"
    assert len(verdict.checks) == 7
    assert all(c.ok for c in verdict.checks)
    names = [c.name for c in verdict.checks]
    assert names == [
        "source_hash",
        "plan_fingerprint",
        "output_hash",
        "transformation_audit",
        "loss_audit",
        "assurance_audit",
        "idempotence",
    ]


def test_fixture_tampered_output() -> None:
    """Validate fixtures/verify/tampered_output fails checks 3 & 4 while others pass."""
    d = FIXTURES_DIR / "tampered_output"
    verdict = verify(
        source_path=d / "source.jsonl",
        plan_path=d / "plan.json",
        output_path=d / "output.jsonl",
        manifest_path=d / "manifest.json",
    )
    assert verdict.ok is False
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["source_hash"].ok is True
    assert c_map["plan_fingerprint"].ok is True
    assert c_map["output_hash"].ok is False
    assert "mismatch" in c_map["output_hash"].detail
    assert c_map["transformation_audit"].ok is False
    assert c_map["loss_audit"].ok is True
    assert c_map["assurance_audit"].ok is True
    assert c_map["idempotence"].ok is True


def test_fixture_tampered_plan() -> None:
    """Validate fixtures/verify/tampered_plan fails check 2."""
    d = FIXTURES_DIR / "tampered_plan"
    verdict = verify(
        source_path=d / "source.jsonl",
        plan_path=d / "plan.json",
        output_path=d / "output.jsonl",
        manifest_path=d / "manifest.json",
    )
    assert verdict.ok is False
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["source_hash"].ok is True
    assert c_map["plan_fingerprint"].ok is False
    assert "plan-tampered" in c_map["plan_fingerprint"].detail
    assert c_map["output_hash"].ok is True


def test_fixture_non_idempotent() -> None:
    """Validate fixtures/verify/non_idempotent passes checks 1-6 but fails idempotence."""
    d = FIXTURES_DIR / "non_idempotent"
    verdict = verify(
        source_path=d / "source.jsonl",
        plan_path=d / "plan.json",
        output_path=d / "output.jsonl",
        manifest_path=d / "manifest.json",
    )
    assert verdict.ok is False
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["source_hash"].ok is True
    assert c_map["plan_fingerprint"].ok is True
    assert c_map["output_hash"].ok is True
    assert c_map["transformation_audit"].ok is True
    assert c_map["loss_audit"].ok is True
    assert c_map["assurance_audit"].ok is True
    assert c_map["idempotence"].ok is False
    assert "non-idempotent" in c_map["idempotence"].detail


# ---------------------------------------------------------------------------
# 2. Individual Check Failure & Edge Case Tests
# ---------------------------------------------------------------------------


def test_tampered_source(tmp_path: Path) -> None:
    """Check 1 fails when source bytes are modified."""
    src, pln, out, man = _write_ok_bundle(tmp_path)
    # Flip a character in source
    src.write_bytes(src.read_bytes() + b"\n")
    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    assert verdict.ok is False
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["source_hash"].ok is False
    assert "mismatch" in c_map["source_hash"].detail


def test_in_place_manifest_rejected(tmp_path: Path) -> None:
    """Unknown-shape manifest with in_place: true is rejected with manifest-schema."""
    src, pln, out, man = _write_ok_bundle(tmp_path)
    src.write_bytes(out.read_bytes())
    manifest_data = json.loads(man.read_text(encoding="utf-8"))
    manifest_data["in_place"] = True
    man.write_text(json.dumps(manifest_data), encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    assert verdict.ok is False
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["source_hash"].ok is False
    assert c_map["source_hash"].detail == "manifest-schema"


def test_tampered_plan_fingerprint(tmp_path: Path) -> None:
    """Check 2 fails when plan fingerprint doesn't match content."""
    src, pln, out, man = _write_ok_bundle(tmp_path)
    plan_data = json.loads(pln.read_text(encoding="utf-8"))
    plan_data["fingerprint"] = "0" * 64
    pln.write_text(json.dumps(plan_data), encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["plan_fingerprint"].ok is False
    assert "plan-tampered" in c_map["plan_fingerprint"].detail


def test_manifest_plan_fingerprint_mismatch(tmp_path: Path) -> None:
    """Check 2 fails when manifest plan_fingerprint mismatches valid plan fingerprint."""
    src, pln, out, man = _write_ok_bundle(tmp_path)
    manifest_data = json.loads(man.read_text(encoding="utf-8"))
    manifest_data["plan_fingerprint"] = "f" * 64
    man.write_text(json.dumps(manifest_data), encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["plan_fingerprint"].ok is False
    assert "manifest-mismatch" in c_map["plan_fingerprint"].detail


def test_tampered_output_hash(tmp_path: Path) -> None:
    """Check 3 fails when output bytes do not match manifest fingerprint."""
    src, pln, out, man = _write_ok_bundle(tmp_path)
    manifest_data = json.loads(man.read_text(encoding="utf-8"))
    manifest_data["output_fingerprint"] = "e" * 64
    man.write_text(json.dumps(manifest_data), encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["output_hash"].ok is False
    assert "mismatch" in c_map["output_hash"].detail


def test_key_reorder_passes(tmp_path: Path) -> None:
    """Check 4 passes when output JSON lines have permuted key order (canonical compare proof)."""
    src, pln, out, man = _write_ok_bundle(tmp_path)

    # Read output events and serialize with intentionally reversed keys
    lines = out.read_text(encoding="utf-8").splitlines()
    reordered_lines: list[str] = [lines[0]]  # header
    for line in lines[1:]:
        obj = json.loads(line)
        # Reverse key order in JSON output
        reversed_obj = {k: obj[k] for k in reversed(list(obj.keys()))}
        reordered_lines.append(json.dumps(reversed_obj))

    reordered_bytes = ("\n".join(reordered_lines) + "\n").encode("utf-8")
    out.write_bytes(reordered_bytes)

    # Update manifest output_fingerprint to match new raw bytes so Check 3 passes
    new_out_hash = hashlib.sha256(reordered_bytes).hexdigest()
    manifest_data = json.loads(man.read_text(encoding="utf-8"))
    manifest_data["output_fingerprint"] = new_out_hash
    man.write_text(json.dumps(manifest_data), encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["output_hash"].ok is True
    # Key reordering is normalized out by canonical comparison
    assert c_map["transformation_audit"].ok is True
    assert verdict.ok is True


def test_event_reorder_fails(tmp_path: Path) -> None:
    """Check 4 fails when two event lines are swapped in the output file."""
    src, pln, out, man = _write_ok_bundle(tmp_path)

    lines = out.read_text(encoding="utf-8").splitlines()
    # Swap event lines 2 and 3 (indices 2 and 3, after header line 0)
    lines[2], lines[3] = lines[3], lines[2]
    swapped_bytes = ("\n".join(lines) + "\n").encode("utf-8")
    out.write_bytes(swapped_bytes)

    # Update manifest output_fingerprint so Check 3 passes, isolating Check 4
    new_out_hash = hashlib.sha256(swapped_bytes).hexdigest()
    manifest_data = json.loads(man.read_text(encoding="utf-8"))
    manifest_data["output_fingerprint"] = new_out_hash
    man.write_text(json.dumps(manifest_data), encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["output_hash"].ok is True
    assert c_map["transformation_audit"].ok is False
    assert "events-mismatch" in c_map["transformation_audit"].detail


def test_tampered_loss_audit(tmp_path: Path) -> None:
    """Check 5 fails when manifest declared_loss does not match recomputed plan loss."""
    src, pln, out, man = _write_ok_bundle(tmp_path)
    manifest_data = json.loads(man.read_text(encoding="utf-8"))
    manifest_data["declared_loss"] = ["discarded-suffix:99"]
    man.write_text(json.dumps(manifest_data), encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["loss_audit"].ok is False
    assert "mismatch" in c_map["loss_audit"].detail


def test_loss_totals_fallback(tmp_path: Path) -> None:
    """Missing required declared_loss with legacy loss_totals is rejected with manifest-schema."""
    src, pln, out, man = _write_ok_bundle(tmp_path)
    manifest_data = json.loads(man.read_text(encoding="utf-8"))
    del manifest_data["declared_loss"]
    manifest_data["loss_totals"] = {"discarded-suffix": 0}
    man.write_text(json.dumps(manifest_data), encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    assert verdict.ok is False
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["loss_audit"].ok is False
    assert c_map["loss_audit"].detail == "manifest-schema"


def test_tampered_assurance_audit(tmp_path: Path) -> None:
    """Check 6 fails when manifest claims clean on a plan requiring repair."""
    src, pln, out, man = _write_ok_bundle(tmp_path)
    manifest_data = json.loads(man.read_text(encoding="utf-8"))
    manifest_data["assurance"] = "clean"  # Recomputed will be repaired-lossless
    man.write_text(json.dumps(manifest_data), encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["assurance_audit"].ok is False
    assert "mismatch" in c_map["assurance_audit"].detail


def test_non_short_circuiting(tmp_path: Path) -> None:
    """Multiple independent failures are all recorded in the verdict."""
    src, pln, out, man = _write_ok_bundle(tmp_path)

    # 1. Tamper source -> Check 1 fails
    src.write_bytes(b'{"corrupted": true}\n')
    # 2. Tamper plan -> Check 2 fails
    pln_data = json.loads(pln.read_text(encoding="utf-8"))
    pln_data["fingerprint"] = "bad"
    pln.write_text(json.dumps(pln_data), encoding="utf-8")
    # 3. Tamper output -> Check 3 fails
    out.write_bytes(b'{"tampered": true}\n')

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    assert verdict.ok is False
    assert len(verdict.checks) == 7
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["source_hash"].ok is False
    assert c_map["plan_fingerprint"].ok is False
    assert c_map["output_hash"].ok is False


# ---------------------------------------------------------------------------
# 3. Adversarial, Truncated & Total Function Proofs
# ---------------------------------------------------------------------------


def test_truncated_manifest(tmp_path: Path) -> None:
    """Missing output_fingerprint evaluates to ok=False with detail='manifest-schema'."""
    src, pln, out, man = _write_ok_bundle(tmp_path)
    manifest_data = json.loads(man.read_text(encoding="utf-8"))
    del manifest_data["output_fingerprint"]
    man.write_text(json.dumps(manifest_data), encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    assert verdict.ok is False
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["output_hash"].ok is False
    assert c_map["output_hash"].detail in ("field-missing", "manifest-schema")


def test_empty_output_file(tmp_path: Path) -> None:
    """Zero-byte output file produces a valid Verdict with failed checks rather than crashing."""
    src, pln, out, man = _write_ok_bundle(tmp_path)
    out.write_bytes(b"")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    assert verdict.ok is False
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["output_hash"].ok is False
    assert c_map["transformation_audit"].ok is False


def test_malformed_json_files(tmp_path: Path) -> None:
    """Malformed JSON in plan and manifest are caught as failed checks."""
    src, pln, out, man = _write_ok_bundle(tmp_path)
    pln.write_bytes(b"{not valid json")
    man.write_bytes(b"{not valid json")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    assert verdict.ok is False
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["source_hash"].ok is False
    assert c_map["source_hash"].detail == "manifest-invalid-json"
    assert c_map["plan_fingerprint"].ok is False
    assert c_map["plan_fingerprint"].detail == "invalid-plan-json"


def test_missing_files_raise_filenotfound(tmp_path: Path) -> None:
    """Missing file paths raise FileNotFoundError for CLI exit code 2."""
    src, pln, out, man = _write_ok_bundle(tmp_path)
    missing_file = tmp_path / "nonexistent.json"
    with pytest.raises(FileNotFoundError):
        verify(source_path=missing_file, plan_path=pln, output_path=out, manifest_path=man)
    with pytest.raises(FileNotFoundError):
        verify(source_path=src, plan_path=missing_file, output_path=out, manifest_path=man)


def test_directory_as_file_raises_isadirectoryerror(tmp_path: Path) -> None:
    """Directory passed as file argument raises IsADirectoryError."""
    src, pln, out, man = _write_ok_bundle(tmp_path)
    sub_dir = tmp_path / "subdir"
    sub_dir.mkdir()
    with pytest.raises(IsADirectoryError):
        verify(source_path=sub_dir, plan_path=pln, output_path=out, manifest_path=man)


def test_symlinked_files(tmp_path: Path) -> None:
    """Verifier follows symlinks and hashes target bytes correctly."""
    src, pln, out, man = _write_ok_bundle(tmp_path)
    symlink_src = tmp_path / "sym_source.jsonl"
    try:
        symlink_src.symlink_to(src)
    except OSError:
        pytest.skip("Symlink creation requires elevated privileges on this system")

    verdict = verify(source_path=symlink_src, plan_path=pln, output_path=out, manifest_path=man)
    assert verdict.ok is True


def test_50_step_plan_replay_perf(tmp_path: Path) -> None:
    """50-step linear replay finishes under 2.0 seconds (performance guard)."""
    dest_dir = tmp_path / "perf"
    dest_dir.mkdir()

    # Generate session with 50 duplicate pairs
    events: list[dict[str, Any]] = [
        {
            "created_at": "2026-09-05T12:00:00Z",
            "schema_version": "sesslint.session/v1",
            "session_id": "perf-test",
        }
    ]
    repaired_events: list[dict[str, Any]] = [dict(events[0])]
    steps: list[dict[str, Any]] = []

    for i in range(50):
        ev = {
            "actor": "user",
            "id": f"msg-{i}",
            "kind": "message",
            "parent_id": None if i == 0 else f"msg-{i - 1}",
            "payload": {"text": f"payload-{i}"},
            "seq": i,
            "ts": f"2026-09-05T12:00:{i:02d}Z",
        }
        events.append(ev)
        # Add duplicate
        events.append(dict(ev))
        repaired_events.append(ev)
        steps.append(
            {
                "params": {},
                "recipe": "identical-duplicate-collapse",
                "seq": i,
                "target_finding_fp": f"fp-{i}",
                "target_index": len(repaired_events) - 1,
            }
        )

    src_bytes = ("\n".join(to_canonical_json(e) for e in events) + "\n").encode("utf-8")
    out_bytes = ("\n".join(to_canonical_json(e) for e in repaired_events) + "\n").encode("utf-8")

    src_path = dest_dir / "source.jsonl"
    out_path = dest_dir / "output.jsonl"
    src_path.write_bytes(src_bytes)
    out_path.write_bytes(out_bytes)

    src_hash = hashlib.sha256(src_bytes).hexdigest()
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
        "profile": "neutral",
        "source_hash": src_hash,
        "steps": steps,
        "version": "sesslint.plan/v1",
    }
    plan_fp = compute_plan_fingerprint(plan_dict)
    plan_dict["fingerprint"] = plan_fp

    plan_path = dest_dir / "plan.json"
    plan_path.write_bytes((json.dumps(plan_dict, indent=2, sort_keys=True) + "\n").encode("utf-8"))

    manifest_dict: dict[str, Any] = {
        "actions": [{"detail": f"step {s['seq']}", "kind": s["recipe"]} for s in steps],
        "assurance": "repaired-lossless",
        "declared_loss": [],
        "idempotency_key": "a" * 64,
        "input_fingerprint": src_hash,
        "output_fingerprint": out_hash,
        "plan_fingerprint": plan_fp,
        "policy": "conservative",
        "revalidate_report": None,
        "revalidation": {
            "assurance": "A3",
            "error_count": 0,
            "warning_count": 0,
            "profile_id": "neutral",
            "profile_version": "1.0.0",
            "report_fingerprint": None,
        },
        "assurance_ceiling": "A3",
        "schema_version": "sesslint.repair-manifest/v1",
    }
    manifest_path = dest_dir / "manifest.json"
    manifest_path.write_bytes(
        (json.dumps(manifest_dict, indent=2, sort_keys=True) + "\n").encode("utf-8")
    )

    start_time = time.perf_counter()
    verdict = verify(
        source_path=src_path,
        plan_path=plan_path,
        output_path=out_path,
        manifest_path=manifest_path,
    )
    duration = time.perf_counter() - start_time

    assert duration < 2.0, f"Replay of 50 steps took {duration:.3f}s (must be < 2.0s)"
    assert verdict.ok is True


# ---------------------------------------------------------------------------
# 4. Safety Invariants (Static Grep & Read-Only Runtime)
# ---------------------------------------------------------------------------


def test_no_executor_import() -> None:
    """Static grep: verify.py contains zero occurrences of 'executor'."""
    content = VERIFY_SRC.read_text(encoding="utf-8")
    matches = re.findall(r"\bexecutor\b", content, re.IGNORECASE)
    assert not matches, f"Forbidden reference to 'executor' found in verify.py: {matches}"


def test_read_only_static() -> None:
    """Static AST/regex: verify.py contains zero write primitives."""
    content = VERIFY_SRC.read_text(encoding="utf-8")
    forbidden_patterns = [
        re.compile(r"\bopen\s*\([^)]*['\"][wWaA\+]"),
        re.compile(r"\bos\.(replace|rename|remove|unlink|rmdir|mkdir|makedirs)\b"),
        re.compile(r"\bshutil\b"),
        re.compile(r"\.write_(text|bytes)\s*\("),
    ]
    for pat in forbidden_patterns:
        match = pat.search(content)
        assert match is None, f"Forbidden write primitive matched pattern {pat.pattern}: {match}"


def test_read_only_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Runtime execution proof: verify succeeds with write primitives intercepted/blocked."""
    src, pln, out, man = _write_ok_bundle(tmp_path)

    # Intercept write operations
    def _forbidden_write(*args: Any, **kwargs: Any) -> Any:
        raise PermissionError("Attempted write during read-only verify execution")

    monkeypatch.setattr(Path, "write_bytes", _forbidden_write)
    monkeypatch.setattr(Path, "write_text", _forbidden_write)
    monkeypatch.setattr(os, "replace", _forbidden_write)
    monkeypatch.setattr(os, "rename", _forbidden_write)

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    assert verdict.ok is True


# ---------------------------------------------------------------------------
# 5. CLI Invocation Tests & Exit Codes
# ---------------------------------------------------------------------------


def test_cli_exit_code_0(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """CLI exits with 0 and prints valid JSON on successful verification."""
    src, pln, out, man = _write_ok_bundle(tmp_path)
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
    assert exit_code == 0
    parsed = json.loads(captured.out)
    assert parsed["ok"] is True
    assert parsed["assurance"] == "repaired-lossless"
    assert len(parsed["checks"]) == 7


def test_cli_exit_code_1_on_audit_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """CLI exits with 1 and prints valid JSON when audit checks fail."""
    src, pln, out, man = _write_ok_bundle(tmp_path)
    out.write_bytes(b'{"tampered": true}\n')

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
    assert exit_code == 1
    parsed = json.loads(captured.out)
    assert parsed["ok"] is False


def test_cli_exit_code_2_on_missing_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """CLI exits with 2 when a file cannot be found."""
    src, pln, out, man = _write_ok_bundle(tmp_path)
    missing = tmp_path / "nonexistent.jsonl"

    exit_code = main(
        [
            "verify",
            "--source",
            str(missing),
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


def test_cli_exit_code_2_on_missing_args() -> None:
    """CLI exits with 2 when required options are omitted."""
    with pytest.raises(SystemExit) as exc_info:
        main(["verify", "--source", "file.jsonl"])
    assert exc_info.value.code == 2


def test_verdict_and_check_dataclasses() -> None:
    """Check and Verdict dataclasses serialize to dict and JSON deterministically."""
    c = Check(name="source_hash", ok=True, detail="matched")
    assert c.to_dict() == {"detail": "matched", "name": "source_hash", "ok": True}

    v = Verdict(ok=True, checks=(c,), assurance="clean")
    v_dict = v.to_dict()
    assert v_dict["ok"] is True
    assert v_dict["assurance"] == "clean"
    assert v_dict["checks"] == [c.to_dict()]

    v_json = v.to_json(indent=2)
    assert '"assurance": "clean"' in v_json
    assert '"ok": true' in v_json


def test_verify_without_plan_bootstrapping(tmp_path: Path) -> None:
    """verify() succeeds without plan_path by re-planning from source events and manifest."""
    from sesslint.api import repair

    src_lines = [
        '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"test-verify-sess"}',
        '{"actor":"user","id":"msg-0","kind":"message","parent_id":null,"payload":{"text":"hello"},"seq":0,"ts":"2026-09-05T12:00:00Z"}',
        '{"actor":"assistant","id":"msg-1","kind":"message","parent_id":"msg-0","payload":{"text":"ack"},"seq":1,"ts":"2026-09-05T12:00:01Z"}',
        '{"actor":"assistant","id":"msg-1","kind":"message","parent_id":"msg-0","payload":{"text":"ack"},"seq":1,"ts":"2026-09-05T12:00:01Z"}',
        '{"actor":"user","id":"msg-2","kind":"message","parent_id":"msg-1","payload":{"text":"next"},"seq":2,"ts":"2026-09-05T12:00:02Z"}',
    ]
    src = tmp_path / "source.jsonl"
    src.write_text("\n".join(src_lines) + "\n", encoding="utf-8")
    out = tmp_path / "output.jsonl"
    man = tmp_path / "output.jsonl.manifest.json"

    plan_obj, manifest = repair(src, out)
    assert manifest is not None
    assert man.is_file()

    verdict = verify(
        source_path=src,
        output_path=out,
        manifest_path=man,
    )
    assert verdict.ok is True
    c2 = verdict.checks[1]
    assert c2.name == "plan_fingerprint"
    assert c2.ok is True
    assert c2.detail == "matched"


def test_verify_manifest_actions_tampered_fails_check_4(tmp_path: Path) -> None:
    """verify() fails Check 4 when manifest.actions does not match planned steps."""
    src, pln, out, man = _write_ok_bundle(tmp_path)
    manifest_data = json.loads(man.read_text(encoding="utf-8"))
    # Alter the action kind
    manifest_data["actions"][0]["kind"] = "unauthorized-synthetic-recipe"
    man.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    verdict = verify(
        source_path=src,
        plan_path=pln,
        output_path=out,
        manifest_path=man,
    )
    assert verdict.ok is False
    c4 = verdict.checks[3]
    assert c4.name == "transformation_audit"
    assert c4.ok is False
    assert "actions" in c4.detail or "mismatch" in c4.detail


def test_verify_missing_plan_fingerprint_fails_check_2(tmp_path: Path) -> None:
    """verify() fails Check 2 (plan_fingerprint) if plan_fingerprint is missing from manifest."""
    src, pln, out, man = _write_ok_bundle(tmp_path)
    manifest_data = json.loads(man.read_text(encoding="utf-8"))
    del manifest_data["plan_fingerprint"]
    man.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    verdict = verify(
        source_path=src,
        plan_path=pln,
        output_path=out,
        manifest_path=man,
    )
    assert verdict.ok is False
    c2 = verdict.checks[1]
    assert c2.name == "plan_fingerprint"
    assert c2.ok is False
    assert c2.detail == "manifest-missing-plan-fingerprint"


def test_verify_missing_assurance_fails_check_6(tmp_path: Path) -> None:
    """verify() fails Check 6 (assurance_audit) if assurance is missing from manifest."""
    src, pln, out, man = _write_ok_bundle(tmp_path)
    manifest_data = json.loads(man.read_text(encoding="utf-8"))
    del manifest_data["assurance"]
    man.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    verdict = verify(
        source_path=src,
        plan_path=pln,
        output_path=out,
        manifest_path=man,
    )
    assert verdict.ok is False
    c6 = verdict.checks[5]
    assert c6.name == "assurance_audit"
    assert c6.ok is False
    assert c6.detail == "manifest-missing-assurance"


def test_render_verify_human_formatting() -> None:
    """render_verify_human formats pass and fail verdicts with check details."""
    from sesslint.verify import render_verify_human

    c_pass = Check(name="source_hash", ok=True, detail="matched")
    c_fail = Check(name="idempotence", ok=False, detail="non-idempotent")

    v_pass = Verdict(ok=True, checks=(c_pass,), assurance="repaired-lossless")
    text_pass = render_verify_human(v_pass, color=False)
    assert "Verification: PASSED" in text_pass
    assert "[PASS] source_hash: matched" in text_pass

    v_fail = Verdict(ok=False, checks=(c_fail,), assurance="unrepairable")
    text_fail = render_verify_human(v_fail, color=True)
    assert "FAILED" in text_fail
    assert "idempotence: non-idempotent" in text_fail


def test_verify_missing_actions_fails_check_4(tmp_path: Path) -> None:
    """verify() fails Check 4 (transformation_audit) if actions is missing from manifest."""
    src, pln, out, man = _write_ok_bundle(tmp_path)
    manifest_data = json.loads(man.read_text(encoding="utf-8"))
    del manifest_data["actions"]
    man.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    verdict = verify(
        source_path=src,
        plan_path=pln,
        output_path=out,
        manifest_path=man,
    )
    assert verdict.ok is False
    c4 = verdict.checks[3]
    assert c4.name == "transformation_audit"
    assert c4.ok is False
    assert c4.detail in ("manifest-missing-actions", "manifest-schema")


def test_old_shape_manifest_rejected_with_manifest_schema(tmp_path: Path) -> None:
    """Old-shape manifest missing revalidation is rejected with manifest-schema."""
    src, pln, out, man = _write_ok_bundle(tmp_path)
    manifest_data = json.loads(man.read_text(encoding="utf-8"))
    del manifest_data["revalidation"]
    del manifest_data["assurance_ceiling"]
    man.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    verdict = verify(source_path=src, plan_path=pln, output_path=out, manifest_path=man)
    assert verdict.ok is False
    c_map = {c.name: c for c in verdict.checks}
    assert c_map["source_hash"].ok is False
    assert c_map["source_hash"].detail == "manifest-schema"
    assert c_map["assurance_audit"].ok is False
    assert c_map["assurance_audit"].detail == "manifest-schema"


def test_verify_with_real_manifest_from_executor(tmp_path: Path) -> None:
    """verify() succeeds on a real manifest emitted by executor.py (RVW-008, RVW-036)."""
    from sesslint.api import repair

    src = tmp_path / "real_source.jsonl"
    out = tmp_path / "real_repaired.jsonl"

    lines = [
        '{"created_at":"2026-09-08T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"sess_real_verify"}',
        '{"actor":"user","id":"evt_001","kind":"message","parent_id":null,"payload":{"text":"hello"},"seq":0,"ts":"2026-09-08T12:00:00Z"}',
        '{"actor":"assistant","id":"evt_002","kind":"message","parent_id":"evt_001","payload":{"text":"hi"},"seq":1,"ts":"2026-09-08T12:00:01Z"}',
        # Duplicate identical record
        '{"actor":"assistant","id":"evt_002","kind":"message","parent_id":"evt_001","payload":{"text":"hi"},"seq":1,"ts":"2026-09-08T12:00:01Z"}',
    ]
    src.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Run real programmatic repair which invokes executor.execute()
    plan_obj, manifest = repair(src, out)
    assert plan_obj is not None
    assert manifest is not None
    assert out.is_file()

    manifest_path = Path(f"{out}.manifest.json")
    assert manifest_path.is_file()

    # Verify directly with real manifest from executor
    verdict = verify(
        source_path=src,
        output_path=out,
        manifest_path=manifest_path,
    )
    assert verdict.ok is True
    for check in verdict.checks:
        assert check.ok is True, f"Check {check.name} failed with detail: {check.detail}"


def test_verify_cli_with_real_manifest(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """CLI verify passes with exit 0 when given real manifest generated by CLI repair."""
    src = tmp_path / "cli_source.jsonl"
    out = tmp_path / "cli_repaired.jsonl"

    lines = [
        '{"created_at":"2026-09-08T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"sess_cli_verify"}',
        '{"actor":"user","id":"evt_001","kind":"message","parent_id":null,"payload":{"text":"hello"},"seq":0,"ts":"2026-09-08T12:00:00Z"}',
        '{"actor":"assistant","id":"evt_002","kind":"message","parent_id":"evt_001","payload":{"text":"hi"},"seq":1,"ts":"2026-09-08T12:00:01Z"}',
        '{"actor":"assistant","id":"evt_002","kind":"message","parent_id":"evt_001","payload":{"text":"hi"},"seq":1,"ts":"2026-09-08T12:00:01Z"}',
    ]
    src.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # 1. Repair via CLI
    code_rep = main(["repair", str(src), "--out", str(out)])
    assert code_rep == 0
    capsys.readouterr()  # Clear repair stdout
    manifest_p = Path(f"{out}.manifest.json")
    assert manifest_p.is_file()

    # 2. Verify via CLI in JSON mode
    code_ver = main(
        [
            "verify",
            str(src),
            str(out),
            "--manifest",
            str(manifest_p),
            "--json",
        ]
    )
    assert code_ver == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["ok"] is True

    # 3. Verify via CLI in human mode
    code_ver_human = main(
        [
            "verify",
            str(src),
            str(out),
            "--manifest",
            str(manifest_p),
        ]
    )
    assert code_ver_human == 0
    captured_human = capsys.readouterr()
    assert "Verification: PASSED" in captured_human.out


def test_verify_detects_tampered_output_with_real_manifest(tmp_path: Path) -> None:
    """verify() fails when output file is tampered after real repair execution."""
    from sesslint.api import repair

    src = tmp_path / "tamper_source.jsonl"
    out = tmp_path / "tamper_repaired.jsonl"

    lines = [
        '{"created_at":"2026-09-08T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"sess_tamper"}',
        '{"actor":"user","id":"evt_001","kind":"message","parent_id":null,"payload":{"text":"hello"},"seq":0,"ts":"2026-09-08T12:00:00Z"}',
        '{"actor":"assistant","id":"evt_002","kind":"message","parent_id":"evt_001","payload":{"text":"hi"},"seq":1,"ts":"2026-09-08T12:00:01Z"}',
        '{"actor":"assistant","id":"evt_002","kind":"message","parent_id":"evt_001","payload":{"text":"hi"},"seq":1,"ts":"2026-09-08T12:00:01Z"}',
    ]
    src.write_text("\n".join(lines) + "\n", encoding="utf-8")

    plan_obj, manifest = repair(src, out)
    assert plan_obj is not None
    assert manifest is not None
    manifest_p = Path(f"{out}.manifest.json")

    tampered_evt = (
        '{"actor":"user","id":"evt_tampered","kind":"message",'
        '"parent_id":null,"payload":{},"seq":3,"ts":"2026-09-08T12:00:05Z"}\n'
    )
    out.write_text(out.read_text(encoding="utf-8") + tampered_evt)

    verdict = verify(
        source_path=src,
        output_path=out,
        manifest_path=manifest_p,
    )
    assert verdict.ok is False
