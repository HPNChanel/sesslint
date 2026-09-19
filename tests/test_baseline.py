"""Tests for ``--baseline`` / ``--write-baseline`` fingerprint diffing.

v1 baselines are ``sesslint.baseline/v1`` documents of raw finding
fingerprints — they still load and match. ``--write-baseline`` emits
``sesslint.baseline/v2``: path-normalized keys binding rule code, file role
(``parent-basename/basename``), and structural position — matching survives
absolute/relative spelling changes and relocations above the immediate
parent directory. ``sesslint baseline --upgrade`` migrates v1 files to v2.
Missing or malformed baselines fail closed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.api import check_file
from sesslint.baseline import (
    BASELINE_SCHEMA_VERSION,
    BASELINE_SCHEMA_VERSION_V2,
    BaselineError,
    compute_v2_key,
    dump_baseline,
    file_role,
    filter_findings,
    load_baseline,
    upgrade_baseline,
    write_baseline,
)
from sesslint.cli import main

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
CORRUPT = FIXTURES / "adapters" / "codex" / "orphan_output.jsonl"  # SL101


def _v1_file(path: Path, fingerprints: list[str]) -> Path:
    doc = {"fingerprints": fingerprints, "schema_version": BASELINE_SCHEMA_VERSION}
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def _findings() -> list:
    return list(check_file(CORRUPT).findings)


def test_baseline_v2_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "base.json"
    findings = _findings()
    assert write_baseline(path, findings, created_by="sesslint test") == len(
        {compute_v2_key(f) for f in findings}
    )
    keys = load_baseline(path)
    assert keys == frozenset(compute_v2_key(f) for f in findings)
    # deterministic bytes
    assert path.read_text(encoding="utf-8") == dump_baseline(findings, created_by="sesslint test")
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["schema_version"] == BASELINE_SCHEMA_VERSION_V2
    assert all(set(e) == {"code", "created_by", "file_role", "key"} for e in doc["entries"])


def test_load_v1_still_supported(tmp_path: Path) -> None:
    path = _v1_file(tmp_path / "v1.json", ["5d4465190d6abf3f", "aabbccddeeff0011"])
    assert load_baseline(path) == frozenset({"5d4465190d6abf3f", "aabbccddeeff0011"})


def test_load_missing_fails(tmp_path: Path) -> None:
    with pytest.raises(BaselineError, match="not found"):
        load_baseline(tmp_path / "nope.json")


def test_load_malformed_v1_fails(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"schema_version":"sesslint.baseline/v1","fingerprints":["nope"]}')
    with pytest.raises(BaselineError, match="16-hex"):
        load_baseline(bad)


def test_load_malformed_v2_fails(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(
        '{"schema_version":"sesslint.baseline/v2","entries":[{"key":"nothex"}]}',
        encoding="utf-8",
    )
    with pytest.raises(BaselineError, match="16-hex"):
        load_baseline(bad)


def test_load_wrong_schema_fails(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"schema_version":"other/v9","fingerprints":[]}')
    with pytest.raises(BaselineError, match="schema_version"):
        load_baseline(bad)


def test_file_role_normalizes_spelling() -> None:
    assert file_role(r"C:\work\proj\sess\run.jsonl") == "sess/run.jsonl"
    assert file_role("sess/run.jsonl") == "sess/run.jsonl"
    assert file_role("./sess/run.jsonl") == "sess/run.jsonl"
    assert file_role("/abs/anywhere/sess/run.jsonl") == "sess/run.jsonl"
    assert file_role("<stdin>") == "<stdin>"


def test_file_role_bare_name_uses_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A bare relative name inherits the cwd basename as its parent."""
    cwd = tmp_path / "sess"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    assert file_role("run.jsonl") == "sess/run.jsonl"
    # dotdot collapses lexically
    assert file_role("../sess/run.jsonl") == "sess/run.jsonl"


def test_v2_key_path_spelling_independent() -> None:
    """Same finding at different path spellings yields the same v2 key."""
    from sesslint.finding import SourceRef, make_finding

    f_rel = make_finding(
        code="SL101",
        severity="error",
        message_template="x",
        source=SourceRef("sess/run.jsonl"),
    )
    f_abs = make_finding(
        code="SL101",
        severity="error",
        message_template="x",
        source=SourceRef("C:/deep/checkout/sess/run.jsonl"),
    )
    # v1 fingerprints differ (path is bound); v2 keys agree (file_role only).
    assert f_rel.fingerprint != f_abs.fingerprint
    assert compute_v2_key(f_rel) == compute_v2_key(f_abs)


def test_v2_key_immediate_parent_rename_differs() -> None:
    """Renaming the immediate parent changes file_role — documented residual
    ambiguity, never silently widened."""
    from sesslint.finding import SourceRef, make_finding

    f_a = make_finding(
        code="SL101",
        severity="error",
        message_template="x",
        source=SourceRef("dirA/run.jsonl"),
    )
    f_b = make_finding(
        code="SL101",
        severity="error",
        message_template="x",
        source=SourceRef("dirB/run.jsonl"),
    )
    assert compute_v2_key(f_a) != compute_v2_key(f_b)


def test_check_write_v2_then_baseline(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    base = tmp_path / "b.json"
    # write: findings still reported and counted; file is v2 format
    assert main(["check", str(CORRUPT), "--write-baseline", str(base)]) == 1
    capsys.readouterr()
    doc = json.loads(base.read_text(encoding="utf-8"))
    assert doc["schema_version"] == BASELINE_SCHEMA_VERSION_V2
    assert len(doc["entries"]) == 1
    # apply: the known finding is suppressed → clean report, exit 0
    code = main(["check", str(CORRUPT), "--baseline", str(base), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["counts"]["by_code"].get("SL101", 0) == 0
    assert code == 0


def test_check_v2_baseline_survives_relative_invoke(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A v2 baseline written via an absolute path suppresses the same finding
    when the file is checked through a relative spelling."""
    base = tmp_path / "b.json"
    assert main(["check", str(CORRUPT), "--write-baseline", str(base)]) == 1
    capsys.readouterr()
    monkeypatch.chdir(CORRUPT.parent)
    code = main(["check", CORRUPT.name, "--baseline", str(base), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["counts"]["by_code"].get("SL101", 0) == 0
    assert code == 0


def test_v1_baseline_still_suppresses_via_v1_leg(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Legacy v1 baselines match by raw fingerprint — unchanged semantics."""
    fps = [f.fingerprint for f in _findings()]
    base = _v1_file(tmp_path / "v1.json", fps)
    code = main(["check", str(CORRUPT), "--baseline", str(base), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["counts"]["by_code"].get("SL101", 0) == 0
    assert code == 0


def test_ambiguous_v2_key_suppresses_nothing(tmp_path: Path) -> None:
    """Two distinct findings sharing one v2 key match neither (fail-closed)."""
    from sesslint.finding import SourceRef, make_finding

    # Same code + file_role + position + evidence, but different adapter_id:
    # v1 fingerprints differ (adapter is bound), v2 keys collide (adapter is
    # deliberately not part of the v2 preimage).
    f1 = make_finding(
        code="SL006",
        severity="warning",
        message_template="x",
        source=SourceRef("sess/run.jsonl", line=3),
        adapter_id="adapt-a",
    )
    f2 = make_finding(
        code="SL006",
        severity="warning",
        message_template="x",
        source=SourceRef("sess/run.jsonl", line=3),
        adapter_id="adapt-b",
    )
    assert f1.fingerprint != f2.fingerprint
    shared = compute_v2_key(f1)
    assert shared == compute_v2_key(f2)
    kept = filter_findings([f1, f2], frozenset({shared}))
    assert kept == [f1, f2]
    # a non-ambiguous key still suppresses normally
    kept2 = filter_findings([f1], frozenset({shared}))
    assert kept2 == []


def test_upgrade_unverified_without_source(tmp_path: Path) -> None:
    v1 = _v1_file(tmp_path / "v1.json", ["5d4465190d6abf3f", "aabbccddeeff0011"])
    doc_str, verified, unverified = upgrade_baseline(v1, None)
    assert verified == 0
    assert unverified == 2
    doc = json.loads(doc_str)
    assert doc["schema_version"] == BASELINE_SCHEMA_VERSION_V2
    assert all(e["migrated"] == "unverified" for e in doc["entries"])
    # unverified entries still suppress through the v1 leg
    keys = frozenset(e["key"] for e in doc["entries"])
    assert keys == frozenset({"5d4465190d6abf3f", "aabbccddeeff0011"})


def test_upgrade_verified_with_source(tmp_path: Path) -> None:
    findings = _findings()
    v1 = _v1_file(tmp_path / "v1.json", [f.fingerprint for f in findings] + ["deadbeefdeadbeef"])
    doc_str, verified, unverified = upgrade_baseline(v1, findings)
    assert verified == 1
    assert unverified == 1
    doc = json.loads(doc_str)
    by_mig = {e["migrated"]: e for e in doc["entries"]}
    assert by_mig["verified"]["key"] == compute_v2_key(findings[0])
    assert by_mig["verified"]["file_role"] == file_role(findings[0].source.path)
    assert by_mig["unverified"]["key"] == "deadbeefdeadbeef"


def test_upgrade_rejects_non_v1(tmp_path: Path) -> None:
    v2 = tmp_path / "v2.json"
    write_baseline(v2, _findings())
    with pytest.raises(BaselineError, match="requires"):
        upgrade_baseline(v2, None)


def test_upgrade_deterministic(tmp_path: Path) -> None:
    v1 = _v1_file(tmp_path / "v1.json", ["aabbccddeeff0011", "5d4465190d6abf3f"])
    assert upgrade_baseline(v1, None)[0] == upgrade_baseline(v1, None)[0]


def test_cli_baseline_upgrade(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    fps = [f.fingerprint for f in _findings()]
    v1 = _v1_file(tmp_path / "v1.json", fps)
    out = tmp_path / "v2.json"
    code = main(
        [
            "baseline",
            "--upgrade",
            str(v1),
            "--source",
            str(CORRUPT),
            "--output",
            str(out),
        ]
    )
    assert code == 0
    assert "verified" in capsys.readouterr().err
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["schema_version"] == BASELINE_SCHEMA_VERSION_V2
    assert doc["entries"][0]["migrated"] == "verified"
    # upgraded baseline suppresses like the original
    code2 = main(["check", str(CORRUPT), "--baseline", str(out), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["counts"]["by_code"].get("SL101", 0) == 0
    assert code2 == 0


def test_cli_baseline_upgrade_to_stdout(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    v1 = _v1_file(tmp_path / "v1.json", ["deadbeefdeadbeef"])
    code = main(["baseline", "--upgrade", str(v1)])
    out = capsys.readouterr().out
    assert code == 0
    doc = json.loads(out)
    assert doc["entries"][0]["migrated"] == "unverified"


def test_cli_baseline_upgrade_missing_source_fails(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    v1 = _v1_file(tmp_path / "v1.json", ["deadbeefdeadbeef"])
    code = main(["baseline", "--upgrade", str(v1), "--source", str(tmp_path / "nope.jsonl")])
    assert code == 2
    assert "not found" in capsys.readouterr().err.lower()


def test_check_missing_baseline_fails(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["check", str(CORRUPT), "--baseline", "nope.json"])
    assert code == 2
    assert "not found" in capsys.readouterr().err.lower()


def test_scan_baseline_suppresses(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    import shutil

    sessions = tmp_path / "sessions"
    sessions.mkdir()
    shutil.copy(CORRUPT, sessions / "rollout.jsonl")
    base = tmp_path / "b.json"
    main(["scan", str(sessions), "--write-baseline", str(base)])
    capsys.readouterr()
    code = main(["scan", str(sessions), "--baseline", str(base), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["totals"]["invalid"] == 0
    assert data["totals"]["healthy"] == 1
    assert code == 0


def test_scan_v2_baseline_survives_tree_rename(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Scan baselines match after the scanned root is relocated (ancestor
    rename keeps file_role stable)."""
    import shutil

    orig = tmp_path / "orig"
    orig.mkdir()
    shutil.copy(CORRUPT, orig / "rollout.jsonl")
    base = tmp_path / "b.json"
    main(["scan", str(orig), "--write-baseline", str(base)])
    capsys.readouterr()
    # relocate the whole tree: parent dir name 'orig' preserved, ancestors differ
    moved_root = tmp_path / "elsewhere" / "deep"
    moved_root.mkdir(parents=True)
    moved = moved_root / "orig"
    shutil.copytree(orig, moved)
    code = main(["scan", str(moved), "--baseline", str(base), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["totals"]["invalid"] == 0
    assert data["totals"]["healthy"] == 1
    assert code == 0


def test_baseline_flags_mutually_exclusive() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["check", str(CORRUPT), "--baseline", "a.json", "--write-baseline", "b.json"])
    assert exc.value.code == 2
