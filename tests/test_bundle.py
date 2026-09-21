"""Tests for diagnostic bundle command, API, and fixture skeleton (DEV-014, US-016, UC-07).

Verifies:
1. Determinism: Same input bytes yield 100% byte-identical bundle JSON.
2. Basename-only: Absolute paths are strictly stripped from bundle source and spans.
3. Hash and size integrity: source.sha256 and source.size match actual file bytes.
4. Skeleton shape: fixture_skeleton contains record_count, kinds, codes, and template.
5. No host/env leak: created_by contains only versions, zero platform/host/user/timestamp data.
6. CLI wrapper: `sesslint bundle` stdout/file output, exit codes, and argument handling.
7. Golden structure: One golden structural proof verifying the bundle contract.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from sesslint import api
from sesslint.bundle import _count_records_bounded, build_bundle
from sesslint.cli import main

FIXTURES_ROOT = Path(__file__).resolve().parent.parent / "fixtures"
HEALTHY_CANONICAL = FIXTURES_ROOT / "cli" / "check_basic" / "healthy.jsonl"
CLAUDE_BASIC = FIXTURES_ROOT / "claude_code" / "basic.jsonl"
POLYGLOT_FIXTURE = FIXTURES_ROOT / "cli" / "check_ambiguity" / "polyglot.json"
HOSTILE_FIXTURE = FIXTURES_ROOT / "bundle" / "hostile_pii.jsonl"


class TestBundleUnit:
    """Unit tests for api.build_bundle and Bundle frozen dataclass."""

    def test_bundle_determinism(self) -> None:
        """Building a bundle twice from the same source file must produce byte-identical JSON."""
        bundle_1 = build_bundle(HEALTHY_CANONICAL)
        bundle_2 = build_bundle(HEALTHY_CANONICAL)

        json_1 = bundle_1.to_json()
        json_2 = bundle_2.to_json()

        assert json_1 == json_2
        assert (
            hashlib.sha256(json_1.encode("utf-8")).hexdigest()
            == hashlib.sha256(json_2.encode("utf-8")).hexdigest()
        )

    def test_source_basename_only(self) -> None:
        """source.path must be basename-only, even when absolute path is passed."""
        abs_path = HEALTHY_CANONICAL.resolve()
        assert abs_path.is_absolute()

        bundle = build_bundle(abs_path)
        assert bundle.source["path"] == HEALTHY_CANONICAL.name
        assert "/" not in bundle.source["path"]
        assert "\\" not in bundle.source["path"]

    def test_source_size_and_sha256(self) -> None:
        """source.sha256 and size must accurately reflect raw file bytes."""
        raw_bytes = HEALTHY_CANONICAL.read_bytes()
        expected_sha = hashlib.sha256(raw_bytes).hexdigest()
        expected_size = len(raw_bytes)

        bundle = build_bundle(HEALTHY_CANONICAL)
        assert bundle.source["sha256"] == expected_sha
        assert bundle.source["size"] == expected_size

    def test_created_by_content_free(self) -> None:
        """created_by must contain tool and versions only, no host/user/env/platform info."""
        bundle = build_bundle(HEALTHY_CANONICAL)
        cb = bundle.created_by

        assert cb["tool"] == "sesslint"
        assert "cli" in cb
        assert "versions" in cb
        assert "schema_session" in cb
        assert "schema_report" in cb
        assert "schema_manifest" in cb
        assert "adapters" in cb
        assert "profiles" in cb

        forbidden_keys = {
            "platform",
            "os",
            "host",
            "hostname",
            "user",
            "username",
            "env",
            "timestamp",
            "created_at",
            "time",
            "date",
        }
        for key in forbidden_keys:
            assert key not in cb, f"Forbidden key {key!r} found in created_by"

    def test_fixture_skeleton_structure(self) -> None:
        """fixture_skeleton must contain record_count, kinds, codes, and template."""
        bundle = build_bundle(HEALTHY_CANONICAL)
        skel = bundle.fixture_skeleton

        assert "record_count" in skel
        assert isinstance(skel["record_count"], int)
        assert skel["record_count"] > 0

        assert "kinds" in skel
        assert isinstance(skel["kinds"], dict)

        assert "codes" in skel
        assert isinstance(skel["codes"], list)

        assert "template" in skel
        template_str = skel["template"]
        assert isinstance(template_str, str)
        assert "FIXTURES.md" in template_str
        assert "evt_example_1" in template_str
        assert "SYNTHETIC" in template_str

    def test_bundle_version_constant(self) -> None:
        """Bundle schema version must strictly be sesslint.bundle/v1."""
        bundle = build_bundle(HEALTHY_CANONICAL)
        assert bundle.bundle_version == "sesslint.bundle/v1"

    def test_missing_file_raises_filenotfound(self) -> None:
        """build_bundle raises FileNotFoundError for nonexistent paths."""
        with pytest.raises(FileNotFoundError):
            build_bundle("non_existent_file_path_xyz123.jsonl")

    def test_directory_raises_isadirectoryerror(self) -> None:
        """build_bundle raises IsADirectoryError when passed a directory."""
        with pytest.raises(IsADirectoryError):
            build_bundle(FIXTURES_ROOT)

    def test_count_records_bounded_io_error(self, tmp_path: Path) -> None:
        """_count_records_bounded returns -1 sentinel on I/O error instead of 0 (P0-07)."""
        dir_path = tmp_path / "a_directory"
        dir_path.mkdir()
        assert _count_records_bounded(dir_path) == -1
        assert _count_records_bounded(tmp_path / "non_existent.jsonl") == -1

    def test_bundle_surfaces_read_error_not_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When counting fails with I/O error, bundle surfaces error, not 0 count (P0-07)."""
        monkeypatch.setattr("sesslint.bundle._count_records_bounded", lambda _p: -1)
        from sesslint.adapters.detect import DetectionResult

        monkeypatch.setattr(
            "sesslint.bundle.resolve_format",
            lambda *args, **kwargs: (
                "unknown",
                DetectionResult(format="unknown", confidences={}, reason="no-match"),
                [],
            ),
        )
        bundle = build_bundle(HEALTHY_CANONICAL)
        skel = bundle.fixture_skeleton
        assert skel["record_count"] == -1
        assert skel.get("error") == "read_error"
        assert skel["record_count"] != 0


class TestBundleCLI:
    """Tests for sesslint bundle CLI command."""

    def test_bundle_stdout_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        """sesslint bundle <path> prints valid JSON to stdout and exits 0."""
        code = main(["bundle", str(HEALTHY_CANONICAL)])
        assert code == 0
        captured = capsys.readouterr()
        assert captured.err == ""

        data = json.loads(captured.out)
        assert data["bundle_version"] == "sesslint.bundle/v1"
        assert data["source"]["path"] == HEALTHY_CANONICAL.name
        assert "created_by" in data
        assert "detection" in data
        assert "report" in data
        assert "fixture_skeleton" in data

    def test_bundle_flag_json_parity(self, capsys: pytest.CaptureFixture[str]) -> None:
        """sesslint bundle <path> --json outputs identical JSON to stdout."""
        code = main(["bundle", str(HEALTHY_CANONICAL), "--json"])
        assert code == 0
        captured = capsys.readouterr()

        data = json.loads(captured.out)
        assert data["bundle_version"] == "sesslint.bundle/v1"

    def test_bundle_out_file(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """sesslint bundle <path> --out <file> writes bundle JSON to specified destination."""
        out_file = tmp_path / "bundle_output.json"
        code = main(["bundle", str(HEALTHY_CANONICAL), "--out", str(out_file)])
        assert code == 0
        captured = capsys.readouterr()
        assert "Diagnostic bundle written to" in captured.out
        assert out_file.exists()

        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert data["bundle_version"] == "sesslint.bundle/v1"
        assert data["source"]["path"] == HEALTHY_CANONICAL.name

    def test_bundle_missing_file_exits_2(self, capsys: pytest.CaptureFixture[str]) -> None:
        """sesslint bundle on nonexistent file prints error to stderr and exits 2."""
        code = main(["bundle", "non_existent_file_98765.jsonl"])
        assert code == 2
        captured = capsys.readouterr()
        assert "Error: Path not found" in captured.err

    def test_bundle_directory_exits_2(self, capsys: pytest.CaptureFixture[str]) -> None:
        """sesslint bundle on directory prints error to stderr and exits 2."""
        code = main(["bundle", str(FIXTURES_ROOT)])
        assert code == 2
        captured = capsys.readouterr()
        assert "directory" in captured.err.lower()

    def test_bundle_confidence_and_margin_min_cli(self, capsys: pytest.CaptureFixture[str]) -> None:
        """sesslint bundle accepts --confidence-min and --margin-min flags."""
        code = main(
            [
                "bundle",
                str(HEALTHY_CANONICAL),
                "--confidence-min",
                "0.8",
                "--margin-min",
                "0.1",
            ]
        )
        assert code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["bundle_version"] == "sesslint.bundle/v1"

    def test_check_stderr_hint_on_detection_failure(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """sesslint check on ambiguous format emits hint to stderr pointing to sesslint bundle."""
        code = main(["check", str(POLYGLOT_FIXTURE), "--json"])
        assert code == 1
        captured = capsys.readouterr()
        # Hint must be present on stderr
        assert "hint: run 'sesslint bundle " in captured.err
        assert "attach the output to an adapter request" in captured.err
        # Stdout must remain pure JSON
        data = json.loads(captured.out)
        assert data["schema_version"] == "sesslint.report/v1"


class TestBundleShareAdvisory:
    """Pre-share advisory for SL009-positive sources (transcript-hygiene T-03).

    The bundle is content-free, but the *source* artifact may still carry live
    secret-shaped material — the advisory warns at the exact moment a user
    produces a shareable artifact.
    """

    SEEDED = FIXTURES_ROOT / "checks" / "secret_seed" / "sl009_seeded.jsonl"
    CLEAN = FIXTURES_ROOT / "checks" / "secret_seed" / "sl009_clean.jsonl"

    def test_seeded_source_emits_advisory(self) -> None:
        bundle = build_bundle(self.SEEDED, format="canonical")
        adv = bundle.to_dict()["share_advisory"]
        assert adv["kind"] == "secret-material-present"
        assert adv["finding_count"] == 14
        assert adv["families"] == sorted(adv["families"])
        assert len(adv["families"]) == 14
        assert "aws-access-key" in adv["families"]
        assert "rotate" in adv["note"]

    def test_clean_source_omits_advisory_key(self) -> None:
        bundle = build_bundle(self.CLEAN, format="canonical")
        # Absent, not null — the key must not appear at all.
        assert "share_advisory" not in bundle.to_dict()
        assert "share_advisory" not in bundle.to_json()

    def test_advisory_is_content_free(self) -> None:
        """No canary bytes anywhere in a seeded bundle JSON."""
        blob = build_bundle(self.SEEDED, format="canonical").to_json()
        for token in (
            "sk-ant-api03-SECRET-CANARY-TOKEN-XYZ123",
            "sk-live-OPENAI-SECRET-TOKEN-51Nz888",
            "AKIAIOSFODNN7EXAMPLE",
            "whsec_TESTWEBHOOKSECRET1234567890",
        ):
            assert token not in blob

    def test_advisory_deterministic(self) -> None:
        j1 = build_bundle(self.SEEDED, format="canonical").to_json()
        j2 = build_bundle(self.SEEDED, format="canonical").to_json()
        assert j1 == j2

    def test_cli_advisory_warns_stderr_but_exits_0(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Non-strict bundle of a seeded file: advisory on stderr, exit 0."""
        code = main(["bundle", str(self.SEEDED), "--format", "canonical", "--json"])
        assert code == 0
        captured = capsys.readouterr()
        assert "share_advisory: source contains secret-shaped material" in captured.err
        data = json.loads(captured.out)  # stdout stays pure JSON
        assert data["share_advisory"]["kind"] == "secret-material-present"

    def test_cli_strict_share_gates_and_writes_nothing(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """--strict-share turns the advisory into a gate: exit 1, no output."""
        out_file = tmp_path / "bundle.json"
        code = main(
            [
                "bundle",
                str(self.SEEDED),
                "--format",
                "canonical",
                "--strict-share",
                "-o",
                str(out_file),
            ]
        )
        assert code == 1
        assert "share_advisory" in capsys.readouterr().err
        assert not out_file.exists()

    def test_cli_strict_share_clean_source_passes(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """--strict-share on a clean source: no advisory, exit 0."""
        out_file = tmp_path / "bundle.json"
        code = main(
            [
                "bundle",
                str(self.CLEAN),
                "--format",
                "canonical",
                "--strict-share",
                "-o",
                str(out_file),
            ]
        )
        assert code == 0
        assert "share_advisory" not in capsys.readouterr().err
        assert out_file.exists()


class TestBundleGolden:
    """Golden contract test for bundle JSON structure and byte snapshot."""

    def test_golden_bundle_schema_and_keys(self) -> None:
        """Verify the exact top-level and nested structure of a generated bundle."""
        bundle = api.build_bundle(HEALTHY_CANONICAL)
        bundle_dict = bundle.to_dict()

        expected_root_keys = {
            "bundle_version",
            "created_by",
            "detection",
            "fixture_skeleton",
            "report",
            "source",
        }
        assert set(bundle_dict.keys()) == expected_root_keys

        # source keys
        assert set(bundle_dict["source"].keys()) == {"path", "sha256", "size"}

        # detection keys
        expected_det_keys = {"confidences", "reason", "requested", "resolved"}
        assert expected_det_keys.issubset(set(bundle_dict["detection"].keys()))

        # fixture_skeleton keys
        expected_skel_keys = {"codes", "kinds", "record_count", "template"}
        assert set(bundle_dict["fixture_skeleton"].keys()) == expected_skel_keys

        # report keys
        expected_report_keys = {
            "assurance",
            "counts",
            "coverage",
            "findings",
            "limitation",
            "schema_version",
            "session_id",
            "source_fingerprint",
            "tool_version",
        }
        assert set(bundle_dict["report"].keys()) == expected_report_keys

    def test_golden_bundle_byte_exact_snapshot(self) -> None:
        """Verify bundle JSON output identically matches committed golden snapshot."""
        golden_path = FIXTURES_ROOT / "bundle" / "golden_bundle.json"
        assert golden_path.is_file(), f"Golden bundle missing at {golden_path}"

        bundle = api.build_bundle(HEALTHY_CANONICAL)
        assert bundle.to_json() == golden_path.read_text(encoding="utf-8")


class TestBundleIntegration:
    """Integration tests combining check, bundle, hints, and evidence flows."""

    def test_unsupported_version_integration_check_hint_and_bundle_evidence(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Unsupported version input emits stderr hint on check and captures
        version_evidence in bundle.
        """
        unsupported_session = tmp_path / "unsupported_version.jsonl"
        unsupported_session.write_text(
            json.dumps(
                {
                    "created_at": "2026-09-13T10:00:00Z",
                    "schema_version": "sesslint.session/v1",
                    "session_id": "sess_unsupported_99",
                    "version": 99,
                }
            )
            + "\n"
            + json.dumps(
                {
                    "actor": "user",
                    "id": "evt_1",
                    "kind": "message",
                    "parent_id": None,
                    "payload": {"text": "hello"},
                    "seq": 0,
                    "ts": "2026-09-13T10:00:01Z",
                }
            )
            + "\n",
            encoding="utf-8",
        )

        # 1. sesslint check: fails and prints hint on stderr
        check_code = main(["check", str(unsupported_session)])
        assert check_code == 1
        captured_check = capsys.readouterr()
        assert "hint: run 'sesslint bundle " in captured_check.err
        assert "attach the output to an adapter request" in captured_check.err

        # 2. sesslint bundle: succeeds with code 0 and records version_evidence
        bundle_code = main(["bundle", str(unsupported_session), "--format", "canonical"])
        assert bundle_code == 0
        captured_bundle = capsys.readouterr()
        bundle_data = json.loads(captured_bundle.out)

        assert bundle_data["bundle_version"] == "sesslint.bundle/v1"
        assert "version_evidence" in bundle_data["detection"]
        assert "version_raw" in bundle_data["detection"]["version_evidence"]
        assert "supported_set" in bundle_data["detection"]["version_evidence"]
        assert "SL301" in bundle_data["fixture_skeleton"]["codes"]

    def test_bundle_toctou_mutation_detected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Concurrent file mutation during bundle generation raises SourceChangedError."""
        import sesslint.api as api_mod
        from sesslint.errors import SourceChangedError

        session_file = tmp_path / "mutating_session.jsonl"
        session_file.write_text(HEALTHY_CANONICAL.read_text(encoding="utf-8"), encoding="utf-8")

        original_check_file = api_mod.check_file

        def mutating_check_file(*args: Any, **kwargs: Any) -> Any:
            with open(session_file, "a", encoding="utf-8") as f:
                f.write('{"mutated": true}\n')
            return original_check_file(*args, **kwargs)

        monkeypatch.setattr("sesslint.api.check_file", mutating_check_file)

        with pytest.raises(SourceChangedError, match="TOCTOU detected"):
            api.build_bundle(session_file)


# ---------------------------------------------------------------------------
# T-02: bundle outer detection and embedded report use identical thresholds
# ---------------------------------------------------------------------------


def test_bundle_outer_and_embedded_share_effective_thresholds() -> None:
    """Outer resolve_format and embedded check_file must use identical effective thresholds.

    A detector score of 0.60 succeeds under the default 0.55 but fails under 0.70;
    asserting both surfaces flip together proves they consumed the same values.
    """
    from unittest.mock import patch

    bundle = build_bundle  # local alias for readability

    with (
        patch("sesslint.adapters.detect.detect_claude_code", return_value=0.60),
        patch("sesslint.adapters.detect.detect_openai_agents", return_value=0.10),
        patch("sesslint.adapters.detect.detect_canonical", return_value=0.10),
    ):
        default_bundle = bundle(HEALTHY_CANONICAL)
        assert default_bundle.detection["resolved"] == "claude-code-jsonl"
        assert not any(f["code"] == "SL302" for f in default_bundle.report["findings"])

        strict_bundle = bundle(HEALTHY_CANONICAL, confidence_min=0.70)
        # Outer detection surface: resolution failed under the raised threshold.
        assert strict_bundle.detection["resolved"] is None
        # Embedded report surface: SL302 evidence records the same effective value.
        sl302 = [f for f in strict_bundle.report["findings"] if f["code"] == "SL302"]
        assert sl302, "embedded report must carry the SL302 detection-failure finding"
        assert sl302[0]["evidence"]["confidence_min"] == 0.70
        assert sl302[0]["evidence"]["margin_min"] == 0.15


def test_bundle_resolve_format_call_kwargs_match_embedded() -> None:
    """Capture kwargs reaching both resolve_format call sites and assert equality."""
    from unittest.mock import patch

    import sesslint.api as api_mod
    import sesslint.bundle as bundle_mod

    seen: list[dict[str, Any]] = []
    real_bundle_rf = bundle_mod.resolve_format
    real_api_rf = api_mod.resolve_format

    def spy_bundle(*args: Any, **kwargs: Any) -> Any:
        seen.append(dict(kwargs))
        return real_bundle_rf(*args, **kwargs)

    def spy_api(*args: Any, **kwargs: Any) -> Any:
        seen.append(dict(kwargs))
        return real_api_rf(*args, **kwargs)

    with (
        patch.object(bundle_mod, "resolve_format", spy_bundle),
        patch.object(api_mod, "resolve_format", spy_api),
    ):
        build_bundle(HEALTHY_CANONICAL, confidence_min=0.70, margin_min=0.20)

    assert len(seen) == 2
    assert seen[0] == seen[1] == {"confidence_min": 0.70, "margin_min": 0.20}
