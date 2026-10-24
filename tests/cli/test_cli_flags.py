"""Tests for CLI flag preservation (P1-01) and numeric range validation (P1-02)."""

from __future__ import annotations

from pathlib import Path

import pytest

from sesslint.cli import create_parser, main


def test_global_flag_preservation_subcommands() -> None:
    """Root --color/--no-color survive into subcommand namespaces (P1-01)."""
    parser = create_parser()

    # check subcommand
    args = parser.parse_args(["--color", "always", "check", "file.jsonl"])
    assert args.color == "always"

    # check with --no-color global
    args = parser.parse_args(["--no-color", "check", "file.jsonl"])
    assert args.no_color is True

    # scan (check alias) with --no-color global
    args = parser.parse_args(["--color", "never", "--no-color", "scan", "some_dir"])
    assert args.color == "never"
    assert args.no_color is True

    # repair subcommand with --no-color global
    args = parser.parse_args(["--no-color", "repair", "file.jsonl", "-o", "out.jsonl"])
    assert args.no_color is True

    # verify subcommand with --no-color global
    args = parser.parse_args(["--color", "never", "--no-color", "verify", "--manifest", "m.json"])
    assert args.color == "never"
    assert args.no_color is True

    # adapter/profile/policy/include-content are subcommand-level flags
    args = parser.parse_args(
        ["check", "file.jsonl", "--profile", "p_check", "--adapter", "canonical"]
    )
    assert args.profile == "p_check"
    assert args.adapter == "canonical"

    args = parser.parse_args(
        ["repair", "file.jsonl", "-o", "out.jsonl", "--policy", "salvage", "--include-content"]
    )
    assert args.policy == "salvage"
    assert args.include_content is True


def test_subcommand_flag_override() -> None:
    """Subcommand-level flags override root flags when explicitly provided (P1-01)."""
    parser = create_parser()

    # check subcommand overrides root color
    args = parser.parse_args(["--color", "always", "check", "file.jsonl", "--color", "never"])
    assert args.color == "never"

    # scan (check alias) subcommand overrides root color
    args = parser.parse_args(["--color", "always", "scan", "some_dir", "--color", "never"])
    assert args.color == "never"

    # repair subcommand policy
    args = parser.parse_args(["repair", "file.jsonl", "-o", "out.jsonl", "--policy", "salvage"])
    assert args.policy == "salvage"

    # verify subcommand overrides color
    args = parser.parse_args(
        [
            "--color",
            "always",
            "verify",
            "--color",
            "never",
            "--manifest",
            "manifest.json",
        ]
    )
    assert args.color == "never"


def test_cli_range_validation_max_files_max_bytes(capsys: pytest.CaptureFixture[str]) -> None:
    """Validate that non-positive integer limits are rejected with exit code 2 (P1-02)."""
    parser = create_parser()

    for cmd in ["check", "scan"]:
        for flag in ["--max-files", "--max-bytes"]:
            for bad_val in ["0", "-1", "-100"]:
                argv = [cmd, flag, bad_val, "dummy_path"]
                with pytest.raises(SystemExit) as exc_info:
                    parser.parse_args(argv)
                assert exc_info.value.code == 2
                err = capsys.readouterr().err
                assert "positive integer (> 0)" in err


def test_cli_range_validation_confidence_margin(capsys: pytest.CaptureFixture[str]) -> None:
    """Validate that threshold values outside (0.0, 1.0) are rejected with exit code 2 (P1-02).

    Contract: Per sesslint.profiles.profile.resolve_effective_config lines 141-144,
    the documented contract requires:
        0.0 < confidence_min < 1.0 (finite float)
        0.0 < margin_min < 1.0 (finite float)
    Therefore, boundaries 0.0 and 1.0 are rejected, as well as negatives and values > 1.0.
    """
    parser = create_parser()

    for cmd in ["check", "bundle"]:
        for flag in ["--confidence-min", "--margin-min"]:
            for bad_val in ["0", "0.0", "1", "1.0", "-0.1", "1.1", "nan", "inf"]:
                argv = [cmd, flag, bad_val, "dummy_path"]
                with pytest.raises(SystemExit) as exc_info:
                    parser.parse_args(argv)
                assert exc_info.value.code == 2
                err = capsys.readouterr().err
                assert "strictly between 0.0 and 1.0" in err


def _run_cli(argv: list[str]) -> int:
    try:
        return main(argv)
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 0


def test_cli_main_exit_code_on_range_error(tmp_path: Path) -> None:
    """Test main() entry point returns exit code 2 on range validation failures (P1-02)."""
    sample = tmp_path / "sample.jsonl"
    sample.write_text(
        '{"schema_version":"sesslint.session/v1","session_id":"s1"}\n',
        encoding="utf-8",
    )

    assert _run_cli(["check", "--max-files", "0", str(sample)]) == 2
    assert _run_cli(["check", "--max-bytes", "-10", str(sample)]) == 2
    assert _run_cli(["check", "--confidence-min", "2.0", str(sample)]) == 2
    assert _run_cli(["check", "--margin-min", "0.0", str(sample)]) == 2


# ---------------------------------------------------------------------------
# T-02: standalone scan threshold flags
# ---------------------------------------------------------------------------


def test_scan_parser_accepts_threshold_flags() -> None:
    """The standalone scan parser accepts --confidence-min/--margin-min (T-02)."""
    parser = create_parser()
    args = parser.parse_args(["scan", "some_dir", "--confidence-min", "0.7", "--margin-min", "0.2"])
    assert args.confidence_min == 0.7
    assert args.margin_min == 0.2


def test_scan_threshold_flags_reject_out_of_range(capsys: pytest.CaptureFixture[str]) -> None:
    """scan --confidence-min/--margin-min reject values outside (0.0, 1.0) with exit 2."""
    parser = create_parser()
    for flag in ["--confidence-min", "--margin-min"]:
        for bad_val in ["0", "0.0", "1", "1.0", "-0.1", "1.1", "nan", "inf"]:
            with pytest.raises(SystemExit) as exc_info:
                parser.parse_args(["scan", flag, bad_val, "dummy_dir"])
            assert exc_info.value.code == 2
            err = capsys.readouterr().err
            assert "strictly between 0.0 and 1.0" in err


def test_scan_threshold_flags_reach_detection(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """scan <dir> --confidence-min applies the effective threshold to per-file detection."""
    from unittest.mock import patch

    fixture = (
        Path(__file__).resolve().parent.parent.parent
        / "fixtures"
        / "cli"
        / "check_basic"
        / "healthy.jsonl"
    )
    (tmp_path / "a.jsonl").write_bytes(fixture.read_bytes())

    with (
        patch("sesslint.adapters.detect.detect_claude_code", return_value=0.60),
        patch("sesslint.adapters.detect.detect_openai_agents", return_value=0.10),
        patch("sesslint.adapters.detect.detect_canonical", return_value=0.10),
    ):
        # Default thresholds: 0.60 wins -> file is healthy -> exit 0.
        assert main(["scan", str(tmp_path)]) == 0
        capsys.readouterr()
        # Raised confidence_min=0.70: detection is unsupported by default.
        assert main(["scan", str(tmp_path), "--confidence-min", "0.7"]) == 0
        capsys.readouterr()
        assert (
            main(["scan", str(tmp_path), "--confidence-min", "0.7", "--fail-on-unsupported"]) == 1
        )


def test_check_dir_branch_threshold_flags_reach_detection(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """check <dir> forwards --confidence-min/--margin-min to check_dir (T-02)."""
    from unittest.mock import patch

    fixture = (
        Path(__file__).resolve().parent.parent.parent
        / "fixtures"
        / "cli"
        / "check_basic"
        / "healthy.jsonl"
    )
    (tmp_path / "a.jsonl").write_bytes(fixture.read_bytes())

    with (
        patch("sesslint.adapters.detect.detect_claude_code", return_value=0.60),
        patch("sesslint.adapters.detect.detect_openai_agents", return_value=0.10),
        patch("sesslint.adapters.detect.detect_canonical", return_value=0.10),
    ):
        assert main(["check", str(tmp_path)]) == 0
        capsys.readouterr()
        assert main(["check", str(tmp_path), "--confidence-min", "0.7"]) == 0
        capsys.readouterr()
        assert (
            main(
                [
                    "check",
                    str(tmp_path),
                    "--confidence-min",
                    "0.7",
                    "--fail-on-unsupported",
                ]
            )
            == 1
        )
