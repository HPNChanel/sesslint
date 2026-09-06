"""Unit, matrix, boundary, and adversarial tests for format auto-detection (TASK-011).

Validates:
- Threshold and margin constants pinning (CONFIDENCE_MIN=0.55, MARGIN_MIN=0.15, SNIFF_BYTES=65536).
- Clear-winner auto-detection across vendor fixtures (claude-code-jsonl, openai-agents, canonical).
- Ambiguity fail-closed rule: tied scores or margin < 0.15 emit SL302 finding without loaders.
- Low-confidence fail-closed rule: unrecognized formats emit SL302 finding without guess-parsing.
- Explicit --format override: bypasses sniffing; invalid values raise ValueError.
- Empty input refusal: 0-byte, whitespace-only, and BOM-only files emit empty-input finding.
- Live SQLite database short-circuit: SQLite magic header triggers immediate refusal finding.
- Determinism and idempotency: repeated sniffing produces identical DetectionResult instances.
- Adversarial boundaries: 0.55 confidence boundary, margin boundary, epsilon ties, lying extensions.
- CLI smoke: --format flag wiring and exit code behavior.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from sesslint.adapters.detect import (
    CONFIDENCE_MIN,
    EPSILON,
    FORMAT_AUTO,
    FORMAT_CANONICAL,
    FORMAT_CLAUDE_CODE,
    FORMAT_OPENAI_AGENTS,
    MARGIN_MIN,
    REASON_CLEAR_WINNER,
    REASON_EMPTY,
    REASON_EXPLICIT_OVERRIDE,
    REASON_LOW_CONFIDENCE,
    REASON_REFUSED_LIVE_DB,
    REASON_TIE,
    SNIFF_BYTES,
    SUPPORTED_FORMATS,
    VALID_FORMAT_OPTIONS,
    DetectionResult,
    detect_format,
    resolve_format,
    to_source_block,
)
from sesslint.adapters.openai_agents import SQLITE_MAGIC
from sesslint.cli import main
from sesslint.codes import SL001, SL302, Repairability, Severity

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "detect"


def test_threshold_constants_pinned() -> None:
    """Assert threshold, margin, and sniff limits are strictly pinned.

    Any modification to these constants requires an explicit design change.
    """
    assert CONFIDENCE_MIN == 0.55, "CONFIDENCE_MIN must be 0.55 per spec"
    assert MARGIN_MIN == 0.15, "MARGIN_MIN must be 0.15 per spec"
    assert SNIFF_BYTES == 65536, "SNIFF_BYTES must be 64KB (65536) per spec"
    assert EPSILON == 1e-9, "EPSILON must be 1e-9 for floating-point tie checks"
    assert FORMAT_CLAUDE_CODE == "claude-code-jsonl"
    assert FORMAT_OPENAI_AGENTS == "openai-agents"
    assert FORMAT_CANONICAL == "canonical"
    assert FORMAT_AUTO == "auto"
    assert SUPPORTED_FORMATS == frozenset(
        {
            "claude-code-jsonl",
            "openai-agents",
            "canonical",
        }
    )
    assert VALID_FORMAT_OPTIONS == SUPPORTED_FORMATS | {"auto"}


def test_each_vendor_clear_winner() -> None:
    """3 vendor samples -> correct format, reason clear-winner, confidences recorded."""
    claude_fixture = FIXTURES_DIR / "claude_sample.jsonl"
    openai_fixture = FIXTURES_DIR / "openai_sample.json"
    canonical_fixture = FIXTURES_DIR / "canonical_sample.json"

    assert claude_fixture.is_file(), f"Missing fixture {claude_fixture}"
    assert openai_fixture.is_file(), f"Missing fixture {openai_fixture}"
    assert canonical_fixture.is_file(), f"Missing fixture {canonical_fixture}"

    # Claude Code sample
    res_claude = detect_format(claude_fixture)
    assert res_claude.format == FORMAT_CLAUDE_CODE
    assert res_claude.reason == REASON_CLEAR_WINNER
    assert res_claude.confidences[FORMAT_CLAUDE_CODE] >= CONFIDENCE_MIN
    margin_claude = res_claude.confidences[FORMAT_CLAUDE_CODE] - max(
        res_claude.confidences[FORMAT_OPENAI_AGENTS],
        res_claude.confidences[FORMAT_CANONICAL],
    )
    assert margin_claude >= MARGIN_MIN

    # OpenAI Agents sample
    res_openai = detect_format(openai_fixture)
    assert res_openai.format == FORMAT_OPENAI_AGENTS
    assert res_openai.reason == REASON_CLEAR_WINNER
    assert res_openai.confidences[FORMAT_OPENAI_AGENTS] >= CONFIDENCE_MIN
    margin_openai = res_openai.confidences[FORMAT_OPENAI_AGENTS] - max(
        res_openai.confidences[FORMAT_CLAUDE_CODE],
        res_openai.confidences[FORMAT_CANONICAL],
    )
    assert margin_openai >= MARGIN_MIN

    # Canonical sample
    res_canonical = detect_format(canonical_fixture)
    assert res_canonical.format == FORMAT_CANONICAL
    assert res_canonical.reason == REASON_CLEAR_WINNER
    assert res_canonical.confidences[FORMAT_CANONICAL] >= CONFIDENCE_MIN
    margin_canonical = res_canonical.confidences[FORMAT_CANONICAL] - max(
        res_canonical.confidences[FORMAT_CLAUDE_CODE],
        res_canonical.confidences[FORMAT_OPENAI_AGENTS],
    )
    assert margin_canonical >= MARGIN_MIN


def test_ambiguous_fail_closed() -> None:
    """Ambiguous fixture -> format None, exactly 1 ambiguous_format finding (error/manual).

    Asserts via spies that no load_* functions are invoked on ambiguity.
    """
    ambiguous_fixture = FIXTURES_DIR / "ambiguous.json"
    assert ambiguous_fixture.is_file(), f"Missing fixture {ambiguous_fixture}"

    # Detect format directly
    res = detect_format(ambiguous_fixture)
    assert res.format is None
    assert res.reason == REASON_TIE
    # Verify tie condition: top two confidences fail margin
    sorted_scores = sorted(res.confidences.values(), reverse=True)
    assert sorted_scores[0] >= CONFIDENCE_MIN
    assert (sorted_scores[0] - sorted_scores[1]) < MARGIN_MIN

    # Resolve format via resolve_format with spy on loaders
    with (
        patch("sesslint.adapters.canonical.load_canonical") as mock_load_canon,
        patch("sesslint.adapters.claude_code.load_claude_code") as mock_load_claude,
        patch("sesslint.adapters.openai_agents.load_openai_agents") as mock_load_openai,
    ):
        resolved_fmt, detection_res, findings = resolve_format(None, ambiguous_fixture)

        # No loaders should have been invoked
        mock_load_canon.assert_not_called()
        mock_load_claude.assert_not_called()
        mock_load_openai.assert_not_called()

        assert resolved_fmt is None
        assert detection_res is not None
        assert detection_res.reason == REASON_TIE
        assert len(findings) == 1

        finding = findings[0]
        assert finding.code == SL302
        assert finding.severity == Severity.ERROR
        assert finding.repairability == Repairability.MANUAL
        assert "[detail: ambiguous_format]" in finding.message
        assert finding.evidence is not None
        assert finding.evidence["reason"] == REASON_TIE
        assert finding.evidence["confidence_min"] == CONFIDENCE_MIN
        assert finding.evidence["margin_min"] == MARGIN_MIN
        assert "confidences" in finding.evidence


def test_low_confidence_fail_closed(tmp_path: Path) -> None:
    """Random-text / unstructured file -> None + SL302 finding (not best-guess parse)."""
    random_file = tmp_path / "random.txt"
    random_file.write_text("random unstructured log content line 1\nline 2", encoding="utf-8")

    res = detect_format(random_file)
    assert res.format is None
    assert res.reason == REASON_LOW_CONFIDENCE
    assert max(res.confidences.values()) < CONFIDENCE_MIN

    resolved_fmt, detection_res, findings = resolve_format("auto", random_file)
    assert resolved_fmt is None
    assert detection_res is not None
    assert detection_res.reason == REASON_LOW_CONFIDENCE
    assert len(findings) == 1

    finding = findings[0]
    assert finding.code == SL302
    assert finding.severity == Severity.ERROR
    assert finding.repairability == Repairability.MANUAL
    assert "[detail: ambiguous_format]" in finding.message
    assert finding.evidence is not None
    assert finding.evidence["reason"] == REASON_LOW_CONFIDENCE


def test_explicit_override_wins() -> None:
    """Ambiguous file + explicit="canonical" -> resolves canonical, zero detection findings."""
    ambiguous_fixture = FIXTURES_DIR / "ambiguous.json"
    resolved_fmt, detection_res, findings = resolve_format(FORMAT_CANONICAL, ambiguous_fixture)

    assert resolved_fmt == FORMAT_CANONICAL
    assert len(findings) == 0
    assert detection_res is not None
    assert detection_res.format == FORMAT_CANONICAL
    assert detection_res.reason == REASON_EXPLICIT_OVERRIDE


def test_explicit_invalid_exits(tmp_path: Path) -> None:
    """Invalid explicit format string -> ValueError."""
    dummy_file = tmp_path / "dummy.json"
    dummy_file.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="Unknown format 'bogus'"):
        resolve_format("bogus", dummy_file)

    with pytest.raises(ValueError, match="Unknown format 'yaml'"):
        resolve_format("yaml", dummy_file)


def test_empty_refused() -> None:
    """Empty 0-byte file -> None + empty-input finding (SL001 error/manual)."""
    empty_fixture = FIXTURES_DIR / "empty.jsonl"
    assert empty_fixture.is_file(), f"Missing fixture {empty_fixture}"
    assert empty_fixture.stat().st_size == 0

    res = detect_format(empty_fixture)
    assert res.format is None
    assert res.reason == REASON_EMPTY
    assert all(c == 0.0 for c in res.confidences.values())

    resolved_fmt, detection_res, findings = resolve_format(None, empty_fixture)
    assert resolved_fmt is None
    assert detection_res is not None
    assert detection_res.reason == REASON_EMPTY
    assert len(findings) == 1

    finding = findings[0]
    assert finding.code == SL001
    assert finding.severity == Severity.ERROR
    assert finding.repairability == Repairability.MANUAL
    assert "[detail: EMPTY]" in finding.message
    assert finding.evidence == {"reason": "empty_input"}


def test_live_db_short_circuit(tmp_path: Path) -> None:
    """SQLite-magic file -> refusal reason regardless of scores (delegates to TASK-009 finding)."""
    sqlite_file = tmp_path / "session.sqlite"
    sqlite_file.write_bytes(SQLITE_MAGIC + b"\x00" * 84)

    res = detect_format(sqlite_file)
    assert res.format is None
    assert res.reason == REASON_REFUSED_LIVE_DB
    assert all(c == 0.0 for c in res.confidences.values())

    resolved_fmt, detection_res, findings = resolve_format(None, sqlite_file)
    assert resolved_fmt is None
    assert detection_res is not None
    assert detection_res.reason == REASON_REFUSED_LIVE_DB
    assert len(findings) == 1

    finding = findings[0]
    assert finding.code == SL001
    assert finding.severity == Severity.FATAL
    assert finding.repairability == Repairability.UNSUPPORTED
    assert "[detail: refused_live_db]" in finding.message
    assert finding.evidence == {"reason": "refused_live_db"}


def test_detection_deterministic() -> None:
    """Sniff twice -> identical result objects."""
    canonical_fixture = FIXTURES_DIR / "canonical_sample.json"
    res1 = detect_format(canonical_fixture)
    res2 = detect_format(canonical_fixture)

    assert res1 == res2
    assert res1.format == res2.format
    assert res1.confidences == res2.confidences
    assert res1.reason == res2.reason

    ambiguous_fixture = FIXTURES_DIR / "ambiguous.json"
    amb1 = detect_format(ambiguous_fixture)
    amb2 = detect_format(ambiguous_fixture)

    assert amb1 == amb2


def test_confidence_boundary_exact_055(tmp_path: Path) -> None:
    """File crafted or mocked to score 0.55 exactly passes per >= rule."""
    test_file = tmp_path / "boundary.json"
    test_file.write_text("{}", encoding="utf-8")

    # Score exactly 0.55, runner up 0.0 -> clears threshold (0.55 >= 0.55) and margin (0.55 >= 0.15)
    with (
        patch("sesslint.adapters.detect.detect_canonical", return_value=0.55),
        patch("sesslint.adapters.detect.detect_claude_code", return_value=0.0),
        patch("sesslint.adapters.detect.detect_openai_agents", return_value=0.0),
    ):
        res = detect_format(test_file)
        assert res.format == FORMAT_CANONICAL
        assert res.reason == REASON_CLEAR_WINNER
        assert res.confidences[FORMAT_CANONICAL] == 0.55

    # Score 0.549, runner up 0.0 -> fails threshold (0.549 < 0.55) -> low-confidence
    with (
        patch("sesslint.adapters.detect.detect_canonical", return_value=0.549),
        patch("sesslint.adapters.detect.detect_claude_code", return_value=0.0),
        patch("sesslint.adapters.detect.detect_openai_agents", return_value=0.0),
    ):
        res_fail = detect_format(test_file)
        assert res_fail.format is None
        assert res_fail.reason == REASON_LOW_CONFIDENCE


def test_margin_boundary_exact_015(tmp_path: Path) -> None:
    """Winner score 0.70, second score 0.55 (diff = 0.15 >= MARGIN_MIN) clears margin."""
    test_file = tmp_path / "margin_test.json"
    test_file.write_text("{}", encoding="utf-8")

    # diff = 0.15 -> clears margin
    with (
        patch("sesslint.adapters.detect.detect_canonical", return_value=0.70),
        patch("sesslint.adapters.detect.detect_claude_code", return_value=0.55),
        patch("sesslint.adapters.detect.detect_openai_agents", return_value=0.0),
    ):
        res = detect_format(test_file)
        assert res.format == FORMAT_CANONICAL
        assert res.reason == REASON_CLEAR_WINNER

    # diff = 0.149 < 0.15 -> fails margin -> tie
    with (
        patch("sesslint.adapters.detect.detect_canonical", return_value=0.70),
        patch("sesslint.adapters.detect.detect_claude_code", return_value=0.551),
        patch("sesslint.adapters.detect.detect_openai_agents", return_value=0.0),
    ):
        res_tie = detect_format(test_file)
        assert res_tie.format is None
        assert res_tie.reason == REASON_TIE


def test_epsilon_tie(tmp_path: Path) -> None:
    """Scores that differ by less than EPSILON (1e-9) are treated as ties."""
    test_file = tmp_path / "epsilon.json"
    test_file.write_text("{}", encoding="utf-8")

    with (
        patch("sesslint.adapters.detect.detect_canonical", return_value=0.8000000001),
        patch("sesslint.adapters.detect.detect_claude_code", return_value=0.80),
        patch("sesslint.adapters.detect.detect_openai_agents", return_value=0.0),
    ):
        res = detect_format(test_file)
        assert res.format is None
        assert res.reason == REASON_TIE


def test_lying_extension(tmp_path: Path) -> None:
    """Canonical content with .jsonl extension -> content sniffing wins if margin clears."""
    lying_file = tmp_path / "session.jsonl"
    # Write canonical content into a .jsonl file
    canonical_fixture = FIXTURES_DIR / "canonical_sample.json"
    lying_file.write_bytes(canonical_fixture.read_bytes())

    res = detect_format(lying_file)
    # Content sniffing wins: canonical scores 1.0, claude scores 0.0 or 0.2
    assert res.format == FORMAT_CANONICAL
    assert res.reason == REASON_CLEAR_WINNER


def test_whitespace_only_refused(tmp_path: Path) -> None:
    """Whitespace-only file is treated as empty refusal."""
    ws_file = tmp_path / "whitespace.json"
    ws_file.write_text("   \n\t  \r\n   ", encoding="utf-8")

    res = detect_format(ws_file)
    assert res.format is None
    assert res.reason == REASON_EMPTY

    _fmt, _res, findings = resolve_format(None, ws_file)
    assert len(findings) == 1
    assert findings[0].code == SL001
    assert "[detail: EMPTY]" in findings[0].message


def test_bom_only_refused(tmp_path: Path) -> None:
    """UTF-8 BOM only file is treated as empty refusal."""
    bom_file = tmp_path / "bom_only.json"
    bom_file.write_bytes(b"\xef\xbb\xbf")

    res = detect_format(bom_file)
    assert res.format is None
    assert res.reason == REASON_EMPTY

    _fmt, _res, findings = resolve_format(None, bom_file)
    assert len(findings) == 1
    assert findings[0].code == SL001
    assert "[detail: EMPTY]" in findings[0].message


def test_bom_and_whitespace_refused(tmp_path: Path) -> None:
    """UTF-8 BOM followed only by whitespace is treated as empty refusal."""
    bom_ws_file = tmp_path / "bom_ws.json"
    bom_ws_file.write_bytes(b"\xef\xbb\xbf   \r\n\t")

    res = detect_format(bom_ws_file)
    assert res.format is None
    assert res.reason == REASON_EMPTY


def test_giant_first_line_bounded(tmp_path: Path) -> None:
    """Oversized file (e.g. 1MB line) is capped at SNIFF_BYTES without OOM."""
    large_file = tmp_path / "giant_line.jsonl"
    # First line contains Claude signal then 200KB of padding
    line = '{"type":"user_message","sessionId":"sess-large"}' + (" " * 200_000) + "\n"
    large_file.write_bytes(line.encode("utf-8"))

    res = detect_format(large_file)
    # Head bytes contain the Claude signal, sniffing finishes without error
    assert res.format == FORMAT_CLAUDE_CODE
    assert res.reason == REASON_CLEAR_WINNER


def test_to_source_block_helper() -> None:
    """to_source_block emits structured audit block with rounded scores."""
    result = DetectionResult(
        format=FORMAT_CANONICAL,
        confidences={
            FORMAT_CLAUDE_CODE: 0.123456,
            FORMAT_OPENAI_AGENTS: 0.0,
            FORMAT_CANONICAL: 1.0,
        },
        reason=REASON_CLEAR_WINNER,
    )

    block = to_source_block(result, requested="auto")
    assert block == {
        "requested": "auto",
        "resolved": FORMAT_CANONICAL,
        "confidences": {
            FORMAT_CLAUDE_CODE: 0.123,
            FORMAT_OPENAI_AGENTS: 0.0,
            FORMAT_CANONICAL: 1.0,
        },
        "reason": REASON_CLEAR_WINNER,
    }

    # Method on DetectionResult
    block2 = result.to_source_block(requested="canonical")
    assert block2["requested"] == "canonical"
    assert block2["resolved"] == FORMAT_CANONICAL

    # None result
    block_none = to_source_block(None, requested="auto")
    assert block_none["requested"] == "auto"
    assert block_none["resolved"] is None
    assert block_none["confidences"] == {}


def test_detect_format_nonexistent_raises() -> None:
    """Nonexistent file path raises FileNotFoundError to propagate to I/O path."""
    with pytest.raises(FileNotFoundError):
        detect_format(Path("nonexistent_session_file_12345.json"))


def test_detect_format_directory_raises(tmp_path: Path) -> None:
    """Directory path raises IsADirectoryError."""
    with pytest.raises(IsADirectoryError):
        detect_format(tmp_path)


def test_cli_smoke_invalid_format(capsys: pytest.CaptureFixture[str]) -> None:
    """CLI with invalid --format option exits with code 2."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--format", "bogus"])
    assert exc_info.value.code == 2


def test_cli_smoke_ambiguous_auto(capsys: pytest.CaptureFixture[str]) -> None:
    """CLI check on ambiguous file exits non-zero with finding."""
    ambiguous_fixture = FIXTURES_DIR / "ambiguous.json"
    exit_code = main(["check", str(ambiguous_fixture)])
    assert exit_code == 1

    captured = capsys.readouterr()
    assert "SL302" in captured.err
    assert "ambiguous_format" in captured.err


def test_cli_smoke_explicit_override_canonical(capsys: pytest.CaptureFixture[str]) -> None:
    """CLI check on canonical sample succeeds with exit code 0."""
    canonical_fixture = FIXTURES_DIR / "canonical_sample.json"
    exit_code = main(
        [
            "check",
            "--format",
            "canonical",
            str(canonical_fixture),
        ]
    )
    assert exit_code == 0

    captured = capsys.readouterr()
    assert "Valid session" in captured.out or "Valid canonical session" in captured.out


def test_cli_smoke_explicit_override_before_check_honored(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """CLI with --format BEFORE sub-command is honored and not clobbered by subparser defaults."""
    ambiguous_fixture = FIXTURES_DIR / "ambiguous.json"
    # ambiguous.json auto-detects as tie (exit 1), but with explicit openai-agents
    # it resolves cleanly
    exit_code = main(
        [
            "--format",
            "openai-agents",
            "check",
            str(ambiguous_fixture),
        ]
    )
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Valid OpenAI Agents session" in captured.out


def test_cli_smoke_explicit_override_after_path_honored(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """CLI with --format AFTER path argument is honored."""
    ambiguous_fixture = FIXTURES_DIR / "ambiguous.json"
    exit_code = main(
        [
            "check",
            str(ambiguous_fixture),
            "--format",
            "openai-agents",
        ]
    )
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Valid OpenAI Agents session" in captured.out


def test_sniff_boundary_partial_utf8_sliced(tmp_path: Path) -> None:
    """Multi-megabyte file sliced at exactly SNIFF_BYTES mid-multibyte UTF-8 doesn't crash."""
    test_file = tmp_path / "sliced_utf8.jsonl"
    head = b'{"id":"msg_01","type":"user_message"}\n'
    # Pad so byte 65535 is ascii space and byte 65536 is \xe2 (start of 3-byte utf8 sequence)
    pad = b" " * (SNIFF_BYTES - len(head) - 1)
    boundary_bytes = head + pad + b"\xe2"
    assert len(boundary_bytes) == SNIFF_BYTES

    # Write boundary bytes followed by the rest of the multi-byte sequence and extra padding
    test_file.write_bytes(boundary_bytes + (b"\x80\x99 extra content\n" * 5000))
    assert test_file.stat().st_size > 100_000

    res = detect_format(test_file)
    assert res.format == FORMAT_CLAUDE_CODE
    assert res.reason == REASON_CLEAR_WINNER


def test_defensive_detector_nan_and_out_of_bounds(tmp_path: Path) -> None:
    """Detectors returning NaN or out-of-bounds scores are defensively clamped and fail closed."""
    test_file = tmp_path / "dummy.json"
    test_file.write_text("{}", encoding="utf-8")

    # NaN returned by a detector must not pass threshold or margin
    with (
        patch("sesslint.adapters.detect.detect_canonical", return_value=float("nan")),
        patch("sesslint.adapters.detect.detect_claude_code", return_value=0.0),
        patch("sesslint.adapters.detect.detect_openai_agents", return_value=0.0),
    ):
        res = detect_format(test_file)
        assert res.format is None
        assert res.reason == REASON_LOW_CONFIDENCE
        assert res.confidences[FORMAT_CANONICAL] == 0.0

    # Negative score clamped to 0.0
    with (
        patch("sesslint.adapters.detect.detect_canonical", return_value=-0.5),
        patch("sesslint.adapters.detect.detect_claude_code", return_value=0.0),
        patch("sesslint.adapters.detect.detect_openai_agents", return_value=0.0),
    ):
        res = detect_format(test_file)
        assert res.confidences[FORMAT_CANONICAL] == 0.0
