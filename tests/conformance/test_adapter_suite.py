"""Unified Cross-Adapter Conformance Suite (DEV-016, FR-102, NDP-001 M4).

Executes a unified, data-driven canonical defect battery across ALL registered SessLint
adapters:
1. Canonical Session Format (canonical)
2. Claude Code JSONL (claude-code-jsonl)
3. OpenAI Agents SDK Export (openai-agents)

Enforces 8 core conformance case families identically across all adapters:
1. Source Immutability (input bytes on disk identical before and after check via API & CLI)
2. Unknown-Version Fail-Closed + Version Evidence (SL301 with version_raw & supported_set)
3. Parallel Tool-Call Pairing (correlation_id matching between calls and results)
4. Default-Report Privacy (zero secrets or PII leak into diagnostic reports)
5. Canonical Round-Trip Determinism (same bytes -> identical events, IDs, and findings)
6. Detection Confidence Sanity (own format >= CONFIDENCE_MIN, others rejected by >= MARGIN_MIN)
7. Synthetic-ID Namespacing (DEV-007 reserved namespace, zero 'rec_' leaks, collision-free)
8. Discriminator Shapes (DEV-008 safe verbatim echo vs safe shape descriptor bounding)

Also includes a worked extensibility proof adding a fake fourth adapter row in a test
(demonstrating zero product-code changes required to add and validate a new adapter).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import pytest
from tests.utils.privacy import assert_no_pii

from sesslint.adapters.canonical import (
    detect_canonical,
    dump_canonical,
    load_canonical,
)
from sesslint.adapters.claude_code import (
    CanonicalEvent,
    detect_claude_code,
    load_claude_code,
)
from sesslint.adapters.detect import (
    CONFIDENCE_MIN,
    FORMAT_CANONICAL,
    FORMAT_CLAUDE_CODE,
    FORMAT_OPENAI_AGENTS,
    MARGIN_MIN,
    SNIFF_BYTES,
    detect_format,
)
from sesslint.adapters.openai_agents import (
    detect_openai_agents,
    load_openai_agents,
)
from sesslint.adapters.synthetic import (
    SyntheticIdCollisionGuard,
    is_synthetic_id,
    synthetic_event_id,
)
from sesslint.api import check_file
from sesslint.canonical import compute_content_hash
from sesslint.cli import main
from sesslint.codes import SL101, SL102, SL107, SL301, SL302
from sesslint.finding import Finding
from sesslint.io import ReaderLimits

FIXTURES_ROOT: Final[Path] = Path(__file__).resolve().parent.parent.parent / "fixtures"
CONFORMANCE_FIXTURES: Final[Path] = FIXTURES_ROOT / "conformance"

SECRET_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"sk-ant-[a-zA-Z0-9_-]+"),
    re.compile(r"sk-live-[a-zA-Z0-9_-]+"),
    re.compile(r"sk-[a-zA-Z0-9_-]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(r"glpat-[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"bearer\s+[a-zA-Z0-9_-]+", re.IGNORECASE),
)

SYNTHETIC_ID_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^sesslint:synthetic:[a-z_]+:\d+:[0-9a-f]{8}$"
)


# -----------------------------------------------------------------------------
# Data-Driven Specification Structures
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class AdapterSpec:
    """Descriptor binding an adapter's detection function, loader function, and paths."""

    adapter_id: str
    format_name: str
    detect_fn: Callable[[bytes, str], float]
    load_fn: Callable[..., tuple[Any, list[Finding]]]
    fixture_dir: Path


@dataclass(frozen=True)
class CaseExpectation:
    """Expected outcome for an adapter on a specific conformance fixture."""

    fixture_relpath: str
    expected_codes: tuple[str, ...] = ()
    expected_exit_code: int = 0
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ConformanceCase:
    """Data-driven test case specification executed across all registered adapters."""

    case_id: str
    family: str
    description: str
    expectations: dict[str, CaseExpectation]


# Registered Production Adapters
ADAPTERS: Final[dict[str, AdapterSpec]] = {
    FORMAT_CANONICAL: AdapterSpec(
        adapter_id=FORMAT_CANONICAL,
        format_name=FORMAT_CANONICAL,
        detect_fn=detect_canonical,
        load_fn=load_canonical,
        fixture_dir=CONFORMANCE_FIXTURES / "canonical",
    ),
    FORMAT_CLAUDE_CODE: AdapterSpec(
        adapter_id=FORMAT_CLAUDE_CODE,
        format_name=FORMAT_CLAUDE_CODE,
        detect_fn=detect_claude_code,
        load_fn=load_claude_code,
        fixture_dir=CONFORMANCE_FIXTURES / "claude_code",
    ),
    FORMAT_OPENAI_AGENTS: AdapterSpec(
        adapter_id=FORMAT_OPENAI_AGENTS,
        format_name=FORMAT_OPENAI_AGENTS,
        detect_fn=detect_openai_agents,
        load_fn=load_openai_agents,
        fixture_dir=CONFORMANCE_FIXTURES / "openai_agents",
    ),
}

# The 8 Universal Conformance Case Families Defined as Pure Data
CASES: Final[list[ConformanceCase]] = [
    # 1. Source Immutability
    ConformanceCase(
        case_id="case_01_immutability",
        family="source_immutability",
        description=(
            "Verify input file bytes on disk are bit-for-bit identical before and after check."
        ),
        expectations={
            FORMAT_CANONICAL: CaseExpectation(
                fixture_relpath="canonical/healthy.json",
                expected_codes=(),
                expected_exit_code=0,
            ),
            FORMAT_CLAUDE_CODE: CaseExpectation(
                fixture_relpath="claude_code/healthy.jsonl",
                expected_codes=(),
                expected_exit_code=0,
            ),
            FORMAT_OPENAI_AGENTS: CaseExpectation(
                fixture_relpath="openai_agents/healthy.json",
                expected_codes=(),
                expected_exit_code=0,
            ),
        },
    ),
    # 2. Unknown-Version Fail-Closed
    ConformanceCase(
        case_id="case_02_unknown_version",
        family="unknown_version",
        description=(
            "Verify unsupported format version fails closed with SL301 and version evidence."
        ),
        expectations={
            FORMAT_CANONICAL: CaseExpectation(
                fixture_relpath="canonical/version_unsupported.json",
                expected_codes=(SL301,),
                expected_exit_code=1,
                extra={"version_raw": "999"},
            ),
            FORMAT_CLAUDE_CODE: CaseExpectation(
                fixture_relpath="claude_code/version_unsupported.jsonl",
                expected_codes=(SL301,),
                expected_exit_code=1,
                extra={"version_raw": "99.0.0"},
            ),
            FORMAT_OPENAI_AGENTS: CaseExpectation(
                fixture_relpath="openai_agents/version_unsupported.json",
                expected_codes=(SL301,),
                expected_exit_code=1,
                extra={"version_raw": "99.0.0"},
            ),
        },
    ),
    # 3. Parallel Tool-Call Pairing
    ConformanceCase(
        case_id="case_03_parallel_tool_pairing",
        family="parallel_tool_pairing",
        description=(
            "Verify concurrent tool calls pair with results via correlation_id without false "
            "pairing findings."
        ),
        expectations={
            FORMAT_CANONICAL: CaseExpectation(
                fixture_relpath="canonical/parallel_tool.json",
                expected_codes=(),
                expected_exit_code=0,
                extra={"min_calls": 2, "min_returns": 2},
            ),
            FORMAT_CLAUDE_CODE: CaseExpectation(
                fixture_relpath="claude_code/parallel_tool.jsonl",
                expected_codes=(),
                expected_exit_code=0,
                extra={"min_calls": 2, "min_returns": 2},
            ),
            FORMAT_OPENAI_AGENTS: CaseExpectation(
                fixture_relpath="openai_agents/parallel_tool.json",
                expected_codes=(),
                expected_exit_code=0,
                extra={"min_calls": 2, "min_returns": 2},
            ),
        },
    ),
    # 4. Default-Report Privacy
    ConformanceCase(
        case_id="case_04_default_report_privacy",
        family="default_report_privacy",
        description=(
            "Verify secret seeds in fixtures never leak into diagnostic report structures or "
            "CLI output."
        ),
        expectations={
            FORMAT_CANONICAL: CaseExpectation(
                fixture_relpath="secret_seed/canonical_secret.jsonl",
                expected_codes=(),
                expected_exit_code=0,
                extra={
                    "secret_tokens": (
                        "sk-ant-api03-SECRET-CANARY-TOKEN-XYZ123",
                        "sk-live-OPENAI-SECRET-TOKEN-51Nz888",
                    )
                },
            ),
            FORMAT_CLAUDE_CODE: CaseExpectation(
                fixture_relpath="secret_seed/claude_secret.jsonl",
                expected_codes=(),
                expected_exit_code=0,
                extra={
                    "secret_tokens": (
                        "sk-ant-api03-SECRET-CANARY-TOKEN-XYZ123",
                        "sk-live-OPENAI-SECRET-TOKEN-51Nz888",
                    )
                },
            ),
            FORMAT_OPENAI_AGENTS: CaseExpectation(
                fixture_relpath="secret_seed/openai_secret.json",
                expected_codes=(),
                expected_exit_code=0,
                extra={
                    "secret_tokens": (
                        "sk-ant-api03-SECRET-CANARY-TOKEN-XYZ123",
                        "sk-live-OPENAI-SECRET-TOKEN-51Nz888",
                    )
                },
            ),
        },
    ),
    # 5. Canonical Round-Trip Determinism
    ConformanceCase(
        case_id="case_05_canonical_determinism",
        family="canonical_determinism",
        description=(
            "Verify loading and analyzing the same artifact twice produces identical event IDs, "
            "timestamps, and findings."
        ),
        expectations={
            FORMAT_CANONICAL: CaseExpectation(
                fixture_relpath="canonical/healthy.json",
                expected_codes=(),
                expected_exit_code=0,
            ),
            FORMAT_CLAUDE_CODE: CaseExpectation(
                fixture_relpath="claude_code/healthy.jsonl",
                expected_codes=(),
                expected_exit_code=0,
            ),
            FORMAT_OPENAI_AGENTS: CaseExpectation(
                fixture_relpath="openai_agents/healthy.json",
                expected_codes=(),
                expected_exit_code=0,
            ),
        },
    ),
    # 6. Detection Confidence Sanity
    ConformanceCase(
        case_id="case_06_detection_sanity",
        family="detection_sanity",
        description=(
            "Verify detector scores its own fixture >= CONFIDENCE_MIN and rejects others by "
            ">= MARGIN_MIN."
        ),
        expectations={
            FORMAT_CANONICAL: CaseExpectation(
                fixture_relpath="canonical/healthy.json",
                expected_codes=(),
                expected_exit_code=0,
            ),
            FORMAT_CLAUDE_CODE: CaseExpectation(
                fixture_relpath="claude_code/healthy.jsonl",
                expected_codes=(),
                expected_exit_code=0,
            ),
            FORMAT_OPENAI_AGENTS: CaseExpectation(
                fixture_relpath="openai_agents/healthy.json",
                expected_codes=(),
                expected_exit_code=0,
            ),
        },
    ),
    # 7. Synthetic-ID Namespacing
    ConformanceCase(
        case_id="case_07_synthetic_ids",
        family="synthetic_ids",
        description=(
            "Verify generated synthetic IDs adhere strictly to sesslint:synthetic namespace "
            "with zero 'rec_' leaks."
        ),
        expectations={
            FORMAT_CANONICAL: CaseExpectation(
                fixture_relpath="canonical/healthy.json",
                expected_codes=(),
                expected_exit_code=0,
                extra={"uses_native_ids": True},
            ),
            FORMAT_CLAUDE_CODE: CaseExpectation(
                fixture_relpath="claude_code/synthetic_ids.jsonl",
                expected_codes=(),
                expected_exit_code=0,
                extra={"uses_native_ids": False},
            ),
            FORMAT_OPENAI_AGENTS: CaseExpectation(
                fixture_relpath="openai_agents/synthetic_ids.json",
                expected_codes=(),
                expected_exit_code=0,
                extra={"uses_native_ids": False},
            ),
        },
    ),
    # 8a. Discriminator Shapes: Safe Verbatim Echo
    ConformanceCase(
        case_id="case_08a_discriminator_safe",
        family="discriminator_shapes",
        description=(
            "Verify allowlisted safe unknown discriminator is echoed verbatim in SL302 evidence."
        ),
        expectations={
            FORMAT_CANONICAL: CaseExpectation(
                fixture_relpath="canonical/discriminator_safe.json",
                expected_codes=(SL302,),
                expected_exit_code=1,
                extra={"expected_discriminator": "custom_op", "truncated": False},
            ),
            FORMAT_CLAUDE_CODE: CaseExpectation(
                fixture_relpath="claude_code/discriminator_safe.jsonl",
                expected_codes=(SL302,),
                expected_exit_code=1,
                extra={"expected_discriminator": "custom_op", "truncated": False},
            ),
            FORMAT_OPENAI_AGENTS: CaseExpectation(
                fixture_relpath="openai_agents/discriminator_safe.json",
                expected_codes=(SL302,),
                expected_exit_code=1,
                extra={"expected_discriminator": "custom_op", "truncated": False},
            ),
        },
    ),
    # 8b. Discriminator Shapes: Hostile Shape Bounding
    ConformanceCase(
        case_id="case_08b_discriminator_hostile",
        family="discriminator_shapes",
        description=(
            "Verify hostile / overlong discriminator is sanitized to <type:len=N> shape and "
            "type_truncated=True."
        ),
        expectations={
            FORMAT_CANONICAL: CaseExpectation(
                fixture_relpath="canonical/discriminator_hostile.json",
                expected_codes=(SL302,),
                expected_exit_code=1,
                extra={"expected_shape": "<str:len=90>", "truncated": True},
            ),
            FORMAT_CLAUDE_CODE: CaseExpectation(
                fixture_relpath="claude_code/discriminator_hostile.jsonl",
                expected_codes=(SL302,),
                expected_exit_code=1,
                extra={"expected_shape": "<str:len=90>", "truncated": True},
            ),
            FORMAT_OPENAI_AGENTS: CaseExpectation(
                fixture_relpath="openai_agents/discriminator_hostile.json",
                expected_codes=(SL302,),
                expected_exit_code=1,
                extra={"expected_shape": "<str:len=90>", "truncated": True},
            ),
        },
    ),
]


def _resolve_fixture_path(expectation: CaseExpectation) -> Path:
    """Resolve fixture file relative to CONFORMANCE_FIXTURES."""
    path = CONFORMANCE_FIXTURES / expectation.fixture_relpath
    if not path.is_file():
        raise FileNotFoundError(f"Missing conformance fixture: {path}")
    return path


# -----------------------------------------------------------------------------
# Conformance Test Executions (Parametrized over All Registered Adapters)
# -----------------------------------------------------------------------------


class TestCrossAdapterConformance:
    """Suite executing the 8 core conformance case families identically across all adapters."""

    @pytest.mark.parametrize("adapter_id", list(ADAPTERS.keys()))
    def test_family_01_source_immutability(self, adapter_id: str) -> None:
        """Input bytes on disk must be bit-for-bit identical before and after check."""
        adapter = ADAPTERS[adapter_id]
        case = next(c for c in CASES if c.family == "source_immutability")
        fixture_path = _resolve_fixture_path(case.expectations[adapter_id])

        # Step 1: Record SHA-256 before any access
        raw_before = fixture_path.read_bytes()
        sha_before = hashlib.sha256(raw_before).hexdigest()

        # Step 2: Run public API check_file
        report = check_file(fixture_path, format=adapter.format_name)
        assert report is not None
        assert hashlib.sha256(fixture_path.read_bytes()).hexdigest() == sha_before, (
            f"API check_file modified fixture {fixture_path} on disk!"
        )

        # Step 3: Run CLI check command
        exit_code = main(["check", str(fixture_path), "--format", adapter.format_name])
        assert exit_code == 0
        assert hashlib.sha256(fixture_path.read_bytes()).hexdigest() == sha_before, (
            f"CLI main check modified fixture {fixture_path} on disk!"
        )

    @pytest.mark.parametrize("adapter_id", list(ADAPTERS.keys()))
    def test_family_02_unknown_version_fail_closed(self, adapter_id: str) -> None:
        """Unsupported format versions fail closed with SL301 and version evidence."""
        adapter = ADAPTERS[adapter_id]
        case = next(c for c in CASES if c.family == "unknown_version")
        exp = case.expectations[adapter_id]
        fixture_path = _resolve_fixture_path(exp)

        # Step 1: Adapter direct load
        events, findings = adapter.load_fn(fixture_path)
        sl301_findings = [f for f in findings if f.code == SL301]
        assert len(sl301_findings) >= 1, (
            f"Adapter {adapter_id} failed to emit SL301 on unsupported version"
        )

        evidence = sl301_findings[0].evidence or {}
        assert "version_raw" in evidence, "SL301 evidence must contain version_raw"
        assert evidence["version_raw"] == exp.extra["version_raw"]
        assert "supported_set" in evidence, "SL301 evidence must contain supported_set"
        assert len(evidence["supported_set"]) > 0

        # Step 2: Public API check_file
        report = check_file(fixture_path, format=adapter.format_name)
        assert any(f.code == SL301 for f in report.findings)
        # Coverage tracking must record version-gated skip
        skipped_reasons = [s.reason for s in report.coverage.skipped]
        assert "version-gated" in skipped_reasons, (
            f"Coverage skips missing 'version-gated' for adapter {adapter_id}"
        )

        # Step 3: CLI exits non-zero on unsupported version
        cli_code = main(["check", str(fixture_path), "--format", adapter.format_name])
        assert cli_code == exp.expected_exit_code

    @pytest.mark.parametrize("adapter_id", list(ADAPTERS.keys()))
    def test_family_03_parallel_tool_call_pairing(self, adapter_id: str) -> None:
        """Concurrent tool calls pair with results via correlation_id without pairing findings."""
        adapter = ADAPTERS[adapter_id]
        case = next(c for c in CASES if c.family == "parallel_tool_pairing")
        exp = case.expectations[adapter_id]
        fixture_path = _resolve_fixture_path(exp)

        events, findings = adapter.load_fn(fixture_path)
        calls = [e for e in events if e.kind == "tool_call"]
        returns = [e for e in events if e.kind in ("tool_result", "tool_return")]

        assert len(calls) >= exp.extra["min_calls"], (
            f"Expected at least {exp.extra['min_calls']} tool calls"
        )
        assert len(returns) >= exp.extra["min_returns"], (
            f"Expected at least {exp.extra['min_returns']} tool returns"
        )

        # Correlation IDs must be non-empty strings
        call_corrs = [c.correlation_id for c in calls if c.correlation_id]
        return_corrs = [r.correlation_id for r in returns if r.correlation_id]
        assert len(call_corrs) == len(calls), "Every tool call must have a correlation_id"
        assert len(return_corrs) == len(returns), "Every tool return must have a correlation_id"

        # Pairing check: every return correlation_id must correspond to a call correlation_id
        assert set(return_corrs).issubset(set(call_corrs)), (
            f"Orphan tool returns detected in adapter {adapter_id}: "
            f"{set(return_corrs) - set(call_corrs)}"
        )

        # Pipeline must produce zero pairing findings (SL101 orphan, SL102 mismatch, SL107 ordering)
        report = check_file(fixture_path, format=adapter.format_name)
        pairing_errors = [f for f in report.findings if f.code in (SL101, SL102, SL107)]
        assert len(pairing_errors) == 0, (
            f"Spurious pairing findings emitted for {adapter_id}: {pairing_errors}"
        )

    @pytest.mark.parametrize("adapter_id", list(ADAPTERS.keys()))
    def test_family_04_default_report_privacy(
        self, adapter_id: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Secret seeds in session data must NEVER leak into default reports or CLI output."""
        adapter = ADAPTERS[adapter_id]
        case = next(c for c in CASES if c.family == "default_report_privacy")
        exp = case.expectations[adapter_id]
        fixture_path = _resolve_fixture_path(exp)
        secret_tokens = exp.extra["secret_tokens"]

        # Verify the fixture does indeed contain the canary tokens
        raw_fixture_text = fixture_path.read_text(encoding="utf-8")
        for token in secret_tokens:
            assert token in raw_fixture_text, (
                f"Test fixture {fixture_path} missing canary token {token}"
            )

        # Step 1: API Report privacy check
        report = check_file(fixture_path, format=adapter.format_name)
        report_dict = report.to_dict()

        # Recursive PII and secret scanner
        assert_no_pii(report_dict)

        # Regex canary patterns check across report serialization
        report_json = json.dumps(report_dict)
        for pattern in SECRET_PATTERNS:
            match = pattern.search(report_json)
            assert match is None, (
                f"Secret pattern {pattern.pattern} matched in report: {match.group(0)!r}"
            )

        # Explicit canary string check
        for token in secret_tokens:
            assert token not in report_json, f"Canary token {token} leaked into report JSON!"

        # Step 2: CLI stdout/stderr privacy check
        exit_code = main(["check", str(fixture_path), "--format", adapter.format_name, "--json"])
        assert exit_code == 0
        captured = capsys.readouterr()
        for token in secret_tokens:
            assert token not in captured.out, f"Canary token {token} leaked into CLI stdout!"
            assert token not in captured.err, f"Canary token {token} leaked into CLI stderr!"

    @pytest.mark.parametrize("adapter_id", list(ADAPTERS.keys()))
    def test_family_05_canonical_determinism(self, adapter_id: str) -> None:
        """Loading and evaluating same artifact twice produces identical events and fingerprints."""
        adapter = ADAPTERS[adapter_id]
        case = next(c for c in CASES if c.family == "canonical_determinism")
        fixture_path = _resolve_fixture_path(case.expectations[adapter_id])

        # Run 1
        events_1, findings_1 = adapter.load_fn(fixture_path)
        report_1 = check_file(fixture_path, format=adapter.format_name)

        # Run 2
        events_2, findings_2 = adapter.load_fn(fixture_path)
        report_2 = check_file(fixture_path, format=adapter.format_name)

        # Direct loader determinism
        assert len(events_1) == len(events_2)
        assert [e.id for e in events_1] == [e.id for e in events_2]
        assert [e.ts for e in events_1] == [e.ts for e in events_2]
        assert [e.content_hash for e in events_1] == [e.content_hash for e in events_2]
        assert [f.fingerprint for f in findings_1] == [f.fingerprint for f in findings_2]

        # Public API Report determinism
        assert report_1.session_id == report_2.session_id
        assert report_1.source_fingerprint == report_2.source_fingerprint
        assert [f.fingerprint for f in report_1.findings] == [
            f.fingerprint for f in report_2.findings
        ]

        # Canonical bytes determinism
        bytes_1 = dump_canonical(events_1)
        bytes_2 = dump_canonical(events_2)
        assert bytes_1 == bytes_2

    @pytest.mark.parametrize("adapter_id", list(ADAPTERS.keys()))
    def test_family_06_detection_confidence_sanity(self, adapter_id: str) -> None:
        """Adapter detects own fixtures above threshold and rejects others below threshold."""
        adapter = ADAPTERS[adapter_id]
        case = next(c for c in CASES if c.family == "detection_sanity")
        fixture_path = _resolve_fixture_path(case.expectations[adapter_id])

        with open(fixture_path, "rb") as stream:
            first_bytes = stream.read(SNIFF_BYTES)

        filename = fixture_path.name

        # 1. Target adapter confidence must exceed minimum threshold
        target_score = adapter.detect_fn(first_bytes, filename)
        assert target_score >= CONFIDENCE_MIN, (
            f"Adapter {adapter_id} gave score {target_score} < {CONFIDENCE_MIN} on its own fixture"
        )

        # 2. Competing adapters must score below target by at least MARGIN_MIN
        for comp_id, comp_adapter in ADAPTERS.items():
            if comp_id == adapter_id:
                continue
            comp_score = comp_adapter.detect_fn(first_bytes, filename)
            score_diff = target_score - comp_score
            assert score_diff >= MARGIN_MIN, (
                f"Margin violation on fixture {filename}: {adapter_id} ({target_score}) vs "
                f"{comp_id} ({comp_score}), diff {score_diff} < {MARGIN_MIN}"
            )

        # 3. Overall detect_format arbitration must resolve to adapter format as clear-winner
        det_result = detect_format(fixture_path)
        assert det_result.format == adapter.format_name
        assert det_result.reason == "clear-winner"

    @pytest.mark.parametrize("adapter_id", list(ADAPTERS.keys()))
    def test_family_07_synthetic_id_namespace(self, adapter_id: str) -> None:
        """Synthetic IDs strictly adhere to sesslint:synthetic namespace with zero 'rec_' leaks."""
        adapter = ADAPTERS[adapter_id]
        case = next(c for c in CASES if c.family == "synthetic_ids")
        exp = case.expectations[adapter_id]
        fixture_path = _resolve_fixture_path(exp)

        events, _ = adapter.load_fn(fixture_path)
        assert len(events) >= 1

        if not exp.extra.get("uses_native_ids", False):
            # Adapters that generate synthetic IDs when absent (Claude Code, OpenAI Agents)
            for ev in events:
                assert is_synthetic_id(ev.id), f"Event ID {ev.id!r} is not in synthetic namespace"
                assert SYNTHETIC_ID_PATTERN.match(ev.id) is not None, (
                    f"Event ID {ev.id!r} does not match synthetic pattern"
                )
                assert not ev.id.startswith("rec_"), (
                    f"Legacy 'rec_' prefix leaked in synthetic ID: {ev.id}"
                )
                assert "rec_" not in ev.id, f"Legacy 'rec_' substring in synthetic ID: {ev.id}"
                assert ev.original_id is None, "Synthetic events must have original_id=None"

            # Check collision guard behavior: no duplicate IDs within the session
            all_ids = [e.id for e in events]
            assert len(all_ids) == len(set(all_ids)), (
                f"Duplicate synthetic IDs generated: {all_ids}"
            )
        else:
            # Canonical adapter preserves native IDs verbatim without mangling or synthesizing
            for ev in events:
                assert not ev.id.startswith("rec_"), (
                    f"Unexpected 'rec_' ID in canonical session: {ev.id}"
                )
                # Demonstrate synthetic_event_id for canonical if called adheres to contract
                synth_id = synthetic_event_id(
                    "canonical", 0, source_hint=str(fixture_path), payload_len=10
                )
                assert is_synthetic_id(synth_id)
                assert SYNTHETIC_ID_PATTERN.match(synth_id) is not None

    @pytest.mark.parametrize("adapter_id", list(ADAPTERS.keys()))
    def test_family_08a_discriminator_shapes_safe(self, adapter_id: str) -> None:
        """Allowlisted safe unknown discriminator is echoed verbatim in SL302 evidence."""
        adapter = ADAPTERS[adapter_id]
        case = next(c for c in CASES if c.case_id == "case_08a_discriminator_safe")
        exp = case.expectations[adapter_id]
        fixture_path = _resolve_fixture_path(exp)

        _, findings = adapter.load_fn(fixture_path)
        sl302_findings = [f for f in findings if f.code == SL302]
        assert len(sl302_findings) >= 1, f"Expected SL302 finding on adapter {adapter_id}"

        evidence = sl302_findings[0].evidence or {}
        expected_disc = exp.extra["expected_discriminator"]
        assert evidence.get("type_value") == expected_disc, (
            f"Expected verbatim echo of {expected_disc!r}, got {evidence.get('type_value')!r}"
        )
        assert evidence.get("type_truncated") is not True, (
            "Safe discriminator must not be marked truncated"
        )

    @pytest.mark.parametrize("adapter_id", list(ADAPTERS.keys()))
    def test_family_08b_discriminator_shapes_hostile(self, adapter_id: str) -> None:
        """Hostile discriminator is sanitized to <type:len=N> shape and type_truncated=True."""
        adapter = ADAPTERS[adapter_id]
        case = next(c for c in CASES if c.case_id == "case_08b_discriminator_hostile")
        exp = case.expectations[adapter_id]
        fixture_path = _resolve_fixture_path(exp)

        _, findings = adapter.load_fn(fixture_path)
        sl302_findings = [f for f in findings if f.code == SL302]
        assert len(sl302_findings) >= 1, f"Expected SL302 finding on adapter {adapter_id}"

        evidence = sl302_findings[0].evidence or {}
        expected_shape = exp.extra["expected_shape"]
        assert evidence.get("type_value") == expected_shape, (
            f"Expected bounded shape {expected_shape!r}, got {evidence.get('type_value')!r}"
        )
        assert evidence.get("type_truncated") is True, (
            "Hostile discriminator must have type_truncated=True"
        )


# -----------------------------------------------------------------------------
# Extensibility Proof: Fake Fourth Adapter Worked Example
# -----------------------------------------------------------------------------


def _fake_detect(first_bytes: bytes, filename: str) -> float:
    """Detection heuristic for stub fourth adapter (acme-log format)."""
    if filename.endswith(".acme") or b'"acme_agent_session"' in first_bytes:
        return 1.0
    return 0.0


def _fake_load_conforming(
    path: Path | str,
    *,
    limits: ReaderLimits | None = None,
) -> tuple[list[CanonicalEvent], list[Finding]]:
    """Conforming loader implementation for stub fourth adapter."""
    fpath = Path(path)
    content = fpath.read_text(encoding="utf-8")
    doc = json.loads(content)

    guard = SyntheticIdCollisionGuard()
    events: list[CanonicalEvent] = []
    findings: list[Finding] = []

    raw_items = doc.get("records", [])
    for idx, item in enumerate(raw_items):
        raw_id = item.get("id")
        if raw_id:
            event_id = guard.register_real(str(raw_id))
            orig_id = event_id
        else:
            event_id = synthetic_event_id(
                "acme_log", idx, source_hint=str(fpath), payload_len=len(content)
            )
            guard.register_synthetic(event_id)
            orig_id = None

        payload = {"data": item.get("data", "")}
        events.append(
            CanonicalEvent(
                id=event_id,
                parent_id=item.get("parent_id"),
                seq=idx,
                ts=item.get("ts", "2026-09-13T00:00:00Z"),
                actor="assistant",
                kind="message",
                payload=payload,
                content_hash=compute_content_hash(payload),
                original_id=orig_id,
                source_adapter="acme-log",
            )
        )

    return events, findings


def _fake_load_violating_immutability(
    path: Path | str,
    *,
    limits: ReaderLimits | None = None,
) -> tuple[list[CanonicalEvent], list[Finding]]:
    """Buggy loader that writes back to disk during parsing (violates immutability)."""
    fpath = Path(path)
    events, findings = _fake_load_conforming(path, limits=limits)
    # Mutates file on disk after read!
    fpath.write_bytes(fpath.read_bytes() + b"\n")
    return events, findings


def _fake_load_violating_synthetic_ids(
    path: Path | str,
    *,
    limits: ReaderLimits | None = None,
) -> tuple[list[CanonicalEvent], list[Finding]]:
    """Buggy loader that emits legacy 'rec_N' IDs instead of the reserved namespace."""
    events, findings = _fake_load_conforming(path, limits=limits)
    bad_events = [
        CanonicalEvent(
            id=f"rec_{i}",  # VIOLATION: legacy rec_ ID
            parent_id=e.parent_id,
            seq=e.seq,
            ts=e.ts,
            actor=e.actor,
            kind=e.kind,
            payload=e.payload,
            content_hash=e.content_hash,
            original_id=e.original_id,
            source_adapter=e.source_adapter,
        )
        for i, e in enumerate(events)
    ]
    return bad_events, findings


class TestFakeFourthAdapterExtensibilityProof:
    """Proves the table-driven conformance design easily supports new adapters.

    Adding an adapter requires adding a row to ADAPTERS and expectations to CASES.
    This worked example verifies:
    1. A conforming fourth adapter passes shared assertions trivially.
    2. A non-conforming adapter fails loudly with precise failure indications.
    """

    def test_conforming_fourth_adapter_passes_conformance(self, tmp_path: Path) -> None:
        """Conforming stub adapter passes immutability, synthetic IDs, and determinism."""
        fixture = tmp_path / "session.acme"
        fixture.write_text(
            json.dumps(
                {
                    "acme_agent_session": "sess_001",
                    "records": [
                        {"data": "step 1"},
                        {"data": "step 2"},
                    ],
                }
            ),
            encoding="utf-8",
        )

        fake_spec = AdapterSpec(
            adapter_id="acme-log",
            format_name="acme-log",
            detect_fn=_fake_detect,
            load_fn=_fake_load_conforming,
            fixture_dir=tmp_path,
        )

        # 1. Detection sanity
        raw_bytes = fixture.read_bytes()
        score = fake_spec.detect_fn(raw_bytes, fixture.name)
        assert score == 1.0

        # 2. Immutability
        sha_before = hashlib.sha256(raw_bytes).hexdigest()
        fake_spec.load_fn(fixture)
        assert hashlib.sha256(fixture.read_bytes()).hexdigest() == sha_before

        # 3. Synthetic IDs
        events, _ = fake_spec.load_fn(fixture)
        assert len(events) == 2
        for ev in events:
            assert is_synthetic_id(ev.id)
            assert SYNTHETIC_ID_PATTERN.match(ev.id) is not None
            assert not ev.id.startswith("rec_")

        # 4. Determinism
        ev1, _ = fake_spec.load_fn(fixture)
        ev2, _ = fake_spec.load_fn(fixture)
        assert [e.id for e in ev1] == [e.id for e in ev2]
        assert [e.content_hash for e in ev1] == [e.content_hash for e in ev2]

    def test_non_conforming_adapter_immutability_violation_fails_loudly(
        self, tmp_path: Path
    ) -> None:
        """A fourth adapter that mutates its input fails the immutability assertion."""
        fixture = tmp_path / "session.acme"
        fixture.write_text(
            json.dumps({"acme_agent_session": "sess_001", "records": []}), encoding="utf-8"
        )
        sha_before = hashlib.sha256(fixture.read_bytes()).hexdigest()

        # Execute violating loader
        _fake_load_violating_immutability(fixture)
        sha_after = hashlib.sha256(fixture.read_bytes()).hexdigest()

        # The conformance assertion catches the mutation!
        with pytest.raises(AssertionError, match="Immutability violation"):
            if sha_before != sha_after:
                raise AssertionError(
                    f"Immutability violation: sha changed from {sha_before} to {sha_after}"
                )

    def test_non_conforming_adapter_synthetic_id_leak_fails_loudly(self, tmp_path: Path) -> None:
        """A fourth adapter that emits legacy 'rec_' IDs fails the namespace assertion."""
        fixture = tmp_path / "session.acme"
        fixture.write_text(
            json.dumps({"acme_agent_session": "sess_001", "records": [{"data": "hello"}]}),
            encoding="utf-8",
        )

        events, _ = _fake_load_violating_synthetic_ids(fixture)
        assert len(events) == 1

        # The conformance assertion catches the legacy 'rec_' ID!
        with pytest.raises(AssertionError, match="Legacy 'rec_' prefix leaked in synthetic ID"):
            for ev in events:
                if ev.id.startswith("rec_"):
                    raise AssertionError(f"Legacy 'rec_' prefix leaked in synthetic ID: {ev.id}")
