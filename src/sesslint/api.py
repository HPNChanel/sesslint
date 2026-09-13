"""SessLint public programmatic API providing 1:1 library-CLI parity (TASK-024).

This module exposes pure, side-effect-free library functions returning frozen
dataclasses. It performs no terminal printing, no sys.exit, and no color formatting.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from sesslint._version import CLI_VERSION
from sesslint.adapters.detect import (
    FORMAT_CANONICAL,
    FORMAT_CLAUDE_CODE,
    FORMAT_OPENAI_AGENTS,
    resolve_format,
)
from sesslint.bundle import Bundle, build_bundle
from sesslint.codes import SL302, Repairability, Severity
from sesslint.context import CheckContext
from sesslint.finding import Finding, SourceRef, make_finding
from sesslint.precheck import PrecheckReason, PrecheckResult, precheck
from sesslint.profiles import resolve_effective_config
from sesslint.repair import (
    RepairPlan,
    execute,
    load_plan,
)
from sesslint.repair import executor as repair_executor
from sesslint.repair.planner import plan as planner_plan
from sesslint.report import (
    Coverage,
    CoverageSkip,
    RepairManifest,
    Report,
    build_report,
    compute_assurance,
)
from sesslint.scan import (
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_FILES,
    ScanReport,
    scan_path,
)
from sesslint.source import fingerprint_file
from sesslint.verify import Verdict
from sesslint.verify import verify as verify_artifacts

VerifyVerdict = Verdict


def check_file(
    path: Path | str,
    *,
    format: str | None = None,
    profile: str = "neutral",
    confidence_min: float | None = None,
    margin_min: float | None = None,
) -> Report:
    """Evaluate a single session file artifact and return a frozen Report.

    Args:
        path: Path to session file.
        format: Format override ('auto', None, or known format name).
        profile: Validation profile name (default 'neutral').
        confidence_min: Format auto-detection minimum confidence threshold.
        margin_min: Format auto-detection minimum margin threshold.

    Returns:
        A frozen Report dataclass with findings, counts, assurance, and limitation.
    """
    target_path = Path(path)
    if not target_path.exists():
        raise FileNotFoundError(f"Path not found: {target_path}")

    effective_cfg = resolve_effective_config(
        profile,
        format=format if format != "auto" else None,
        confidence_min=confidence_min,
        margin_min=margin_min,
    )

    resolved_fmt, detection_res, det_findings = resolve_format(format, target_path)

    if resolved_fmt is None:
        rep_findings = (
            list(det_findings)
            if det_findings
            else [
                make_finding(
                    code=SL302,
                    severity=Severity.ERROR,
                    repairability=Repairability.MANUAL,
                    message_template="Format detection failed",
                    source=SourceRef(path=str(target_path)),
                    evidence={"detail": detection_res.reason if detection_res else "unknown"},
                )
            ]
        )
        fp = fingerprint_file(target_path) if target_path.is_file() else "0" * 64
        cov = Coverage(
            performed=(),
            skipped=tuple(
                CoverageSkip(
                    check=r, reason="adapter-not-applicable", detail="format detection failed"
                )
                for r in (
                    "SL001",
                    "SL002",
                    "SL003",
                    "SL004",
                    "SL005",
                    "SL006",
                    "SL007",
                    "SL101",
                    "SL102",
                    "SL103",
                    "SL104",
                    "SL105",
                    "SL106",
                    "SL107",
                    "SL108",
                    "SL201",
                    "SL202",
                    "SL203",
                    "SL301",
                    "SL302",
                )
            ),
            adapter={"id": "unknown", "version": "unknown"},
            profile={"id": effective_cfg.profile, "version": effective_cfg.version},
        )
        return build_report(
            session_id=target_path.stem,
            source_fingerprint=fp,
            tool_version=CLI_VERSION,
            findings=rep_findings,
            assurance="A0",
            limitation="No structural conclusion.",
            coverage=cov,
        )

    fmt_key = (
        "claude"
        if resolved_fmt == FORMAT_CLAUDE_CODE
        else (
            "openai"
            if resolved_fmt == FORMAT_OPENAI_AGENTS
            else ("canonical" if resolved_fmt == FORMAT_CANONICAL else resolved_fmt)
        )
    )
    if (
        fmt_key not in effective_cfg.allowed_adapters
        and resolved_fmt not in effective_cfg.allowed_adapters
    ):
        raise ValueError(
            f"Format {resolved_fmt} is not permitted by profile {effective_cfg.profile}"
        )

    events: Any = ()
    adapter_findings: list[Finding] = list(det_findings)

    if resolved_fmt == FORMAT_CANONICAL:
        from sesslint.adapters.canonical import load_canonical

        events, can_findings = load_canonical(target_path)
        adapter_findings.extend(can_findings)
    elif resolved_fmt == FORMAT_CLAUDE_CODE:
        from sesslint.adapters.claude_code import load_claude_code

        events, c_findings = load_claude_code(target_path)
        adapter_findings.extend(c_findings)
    elif resolved_fmt == FORMAT_OPENAI_AGENTS:
        from sesslint.adapters.openai_agents import load_openai_agents

        events, o_findings = load_openai_agents(target_path)
        adapter_findings.extend(o_findings)

    adapter_skips: list[CoverageSkip] = []
    if any(f.code == "SL301" for f in adapter_findings):
        adapter_skips.append(
            CoverageSkip(
                check="SL301",
                reason="version-gated",
                detail="unsupported format version (SL301)",
            )
        )

    source_meta = getattr(events, "source", None)
    check_ctx = CheckContext.from_profile_and_adapter(
        profile=effective_cfg.profile,
        adapter=resolved_fmt,
        source_metadata=source_meta if isinstance(source_meta, Mapping) else None,
    )

    check_findings, coverage = repair_executor.run_all_checks(
        events,
        profile=effective_cfg.profile,
        source_path=str(target_path),
        context=check_ctx,
        adapter=resolved_fmt,
        adapter_skips=adapter_skips,
        return_coverage=True,
    )
    all_findings = list(adapter_findings) + list(check_findings)

    session_id: str = target_path.stem
    if events and hasattr(events[0], "session_id") and events[0].session_id:
        session_id = str(events[0].session_id)

    assurance, limitation = compute_assurance(events, all_findings)

    fp = fingerprint_file(target_path)
    return build_report(
        session_id=session_id,
        source_fingerprint=fp,
        tool_version=CLI_VERSION,
        findings=all_findings,
        assurance=assurance,
        limitation=limitation,
        coverage=coverage,
    )


def check_dir(
    path: Path | str,
    *,
    recursive: bool = True,
    follow_symlinks: bool = False,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes: int = DEFAULT_MAX_BYTES,
    format: str | None = None,
    profile: str = "neutral",
) -> ScanReport:
    """Scan a directory tree and return a ScanReport with aggregate 5-bucket totals.

    Args:
        path: Path to directory.
        recursive: Whether to scan recursively (default True).
        follow_symlinks: Whether to follow symlinks (default False).
        max_files: Maximum number of files to process.
        max_bytes: Maximum cumulative bytes to process.
        format: Format override ('auto', None, or known format name).
        profile: Validation profile name (default 'neutral').

    Returns:
        A frozen ScanReport dataclass.
    """
    return scan_path(
        path=path,
        recursive=recursive,
        follow_symlinks=follow_symlinks,
        max_files=max_files,
        max_bytes=max_bytes,
        format=format,
        profile=profile,
    )


def repair(
    source_path: Path | str,
    output_path: Path | str | None,
    *,
    policy: Literal["conservative", "salvage"] = "conservative",
    format: str | None = None,
    profile: str = "neutral",
    plan_path: Path | str | None = None,
    dry_run: bool = False,
    acknowledge_side_effects: bool = False,
) -> tuple[RepairPlan, RepairManifest | None]:
    """Safely plan and execute session repair.

    Args:
        source_path: Path to source session file.
        output_path: Path to output repaired session file (required if not dry_run).
        policy: 'conservative' or 'salvage' (default 'conservative').
        format: Optional format adapter override.
        profile: Profile name (default 'neutral').
        plan_path: Optional path to pre-computed plan JSON.
        dry_run: If True, computes plan without writing files.
        acknowledge_side_effects: Explicit acknowledgment for salvage policy.

    Returns:
        Tuple of (RepairPlan, RepairManifest or None if dry_run).
    """
    src = Path(source_path)
    if not src.is_file():
        raise FileNotFoundError(f"Source file not found: {src}")

    # RVW-019: Vendor formats are rejected in repair (canonical only)
    from sesslint.adapters.detect import detect_format

    if format in (FORMAT_CLAUDE_CODE, FORMAT_OPENAI_AGENTS):
        from sesslint.repair.errors import RepairRefused

        raise RepairRefused(
            f"Direct repair of vendor format '{format}' is not supported. "
            "Repair operates exclusively on canonical session streams (JSONL)."
        )
    if format in (None, "auto"):
        det = detect_format(src)
        if det.format in (FORMAT_CLAUDE_CODE, FORMAT_OPENAI_AGENTS):
            from sesslint.repair.errors import RepairRefused

            raise RepairRefused(
                f"Direct repair of vendor format '{det.format}' is not supported. "
                "Repair operates exclusively on canonical session streams (JSONL)."
            )

    plan_obj: RepairPlan
    if plan_path is not None:
        plan_obj = load_plan(plan_path)
    else:
        from sesslint.repair.executor import (
            load_session_source_with_findings,
            run_all_checks,
        )

        _source_header, source_events, stream_findings = load_session_source_with_findings(src)
        check_findings = run_all_checks(
            source_events,
            profile=profile,
            source_path=src.name,
            adapter="canonical",
        )
        source_findings = list(stream_findings) + list(check_findings)
        source_hash = hashlib.sha256(src.read_bytes()).hexdigest()
        import sys

        p_mod = sys.modules.get("sesslint.repair.planner")
        planner_fn = getattr(p_mod, "plan", planner_plan) if p_mod else planner_plan
        plan_obj = planner_fn(
            findings=source_findings,
            events=source_events,
            profile=profile,
            policy=policy,
            source_hash=source_hash,
            acknowledge_side_effects=acknowledge_side_effects,
        )
        has_error_findings = any(
            f.severity in (Severity.ERROR, Severity.FATAL) for f in source_findings
        )
        if has_error_findings and len(plan_obj.steps) == 0:
            from sesslint.repair.errors import RepairRefused

            raise RepairRefused(
                "Findings exist on source session, but no authorized safe repair plan completes."
            )

    if dry_run:
        execute(
            source_path=src,
            plan=plan_obj,
            output_path=Path(output_path) if output_path is not None else None,
            policy=policy,
            dry_run=True,
            profile=profile,
            format=format if format != "auto" else None,
            acknowledge_side_effects=acknowledge_side_effects,
        )
        return plan_obj, None

    if output_path is None:
        raise ValueError("output_path is required when dry_run is False")

    out = Path(output_path)
    manifest = execute(
        source_path=src,
        plan=plan_obj,
        output_path=out,
        policy=policy,
        dry_run=False,
        profile=profile,
        format=format if format != "auto" else None,
        acknowledge_side_effects=acknowledge_side_effects,
    )
    return plan_obj, manifest


def verify(
    source_path: Path | str,
    output_path: Path | str,
    manifest_path: Path | str,
    plan_path: Path | str | None = None,
    acknowledge_side_effects: bool = False,
) -> VerifyVerdict:
    """Verify integrity, hash bindings, and idempotence of a repaired session.

    Args:
        source_path: Path to original source session file.
        output_path: Path to repaired session file.
        manifest_path: Path to repair manifest JSON file.
        plan_path: Path to repair plan JSON file (optional).
        acknowledge_side_effects: Whether to acknowledge tool side-effects.

    Returns:
        VerifyVerdict with audit steps, pass/fail status, and diagnostic messages.
    """
    import sys

    v_mod = sys.modules.get("sesslint.verify")
    verify_fn = getattr(v_mod, "verify", verify_artifacts) if v_mod else verify_artifacts
    return verify_fn(
        source_path=source_path,
        output_path=output_path,
        manifest_path=manifest_path,
        plan_path=plan_path,
        acknowledge_side_effects=acknowledge_side_effects,
    )


def plan(
    source_path: Path | str,
    *,
    policy: Literal["conservative", "salvage"] = "conservative",
    format: str | None = None,
    profile: str = "neutral",
) -> RepairPlan:
    """Compute a dry-run repair plan for a source session file without writing files.

    Args:
        source_path: Path to source session file.
        policy: 'conservative' or 'salvage' (default 'conservative').
        format: Optional format adapter override.
        profile: Profile name (default 'neutral').

    Returns:
        A frozen RepairPlan instance.
    """
    res, _ = repair(
        source_path,
        output_path=None,
        policy=policy,
        format=format,
        profile=profile,
        dry_run=True,
    )
    return res


__all__ = [
    "Bundle",
    "PrecheckReason",
    "PrecheckResult",
    "ScanReport",
    "VerifyVerdict",
    "build_bundle",
    "check_dir",
    "check_file",
    "plan",
    "precheck",
    "repair",
    "verify",
]
