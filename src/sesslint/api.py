"""SessLint public programmatic API providing 1:1 library-CLI parity (TASK-024).

This module exposes pure, side-effect-free library functions returning frozen
dataclasses. It performs no terminal printing, no sys.exit, and no color formatting.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from sesslint._version import CLI_VERSION
from sesslint.adapters.detect import (
    FORMAT_CANONICAL,
    FORMAT_CLAUDE_CODE,
    FORMAT_OPENAI_AGENTS,
    resolve_format,
)
from sesslint.codes import SL302, Repairability, Severity
from sesslint.finding import Finding, SourceRef, make_finding
from sesslint.profiles import resolve_effective_config
from sesslint.repair import (
    RepairPlan,
    execute,
    load_plan,
    run_all_checks,
)
from sesslint.repair.planner import plan as planner_plan
from sesslint.report import Assurance, RepairManifest, Report, build_report
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
) -> Report:
    """Evaluate a single session file artifact and return a frozen Report.

    Args:
        path: Path to session file.
        format: Format override ('auto', None, or known format name).
        profile: Validation profile name (default 'neutral').

    Returns:
        A frozen Report dataclass with findings, counts, assurance, and limitation.
    """
    target_path = Path(path)
    if not target_path.exists():
        raise FileNotFoundError(f"Path not found: {target_path}")

    effective_cfg = resolve_effective_config(
        profile,
        format=format if format != "auto" else None,
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
        return build_report(
            session_id=target_path.stem,
            source_fingerprint=fp,
            tool_version=CLI_VERSION,
            findings=rep_findings,
            assurance="A0",
            limitation="No structural conclusion.",
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
        finding = make_finding(
            code=SL302,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message_template="Format is not permitted by profile",
            source=SourceRef(path=str(target_path)),
            evidence={"format": resolved_fmt, "profile": effective_cfg.profile},
        )
        fp = fingerprint_file(target_path) if target_path.is_file() else "0" * 64
        return build_report(
            session_id=target_path.stem,
            source_fingerprint=fp,
            tool_version=CLI_VERSION,
            findings=[finding],
            assurance="A0",
            limitation="No structural conclusion.",
        )

    events: list[Any] = []
    adapter_findings: list[Finding] = list(det_findings)

    if resolved_fmt == FORMAT_CANONICAL:
        from sesslint.adapters.canonical import load_canonical

        can_events, can_findings = load_canonical(target_path)
        events = list(can_events)
        adapter_findings.extend(can_findings)
    elif resolved_fmt == FORMAT_CLAUDE_CODE:
        from sesslint.adapters.claude_code import load_claude_code

        c_events, c_findings = load_claude_code(target_path)
        events = list(c_events)
        adapter_findings.extend(c_findings)
    elif resolved_fmt == FORMAT_OPENAI_AGENTS:
        from sesslint.adapters.openai_agents import load_openai_agents

        o_events, o_findings = load_openai_agents(target_path)
        events = list(o_events)
        adapter_findings.extend(o_findings)

    check_findings = run_all_checks(
        events,
        profile=effective_cfg.profile,
        source_path=str(target_path),
    )
    all_findings = list(adapter_findings) + list(check_findings)

    session_id: str = target_path.stem
    if (
        hasattr(events, "source")
        and isinstance(events.source, dict)
        and events.source.get("session_id")
    ):
        session_id = str(events.source["session_id"])
    elif events and hasattr(events[0], "session_id") and events[0].session_id:
        session_id = str(events[0].session_id)

    has_error = any(f.severity in (Severity.ERROR, Severity.FATAL) for f in all_findings)
    has_warning = any(f.severity == Severity.WARNING for f in all_findings)

    assurance: Assurance
    if has_error:
        assurance = "A0"
        limitation = "No structural conclusion."
    elif has_warning:
        assurance = "A1"
        limitation = "Relationships may still be invalid."
    else:
        assurance = "A2"
        limitation = "Provider/runtime replay has not been independently exercised."

    fp = fingerprint_file(target_path)
    return build_report(
        session_id=session_id,
        source_fingerprint=fp,
        tool_version=CLI_VERSION,
        findings=all_findings,
        assurance=assurance,
        limitation=limitation,
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
            source_path=str(src),
        )
        source_findings = list(stream_findings) + list(check_findings)
        plan_obj = planner_plan(
            findings=source_findings,
            events=source_events,
            profile=profile,
            policy=policy,
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
    plan_path: Path | str,
    output_path: Path | str,
    manifest_path: Path | str,
) -> VerifyVerdict:
    """Verify integrity, hash bindings, and idempotence of a repaired session.

    Args:
        source_path: Path to original source session file.
        plan_path: Path to repair plan JSON file.
        output_path: Path to repaired session file.
        manifest_path: Path to repair manifest JSON file.

    Returns:
        VerifyVerdict with audit steps, pass/fail status, and diagnostic messages.
    """
    return verify_artifacts(
        source_path=source_path,
        plan_path=plan_path,
        output_path=output_path,
        manifest_path=manifest_path,
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
    "VerifyVerdict",
    "check_dir",
    "check_file",
    "plan",
    "repair",
    "verify",
]
