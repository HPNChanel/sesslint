"""SessLint public programmatic API providing 1:1 library-CLI parity (TASK-024).

This module exposes pure, side-effect-free library functions returning frozen
dataclasses. It performs no terminal printing, no sys.exit, and no color formatting.
"""

from __future__ import annotations

import hashlib
import io
import os
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from sesslint._version import CLI_VERSION
from sesslint.adapters.detect import (
    FORMAT_CANONICAL,
    FORMAT_CLAUDE_CODE,
    FORMAT_CODEX_ROLLOUT,
    FORMAT_OPENAI_AGENTS,
    resolve_format,
    validate_detection_thresholds,
)
from sesslint.batch import BatchRepairReport
from sesslint.bundle import Bundle, build_bundle
from sesslint.canonical import Session, SessionEvent, load_session_file
from sesslint.codes import SL001, SL302, Repairability, Severity
from sesslint.context import CheckContext
from sesslint.diff import SessionDiff
from sesslint.doctor import DoctorReport
from sesslint.exporter import ExportSummary
from sesslint.finding import Finding, SourceRef, make_finding
from sesslint.precheck import PrecheckReason, PrecheckResult, precheck
from sesslint.preview import PreviewDoc
from sesslint.profiles import (
    ALL_RULES,
    apply_rule_selection,
    deselected_rules,
    resolve_effective_config,
)
from sesslint.progress import (
    CancellationToken,
    OperationCancelled,
    ProgressCallback,
    ProgressEvent,
    check_token,
)
from sesslint.progress import emit as emit_progress
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
    scan_bytes,
    scan_path,
)
from sesslint.source import fingerprint_bytes, fingerprint_file
from sesslint.stats import SessionStats
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
    progress_cb: ProgressCallback | None = None,
    cancel_token: CancellationToken | None = None,
    select: Sequence[str] | None = None,
    ignore: Sequence[str] | None = None,
    baseline: Collection[str] | None = None,
) -> Report:
    """Evaluate a single session file artifact and return a frozen Report.

    Args:
        path: Path to session file.
        format: Format override ('auto', None, or known format name).
        profile: Validation profile name (default 'neutral').
        confidence_min: Format auto-detection minimum confidence threshold.
        margin_min: Format auto-detection minimum margin threshold.
        progress_cb: Optional callback receiving ``ProgressEvent`` records at
            phase boundaries (``check:detect``, ``check:load``,
            ``check:analyze``, ``check:report``) — DW-T-13.
        cancel_token: Optional cooperative cancellation token checked at
            phase boundaries.
        select: Optional rule codes to run exclusively (e.g. ``("SL101",)``).
        ignore: Optional rule codes to skip (mutually exclusive with select).
        baseline: Optional finding fingerprints to suppress (baseline mode:
            the returned report describes only findings absent from the set).

    Returns:
        A frozen Report dataclass with findings, counts, assurance, and limitation.
    """
    return _check_impl(
        Path(path),
        data=None,
        virtual_path=None,
        format=format,
        profile=profile,
        confidence_min=confidence_min,
        margin_min=margin_min,
        progress_cb=progress_cb,
        cancel_token=cancel_token,
        select=select,
        ignore=ignore,
        baseline=baseline,
    )


def check_bytes(
    data: bytes,
    *,
    virtual_path: str = "<stdin>",
    format: str | None = None,
    profile: str = "neutral",
    confidence_min: float | None = None,
    margin_min: float | None = None,
    progress_cb: ProgressCallback | None = None,
    cancel_token: CancellationToken | None = None,
    select: Sequence[str] | None = None,
    ignore: Sequence[str] | None = None,
    baseline: Collection[str] | None = None,
    max_input_bytes: int | None = None,
) -> Report:
    """Evaluate a session artifact held in memory (e.g. piped stdin bytes).

    Runs the identical probe → detect → load → check pipeline as
    ``check_file``; the only differences are the byte source and the display
    path (``virtual_path``, reported verbatim — never resolved against cwd).
    Content detection relies on record signatures since a virtual source has
    no meaningful filename; ``--format`` overrides as usual.
    ``max_input_bytes`` bounds the slurped buffer: when exceeded the result is
    a structured SL001 finding, never a traceback (ux T-06).
    """
    if max_input_bytes is not None and len(data) > max_input_bytes:
        resolved_profile = apply_rule_selection(profile, select=select, ignore=ignore)
        effective_cfg = resolve_effective_config(resolved_profile)
        det_finding = make_finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message_template="Input exceeds maximum supported size",
            source=SourceRef(path=virtual_path),
            evidence={"reason": "limit_or_io_error", "detail": "stdin_too_large"},
        )
        rep_findings = [det_finding] if SL001 in set(resolved_profile.enabled_rules) else []
        if baseline is not None:
            from sesslint.baseline import filter_findings

            rep_findings = filter_findings(rep_findings, frozenset(baseline))
        cov = Coverage(
            performed=(),
            skipped=tuple(
                CoverageSkip(
                    check=r, reason="adapter-not-applicable", detail="input exceeds size limit"
                )
                for r in ALL_RULES
            ),
            adapter={"id": "unknown", "version": "unknown"},
            profile={"id": effective_cfg.profile, "version": effective_cfg.version},
        )
        return build_report(
            session_id="stdin",
            source_fingerprint="0" * 64,
            tool_version=CLI_VERSION,
            findings=rep_findings,
            assurance="A0",
            limitation="No structural conclusion.",
            coverage=cov,
        )
    return _check_impl(
        Path(virtual_path),
        data=data,
        virtual_path=virtual_path,
        format=format,
        profile=profile,
        confidence_min=confidence_min,
        margin_min=margin_min,
        progress_cb=progress_cb,
        cancel_token=cancel_token,
        select=select,
        ignore=ignore,
        baseline=baseline,
    )


def _check_impl(
    target_path: Path,
    *,
    data: bytes | None,
    virtual_path: str | None,
    format: str | None,
    profile: str,
    confidence_min: float | None,
    margin_min: float | None,
    progress_cb: ProgressCallback | None,
    cancel_token: CancellationToken | None,
    select: Sequence[str] | None,
    ignore: Sequence[str] | None,
    baseline: Collection[str] | None,
) -> Report:
    """Shared check pipeline for file and in-memory byte sources (ux T-06).

    ``data is not None`` selects byte mode: ``virtual_path`` is the display
    path and every filesystem touch is replaced by a buffer/stream equivalent.
    """
    validate_detection_thresholds(confidence_min, margin_min)

    # Narrowing note for mypy --strict: guards on `data`/`virtual_path` use the
    # `is not None` form so Optional types narrow without a flag variable.
    display_path = virtual_path if virtual_path is not None else str(target_path)
    item_name = virtual_path if virtual_path is not None else target_path.name
    item_stem = "stdin" if data is not None else target_path.stem

    if data is None and not target_path.exists():
        raise FileNotFoundError(f"Path not found: {target_path}")

    resolved_profile = apply_rule_selection(profile, select=select, ignore=ignore)
    effective_cfg = resolve_effective_config(
        resolved_profile,
        format=format if format != "auto" else None,
        confidence_min=confidence_min,
        margin_min=margin_min,
    )
    enabled_rules = set(resolved_profile.enabled_rules)
    deselected = deselected_rules(profile, select=select, ignore=ignore)

    # Binary/encoding gate before format detection: a file that cannot decode
    # as UTF-8 (or contains NUL bytes) is unreadable regardless of what its
    # first 64 KiB sniff suggests. Keeps check verdicts consistent with scan,
    # which runs the same probe before classification.
    from sesslint.io import probe_bytes_encoding, probe_text_encoding

    if data is not None:
        enc_probe = probe_bytes_encoding(data)
    else:
        try:
            enc_probe = probe_text_encoding(target_path)
        except OSError:
            enc_probe = None
    if enc_probe is not None:
        det_finding = make_finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message_template=(
                "File contains forbidden NUL byte or binary data"
                if enc_probe == "nul"
                else "File encoding error non-UTF-8"
            ),
            source=SourceRef(path=display_path),
            evidence=(
                {"reason": "encoding_error", "detail": "invalid_utf8"}
                if enc_probe == "utf8"
                else {}
            ),
        )
        rep_findings = [det_finding] if SL001 in enabled_rules else []
        if baseline is not None:
            from sesslint.baseline import filter_findings

            rep_findings = filter_findings(rep_findings, frozenset(baseline))
        if data is not None:
            fp = fingerprint_bytes(data)
        else:
            fp = fingerprint_file(target_path) if target_path.is_file() else "0" * 64
        cov = Coverage(
            performed=(),
            skipped=tuple(
                CoverageSkip(check=r, reason="adapter-not-applicable", detail="file not decodable")
                for r in ALL_RULES
            ),
            adapter={"id": "unknown", "version": "unknown"},
            profile={"id": effective_cfg.profile, "version": effective_cfg.version},
        )
        emit_progress(
            progress_cb,
            ProgressEvent(phase="check:report", completed=4, total=4, item=item_name),
        )
        return build_report(
            session_id=item_stem,
            source_fingerprint=fp,
            tool_version=CLI_VERSION,
            findings=rep_findings,
            assurance="A0",
            limitation="No structural conclusion.",
            coverage=cov,
        )

    if data is not None:
        from sesslint.adapters.detect import resolve_format_bytes

        # Content-only detection: a virtual source has no meaningful filename,
        # so heuristics see a neutral .jsonl name that opens content sniffing
        # without privileging any vendor's filename signature.
        resolved_fmt, detection_res, det_findings = resolve_format_bytes(
            format,
            data,
            filename="stdin.jsonl",
            display_path=display_path,
            confidence_min=effective_cfg.confidence_min,
            margin_min=effective_cfg.margin_min,
        )
    else:
        resolved_fmt, detection_res, det_findings = resolve_format(
            format,
            target_path,
            confidence_min=effective_cfg.confidence_min,
            margin_min=effective_cfg.margin_min,
        )
    emit_progress(
        progress_cb,
        ProgressEvent(phase="check:detect", completed=1, total=4, item=item_name),
    )
    check_token(cancel_token)

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
                    source=SourceRef(path=display_path),
                    evidence={"detail": detection_res.reason if detection_res else "unknown"},
                )
            ]
        )
        rep_findings = [f for f in rep_findings if f.code in enabled_rules]
        if baseline is not None:
            from sesslint.baseline import filter_findings

            rep_findings = filter_findings(rep_findings, frozenset(baseline))
        if data is not None:
            fp = fingerprint_bytes(data)
        else:
            fp = fingerprint_file(target_path) if target_path.is_file() else "0" * 64
        cov = Coverage(
            performed=(),
            skipped=tuple(
                CoverageSkip(
                    check=r, reason="adapter-not-applicable", detail="format detection failed"
                )
                for r in ALL_RULES
            ),
            adapter={"id": "unknown", "version": "unknown"},
            profile={"id": effective_cfg.profile, "version": effective_cfg.version},
        )
        emit_progress(
            progress_cb,
            ProgressEvent(phase="check:report", completed=4, total=4, item=item_name),
        )
        return build_report(
            session_id=item_stem,
            source_fingerprint=fp,
            tool_version=CLI_VERSION,
            findings=rep_findings,
            assurance="A0",
            limitation="No structural conclusion.",
            coverage=cov,
        )

    from sesslint.adapters.load import load_events_for_format, profile_key_for_format

    fmt_key = profile_key_for_format(resolved_fmt)
    if (
        fmt_key not in effective_cfg.allowed_adapters
        and resolved_fmt not in effective_cfg.allowed_adapters
    ):
        raise ValueError(
            f"Format {resolved_fmt} is not permitted by profile {effective_cfg.profile}"
        )

    adapter_findings: list[Finding] = list(det_findings)
    load_source: Path | io.BytesIO = io.BytesIO(data) if data is not None else target_path
    events, loaded_findings = load_events_for_format(load_source, resolved_fmt)
    adapter_findings.extend(loaded_findings)
    # An empty/whitespace-only file is not a valid session of any format —
    # a forced --format must not let it report healthy. (Auto-detect already
    # fails closed via SL302.)
    if not events:
        if data is not None:
            _empty_input = not data.strip()
        else:
            _empty_input = target_path.stat().st_size == 0 or not target_path.read_bytes().strip()
        if _empty_input:
            adapter_findings.append(
                make_finding(
                    code=SL001,
                    severity=Severity.ERROR,
                    repairability=Repairability.MANUAL,
                    message_template="Empty input: file contains no session records",
                    source=SourceRef(path=display_path),
                    evidence={"detail": "empty-or-whitespace-only input"},
                )
            )
    # Version-gating is a fail-closed reliability mechanism, not a reportable
    # finding — it must consult the unfiltered adapter findings so that
    # --ignore SL301 suppresses the report without un-gating unsafe analysis.
    has_version_abort = any(f.code == "SL301" for f in adapter_findings)
    # Detection/reader-stage findings honor the same rule selection as
    # detector-stage ones — --ignore SL302 must silence adapter noise too.
    adapter_findings = [f for f in adapter_findings if f.code in enabled_rules]

    emit_progress(
        progress_cb,
        ProgressEvent(phase="check:load", completed=2, total=4, item=item_name),
    )
    check_token(cancel_token)

    adapter_skips: list[CoverageSkip] = []
    if has_version_abort:
        adapter_skips.append(
            CoverageSkip(
                check="SL301",
                reason="version-gated",
                detail="unsupported format version (SL301)",
            )
        )

    source_meta = getattr(events, "source", None)
    check_ctx = CheckContext.from_profile_and_adapter(
        profile=resolved_profile,
        adapter=resolved_fmt,
        source_metadata=source_meta if isinstance(source_meta, Mapping) else None,
    )

    check_findings, coverage = repair_executor.run_all_checks(
        events,
        profile=resolved_profile,
        source_path=display_path,
        context=check_ctx,
        adapter=resolved_fmt,
        adapter_skips=adapter_skips,
        deselected_rules=deselected,
        return_coverage=True,
    )
    all_findings = list(adapter_findings) + list(check_findings)
    if baseline is not None:
        from sesslint.baseline import filter_findings

        all_findings = filter_findings(all_findings, frozenset(baseline))
    emit_progress(
        progress_cb,
        ProgressEvent(phase="check:analyze", completed=3, total=4, item=item_name),
    )
    check_token(cancel_token)

    session_id: str = item_stem
    if events and hasattr(events[0], "session_id") and events[0].session_id:
        session_id = str(events[0].session_id)

    from sesslint.reference import reference_equivalent_if_clean

    assurance, limitation = compute_assurance(
        events,
        all_findings,
        reference_equivalent=(
            reference_equivalent_if_clean(events, all_findings)
            if resolved_fmt == FORMAT_CANONICAL
            else False
        ),
    )

    fp = fingerprint_bytes(data) if data is not None else fingerprint_file(target_path)
    emit_progress(
        progress_cb,
        ProgressEvent(phase="check:report", completed=4, total=4, item=item_name),
    )
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
    confidence_min: float | None = None,
    margin_min: float | None = None,
    progress_cb: ProgressCallback | None = None,
    cancel_token: CancellationToken | None = None,
    skip_undetected: bool = False,
    select: Sequence[str] | None = None,
    ignore: Sequence[str] | None = None,
    baseline: Collection[str] | None = None,
    exclude: Sequence[str] | None = None,
    ext: Sequence[str] | None = None,
    jobs: int = 1,
    incremental: bool = False,
    cache_dir: Path | str | None = None,
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
        confidence_min: Format auto-detection minimum confidence threshold.
        margin_min: Format auto-detection minimum margin threshold.
        progress_cb: Optional callback receiving ``ProgressEvent`` records per
            inspected file (DW-T-13).
        cancel_token: Optional cooperative cancellation token checked at each
            directory-entry boundary.
        skip_undetected: Classify format-undetected files as ``skipped`` instead
            of ``invalid`` (useful for mixed-content trees and pre-commit hooks).
        select: Optional rule codes to run exclusively.
        ignore: Optional rule codes to skip (mutually exclusive with select).
        baseline: Optional finding fingerprints to suppress per file.
        exclude: Glob patterns for names/root-relative paths to skip entirely.
        ext: File-extension allowlist for directory walks.
        jobs: Worker processes for per-file analysis (default 1 = sequential);
            report bytes are identical for any ``jobs`` value.
        incremental: Reuse cached per-file results when content hash and
            analysis fingerprint match (opt-in sqlite cache, perf-scale T-02).
        cache_dir: Override the default platform cache directory.

    Returns:
        A frozen ScanReport dataclass.
    """
    if isinstance(max_files, bool) or not isinstance(max_files, int) or max_files <= 0:
        raise ValueError(f"max_files must be a positive integer (> 0), got {max_files}")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError(f"max_bytes must be a positive integer (> 0), got {max_bytes}")
    validate_detection_thresholds(confidence_min, margin_min)
    return scan_path(
        path=path,
        recursive=recursive,
        follow_symlinks=follow_symlinks,
        max_files=max_files,
        max_bytes=max_bytes,
        format=format,
        profile=profile,
        confidence_min=confidence_min,
        margin_min=margin_min,
        progress_cb=progress_cb,
        cancel_token=cancel_token,
        skip_undetected=skip_undetected,
        select=select,
        ignore=ignore,
        baseline=frozenset(baseline) if baseline is not None else None,
        exclude=exclude,
        ext=ext,
        jobs=jobs,
        incremental=incremental,
        cache_dir=cache_dir,
    )


def repair(
    source_path: Path | str,
    output_path: Path | str | None,
    *,
    policy: Literal["conservative", "salvage"] = "conservative",
    format: str | None = None,
    profile: str = "neutral",
    plan_path: Path | str | None = None,
    plan: RepairPlan | None = None,
    dry_run: bool = False,
    acknowledge_side_effects: bool = False,
    emit: Literal["auto", "canonical", "vendor"] = "auto",
    progress_cb: ProgressCallback | None = None,
    cancel_token: CancellationToken | None = None,
) -> tuple[RepairPlan, RepairManifest | None]:
    """Safely plan and execute session repair.

    Args:
        source_path: Path to source session file.
        output_path: Path to output repaired session file (required if not dry_run).
        policy: 'conservative' or 'salvage' (default 'conservative').
        format: Optional format adapter override.
        profile: Profile name (default 'neutral').
        plan_path: Optional path to pre-computed plan JSON.
        plan: Optional in-memory RepairPlan to apply directly (mutually
            exclusive with ``plan_path``); the plan is authoritative —
            fingerprint, source binding, and policy are re-validated at
            execution.
        dry_run: If True, computes plan without writing files.
        acknowledge_side_effects: Explicit acknowledgment for salvage policy.
        emit: Output artifact format. 'auto' (default) emits the input's own
            format — canonical in → canonical out; vendor in → vendor write-back
            (drop-only line-verbatim projection). 'canonical' always emits a
            canonical session stream. 'vendor' forces vendor write-back and is
            refused for canonical input.
        progress_cb: Optional callback receiving ``ProgressEvent`` records at
            stage boundaries (``repair:load``, ``repair:plan``,
            ``repair:execute``, ``repair:done``) plus per-step
            ``repair:step`` events during execution — DW-T-13.
        cancel_token: Optional cooperative cancellation token. On cancel,
            ``OperationCancelled`` propagates through the executor's existing
            failure-cleanup path — no partial output or manifest is left
            behind, same as ``KeyboardInterrupt``.

    Returns:
        Tuple of (RepairPlan, RepairManifest or None if dry_run).
    """
    src = Path(source_path)
    if not src.is_file():
        raise FileNotFoundError(f"Source file not found: {src}")

    if emit not in ("auto", "canonical", "vendor"):
        raise ValueError(f"emit must be 'auto', 'canonical', or 'vendor', got {emit!r}")
    if plan is not None and plan_path is not None:
        raise ValueError("plan and plan_path are mutually exclusive")

    # Resolve the input format exactly once (explicit override or a single
    # detection pass under the selected profile's effective thresholds).
    from sesslint.adapters.detect import FORMAT_CANONICAL, detect_format
    from sesslint.repair.errors import VendorRepairRefused

    resolved_format: str
    if format in (None, "auto"):
        effective_cfg = resolve_effective_config(profile)
        det = detect_format(
            src,
            confidence_min=effective_cfg.confidence_min,
            margin_min=effective_cfg.margin_min,
        )
        # Ambiguous/refused detection (format=None) falls back to the canonical
        # path, which fails honestly if the file is not a canonical stream.
        resolved_format = det.format or FORMAT_CANONICAL
    else:
        resolved_format = str(format)

    input_is_vendor = resolved_format in (
        FORMAT_CLAUDE_CODE,
        FORMAT_OPENAI_AGENTS,
        FORMAT_CODEX_ROLLOUT,
    )

    # Resolve the emit target. Vendor write-back projection is supported only
    # for formats in WRITEBACK_FORMATS; other vendor inputs (e.g. codex-rollout)
    # emit canonical output under 'auto'.
    from sesslint.repair.writeback import WRITEBACK_FORMATS

    writeback_capable = resolved_format in WRITEBACK_FORMATS
    if emit == "vendor":
        if not writeback_capable:
            supported = ", ".join(sorted(WRITEBACK_FORMATS))
            if input_is_vendor:
                reason = f"vendor write-back is not implemented for {resolved_format!r}"
            else:
                reason = f"{resolved_format!r} events carry no vendor provenance"
            raise VendorRepairRefused(
                f"Cannot emit vendor output: {reason}. Vendor write-back is "
                f"supported for {supported} inputs. Omit --emit or use "
                "'--emit canonical'."
            )
        emit_format = resolved_format
    elif emit == "canonical":
        emit_format = FORMAT_CANONICAL
    else:  # auto
        emit_format = resolved_format if writeback_capable else FORMAT_CANONICAL

    plan_obj: RepairPlan
    loaded_events: list[SessionEvent] = []
    all_findings: list[Finding] = []
    source_events: list[SessionEvent] | None = None
    source_findings: list[Finding] | None = None
    if (plan_path is None and plan is None) or input_is_vendor:
        # Load for planning. For vendor input these events/findings are also
        # passed to execute(): vendor events carry write-back provenance, and
        # findings locate event-less source lines the plan explicitly discards
        # (e.g. torn terminal record). For canonical input the executor
        # re-loads the source itself (preserving the session header).
        from sesslint.repair.executor import load_source_for_format, run_all_checks

        check_token(cancel_token)
        _source_header, loaded_events, stream_findings = load_source_for_format(
            src, resolved_format
        )
        check_findings = run_all_checks(
            loaded_events,
            profile=profile,
            source_path=src.name,
            adapter=resolved_format,
        )
        all_findings = list(stream_findings) + list(check_findings)
        if input_is_vendor:
            source_events = list(loaded_events)
            source_findings = all_findings
    emit_progress(
        progress_cb,
        ProgressEvent(phase="repair:load", completed=1, total=4, item=src.name),
    )
    check_token(cancel_token)

    if plan is not None:
        plan_obj = plan
    elif plan_path is not None:
        plan_obj = load_plan(plan_path, policy=policy)
    else:
        source_hash = hashlib.sha256(src.read_bytes()).hexdigest()
        import sys

        p_mod = sys.modules.get("sesslint.repair.planner")
        planner_fn = getattr(p_mod, "plan", planner_plan) if p_mod else planner_plan
        plan_obj = planner_fn(
            findings=all_findings,
            events=loaded_events,
            profile=profile,
            policy=policy,
            source_hash=source_hash,
            acknowledge_side_effects=acknowledge_side_effects,
            input_format=resolved_format,
        )
        has_error_findings = any(
            f.severity in (Severity.ERROR, Severity.FATAL) for f in all_findings
        )
        if has_error_findings and len(plan_obj.steps) == 0:
            from sesslint.repair.errors import RepairRefused

            blocked_detail = "; ".join(sorted({f"{b.code}:{b.reason}" for b in plan_obj.blocked}))
            if not blocked_detail:
                blocked_detail = "no repairable findings"
            raise RepairRefused(
                "Findings exist on source session, but no authorized safe "
                f"repair plan completes (blocked: {blocked_detail}). "
                "Run 'sesslint repair <file> --dry-run' for per-finding detail."
            )
    emit_progress(
        progress_cb,
        ProgressEvent(phase="repair:plan", completed=2, total=4, item=src.name),
    )
    check_token(cancel_token)

    exec_format = resolved_format if input_is_vendor else None
    if dry_run:
        execute(
            source_path=src,
            plan=plan_obj,
            output_path=Path(output_path) if output_path is not None else None,
            policy=policy,
            dry_run=True,
            profile=profile,
            format=exec_format,
            emit_format=emit_format,
            acknowledge_side_effects=acknowledge_side_effects,
            source_events=source_events,
            source_findings=source_findings,
            progress_cb=progress_cb,
            cancel_token=cancel_token,
        )
        emit_progress(
            progress_cb,
            ProgressEvent(phase="repair:execute", completed=3, total=4, item=src.name),
        )
        emit_progress(
            progress_cb,
            ProgressEvent(phase="repair:done", completed=4, total=4, item=src.name),
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
        format=exec_format,
        emit_format=emit_format,
        acknowledge_side_effects=acknowledge_side_effects,
        source_events=source_events,
        source_findings=source_findings,
        progress_cb=progress_cb,
        cancel_token=cancel_token,
    )
    emit_progress(
        progress_cb,
        ProgressEvent(phase="repair:execute", completed=3, total=4, item=src.name),
    )
    emit_progress(
        progress_cb,
        ProgressEvent(phase="repair:done", completed=4, total=4, item=src.name),
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
    # Resolve through the module (not the import-time alias) so tests can
    # patch `sesslint.verify.verify` and fault-inject the engine.
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
    acknowledge_side_effects: bool = False,
) -> RepairPlan:
    """Compute a dry-run repair plan for a source session file without writing files.

    Args:
        source_path: Path to source session file.
        policy: 'conservative' or 'salvage' (default 'conservative').
        format: Optional format adapter override.
        profile: Profile name (default 'neutral').
        acknowledge_side_effects: Explicit acknowledgment for salvage policy.

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
        acknowledge_side_effects=acknowledge_side_effects,
    )
    return res


def plan_repair(
    source_path: Path | str,
    *,
    policy: Literal["conservative", "salvage"] = "conservative",
    format: str | None = None,
    profile: str = "neutral",
    acknowledge_side_effects: bool = False,
) -> RepairPlan:
    """Compute a repair plan without writing files (repair-engine T-01).

    Identical to :func:`plan`; the exported plan is serializable via
    ``RepairPlan.to_dict()`` as a ``sesslint.plan/v1`` document for later
    :func:`apply_plan` execution.
    """
    return plan(
        source_path,
        policy=policy,
        format=format,
        profile=profile,
        acknowledge_side_effects=acknowledge_side_effects,
    )


def apply_plan(
    source_path: Path | str,
    plan_doc: RepairPlan | Path | str | Mapping[str, Any],
    *,
    output_path: Path | str | None = None,
    format: str | None = None,
    acknowledge_side_effects: bool = False,
    emit: Literal["auto", "canonical", "vendor"] = "auto",
    dry_run: bool = False,
    progress_cb: ProgressCallback | None = None,
    cancel_token: CancellationToken | None = None,
) -> tuple[RepairPlan, RepairManifest | None]:
    """Execute a previously exported repair plan — plan-authoritative apply.

    The plan document is loaded through the strict deserializer and its own
    ``policy``/``profile`` govern execution; no re-planning occurs. Every
    executor-side validation still applies: plan fingerprint recomputation,
    source-hash binding against the current source bytes/events, TOCTOU
    abstention, and post-execution output audit. A source that drifted since
    plan export is refused (``PlanSourceMismatch``, i.e. plan-stale).

    Args:
        source_path: Path to source session file (must equal the planned one).
        plan_doc: ``RepairPlan``, path to a ``sesslint.plan/v1`` JSON, or a
            plan mapping.
        output_path: Path to output repaired session file (required unless
            ``dry_run``).
        format: Optional format adapter override (auto-detection otherwise).
        acknowledge_side_effects: Explicit acknowledgment for salvage plans.
        emit: Output artifact format ('auto'/'canonical'/'vendor').
        dry_run: Validate plan bindings without writing files.
        progress_cb: Optional progress callback.
        cancel_token: Optional cooperative cancellation token.

    Returns:
        Tuple of (RepairPlan, RepairManifest or None if dry_run).
    """
    if isinstance(plan_doc, RepairPlan):
        plan_obj = plan_doc
    else:
        plan_obj = load_plan(plan_doc)
    derived_policy: Literal["conservative", "salvage"] = (
        "salvage" if plan_obj.policy == "salvage" else "conservative"
    )
    return repair(
        source_path,
        output_path,
        policy=derived_policy,
        format=format,
        profile=plan_obj.profile,
        plan=plan_obj,
        dry_run=dry_run,
        acknowledge_side_effects=acknowledge_side_effects,
        emit=emit,
        progress_cb=progress_cb,
        cancel_token=cancel_token,
    )


def repair_preview(
    source_path: Path | str,
    *,
    format: str | None = None,
    policy: Literal["conservative", "salvage"] = "conservative",
    profile: str = "neutral",
    acknowledge_side_effects: bool = False,
) -> PreviewDoc:
    """Structural repair preview — what a repair would do, without writes.

    Returns a ``sesslint.preview/v1`` document: content-free delta rows
    (drop/relink/discard-tail/dedupe with bounded identifiers and rule codes)
    plus blocked findings with pinned reasons. Deterministic on identical
    input. See :func:`sesslint.preview.repair_preview`.
    """
    from sesslint.preview import repair_preview as _repair_preview

    return _repair_preview(
        source_path,
        format=format,
        policy=policy,
        profile=profile,
        acknowledge_side_effects=acknowledge_side_effects,
    )


def repair_many(
    files: Sequence[Path | str],
    *,
    output_dir: Path | str,
    manifest_dir: Path | str | None = None,
    common_root: Path | str | None = None,
    policy: Literal["conservative", "salvage"] = "conservative",
    format: str | None = None,
    profile: str = "neutral",
    acknowledge_side_effects: bool = False,
    emit: Literal["auto", "canonical", "vendor"] = "auto",
    dry_run: bool = False,
    progress_cb: ProgressCallback | None = None,
    cancel_token: CancellationToken | None = None,
) -> BatchRepairReport:
    """Repair every eligible file in ``files`` into ``output_dir`` (repair T-02).

    Eligibility reuses the planner's classification verbatim: a file is
    attempted only when its plan has steps and zero blocked findings.
    Files are processed in sorted-path order; outputs mirror the input's
    relative structure under ``output_dir``. See
    :func:`sesslint.batch.repair_many` for full semantics.
    """
    from sesslint.batch import repair_many as _repair_many

    return _repair_many(
        files,
        output_dir=output_dir,
        manifest_dir=manifest_dir,
        common_root=common_root,
        policy=policy,
        format=format,
        profile=profile,
        acknowledge_side_effects=acknowledge_side_effects,
        emit=emit,
        dry_run=dry_run,
        progress_cb=progress_cb,
        cancel_token=cancel_token,
    )


def check(
    path: Path | str,
    *,
    format: str | None = None,
    profile: str = "neutral",
    recursive: bool = True,
    follow_symlinks: bool = False,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes: int = DEFAULT_MAX_BYTES,
    confidence_min: float | None = None,
    margin_min: float | None = None,
    progress_cb: ProgressCallback | None = None,
    cancel_token: CancellationToken | None = None,
    select: Sequence[str] | None = None,
    ignore: Sequence[str] | None = None,
    baseline: Collection[str] | None = None,
    exclude: Sequence[str] | None = None,
    ext: Sequence[str] | None = None,
) -> Report | ScanReport:
    """Unified check dispatcher: evaluates a single session file or scans a directory tree.

    Args:
        path: Path to session file or directory.
        format: Format override ('auto', None, or known format name).
        profile: Validation profile name (default 'neutral').
        recursive: Whether to scan directory recursively (default True).
        follow_symlinks: Whether to follow symlinks in directory scan (default False).
        max_files: Maximum files to scan in directory mode.
        max_bytes: Maximum cumulative bytes in directory mode.
        confidence_min: Format detection minimum confidence threshold.
        margin_min: Format detection minimum margin threshold.
        progress_cb: Optional callback receiving ``ProgressEvent`` records
            (DW-T-13).
        cancel_token: Optional cooperative cancellation token.
        select: Optional rule codes to run exclusively.
        ignore: Optional rule codes to skip (mutually exclusive with select).
        baseline: Optional finding fingerprints to suppress.
        exclude: Glob patterns to skip in directory walks.
        ext: File-extension allowlist for directory walks.

    Returns:
        Report instance for single file, or ScanReport instance for directory.

    Raises:
        FileNotFoundError: If path does not exist.
    """
    target_path = Path(path)
    if not target_path.exists():
        raise FileNotFoundError(f"Path not found: {target_path}")

    if target_path.is_dir():
        return check_dir(
            target_path,
            recursive=recursive,
            follow_symlinks=follow_symlinks,
            max_files=max_files,
            max_bytes=max_bytes,
            format=format,
            profile=profile,
            confidence_min=confidence_min,
            margin_min=margin_min,
            progress_cb=progress_cb,
            cancel_token=cancel_token,
            select=select,
            ignore=ignore,
            baseline=baseline,
            exclude=exclude,
            ext=ext,
        )
    return check_file(
        target_path,
        format=format,
        profile=profile,
        confidence_min=confidence_min,
        margin_min=margin_min,
        progress_cb=progress_cb,
        cancel_token=cancel_token,
        select=select,
        ignore=ignore,
        baseline=baseline,
    )


def validate_session(path: Path | str) -> Session:
    """Validate and parse a canonical session file, returning the frozen Session instance.

    Args:
        path: Path to the canonical session file (JSON or JSONL).

    Returns:
        A strongly-typed, immutable Session instance.

    Raises:
        FileNotFoundError: If the file does not exist.
        SchemaError: If the file fails canonical schema validation.
    """
    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(f"Session file not found: {target}")
    return load_session_file(target)


def build_internal_error_envelope(
    err: Exception,
    error_id: str | None = None,
) -> dict[str, str]:
    """Construct a structured JSON envelope for unexpected internal errors (FR-097, FR-098)."""
    import secrets

    eid = error_id if error_id is not None else f"ERR-{secrets.token_hex(4)}"
    return {
        "code": "INTERNAL_ERROR",
        "error_id": eid,
        "message": str(err),
        "verdict": "error",
    }


def doctor_report(
    *,
    agents: Sequence[str] | None = None,
    quick_checks: bool = True,
) -> DoctorReport:
    """Collect read-only environment diagnostics (sesslint.doctor/v1).

    Reports tool/adapter versions, the resolved config file, and per-agent
    session-root diagnostics (existence, bounded file counts, newest mtime,
    quick verdicts on the newest files). Counts and timestamps only —
    never file names or payloads.
    """
    from sesslint.doctor import doctor_report as _doctor_report

    return _doctor_report(agents=agents, quick_checks=quick_checks)


def stats_paths(
    paths: Sequence[Path | str],
    *,
    recursive: bool = False,
    format: str | None = None,
) -> SessionStats:
    """Aggregate content-free statistics over session files or directories.

    Counters only — never payload values, never raw tool names (truncated
    sha256 hashes), paths minimized. Deterministic output.

    Raises:
        FileNotFoundError: If a path does not exist.
        ValueError: If a directory is passed without ``recursive=True``.
    """
    from sesslint.stats import stats_paths as _stats_paths

    return _stats_paths(paths, recursive=recursive, format=format)


def diff_sessions(
    a: Path | str,
    b: Path | str,
    *,
    format_a: str | None = None,
    format_b: str | None = None,
) -> SessionDiff:
    """Compare two session files structurally (event-identity alignment).

    Both inputs go through normal detection + adapter parse; deltas are
    content-free (bounded ids, kinds, indices, content hashes only).

    Raises:
        FileNotFoundError: If either path does not exist.
        DiffInputError: If either input fails detection or load.
    """
    from sesslint.diff import diff_sessions as _diff_sessions

    return _diff_sessions(a, b, format_a=format_a, format_b=format_b)


def export_file(
    source_path: Path | str,
    output_path: Path | str,
    *,
    format: str | None = None,
) -> ExportSummary:
    """Export a supported session artifact to a byte-deterministic canonical file.

    Args:
        source_path: Path to source session file.
        output_path: Destination path for the canonical file (must not exist).
        format: Format override ('auto', None, or known format name).

    Returns:
        Content-free ExportSummary describing the projection.
    """
    from sesslint.exporter import export_to_canonical

    return export_to_canonical(source_path, output_path, format=format)


@dataclass(frozen=True, slots=True)
class DiscoveredRoot:
    """A candidate well-known agent session root for scan auto-discovery (DW-T-05).

    ``exists`` is True only when the candidate is a real directory at the root
    level (a symlinked root resolves False so callers never traverse a link
    they did not explicitly opt into).
    """

    agent: str
    path: Path
    exists: bool
    source: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize with path minimized (content-free, privacy-safe)."""
        from sesslint.report import minimize_path

        return {
            "agent": self.agent,
            "exists": self.exists,
            "path": minimize_path(self.path),
            "source": self.source,
        }


def discover_session_roots(
    agents: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> tuple[DiscoveredRoot, ...]:
    """Enumerate well-known agent session roots in deterministic order (DW-T-05).

    Read-only: performs no writes and creates no directories. Candidates, in
    order: ``claude`` → ``$CLAUDE_CONFIG_DIR/projects/`` else
    ``~/.claude/projects/``; ``codex`` → ``$CODEX_HOME/sessions/`` else
    ``~/.codex/sessions/``. ``env`` and ``home`` are injectable for testing.
    """
    environ = os.environ if env is None else env
    home_dir = Path.home() if home is None else home
    selected = tuple(agents) if agents is not None else ("claude", "codex")

    roots: list[DiscoveredRoot] = []
    for agent in selected:
        if agent == "claude":
            override = environ.get("CLAUDE_CONFIG_DIR", "").strip()
            if override:
                candidate = Path(override) / "projects"
                source = "env"
            else:
                candidate = home_dir / ".claude" / "projects"
                source = "default"
        elif agent == "codex":
            override = environ.get("CODEX_HOME", "").strip()
            if override:
                candidate = Path(override) / "sessions"
                source = "env"
            else:
                candidate = home_dir / ".codex" / "sessions"
                source = "default"
        else:
            raise ValueError(f"Unknown agent {agent!r}: expected 'claude' or 'codex'")
        roots.append(
            DiscoveredRoot(
                agent=agent,
                path=candidate,
                exists=candidate.is_dir() and not candidate.is_symlink(),
                source=source,
            )
        )
    return tuple(roots)


__all__ = [
    "BatchRepairReport",
    "Bundle",
    "CancellationToken",
    "DiscoveredRoot",
    "ExportSummary",
    "OperationCancelled",
    "PrecheckReason",
    "PreviewDoc",
    "PrecheckResult",
    "ProgressEvent",
    "ScanReport",
    "SessionDiff",
    "DoctorReport",
    "SessionStats",
    "VerifyVerdict",
    "build_bundle",
    "build_internal_error_envelope",
    "check",
    "check_bytes",
    "check_dir",
    "check_file",
    "diff_sessions",
    "stats_paths",
    "discover_session_roots",
    "doctor_report",
    "export_file",
    "plan",
    "plan_repair",
    "apply_plan",
    "repair_many",
    "repair_preview",
    "precheck",
    "repair",
    "scan_bytes",
    "validate_session",
    "verify",
]
