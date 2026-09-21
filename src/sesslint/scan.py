"""Filesystem scanning with recursive walk, 5-bucket totals, and safety guards (TASK-024).

Implements directory scanning for session artifacts with:
- Iterative walk with cycle detection
- Symlink safety (no-follow by default, loop guards)
- Special file isolation (FIFO, socket, character/block devices ignored)
- Hardlink and repeat-path deduplication via (st_dev, st_ino)
- Bounded file-count and byte-count caps
- Strict 5-bucket classification: healthy, invalid, unsupported, unreadable, skipped
"""

from __future__ import annotations

import fnmatch
import io
import json
import os
import stat
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, Literal, cast

from sesslint.codes import SL001, SL301, SL302, SL401, SL402, Repairability, Severity
from sesslint.errors import FileTooLargeError, MaxRecordsExceededError
from sesslint.finding import SEVERITY_ORDER, Finding, SourceRef, make_finding
from sesslint.indexes import INDEX_FILE_NAMES
from sesslint.io import probe_bytes_encoding, probe_text_encoding, sha256_file_bytes
from sesslint.profiles import (
    EffectiveConfig,
    Profile,
    apply_rule_selection,
    resolve_effective_config,
)
from sesslint.progress import (
    CancellationToken,
    ProgressCallback,
    ProgressEvent,
    check_token,
    emit,
)
from sesslint.report import minimize_path, short_hash

if TYPE_CHECKING:
    from sesslint.cache import ScanCache

Verdict = Literal["healthy", "invalid", "unsupported", "unreadable", "skipped"]

DEFAULT_MAX_FILES: int = 10000
DEFAULT_MAX_BYTES: int = 1024 * 1024 * 1024  # 1GB


@dataclass(frozen=True, slots=True)
class SessionLink:
    """Bounded cross-file resume pointer extracted by an adapter (SL401).

    ``kind`` is ``session_ref`` (points at a predecessor session/file, resolved
    against scanned session ids and filename stems) or ``head_ref`` (points at
    a predecessor session's tip event, resolved against per-file tip ids).
    ``target`` is the declared structural identifier — never payload content.
    Internal resolution metadata only: it rides the worker wire payload but is
    deliberately absent from ``FileResult.to_dict`` (report shape unchanged).
    """

    kind: str
    target: str
    record_id: str | None = None
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "line": self.line,
            "record_id": self.record_id,
            "target": self.target,
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> SessionLink:
        return cls(
            kind=str(d["kind"]),
            target=str(d["target"]),
            record_id=d.get("record_id"),
            line=d.get("line"),
        )


@dataclass(frozen=True, slots=True)
class FileResult:
    """Outcome of scanning an individual file artifact."""

    path: str
    verdict: Verdict
    findings: tuple[Finding, ...] = ()
    skipped_reason: str | None = None
    error_count: int = 0
    warning_count: int = 0
    cache_hit: bool = False
    links: tuple[SessionLink, ...] = ()
    session_id: str | None = None
    tip_id: str | None = None
    detected_format: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize file result to canonical JSON-compatible dictionary."""
        from sesslint.report import format_finding_content_free, minimize_path

        res: dict[str, Any] = {
            "error_count": self.error_count,
            "path": minimize_path(self.path),
            "verdict": self.verdict,
            "warning_count": self.warning_count,
        }
        if self.skipped_reason is not None:
            res["skipped_reason"] = self.skipped_reason
        if self.cache_hit:
            res["cache"] = "hit"
        if self.findings:
            res["findings"] = [format_finding_content_free(f) for f in self.findings]
        return res

    def to_wire(self) -> dict[str, Any]:
        """Full-fidelity payload for crossing process boundaries (parallel scan).

        Unlike ``to_dict`` (the content-minimized report shape), the wire form
        preserves the path string verbatim and complete ``Finding.to_dict``
        payloads so ``from_wire`` restores an equal object.
        """
        return {
            "path": self.path,
            "verdict": self.verdict,
            "skipped_reason": self.skipped_reason,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "cache_hit": self.cache_hit,
            "links": [lk.to_dict() for lk in self.links],
            "session_id": self.session_id,
            "tip_id": self.tip_id,
            "detected_format": self.detected_format,
            "findings": [f.to_dict() for f in self.findings],
        }

    @classmethod
    def from_wire(cls, d: Mapping[str, Any]) -> FileResult:
        """Reconstruct a FileResult from a ``to_wire`` payload."""
        return cls(
            path=d["path"],
            verdict=d["verdict"],
            skipped_reason=d.get("skipped_reason"),
            error_count=d.get("error_count", 0),
            warning_count=d.get("warning_count", 0),
            cache_hit=bool(d.get("cache_hit", False)),
            links=tuple(SessionLink.from_dict(lk) for lk in d.get("links", ())),
            session_id=d.get("session_id"),
            tip_id=d.get("tip_id"),
            detected_format=d.get("detected_format"),
            findings=tuple(Finding.from_dict(f) for f in d.get("findings", ())),
        )


@dataclass(frozen=True, slots=True)
class ScanTotals:
    """Aggregate counts partitioned into 5 mutually exclusive buckets."""

    healthy: int = 0
    invalid: int = 0
    unsupported: int = 0
    unreadable: int = 0
    skipped: int = 0

    @property
    def total(self) -> int:
        """Total number of scanned or evaluated items."""
        return self.healthy + self.invalid + self.unsupported + self.unreadable + self.skipped

    def to_dict(self) -> dict[str, int]:
        """Serialize totals to sorted dictionary."""
        return {
            "healthy": self.healthy,
            "invalid": self.invalid,
            "skipped": self.skipped,
            "total": self.total,
            "unreadable": self.unreadable,
            "unsupported": self.unsupported,
        }


@dataclass(frozen=True, slots=True)
class ByCodeRow:
    """One aggregated rule-code row: total findings and affected files."""

    code: str
    severity: str
    count: int
    files: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize the row to a canonical JSON-compatible dictionary."""
        return {
            "code": self.code,
            "count": self.count,
            "files": self.files,
            "severity": self.severity,
        }


@dataclass(frozen=True, slots=True)
class WorstFileRow:
    """One worst-file row ranked by error count then warning count."""

    path: str
    error_count: int
    warning_count: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize the row to a canonical JSON-compatible dictionary."""
        from sesslint.report import minimize_path

        return {
            "error_count": self.error_count,
            "path": minimize_path(self.path),
            "warning_count": self.warning_count,
        }


@dataclass(frozen=True, slots=True)
class ScanSummary:
    """Presentation-layer aggregation over scan file results (T-08).

    Contains only codes, counts, and paths — the same content-free
    vocabulary the report already uses.
    """

    by_code: tuple[ByCodeRow, ...] = ()
    worst_files: tuple[WorstFileRow, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialize summary to a canonical JSON-compatible dictionary."""
        return {
            "by_code": [r.to_dict() for r in self.by_code],
            "worst_files": [r.to_dict() for r in self.worst_files],
        }


@dataclass(frozen=True, slots=True)
class ScanReport:
    """Top-level report containing per-file results and aggregate 5-bucket totals."""

    schema_version: str = "sesslint.scan-report/v1"
    root_path: str = ""
    totals: ScanTotals = field(default_factory=ScanTotals)
    files: tuple[FileResult, ...] = ()
    summary: ScanSummary | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize scan report to canonical JSON-compatible dictionary."""
        res: dict[str, Any] = {
            "files": [f.to_dict() for f in self.files],
            "root_path": self.root_path,
            "schema_version": self.schema_version,
            "totals": self.totals.to_dict(),
        }
        if self.summary is not None:
            res["summary"] = self.summary.to_dict()
        return res

    def to_json(self) -> str:
        """Serialize scan report to formatted JSON string."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


SCAN_SCHEMA_VERSION: str = "sesslint.scan-report/v1"


def get_scan_schema_path() -> Path:
    """Return the filesystem path to schemas/sesslint.scan-report.v1.json."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    dev_path = repo_root / "schemas" / "sesslint.scan-report.v1.json"
    if dev_path.is_file():
        return dev_path
    prefix_path = (
        Path(sys.prefix) / "share" / "sesslint" / "schemas" / "sesslint.scan-report.v1.json"
    )
    if prefix_path.is_file():
        return prefix_path
    return dev_path


def load_scan_schema() -> dict[str, Any]:
    """Load the committed JSON Schema for sesslint.scan-report/v1 as a dict."""
    schema_path = get_scan_schema_path()
    if not schema_path.is_file():
        raise FileNotFoundError(f"Scan report schema not found at {schema_path}")
    return cast(dict[str, Any], json.loads(schema_path.read_text(encoding="utf-8")))


def aggregate_scan(
    files: Iterable[FileResult],
    *,
    top: int = 10,
    group_by: str = "code",
) -> ScanSummary:
    """Aggregate per-file results into by-code and worst-file views (T-08).

    Args:
        files: Per-file scan results to aggregate.
        top: Maximum worst-file rows; 0 disables the worst-files view.
        group_by: ``"code"`` groups findings by rule code; ``"none"``
            disables the by-code view.

    Returns:
        A deterministic ``ScanSummary`` — by_code rows sort by severity
        rank then count desc then code; worst_files rank by error count
        desc then warning count desc then path.
    """
    if top < 0:
        raise ValueError(f"top must be >= 0, got {top}")
    if group_by not in ("code", "none"):
        raise ValueError(f"group_by must be 'code' or 'none', got {group_by!r}")

    by_code: tuple[ByCodeRow, ...] = ()
    if group_by == "code":
        counts: dict[str, int] = {}
        file_sets: dict[str, set[str]] = {}
        severities: dict[str, Severity] = {}
        for fr in files:
            seen_in_file: set[str] = set()
            for f in fr.findings:
                counts[f.code] = counts.get(f.code, 0) + 1
                prev_sev = severities.get(f.code)
                if prev_sev is None or SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[prev_sev]:
                    severities[f.code] = f.severity
                if f.code not in seen_in_file:
                    seen_in_file.add(f.code)
                    file_sets.setdefault(f.code, set()).add(fr.path)
        by_code = tuple(
            ByCodeRow(
                code=code,
                severity=severities[code].value,
                count=counts[code],
                files=len(file_sets[code]),
            )
            for code in sorted(counts, key=lambda c: (SEVERITY_ORDER[severities[c]], -counts[c], c))
        )

    worst_files: tuple[WorstFileRow, ...] = ()
    if top > 0:
        ranked = sorted(
            (fr for fr in files if fr.error_count > 0 or fr.warning_count > 0),
            key=lambda fr: (-fr.error_count, -fr.warning_count, fr.path),
        )
        worst_files = tuple(
            WorstFileRow(
                path=fr.path,
                error_count=fr.error_count,
                warning_count=fr.warning_count,
            )
            for fr in ranked[:top]
        )

    return ScanSummary(by_code=by_code, worst_files=worst_files)


def _scan_single_file(
    file_path: Path,
    *,
    format: str | None = None,
    effective_cfg: EffectiveConfig,
    skip_undetected: bool = False,
    resolved_profile: Profile | None = None,
    baseline: frozenset[str] | None = None,
) -> FileResult:
    """Evaluate a single regular file artifact, mapping to one of 4 active buckets."""
    return _scan_single_source(
        file_path,
        minimize_path(file_path),
        data=None,
        format=format,
        effective_cfg=effective_cfg,
        skip_undetected=skip_undetected,
        resolved_profile=resolved_profile,
        baseline=baseline,
    )


def _scan_single_source(
    file_path: Path,
    display_path: str,
    *,
    data: bytes | None,
    format: str | None = None,
    effective_cfg: EffectiveConfig,
    skip_undetected: bool = False,
    resolved_profile: Profile | None = None,
    baseline: frozenset[str] | None = None,
) -> FileResult:
    """Per-source evaluation shared by file and in-memory byte inputs (ux T-06).

    ``data is not None`` selects byte mode: ``display_path`` is taken verbatim
    and every filesystem touch is replaced by the buffer equivalent.
    """
    source_path_str = display_path if data is not None else str(file_path)

    # 1. Read file with I/O and non-UTF8 / binary safety
    oversize = False
    if data is not None:
        oversize = len(data) > DEFAULT_MAX_BYTES
    else:
        try:
            oversize = file_path.stat().st_size > DEFAULT_MAX_BYTES
        except OSError:
            pass
    if oversize:
        finding = make_finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message_template="Unreadable file [detail: LIMIT_OR_IO]",
            source=SourceRef(path=display_path),
            evidence={"reason": "limit_or_io_error", "detail": "FileTooLargeError"},
        )
        return FileResult(
            path=display_path,
            verdict="unreadable",
            findings=(finding,),
            error_count=1,
            warning_count=0,
        )

    # Binary check: NUL byte or invalid UTF-8 anywhere in the file, probed in
    # bounded chunks (DW-T-11). Semantics are identical to a whole-file read:
    # any NUL byte or undecodable sequence — head or tail — classifies the
    # file unreadable before JSON decoding is attempted.
    if data is not None:
        probe = probe_bytes_encoding(data)
    else:
        try:
            probe = probe_text_encoding(file_path)
        except OSError:
            finding = make_finding(
                code=SL001,
                severity=Severity.ERROR,
                repairability=Repairability.MANUAL,
                message_template="Unreadable file or I/O error",
                source=SourceRef(path=display_path),
                evidence={"reason": "os_error", "detail": "io_error"},
            )
            return FileResult(
                path=display_path,
                verdict="unreadable",
                findings=(finding,),
                error_count=1,
                warning_count=0,
            )

    if probe == "nul":
        finding = make_finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message_template="File contains forbidden NUL byte or binary data",
            source=SourceRef(path=display_path),
        )
        return FileResult(
            path=display_path,
            verdict="unreadable",
            findings=(finding,),
            error_count=1,
            warning_count=0,
        )

    if probe == "utf8":
        finding = make_finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message_template="File encoding error non-UTF-8",
            source=SourceRef(path=display_path),
            evidence={"reason": "encoding_error", "detail": "invalid_utf8"},
        )
        return FileResult(
            path=display_path,
            verdict="unreadable",
            findings=(finding,),
            error_count=1,
            warning_count=0,
        )

    # 2. Format resolution, 3. Adapter loading, 4. Invariant checks, 5. Bucket classification
    # Rule selection applies to detection/reader-stage findings too (not just
    # detector-stage): --ignore SL302 must silence adapter-level noise.
    enabled_rules = (
        set(resolved_profile.enabled_rules)
        if resolved_profile is not None
        else set(effective_cfg.enabled_rules)
    )
    try:
        from sesslint.adapters.detect import resolve_format, resolve_format_bytes

        if data is not None:
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
                file_path,
                confidence_min=effective_cfg.confidence_min,
                margin_min=effective_cfg.margin_min,
            )
        if resolved_fmt is None:
            if skip_undetected:
                return FileResult(
                    path=display_path,
                    verdict="skipped",
                    skipped_reason="format-undetected",
                )
            rep_findings = list(det_findings)
            if not rep_findings:
                rep_findings.append(
                    make_finding(
                        code=SL302,
                        severity=Severity.ERROR,
                        repairability=Repairability.MANUAL,
                        message_template="Format detection failed",
                        source=SourceRef(path=display_path),
                        evidence={"detail": detection_res.reason if detection_res else "unknown"},
                    )
                )
            rep_findings = [f for f in rep_findings if f.code in enabled_rules]
            err_c = sum(1 for f in rep_findings if f.severity in (Severity.ERROR, Severity.FATAL))
            warn_c = sum(1 for f in rep_findings if f.severity == Severity.WARNING)
            return FileResult(
                path=display_path,
                verdict="invalid",
                findings=tuple(rep_findings),
                error_count=err_c,
                warning_count=warn_c,
            )

        from sesslint.adapters.load import load_events_for_format, profile_key_for_format

        fmt_key = profile_key_for_format(resolved_fmt)
        if (
            fmt_key not in effective_cfg.allowed_adapters
            and resolved_fmt not in effective_cfg.allowed_adapters
        ):
            finding = make_finding(
                code=SL302,
                severity=Severity.ERROR,
                repairability=Repairability.MANUAL,
                message_template="Format is not permitted by profile",
                source=SourceRef(path=display_path),
                evidence={"format": resolved_fmt, "profile": effective_cfg.profile},
            )
            return FileResult(
                path=display_path,
                verdict="invalid",
                findings=(finding,),
                error_count=1,
                warning_count=0,
            )

        # 3. Adapter loading — single dispatch shared with check/export/verify
        # so every supported format (incl. codex-rollout) loads identically.
        adapter_findings: list[Finding] = list(det_findings)
        load_source: Path | io.BytesIO = io.BytesIO(data) if data is not None else file_path
        events, loaded_findings = load_events_for_format(load_source, resolved_fmt)
        adapter_findings.extend(loaded_findings)
        # An empty/whitespace-only file is not a valid session of any format —
        # a forced --format must not let it report healthy.
        if not events:
            if data is not None:
                _empty = not data.strip()
            else:
                _empty = file_path.stat().st_size == 0 or not file_path.read_bytes().strip()
            if _empty:
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
        adapter_findings = [f for f in adapter_findings if f.code in enabled_rules]

        # 4. Invariant checks
        from sesslint.context import CheckContext
        from sesslint.repair.executor import run_all_checks

        check_profile: Profile | str = (
            resolved_profile if resolved_profile is not None else effective_cfg.profile
        )
        source_meta = getattr(events, "source", None)
        check_ctx = CheckContext.from_profile_and_adapter(
            profile=check_profile,
            adapter=resolved_fmt,
            source_metadata=source_meta if isinstance(source_meta, Mapping) else None,
        )

        try:
            check_findings = run_all_checks(
                events,
                profile=check_profile,
                source_path=source_path_str,
                context=check_ctx,
                adapter=resolved_fmt,
            )
        except TypeError:
            check_findings = run_all_checks(
                events,
                profile=effective_cfg.profile,
                source_path=source_path_str,
            )
        all_findings_list: list[Finding] = adapter_findings + list(check_findings)
        if baseline is not None:
            from sesslint.baseline import filter_findings

            all_findings_list = filter_findings(all_findings_list, baseline)
        all_findings = tuple(all_findings_list)

        err_count = sum(1 for f in all_findings if f.severity in (Severity.ERROR, Severity.FATAL))
        warn_count = sum(1 for f in all_findings if f.severity == Severity.WARNING)

        # 5. Bucket classification
        has_sl301 = any(f.code == SL301 for f in all_findings)
        if has_sl301:
            verdict: Verdict = "unsupported"
        elif err_count > 0:
            verdict = "invalid"
        else:
            verdict = "healthy"

        # Cross-file link metadata (SL401): bounded pointers surfaced by the
        # adapter on ``events.source`` plus the file's declared session id and
        # tip event id. Resolution happens once per scan — never per file.
        scan_links: tuple[SessionLink, ...] = ()
        scan_session_id: str | None = None
        if isinstance(source_meta, Mapping):
            raw_links = source_meta.get("links")
            if isinstance(raw_links, list):
                scan_links = tuple(
                    SessionLink(
                        kind=str(lk["kind"]),
                        target=str(lk["target"]),
                        record_id=lk.get("record_id"),
                        line=lk.get("line"),
                    )
                    for lk in raw_links
                    if isinstance(lk, Mapping) and "kind" in lk and "target" in lk
                )
            sid = source_meta.get("session_id")
            if isinstance(sid, str) and sid.strip():
                scan_session_id = sid.strip()
        scan_tip_id = events[-1].id if events else None

        return FileResult(
            path=display_path,
            verdict=verdict,
            findings=all_findings,
            error_count=err_count,
            warning_count=warn_count,
            links=scan_links,
            session_id=scan_session_id,
            tip_id=scan_tip_id,
            detected_format=resolved_fmt,
        )
    except (FileTooLargeError, MaxRecordsExceededError, OSError) as err:
        f = make_finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message_template="Unreadable file [detail: LIMIT_OR_IO]",
            source=SourceRef(path=display_path),
            evidence={"reason": "limit_or_io_error", "detail": type(err).__name__},
        )
        return FileResult(
            path=display_path,
            verdict="unreadable",
            findings=(f,),
            error_count=1,
            warning_count=0,
        )
    except Exception as err:
        f = make_finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message_template="Failed to process file [detail: INTERNAL_ERROR]",
            source=SourceRef(path=display_path),
            evidence={"reason": "unhandled_exception", "detail": type(err).__name__},
        )
        return FileResult(
            path=display_path,
            verdict="invalid",
            findings=(f,),
            error_count=1,
            warning_count=0,
        )


# --- Parallel scan workers (--jobs N > 1) -----------------------------------
#
# Worker pool contract: the parent resolves the file list and all caps during
# the sequential walk; workers only run _scan_single_file and return wire
# payloads. Results merge in submission order and the final report sorts by
# path, so output bytes are identical to jobs=1.
_WORKER_KWARGS: dict[str, Any] | None = None


def _init_scan_worker(cfg: Mapping[str, Any]) -> None:
    """Pool initializer: resolve effective config once per worker process."""
    global _WORKER_KWARGS
    resolved_profile = apply_rule_selection(
        str(cfg["profile"]), select=cfg["select"], ignore=cfg["ignore"]
    )
    fmt = cfg["format"]
    effective_cfg = resolve_effective_config(
        resolved_profile,
        format=fmt if fmt != "auto" else None,
        confidence_min=cfg["confidence_min"],
        margin_min=cfg["margin_min"],
    )
    baseline_list = cfg["baseline"]
    _WORKER_KWARGS = {
        "format": fmt,
        "effective_cfg": effective_cfg,
        "skip_undetected": cfg["skip_undetected"],
        "resolved_profile": resolved_profile,
        "baseline": frozenset(baseline_list) if baseline_list else None,
    }


def _scan_file_worker(path_str: str) -> dict[str, Any]:
    """Pool task: scan one file, return its FileResult wire payload.

    Never raises — failures map to an ``unreadable`` result identical to the
    sequential catch-all so one bad file cannot abort the pool.
    """
    disp_path = minimize_path(path_str)
    try:
        res = _scan_single_file(Path(path_str), **(_WORKER_KWARGS or {}))
    except Exception as err:
        f = make_finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message_template="Unreadable file [detail: INTERNAL_ERROR]",
            source=SourceRef(path=disp_path),
            evidence={"reason": "unhandled_exception", "detail": type(err).__name__},
        )
        res = FileResult(path=disp_path, verdict="unreadable", findings=(f,), error_count=1)
    return res.to_wire()


def scan_path(
    path: Path | str,
    *,
    recursive: bool = False,
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
    baseline: frozenset[str] | None = None,
    exclude: Sequence[str] | None = None,
    ext: Sequence[str] | None = None,
    jobs: int = 1,
    incremental: bool = False,
    cache_dir: Path | str | None = None,
) -> ScanReport:
    """Scan a target path or directory tree, returning a ScanReport with 5-bucket totals.

    When ``progress_cb`` is attached, one ``ProgressEvent(phase="scan")`` is
    emitted per file actually inspected (skipped/special files do not emit);
    ``total`` is ``None`` because the file count is not pre-walked (DW-T-13).
    ``cancel_token`` is checked at each directory-entry boundary.
    When ``skip_undetected`` is True, files whose format cannot be detected are
    classified ``skipped`` (``format-undetected``) instead of ``invalid`` —
    useful for hooks and mixed-content trees where non-session files exist.
    ``exclude`` drops entries whose name or path (relative to the scan root)
    matches a glob — directories excluded this way are not descended. ``ext``
    is an extension allowlist (``.jsonl``/``jsonl``) applied to files only;
    non-matching files are out of scope and never probed. Both filters apply
    to directory walks only, never to an explicitly named path.
    ``jobs`` > 1 dispatches per-file analysis to a worker pool while the walk,
    caps, and merge stay in the parent — report bytes are identical to
    ``jobs=1``. Single-file input always runs inline regardless of ``jobs``.
    ``incremental`` enables an opt-in sqlite result cache (perf-scale T-02):
    files whose content hash and analysis fingerprint match a stored row
    replay their cached result with ``cache_hit=True`` instead of
    re-analysis; ``unreadable`` verdicts are never cached. ``cache_dir``
    overrides the default platform cache location. Cache failures degrade
    to an uncached scan — never to an error.
    """
    if isinstance(max_files, bool) or not isinstance(max_files, int) or max_files <= 0:
        raise ValueError(f"max_files must be a positive integer (> 0), got {max_files}")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError(f"max_bytes must be a positive integer (> 0), got {max_bytes}")
    if isinstance(jobs, bool) or not isinstance(jobs, int) or jobs < 1:
        raise ValueError(f"jobs must be a positive integer (>= 1), got {jobs}")

    target = Path(path)
    root_str = minimize_path(target)

    if not target.exists() and not target.is_symlink():
        raise FileNotFoundError(f"Path not found: {target}")

    # Resolve exactly one effective configuration for the whole scan; every per-file
    # detection below uses these thresholds rather than re-resolving per file.
    from sesslint.adapters.detect import validate_detection_thresholds

    validate_detection_thresholds(confidence_min, margin_min)
    resolved_profile = apply_rule_selection(profile, select=select, ignore=ignore)
    effective_cfg = resolve_effective_config(
        resolved_profile,
        format=format if format != "auto" else None,
        confidence_min=confidence_min,
        margin_min=margin_min,
    )

    # Incremental cache (opt-in): opened lazily so the default path has zero
    # overhead. Every failure inside ScanCache or hashing degrades to a miss —
    # the scan never depends on cache availability.
    cache: ScanCache | None = None
    analysis_fp = ""
    if incremental:
        from sesslint.cache import ScanCache, analysis_fingerprint, default_cache_dir

        db_path = (
            Path(cache_dir) / "cache.db"
            if cache_dir is not None
            else default_cache_dir() / "cache.db"
        )
        # Invariant: never write cache files inside the scanned tree — a
        # cache placed there would self-flag as scan noise on later runs.
        try:
            inside_tree = db_path.resolve().is_relative_to(target.resolve())
        except OSError:
            inside_tree = False
        cache = None if inside_tree else ScanCache(db_path)
        analysis_fp = analysis_fingerprint(
            format=format,
            profile=profile,
            select=select,
            ignore=ignore,
            confidence_min=confidence_min,
            margin_min=margin_min,
            skip_undetected=skip_undetected,
            baseline=baseline,
        )

    def _cache_lookup(disp: str, file_path: Path) -> tuple[FileResult | None, str | None]:
        """Return (hit-result with cache_hit set, content hash for put) — or (None, hash)."""
        if cache is None:
            return None, None
        try:
            file_sha = sha256_file_bytes(file_path)
        except OSError:
            return None, None
        wire = cache.get(disp, analysis_fp, file_sha)
        if wire is None:
            return None, file_sha
        try:
            return replace(FileResult.from_wire(wire), cache_hit=True), file_sha
        except Exception:
            return None, file_sha

    def _cache_store(disp: str, file_sha: str | None, res: FileResult) -> None:
        """Store a computed result; unreadable verdicts are never cached."""
        if cache is None or file_sha is None or res.verdict == "unreadable":
            return
        cache.put(disp, analysis_fp, file_sha, res.to_wire())

    # Single-file mode
    if not target.is_dir() or target.is_symlink():
        try:
            st = target.lstat()
        except OSError as err:
            err_finding = make_finding(
                code=SL001,
                severity=Severity.ERROR,
                repairability=Repairability.MANUAL,
                message_template="I/O error stating file",
                source=SourceRef(path=str(target)),
                evidence={"detail": str(err)},
            )
            res = FileResult(
                path=root_str,
                verdict="unreadable",
                findings=(err_finding,),
                error_count=1,
            )
            totals = ScanTotals(unreadable=1)
            return ScanReport(root_path=root_str, totals=totals, files=(res,))

        if stat.S_ISFIFO(st.st_mode):
            res = FileResult(
                path=root_str, verdict="skipped", skipped_reason="fifo-special-file-skipped"
            )
            return ScanReport(root_path=root_str, totals=ScanTotals(skipped=1), files=(res,))
        if stat.S_ISSOCK(st.st_mode):
            res = FileResult(
                path=root_str, verdict="skipped", skipped_reason="socket-special-file-skipped"
            )
            return ScanReport(root_path=root_str, totals=ScanTotals(skipped=1), files=(res,))
        if stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode):
            res = FileResult(
                path=root_str, verdict="skipped", skipped_reason="device-special-file-skipped"
            )
            return ScanReport(root_path=root_str, totals=ScanTotals(skipped=1), files=(res,))

        check_token(cancel_token)
        file_res, file_sha = _cache_lookup(root_str, target)
        if file_res is None:
            try:
                file_res = _scan_single_file(
                    target,
                    format=format,
                    effective_cfg=effective_cfg,
                    skip_undetected=skip_undetected,
                    resolved_profile=resolved_profile,
                    baseline=baseline,
                )
            except Exception as err:
                err_finding = make_finding(
                    code=SL001,
                    severity=Severity.ERROR,
                    repairability=Repairability.MANUAL,
                    message_template="Unreadable file [detail: INTERNAL_ERROR]",
                    source=SourceRef(path=str(target)),
                    evidence={"reason": "unhandled_exception", "detail": type(err).__name__},
                )
                file_res = FileResult(
                    path=root_str,
                    verdict="unreadable",
                    findings=(err_finding,),
                    error_count=1,
                )
        _cache_store(root_str, file_sha, file_res)
        if cache is not None:
            cache.close()
        emit(
            progress_cb,
            ProgressEvent(phase="scan", completed=1, total=1, item=target.name),
        )
        totals = ScanTotals(
            healthy=1 if file_res.verdict == "healthy" else 0,
            invalid=1 if file_res.verdict == "invalid" else 0,
            unsupported=1 if file_res.verdict == "unsupported" else 0,
            unreadable=1 if file_res.verdict == "unreadable" else 0,
            skipped=1 if file_res.verdict == "skipped" else 0,
        )
        return ScanReport(root_path=root_str, totals=totals, files=(file_res,))

    # Directory mode
    if not recursive:
        raise ValueError(
            f"Path {target} is a directory. Recursive scanning requires recursive=True."
        )

    visited_dirs: set[tuple[int, int]] = set()
    seen_files: set[tuple[int, int]] = set()
    file_results: list[FileResult] = []
    pending_files: list[tuple[Path, str, str | None]] = []
    index_files: list[Path] = []
    cumulative_bytes = 0
    scanned_count = 0

    # Built-in scope exclusions (directory walks only): VCS internals are
    # never session artifacts, and SessLint's own generated files (repair
    # manifests, tool config) would only self-flag as undetected noise.
    builtin_excluded_dirs = {".git", ".hg", ".svn"}
    builtin_excluded_names = {"sesslint.toml", ".sesslint.toml"}

    # User scope filters — excluded entries are out of scope entirely.
    exclude_globs = [g.strip().replace("\\", "/") for g in (exclude or []) if g.strip()]
    ext_set: frozenset[str] | None = None
    if ext:
        exts = {e.strip().lower() for e in ext if e.strip()}
        ext_set = frozenset(e if e.startswith(".") else f".{e}" for e in exts) or None

    # Record root dir
    root_st = target.stat()
    if root_st.st_ino != 0:
        visited_dirs.add((root_st.st_dev, root_st.st_ino))

    # Iterative stack for deterministic traversal
    dir_stack: list[Path] = [target]

    while dir_stack:
        curr_dir = dir_stack.pop()
        try:
            entries = sorted(os.scandir(curr_dir), key=lambda e: e.name)
        except OSError as err:
            err_f = make_finding(
                code=SL001,
                severity=Severity.ERROR,
                repairability=Repairability.MANUAL,
                message_template="I/O error reading directory",
                source=SourceRef(path=str(curr_dir)),
                evidence={"detail": str(err)},
            )
            file_results.append(
                FileResult(
                    path=minimize_path(curr_dir),
                    verdict="unreadable",
                    findings=(err_f,),
                    error_count=1,
                )
            )
            continue

        for entry in entries:
            check_token(cancel_token)
            entry_p = Path(entry.path)
            disp_path = minimize_path(entry_p)

            # Built-in exclusions: never descend VCS internals; never flag
            # the tool's own generated/config files.
            if entry.is_dir(follow_symlinks=False) and entry.name in builtin_excluded_dirs:
                continue
            if not entry.is_dir(follow_symlinks=False) and (
                entry.name in builtin_excluded_names or entry.name.endswith(".manifest.json")
            ):
                continue

            # Scope filters: --exclude globs match the name or the
            # root-relative path; --ext allowlists file suffixes. Neither
            # emits a result — filtered entries are simply out of scope.
            if exclude_globs:
                try:
                    rel = entry_p.relative_to(target).as_posix()
                except ValueError:
                    rel = entry.name
                if any(
                    fnmatch.fnmatch(entry.name, g) or fnmatch.fnmatch(rel, g) for g in exclude_globs
                ):
                    continue
            if (
                ext_set is not None
                and not entry.is_dir(follow_symlinks=False)
                and entry_p.suffix.lower() not in ext_set
            ):
                continue

            # Index-reconciliation (SL402): vendor index files in scope are
            # collected for the post-walk membership diff. They still get
            # scanned as ordinary files below — findings attach to their
            # own FileResult.
            if not entry.is_dir(follow_symlinks=False) and entry.name in INDEX_FILE_NAMES:
                index_files.append(entry_p)

            try:
                st = entry_p.lstat()
            except OSError as err:
                err_f = make_finding(
                    code=SL001,
                    severity=Severity.ERROR,
                    repairability=Repairability.MANUAL,
                    message_template="I/O error stating file",
                    source=SourceRef(path=str(entry_p)),
                    evidence={"detail": str(err)},
                )
                file_results.append(
                    FileResult(
                        path=disp_path,
                        verdict="unreadable",
                        findings=(err_f,),
                        error_count=1,
                    )
                )
                continue

            # Special file checks
            if stat.S_ISFIFO(st.st_mode):
                file_results.append(
                    FileResult(
                        path=disp_path,
                        verdict="skipped",
                        skipped_reason="fifo-special-file-skipped",
                    )
                )
                continue
            if stat.S_ISSOCK(st.st_mode):
                file_results.append(
                    FileResult(
                        path=disp_path,
                        verdict="skipped",
                        skipped_reason="socket-special-file-skipped",
                    )
                )
                continue
            if stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode):
                file_results.append(
                    FileResult(
                        path=disp_path,
                        verdict="skipped",
                        skipped_reason="device-special-file-skipped",
                    )
                )
                continue

            # Directory handling
            if stat.S_ISDIR(st.st_mode):
                if st.st_ino != 0:
                    dir_ident = (st.st_dev, st.st_ino)
                    if dir_ident in visited_dirs:
                        file_results.append(
                            FileResult(
                                path=disp_path,
                                verdict="skipped",
                                skipped_reason="symlink-loop-detected",
                            )
                        )
                        continue
                    visited_dirs.add(dir_ident)
                dir_stack.append(entry_p)
                continue

            # Symlink handling
            if entry.is_symlink():
                if not follow_symlinks:
                    file_results.append(
                        FileResult(
                            path=disp_path,
                            verdict="skipped",
                            skipped_reason="symlink-directory-skipped"
                            if entry.is_dir()
                            else "symlink-skipped",
                        )
                    )
                    continue

                # When follow_symlinks=True
                try:
                    target_st = entry_p.stat()
                except OSError:
                    file_results.append(
                        FileResult(
                            path=disp_path,
                            verdict="unreadable",
                            skipped_reason="broken-symlink",
                        )
                    )
                    continue

                if stat.S_ISDIR(target_st.st_mode):
                    if target_st.st_ino != 0:
                        sym_ident = (target_st.st_dev, target_st.st_ino)
                        if sym_ident in visited_dirs:
                            file_results.append(
                                FileResult(
                                    path=disp_path,
                                    verdict="skipped",
                                    skipped_reason="symlink-loop-detected",
                                )
                            )
                            continue
                        visited_dirs.add(sym_ident)
                    dir_stack.append(entry_p)
                    continue
                st = target_st

            # Hardlink / repeat path deduplication
            if st.st_ino != 0:
                file_ident = (st.st_dev, st.st_ino)
                if file_ident in seen_files:
                    file_results.append(
                        FileResult(
                            path=disp_path,
                            verdict="skipped",
                            skipped_reason="duplicate-hardlink",
                        )
                    )
                    continue
                seen_files.add(file_ident)

            # Cap checks: max files — pending (dispatched-but-unmerged) entries
            # count identically to inline results so jobs>1 caps the same way.
            if len(file_results) + len(pending_files) >= max_files:
                file_results.append(
                    FileResult(
                        path=disp_path,
                        verdict="skipped",
                        skipped_reason="max-files-cap-exceeded",
                    )
                )
                continue

            # Cap checks: max bytes
            if cumulative_bytes + st.st_size > max_bytes:
                file_results.append(
                    FileResult(
                        path=disp_path,
                        verdict="skipped",
                        skipped_reason="max-bytes-cap-exceeded",
                    )
                )
                continue

            cumulative_bytes += st.st_size
            cached_res, file_sha = _cache_lookup(disp_path, entry_p)
            if cached_res is not None:
                file_results.append(cached_res)
                scanned_count += 1
                emit(
                    progress_cb,
                    ProgressEvent(
                        phase="scan",
                        completed=scanned_count,
                        total=None,
                        item=entry_p.name,
                    ),
                )
                continue
            if jobs > 1:
                pending_files.append((entry_p, disp_path, file_sha))
                continue
            try:
                res = _scan_single_file(
                    entry_p,
                    format=format,
                    effective_cfg=effective_cfg,
                    skip_undetected=skip_undetected,
                    resolved_profile=resolved_profile,
                    baseline=baseline,
                )
            except Exception as err:
                err_finding = make_finding(
                    code=SL001,
                    severity=Severity.ERROR,
                    repairability=Repairability.MANUAL,
                    message_template="Unreadable file [detail: INTERNAL_ERROR]",
                    source=SourceRef(path=disp_path),
                    evidence={"reason": "unhandled_exception", "detail": type(err).__name__},
                )
                res = FileResult(
                    path=disp_path,
                    verdict="unreadable",
                    findings=(err_finding,),
                    error_count=1,
                )
            _cache_store(disp_path, file_sha, res)
            file_results.append(res)
            scanned_count += 1
            emit(
                progress_cb,
                ProgressEvent(
                    phase="scan",
                    completed=scanned_count,
                    total=None,
                    item=entry_p.name,
                ),
            )

    # Parallel dispatch: workers return wire payloads in submission order;
    # merge into file_results before the deterministic path sort.
    if pending_files:
        # Lazy import: multiprocessing pulls in socket — importing it eagerly
        # would load network modules at `import sesslint` time (test_no_network_imports).
        from concurrent.futures import ProcessPoolExecutor

        worker_cfg: dict[str, Any] = {
            "format": format,
            "profile": profile,
            "select": list(select or ()),
            "ignore": list(ignore or ()),
            "confidence_min": confidence_min,
            "margin_min": margin_min,
            "skip_undetected": skip_undetected,
            "baseline": sorted(baseline) if baseline is not None else None,
        }
        paths = [str(p) for p, _, _ in pending_files]
        chunk = max(1, min(256, len(paths) // (jobs * 8) or 1))
        pool = ProcessPoolExecutor(
            max_workers=jobs,
            initializer=_init_scan_worker,
            initargs=(worker_cfg,),
        )
        try:
            for idx, wire in enumerate(pool.map(_scan_file_worker, paths, chunksize=chunk)):
                check_token(cancel_token)
                entry_p, disp_path, file_sha = pending_files[idx]
                try:
                    res = FileResult.from_wire(wire)
                except Exception as err:
                    err_finding = make_finding(
                        code=SL001,
                        severity=Severity.ERROR,
                        repairability=Repairability.MANUAL,
                        message_template="Unreadable file [detail: INTERNAL_ERROR]",
                        source=SourceRef(path=disp_path),
                        evidence={
                            "reason": "unhandled_exception",
                            "detail": type(err).__name__,
                        },
                    )
                    res = FileResult(
                        path=disp_path,
                        verdict="unreadable",
                        findings=(err_finding,),
                        error_count=1,
                    )
                _cache_store(disp_path, file_sha, res)
                file_results.append(res)
                scanned_count += 1
                emit(
                    progress_cb,
                    ProgressEvent(
                        phase="scan",
                        completed=scanned_count,
                        total=None,
                        item=entry_p.name,
                    ),
                )
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    if cache is not None:
        cache.close()

    # Sort results deterministically by path
    file_results.sort(key=lambda r: r.path)

    # SL401 cross-file linkage — a scan-layer resolution pass over the whole
    # file set (never single-file ``check``; layer discipline).
    scan_enabled = (
        resolved_profile.enabled_rules
        if resolved_profile is not None
        else effective_cfg.enabled_rules
    )
    if SL401 in scan_enabled:
        file_results = _resolve_cross_file_links(file_results, baseline=baseline)

    # SL402 session-index reconciliation — same scan-layer discipline: the
    # membership diff needs the whole file set plus the vendor index, so it
    # never runs from single-file ``check``.
    if SL402 in scan_enabled and index_files:
        file_results = _reconcile_session_indexes(file_results, index_files, baseline=baseline)

    healthy_c = sum(1 for r in file_results if r.verdict == "healthy")
    invalid_c = sum(1 for r in file_results if r.verdict == "invalid")
    unsupported_c = sum(1 for r in file_results if r.verdict == "unsupported")
    unreadable_c = sum(1 for r in file_results if r.verdict == "unreadable")
    skipped_c = sum(1 for r in file_results if r.verdict == "skipped")

    totals = ScanTotals(
        healthy=healthy_c,
        invalid=invalid_c,
        unsupported=unsupported_c,
        unreadable=unreadable_c,
        skipped=skipped_c,
    )

    return ScanReport(
        root_path=root_str,
        totals=totals,
        files=tuple(file_results),
    )


def _looks_pathy(target: str) -> bool:
    """True when a link target is spelled like a path rather than a bare id."""
    t = target.replace("\\", "/")
    return "/" in t or t.endswith(".jsonl") or t.endswith(".json")


def _resolve_cross_file_links(
    results: list[FileResult], *, baseline: frozenset[str] | None
) -> list[FileResult]:
    """Resolve adapter-extracted resume links across the scanned set (SL401).

    Index ``session_id`` -> files, filename stem -> files, and tip event id ->
    files; then resolve every ``SessionLink`` on each ``FileResult``:

    * exactly one candidate          -> resolved (silent)
    * more than one candidate        -> SL401 warning, ``resolution="ambiguous"``
    * zero candidates, ``session_ref`` bare id  -> SL401 warning, ``"missing"``
      (the scan enumerated every session id in the set — absence is provable)
    * zero candidates, path-like or ``head_ref`` -> SL401 info, ``"unresolved"``
      (a narrower scan cannot prove absence outside its root, and a head event
      could sit mid-file — only tips are indexed)

    Results are already path-sorted; findings append in link order so output is
    deterministic: ordered by referencing file, then link index.
    """
    from sesslint.adapters.safe_value import safe_discriminator

    by_session: dict[str, set[int]] = {}
    by_stem: dict[str, set[int]] = {}
    by_tip: dict[str, set[int]] = {}
    for idx, res in enumerate(results):
        if res.session_id:
            by_session.setdefault(res.session_id, set()).add(idx)
        stem = Path(res.path).stem
        if stem:
            by_stem.setdefault(stem, set()).add(idx)
        if res.tip_id:
            by_tip.setdefault(res.tip_id, set()).add(idx)

    out = list(results)
    for idx, res in enumerate(results):
        if not res.links:
            continue
        new_findings = list(res.findings)
        added_warn = 0
        for link_index, link in enumerate(res.links):
            if link.kind == "session_ref":
                cand = set(by_session.get(link.target, ())) | set(by_stem.get(link.target, ()))
                if _looks_pathy(link.target):
                    t_stem = Path(link.target).stem
                    cand |= set(by_session.get(t_stem, ())) | set(by_stem.get(t_stem, ()))
            else:
                cand = set(by_tip.get(link.target, ()))
            # A pointer at the file's own session identity is a self-reference,
            # not a cross-file link — satisfied by definition, never flagged.
            self_matched = idx in cand
            cand.discard(idx)
            if len(cand) == 1 or (self_matched and not cand):
                continue
            if len(cand) > 1:
                resolution = "ambiguous"
                sev = Severity.WARNING
                msg = "Cross-file resume link is ambiguous: multiple scanned files match"
            elif link.kind == "head_ref" or _looks_pathy(link.target):
                resolution = "unresolved"
                sev = Severity.INFO
                msg = "Cross-file resume link target is outside the scanned set"
            else:
                resolution = "missing"
                sev = Severity.WARNING
                msg = "Cross-file resume link target is absent from the scanned set"
            t_val, t_trunc = safe_discriminator(link.target)
            ev: dict[str, Any] = {
                "candidate_count": len(cand),
                "link_index": link_index,
                "link_kind": link.kind,
                "resolution": resolution,
                "target": t_val,
            }
            if t_trunc:
                ev["truncated"] = True
            new_findings.append(
                make_finding(
                    code=SL401,
                    severity=sev,
                    repairability=Repairability.MANUAL,
                    message_template=msg,
                    source=SourceRef(path=res.path, line=link.line, record_id=link.record_id),
                    evidence=ev,
                )
            )
            if sev is Severity.WARNING:
                added_warn += 1
        if added_warn or len(new_findings) != len(res.findings):
            if baseline is not None:
                kept = [f for f in res.findings]
                kept += [
                    f for f in new_findings[len(res.findings) :] if f.fingerprint not in baseline
                ]
                if len(kept) == len(res.findings):
                    continue
                added_warn = sum(
                    1 for f in kept[len(res.findings) :] if f.severity is Severity.WARNING
                )
                new_findings = kept
            out[idx] = replace(
                res,
                findings=tuple(new_findings),
                warning_count=res.warning_count + added_warn,
            )
    return out


def _reconcile_session_indexes(
    results: list[FileResult],
    index_paths: Sequence[Path],
    *,
    baseline: frozenset[str] | None,
) -> list[FileResult]:
    """Diff each in-scope vendor index against the scanned file set (SL402).

    For every collected index file the scan already produced a ``FileResult``
    (the index was walked like any other file); findings attach there for
    index-side divergence and to sibling session files for membership gaps:

    * ``parse_ok=False, truncated``      -> one ``index-truncated`` warning;
      the salvaged subset cannot support membership claims.
    * ``parse_ok=False``                 -> one ``index-malformed`` warning.
    * ``parse_ok``                       -> ``index-entry-no-file`` per index
      entry that provably resolves to nothing (no sibling result, no member
      session id, no file on disk); ``file-not-in-index`` per indexable
      sibling file absent from the index — only when
      ``membership_complete`` (a partial/unknown index cannot prove absence).

    "Indexable" is conservative: only files the adapter layer identified as
    primary session ledgers of the index's vendor format count as members
    (``detected_format``). Sidecars, sub-agent logs, and undetected files can
    exist without index membership, so they are never flagged — but their
    stems still satisfy dangling checks because the file *exists*.

    Findings append in deterministic order: malformed/truncated first, then
    dangling entries sorted by id. Never runs from single-file ``check``.
    """
    from sesslint.adapters.detect import FORMAT_CLAUDE_CODE
    from sesslint.indexes import read_index

    # Per-index-filename vendor format: only ledger files the adapter layer
    # identified as this format count as membership candidates (T-02 scope:
    # Claude only; non-Claude index readers land in T-03).
    index_format_by_name = {"sessions-index.json": FORMAT_CLAUDE_CODE}

    by_path = {res.path: i for i, res in enumerate(results)}
    out = list(results)
    by_parent: dict[str, list[int]] = {}
    for i, res in enumerate(results):
        by_parent.setdefault(PurePosixPath(res.path).parent.as_posix(), []).append(i)

    def _emit(res_idx: int, finding: Finding) -> None:
        res = out[res_idx]
        if baseline is not None and finding.fingerprint in baseline:
            return
        out[res_idx] = replace(
            res,
            findings=res.findings + (finding,),
            warning_count=res.warning_count + 1,
        )

    def _index_finding(res: FileResult, ev: dict[str, Any], msg: str) -> Finding:
        return make_finding(
            code=SL402,
            severity=Severity.WARNING,
            repairability=Repairability.MANUAL,
            message_template=msg,
            source=SourceRef(path=res.path),
            evidence=ev,
        )

    for index_p in sorted(index_paths, key=lambda p: str(p)):
        index_disp = minimize_path(index_p)
        idx_i = by_path.get(index_disp)
        if idx_i is None:
            continue  # scope-filtered or capped out of the scan
        snap = read_index(index_p)
        if snap.parse_ok and snap.schema_note == "absent" and not snap.truncated:
            continue  # index vanished between walk and read — normal, silent
        idx_res = out[idx_i]

        if not snap.parse_ok:
            if snap.truncated:
                ev = {
                    "divergence": "index-truncated",
                    "resolution": "truncated",
                    "parsed_entry_count": snap.entry_count,
                }
                msg = "Vendor session index is truncated (partial index cannot be trusted)"
            else:
                ev = {
                    "divergence": "index-malformed",
                    "resolution": "unparseable",
                    "error_kind": snap.schema_note or "malformed",
                }
                msg = "Vendor session index cannot be parsed"
            _emit(idx_i, _index_finding(idx_res, ev, msg))
            continue  # no membership claims from an unproven index

        parent_key = PurePosixPath(index_disp).parent.as_posix()
        siblings = [i for i in by_parent.get(parent_key, ()) if i != idx_i]
        expected_fmt = index_format_by_name.get(index_p.name)
        members = (
            [
                i
                for i in siblings
                if results[i].detected_format == expected_fmt
                and results[i].verdict in ("healthy", "invalid")
            ]
            if expected_fmt is not None
            else []
        )
        member_ids: set[str] = set()
        for i in members:
            r = results[i]
            member_ids.update(x for x in (r.session_id, PurePosixPath(r.path).stem) if x)
        sibling_stems = {
            PurePosixPath(results[i].path).stem
            for i in siblings
            if PurePosixPath(results[i].path).stem
        }
        claimed = snap.normalized_ids

        if snap.membership_complete:
            for i in members:
                r = results[i]
                ids = {x for x in (r.session_id, PurePosixPath(r.path).stem) if x}
                if ids and not ids & claimed:
                    ev = {
                        "divergence": "file-not-in-index",
                        "resolution": "missing",
                        "session_id_hash8": short_hash(r.session_id or sorted(ids)[0]),
                        "index_entry_count": snap.entry_count,
                    }
                    _emit(
                        i,
                        _index_finding(
                            r, ev, "Session file is not listed in the vendor session index"
                        ),
                    )

        # Dangling entries: one finding per index entry whose claims resolve
        # to nothing — an entry's sessionId and fullPath describe the same
        # session, so both must miss before the entry is dangling. Provable
        # per entry even when the full set is uncertain; truncated snapshots
        # never reach this loop.
        seen_keys: set[str] = set()
        ordered = sorted(
            snap.entries,
            key=lambda e: (e.session_id or "", e.full_path or ""),
        )
        for entry in ordered:
            forms = {
                x
                for x in (
                    entry.session_id,
                    Path(entry.session_id).stem if entry.session_id else None,
                    Path(entry.full_path).stem if entry.full_path else None,
                )
                if x
            }
            ekey = entry.session_id or next(iter(sorted(forms)), "")
            if not ekey or ekey in seen_keys:
                continue
            seen_keys.add(ekey)
            if forms & member_ids or forms & sibling_stems:
                continue
            if entry.full_path:
                fp = Path(entry.full_path)
                if fp.is_absolute() and fp.is_file():
                    continue  # path claim resolves outside this dir but exists
                if not fp.is_absolute() and (index_p.parent / fp).is_file():
                    continue  # relative path claim resolves beside the index
            if any((index_p.parent / f"{k}.jsonl").is_file() for k in forms):
                continue  # sibling file exists but was filtered out of scope
            ev = {
                "divergence": "index-entry-no-file",
                "resolution": "dangling",
                "entry_id_hash8": short_hash(ekey),
            }
            _emit(
                idx_i,
                _index_finding(
                    out[idx_i],
                    ev,
                    "Vendor session index entry has no matching session file",
                ),
            )
    return out


def scan_bytes(
    data: bytes,
    *,
    virtual_path: str = "<stdin>",
    format: str | None = None,
    profile: str = "neutral",
    confidence_min: float | None = None,
    margin_min: float | None = None,
    progress_cb: ProgressCallback | None = None,
    cancel_token: CancellationToken | None = None,
    skip_undetected: bool = False,
    select: Sequence[str] | None = None,
    ignore: Sequence[str] | None = None,
    baseline: frozenset[str] | None = None,
    max_input_bytes: int | None = None,
) -> ScanReport:
    """Scan an in-memory session artifact (e.g. piped stdin bytes) — ux T-06.

    Runs the identical per-source evaluation as ``scan_path`` on a file;
    ``virtual_path`` is the verbatim display path (``<stdin>``) used in the
    report and findings — never resolved against cwd. Content detection relies
    on record signatures only (no meaningful filename); ``format`` overrides
    as usual. ``jobs``/``incremental`` do not apply to a single buffer.
    ``max_input_bytes`` bounds the slurped buffer: when exceeded the result is
    a structured SL001 ``unreadable`` finding, never a traceback.
    """
    if max_input_bytes is not None and len(data) > max_input_bytes:
        finding = make_finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message_template="Unreadable file [detail: LIMIT_OR_IO]",
            source=SourceRef(path=virtual_path),
            evidence={"reason": "limit_or_io_error", "detail": "stdin_too_large"},
        )
        res = FileResult(
            path=virtual_path,
            verdict="unreadable",
            findings=(finding,),
            error_count=1,
            warning_count=0,
        )
        return ScanReport(
            root_path=virtual_path,
            totals=ScanTotals(unreadable=1),
            files=(res,),
        )
    from sesslint.adapters.detect import validate_detection_thresholds

    validate_detection_thresholds(confidence_min, margin_min)
    resolved_profile = apply_rule_selection(profile, select=select, ignore=ignore)
    effective_cfg = resolve_effective_config(
        resolved_profile,
        format=format if format != "auto" else None,
        confidence_min=confidence_min,
        margin_min=margin_min,
    )

    check_token(cancel_token)
    try:
        file_res = _scan_single_source(
            Path(virtual_path),
            virtual_path,
            data=data,
            format=format,
            effective_cfg=effective_cfg,
            skip_undetected=skip_undetected,
            resolved_profile=resolved_profile,
            baseline=baseline,
        )
    except Exception as err:
        err_finding = make_finding(
            code=SL001,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message_template="Unreadable file [detail: INTERNAL_ERROR]",
            source=SourceRef(path=virtual_path),
            evidence={"reason": "unhandled_exception", "detail": type(err).__name__},
        )
        file_res = FileResult(
            path=virtual_path,
            verdict="unreadable",
            findings=(err_finding,),
            error_count=1,
        )
    emit(
        progress_cb,
        ProgressEvent(phase="scan", completed=1, total=1, item=virtual_path),
    )
    totals = ScanTotals(
        healthy=1 if file_res.verdict == "healthy" else 0,
        invalid=1 if file_res.verdict == "invalid" else 0,
        unsupported=1 if file_res.verdict == "unsupported" else 0,
        unreadable=1 if file_res.verdict == "unreadable" else 0,
        skipped=1 if file_res.verdict == "skipped" else 0,
    )
    return ScanReport(root_path=virtual_path, totals=totals, files=(file_res,))
