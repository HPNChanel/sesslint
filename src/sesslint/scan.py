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

import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from sesslint.codes import SL001, SL301, SL302, Repairability, Severity
from sesslint.errors import FileTooLargeError, MaxRecordsExceededError
from sesslint.finding import Finding, SourceRef, make_finding
from sesslint.profiles import resolve_effective_config
from sesslint.report import minimize_path

Verdict = Literal["healthy", "invalid", "unsupported", "unreadable", "skipped"]

DEFAULT_MAX_FILES: int = 10000
DEFAULT_MAX_BYTES: int = 1024 * 1024 * 1024  # 1GB


@dataclass(frozen=True, slots=True)
class FileResult:
    """Outcome of scanning an individual file artifact."""

    path: str
    verdict: Verdict
    findings: tuple[Finding, ...] = ()
    skipped_reason: str | None = None
    error_count: int = 0
    warning_count: int = 0

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
        if self.findings:
            res["findings"] = [format_finding_content_free(f) for f in self.findings]
        return res


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
class ScanReport:
    """Top-level report containing per-file results and aggregate 5-bucket totals."""

    schema_version: str = "sesslint.scan-report/v1"
    root_path: str = ""
    totals: ScanTotals = field(default_factory=ScanTotals)
    files: tuple[FileResult, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialize scan report to canonical JSON-compatible dictionary."""
        return {
            "files": [f.to_dict() for f in self.files],
            "root_path": self.root_path,
            "schema_version": self.schema_version,
            "totals": self.totals.to_dict(),
        }

    def to_json(self) -> str:
        """Serialize scan report to formatted JSON string."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


def _scan_single_file(
    file_path: Path,
    *,
    format: str | None = None,
    profile: str = "neutral",
) -> FileResult:
    """Evaluate a single regular file artifact, mapping to one of 4 active buckets."""
    display_path = minimize_path(file_path)

    # 1. Read file with I/O and non-UTF8 / binary safety
    try:
        raw_bytes = file_path.read_bytes()
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

    # Binary check: null byte or invalid utf-8 before JSON decoding
    if b"\x00" in raw_bytes:
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

    try:
        raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
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
    try:
        from sesslint.adapters.detect import (
            FORMAT_CANONICAL,
            FORMAT_CLAUDE_CODE,
            FORMAT_OPENAI_AGENTS,
            resolve_format,
        )

        resolved_fmt, detection_res, det_findings = resolve_format(format, file_path)
        if resolved_fmt is None:
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
            err_c = sum(1 for f in rep_findings if f.severity in (Severity.ERROR, Severity.FATAL))
            warn_c = sum(1 for f in rep_findings if f.severity == Severity.WARNING)
            return FileResult(
                path=display_path,
                verdict="invalid",
                findings=tuple(rep_findings),
                error_count=err_c,
                warning_count=warn_c,
            )

        effective_cfg = resolve_effective_config(
            profile,
            format=format if format != "auto" else None,
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

        # 3. Adapter loading
        events: Any = ()
        adapter_findings: list[Finding] = list(det_findings)
        if resolved_fmt == FORMAT_CANONICAL:
            from sesslint.adapters.canonical import load_canonical

            can_events, can_findings = load_canonical(file_path)
            events = can_events
            adapter_findings.extend(can_findings)
        elif resolved_fmt == FORMAT_CLAUDE_CODE:
            from sesslint.adapters.claude_code import load_claude_code

            c_events, c_findings = load_claude_code(file_path)
            events = c_events
            adapter_findings.extend(c_findings)
        elif resolved_fmt == FORMAT_OPENAI_AGENTS:
            from sesslint.adapters.openai_agents import load_openai_agents

            o_events, o_findings = load_openai_agents(file_path)
            events = o_events
            adapter_findings.extend(o_findings)

        # 4. Invariant checks
        from sesslint.context import CheckContext
        from sesslint.repair.executor import run_all_checks

        source_meta = getattr(events, "source", None)
        check_ctx = CheckContext.from_profile_and_adapter(
            profile=effective_cfg.profile,
            adapter=resolved_fmt,
            source_metadata=source_meta if isinstance(source_meta, Mapping) else None,
        )

        try:
            check_findings = run_all_checks(
                events,
                profile=effective_cfg.profile,
                source_path=str(file_path),
                context=check_ctx,
                adapter=resolved_fmt,
            )
        except TypeError:
            check_findings = run_all_checks(
                events,
                profile=effective_cfg.profile,
                source_path=str(file_path),
            )
        all_findings = tuple(adapter_findings + list(check_findings))

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

        return FileResult(
            path=display_path,
            verdict=verdict,
            findings=all_findings,
            error_count=err_count,
            warning_count=warn_count,
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


def scan_path(
    path: Path | str,
    *,
    recursive: bool = False,
    follow_symlinks: bool = False,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes: int = DEFAULT_MAX_BYTES,
    format: str | None = None,
    profile: str = "neutral",
) -> ScanReport:
    """Scan a target path or directory tree, returning a ScanReport with 5-bucket totals."""
    target = Path(path)
    root_str = minimize_path(target)

    if not target.exists() and not target.is_symlink():
        raise FileNotFoundError(f"Path not found: {target}")

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

        file_res = _scan_single_file(target, format=format, profile=profile)
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
    cumulative_bytes = 0

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
            entry_p = Path(entry.path)
            disp_path = minimize_path(entry_p)

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

            # Cap checks: max files
            if len(file_results) >= max_files:
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
            res = _scan_single_file(entry_p, format=format, profile=profile)
            file_results.append(res)

    # Sort results deterministically by path
    file_results.sort(key=lambda r: r.path)

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
