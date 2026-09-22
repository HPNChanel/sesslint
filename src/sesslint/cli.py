"""SessLint command line interface."""

from __future__ import annotations

import argparse
import json
import math
import os
import secrets
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, Final, Literal

from sesslint import __version__
from sesslint._version import get_version_info
from sesslint.adapters.canonical import SUPPORTED_CANONICAL_VERSIONS
from sesslint.adapters.claude_code import SUPPORTED_CLAUDE_VERSIONS
from sesslint.adapters.codex_rollout import SUPPORTED_CODEX_ROLLOUT_VERSIONS
from sesslint.adapters.openai_agents import SUPPORTED_OPENAI_AGENTS_VERSIONS
from sesslint.api import build_internal_error_envelope, validate_session
from sesslint.errors import SesslintError
from sesslint.finding import Finding
from sesslint.progress import OperationCancelled

load_session_file = validate_session

FORMAT_DISPLAY_NAMES: Final[dict[str, str]] = {
    "canonical": "canonical",
    "claude-code-jsonl": "Claude Code",
    "codex-rollout": "Codex rollout",
    "openai-agents": "OpenAI Agents",
}


def _handle_internal_error(err: Exception, args: argparse.Namespace | None = None) -> int:
    """Handle unexpected internal operational errors per FR-097, FR-098, FR-099.

    Guarantees:
    - Generates a unique, content-free diagnostic ID matching ^ERR-[0-9a-f]{8}$.
    - In JSON mode: outputs a JSON envelope to stdout with verdict='error', code='INTERNAL_ERROR',
      error_id, and message.
    - In human mode: outputs actionable error information to stderr.
    - Never prints raw Python tracebacks to stdout.
    - Never verdicts healthy.
    - Exits with return code 2.
    """
    error_id = f"ERR-{secrets.token_hex(4)}"
    is_json = getattr(args, "json", False) if args is not None else False
    if is_json:
        envelope = build_internal_error_envelope(err, error_id=error_id)
        print(json.dumps(envelope, sort_keys=True))
    else:
        print(f"Operational error [{error_id}]: {err}", file=sys.stderr)
    return 2


def should_color(args: argparse.Namespace, stream: Any = sys.stdout) -> bool:
    """Determine whether color output should be enabled."""
    if getattr(args, "no_color", False):
        return False
    if getattr(args, "json", False):
        return False
    if "NO_COLOR" in os.environ and os.environ["NO_COLOR"]:
        return False
    color_opt = getattr(args, "color", "auto")
    if color_opt == "never":
        return False
    if color_opt == "always":
        return True
    return hasattr(stream, "isatty") and bool(stream.isatty())


def format_scan_report_human(scan_report: Any, color: bool = False) -> str:
    """Format human-readable summary of ScanReport with 5-bucket totals."""
    bold = "\033[1m" if color else ""
    reset = "\033[0m" if color else ""
    red = "\033[31m" if color else ""
    green = "\033[32m" if color else ""
    yellow = "\033[33m" if color else ""

    lines: list[str] = [
        f"[read-only] Scan report for: {scan_report.root_path}",
        (
            f"Totals: healthy={scan_report.totals.healthy} "
            f"invalid={scan_report.totals.invalid} "
            f"unsupported={scan_report.totals.unsupported} "
            f"unreadable={scan_report.totals.unreadable} "
            f"skipped={scan_report.totals.skipped} "
            f"(total={scan_report.totals.total})"
        ),
    ]
    reason_totals = scan_report.skipped_reason_totals()
    if reason_totals:
        lines.append("Skipped reasons: " + " ".join(f"{k}={v}" for k, v in reason_totals.items()))
        if "max-bytes-cap-exceeded" in reason_totals or "max-files-cap-exceeded" in reason_totals:
            lines.append(
                "Hint: resource budget exhausted -- raise --max-bytes/--max-files "
                "to scan remaining files."
            )
    lines.append("-" * 80)
    for r in scan_report.files:
        if r.verdict == "healthy":
            tag_color = green
            raw_tag = "[HEALTHY]"
            detail = ""
        elif r.verdict == "invalid":
            tag_color = red
            raw_tag = "[INVALID]"
            detail = f" ({r.error_count} error(s), {r.warning_count} warning(s))"
        elif r.verdict == "unsupported":
            tag_color = yellow
            raw_tag = "[UNSUPPORTED]"
            detail = " (unsupported version)"
        elif r.verdict == "unreadable":
            tag_color = red
            raw_tag = "[UNREADABLE]"
            detail = " (read error or non-UTF8)"
        else:  # skipped
            tag_color = bold
            raw_tag = "[SKIPPED]"
            detail = f" (reason: {r.skipped_reason})"
        if getattr(r, "cache_hit", False):
            detail += " [cache-hit]"
        tag_col = f"{tag_color}{raw_tag}{reset}{' ' * max(0, 20 - len(raw_tag))}"
        lines.append(f"  {tag_col} {r.path}{detail}")

    summary = getattr(scan_report, "summary", None)
    if summary is not None and (summary.by_code or summary.worst_files):
        lines.append("-" * 80)
        if summary.by_code:
            lines.append("Findings by code:")
            for row in summary.by_code:
                lines.append(
                    f"  {row.code}  {row.severity:<8} {row.count} finding(s) in {row.files} file(s)"
                )
        if summary.worst_files:
            lines.append("Worst files:")
            for row in summary.worst_files:
                lines.append(
                    f"  {row.path}  ({row.error_count} error(s), {row.warning_count} warning(s))"
                )

    # SL009 hygiene rollup: secret-shaped material deserves its own
    # section — a warning-bucket row can hide inside a long by_code list.
    secret_files = sum(1 for r in scan_report.files if any(f.code == "SL009" for f in r.findings))
    if secret_files:
        lines.append("-" * 80)
        lines.append(f"  secret-shaped material: {secret_files} file(s)")

    # SL402 index-divergence rollup (index-reconciliation T-03): divergence
    # is invisible in per-file verdicts — the file itself is healthy.
    kinds: dict[str, int] = {}
    for r in scan_report.files:
        for f in r.findings:
            if f.code == "SL402" and f.evidence:
                kind = f.evidence.get("divergence")
                if isinstance(kind, str):
                    kinds[kind] = kinds.get(kind, 0) + 1
    if kinds:
        parts: list[str] = []
        if kinds.get("file-not-in-index"):
            parts.append(f"{kinds['file-not-in-index']} session file(s) not listed in vendor index")
        if kinds.get("index-entry-no-file"):
            n = kinds["index-entry-no-file"]
            parts.append(f"{n} dangling index {'entry' if n == 1 else 'entries'}")
        if kinds.get("index-malformed"):
            parts.append("malformed index")
        if kinds.get("index-truncated"):
            parts.append("truncated index")
        hint = (
            "resumable by explicit id; see docs/codes/SL402.md"
            if kinds.get("file-not-in-index")
            else "see docs/codes/SL402.md"
        )
        lines.append("-" * 80)
        lines.append(f"  index divergence: {', '.join(parts)} ({hint})")

    return "\n".join(lines)


def _validate_positive_int(val_str: str) -> int:
    """Validate that integer flag is strictly positive (> 0) (P1-02)."""
    try:
        val = int(val_str)
    except (ValueError, TypeError) as err:
        raise argparse.ArgumentTypeError(f"Invalid integer value: {val_str!r}") from err
    if val <= 0:
        raise argparse.ArgumentTypeError(f"Value must be a positive integer (> 0), got {val}")
    return val


def _validate_unit_interval_float(val_str: str) -> float:
    """Validate that float threshold is strictly between 0.0 and 1.0 exclusive (P1-02)."""
    try:
        val = float(val_str)
    except (ValueError, TypeError) as err:
        raise argparse.ArgumentTypeError(f"Invalid float value: {val_str!r}") from err
    if math.isnan(val) or math.isinf(val) or not (0.0 < val < 1.0):
        raise argparse.ArgumentTypeError(
            f"Value must be a float strictly between 0.0 and 1.0 (0.0 < value < 1.0), got {val}"
        )
    return val


def _rule_codes_arg(args: argparse.Namespace, name: str) -> list[str] | None:
    """Split a comma-separated --select/--ignore value into a code list, or None."""
    raw = getattr(args, name, None)
    if raw is None:
        return None
    codes = [c.strip() for c in str(raw).split(",") if c.strip()]
    return codes or None


def _load_baseline_arg(args: argparse.Namespace) -> frozenset[str] | None:
    """Load the ``--baseline`` file into a fingerprint set, or None when unset.

    Raises ``BaselineError`` (a ``ValueError``) on missing/malformed files.
    """
    path = getattr(args, "baseline", None)
    if path is None:
        return None
    from sesslint.baseline import load_baseline

    return load_baseline(path)


def _write_baseline_arg(args: argparse.Namespace, findings: Iterable[Finding]) -> None:
    """Write a baseline file for ``--write-baseline`` and note it on stderr."""
    path = getattr(args, "write_baseline", None)
    if path is None:
        return
    from sesslint.baseline import write_baseline

    count = write_baseline(path, findings, created_by=f"sesslint {__version__}")
    print(f"wrote baseline: {count} fingerprint(s) -> {path}", file=sys.stderr)


def _output_format(args: argparse.Namespace) -> str:
    """Resolve the effective output format: --json wins, else --output-format."""
    if getattr(args, "json", False):
        return "json"
    return getattr(args, "output_format", None) or "human"


def _apply_config(args: argparse.Namespace, cfg: Mapping[str, Any]) -> None:
    """Fold ``[tool.sesslint]`` values into unset CLI options (explicit CLI wins).

    Argparse leaves config-overridable options at ``None`` (or absent under
    ``SUPPRESS``) unless the user passed them, so a ``None`` value here means
    "fall back to config, then the built-in default".
    """
    if getattr(args, "fail_on", None) is None:
        args.fail_on = cfg.get("fail_on", "error")
    if getattr(args, "max_files", None) is None:
        args.max_files = cfg.get("max_files", 10000)
    if getattr(args, "max_bytes", None) is None:
        args.max_bytes = cfg.get("max_bytes", 1024 * 1024 * 1024)
    if getattr(args, "format", None) is None:
        args.format = cfg.get("format", "auto")
    if getattr(args, "profile", None) is None:
        args.profile = cfg.get("profile", "neutral")
    if getattr(args, "confidence_min", None) is None:
        args.confidence_min = cfg.get("confidence_min")
    if getattr(args, "margin_min", None) is None:
        args.margin_min = cfg.get("margin_min")
    if not getattr(args, "skip_undetected", False) and cfg.get("skip_undetected"):
        args.skip_undetected = True
    # select/ignore share one axis: an explicit CLI choice overrides the whole
    # config axis (a config file that sets both is rejected downstream).
    if _rule_codes_arg(args, "select") is None and _rule_codes_arg(args, "ignore") is None:
        if cfg.get("select"):
            args.select = ",".join(cfg["select"])
        elif cfg.get("ignore"):
            args.ignore = ",".join(cfg["ignore"])
    # Repair policy is meaningful only for the repair command; folding it into
    # check/scan would silently pretend to apply (and trip the unused-flag
    # warning below for a value the user never typed).
    if (
        getattr(args, "command", None) == "repair"
        and getattr(args, "policy", None) is None
        and cfg.get("policy")
    ):
        args.policy = cfg["policy"]
    if not getattr(args, "exclude", None) and cfg.get("exclude"):
        args.exclude = list(cfg["exclude"])
    if not getattr(args, "ext", None) and cfg.get("ext"):
        args.ext = list(cfg["ext"])


def _ndjson_progress_cb(args: argparse.Namespace) -> Any:
    """Return an NDJSON progress callback writing to stderr, or None (DW-T-13).

    stdout remains the result channel (FR-091); progress events are flushed
    per line so a supervising process can consume them incrementally.
    """
    if not getattr(args, "progress_json", False):
        return None
    from sesslint.progress import ProgressEvent

    def _cb(event: ProgressEvent) -> None:
        print(json.dumps(event.to_dict(), sort_keys=True), file=sys.stderr, flush=True)

    return _cb


def _read_stdin_bytes() -> bytes:
    """Slurp stdin once into a bounded buffer (ux T-06).

    Reads at most ``DEFAULT_MAX_FILE_BYTES + 1`` bytes so callers detect
    oversize exactly (``len(data) > cap``). Binary-mode read avoids Windows
    text-mode newline translation.
    """
    from sesslint.io import DEFAULT_MAX_FILE_BYTES

    return sys.stdin.buffer.read(DEFAULT_MAX_FILE_BYTES + 1)


def _emit_check_report(
    report: Any,
    args: argparse.Namespace,
    *,
    display_path: str,
    format_opt: str,
    profile_opt: str,
) -> int:
    """Shared check-report emission for file and stdin sources (ux T-06).

    ``display_path`` is the path shown in skip/hint messages — ``<stdin>``
    for piped input.
    """
    _write_baseline_arg(args, report.findings)

    # --skip-undetected: detection-failed files are skipped, not failed
    if getattr(args, "skip_undetected", False) and report.coverage.adapter.get("id") == "unknown":
        skip_fmt = _output_format(args)
        if skip_fmt == "json":
            # Valid empty-state payload keeps `| jq` pipelines alive —
            # an empty stdout would strand JSON consumers.
            from sesslint.report import minimize_path

            print(
                json.dumps(
                    {
                        "findings": [],
                        "ok": True,
                        "path": minimize_path(display_path),
                        "skipped": True,
                        "skipped_reason": "format-undetected",
                    },
                    sort_keys=True,
                )
            )
        elif skip_fmt == "sarif":
            from sesslint.sarif import render_sarif

            print(render_sarif((), tool_version=__version__))
        else:
            print(f"skipped (format-undetected): {display_path}", file=sys.stderr)
        return 0

    has_error = (
        report.counts.by_severity.get("error", 0) > 0
        or report.counts.by_severity.get("fatal", 0) > 0
    )
    if getattr(args, "fail_on", "error") == "warning":
        has_error = has_error or report.counts.by_severity.get("warning", 0) > 0
    exit_code = 1 if has_error else 0

    # If format detection failed or was ambiguous, emit actionable hints on stderr
    has_detection_or_version_failure = False
    for f in report.findings:
        if f.code == "SL302":
            has_detection_or_version_failure = True
            if isinstance(f.evidence, dict):
                reason = f.evidence.get("reason")
                if reason in ("tie", "low-confidence", "empty"):
                    print(
                        "Format detection ambiguous. Please specify --format explicitly "
                        "(see sesslint formats).",
                        file=sys.stderr,
                    )
                    confidences = f.evidence.get("confidences")
                    if confidences and isinstance(confidences, dict):
                        sorted_conf = dict(sorted(confidences.items()))
                        print(
                            f"Candidate confidences: {sorted_conf}",
                            file=sys.stderr,
                        )
            print(f"Format detection error [{f.code}]: {f.message}", file=sys.stderr)
        elif f.code == "SL301":
            has_detection_or_version_failure = True
            print(f"Format detection error [{f.code}]: {f.message}", file=sys.stderr)

    if has_detection_or_version_failure:
        if display_path == "<stdin>":
            print(
                "hint: save the stream to a file, then run 'sesslint bundle <file>' "
                "and attach the output to an adapter request",
                file=sys.stderr,
            )
        else:
            target_disp = display_path.replace("\\", "/")
            print(
                f"hint: run 'sesslint bundle {target_disp}' "
                "and attach the output to an adapter request",
                file=sys.stderr,
            )

    adapter_id = report.coverage.adapter.get("id", "canonical")
    format_display = FORMAT_DISPLAY_NAMES.get(adapter_id, adapter_id)

    single_out_fmt = _output_format(args)
    if single_out_fmt == "json":
        from sesslint.report import build_repro_metadata, render_json

        adapter_cov = report.coverage.adapter
        profile_cov = report.coverage.profile
        repro_meta = build_repro_metadata(
            adapter_name=str(adapter_cov.get("id", "unknown")),
            adapter_version=str(adapter_cov.get("version", "unknown")),
            profile_name=str(profile_cov.get("id", "unknown")),
            profile_version=str(profile_cov.get("version", "unknown")),
            detection_method="manual" if format_opt != "auto" else "auto",
            detection_confidence=None,
        )
        print(
            render_json(
                report,
                include_content=getattr(args, "include_content", False),
                repro=repro_meta,
            )
        )
        return exit_code
    if single_out_fmt == "sarif":
        from sesslint.sarif import render_sarif

        print(render_sarif(report.findings, tool_version=report.tool_version))
        return exit_code
    if single_out_fmt == "html":
        from sesslint.html_report import render_html

        print(
            render_html(
                report,
                adapter=format_display,
                profile=report.coverage.profile.get("id", profile_opt),
            )
        )
        return exit_code
    from sesslint.report import render_human

    use_color = should_color(args, sys.stdout)
    human_text = render_human(
        report,
        color=use_color,
        adapter=format_display,
        profile=report.coverage.profile.get("id", profile_opt),
    )
    if not has_error:
        print(f"Valid {format_display} session")
    print(human_text)
    return exit_code


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser for sesslint CLI."""
    parser = argparse.ArgumentParser(
        prog="sesslint",
        description=(
            "Offline, vendor-neutral session integrity checker and conservative repair tool."
        ),
        epilog=(
            "Exit codes:\n"
            "  0  Healthy session / verification passed / dry-run plan generated\n"
            "  1  Integrity findings detected / verification failed / repair refused\n"
            "  2  Usage error / invalid flag combination / I/O failure\n\n"
            "Important Notes:\n"
            "  - redaction is best-effort minimization, not a completeness guarantee\n"
            "  - sesslint makes no semantic or side-effect safety claims"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--include-content",
        action="store_true",
        default=False,
        help="Embed raw transcript content in reports (warning: emits raw sensitive data)",
    )

    parser.add_argument(
        "--format",
        choices=["auto", "claude-code-jsonl", "openai-agents", "codex-rollout", "canonical"],
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--profile",
        default=argparse.SUPPRESS,
        help="Replay validation profile (default: neutral)",
    )
    parser.add_argument(
        "--policy",
        choices=["conservative", "salvage"],
        default=argparse.SUPPRESS,
        help="Repair policy (choices: conservative, salvage; default: conservative)",
    )
    parser.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default="auto",
        help="Control colored terminal output (default: auto)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color styling (equivalent to NO_COLOR=1)",
    )

    subparsers = parser.add_subparsers(dest="command")

    # validate-session
    val_parser = subparsers.add_parser(
        "validate-session",
        help="[read-only] Validate a canonical session file against schema.",
        description="[read-only] Validate a canonical session file against schema.",
    )
    val_parser.add_argument(
        "path",
        type=Path,
        help="Path to session file (.json or .jsonl)",
    )

    # check
    check_parser = subparsers.add_parser(
        "check",
        help="[read-only] Check a session file with auto-detection.",
        description=(
            "[read-only] Check a session file for structural defects, causal breaks, "
            "and schema violations."
        ),
    )
    check_parser.add_argument(
        "path",
        type=Path,
        nargs="+",
        help=(
            "Path(s) to session file(s) (.json or .jsonl) or directories. "
            "Multiple paths produce one aggregated scan report. "
            "'-' reads one session artifact from stdin (max 100 MB)."
        ),
    )
    check_parser.add_argument(
        "--format",
        choices=["auto", "claude-code-jsonl", "openai-agents", "codex-rollout", "canonical"],
        default=argparse.SUPPRESS,
        help="Session format adapter (default: auto)",
    )
    check_parser.add_argument(
        "--profile",
        default=argparse.SUPPRESS,
        help="Replay validation profile (default: neutral)",
    )
    check_parser.add_argument(
        "--policy",
        dest="check_policy",
        default=None,
        help="[Invalid for check] Repair policy is only applicable to 'repair'",
    )
    check_parser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        default=False,
        help="Recursively scan directory trees for session artifacts",
    )
    check_parser.add_argument(
        "--follow-symlinks",
        action="store_true",
        default=False,
        help="[lossy: follows links] Follow directory symlinks during recursive scanning",
    )
    check_parser.add_argument(
        "--max-files",
        type=_validate_positive_int,
        default=None,
        help="Maximum number of files to inspect during recursive scan (default: 10000)",
    )
    check_parser.add_argument(
        "--max-bytes",
        type=_validate_positive_int,
        default=None,
        help="Maximum cumulative bytes to read during recursive scan (default: 1GB)",
    )
    check_out_group = check_parser.add_mutually_exclusive_group()
    check_out_group.add_argument(
        "--json",
        action="store_true",
        help="Output check report as a single canonical JSON document to stdout",
    )
    check_out_group.add_argument(
        "--output-format",
        choices=["human", "json", "sarif", "html"],
        default=None,
        help="Output format (default: human; --json is equivalent to 'json')",
    )
    check_parser.add_argument(
        "--progress-json",
        action="store_true",
        help="Emit NDJSON progress events to stderr (stdout stays the result channel)",
    )
    check_parser.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default=argparse.SUPPRESS,
        help="Control colored output in human report mode (default: auto)",
    )
    check_parser.add_argument(
        "--no-color",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Disable ANSI color styling",
    )
    check_parser.add_argument(
        "--confidence-min",
        type=_validate_unit_interval_float,
        default=None,
        help="Format auto-detection minimum confidence threshold",
    )
    check_parser.add_argument(
        "--margin-min",
        type=_validate_unit_interval_float,
        default=None,
        help="Format auto-detection minimum margin threshold",
    )
    check_parser.add_argument(
        "--skip-undetected",
        action="store_true",
        default=False,
        help=(
            "Classify files whose format cannot be detected as skipped instead "
            "of invalid (useful for pre-commit hooks and mixed-content trees)"
        ),
    )
    check_parser.add_argument(
        "--fail-on",
        choices=["error", "warning"],
        default=None,
        help="Minimum finding severity that fails the command (default: error)",
    )
    check_parser.add_argument(
        "--config",
        type=Path,
        default=None,
        metavar="PATH",
        help="Explicit config file path (overrides [tool.sesslint] discovery)",
    )
    check_rules_group = check_parser.add_mutually_exclusive_group()
    check_rules_group.add_argument(
        "--select",
        metavar="CODES",
        default=None,
        help="Comma-separated rule codes to run exclusively (e.g. SL101,SL102)",
    )
    check_rules_group.add_argument(
        "--ignore",
        metavar="CODES",
        default=None,
        help="Comma-separated rule codes to skip (e.g. SL101,SL102)",
    )
    check_baseline_group = check_parser.add_mutually_exclusive_group()
    check_baseline_group.add_argument(
        "--baseline",
        type=Path,
        default=None,
        metavar="PATH",
        help="Suppress findings whose fingerprints are recorded in baseline file",
    )
    check_baseline_group.add_argument(
        "--write-baseline",
        type=Path,
        default=None,
        metavar="PATH",
        help="Write the current finding fingerprints as a new baseline file",
    )
    check_parser.add_argument(
        "--exclude",
        action="append",
        default=None,
        metavar="GLOB",
        help="Skip files/dirs whose name or root-relative path matches GLOB (repeatable)",
    )
    check_parser.add_argument(
        "--ext",
        action="append",
        default=None,
        metavar="EXT",
        help="Only inspect files with these extensions during directory walks (repeatable)",
    )
    check_parser.add_argument(
        "--include-content",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Embed raw transcript content in reports (warning: emits raw sensitive data)",
    )

    # formats
    formats_parser = subparsers.add_parser(
        "formats",
        help="[read-only] List supported session format adapters.",
        description=(
            "[read-only] List supported session format adapters and their supported version specs."
        ),
    )
    formats_parser.add_argument(
        "--json",
        action="store_true",
        help="Output supported formats as JSON array",
    )

    # version
    version_parser = subparsers.add_parser(
        "version",
        help="[read-only] Display detailed component and schema version information.",
        description="[read-only] Display detailed component and schema version information.",
    )
    version_parser.add_argument(
        "--json",
        action="store_true",
        help="Output version details as JSON object",
    )

    # scan
    scan_parser = subparsers.add_parser(
        "scan",
        help="[read-only] Scan directory trees for session artifacts or display limits.",
        description="[read-only] Scan directory trees for session artifacts or display limits.",
    )
    scan_parser.add_argument(
        "path",
        type=Path,
        nargs="?",
        default=None,
        help="Directory path to scan (or omit when using --agent or --show-limits). "
        "'-' scans one session artifact from stdin (max 100 MB)",
    )
    scan_parser.add_argument(
        "--agent",
        choices=["claude", "codex", "all"],
        default=None,
        help="Scan well-known session roots for an agent runtime "
        "($CLAUDE_CONFIG_DIR/projects or ~/.claude/projects; "
        "$CODEX_HOME/sessions or ~/.codex/sessions). Explicit PATH overrides.",
    )
    scan_parser.add_argument(
        "--show-limits",
        action="store_true",
        help="Display default hostile-input reader limits.",
    )
    scan_parser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        default=True,
        help="Recursively scan directory trees (default: True)",
    )
    scan_parser.add_argument(
        "--follow-symlinks",
        action="store_true",
        default=False,
        help="Follow directory symlinks during scan",
    )
    scan_parser.add_argument(
        "--max-files",
        type=_validate_positive_int,
        default=None,
        help="Maximum files to scan (default: 10000)",
    )
    scan_parser.add_argument(
        "--max-bytes",
        type=_validate_positive_int,
        default=None,
        help="Maximum cumulative bytes to read during recursive scan (default: 1GB)",
    )
    scan_parser.add_argument(
        "--format",
        choices=["auto", "claude-code-jsonl", "openai-agents", "codex-rollout", "canonical"],
        default=argparse.SUPPRESS,
        help="Session format adapter (default: auto)",
    )
    scan_parser.add_argument(
        "--profile",
        default=argparse.SUPPRESS,
        help="Replay validation profile (default: neutral)",
    )
    scan_parser.add_argument(
        "--confidence-min",
        type=_validate_unit_interval_float,
        default=None,
        help="Format auto-detection minimum confidence threshold",
    )
    scan_parser.add_argument(
        "--margin-min",
        type=_validate_unit_interval_float,
        default=None,
        help="Format auto-detection minimum margin threshold",
    )
    scan_parser.add_argument(
        "--skip-undetected",
        action="store_true",
        default=False,
        help=(
            "Classify files whose format cannot be detected as skipped instead "
            "of invalid (useful for hooks and mixed-content trees)"
        ),
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["error", "warning"],
        default=None,
        help="Minimum finding severity that fails the command (default: error)",
    )
    scan_parser.add_argument(
        "--config",
        type=Path,
        default=None,
        metavar="PATH",
        help="Explicit config file path (overrides [tool.sesslint] discovery)",
    )
    scan_rules_group = scan_parser.add_mutually_exclusive_group()
    scan_rules_group.add_argument(
        "--select",
        metavar="CODES",
        default=None,
        help="Comma-separated rule codes to run exclusively (e.g. SL101,SL102)",
    )
    scan_rules_group.add_argument(
        "--ignore",
        metavar="CODES",
        default=None,
        help="Comma-separated rule codes to skip (e.g. SL101,SL102)",
    )
    scan_baseline_group = scan_parser.add_mutually_exclusive_group()
    scan_baseline_group.add_argument(
        "--baseline",
        type=Path,
        default=None,
        metavar="PATH",
        help="Suppress findings whose fingerprints are recorded in baseline file",
    )
    scan_baseline_group.add_argument(
        "--write-baseline",
        type=Path,
        default=None,
        metavar="PATH",
        help="Write the current finding fingerprints as a new baseline file",
    )
    scan_parser.add_argument(
        "--exclude",
        action="append",
        default=None,
        metavar="GLOB",
        help="Skip files/dirs whose name or root-relative path matches GLOB (repeatable)",
    )
    scan_parser.add_argument(
        "--ext",
        action="append",
        default=None,
        metavar="EXT",
        help="Only inspect files with these extensions during directory walks (repeatable)",
    )
    scan_out_group = scan_parser.add_mutually_exclusive_group()
    scan_out_group.add_argument(
        "--json",
        action="store_true",
        help="Output scan report as JSON",
    )
    scan_out_group.add_argument(
        "--output-format",
        choices=["human", "json", "sarif", "html"],
        default=None,
        help="Output format (default: human; --json is equivalent to 'json')",
    )
    scan_parser.add_argument(
        "--progress-json",
        action="store_true",
        help="Emit NDJSON progress events to stderr (stdout stays the result channel)",
    )
    scan_parser.add_argument(
        "--top",
        type=int,
        default=10,
        metavar="N",
        help=(
            "Show up to N worst files in the report summary (default: 10; "
            "0 disables the worst-files view)"
        ),
    )
    scan_parser.add_argument(
        "--group-by",
        choices=["code", "none"],
        default="code",
        help="Summary grouping: 'code' aggregates findings by rule code (default), 'none' disables",
    )
    scan_parser.add_argument(
        "--jobs",
        default="1",
        metavar="N",
        help=(
            "Parallel worker processes for per-file analysis (default: 1 = "
            "sequential; 'auto' or 0 = CPU count). Report output is identical "
            "for any N; only wall time changes. Ignored for single-file input."
        ),
    )
    scan_parser.add_argument(
        "--incremental",
        action="store_true",
        help=(
            "Reuse cached per-file results when content is provably unchanged "
            "(sqlite cache; findings/verdicts identical, hits marked 'cache: hit')"
        ),
    )
    scan_parser.add_argument(
        "--cache-dir",
        default=None,
        metavar="DIR",
        help=(
            "Override the incremental cache directory "
            "(default: SESSLINT_CACHE_DIR or platform cache location)"
        ),
    )
    scan_parser.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default=argparse.SUPPRESS,
        help="Control colored terminal output (default: auto)",
    )
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Disable ANSI color styling",
    )

    # repair
    repair_parser = subparsers.add_parser(
        "repair",
        help=(
            "[writes: output file and manifest, lossy under --policy salvage] "
            "Safely repair a session file."
        ),
        description=(
            "[writes: output file and manifest, lossy under --policy salvage] "
            "Safely repair a session file with atomic execution."
        ),
    )
    repair_parser.add_argument(
        "path",
        type=Path,
        nargs="?",
        default=None,
        help="Path to source session file. '-' reads the source from stdin "
        "(max 100 MB; still requires --output unless --dry-run). Omit when "
        "using --batch/--from-scan/--files",
    )
    repair_parser.add_argument(
        "--output",
        "--out",
        "-o",
        type=Path,
        default=None,
        dest="output",
        help="Path to output repaired session file",
    )
    repair_parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Plan-only mode; do not write any files",
    )
    repair_parser.add_argument(
        "--preview",
        action="store_true",
        default=False,
        help=(
            "Render the structural repair preview (sesslint.preview/v1): "
            "content-free delta rows per plan step, then exit without "
            "writing. Incompatible with --output/--plan-out/--apply-plan/"
            "batch modes. *(next release)*"
        ),
    )
    repair_parser.add_argument(
        "--policy",
        choices=["conservative", "salvage"],
        default=argparse.SUPPRESS,
        help="Repair policy (choices: conservative, salvage; default: conservative)",
    )
    repair_parser.add_argument(
        "--format",
        choices=["auto", "claude-code-jsonl", "openai-agents", "codex-rollout", "canonical"],
        default=argparse.SUPPRESS,
        help="Session format adapter (default: auto)",
    )
    repair_parser.add_argument(
        "--emit",
        choices=["auto", "canonical", "vendor"],
        default="auto",
        help=(
            "Output artifact format. 'auto' (default) emits the input's own "
            "format: vendor input produces a drop-only line-verbatim "
            "write-back; 'canonical' always emits the canonical session stream."
        ),
    )
    repair_parser.add_argument(
        "--profile",
        default=argparse.SUPPRESS,
        help="Replay validation profile (default: neutral)",
    )
    repair_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output manifest or plan in JSON format",
    )
    repair_parser.add_argument(
        "--progress-json",
        action="store_true",
        default=False,
        help="Emit NDJSON progress events to stderr (stdout stays the result channel)",
    )
    repair_parser.add_argument(
        "--plan",
        "--apply-plan",
        type=Path,
        default=None,
        dest="plan",
        help=(
            "Apply a previously exported plan JSON (sesslint.plan/v1) without "
            "re-planning. The plan is authoritative: --policy/--profile/--format "
            "overrides are refused, and execution still re-validates the plan "
            "fingerprint and source binding. *(next release)*"
        ),
    )
    repair_parser.add_argument(
        "--plan-out",
        type=Path,
        default=None,
        dest="plan_out",
        help=(
            "Export the computed repair plan (sesslint.plan/v1) to PATH for "
            "review or later --apply-plan. Plan-only when --output is absent; "
            "with --output the exported plan is executed in the same run. "
            "*(next release)*"
        ),
    )
    repair_parser.add_argument(
        "--batch",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "Batch-repair every eligible session file under DIR (eligibility "
            "= planner computes steps with zero blocked findings). Outputs "
            "mirror DIR's structure under --output-dir. *(next release)*"
        ),
    )
    repair_parser.add_argument(
        "--from-scan",
        type=Path,
        default=None,
        metavar="REPORT.json",
        help=(
            "Batch-repair files listed in a sesslint scan JSON report; only "
            "'~/'-minimized and absolute paths resolve — '.._<hash>' entries "
            "are reported skipped. *(next release)*"
        ),
    )
    repair_parser.add_argument(
        "--files",
        type=Path,
        nargs="+",
        default=None,
        metavar="FILE",
        help="Batch-repair an explicit file list into --output-dir. *(next release)*",
    )
    repair_parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help="Output root for batch repair modes (mirrors input structure). *(next release)*",
    )
    repair_parser.add_argument(
        "--manifest-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "Manifest root for batch modes; manifests are named "
            "<sha8-of-source-path>.manifest.json. Default: adjacent to each "
            "output. *(next release)*"
        ),
    )
    repair_parser.add_argument(
        "--acknowledge-side-effects",
        action="store_true",
        default=False,
        help="Acknowledge tool side-effects for salvage policy",
    )
    repair_parser.add_argument(
        "--salvage-unsupported",
        action="store_true",
        default=False,
        help="[Deprecated] Use '--policy salvage' instead",
    )
    repair_parser.add_argument(
        "--include-content",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Embed raw transcript content in manifests (warning: emits raw sensitive data)",
    )
    repair_parser.add_argument(
        "--config",
        type=Path,
        default=None,
        metavar="PATH",
        help="Explicit config file path (overrides [tool.sesslint] discovery)",
    )

    # verify
    verify_parser = subparsers.add_parser(
        "verify",
        help="[read-only] Verify integrity, hash bindings, and idempotence of a repaired session.",
        description=(
            "[read-only] Verify integrity, hash bindings, and idempotence of a repaired "
            "session artifact."
        ),
    )
    verify_parser.add_argument(
        "source",
        type=Path,
        nargs="?",
        default=None,
        help="Path to source session file",
    )
    verify_parser.add_argument(
        "repaired",
        type=Path,
        nargs="?",
        default=None,
        help="Path to repaired session file",
    )
    verify_parser.add_argument(
        "--source",
        type=Path,
        default=None,
        dest="source_flag",
        help=argparse.SUPPRESS,
    )
    verify_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        dest="output_flag",
        help=argparse.SUPPRESS,
    )
    verify_parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="Path to repair manifest JSON file",
    )
    verify_parser.add_argument(
        "--plan",
        type=Path,
        default=None,
        help="Path to repair plan JSON file (optional)",
    )
    verify_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output verify verdict as JSON to stdout",
    )
    verify_parser.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default=argparse.SUPPRESS,
        help="Control colored output in human report mode",
    )
    verify_parser.add_argument(
        "--no-color",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Disable ANSI color styling",
    )
    verify_parser.add_argument(
        "--acknowledge-side-effects",
        action="store_true",
        default=False,
        help="Acknowledge tool side-effects for salvage policy during verify idempotence check",
    )
    verify_parser.add_argument(
        "--include-content",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Embed raw transcript content (warning: emits raw sensitive data)",
    )

    # bundle
    bundle_parser = subparsers.add_parser(
        "bundle",
        help="[read-only] Generate a privacy-safe diagnostic support bundle and fixture skeleton.",
        description=(
            "[read-only] Generate a privacy-safe diagnostic support bundle and fixture skeleton."
        ),
    )
    bundle_parser.add_argument(
        "path",
        type=Path,
        help="Path to session file (.json or .jsonl)",
    )
    bundle_parser.add_argument(
        "--output",
        "--out",
        "-o",
        type=Path,
        default=None,
        dest="output",
        help="Path to output bundle JSON file",
    )
    bundle_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output bundle as JSON to stdout",
    )
    bundle_parser.add_argument(
        "--format",
        choices=["auto", "claude-code-jsonl", "openai-agents", "codex-rollout", "canonical"],
        default=argparse.SUPPRESS,
        help="Session format adapter (default: auto)",
    )
    bundle_parser.add_argument(
        "--profile",
        default=argparse.SUPPRESS,
        help="Replay validation profile (default: neutral)",
    )
    bundle_parser.add_argument(
        "--confidence-min",
        type=_validate_unit_interval_float,
        default=None,
        help="Minimum confidence threshold for format auto-detection",
    )
    bundle_parser.add_argument(
        "--margin-min",
        type=_validate_unit_interval_float,
        default=None,
        help="Minimum margin threshold between top candidates for auto-detection",
    )
    bundle_parser.add_argument(
        "--strict-share",
        action="store_true",
        default=False,
        help=(
            "Exit 1 without writing output when the source file contains "
            "secret-shaped material (SL009 share_advisory present)"
        ),
    )

    # export
    export_parser = subparsers.add_parser(
        "export",
        help="[writes: output file] Export a session artifact to canonical format for repair.",
        description=(
            "[writes: output file] Export a supported session artifact to a "
            "byte-deterministic canonical file that the repair pipeline accepts."
        ),
    )
    export_parser.add_argument(
        "path",
        type=Path,
        help="Path to session file (.json or .jsonl)",
    )
    export_parser.add_argument(
        "--output",
        "--out",
        "-o",
        type=Path,
        default=None,
        dest="output",
        help="Path to output canonical file (required)",
    )
    export_parser.add_argument(
        "--format",
        choices=["auto", "claude-code-jsonl", "openai-agents", "codex-rollout", "canonical"],
        default=argparse.SUPPRESS,
        help="Session format adapter (default: auto)",
    )
    export_parser.add_argument(
        "--json",
        action="store_true",
        help="Output export summary as JSON",
    )

    # completion
    completion_parser = subparsers.add_parser(
        "completion",
        help="[read-only] Print shell completion script.",
        description=("[read-only] Print a shell completion script generated from the live parser."),
    )
    completion_parser.add_argument(
        "shell",
        choices=["bash", "zsh", "fish", "powershell"],
        help="Shell dialect (bash, zsh, fish, powershell)",
    )

    # baseline
    baseline_parser = subparsers.add_parser(
        "baseline",
        help="[read-only] Upgrade a v1 baseline to the path-normalized v2 format.",
        description=(
            "[read-only] Baseline maintenance: --upgrade rewrites a "
            "sesslint.baseline/v1 file as v2 (path-normalized keys). With "
            "--source, findings are reproduced to verify entries; without it "
            "every entry migrates 'unverified' (still matchable via the v1 leg)."
        ),
    )
    baseline_parser.add_argument(
        "--upgrade",
        required=True,
        type=Path,
        metavar="FILE",
        help="Baseline file to upgrade (must be sesslint.baseline/v1)",
    )
    baseline_parser.add_argument(
        "--source",
        type=Path,
        default=None,
        metavar="PATH",
        help="Session file or directory to re-check for verified migration",
    )
    baseline_parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        metavar="PATH",
        help="Write the upgraded baseline here (default: stdout)",
    )
    baseline_parser.add_argument(
        "--format",
        choices=["auto", "canonical", "claude-code-jsonl", "openai-agents", "codex-rollout"],
        default="auto",
        help="Input format override for --source (default: auto)",
    )
    baseline_parser.add_argument(
        "--profile",
        default="neutral",
        help="Validation profile for --source re-check (default: neutral)",
    )

    # diff
    diff_parser = subparsers.add_parser(
        "diff",
        help="[read-only] Structurally diff two session files.",
        description=(
            "[read-only] Compare two session files by event identity "
            "(not text diff): added/removed events, kind changes, parent "
            "relinks, sequence reorders, content changes (hash only)."
        ),
    )
    diff_parser.add_argument("a", type=Path, help="Path to the first session file")
    diff_parser.add_argument("b", type=Path, help="Path to the second session file")
    diff_parser.add_argument(
        "--format",
        choices=["auto", "claude-code-jsonl", "openai-agents", "codex-rollout", "canonical"],
        default="auto",
        help="Session format adapter for both inputs (default: auto)",
    )
    diff_parser.add_argument(
        "--format-a",
        dest="format_a",
        choices=["claude-code-jsonl", "openai-agents", "codex-rollout", "canonical"],
        default=None,
        help="Format override for input A only",
    )
    diff_parser.add_argument(
        "--format-b",
        dest="format_b",
        choices=["claude-code-jsonl", "openai-agents", "codex-rollout", "canonical"],
        default=None,
        help="Format override for input B only",
    )
    diff_parser.add_argument(
        "--output-format",
        choices=["human", "json"],
        default=None,
        help="Output format (default: human)",
    )
    diff_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit sesslint.diff/v1 JSON (shortcut for --output-format json)",
    )

    # stats
    stats_parser = subparsers.add_parser(
        "stats",
        help="[read-only] Aggregate content-free statistics over session files.",
        description=(
            "[read-only] Aggregate statistics over session files or "
            "directories: event counts by kind/actor, tool-call volume per "
            "hashed tool name, compactions, checkpoints, size percentiles."
        ),
    )
    stats_parser.add_argument(
        "path",
        type=Path,
        nargs="*",
        help="Path(s) to session file(s) or directories (use -r for dirs)",
    )
    stats_parser.add_argument(
        "--agent",
        choices=["claude", "codex", "all"],
        default=None,
        help="Aggregate over a well-known agent session root instead of paths",
    )
    stats_parser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        default=False,
        help="Recursively walk directory arguments",
    )
    stats_parser.add_argument(
        "--format",
        choices=["auto", "claude-code-jsonl", "openai-agents", "codex-rollout", "canonical"],
        default="auto",
        help="Session format adapter for all inputs (default: auto)",
    )
    stats_parser.add_argument(
        "--output-format",
        choices=["human", "json"],
        default=None,
        help="Output format (default: human)",
    )
    stats_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit sesslint.stats/v1 JSON (shortcut for --output-format json)",
    )

    # doctor
    doctor_parser = subparsers.add_parser(
        "doctor",
        help="[read-only] Environment diagnostics for support reports.",
        description=(
            "[read-only] Report what SessLint sees on this machine: tool "
            "and adapter versions, resolved config file, agent session "
            "roots, bounded quick verdicts. Counts only — never file names."
        ),
    )
    doctor_parser.add_argument(
        "--agent",
        choices=["claude", "codex", "all"],
        default=None,
        help="Restrict diagnostics to one agent (default: all)",
    )
    doctor_parser.add_argument(
        "--no-quick-checks",
        dest="no_quick_checks",
        action="store_true",
        default=False,
        help="Skip the bounded per-file check pass (counts only)",
    )
    doctor_parser.add_argument(
        "--output-format",
        choices=["human", "json"],
        default=None,
        help="Output format (default: human)",
    )
    doctor_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit sesslint.doctor/v1 JSON (shortcut for --output-format json)",
    )

    # watch
    watch_parser = subparsers.add_parser(
        "watch",
        help="[read-only] Poll session directories and flag newly corrupted files.",
        description=(
            "[read-only] Poll-based observer: debounced mtime+size snapshots, "
            "emits one line per verdict transition. Pure observer — never "
            "writes, never installs hooks. Ctrl+C exits cleanly."
        ),
    )
    watch_parser.add_argument(
        "path",
        type=Path,
        nargs="*",
        help="Path(s) to session file(s) or directories to watch",
    )
    watch_parser.add_argument(
        "--agent",
        choices=["claude", "codex", "all"],
        default=None,
        help="Watch a well-known agent session root instead of paths",
    )
    watch_parser.add_argument(
        "--interval",
        type=float,
        default=2.0,
        metavar="SEC",
        help="Poll interval in seconds (default: 2.0, min: 0.05)",
    )
    watch_parser.add_argument(
        "--format",
        choices=["auto", "claude-code-jsonl", "openai-agents", "codex-rollout", "canonical"],
        default="auto",
        help="Session format adapter for all inputs (default: auto)",
    )
    watch_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit sesslint.watch-event/v1 NDJSON transition events",
    )

    # init-hooks
    hooks_parser = subparsers.add_parser(
        "init-hooks",
        help="[read-only] Print ready-to-merge agent hook snippets (never writes config).",
        description=(
            "[read-only] Print ready-to-merge settings.json hook blocks for "
            "the documented SessionStart/PreCompact recipes. Print-only by "
            "permanent design — SessLint never writes agent configuration."
        ),
    )
    hooks_parser.add_argument(
        "--agent",
        choices=["claude", "codex", "all"],
        default="all",
        help="Agent to generate snippets for (default: all)",
    )
    hooks_parser.add_argument(
        "--print",
        dest="print_mode",
        action="store_true",
        default=True,
        help="Print snippets (the only mode — nothing is ever written)",
    )
    hooks_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit sesslint.init-hooks/v1 JSON instead of human text",
    )

    # hook
    hook_parser = subparsers.add_parser(
        "hook",
        help=(
            "[read-only] Agent hook entrypoint: reads one hook payload "
            "from stdin and checks the transcript."
        ),
        description=(
            "[read-only] Reads one JSON hook payload from stdin (Claude Code "
            "contract: session_id, transcript_path, cwd, hook_event_name), "
            "resolves the transcript file, and runs the event-appropriate "
            "integrity check. Prints one content-free line and exits 0 "
            "(advisory) — or 1 when --fail-on gates on findings. Exit 2 is "
            "never emitted: hook checks never block the agent."
        ),
    )
    hook_parser.add_argument(
        "--event",
        required=True,
        metavar="NAME",
        help=(
            "Hook event name (e.g. SessionStart, PreCompact, PostCompact, "
            "SessionEnd). Unknown names run the generic integrity check."
        ),
    )
    hook_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit sesslint.hook-result/v1 JSON instead of the one-line form",
    )
    hook_parser.add_argument(
        "--fail-on",
        choices=["never", "error", "warning"],
        default=None,
        help=(
            "Minimum finding severity that exits 1 (default: never — hook "
            "checks are advisory; 'warning' fails on any finding)"
        ),
    )
    hook_parser.add_argument(
        "--profile",
        default=None,
        help="Validation profile (default: neutral)",
    )
    hook_parser.add_argument(
        "--format",
        choices=["auto", "claude-code-jsonl", "openai-agents", "codex-rollout", "canonical"],
        default=None,
        help="Session format adapter (default: auto-detect)",
    )

    # mcp
    subparsers.add_parser(
        "mcp",
        help="[read-only] Run a Model Context Protocol server over stdio.",
        description=(
            "[read-only] MCP stdio server (protocol 2025-06-18, newline-"
            "delimited JSON-RPC): exposes sesslint_check / sesslint_precheck / "
            "sesslint_scan tools so agents can call checks natively. "
            "Long-running process — EOF or Ctrl+C exits cleanly."
        ),
    )

    return parser


def _dispatch_command(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """Dispatch parsed CLI command and return exit code."""
    if getattr(args, "include_content", False):
        sys.stderr.write(
            "WARNING: --include-content embeds raw transcript content; do not share output\n"
        )
        sys.stderr.flush()

    # --policy only takes effect on 'repair'; warn instead of silently ignoring
    # (e.g. 'sesslint --policy salvage check' reads as if it applies).
    if (
        getattr(args, "command", None) not in (None, "repair")
        and getattr(args, "policy", None) is not None
    ):
        sys.stderr.write(
            f"WARNING: --policy has no effect on '{args.command}' (it only applies to 'repair')\n"
        )
        sys.stderr.flush()

    if args.command is None:
        parser.print_help(sys.stdout)
        return 2

    if args.command == "formats":
        adapter_data = [
            {
                "default_profile": "neutral",
                "description": "SessLint Canonical Session Format v1 (JSON/JSONL)",
                "name": "canonical",
                "versions_supported": sorted(SUPPORTED_CANONICAL_VERSIONS),
            },
            {
                "default_profile": "claude-strict",
                "description": "Claude Code JSONL session logs adapter",
                "name": "claude-code-jsonl",
                "versions_supported": sorted(SUPPORTED_CLAUDE_VERSIONS),
            },
            {
                "default_profile": "openai-strict",
                "description": "OpenAI Agents SDK item-export adapter",
                "name": "openai-agents",
                "versions_supported": sorted(SUPPORTED_OPENAI_AGENTS_VERSIONS),
            },
            {
                "default_profile": "openai-strict",
                "description": "Codex CLI/Desktop rollout-*.jsonl adapter",
                "name": "codex-rollout",
                "versions_supported": sorted(SUPPORTED_CODEX_ROLLOUT_VERSIONS),
            },
        ]
        if getattr(args, "json", False):
            print(json.dumps(adapter_data, indent=2, sort_keys=True))
        else:
            print(f"{'NAME':<20} {'DEFAULT PROFILE':<18} {'SUPPORTED VERSIONS':<24} DESCRIPTION")
            print("-" * 80)
            for item in adapter_data:
                vers_str = ", ".join(item["versions_supported"])
                print(
                    f"{item['name']:<20} {item['default_profile']:<18} "
                    f"{vers_str:<24} {item['description']}"
                )
        return 0

    if args.command == "version":
        info = get_version_info()
        if getattr(args, "json", False):
            print(json.dumps(info, indent=2, sort_keys=True))
        else:
            print(f"SessLint CLI: {info['cli']}")
            print("Schemas:")
            print(f"  session:  {info['schema_session']}")
            print(f"  report:   {info['schema_report']}")
            print(f"  manifest: {info['schema_manifest']}")
            print("Adapters:")
            for k, v in sorted(info["adapters"].items()):
                print(f"  {k}: {v}")
            print("Profiles:")
            for k, v in sorted(info["profiles"].items()):
                print(f"  {k}: {v}")
        return 0

    if args.command == "scan":
        from sesslint.config import ConfigError, load_config

        try:
            cli_cfg = load_config(explicit=getattr(args, "config", None))
        except ConfigError as err:
            print(f"Error: {err}", file=sys.stderr)
            return 2
        _apply_config(args, cli_cfg)

        if getattr(args, "show_limits", False):
            from sesslint.io import ReaderLimits

            limits = ReaderLimits()
            print(
                f"ReaderLimits: max_line_bytes={limits.max_line_bytes}, "
                f"max_depth={limits.max_depth}, "
                f"max_file_bytes={limits.max_file_bytes}, "
                f"max_records={limits.max_records}"
            )
            return 0

        agent = getattr(args, "agent", None)
        explicit_scan_path = getattr(args, "path", None)
        if agent is not None and explicit_scan_path is not None:
            print(
                "Warning: explicit PATH overrides --agent; scanning PATH only.",
                file=sys.stderr,
            )
            agent = None

        if agent is None and explicit_scan_path is None:
            parser.print_help(sys.stderr)
            return 2

        from sesslint.api import check_dir

        try:
            scan_baseline = _load_baseline_arg(args)
        except ValueError as err:
            print(f"Error: {err}", file=sys.stderr)
            return 2

        scan_kwargs: dict[str, Any] = {
            "recursive": getattr(args, "recursive", True),
            "follow_symlinks": getattr(args, "follow_symlinks", False),
            "max_files": getattr(args, "max_files", 10000),
            "max_bytes": getattr(args, "max_bytes", 1024 * 1024 * 1024),
            "format": getattr(args, "format", "auto"),
            "profile": getattr(args, "profile", "neutral"),
            "confidence_min": getattr(args, "confidence_min", None),
            "margin_min": getattr(args, "margin_min", None),
            "progress_cb": _ndjson_progress_cb(args),
            "skip_undetected": getattr(args, "skip_undetected", False),
            "select": _rule_codes_arg(args, "select"),
            "ignore": _rule_codes_arg(args, "ignore"),
            "baseline": scan_baseline,
            "exclude": getattr(args, "exclude", None),
            "ext": getattr(args, "ext", None),
            "incremental": getattr(args, "incremental", False),
            "cache_dir": getattr(args, "cache_dir", None),
        }

        jobs_raw = str(getattr(args, "jobs", "1")).strip().lower()
        if jobs_raw in ("auto", "0"):
            scan_kwargs["jobs"] = os.cpu_count() or 1
        else:
            try:
                scan_kwargs["jobs"] = int(jobs_raw)
            except ValueError:
                print(
                    f"Error: --jobs must be a positive integer or 'auto', got '{jobs_raw}'",
                    file=sys.stderr,
                )
                return 2
            if scan_kwargs["jobs"] < 1:
                print(
                    f"Error: --jobs must be a positive integer or 'auto', got '{jobs_raw}'",
                    file=sys.stderr,
                )
                return 2

        if agent is not None:
            from sesslint.api import discover_session_roots
            from sesslint.report import minimize_path
            from sesslint.scan import FileResult, ScanReport, ScanTotals

            requested = ("claude", "codex") if agent == "all" else (agent,)
            roots = discover_session_roots(requested)

            merged_files: list[FileResult] = []
            totals = ScanTotals()

            def _acc_totals(t: ScanTotals, r: ScanTotals) -> ScanTotals:
                return ScanTotals(
                    healthy=t.healthy + r.healthy,
                    invalid=t.invalid + r.invalid,
                    unsupported=t.unsupported + r.unsupported,
                    unreadable=t.unreadable + r.unreadable,
                    skipped=t.skipped + r.skipped,
                )

            try:
                for root in roots:
                    if root.exists:
                        rep = check_dir(root.path, **scan_kwargs)
                        merged_files.extend(rep.files)
                        totals = _acc_totals(totals, rep.totals)
                    else:
                        skip_reason = (
                            "agent-root-missing"
                            if not root.path.exists()
                            else "agent-root-not-directory"
                        )
                        merged_files.append(
                            FileResult(
                                path=minimize_path(root.path),
                                verdict="skipped",
                                skipped_reason=skip_reason,
                            )
                        )
                        totals = _acc_totals(totals, ScanTotals(skipped=1))
            except (ValueError, KeyError) as err:
                err_msg = err.args[0] if err.args else str(err)
                print(f"Error: {err_msg}", file=sys.stderr)
                return 2

            root_str = ";".join(minimize_path(r.path) for r in roots)
            scan_rep = ScanReport(root_path=root_str, totals=totals, files=tuple(merged_files))
        else:
            target_scan_path: Path = args.path
            if str(target_scan_path) == "-":
                # `-` scans one session artifact streamed on stdin (ux T-06).
                from sesslint.io import DEFAULT_MAX_FILE_BYTES
                from sesslint.scan import scan_bytes

                stdin_data = _read_stdin_bytes()
                try:
                    scan_rep = scan_bytes(
                        stdin_data,
                        max_input_bytes=DEFAULT_MAX_FILE_BYTES,
                        format=scan_kwargs["format"],
                        profile=scan_kwargs["profile"],
                        confidence_min=scan_kwargs["confidence_min"],
                        margin_min=scan_kwargs["margin_min"],
                        progress_cb=scan_kwargs["progress_cb"],
                        skip_undetected=scan_kwargs["skip_undetected"],
                        select=scan_kwargs["select"],
                        ignore=scan_kwargs["ignore"],
                        baseline=scan_kwargs["baseline"],
                    )
                except (ValueError, KeyError) as err:
                    err_msg = err.args[0] if err.args else str(err)
                    print(f"Error: {err_msg}", file=sys.stderr)
                    return 2
            else:
                if not target_scan_path.exists():
                    print(f"Error: Path not found: {target_scan_path}", file=sys.stderr)
                    return 2
                if scan_kwargs["jobs"] > 1 and not target_scan_path.is_dir():
                    print("Note: --jobs is ignored for single-file input.", file=sys.stderr)

                try:
                    scan_rep = check_dir(target_scan_path, **scan_kwargs)
                except (ValueError, KeyError) as err:
                    err_msg = err.args[0] if err.args else str(err)
                    print(f"Error: {err_msg}", file=sys.stderr)
                    return 2

        _write_baseline_arg(args, [f for fr in scan_rep.files for f in fr.findings])

        # Attach the aggregated summary view (ux T-08): by-code grouping and
        # top-N worst files. Pure presentation — findings are unchanged.
        top_n = getattr(args, "top", 10)
        group_by = getattr(args, "group_by", "code")
        if top_n < 0:
            print(f"Error: --top must be >= 0, got {top_n}", file=sys.stderr)
            return 2
        if group_by != "none" or top_n > 0:
            import dataclasses

            from sesslint.scan import aggregate_scan

            scan_rep = dataclasses.replace(
                scan_rep, summary=aggregate_scan(scan_rep.files, top=top_n, group_by=group_by)
            )

        out_fmt = _output_format(args)
        if out_fmt == "json":
            print(scan_rep.to_json())
        elif out_fmt == "sarif":
            from sesslint.sarif import scan_report_sarif

            print(scan_report_sarif(scan_rep, tool_version=__version__))
        elif out_fmt == "html":
            from sesslint.html_report import scan_report_html

            print(scan_report_html(scan_rep, tool_version=__version__))
        else:
            use_color = should_color(args, sys.stdout)
            print(format_scan_report_human(scan_rep, color=use_color))

        warn_total = sum(f.warning_count for f in scan_rep.files)
        if (
            scan_rep.totals.invalid > 0
            or scan_rep.totals.unsupported > 0
            or scan_rep.totals.unreadable > 0
            or (getattr(args, "fail_on", "error") == "warning" and warn_total > 0)
        ):
            return 1
        return 0

    if args.command == "validate-session":
        try:
            session = load_session_file(args.path)
            print(f"Valid session: {session.header.session_id} ({len(session.events)} events)")
            return 0
        except SesslintError as err:
            print(f"Validation error [{err.code}]: {err}", file=sys.stderr)
            return 1
        except FileNotFoundError as err:
            print(f"Error: {err}", file=sys.stderr)
            return 2
        except Exception as err:
            print(f"Unexpected error: {err}", file=sys.stderr)
            return 2

    if args.command == "check":
        from sesslint.config import ConfigError, load_config

        try:
            cli_cfg = load_config(explicit=getattr(args, "config", None))
        except ConfigError as err:
            print(f"Error: {err}", file=sys.stderr)
            return 2
        _apply_config(args, cli_cfg)

        if getattr(args, "check_policy", None) is not None:
            print(
                "Error: The --policy option is only valid for 'repair', not 'check'.",
                file=sys.stderr,
            )
            return 2

        try:
            check_baseline = _load_baseline_arg(args)
        except ValueError as err:
            print(f"Error: {err}", file=sys.stderr)
            return 2

        def _emit_scan_rep(scan_rep: Any) -> int:
            _write_baseline_arg(args, [f for fr in scan_rep.files for f in fr.findings])
            out_fmt = _output_format(args)
            if out_fmt == "json":
                print(scan_rep.to_json())
            elif out_fmt == "sarif":
                from sesslint.sarif import scan_report_sarif

                print(scan_report_sarif(scan_rep, tool_version=__version__))
            elif out_fmt == "html":
                from sesslint.html_report import scan_report_html

                print(scan_report_html(scan_rep, tool_version=__version__))
            else:
                use_color = should_color(args, sys.stdout)
                print(format_scan_report_human(scan_rep, color=use_color))
            warn_total = sum(f.warning_count for f in scan_rep.files)
            if (
                scan_rep.totals.invalid > 0
                or scan_rep.totals.unsupported > 0
                or scan_rep.totals.unreadable > 0
                or (getattr(args, "fail_on", "error") == "warning" and warn_total > 0)
            ):
                return 1
            return 0

        target_paths: list[Path] = args.path

        # `-` reads one session artifact from stdin (ux T-06). It cannot be
        # combined with filesystem paths — one stream is one virtual file.
        if any(str(p) == "-" for p in target_paths):
            if len(target_paths) > 1:
                print(
                    "Error: '-' (stdin) cannot be combined with other paths.",
                    file=sys.stderr,
                )
                return 2
            stdin_data = _read_stdin_bytes()
            from sesslint.api import check_bytes
            from sesslint.io import DEFAULT_MAX_FILE_BYTES

            format_opt = getattr(args, "format", "auto")
            profile_opt = getattr(args, "profile", "neutral")
            try:
                report = check_bytes(
                    stdin_data,
                    max_input_bytes=DEFAULT_MAX_FILE_BYTES,
                    format=format_opt if format_opt != "auto" else None,
                    profile=profile_opt,
                    confidence_min=getattr(args, "confidence_min", None),
                    margin_min=getattr(args, "margin_min", None),
                    progress_cb=_ndjson_progress_cb(args),
                    select=_rule_codes_arg(args, "select"),
                    ignore=_rule_codes_arg(args, "ignore"),
                    baseline=check_baseline,
                )
            except (ValueError, KeyError) as err:
                if "not permitted by profile" in str(err):
                    print(str(err), file=sys.stderr)
                    return 2
                parser.error(str(err))
            except SesslintError as err:
                print(f"Validation error [{err.code}]: {err}", file=sys.stderr)
                return 1
            except Exception as err:
                return _handle_internal_error(err, args)

            return _emit_check_report(
                report,
                args,
                display_path="<stdin>",
                format_opt=format_opt,
                profile_opt=profile_opt,
            )

        # Multi-path mode: aggregate per-path results into one ScanReport
        # (pre-commit appends every staged filename to a single invocation).
        if len(target_paths) > 1:
            for p in target_paths:
                if not p.exists() and not p.is_symlink():
                    print(f"Error: Path not found: {p}", file=sys.stderr)
                    return 2
                if p.is_dir() and not getattr(args, "recursive", False):
                    print(
                        f"Error: Path {p} is a directory. Use --recursive to scan directories.",
                        file=sys.stderr,
                    )
                    return 2

            from sesslint.report import minimize_path
            from sesslint.scan import FileResult, ScanReport, ScanTotals, scan_path

            multi_files: list[FileResult] = []
            totals = ScanTotals()
            for p in target_paths:
                try:
                    rep = scan_path(
                        p,
                        recursive=getattr(args, "recursive", False),
                        follow_symlinks=getattr(args, "follow_symlinks", False),
                        max_files=getattr(args, "max_files", 10000),
                        max_bytes=getattr(args, "max_bytes", 1024 * 1024 * 1024),
                        format=getattr(args, "format", "auto"),
                        profile=getattr(args, "profile", "neutral"),
                        confidence_min=getattr(args, "confidence_min", None),
                        margin_min=getattr(args, "margin_min", None),
                        progress_cb=_ndjson_progress_cb(args),
                        skip_undetected=getattr(args, "skip_undetected", False),
                        select=_rule_codes_arg(args, "select"),
                        ignore=_rule_codes_arg(args, "ignore"),
                        baseline=check_baseline,
                        exclude=getattr(args, "exclude", None),
                        ext=getattr(args, "ext", None),
                    )
                except (ValueError, KeyError) as err:
                    err_msg = err.args[0] if err.args else str(err)
                    print(f"Error: {err_msg}", file=sys.stderr)
                    return 2
                multi_files.extend(rep.files)
                t = rep.totals
                totals = ScanTotals(
                    healthy=totals.healthy + t.healthy,
                    invalid=totals.invalid + t.invalid,
                    unsupported=totals.unsupported + t.unsupported,
                    unreadable=totals.unreadable + t.unreadable,
                    skipped=totals.skipped + t.skipped,
                )
            multi_files.sort(key=lambda r: r.path)
            scan_rep = ScanReport(
                root_path=";".join(minimize_path(p) for p in target_paths),
                totals=totals,
                files=tuple(multi_files),
            )
            return _emit_scan_rep(scan_rep)

        target_path: Path = target_paths[0]
        if target_path.is_dir():
            if not getattr(args, "recursive", False):
                print(
                    f"Error: Path {target_path} is a directory. "
                    "Use --recursive to scan directories.",
                    file=sys.stderr,
                )
                return 2

            from sesslint.api import check_dir

            try:
                scan_rep = check_dir(
                    target_path,
                    recursive=True,
                    follow_symlinks=getattr(args, "follow_symlinks", False),
                    max_files=getattr(args, "max_files", 10000),
                    max_bytes=getattr(args, "max_bytes", 1024 * 1024 * 1024),
                    format=getattr(args, "format", "auto"),
                    profile=getattr(args, "profile", "neutral"),
                    confidence_min=getattr(args, "confidence_min", None),
                    margin_min=getattr(args, "margin_min", None),
                    progress_cb=_ndjson_progress_cb(args),
                    skip_undetected=getattr(args, "skip_undetected", False),
                    select=_rule_codes_arg(args, "select"),
                    ignore=_rule_codes_arg(args, "ignore"),
                    baseline=check_baseline,
                    exclude=getattr(args, "exclude", None),
                    ext=getattr(args, "ext", None),
                )
            except (ValueError, KeyError) as err:
                err_msg = err.args[0] if err.args else str(err)
                print(f"Error: {err_msg}", file=sys.stderr)
                return 2

            return _emit_scan_rep(scan_rep)

        if not target_path.exists():
            print(f"Error: Path not found: {target_path}", file=sys.stderr)
            return 2

        format_opt = getattr(args, "format", "auto")
        profile_opt = getattr(args, "profile", "neutral")

        try:
            from sesslint.api import check_file

            try:
                report = check_file(
                    target_path,
                    format=format_opt if format_opt != "auto" else None,
                    profile=profile_opt,
                    confidence_min=getattr(args, "confidence_min", None),
                    margin_min=getattr(args, "margin_min", None),
                    progress_cb=_ndjson_progress_cb(args),
                    select=_rule_codes_arg(args, "select"),
                    ignore=_rule_codes_arg(args, "ignore"),
                    baseline=check_baseline,
                )
            except (ValueError, KeyError) as err:
                if "not permitted by profile" in str(err):
                    print(str(err), file=sys.stderr)
                    return 2
                parser.error(str(err))

            return _emit_check_report(
                report,
                args,
                display_path=str(target_path),
                format_opt=format_opt,
                profile_opt=profile_opt,
            )

        except SesslintError as err:
            print(f"Validation error [{err.code}]: {err}", file=sys.stderr)
            return 1
        except FileNotFoundError as err:
            print(f"Error: {err}", file=sys.stderr)
            return 2
        except Exception as err:
            return _handle_internal_error(err, args)

    if args.command == "watch":
        import json as _json

        from sesslint.api import discover_session_roots
        from sesslint.progress import OperationCancelled
        from sesslint.watch import watch

        agent = getattr(args, "agent", None)
        watch_paths: list[Path] = list(getattr(args, "path", []) or [])
        if agent is not None:
            if watch_paths:
                print(
                    "Error: --agent cannot be combined with explicit paths.",
                    file=sys.stderr,
                )
                return 2
            agents = None if agent == "all" else [agent]
            watch_paths = [Path(r.path) for r in discover_session_roots(agents) if r.exists]
            if not watch_paths:
                print(
                    f"Error: no existing session roots found for agent '{agent}'.", file=sys.stderr
                )
                return 2
        if not watch_paths:
            print("Error: watch requires at least one path or --agent.", file=sys.stderr)
            return 2
        for wp in watch_paths:
            if not wp.exists():
                print(f"Error: Path not found: {wp}", file=sys.stderr)
                return 2

        use_json = getattr(args, "json", False)

        def _emit(t: Any) -> None:
            if use_json:
                print(_json.dumps(t.to_dict(), sort_keys=True), flush=True)
            else:
                from sesslint.watch import format_transition

                print(format_transition(t), flush=True)

        shared_fmt = getattr(args, "format", "auto")
        try:
            watch(
                watch_paths,
                interval=getattr(args, "interval", 2.0),
                on_transition=_emit,
                format=None if shared_fmt in (None, "auto") else shared_fmt,
            )
        except OperationCancelled:
            return 0
        except ValueError as err:
            print(f"Error: {err}", file=sys.stderr)
            return 2
        except KeyboardInterrupt:
            return 0
        return 0

    if args.command == "init-hooks":
        from sesslint.hooks import init_hooks_doc

        hooks_doc = init_hooks_doc(getattr(args, "agent", "all"))
        if getattr(args, "json", False):
            print(hooks_doc.to_json())
        else:
            sys.stdout.write(hooks_doc.render_human())
        return 0

    if args.command == "hook":
        from sesslint.hook_event import MAX_HOOK_PAYLOAD_BYTES, run_hook

        # Bounded stdin read: the payload is a small JSON control message,
        # not session bytes — cap at 1 MiB so oversize is detectable.
        payload = sys.stdin.buffer.read(MAX_HOOK_PAYLOAD_BYTES + 1)
        fmt = getattr(args, "format", None)
        hook_result = run_hook(
            args.event,
            payload,
            profile=getattr(args, "profile", None),
            format=None if fmt in (None, "auto") else fmt,
            fail_on=getattr(args, "fail_on", None),
        )
        if getattr(args, "json", False):
            print(hook_result.to_json())
        else:
            print(hook_result.line())
        return hook_result.exit_code

    if args.command == "mcp":
        from sesslint.mcp_server import serve

        return serve(sys.stdin.buffer, sys.stdout.buffer)

    if args.command == "doctor":
        from sesslint.doctor import doctor_report

        agent = getattr(args, "agent", None)
        agents = None if agent in (None, "all") else [agent]
        diag = doctor_report(
            agents=agents,
            quick_checks=not getattr(args, "no_quick_checks", False),
        )
        if _output_format(args) == "json":
            print(diag.to_json())
        else:
            print(diag.render_human())
        return 0

    if args.command == "stats":
        from sesslint.api import discover_session_roots
        from sesslint.stats import stats_paths

        agent = getattr(args, "agent", None)
        arg_paths: list[Path] = list(getattr(args, "path", []) or [])
        if agent is not None:
            if arg_paths:
                print(
                    "Error: --agent cannot be combined with explicit paths.",
                    file=sys.stderr,
                )
                return 2
            agents = None if agent == "all" else [agent]
            root_paths = [r.path for r in discover_session_roots(agents) if r.exists]
            if not root_paths:
                print(
                    f"Error: no existing session roots found for agent '{agent}'.", file=sys.stderr
                )
                return 2
            arg_paths = [Path(rp) for rp in root_paths]
            args.recursive = True
        if not arg_paths:
            print("Error: stats requires at least one path or --agent.", file=sys.stderr)
            return 2
        shared_fmt = getattr(args, "format", "auto")
        try:
            result = stats_paths(
                arg_paths,
                recursive=getattr(args, "recursive", False),
                format=None if shared_fmt in (None, "auto") else shared_fmt,
            )
        except ValueError as err:
            print(f"Error: {err}", file=sys.stderr)
            return 2

        if _output_format(args) == "json":
            print(result.to_json())
        else:
            print(result.render_human())
        return 0

    if args.command == "diff":
        from sesslint.diff import DiffInputError, diff_sessions

        shared_fmt = getattr(args, "format", "auto")
        shared = None if shared_fmt in (None, "auto") else shared_fmt
        try:
            diff_result = diff_sessions(
                args.a,
                args.b,
                format_a=getattr(args, "format_a", None) or shared,
                format_b=getattr(args, "format_b", None) or shared,
            )
        except DiffInputError as err:
            print(f"Error: {err}", file=sys.stderr)
            return 2
        except ValueError as err:
            print(f"Error: {err}", file=sys.stderr)
            return 2

        if _output_format(args) == "json":
            print(diff_result.to_json())
        else:
            print(diff_result.render_human())
        return 0 if diff_result.identical else 1

    if args.command == "repair":
        # Plan-authoritative conflicts (repair-engine T-01): applying an
        # exported plan forbids execution-shaping overrides — checked on raw
        # argparse attrs before config folding so config values don't
        # false-positive here.
        if getattr(args, "plan", None) is not None:
            _plan_overrides = [
                flag
                for flag, attr in (
                    ("--policy", "policy"),
                    ("--profile", "profile"),
                    ("--format", "format"),
                )
                if getattr(args, attr, None) is not None
            ]
            if _plan_overrides:
                print(
                    "Error: --apply-plan is authoritative for the exported plan; "
                    "remove override(s): " + ", ".join(_plan_overrides),
                    file=sys.stderr,
                )
                return 2
            if getattr(args, "plan_out", None) is not None:
                print(
                    "Error: --plan-out cannot be combined with --apply-plan "
                    "(no plan is recomputed to export).",
                    file=sys.stderr,
                )
                return 2

        from sesslint.config import ConfigError, load_config

        try:
            cli_cfg = load_config(explicit=getattr(args, "config", None))
        except ConfigError as err:
            print(f"Error: {err}", file=sys.stderr)
            return 2
        _apply_config(args, cli_cfg)

        if getattr(args, "salvage_unsupported", False):
            print(
                "Error: The --salvage-unsupported flag has been deprecated and removed. "
                "Please use '--policy salvage' instead.",
                file=sys.stderr,
            )
            return 2

        # --preview conflicts (repair-engine T-03): preview writes nothing, so
        # every write-implying or foreign-plan flag is a usage error.
        if getattr(args, "preview", False):
            _preview_conflicts: list[str] = []
            if args.output is not None:
                _preview_conflicts.append("--output")
            if getattr(args, "plan", None) is not None:
                _preview_conflicts.append("--apply-plan/--plan")
            if getattr(args, "plan_out", None) is not None:
                _preview_conflicts.append("--plan-out")
            if (
                getattr(args, "batch", None) is not None
                or getattr(args, "from_scan", None) is not None
                or getattr(args, "files", None)
            ):
                _preview_conflicts.append("batch modes")
            if getattr(args, "emit", "auto") != "auto":
                _preview_conflicts.append("--emit")
            if _preview_conflicts:
                print(
                    "Error: --preview writes nothing; incompatible with "
                    + ", ".join(_preview_conflicts),
                    file=sys.stderr,
                )
                return 2

        # Batch repair modes (repair-engine T-02): --batch/--from-scan/--files
        # drive per-file plan eligibility under a shared output root. Validated
        # before the single-file flow (batch never stages stdin and uses
        # --output-dir, not --output).
        _batch_modes = [m for m in (args.batch, args.from_scan, args.files) if m]
        if _batch_modes:
            if len(_batch_modes) > 1:
                print(
                    "Error: --batch, --from-scan, and --files are mutually exclusive.",
                    file=sys.stderr,
                )
                return 2
            if args.path is not None:
                print(
                    "Error: positional path cannot be combined with batch modes.",
                    file=sys.stderr,
                )
                return 2
            if args.output is not None:
                print(
                    "Error: --output applies to single-file repair; batch modes use --output-dir.",
                    file=sys.stderr,
                )
                return 2
            if (
                getattr(args, "plan", None) is not None
                or getattr(args, "plan_out", None) is not None
            ):
                print(
                    "Error: --apply-plan/--plan-out are single-file options; "
                    "batch computes plans internally per file.",
                    file=sys.stderr,
                )
                return 2
            if getattr(args, "output_dir", None) is None:
                print("Error: batch repair requires --output-dir.", file=sys.stderr)
                return 2

            from sesslint.batch import (
                BatchRepairReport,
                BatchRow,
                iter_batch_files,
                repair_many,
                resolve_scan_report_files,
            )
            from sesslint.scan import DEFAULT_MAX_FILES

            batch_files: list[Path] = []
            unresolvable: list[str] = []
            common_root: Path | None = None
            if args.batch is not None:
                root_dir = Path(args.batch)
                if not root_dir.is_dir():
                    print(f"Error: batch source is not a directory: {root_dir}", file=sys.stderr)
                    return 2
                batch_files, _special = iter_batch_files([root_dir], max_files=DEFAULT_MAX_FILES)
                common_root = root_dir
            elif args.from_scan is not None:
                try:
                    batch_files, unresolvable = resolve_scan_report_files(args.from_scan)
                except (OSError, ValueError, KeyError) as err:
                    print(f"Error: cannot read scan report: {err}", file=sys.stderr)
                    return 2
            else:
                batch_files = [Path(f) for f in (args.files or [])]

            batch_policy: Literal["conservative", "salvage"] = (
                "salvage"
                if getattr(args, "policy", "conservative") == "salvage"
                else "conservative"
            )
            batch_profile = getattr(args, "profile", "neutral")
            batch_format = getattr(args, "format", "auto")

            from sesslint.profiles.profile import get_profile as _get_profile

            try:
                _get_profile(batch_profile)
            except (KeyError, ValueError) as err:
                err_msg = err.args[0] if err.args else str(err)
                print(f"Error: {err_msg}", file=sys.stderr)
                return 2

            try:
                batch_report = repair_many(
                    batch_files,
                    output_dir=args.output_dir,
                    manifest_dir=getattr(args, "manifest_dir", None),
                    common_root=common_root,
                    policy=batch_policy,
                    format=batch_format if batch_format != "auto" else None,
                    profile=batch_profile,
                    acknowledge_side_effects=getattr(args, "acknowledge_side_effects", False),
                    emit=getattr(args, "emit", "auto"),
                    dry_run=bool(args.dry_run),
                    progress_cb=_ndjson_progress_cb(args),
                )
            except Exception as err:
                return _handle_internal_error(err, args)

            if unresolvable:
                merged = list(batch_report.rows) + [
                    BatchRow(path=d, outcome="skipped", reason="unresolvable-path")
                    for d in sorted(unresolvable)
                ]
                batch_report = BatchRepairReport(rows=tuple(sorted(merged, key=lambda r: r.path)))

            if getattr(args, "json", False):
                print(batch_report.to_json())
            else:
                print(batch_report.render_human())
            return 0 if batch_report.refused == 0 and batch_report.skipped == 0 else 1

        if args.path is None:
            print(
                "Error: repair requires a source path, or a batch source "
                "(--batch/--from-scan/--files).",
                file=sys.stderr,
            )
            return 2

        # --plan-out without --output implies plan-only export mode.
        plan_only = bool(args.dry_run) or (
            getattr(args, "plan_out", None) is not None and args.output is None
        )
        if not plan_only and not getattr(args, "preview", False) and args.output is None:
            print(
                "Error: --output is required unless --dry-run, --plan-out, or "
                "--preview is specified.",
                file=sys.stderr,
            )
            return 2

        # `-` reads the source session from stdin (ux T-06): the one-shot
        # buffer is staged through a private temp file so the full 8-step
        # executor protocol (pre/post hashing, atomic publish, write-back
        # projection) applies unchanged. The staged file is deleted before
        # the command returns.
        stdin_tmp: Any = None
        src_path: Path = args.path
        if str(args.path) == "-":
            import tempfile

            from sesslint.io import DEFAULT_MAX_FILE_BYTES

            stdin_data = _read_stdin_bytes()
            if len(stdin_data) > DEFAULT_MAX_FILE_BYTES:
                print(
                    "Error: stdin exceeds maximum supported size "
                    f"({DEFAULT_MAX_FILE_BYTES} bytes).",
                    file=sys.stderr,
                )
                return 2
            stdin_tmp = tempfile.TemporaryDirectory(prefix="sesslint-stdin-")
            src_path = Path(stdin_tmp.name) / "stdin.jsonl"
            src_path.write_bytes(stdin_data)

        if src_path.is_dir():
            print(
                f"Error: repair operates on a single session file, not a directory: {src_path}",
                file=sys.stderr,
            )
            return 2
        if not src_path.is_file():
            print(f"Error: Source file not found: {src_path}", file=sys.stderr)
            return 2

        policy_opt: Literal["conservative", "salvage"] = (
            "salvage" if getattr(args, "policy", "conservative") == "salvage" else "conservative"
        )
        profile_opt = getattr(args, "profile", "neutral")
        ack_side_effects = getattr(args, "acknowledge_side_effects", False)
        format_opt = getattr(args, "format", "auto")

        from sesslint.adapters.detect import VALID_FORMAT_OPTIONS
        from sesslint.profiles.profile import get_profile

        if format_opt not in VALID_FORMAT_OPTIONS:
            print(f"Error: Unsupported format option: {format_opt}", file=sys.stderr)
            return 2

        # Vendor formats are supported via drop-only line-verbatim write-back
        # (emit='auto'|'vendor'); emit='canonical' exports a canonical repaired
        # stream. Unsafe projections refuse via VendorProjectionRefused (R1-R6).

        try:
            get_profile(profile_opt)
        except (KeyError, ValueError) as err:
            err_msg = err.args[0] if err.args else str(err)
            print(f"Error: {err_msg}", file=sys.stderr)
            return 2

        if getattr(args, "preview", False):
            # Structural preview (repair T-03): detection+planning rendered as
            # content-free deltas; blocked findings still surface. No writes.
            from sesslint.preview import repair_preview

            try:
                preview_doc = repair_preview(
                    src_path,
                    format=format_opt if format_opt != "auto" else None,
                    policy=policy_opt,
                    profile=profile_opt,
                    acknowledge_side_effects=ack_side_effects,
                )
            except (FileNotFoundError, OSError) as err:
                print(f"File error: {err}", file=sys.stderr)
                return 2
            except (ValueError, KeyError) as err:
                err_msg = err.args[0] if err.args else str(err)
                print(f"Error: {err_msg}", file=sys.stderr)
                return 2
            except SesslintError as err:
                print(f"Error: {err}", file=sys.stderr)
                return 2
            except Exception as err:
                return _handle_internal_error(err, args)

            if getattr(args, "json", False):
                print(preview_doc.to_json())
            else:
                print(preview_doc.render_human())
            return 1 if preview_doc.refused else 0

        from sesslint import api
        from sesslint.repair import (
            Abstained,
            OutputInvalid,
            PlanSourceMismatch,
            PlanTampered,
            PolicyMismatch,
            RepairRefused,
            VendorRepairRefused,
        )
        from sesslint.report import dump_manifest

        try:
            if getattr(args, "plan_out", None) is not None:
                # Export-first composition (repair T-01): compute the plan,
                # write the sesslint.plan/v1 document, then either stop
                # (plan-only) or apply the just-exported plan.
                plan_obj = api.plan_repair(
                    src_path,
                    policy=policy_opt,
                    format=format_opt if format_opt != "auto" else None,
                    profile=profile_opt,
                )
                try:
                    from sesslint.atomic import atomic_write_text

                    atomic_write_text(
                        Path(args.plan_out),
                        json.dumps(plan_obj.to_dict(), indent=2, sort_keys=True) + chr(10),
                    )
                except OSError as err:
                    print(f"Error writing plan to {args.plan_out}: {err}", file=sys.stderr)
                    return 2
                if plan_only:
                    if not getattr(args, "json", False):
                        print(f"Plan written to: {args.plan_out}")
                    plan_obj, manifest = plan_obj, None
                else:
                    plan_obj, manifest = api.apply_plan(
                        src_path,
                        plan_obj,
                        output_path=args.output,
                        acknowledge_side_effects=ack_side_effects,
                        emit=getattr(args, "emit", "auto"),
                        progress_cb=_ndjson_progress_cb(args),
                    )
            elif getattr(args, "plan", None) is not None:
                # Plan-authoritative apply: policy/profile derive from the
                # plan document; executor re-validates all bindings.
                plan_obj, manifest = api.apply_plan(
                    src_path,
                    args.plan,
                    output_path=args.output,
                    acknowledge_side_effects=ack_side_effects,
                    emit=getattr(args, "emit", "auto"),
                    dry_run=plan_only,
                    progress_cb=_ndjson_progress_cb(args),
                )
            else:
                plan_obj, manifest = api.repair(
                    source_path=src_path,
                    output_path=args.output,
                    policy=policy_opt,
                    format=format_opt if format_opt != "auto" else None,
                    profile=profile_opt,
                    dry_run=plan_only,
                    acknowledge_side_effects=ack_side_effects,
                    emit=getattr(args, "emit", "auto"),
                    progress_cb=_ndjson_progress_cb(args),
                )

            if plan_only:
                if getattr(args, "json", False):
                    print(json.dumps(plan_obj.to_dict(), indent=2, sort_keys=True))
                else:
                    print(f"Plan fingerprint: {plan_obj.fingerprint}")
                    print(f"Policy: {plan_obj.policy}")
                    print(f"Proposed steps: {len(plan_obj.steps)}")
                    print(f"Blocked findings: {len(plan_obj.blocked)}")
                    for blocked in plan_obj.blocked:
                        print(f"  [{blocked.code}] {blocked.describe()}")
                return 0

            if manifest is not None:
                if getattr(args, "json", False):
                    print(dump_manifest(manifest))
                else:
                    print(f"Repair successful. Output: {args.output}")
                    print(f"Manifest written to: {args.output}.manifest.json")
                    print(f"Output fingerprint: {manifest.output_fingerprint}")
                    print(f"Idempotency key: {manifest.idempotency_key}")
                    if manifest.declared_loss:
                        print(
                            "Declared loss: "
                            + ", ".join(manifest.declared_loss)
                            + " (salvage repair — see manifest for detail)"
                        )
                if manifest.adapter_id == "canonical":
                    # A canonical artifact emitted from a vendor source cannot
                    # be dropped back into the vendor's session store.
                    try:
                        from sesslint.adapters.detect import detect_format
                        from sesslint.adapters.load import is_vendor_format

                        _src_fmt = detect_format(src_path).format
                    except Exception:
                        _src_fmt = None
                    if is_vendor_format(_src_fmt):
                        print(
                            f"Note: output is canonical sesslint format, not "
                            f"{_src_fmt}; it cannot be placed back into the "
                            "vendor session store.",
                            file=sys.stderr,
                        )
            return 0
        except VendorRepairRefused as err:
            # Vendor-format refusal (auto-detected inside api.repair) is a usage
            # error, preserving the exit-2 contract previously produced by the
            # removed CLI pre-sniff.
            print(f"Error: {err}", file=sys.stderr)
            return 2
        except (
            PlanTampered,
            Abstained,
            PolicyMismatch,
            OutputInvalid,
            RepairRefused,
            PlanSourceMismatch,
        ) as err:
            if getattr(args, "json", False):
                err_code = getattr(err, "code", type(err).__name__)
                print(
                    json.dumps(
                        {
                            "error": {
                                "code": err_code,
                                "kind": type(err).__name__,
                                "message": str(err),
                            },
                            "ok": False,
                        },
                        sort_keys=True,
                    )
                )
            else:
                err_code = getattr(err, "code", type(err).__name__)
                print(f"Repair refused [{err_code}]: {err}", file=sys.stderr)
            return 1
        except (ValueError, KeyError) as err:
            # Invalid or undetectable input is a usage error, not an internal
            # fault (e.g. source parses as neither canonical nor vendor).
            err_msg = err.args[0] if err.args else str(err)
            print(f"Error: {err_msg}", file=sys.stderr)
            return 2
        except FileNotFoundError as err:
            print(f"File error: {err}", file=sys.stderr)
            return 2
        except SesslintError as err:
            # Schema/adapter failures on the source artifact are input
            # problems, not internal faults.
            print(f"Error: {err}", file=sys.stderr)
            return 2
        except Exception as err:
            return _handle_internal_error(err, args)
        finally:
            if stdin_tmp is not None:
                stdin_tmp.cleanup()

    if args.command == "verify":
        source_target = args.source or getattr(args, "source_flag", None)
        repaired_target = args.repaired or getattr(args, "output_flag", None)

        if source_target is None or repaired_target is None:
            parser.error("sesslint verify requires both source and repaired session paths.")

        try:
            from sesslint import api
            from sesslint.verify import render_verify_human

            verdict = api.verify(
                source_path=source_target,
                output_path=repaired_target,
                manifest_path=args.manifest,
                plan_path=getattr(args, "plan", None),
                acknowledge_side_effects=getattr(args, "acknowledge_side_effects", False),
            )
            use_json = getattr(args, "json", False)
            is_legacy_flags = args.source is None and getattr(args, "source_flag", None) is not None
            if use_json or is_legacy_flags:
                print(verdict.to_json())
            else:
                use_color = should_color(args, sys.stdout)
                print(render_verify_human(verdict, color=use_color))
            return 0 if verdict.ok else 1
        except (FileNotFoundError, OSError) as err:
            print(f"Verify I/O error: {err}", file=sys.stderr)
            return 2
        except Exception as err:
            return _handle_internal_error(err, args)

    if args.command == "bundle":
        target_bundle_path: Path = args.path
        if not target_bundle_path.exists():
            print(f"Error: Path not found: {target_bundle_path}", file=sys.stderr)
            return 2
        if target_bundle_path.is_dir():
            print(
                "Error: Path is a directory. "
                f"Bundle requires a single session file: {target_bundle_path}",
                file=sys.stderr,
            )
            return 2

        from sesslint.api import build_bundle

        format_opt = getattr(args, "format", "auto")
        profile_opt = getattr(args, "profile", "neutral")

        try:
            bundle = build_bundle(
                target_bundle_path,
                format=format_opt if format_opt != "auto" else None,
                profile=profile_opt,
                confidence_min=getattr(args, "confidence_min", None),
                margin_min=getattr(args, "margin_min", None),
            )
        except (ValueError, KeyError) as err:
            if "not permitted by profile" in str(err):
                print(str(err), file=sys.stderr)
                return 2
            parser.error(str(err))
        except FileNotFoundError as err:
            print(f"Error: {err}", file=sys.stderr)
            return 2
        except Exception as err:
            return _handle_internal_error(err, args)

        # SL009 pre-share advisory (transcript-hygiene T-03): the bundle is
        # content-free, but the source file it describes may still hold live
        # secret-shaped material. Warn on stderr (stdout stays pure JSON);
        # --strict-share turns the advisory into a gate.
        if bundle.share_advisory is not None:
            adv = bundle.share_advisory
            fams = ", ".join(str(x) for x in adv.get("families", ()))
            print(
                f"share_advisory: source contains secret-shaped material "
                f"({adv.get('finding_count', 0)} finding(s); families: {fams}) - "
                "rotate affected credentials before sharing the source file "
                "(docs/codes/SL009.md)",
                file=sys.stderr,
            )
            if getattr(args, "strict_share", False):
                return 1

        bundle_json = bundle.to_json()

        out_path: Path | None = getattr(args, "output", None)
        if out_path is not None:
            try:
                from sesslint.atomic import atomic_write_text

                atomic_write_text(out_path, bundle_json)
            except Exception as err:
                print(f"Error writing bundle to {out_path}: {err}", file=sys.stderr)
                return 2

            if getattr(args, "json", False):
                print(bundle_json.rstrip("\n"))
            else:
                print(f"Diagnostic bundle written to: {out_path}")
            return 0

        # No --out specified: emit bundle JSON to stdout
        print(bundle_json.rstrip("\n"))
        return 0

    if args.command == "export":
        if args.output is None:
            print("Error: --output is required for export.", file=sys.stderr)
            return 2
        if not args.path.is_file():
            print(f"Error: Source file not found: {args.path}", file=sys.stderr)
            return 2

        from sesslint import api
        from sesslint.exporter import ExportRefused

        try:
            summary = api.export_file(
                source_path=args.path,
                output_path=args.output,
                format=getattr(args, "format", "auto"),
            )
        except ExportRefused as err:
            print(f"Export refused [{err.code}]: {err}", file=sys.stderr)
            return 1
        except FileNotFoundError as err:
            print(f"File error: {err}", file=sys.stderr)
            return 2
        except Exception as err:
            return _handle_internal_error(err, args)

        if getattr(args, "json", False):
            print(json.dumps(summary.to_dict(), indent=2, sort_keys=True))
        else:
            print(f"Exported {summary.event_count} events ({summary.input_format} -> canonical)")
            print(f"Output: {args.output} (sha256: {summary.output_sha256[:16]}...)")
            if summary.dropped_unknown_fields:
                print(f"Dropped unknown fields: {summary.dropped_unknown_fields}")
            print(
                f"Next Action: Run 'sesslint repair {args.output} --output <file>' to plan repair."
            )
        return 0

    if args.command == "completion":
        from sesslint.completion import generate_completion

        try:
            print(generate_completion(args.shell).rstrip("\n"))
        except ValueError as err:
            print(f"Error: {err}", file=sys.stderr)
            return 2
        return 0

    if args.command == "baseline":
        from sesslint.baseline import BaselineError, upgrade_baseline

        findings: Any = None
        if args.source is not None:
            source_p: Path = args.source
            if not source_p.exists():
                print(f"Error: Path not found: {source_p}", file=sys.stderr)
                return 2
            format_opt = getattr(args, "format", "auto")
            profile_opt = getattr(args, "profile", "neutral")
            format_arg = None if format_opt in (None, "auto") else format_opt
            try:
                if source_p.is_dir():
                    from sesslint.scan import scan_path

                    rep = scan_path(
                        source_p,
                        recursive=True,
                        format=format_arg,
                        profile=profile_opt,
                    )
                    findings = [f for fr in rep.files for f in fr.findings]
                else:
                    from sesslint.api import check_file

                    report = check_file(
                        source_p,
                        format=format_arg,
                        profile=profile_opt,
                    )
                    findings = list(report.findings)
            except (ValueError, KeyError) as err:
                err_msg = err.args[0] if err.args else str(err)
                print(f"Error: {err_msg}", file=sys.stderr)
                return 2

        try:
            doc, verified, unverified = upgrade_baseline(
                args.upgrade, findings, created_by=f"sesslint {__version__}"
            )
        except BaselineError as err:
            print(f"Error: {err}", file=sys.stderr)
            return 2

        if args.output is not None:
            args.output.write_text(doc, encoding="utf-8", newline="\n")
            print(
                f"upgraded baseline: {verified} verified, {unverified} unverified -> {args.output}",
                file=sys.stderr,
            )
        else:
            sys.stdout.write(doc)
            print(
                f"upgraded baseline: {verified} verified, {unverified} unverified",
                file=sys.stderr,
            )
        return 0

    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point returning exit code with top-level safety guarantees."""
    parser = create_parser()
    args = parser.parse_args(argv)

    try:
        return _dispatch_command(args, parser)
    except KeyboardInterrupt:
        print("Operation cancelled by user", file=sys.stderr)
        return 130
    except OperationCancelled:
        # Cooperative cancellation keeps the same CLI exit semantics as
        # Ctrl+C (DW-T-13): cleanup already ran inside the callee.
        print("Operation cancelled", file=sys.stderr)
        return 130
    except FileNotFoundError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 2
    except Exception as err:
        return _handle_internal_error(err, args)


if __name__ == "__main__":
    sys.exit(main())
