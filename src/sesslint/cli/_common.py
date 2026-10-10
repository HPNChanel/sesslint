"""Shared CLI helpers: config folding, output plumbing, error handling."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from collections.abc import Iterable, Mapping
from typing import Any, Final

from sesslint import __version__
from sesslint.api import build_internal_error_envelope
from sesslint.finding import Finding

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
    """Resolve the effective output format: --json wins, else --format."""
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
    for key, default in (
        ("max_file_bytes", 100 * 1024 * 1024),
        ("timestamp_skew_ms", 2000),
        ("max_findings_per_code", 20),
    ):
        if getattr(args, key, None) is None:
            setattr(args, key, cfg.get(key, default))
    if not getattr(args, "fail_on_unsupported", False):
        args.fail_on_unsupported = cfg.get("fail_on_unsupported", False)
    if getattr(args, "max_files", None) is None:
        args.max_files = cfg.get("max_files", 10000)
    if getattr(args, "max_bytes", None) is None:
        args.max_bytes = cfg.get("max_bytes", 1024 * 1024 * 1024)
    if getattr(args, "adapter", None) is None:
        args.adapter = cfg.get("adapter", "auto")
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


def _read_stdin_bytes(max_file_bytes: int | None = None) -> bytes:
    """Slurp stdin once into a bounded buffer (ux T-06).

    Reads at most ``DEFAULT_MAX_FILE_BYTES + 1`` bytes so callers detect
    oversize exactly (``len(data) > cap``). Binary-mode read avoids Windows
    text-mode newline translation.
    """
    from sesslint.io import DEFAULT_MAX_FILE_BYTES

    limit = DEFAULT_MAX_FILE_BYTES if max_file_bytes is None else max_file_bytes
    if limit <= 0:
        raise ValueError("max_file_bytes must be positive")
    return sys.stdin.buffer.read(limit + 1)
