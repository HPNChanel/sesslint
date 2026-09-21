"""Agent hook entrypoint: stdin payload -> resolved check (agent-hooks T-01).

Claude Code hooks deliver one JSON control message on **stdin** carrying
``session_id``, ``transcript_path``, ``cwd``, and ``hook_event_name``.
``sesslint hook --event <name>`` parses that payload, resolves the session
file, runs the event-appropriate integrity check, prints one content-free
line, and exits advisory (0 — or 1 when ``--fail-on`` gates on findings).

Invariants:

- **Never throws.** The subcommand sits on the agent's critical path — a
  crash is worse than a missed check. Every failure path (malformed JSON,
  missing/oversized payload, absent transcript, I/O error) resolves to a
  ``skipped`` verdict with exit 0.
- **Never blocks.** Exit 2 is never emitted in v1: none of the mapped
  events are blocking-capable, so a merge error cannot wedge the agent.
- **Content-free output.** The line and JSON result carry codes, counts,
  and hash-truncated identifiers only — hook stdout may be injected into
  agent context, so payload values are never echoed.
- **Untrusted input.** ``transcript_path`` is treated as data: resolved
  literally, never glob-expanded, shelled, or executed.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

HOOK_RESULT_SCHEMA = "sesslint.hook-result/v1"

# stdin payload is a small JSON control message; anything beyond 1 MiB is
# treated as malformed input rather than a transcript.
MAX_HOOK_PAYLOAD_BYTES: int = 1_048_576

# Events whose hook action narrows the check. SessionEnd sweeps persisted
# secret-shaped material (SL009) at the moment the file stops growing;
# every other event runs the full integrity pass. Unknown event names fall
# through to the generic check (forward-compat with new hook events).
_EVENT_SELECT: dict[str, tuple[str, ...]] = {
    "SessionEnd": ("SL009",),
}

_SEVERITY_ORDER: dict[str, int] = {"fatal": 0, "error": 1, "warning": 2, "info": 3}

Verdict = Literal["ok", "findings", "skipped"]


@dataclass(frozen=True, slots=True)
class HookResult:
    """Outcome of one ``sesslint hook`` invocation (``sesslint.hook-result/v1``)."""

    event: str
    verdict: Verdict
    reason: str
    findings_by_code: dict[str, int]
    top_code: str | None
    session_id: str | None
    exit_code: int
    schema: str = field(default=HOOK_RESULT_SCHEMA, init=False)

    def line(self) -> str:
        """One-line content-free rendering for hook stdout."""
        if self.verdict == "skipped":
            return f"sesslint hook[{self.event}]: skipped ({self.reason})"
        if self.verdict == "ok":
            return f"sesslint hook[{self.event}]: ok"
        total = sum(self.findings_by_code.values())
        return f"sesslint hook[{self.event}]: findings={total} top={self.top_code}"

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "schema": self.schema,
            "event": self.event,
            "verdict": self.verdict,
            "reason": self.reason,
            "findings_by_code": self.findings_by_code,
        }
        if self.top_code is not None:
            d["top_code"] = self.top_code
        if self.session_id is not None:
            d["session_id"] = self.session_id
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def _skip(event: str, reason: str, session_id: str | None = None) -> HookResult:
    return HookResult(
        event=event,
        verdict="skipped",
        reason=reason,
        findings_by_code={},
        top_code=None,
        session_id=session_id,
        exit_code=0,
    )


def _truncated_session_id(raw: Any) -> str | None:
    """Hash-truncate the payload's session_id like other ID surfaces."""
    if not isinstance(raw, str) or not raw:
        return None
    from sesslint.report import short_hash

    return short_hash(raw, 8)


def run_hook(
    event: str,
    data: bytes,
    *,
    profile: str | None = None,
    format: str | None = None,
    fail_on: str | None = None,
) -> HookResult:
    """Run one hook check from a raw stdin payload.

    Args:
        event: Hook event name from ``--event`` (authoritative; the payload's
            ``hook_event_name`` is advisory only and not cross-checked).
        data: Raw stdin bytes, capped by the caller at
            ``MAX_HOOK_PAYLOAD_BYTES + 1`` so oversize is detectable.
        profile: Validation profile name (default: neutral).
        format: Session format override (default: auto-detect).
        fail_on: Optional severity gate — ``"warning"`` exits 1 on any
            finding, ``"error"`` exits 1 on error/fatal findings, and
            ``None``/``"never"`` keeps the hook advisory (always 0).

    Returns:
        A frozen HookResult. This function never raises.
    """
    if len(data) > MAX_HOOK_PAYLOAD_BYTES:
        return _skip(event, "payload-too-large")

    try:
        payload = json.loads(data.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _skip(event, "malformed-payload")
    if not isinstance(payload, dict):
        return _skip(event, "malformed-payload")

    session_id = _truncated_session_id(payload.get("session_id"))

    raw_path = payload.get("transcript_path")
    if not isinstance(raw_path, str) or not raw_path.strip():
        return _skip(event, "no-transcript-path", session_id)
    transcript = Path(raw_path)
    try:
        if not transcript.is_file():
            return _skip(event, "transcript-not-found", session_id)
    except OSError:
        return _skip(event, "transcript-not-found", session_id)

    try:
        from sesslint.api import check_file

        report = check_file(
            transcript,
            profile=profile or "neutral",
            format=format,
            select=_EVENT_SELECT.get(event),
        )
    except (FileNotFoundError, PermissionError, IsADirectoryError, OSError):
        return _skip(event, "io-error", session_id)
    except (ValueError, KeyError, TypeError, AttributeError):
        return _skip(event, "usage-error", session_id)
    except Exception:
        # Last-resort containment: a hook must never crash the agent.
        return _skip(event, "internal-error", session_id)

    by_code = dict(sorted(Counter(f.code for f in report.findings).items()))
    if not by_code:
        return HookResult(
            event=event,
            verdict="ok",
            reason="clean",
            findings_by_code={},
            top_code=None,
            session_id=session_id,
            exit_code=0,
        )

    top_code = min(
        report.findings,
        key=lambda f: (_SEVERITY_ORDER.get(f.severity.value, 9), f.code),
    ).code
    gated = False
    if fail_on == "warning":
        gated = True
    elif fail_on == "error":
        gated = any(f.severity.value in ("error", "fatal") for f in report.findings)
    return HookResult(
        event=event,
        verdict="findings",
        reason=(
            "detection-failed"
            if any(f.code in ("SL301", "SL302") for f in report.findings)
            else "findings-present"
        ),
        findings_by_code=by_code,
        top_code=top_code,
        session_id=session_id,
        exit_code=1 if gated else 0,
    )


__all__ = [
    "HOOK_RESULT_SCHEMA",
    "MAX_HOOK_PAYLOAD_BYTES",
    "HookResult",
    "run_hook",
]
