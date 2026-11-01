"""Agent hook entrypoint: stdin payload -> resolved check (agent-hooks T-01).

Claude Code hooks deliver one JSON control message on **stdin** carrying
``session_id``, ``transcript_path``, ``cwd``, and ``hook_event_name``.
``sesslint hook --event <name>`` parses that payload, resolves the session
file, runs the event-appropriate integrity check, prints one content-free
line, and exits advisory (0 — or 1 when ``--fail-on`` gates on findings).

Output modes (W1-7 / B11): ``line`` (default, unchanged), ``json``
(``sesslint.hook-result/v1``), and ``claude-json`` — one Claude Code
hook-protocol object: a user-visible ``systemMessage`` when findings
exist (plus ``hookSpecificOutput.additionalContext`` on SessionStart),
and an empty ``{}`` when healthy or skipped, so a clean session adds no
noise to the user's screen or the model's context.

Invariants:

- **Never throws.** The subcommand sits on the agent's critical path — a
  crash is worse than a missed check. Every failure path (malformed JSON,
  missing/oversized payload, absent transcript, I/O error) resolves to a
  ``skipped`` verdict with exit 0 — as do the deliberate fast paths (a
  fresh SessionStart, a transcript above the event's byte cap).
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

# SessionStart sources that open a fresh session (W1-7 / B11): ``startup``
# and ``clear`` start a new, empty transcript, so there is no durable state
# to check yet. The hook skips before touching ``transcript_path`` at all.
# ``resume``/``compact``/``fork`` (and any unknown future source) check.
_FRESH_SESSION_SOURCES: frozenset[str] = frozenset({"startup", "clear"})

# Transcript byte cap for the SessionEnd SL009 sweep (W1-7 / B11). Claude
# Code gives all SessionEnd hooks a shared 1.5 s budget, raised by a
# per-hook ``timeout`` to at most 60 s; a full-file sweep of a huge
# transcript would be killed mid-run with its output discarded. Above the
# cap the hook skips deterministically (``too-large-for-hook``) instead of
# racing the timeout — run ``sesslint check --select SL009`` offline.
# 32 MiB sweeps in seconds on commodity hardware, well inside the 30 s
# timeout the init-hooks recipe sets.
MAX_SESSIONEND_SWEEP_BYTES: int = 33_554_432

_EVENT_MAX_BYTES: dict[str, int] = {
    "SessionEnd": MAX_SESSIONEND_SWEEP_BYTES,
}

# Next-step hints for ``claude-json`` messages. ``<transcript>`` is a
# literal placeholder: the payload's ``transcript_path`` is never echoed.
_NEXT_STEP_INTEGRITY = (
    "Next: sesslint check <transcript>, then sesslint repair --dry-run "
    "<transcript> to preview a conservative fix (nothing was changed)."
)
_NEXT_STEP_SECRETS = (
    "Next: rotate exposed credentials at their issuer, then sesslint check "
    "--select SL009 <transcript> for locations (nothing was changed)."
)
_NEXT_STEP_DETECTION = (
    "Next: sesslint check <transcript> for details (format or version not "
    "supported; nothing was changed)."
)

_SEVERITY_ORDER: dict[str, int] = {"fatal": 0, "error": 1, "warning": 2, "info": 3}

Verdict = Literal["ok", "findings", "skipped"]

# ``--output`` choices; ``line`` stays the default for compatibility.
OUTPUT_MODES: tuple[str, ...] = ("line", "json", "claude-json")


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

    def _finding_kind(self) -> Literal["integrity", "secrets", "detection"]:
        if self.reason == "detection-failed":
            return "detection"
        if set(self.findings_by_code) == {"SL009"}:
            return "secrets"
        return "integrity"

    def system_message(self) -> str | None:
        """User-visible ``systemMessage`` text, or ``None`` when nothing to say.

        Content-free: event name, counts, and rule codes only, plus a fixed
        next step whose ``<transcript>`` placeholder is never substituted.
        """
        if self.verdict != "findings":
            return None
        total = sum(self.findings_by_code.values())
        kind = self._finding_kind()
        if kind == "secrets":
            head = (
                f"SessLint {self.event}: {total} SL009 finding(s) - secret-shaped "
                "material persisted in this session's transcript."
            )
            return f"{head} {_NEXT_STEP_SECRETS}"
        if kind == "detection":
            head = (
                f"SessLint {self.event}: could not verify this session's "
                f"transcript ({total} finding(s), top {self.top_code})."
            )
            return f"{head} {_NEXT_STEP_DETECTION}"
        codes = len(self.findings_by_code)
        spread = f"top {self.top_code}" if codes == 1 else f"{codes} codes, top {self.top_code}"
        head = (
            f"SessLint {self.event}: {total} integrity finding(s) in this "
            f"session's transcript ({spread})."
        )
        return f"{head} {_NEXT_STEP_INTEGRITY}"

    def additional_context(self) -> str | None:
        """SessionStart ``additionalContext`` for the model, or ``None``.

        Emitted only on SessionStart with findings — the one event whose
        protocol injects context — so the model knows earlier turns may be
        damaged. Content-free, like :meth:`system_message`.
        """
        if self.verdict != "findings" or self.event != "SessionStart":
            return None
        total = sum(self.findings_by_code.values())
        kind = self._finding_kind()
        if kind == "secrets":
            return (
                "SessLint: this session's transcript persists secret-shaped "
                f"material ({total} SL009 finding(s)); avoid repeating "
                "credentials from earlier turns. The user was shown a warning."
            )
        if kind == "detection":
            return (
                "SessLint could not verify this session's transcript (top "
                f"{self.top_code}); earlier context may be incomplete. The user "
                "was shown a warning."
            )
        return (
            f"SessLint: this session's transcript has {total} integrity "
            f"finding(s) (top {self.top_code}); earlier context may be "
            "incomplete or out of order. The user was shown a warning."
        )

    def to_claude_dict(self) -> dict[str, Any]:
        """Claude Code hook-protocol object for ``--output claude-json``.

        Findings -> ``systemMessage`` (plus SessionStart
        ``hookSpecificOutput``); healthy or skipped -> ``{}`` (silent).
        Never carries ``continue``/``decision``: the hook never blocks.
        """
        message = self.system_message()
        if message is None:
            return {}
        out: dict[str, Any] = {"systemMessage": message}
        context = self.additional_context()
        if context is not None:
            out["hookSpecificOutput"] = {
                "hookEventName": self.event,
                "additionalContext": context,
            }
        return out

    def to_claude_json(self) -> str:
        return json.dumps(self.to_claude_dict(), sort_keys=True)

    def render(self, output: str = "line") -> str:
        """Render for stdout in one of :data:`OUTPUT_MODES` (default ``line``)."""
        if output == "json":
            return self.to_json()
        if output == "claude-json":
            return self.to_claude_json()
        return self.line()


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
    except (ValueError, RecursionError):
        # JSONDecodeError, the int-digit limit, and deep nesting all land
        # here; an escaped RecursionError used to surface as exit 2.
        return _skip(event, "malformed-payload")
    if not isinstance(payload, dict):
        return _skip(event, "malformed-payload")

    session_id = _truncated_session_id(payload.get("session_id"))

    # Fresh sessions have nothing durable to check: skip before the
    # transcript path is even inspected (W1-7 / B11).
    source = payload.get("source")
    if event == "SessionStart" and isinstance(source, str) and source in _FRESH_SESSION_SOURCES:
        return _skip(event, "fresh-session", session_id)

    raw_path = payload.get("transcript_path")
    if not isinstance(raw_path, str) or not raw_path.strip():
        return _skip(event, "no-transcript-path", session_id)
    transcript = Path(raw_path)
    try:
        if not transcript.is_file():
            return _skip(event, "transcript-not-found", session_id)
    except OSError:
        return _skip(event, "transcript-not-found", session_id)

    max_bytes = _EVENT_MAX_BYTES.get(event)
    if max_bytes is not None:
        try:
            size = transcript.stat().st_size
        except OSError:
            return _skip(event, "io-error", session_id)
        if size > max_bytes:
            return _skip(event, "too-large-for-hook", session_id)

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
    "MAX_SESSIONEND_SWEEP_BYTES",
    "OUTPUT_MODES",
    "HookResult",
    "run_hook",
]
