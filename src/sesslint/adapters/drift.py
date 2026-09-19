"""Mid-file schema drift tracking (SL304, DEV-T05).

Per-file tracker driven by adapters during record decode. Two drift kinds
are recorded:

- ``version``: a normalized schema-version marker changes mid-stream while
  both the previous and the observed marker are individually supported.
  Compatible application-release bumps never reach the tracker (adapters
  only observe explicit schema markers).
- ``signature``: a record's envelope ``type`` is discriminative for a
  *different* vendor format — evidence of a spliced file. Shared
  vocabulary (``user``, ``assistant``, ``message``, ``compaction`` …) is
  non-discriminative and never fires.

Precedence (documented in docs/codes/SL304.md): when SL301 fires anywhere
in the file, detection already failed — all buffered SL304 transitions are
discarded at flush time so the unsupported version is reported once and
never double-reported.

Transitions are deduplicated by (kind, previous, observed) keeping the
first occurrence, and capped at ``MAX_DRIFT_TRANSITIONS`` per file.
Evidence is structural only (bounded markers via ``safe_discriminator``);
payload content never enters findings.
"""

from dataclasses import dataclass
from typing import Any, Final

from sesslint.adapters.safe_value import safe_discriminator
from sesslint.codes import SL304
from sesslint.finding import (
    Finding,
    Repairability,
    Severity,
    SourceRef,
    make_finding,
)

MAX_DRIFT_TRANSITIONS: Final[int] = 8

# Envelope ``type`` values that identify exactly one vendor format. A
# record carrying one inside a stream of a different format is a foreign
# signature. Types shared across formats are deliberately absent.
FOREIGN_SIGNATURE_TYPES: Final[dict[str, str]] = {
    # claude-code-jsonl discriminative envelope types
    "summary": "claude-code-jsonl",
    "user_message": "claude-code-jsonl",
    "assistant_message": "claude-code-jsonl",
    "tool_use": "claude-code-jsonl",
    # openai-agents discriminative item types
    "tool_call": "openai-agents",
    "function_call": "openai-agents",
    "function_call_output": "openai-agents",
    "handoff": "openai-agents",
    "checkpoint": "openai-agents",
    # codex-rollout discriminative envelope types
    "session_meta": "codex-rollout",
    "event_msg": "codex-rollout",
    "turn_context": "codex-rollout",
    "world_state": "codex-rollout",
    "inter_agent_communication_metadata": "codex-rollout",
    "token_usage_record": "codex-rollout",
    "response_item": "codex-rollout",
    "compacted": "codex-rollout",
}


@dataclass(frozen=True)
class _Transition:
    """One buffered drift observation with record coordinates."""

    kind: str
    previous: str
    observed: str
    field: str
    observed_format: str | None
    line: int | None
    record_id: str | None
    record_ordinal: int | None
    byte_offset: int | None
    byte_end: int | None


class DriftTracker:
    """Accumulate schema-drift transitions for one file parse.

    Adapters call :meth:`observe_version` for schema-version markers and
    :meth:`observe_signature` for envelope type values. When SL301 fires
    (an unsupported version marker), :meth:`note_unsupported_version`
    suppresses all buffered output so detection failures are reported
    once.
    """

    def __init__(self, format_label: str) -> None:
        self._format = format_label
        self._version_baseline: str | None = None
        self._transitions: list[_Transition] = []
        self._seen: set[tuple[str, str, str]] = set()
        self._sl301_seen = False

    def note_unsupported_version(self) -> None:
        """Record that SL301 fired for this file; suppresses all SL304 output."""
        self._sl301_seen = True

    def observe_version(
        self,
        version_norm: str,
        *,
        supported: bool,
        field: str,
        line: int | None = None,
        record_id: str | None = None,
        record_ordinal: int | None = None,
        byte_offset: int | None = None,
        byte_end: int | None = None,
    ) -> None:
        """Observe a schema-version marker.

        ``version_norm`` is the adapter-normalized marker value. When
        ``supported`` is False the adapter's version predicate rejected it
        (SL301 territory) — the tracker suppresses rather than comparing.
        Otherwise the marker is chained: the first supported marker sets
        the baseline, each later differing marker records a transition and
        becomes the new baseline.
        """
        if not supported:
            self._sl301_seen = True
            return
        if self._version_baseline is None:
            self._version_baseline = version_norm
            return
        if version_norm == self._version_baseline:
            return
        previous = self._version_baseline
        self._version_baseline = version_norm
        self._record(
            kind="version",
            previous=previous,
            observed=version_norm,
            field=field,
            observed_format=None,
            line=line,
            record_id=record_id,
            record_ordinal=record_ordinal,
            byte_offset=byte_offset,
            byte_end=byte_end,
        )

    def observe_signature(
        self,
        raw_type: Any,
        *,
        line: int | None = None,
        record_id: str | None = None,
        record_ordinal: int | None = None,
        byte_offset: int | None = None,
        byte_end: int | None = None,
    ) -> None:
        """Observe an envelope ``type`` value.

        Fires only when ``raw_type`` is a discriminative envelope type of
        a format different from the stream's own (``self._format``).
        Unknown or shared-vocabulary types never fire.
        """
        if not isinstance(raw_type, str):
            return
        observed_format = FOREIGN_SIGNATURE_TYPES.get(raw_type)
        if observed_format is None or observed_format == self._format:
            return
        self._record(
            kind="signature",
            previous=self._format,
            observed=raw_type,
            field="type",
            observed_format=observed_format,
            line=line,
            record_id=record_id,
            record_ordinal=record_ordinal,
            byte_offset=byte_offset,
            byte_end=byte_end,
        )

    def _record(
        self,
        *,
        kind: str,
        previous: str,
        observed: str,
        field: str,
        observed_format: str | None,
        line: int | None,
        record_id: str | None,
        record_ordinal: int | None,
        byte_offset: int | None,
        byte_end: int | None,
    ) -> None:
        key = (kind, previous, observed)
        if key in self._seen:
            return
        self._seen.add(key)
        if len(self._transitions) >= MAX_DRIFT_TRANSITIONS:
            return
        self._transitions.append(
            _Transition(
                kind=kind,
                previous=previous,
                observed=observed,
                field=field,
                observed_format=observed_format,
                line=line,
                record_id=record_id,
                record_ordinal=record_ordinal,
                byte_offset=byte_offset,
                byte_end=byte_end,
            )
        )

    def into_findings(self, *, path_str: str) -> list[Finding]:
        """Materialize buffered transitions as SL304 findings.

        Returns an empty list when SL301 fired anywhere in the file —
        the unsupported version already fails detection, so emitting
        drift diagnostics would double-report the same root cause.
        """
        if self._sl301_seen:
            return []
        out: list[Finding] = []
        for t in self._transitions:
            prev_safe, _ = safe_discriminator(t.previous)
            obs_safe, _ = safe_discriminator(t.observed)
            evidence: dict[str, Any] = {
                "drift_kind": t.kind,
                "previous_marker": prev_safe,
                "observed_marker": obs_safe,
                "field": t.field,
            }
            if t.record_ordinal is not None:
                evidence["record_index"] = t.record_ordinal
            if t.observed_format is not None:
                evidence["observed_format"] = t.observed_format
            if t.byte_offset is not None:
                evidence["byte_offset"] = t.byte_offset
            if t.byte_end is not None:
                evidence["byte_end"] = t.byte_end
            message = (
                "Format signature changes mid-file on line {line} for record {record_id}"
                if t.kind == "signature"
                else "Schema version marker changes mid-file on line {line} for record {record_id}"
            )
            out.append(
                make_finding(
                    code=SL304,
                    severity=Severity.WARNING,
                    repairability=Repairability.MANUAL,
                    message_template=message,
                    source=SourceRef(path=path_str, line=t.line, record_id=t.record_id),
                    evidence=evidence,
                )
            )
        return out


__all__ = [
    "FOREIGN_SIGNATURE_TYPES",
    "MAX_DRIFT_TRANSITIONS",
    "DriftTracker",
]
