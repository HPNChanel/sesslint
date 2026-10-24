"""W1-1/W1-2: bounded advisory evidence for unknown non-linking metadata (SL306)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

from sesslint.adapters.safe_value import safe_discriminator
from sesslint.finding import Finding, SourceRef, make_finding

# Presence of these fields makes an unknown record potentially replay-critical.
# Session membership and timestamps alone do not establish record identity.
SEMANTIC_KEYS: Final[frozenset[str]] = frozenset(
    {
        "id",
        "uuid",
        "record_id",
        "message_id",
        "parentId",
        "parent_id",
        "parentUuid",
        "parent_uuid",
        "logicalParentUuid",
        "call_id",
        "callId",
        "toolUseId",
        "tool_use_id",
        "tool_call_id",
        "correlation_id",
        "turn_id",
        "turnId",
        "previous_response_id",
        "parent_thread_id",
        "forked_from_id",
        "leafUuid",
        "message",
        "messages",
        "content",
        "role",
        "input",
        "output",
        "items",
        "events",
        "history",
        "checkpoint",
        "checkpoints",
        "snapshot",
    }
)


def has_semantic_fields(value: Mapping[str, Any]) -> bool:
    """Fail closed for identity, linkage, payload, or explicit critical fields."""
    pending: list[Any] = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, Mapping):
            for key, child in item.items():
                if (
                    isinstance(key, str)
                    and child is not None
                    and (
                        key in SEMANTIC_KEYS
                        or key.startswith("critical_")
                        or key.startswith("unknown_critical")
                    )
                ):
                    return True
                if isinstance(child, (Mapping, list)):
                    pending.append(child)
        elif isinstance(item, list):
            pending.extend(child for child in item if isinstance(child, (Mapping, list)))
    return False


class UnknownMetadataTracker:
    """Aggregate at most 32 safe discriminators plus one overflow finding."""

    def __init__(self) -> None:
        self._groups: dict[str, tuple[int, int, bool]] = {}

    def note(self, raw_type: str, *, line: int) -> None:
        value, redacted = safe_discriminator(raw_type)
        if value not in self._groups and len(self._groups) >= 32:
            value, redacted = "<other-types>", True
        count, first, was_redacted = self._groups.get(value, (0, line, redacted))
        self._groups[value] = (count + 1, first, was_redacted)

    def findings(self, path: str) -> list[Finding]:
        return [
            make_finding(
                code="SL306",
                message_template="Unknown non-linking metadata on line {line}",
                source=SourceRef(path=path, line=first),
                evidence={"count": count, "type_value": value, "type_truncated": redacted},
            )
            for value, (count, first, redacted) in sorted(self._groups.items())
        ]
