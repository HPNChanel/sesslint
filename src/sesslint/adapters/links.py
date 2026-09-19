"""Bounded cross-file resume-link extraction shared by adapters (SL401).

Adapters surface declared resume/continuation pointers as bounded structural
metadata — ``{"kind", "target", "record_id", "line"}`` dicts stored on the
adapter's ``SourceMetadata`` under ``"links"``. The scan layer resolves each
link against the scanned file set; extraction here is read-only, deduplicated
per file, and capped. Values are structural identifiers only — payload content
is never copied.
"""

from __future__ import annotations

from collections.abc import Mapping, MutableSequence
from typing import Any, Final

MAX_CROSS_LINKS: Final[int] = 16

# Declared pointers to a predecessor *session/file* (``session_ref`` kind).
SESSION_LINK_KEYS: Final[tuple[str, ...]] = (
    "parent_session_id",
    "parentSessionId",
    "resume_from",
    "resumeFrom",
    "source_session_id",
    "sourceSessionId",
    "previous_session_id",
    "previousSessionId",
    "continued_from",
    "continuedFrom",
    "forked_from_session",
    "forkedFromSession",
    "forked_from_id",
    "forkedFromId",
    "parent_thread_id",
    "parentThreadId",
)

# Declared pointers to a predecessor session's *head/tip event* (``head_ref``).
HEAD_LINK_KEYS: Final[tuple[str, ...]] = (
    "resume_head_id",
    "resumeHeadId",
    "resume_from_head",
    "continued_from_event",
    "continuedFromEvent",
    "parent_event_id",
    "parentEventId",
)


def extract_links(
    obj: Mapping[str, Any],
    *,
    links: MutableSequence[dict[str, Any]],
    record_id: str | None,
    line: int | None,
) -> None:
    """Append bounded ``{kind, target, record_id, line}`` link dicts from ``obj``.

    Only scalar (str/int) values are read; non-scalars are ignored. Duplicates
    of an already-recorded ``(kind, target)`` pair are skipped and extraction
    stops at ``MAX_CROSS_LINKS`` per file — a pathological pointer flood is
    bounded.
    """
    if len(links) >= MAX_CROSS_LINKS:
        return
    existing = {(lk["kind"], lk["target"]) for lk in links}
    for key in SESSION_LINK_KEYS:
        _add(
            obj, key, "session_ref", links=links, existing=existing, record_id=record_id, line=line
        )
    for key in HEAD_LINK_KEYS:
        _add(obj, key, "head_ref", links=links, existing=existing, record_id=record_id, line=line)


def _add(
    obj: Mapping[str, Any],
    key: str,
    kind: str,
    *,
    links: MutableSequence[dict[str, Any]],
    existing: set[tuple[str, str]],
    record_id: str | None,
    line: int | None,
) -> None:
    if len(links) >= MAX_CROSS_LINKS:
        return
    v = obj.get(key)
    if isinstance(v, str):
        target = v.strip()
    elif isinstance(v, int) and not isinstance(v, bool):
        target = str(v)
    else:
        return
    if not target or len(target) > 512 or (kind, target) in existing:
        return
    existing.add((kind, target))
    links.append({"kind": kind, "target": target, "record_id": record_id, "line": line})
