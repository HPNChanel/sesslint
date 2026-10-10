"""TRIAGE-001: one bounded source snapshot for checking and repair previews.

Private composition surface. Raw bytes/events never appear in a public report.
The check pipeline owns detection, decoding, coverage and detector semantics.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from sesslint.canonical import SessionEvent
from sesslint.io import DEFAULT_MAX_FILE_BYTES
from sesslint.report import Report


def _identity(st: os.stat_result) -> tuple[int, int, int, int]:
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns


@dataclass(frozen=True)
class SourceAssessment:
    """Internal check result and the exact events which produced it."""

    path: Path
    report: Report
    events: list[SessionEvent]
    format: str | None
    profile: str
    identity: tuple[int, int, int, int]
    readable_snapshot: bool

    def unchanged(self) -> bool:
        """Bounded rehash; metadata alone cannot prove unchanged source bytes."""
        if not self.readable_snapshot:
            return False
        try:
            if _identity(self.path.stat()) != self.identity:
                return False
            digest = hashlib.sha256()
            remaining = self.identity[2]
            with self.path.open("rb") as stream:
                if _identity(os.fstat(stream.fileno())) != self.identity:
                    return False
                while remaining:
                    chunk = stream.read(min(65536, remaining))
                    if not chunk:
                        return False
                    remaining -= len(chunk)
                    digest.update(chunk)
                if stream.read(1) or _identity(os.fstat(stream.fileno())) != self.identity:
                    return False
            return (
                _identity(self.path.stat()) == self.identity
                and digest.hexdigest() == self.report.source_fingerprint
            )
        except OSError:
            return False


def assess_source(
    path: Path | str,
    *,
    format: str | None = None,
    profile: str = "neutral",
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> SourceAssessment:
    """Read once for analysis, retaining the check pipeline's loaded events."""
    from sesslint.api import _check_impl

    if type(max_file_bytes) is not int or max_file_bytes <= 0:
        raise ValueError("max_file_bytes must be a positive integer")
    target = Path(path)
    if not stat.S_ISREG(target.stat().st_mode):
        raise OSError("Triage requires a regular file")
    loaded: list[tuple[str, list[SessionEvent]]] = []

    def capture(adapter: str, events: list[SessionEvent]) -> None:
        loaded.append((adapter, events))

    with target.open("rb") as stream:
        before = os.fstat(stream.fileno())
        # The shared pipeline's limit branch does not read oversized paths.
        oversized = before.st_size > max_file_bytes
        data = None if oversized else stream.read(max_file_bytes + 1)
        after = os.fstat(stream.fileno())
    report = _check_impl(
        target,
        data=data,
        virtual_path=None,
        format=format,
        profile=profile,
        confidence_min=None,
        margin_min=None,
        progress_cb=None,
        cancel_token=None,
        select=None,
        ignore=None,
        baseline=None,
        max_file_bytes=max_file_bytes,
        _capture_events=capture,
        _oversized_snapshot=oversized,
    )
    return SourceAssessment(
        path=target,
        report=report,
        events=loaded[0][1] if loaded else [],
        format=loaded[0][0] if loaded else None,
        profile=profile,
        identity=_identity(before),
        readable_snapshot=(
            data is not None
            and len(data) <= max_file_bytes
            and _identity(before) == _identity(after)
        ),
    )
