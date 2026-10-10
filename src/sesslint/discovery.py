"""TRIAGE-002: shared vendor layout filters and bounded latest-session discovery."""

from __future__ import annotations

import os
from pathlib import Path

MAX_DISCOVERY_ENTRIES = 100_000


def candidate_in_layout(path: Path, root: Path, agent: str, *, subagents: bool = True) -> bool:
    """Recognize ledger positions, excluding auxiliary files before selection."""
    parts = path.relative_to(root).parts
    if agent == "claude":
        return (len(parts) == 2 and path.suffix == ".jsonl") or (
            subagents
            and len(parts) == 4
            and parts[-2] == "subagents"
            and path.name.startswith("agent-")
            and path.suffix == ".jsonl"
        )
    if agent == "codex":
        return path.name.startswith("rollout-") and path.suffix == ".jsonl"
    raise ValueError("agent must be claude or codex")


def latest_session(agent: str) -> Path:
    """Select the newest primary ledger; refuse incomplete enumeration."""
    from sesslint.api import discover_session_roots

    roots = discover_session_roots((agent,))
    candidates: list[tuple[int, str, Path]] = []
    visited: set[tuple[int, int]] = set()
    count = 0
    for root in roots:
        if not root.exists:
            continue
        pending = [root.path]
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as entries:
                children = []
                for entry in entries:
                    count += 1
                    if count > MAX_DISCOVERY_ENTRIES:
                        raise OSError("Discovery limit reached; choose an explicit session file")
                    children.append(entry)
            for entry in sorted(children, key=lambda e: e.name):
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    st = entry.stat(follow_symlinks=False)
                    identity = (st.st_dev, st.st_ino)
                    if st.st_ino and identity in visited:
                        continue
                    visited.add(identity)
                    pending.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    path = Path(entry.path)
                    if candidate_in_layout(path, root.path, agent, subagents=False):
                        st = entry.stat(follow_symlinks=False)
                        candidates.append((-st.st_mtime_ns, path.as_posix(), path))
    if not candidates:
        raise FileNotFoundError("No primary session ledger found for the selected agent")
    return min(candidates)[2]
