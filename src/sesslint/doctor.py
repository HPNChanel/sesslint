"""Environment diagnostics for ``sesslint doctor`` (ux-reporting T-04).

Answers "what does SessLint see on this machine" in one read-only report:
tool and adapter versions, which config file is in effect, which agent
session roots exist, and bounded quick verdicts on the newest session
files per root.

Privacy contract: counts and timestamps only — never file names, never
payloads; paths minimized. Deterministic for identical filesystem state;
roots ordered by agent. Diagnostics, not a gate: exit 0 even when roots
are absent (they report ``absent`` honestly).
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, cast

from sesslint._version import CLI_VERSION

DOCTOR_SCHEMA_VERSION: Final[str] = "sesslint.doctor/v1"

# Bounded walks: stop counting past this many files (reports capped=True).
MAX_FILE_COUNT: Final[int] = 10_000
# Quick verdicts run on at most this many newest files per root.
MAX_QUICK_CHECKS: Final[int] = 5
# Top finding codes reported per root.
MAX_TOP_CODES: Final[int] = 5


def _iso_utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True, slots=True)
class RootDiag:
    """Diagnostics for one discovered agent session root."""

    agent: str
    path: str
    exists: bool
    source: str
    file_count: int
    file_count_capped: bool
    newest_mtime: str | None
    checked: int
    verdicts: Mapping[str, int]
    top_codes: tuple[tuple[str, int], ...]

    def to_dict(self, *, home: Path | None = None) -> dict[str, Any]:
        from sesslint.report import minimize_path

        return {
            "agent": self.agent,
            "path": minimize_path(self.path, home=home),
            "exists": self.exists,
            "source": self.source,
            "file_count": self.file_count,
            "file_count_capped": self.file_count_capped,
            "newest_mtime": self.newest_mtime,
            "checked": self.checked,
            "verdicts": dict(sorted(self.verdicts.items())),
            "top_codes": [{"code": c, "count": n} for c, n in self.top_codes],
        }


@dataclass(frozen=True, slots=True)
class DoctorReport:
    """Frozen environment diagnostics envelope (``sesslint.doctor/v1``)."""

    tool_version: str
    adapters: Mapping[str, tuple[str, ...]]
    config_path: str | None
    roots: tuple[RootDiag, ...]

    def to_dict(self, *, home: Path | None = None) -> dict[str, Any]:
        from sesslint.report import minimize_path

        return {
            "schema_version": DOCTOR_SCHEMA_VERSION,
            "tool_version": self.tool_version,
            "adapters": {k: list(v) for k, v in sorted(self.adapters.items())},
            "config_path": (
                minimize_path(self.config_path, home=home) if self.config_path is not None else None
            ),
            "roots": [r.to_dict(home=home) for r in self.roots],
        }

    def to_json(self, *, home: Path | None = None) -> str:
        return json.dumps(self.to_dict(home=home), indent=2, sort_keys=True)

    def render_human(self, *, home: Path | None = None) -> str:
        from sesslint.report import minimize_path

        lines = [
            "SessLint doctor",
            f"  tool version: {self.tool_version}",
            "  adapters:",
        ]
        for name, vers in sorted(self.adapters.items()):
            lines.append(f"    {name:<24} {', '.join(vers)}")
        cfg = minimize_path(self.config_path, home=home) if self.config_path is not None else "none"
        lines.append(f"  config: {cfg}")
        lines.append("  roots:")
        for r in self.roots:
            if not r.exists:
                lines.append(f"    {r.agent:<10} absent ({minimize_path(r.path, home=home)})")
                continue
            cap = "+" if r.file_count_capped else ""
            lines.append(
                f"    {r.agent:<10} {minimize_path(r.path, home=home)}"
                f"  files={r.file_count}{cap}"
                + (f"  newest={r.newest_mtime}" if r.newest_mtime else "")
            )
            if r.checked:
                verdict_bits = ", ".join(f"{v}={n}" for v, n in sorted(r.verdicts.items()) if n)
                lines.append(f"{'':<14}checked={r.checked}  {verdict_bits or 'clean'}")
                for code, n in r.top_codes:
                    lines.append(f"{'':<16}{code} x{n}")
        return "\n".join(lines)


def _count_files(root: Path) -> tuple[int, bool, list[Path]]:
    """Count session-candidate files under root; return (count, capped, newest-N).

    Iterative sorted walk with the scan exclusions; stops at MAX_FILE_COUNT.
    """
    count = 0
    capped = False
    candidates: list[Path] = []
    stack: list[Path] = [root]
    seen_dirs: set[tuple[int, int]] = set()
    while stack:
        curr = stack.pop()
        try:
            st = curr.stat()
            key = (st.st_dev, st.st_ino)
            if key in seen_dirs:
                continue
            seen_dirs.add(key)
            entries = sorted(os.scandir(curr), key=lambda e: e.name)
        except OSError:
            continue
        for entry in entries:
            if count >= MAX_FILE_COUNT:
                capped = True
                return count, capped, candidates
            try:
                if entry.is_dir(follow_symlinks=False):
                    if entry.name not in (".git", ".hg", ".svn"):
                        stack.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    name = entry.name
                    if name in ("sesslint.toml", ".sesslint.toml"):
                        continue
                    count += 1
                    if name.endswith((".jsonl", ".json")):
                        candidates.append(Path(entry.path))
            except OSError:
                continue
    return count, capped, candidates


def _quick_verdicts(
    files: Sequence[Path],
) -> tuple[int, dict[str, int], tuple[tuple[str, int], ...]]:
    """Run bounded checks on the newest files; return (checked, verdicts, top_codes)."""
    newest = sorted(
        (f for f in files if f.is_file()),
        key=lambda f: (-(f.stat().st_mtime if f.exists() else 0.0), str(f)),
    )[:MAX_QUICK_CHECKS]

    verdicts: dict[str, int] = {}
    code_counts: dict[str, int] = {}
    checked = 0
    from sesslint.api import check_file

    for f in newest:
        try:
            report = check_file(f)
        except Exception:
            verdicts["unreadable"] = verdicts.get("unreadable", 0) + 1
            checked += 1
            continue
        checked += 1
        sev = report.counts.by_severity
        errors = sev.get("error", 0) + sev.get("fatal", 0)
        if errors > 0:
            verdict = "invalid"
        elif sev.get("warning", 0) > 0:
            verdict = "warnings"
        else:
            verdict = "healthy"
        verdicts[verdict] = verdicts.get(verdict, 0) + 1
        for finding in report.findings:
            code_counts[finding.code] = code_counts.get(finding.code, 0) + 1

    top = tuple(sorted(code_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:MAX_TOP_CODES])
    return checked, verdicts, top


def doctor_report(
    *,
    agents: Sequence[str] | None = None,
    env: Mapping[str, str] | None = None,
    home: Path | None = None,
    quick_checks: bool = True,
) -> DoctorReport:
    """Collect environment diagnostics; read-only, never writes.

    ``env``/``home`` are injectable for tests (forwarded to
    ``discover_session_roots``). ``quick_checks=False`` skips the
    bounded per-file check pass (counts only).
    """
    from sesslint.adapters.canonical import SUPPORTED_CANONICAL_VERSIONS
    from sesslint.adapters.claude_code import SUPPORTED_CLAUDE_VERSIONS
    from sesslint.adapters.codex_rollout import SUPPORTED_CODEX_ROLLOUT_VERSIONS
    from sesslint.adapters.openai_agents import SUPPORTED_OPENAI_AGENTS_VERSIONS
    from sesslint.api import discover_session_roots
    from sesslint.config import find_config_file

    adapters: dict[str, tuple[str, ...]] = {
        "canonical": tuple(sorted(SUPPORTED_CANONICAL_VERSIONS)),
        "claude-code-jsonl": tuple(sorted(SUPPORTED_CLAUDE_VERSIONS)),
        "codex-rollout": tuple(sorted(SUPPORTED_CODEX_ROLLOUT_VERSIONS)),
        "openai-agents": tuple(sorted(SUPPORTED_OPENAI_AGENTS_VERSIONS)),
    }

    config_path: str | None = None
    try:
        found = find_config_file(Path.cwd())
        if found is not None:
            config_path = str(found)
    except OSError:
        config_path = None

    diags: list[RootDiag] = []
    for root in discover_session_roots(agents, env=env, home=home):
        if not root.exists:
            diags.append(
                RootDiag(
                    agent=root.agent,
                    path=str(root.path),
                    exists=False,
                    source=root.source,
                    file_count=0,
                    file_count_capped=False,
                    newest_mtime=None,
                    checked=0,
                    verdicts={},
                    top_codes=(),
                )
            )
            continue

        count, capped, candidates = _count_files(root.path)
        newest_mtime: str | None = None
        if candidates:
            try:
                newest_mtime = _iso_utc(max(f.stat().st_mtime for f in candidates if f.is_file()))
            except OSError:
                newest_mtime = None

        checked = 0
        verdicts: dict[str, int] = {}
        top_codes: tuple[tuple[str, int], ...] = ()
        if quick_checks:
            checked, verdicts, top_codes = _quick_verdicts(candidates)

        diags.append(
            RootDiag(
                agent=root.agent,
                path=str(root.path),
                exists=True,
                source=root.source,
                file_count=count,
                file_count_capped=capped,
                newest_mtime=newest_mtime,
                checked=checked,
                verdicts=verdicts,
                top_codes=top_codes,
            )
        )

    return DoctorReport(
        tool_version=CLI_VERSION,
        adapters=adapters,
        config_path=config_path,
        roots=tuple(diags),
    )


def get_doctor_schema_path() -> Path:
    """Return the filesystem path to schemas/sesslint.doctor.v1.json."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    dev_path = repo_root / "schemas" / "sesslint.doctor.v1.json"
    if dev_path.is_file():
        return dev_path
    prefix_path = Path(sys.prefix) / "share" / "sesslint" / "schemas" / "sesslint.doctor.v1.json"
    if prefix_path.is_file():
        return prefix_path
    return dev_path


def load_doctor_schema() -> dict[str, Any]:
    """Load the committed JSON Schema for sesslint.doctor/v1 as a dict."""
    schema_path = get_doctor_schema_path()
    if not schema_path.is_file():
        raise FileNotFoundError(f"Doctor schema not found at {schema_path}")
    return cast(dict[str, Any], json.loads(schema_path.read_text(encoding="utf-8")))


__all__ = [
    "DOCTOR_SCHEMA_VERSION",
    "MAX_FILE_COUNT",
    "MAX_QUICK_CHECKS",
    "MAX_TOP_CODES",
    "DoctorReport",
    "RootDiag",
    "doctor_report",
    "get_doctor_schema_path",
    "load_doctor_schema",
]
