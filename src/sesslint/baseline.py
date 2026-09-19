"""Baseline mode: suppress already-known findings by fingerprint.

Baseline files come in two deterministic JSON shapes::

    {
      "schema_version": "sesslint.baseline/v1",
      "fingerprints": ["<16-hex>", ...]
    }

    {
      "schema_version": "sesslint.baseline/v2",
      "entries": [{"key": "<16-hex>", "code": "SL203",
                   "file_role": "sess/run.jsonl", "created_by": "sesslint 0.2.0"}, ...]
    }

v1 keys are raw finding fingerprints (FR-046) which bind the literal source
path — renaming a directory or invoking from a different cwd breaks matching.
v2 keys are path-normalized: the preimage replaces the path string with a
*file role* (``parent-basename/basename``), so the same finding matches after
relocations while still binding rule code, structural position (line,
ordinal, record id), and the allowlisted evidence subset.

Loading returns the union of v1 fingerprints and v2 keys as one opaque set;
matching checks the v1 fingerprint and the v2 key of every finding (exact v2
key first, legacy v1 fingerprint second — v1 baselines keep working).
``--write-baseline`` always emits v2. ``sesslint baseline --upgrade``
rewrites a v1 baseline as v2: entries reproduced by a re-check of ``--source``
become verified v2 keys; the rest are carried as ``migrated: "unverified"``
v1 keys which still match through the v1 leg.

Missing/unreadable baseline files and malformed entries fail closed — a
baseline that cannot be verified must not silently suppress findings. A v2
key shared by two distinct findings in one scan is *ambiguous* and matches
neither (fail-closed, never a silent over-suppress).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Final, TypeVar

from sesslint.finding import (
    Finding,
    _canonical_evidence_for_fingerprint,
)

BASELINE_SCHEMA_VERSION: Final[str] = "sesslint.baseline/v1"
BASELINE_SCHEMA_VERSION_V2: Final[str] = "sesslint.baseline/v2"
_FINGERPRINT_RE: Final = re.compile(r"^[0-9a-f]{16}$")

F = TypeVar("F", bound=Finding)


class BaselineError(ValueError):
    """Raised when a baseline file is missing, unreadable, or malformed."""


def file_role(path_str: str) -> str:
    """Portable file identity for v2 keys: ``parent-basename/basename``.

    Survives absolute/relative spelling changes and directory relocations
    above the immediate parent. Relative spellings are absolutized against
    the current working directory lexically (no filesystem access), so a
    bare ``check run.jsonl`` still carries its real parent name. Virtual
    ``<...>`` paths (e.g. ``<stdin>``) reduce to themselves.
    """
    if path_str.startswith("<"):
        return path_str
    norm = path_str.replace("\\", "/")
    if not (norm.startswith("/") or (len(norm) > 1 and norm[1] == ":")):
        norm = str(Path.cwd()).replace("\\", "/") + "/" + norm
    # collapse "." / ".." segments lexically
    collapsed: list[str] = []
    for seg in norm.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if collapsed:
                collapsed.pop()
            continue
        collapsed.append(seg)
    if not collapsed:
        return norm.rstrip("/")
    basename = collapsed[-1]
    parent = collapsed[-2] if len(collapsed) >= 2 else ""
    return f"{parent}/{basename}" if parent else basename


def compute_v2_key(finding: Finding) -> str:
    """Path-normalized baseline key (sesslint.baseline/v2).

    Preimage mirrors the FR-046 fingerprint minus the path spelling, with
    ``file_role`` in its place::

        [code, file_role, line, ordinal, record_id, canonical_evidence_subset]

    Adapter/profile ids are intentionally absent — a baseline entry names a
    finding's identity, not the invocation that produced it.
    """
    ord_val: int | None = None
    if finding.evidence is not None:
        raw_ord = finding.evidence.get("record_ordinal")
        if isinstance(raw_ord, int) and not isinstance(raw_ord, bool) and raw_ord >= 0:
            ord_val = raw_ord
    ev_subset = _canonical_evidence_for_fingerprint(finding.evidence)
    preimage: list[Any] = [
        finding.code,
        file_role(finding.source.path),
        finding.source.line,
        ord_val,
        finding.source.record_id,
        ev_subset,
    ]
    from sesslint.determinism import canonical_json_bytes

    encoded = canonical_json_bytes(preimage, newline=False)
    return hashlib.sha256(encoded).hexdigest()[:16]


def _load_v1(path: Path, raw: dict[str, Any]) -> frozenset[str]:
    fps = raw.get("fingerprints")
    if not isinstance(fps, list):
        raise BaselineError(f"Baseline file {path} must contain a 'fingerprints' list")
    for idx, fp in enumerate(fps):
        if not isinstance(fp, str) or not _FINGERPRINT_RE.fullmatch(fp):
            raise BaselineError(
                f"Baseline file {path} fingerprints[{idx}] must be a 16-hex string, got {fp!r}"
            )
    return frozenset(fps)


def _load_v2(path: Path, raw: dict[str, Any]) -> frozenset[str]:
    entries = raw.get("entries")
    if not isinstance(entries, list):
        raise BaselineError(f"Baseline file {path} must contain an 'entries' list")
    keys: set[str] = set()
    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise BaselineError(
                f"Baseline file {path} entries[{idx}] must be an object, got {entry!r}"
            )
        key = entry.get("key")
        if not isinstance(key, str) or not _FINGERPRINT_RE.fullmatch(key):
            raise BaselineError(
                f"Baseline file {path} entries[{idx}].key must be a 16-hex string, got {key!r}"
            )
        keys.add(key)
    return frozenset(keys)


def load_baseline(path: Path) -> frozenset[str]:
    """Load a v1 or v2 baseline file into a validated key set.

    The returned set is the union of v1 finding fingerprints and v2 keys;
    matching tries each finding's v1 fingerprint and v2 key against it.

    Raises:
        BaselineError: file missing, not JSON, unknown schema_version, or
            any entry malformed.
    """
    if not path.is_file():
        raise BaselineError(f"Baseline file not found: {path}")
    try:
        raw: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as err:
        raise BaselineError(f"Cannot read baseline file {path}: {err}") from err

    if not isinstance(raw, dict):
        raise BaselineError(f"Baseline file {path} must contain a JSON object")
    version = raw.get("schema_version")
    if version == BASELINE_SCHEMA_VERSION:
        return _load_v1(path, raw)
    if version == BASELINE_SCHEMA_VERSION_V2:
        return _load_v2(path, raw)
    raise BaselineError(
        f"Baseline file {path} must declare schema_version "
        f"{BASELINE_SCHEMA_VERSION!r} or {BASELINE_SCHEMA_VERSION_V2!r}"
    )


def _v2_entry(finding: Finding, *, created_by: str) -> dict[str, str]:
    return {
        "code": finding.code,
        "created_by": created_by,
        "file_role": file_role(finding.source.path),
        "key": compute_v2_key(finding),
    }


def dump_baseline(findings: Iterable[Finding], *, created_by: str = "sesslint") -> str:
    """Serialize findings as a deterministic v2 baseline document."""
    by_key: dict[str, dict[str, str]] = {}
    for f in findings:
        entry = _v2_entry(f, created_by=created_by)
        by_key.setdefault(entry["key"], entry)
    doc = {
        "entries": [by_key[k] for k in sorted(by_key)],
        "schema_version": BASELINE_SCHEMA_VERSION_V2,
    }
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def write_baseline(path: Path, findings: Iterable[Finding], *, created_by: str = "sesslint") -> int:
    """Write findings as a v2 baseline file; returns the entry count written."""
    doc = dump_baseline(findings, created_by=created_by)
    path.write_text(doc, encoding="utf-8", newline="\n")
    return doc.count('"key"')


def filter_findings(findings: Iterable[F], baseline: frozenset[str]) -> list[F]:
    """Return findings suppressed neither by v1 fingerprint nor v2 key.

    A v2 key shared by two or more *distinct* findings (different v1
    fingerprints) is ambiguous — it matches neither, fail-closed.
    """
    items = list(findings)
    keys = [compute_v2_key(f) for f in items]
    owners: dict[str, set[str]] = {}
    for key, f in zip(keys, items, strict=True):
        owners.setdefault(key, set()).add(f.fingerprint)
    ambiguous = {k for k, fps in owners.items() if len(fps) > 1}
    return [
        f
        for key, f in zip(keys, items, strict=True)
        if f.fingerprint not in baseline and (key not in baseline or key in ambiguous)
    ]


def upgrade_baseline(
    baseline_path: Path,
    findings: Iterable[Finding] | None = None,
    *,
    created_by: str = "sesslint",
) -> tuple[str, int, int]:
    """Rewrite a v1 baseline as a v2 document.

    Args:
        baseline_path: A ``sesslint.baseline/v1`` file.
        findings: Reproduced findings from a re-check of the baseline's
            source artifact(s); entries whose v1 fingerprint reappears become
            verified v2 keys. ``None`` (or findings that reproduce nothing)
            migrates every entry as ``"unverified"``.
        created_by: Tool identity recorded on verified entries.

    Returns:
        ``(document_json, verified_count, unverified_count)``.

    Raises:
        BaselineError: input is not a v1 baseline.
    """
    if not baseline_path.is_file():
        raise BaselineError(f"Baseline file not found: {baseline_path}")
    try:
        raw: Any = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as err:
        raise BaselineError(f"Cannot read baseline file {baseline_path}: {err}") from err
    if not isinstance(raw, dict) or raw.get("schema_version") != BASELINE_SCHEMA_VERSION:
        raise BaselineError(
            f"--upgrade requires a {BASELINE_SCHEMA_VERSION!r} baseline, got {baseline_path}"
        )
    v1_fps = _load_v1(baseline_path, raw)

    by_v1: dict[str, Finding] = {}
    for f in findings or ():
        by_v1[f.fingerprint] = f

    entries: list[dict[str, str]] = []
    verified = 0
    for fp in sorted(v1_fps):
        src = by_v1.get(fp)
        if src is None:
            entries.append({"key": fp, "migrated": "unverified"})
        else:
            entry = _v2_entry(src, created_by=created_by)
            entry["migrated"] = "verified"
            entries.append(entry)
            verified += 1
    doc = {"entries": entries, "schema_version": BASELINE_SCHEMA_VERSION_V2}
    return json.dumps(doc, indent=2, sort_keys=True) + "\n", verified, len(entries) - verified
