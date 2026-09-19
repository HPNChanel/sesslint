#!/usr/bin/env python3
"""Shape inventory — vendor drift early-warning dev tool (adapters T-01).

Walks a local session directory and reports which record ``type`` values,
payload types, and key names exist — run against real data without
committing any of it. Content-free by construction: names and counts
only, never values, never payloads, never paths beyond the root arg.

The script imports the adapter tables directly (no copied sets) so its
"known" diff tracks the live registry. Read-only, stdlib-only, no
network. Not shipped in the wheel.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from sesslint.adapters.claude_code import (
    CRITICAL_KEYS as _CLAUDE_CRITICAL,
)
from sesslint.adapters.claude_code import (
    KNOWN_RECORD_KEYS as _CLAUDE_KEYS,
)
from sesslint.adapters.claude_code import (
    TYPE_MAP as _CLAUDE_TYPES,
)
from sesslint.adapters.codex_rollout import (
    ENVELOPE_OPAQUE_TYPES as _CODEX_ENV_TYPES,
)
from sesslint.adapters.codex_rollout import (
    KNOWN_ENVELOPE_KEYS as _CODEX_ENV_KEYS,
)
from sesslint.adapters.codex_rollout import (
    KNOWN_PAYLOAD_KEYS as _CODEX_PAYLOAD_KEYS,
)
from sesslint.adapters.codex_rollout import (
    RESPONSE_ITEM_TYPE_MAP as _CODEX_ITEM_TYPES,
)
from sesslint.adapters.detect import (
    FORMAT_CANONICAL,
    FORMAT_CLAUDE_CODE,
    FORMAT_CODEX_ROLLOUT,
    FORMAT_OPENAI_AGENTS,
    detect_format,
)
from sesslint.adapters.openai_agents import (
    CRITICAL_KEYS as _OPENAI_CRITICAL,
)
from sesslint.adapters.openai_agents import (
    ITEM_TYPE_MAP as _OPENAI_TYPES,
)
from sesslint.adapters.openai_agents import (
    KNOWN_RECORD_KEYS as _OPENAI_KEYS,
)
from sesslint.canonical import KNOWN_EVENT_FIELDS, VALID_KINDS
from sesslint.io import DEFAULT_MAX_FILE_BYTES
from sesslint.scan import DEFAULT_MAX_FILES
from sesslint.stats import _iter_files

SCHEMA_VERSION = "sesslint.shape-inventory/v1"

# Record types the codex adapter routes explicitly (beyond the opaque
# envelope set). Kept in sync with ``_process_rollout_record`` branches —
# asserted against the live set in tests.
_CODEX_KNOWN_ENV_TYPES: frozenset[str] = _CODEX_ENV_TYPES | frozenset(
    {"response_item", "compacted"}
)

# Known-set tables per adapter: (record/envelope types, payload types,
# record keys, payload keys). ``None`` means "not tracked at that level".
_KNOWN: dict[str, dict[str, frozenset[str]]] = {
    FORMAT_CLAUDE_CODE: {
        "types": frozenset(_CLAUDE_TYPES),
        "payload_types": frozenset(),
        "record_keys": _CLAUDE_KEYS | _CLAUDE_CRITICAL,
        "payload_keys": frozenset(),
    },
    FORMAT_OPENAI_AGENTS: {
        "types": frozenset(_OPENAI_TYPES),
        "payload_types": frozenset(),
        "record_keys": _OPENAI_KEYS | _OPENAI_CRITICAL,
        "payload_keys": frozenset(),
    },
    FORMAT_CODEX_ROLLOUT: {
        "types": _CODEX_KNOWN_ENV_TYPES,
        "payload_types": frozenset(_CODEX_ITEM_TYPES),
        "record_keys": _CODEX_ENV_KEYS,
        "payload_keys": _CODEX_PAYLOAD_KEYS,
    },
    FORMAT_CANONICAL: {
        # Canonical events carry ``kind`` rather than ``type``; the tool
        # counts kinds under the types histogram for this format.
        "types": VALID_KINDS,
        "payload_types": frozenset(),
        "record_keys": KNOWN_EVENT_FIELDS,
        "payload_keys": frozenset(),
    },
}

_MAX_DISTINCT_TYPES = 512
_MAX_DISTINCT_KEYS = 4096
_SESSION_SUFFIXES = frozenset({".jsonl", ".json"})


def _skim_file(path: Path, fmt: str, acc: dict[str, Any]) -> None:
    """Cheap line-split JSON skim — extracts names/types only, never values."""
    try:
        if path.stat().st_size > DEFAULT_MAX_FILE_BYTES:
            acc["oversize_files"] += 1
            return
        raw = path.read_bytes()
    except OSError:
        acc["unreadable_files"] += 1
        return

    types: Counter[str] = acc["types"][fmt]
    payload_types: Counter[str] = acc["payload_types"][fmt]
    keys_by_type: dict[str, Counter[str]] = acc["keys_by_type"][fmt]
    payload_keys_by_type: dict[str, Counter[str]] = acc["payload_keys_by_type"][fmt]

    for line in raw.splitlines():
        line = line.strip()
        if not line or not line.startswith(b"{"):
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            acc["unparsed_lines"] += 1
            continue
        if not isinstance(obj, dict):
            acc["unparsed_lines"] += 1
            continue

        rec_type = obj.get("type")
        if fmt == FORMAT_CANONICAL and rec_type is None:
            rec_type = obj.get("kind")  # canonical shape: kind, not type
        if isinstance(rec_type, str):
            if len(types) < _MAX_DISTINCT_TYPES or rec_type in types:
                types[rec_type] += 1
                bucket = keys_by_type.setdefault(rec_type, Counter())
                for key in obj:
                    if len(bucket) < _MAX_DISTINCT_KEYS or key in bucket:
                        bucket[key] += 1
            else:
                acc["truncated"] = True
        else:
            acc["missing_type_lines"] += 1

        payload = obj.get("payload")
        if isinstance(payload, dict):
            pkeys = acc["payload_keys"][fmt]
            for key in payload:
                if len(pkeys) < _MAX_DISTINCT_KEYS or key in pkeys:
                    pkeys[key] += 1
                else:
                    acc["truncated"] = True
            p_type = payload.get("type")
            if isinstance(p_type, str):
                if len(payload_types) < _MAX_DISTINCT_TYPES or p_type in payload_types:
                    payload_types[p_type] += 1
                    pbucket = payload_keys_by_type.setdefault(p_type, Counter())
                    for key in payload:
                        if len(pbucket) < _MAX_DISTINCT_KEYS or key in pbucket:
                            pbucket[key] += 1
                else:
                    acc["truncated"] = True


def _sorted_counts(counter: Counter[str]) -> dict[str, int]:
    """Deterministic count map: count desc, then name asc."""
    return {k: counter[k] for k in sorted(counter, key=lambda n: (-counter[n], n))}


def _diff_known(fmt: str, acc: dict[str, Any]) -> dict[str, Any]:
    """Names absent from the adapter's known sets — the drift signal."""
    known = _KNOWN.get(fmt)
    if known is None:
        return {}
    out: dict[str, Any] = {}
    unknown_types = sorted(t for t in acc["types"][fmt] if t not in known["types"])
    if unknown_types:
        out["unknown_types"] = unknown_types
    unknown_ptypes = sorted(t for t in acc["payload_types"][fmt] if t not in known["payload_types"])
    if unknown_ptypes:
        out["unknown_payload_types"] = unknown_ptypes
    known_rk = known["record_keys"]
    if known_rk:
        unknown_keys = sorted(
            {
                key
                for bucket in acc["keys_by_type"][fmt].values()
                for key in bucket
                if key not in known_rk
            }
        )
        if unknown_keys:
            out["unknown_record_keys"] = unknown_keys
    known_pk = known["payload_keys"]
    if known_pk:
        unknown_pkeys = sorted(k for k in acc["payload_keys"][fmt] if k not in known_pk)
        if unknown_pkeys:
            out["unknown_payload_keys"] = unknown_pkeys
    return out


def inventory(roots: list[Path]) -> dict[str, Any]:
    """Walk roots and produce the content-free shape inventory document."""
    files, _ = _iter_files(roots, max_files=DEFAULT_MAX_FILES)
    acc: dict[str, Any] = {
        "types": {},
        "payload_types": {},
        "keys_by_type": {},
        "payload_keys": {},
        "payload_keys_by_type": {},
        "unparsed_lines": 0,
        "unreadable_files": 0,
        "oversize_files": 0,
        "missing_type_lines": 0,
        "skipped_suffix": 0,
        "truncated": False,
    }
    formats: Counter[str] = Counter()
    scanned = 0

    for path in files:
        if path.suffix.lower() not in _SESSION_SUFFIXES:
            acc["skipped_suffix"] += 1
            continue
        try:
            det = detect_format(path)
        except Exception:
            det = None
        fmt = det.format if det is not None and det.format else "undetected"
        formats[fmt] += 1
        if fmt == "undetected":
            acc.setdefault("undetected_files", 0)
            acc["undetected_files"] += 1
            continue
        for bucket_name in (
            "types",
            "payload_types",
            "keys_by_type",
            "payload_keys",
            "payload_keys_by_type",
        ):
            acc[bucket_name].setdefault(fmt, {} if bucket_name.endswith("by_type") else Counter())
        _skim_file(path, fmt, acc)
        scanned += 1

    doc: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "files": {
            "scanned": scanned,
            "skipped_suffix": acc["skipped_suffix"],
            "undetected": acc.get("undetected_files", 0),
            "unreadable": acc["unreadable_files"],
            "oversize": acc["oversize_files"],
        },
        "formats": _sorted_counts(formats),
        "types": {fmt: _sorted_counts(c) for fmt, c in sorted(acc["types"].items())},
        "payload_types": {
            fmt: _sorted_counts(c) for fmt, c in sorted(acc["payload_types"].items()) if c
        },
        "record_keys": {
            fmt: {t: _sorted_counts(c) for t, c in sorted(acc["keys_by_type"][fmt].items())}
            for fmt in sorted(acc["keys_by_type"])
        },
        "payload_keys": {
            fmt: _sorted_counts(c) for fmt, c in sorted(acc["payload_keys"].items()) if c
        },
        "payload_keys_by_type": {
            fmt: {t: _sorted_counts(c) for t, c in sorted(acc["payload_keys_by_type"][fmt].items())}
            for fmt in sorted(acc["payload_keys_by_type"])
            if acc["payload_keys_by_type"][fmt]
        },
        "unparsed_lines": acc["unparsed_lines"],
        "missing_type_lines": acc["missing_type_lines"],
        "truncated": acc["truncated"],
    }

    unknown: dict[str, Any] = {}
    for fmt in sorted(acc["types"]):
        d = _diff_known(fmt, acc)
        if d:
            unknown[fmt] = d
    doc["unknown"] = unknown
    return doc


def _render_human(doc: dict[str, Any], *, known_only: bool, unknown_only: bool) -> str:
    lines: list[str] = []
    f = doc["files"]
    lines.append(
        f"Shape inventory: {f['scanned']} files scanned "
        f"({f['skipped_suffix']} skipped, {f['undetected']} undetected, "
        f"{f['unreadable']} unreadable, {f['oversize']} oversize)"
    )
    for fmt, count in doc["formats"].items():
        lines.append(f"  format {fmt}: {count} files")

    if not unknown_only:
        for fmt, types in doc["types"].items():
            lines.append(f"[{fmt}] record types:")
            for name, n in types.items():
                lines.append(f"    {name}: {n}")
        for fmt, ptypes in doc.get("payload_types", {}).items():
            lines.append(f"[{fmt}] payload types:")
            for name, n in ptypes.items():
                lines.append(f"    {name}: {n}")

    if not known_only and doc.get("unknown"):
        lines.append("Unknown vs adapter known-sets:")
        for fmt, diff in doc["unknown"].items():
            for label, names in diff.items():
                lines.append(f"  [{fmt}] {label}: {', '.join(names)}")
    if doc["truncated"]:
        lines.append("(truncated: distinct-name caps reached)")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="shape_inventory",
        description="Content-free shape inventory of session files (dev tool).",
    )
    parser.add_argument("roots", nargs="+", type=Path, help="Directories to scan")
    parser.add_argument("--json", action="store_true", help="Emit JSON document")
    vis = parser.add_mutually_exclusive_group()
    vis.add_argument("--known-only", action="store_true", help="Only known-name histograms")
    vis.add_argument("--unknown-only", action="store_true", help="Only the unknown diff")
    args = parser.parse_args(argv)

    roots = [r for r in args.roots]
    doc = inventory(roots)
    doc["root_count"] = len(roots)

    if args.json:
        out = dict(doc)
        if args.known_only:
            out.pop("unknown", None)
        if args.unknown_only:
            out = {
                "schema": SCHEMA_VERSION,
                "unknown": doc.get("unknown", {}),
                "truncated": doc["truncated"],
            }
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        print(_render_human(doc, known_only=args.known_only, unknown_only=args.unknown_only))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
