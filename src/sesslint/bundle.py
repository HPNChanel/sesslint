"""Privacy-safe diagnostic bundle command and artifact generator (DEV-014, US-016, UC-07).

Architectural Note:
    Diagnostic bundles redistribute validation evidence, format detection results,
    component versions, and a synthetic fixture skeleton into a single portable
    JSON artifact for bug reports and adapter-support requests.

    Anti-leak and Privacy Invariants:
    1. Zero Raw Content: Transcripts, messages, code, prompts, and payloads are never embedded.
    2. Zero Secret/PII Leakage: All paths are basename-only; discriminators are bounded;
       long IDs are minimized to 8-hex hashes.
    3. Zero Host/User/Environment Leakage: `created_by` records component/schema versions only.
       Platform, OS, hostnames, usernames, timestamps, and environment variables are forbidden.
    4. Determinism: Serializing the bundle of unchanged source bytes yields byte-identical output.
    5. Pure & Offline: No network requests, data collection, or third-party dependencies.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from sesslint._version import (
    CLI_VERSION,
    MANIFEST_SCHEMA_VERSION,
    REPORT_SCHEMA_VERSION,
    SESSION_SCHEMA_VERSION,
    get_version_info,
)
from sesslint.adapters.detect import (
    FORMAT_CANONICAL,
    FORMAT_CLAUDE_CODE,
    FORMAT_OPENAI_AGENTS,
    resolve_format,
    to_source_block,
)
from sesslint.adapters.safe_value import safe_discriminator

BUNDLE_SCHEMA_VERSION: Final[str] = "sesslint.bundle/v1"

FIXTURE_TEMPLATE: Final[str] = (
    "# =============================================================================\n"
    "# SessLint Synthetic Fixture Skeleton Template\n"
    "#\n"
    "# MANDATORY PRIVACY RULES:\n"
    "# - All records in contributed fixtures must be 100% SYNTHETIC.\n"
    "# - NEVER paste raw session transcripts, real prompts, code, or secret keys.\n"
    "# - Use obviously fake identifiers (e.g., 'evt_example_1', 'tool_call_example_1').\n"
    "# - See FIXTURES.md for complete provenance and privacy requirements.\n"
    "# =============================================================================\n"
    '{"created_at":"2026-01-01T00:00:00Z","schema_version":"sesslint.session/v1",'
    '"session_id":"session_example_1"}\n'
    '{"actor":"user","id":"evt_example_1","kind":"message","parent_id":null,'
    '"payload":{"text":"Synthetic user message example"},"seq":0,"ts":"2026-01-01T00:00:01Z"}\n'
    '{"actor":"model","id":"evt_example_2","kind":"tool_call","parent_id":"evt_example_1",'
    '"payload":{"arguments":{},"tool_name":"example_tool"},"seq":1,"ts":"2026-01-01T00:00:02Z"}\n'
    '{"actor":"tool","id":"evt_example_3","kind":"tool_result","parent_id":"evt_example_2",'
    '"payload":{"output":"Synthetic tool output example"},"seq":2,"ts":"2026-01-01T00:00:03Z"}\n'
)


@dataclass(frozen=True, slots=True)
class Bundle:
    """Privacy-safe diagnostic support bundle and fixture skeleton (sesslint.bundle/v1)."""

    bundle_version: str
    created_by: dict[str, Any]
    source: dict[str, Any]
    detection: dict[str, Any]
    report: dict[str, Any]
    fixture_skeleton: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Return canonical dictionary representation with sorted keys."""
        return {
            "bundle_version": self.bundle_version,
            "created_by": self.created_by,
            "detection": self.detection,
            "fixture_skeleton": self.fixture_skeleton,
            "report": self.report,
            "source": self.source,
        }

    def to_json(self, *, indent: int = 2) -> str:
        """Serialize bundle to canonical formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True, ensure_ascii=False) + "\n"


def _build_created_by() -> dict[str, Any]:
    """Emit content-free tool and version descriptors devoid of host/user/env metadata."""
    info = get_version_info()
    return {
        "adapters": dict(sorted(info["adapters"].items())),
        "cli": CLI_VERSION,
        "profiles": dict(sorted(info["profiles"].items())),
        "schema_manifest": MANIFEST_SCHEMA_VERSION,
        "schema_report": REPORT_SCHEMA_VERSION,
        "schema_session": SESSION_SCHEMA_VERSION,
        "tool": "sesslint",
        "version": CLI_VERSION,
        "versions": info,
    }


def _sanitize_remediation(remediation: str, basename: str) -> str:
    """Ensure remediation instructions use strictly basename-only paths."""
    return re.sub(r"(run 'sesslint repair\s+)[^'\s]+", rf"\1{basename}", remediation)


def _sanitize_evidence(evidence: dict[str, Any], basename: str) -> dict[str, Any]:
    """Sanitize finding evidence dictionary to ensure zero path or secret leakage."""
    from sesslint.report import short_hash

    sanitized: dict[str, Any] = {}
    for k, v in evidence.items():
        safe_k, _ = safe_discriminator(str(k))
        if isinstance(v, str):
            # 1. Path minimization: strip directories
            if "/" in v or "\\" in v:
                v = Path(v.replace("\\", "/")).name
            # 2. Discriminator / field_path sanitization
            if str(k) in ("field_path", "version_raw", "kind", "type"):
                safe_v, _ = safe_discriminator(v)
                v = safe_v
            # 3. Long ID hashing
            elif len(v) > 16 and ("id" in str(k).lower() or "uuid" in str(k).lower()):
                v = short_hash(v, 8)
            sanitized[safe_k] = v
        elif isinstance(v, (list, tuple)):
            sanitized_list: list[Any] = []
            for item in v:
                if isinstance(item, str):
                    if "/" in item or "\\" in item:
                        item = Path(item.replace("\\", "/")).name
                    safe_item, _ = safe_discriminator(item)
                    sanitized_list.append(safe_item)
                else:
                    sanitized_list.append(item)
            sanitized[safe_k] = sanitized_list
        elif isinstance(v, dict):
            sanitized[safe_k] = _sanitize_evidence(v, basename)
        else:
            sanitized[safe_k] = v
    return sanitized


def _count_records_bounded(path: Path) -> int:
    """Count non-empty lines in text file using bounded chunk streaming."""
    count = 0
    try:
        with open(path, "rb") as stream:
            non_empty_line = False
            while chunk := stream.read(65536):
                for b in chunk:
                    if b == 10:  # \n
                        if non_empty_line:
                            count += 1
                            non_empty_line = False
                    elif b not in (32, 9, 13):  # space, tab, \r
                        non_empty_line = True
            if non_empty_line:
                count += 1
    except Exception:
        return 0
    return count


def _extract_kinds_fallback(path: Path, max_probe_lines: int = 1000) -> Counter[str]:
    """Best-effort safe extraction of record kinds for unrecognized or detection-failed sessions."""
    counter: Counter[str] = Counter()
    try:
        with open(path, "rb") as stream:
            lines_read = 0
            while lines_read < max_probe_lines:
                line_bytes = stream.readline(1_000_000)
                if not line_bytes:
                    break
                lines_read += 1
                stripped = line_bytes.strip()
                if not stripped:
                    continue
                try:
                    obj = json.loads(stripped.decode("utf-8", errors="replace"))
                except Exception:
                    continue
                if isinstance(obj, dict):
                    raw_k = (
                        obj.get("kind") or obj.get("type") or obj.get("event") or obj.get("role")
                    )
                    if isinstance(raw_k, str):
                        safe_k, _ = safe_discriminator(raw_k)
                        counter[safe_k] += 1
    except Exception:
        pass
    return counter


def build_bundle(
    path: Path | str,
    *,
    format: str | None = None,
    profile: str = "neutral",
    confidence_min: float | None = None,
    margin_min: float | None = None,
) -> Bundle:
    """Build a privacy-safe diagnostic support bundle for a session artifact.

    Args:
        path: Path to session file.
        format: Format override ('auto', None, or known format name).
        profile: Validation profile name (default 'neutral').
        confidence_min: Format auto-detection minimum confidence threshold.
        margin_min: Format auto-detection minimum margin threshold.

    Returns:
        A frozen Bundle instance containing versions, source metadata, detection
        evidence, full check report, and synthetic fixture skeleton.

    Raises:
        FileNotFoundError: If the target session file does not exist.
        IsADirectoryError: If the path points to a directory.
    """
    target_path = Path(path)
    if not target_path.exists():
        raise FileNotFoundError(f"Path not found: {target_path}")
    if target_path.is_dir():
        raise IsADirectoryError(f"Expected session file, got directory: {target_path}")

    # Cross-platform basename extraction (strips both / and \ regardless of host OS)
    norm_path_str = str(path).replace("\\", "/")
    basename = Path(norm_path_str).name

    # Chunked hashing and size calculation (O(1) peak RSS bounded by 64KB buffer)
    hasher = hashlib.sha256()
    file_size = 0
    with open(target_path, "rb") as stream:
        while chunk := stream.read(65536):
            file_size += len(chunk)
            hasher.update(chunk)
    file_sha256 = hasher.hexdigest()

    # 1. Source metadata block (basename only, size, sha256)
    source_block: dict[str, Any] = {
        "path": basename,
        "sha256": file_sha256,
        "size": file_size,
    }

    # 2. Version and tool identity block
    created_by_block = _build_created_by()

    # 3. Format detection block
    resolved_fmt, detection_res, _det_findings = resolve_format(format, target_path)
    det_block = to_source_block(detection_res, requested=format)
    detection_dict: dict[str, Any] = dict(det_block)

    # 4. Check report block
    from sesslint.api import check_file
    from sesslint.report import render_json, short_hash

    report = check_file(
        target_path,
        format=format,
        profile=profile,
        confidence_min=confidence_min,
        margin_min=margin_min,
    )

    # If detection failed or version is unsupported (SL301), extract safe version evidence
    sl301 = next((f for f in report.findings if f.code == "SL301"), None)
    if sl301 and sl301.evidence:
        version_ev: dict[str, Any] = {}
        if "version_raw" in sl301.evidence:
            v_raw = str(sl301.evidence["version_raw"])
            safe_v, _ = safe_discriminator(v_raw)
            version_ev["version_raw"] = safe_v
        if "supported_set" in sl301.evidence:
            sup = sl301.evidence["supported_set"]
            if isinstance(sup, (list, tuple)):
                version_ev["supported_set"] = sorted(str(x) for x in sup)
        if "candidate_version" in sl301.evidence:
            cand_v = str(sl301.evidence["candidate_version"])
            safe_cand, _ = safe_discriminator(cand_v)
            version_ev["candidate_version"] = safe_cand
        if version_ev:
            detection_dict["version_evidence"] = version_ev

    # Convert report to content-free dict and enforce basename-only paths
    raw_report_json = render_json(report, include_content=False)
    report_dict: dict[str, Any] = json.loads(raw_report_json)

    findings_list = report_dict.get("findings", [])
    if isinstance(findings_list, list):
        for f_item in findings_list:
            if isinstance(f_item, dict):
                if "span" in f_item and isinstance(f_item["span"], dict):
                    f_item["span"]["path"] = basename
                if "remediation" in f_item and isinstance(f_item["remediation"], str):
                    f_item["remediation"] = _sanitize_remediation(f_item["remediation"], basename)
                if "evidence" in f_item and isinstance(f_item["evidence"], dict):
                    f_item["evidence"] = _sanitize_evidence(f_item["evidence"], basename)

    raw_sess_id = report_dict.get("session_id", "")
    if isinstance(raw_sess_id, str):
        if len(raw_sess_id) > 16:
            report_dict["session_id"] = short_hash(raw_sess_id, 8)
        else:
            safe_sid, _ = safe_discriminator(raw_sess_id)
            report_dict["session_id"] = safe_sid

    # 5. Fixture skeleton block (record_count, kinds histogram, emitted codes, template)
    events: Any = ()
    try:
        if resolved_fmt == FORMAT_CANONICAL:
            from sesslint.adapters.canonical import load_canonical

            events, _ = load_canonical(target_path)
        elif resolved_fmt == FORMAT_CLAUDE_CODE:
            from sesslint.adapters.claude_code import load_claude_code

            events, _ = load_claude_code(target_path)
        elif resolved_fmt == FORMAT_OPENAI_AGENTS:
            from sesslint.adapters.openai_agents import load_openai_agents

            events, _ = load_openai_agents(target_path)
    except Exception:
        events = ()

    kinds_counter: Counter[str] = Counter()
    if events:
        record_count = len(events)
        for e in events:
            k = getattr(e, "kind", None)
            if k and isinstance(k, str):
                safe_k, _ = safe_discriminator(k)
                kinds_counter[safe_k] += 1
    else:
        record_count = _count_records_bounded(target_path)
        kinds_counter = _extract_kinds_fallback(target_path)

    emitted_codes = sorted(list({f.code for f in report.findings}))

    skeleton_dict: dict[str, Any] = {
        "codes": emitted_codes,
        "kinds": dict(sorted(kinds_counter.items())),
        "record_count": record_count,
        "template": FIXTURE_TEMPLATE,
    }

    return Bundle(
        bundle_version=BUNDLE_SCHEMA_VERSION,
        created_by=created_by_block,
        source=source_block,
        detection=detection_dict,
        report=report_dict,
        fixture_skeleton=skeleton_dict,
    )
