"""TRIAGE-001: content-free guidance from one checked source snapshot.

Composes existing checks and planning. Never executes a plan, resumes an agent,
acknowledges side effects or declares application replay safe.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from sesslint._version import CLI_VERSION
from sesslint.assessment import SourceAssessment, assess_source
from sesslint.codes import CODE_REGISTRY, Severity
from sesslint.io import DEFAULT_MAX_FILE_BYTES
from sesslint.preview import _deltas_for_plan
from sesslint.repair.planner import plan
from sesslint.repair.refusals import refusal_rationale_for
from sesslint.report import EMPTY_INPUT_MESSAGE, finding_is_empty_input

TRIAGE_SCHEMA_VERSION = "sesslint.triage/v1"
LIMITATION = (
    "Structural evidence only. Application resume, semantic correctness and external "
    "side effects are unverified. No repair or agent command was executed."
)
MAX_FINDINGS = 100
MAX_IMPACT_LINES = 100


@dataclass(frozen=True)
class TriageReport:
    """Frozen public envelope; the JSON boundary exposes only structural evidence."""

    status: str
    source_sha256: str | None
    adapter: str
    profile: str
    assurance: str
    coverage: dict[str, Any]
    findings: tuple[dict[str, Any], ...]
    finding_count: int
    by_code: dict[str, int]
    previews: tuple[dict[str, Any], ...]
    impact: dict[str, Any]
    native_state: dict[str, str]
    missing_evidence: tuple[dict[str, str], ...]
    next_actions: tuple[dict[str, str], ...]

    @property
    def exit_code(self) -> int:
        if self.status == "unreadable":
            return 2
        return 0 if self.status == "checked" else 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": TRIAGE_SCHEMA_VERSION,
            "tool_version": CLI_VERSION,
            "status": self.status,
            "source_sha256": self.source_sha256,
            "adapter": self.adapter,
            "profile": self.profile,
            "assurance": self.assurance,
            "coverage": self.coverage,
            "findings": list(self.findings),
            "finding_count": self.finding_count,
            "by_code": self.by_code,
            "findings_truncated": self.finding_count > len(self.findings),
            "previews": list(self.previews),
            "impact": self.impact,
            "native_state": self.native_state,
            "missing_evidence": list(self.missing_evidence),
            "next_actions": list(self.next_actions),
            "limitation": LIMITATION,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=True, indent=2, sort_keys=True)

    def render_human(self) -> str:
        lines = [
            f"SessLint triage: {self.status}",
            f"  adapter: {self.adapter}; structural assurance: {self.assurance}",
            "  source: " + (self.source_sha256 or "not inspected"),
            "  findings: " + (", ".join(f"{k} x{v}" for k, v in self.by_code.items()) or "none"),
            f"  native state: {self.native_state['status']}",
        ]
        for preview in self.previews:
            lines.append(
                f"  {preview['policy']} preview: {preview['step_count']} steps; "
                f"{preview['kept_events']} kept events; {preview['lost_records']} lost records; "
                f"{preview['blocked_count']} blocked findings (not applied)"
            )
        if self.impact.get("status") == "mapped":
            lines.append(
                f"  structural impact: {self.impact['affected_events']} / "
                f"{self.impact['parsed_events']} parsed events; "
                "unmapped findings are listed separately"
            )
        lines.append("Evidence still needed:")
        lines.extend(f"  [{item['code']}] {item['detail']}" for item in self.missing_evidence)
        lines.append("Next steps (substitute your paths in command templates):")
        for index, action in enumerate(self.next_actions, 1):
            lines.append(f"  {index}. {action['detail']}")
            if action["command"]:
                lines.append(f"     {action['command']}")
        lines.append(LIMITATION)
        return "\n".join(lines)


def _impact(assessment: SourceAssessment) -> dict[str, Any]:
    """Explicit finding coordinates plus structural descendants, O(V+E)."""
    events = assessment.events
    ids: dict[str, list[int]] = defaultdict(list)
    lines: dict[int, list[int]] = defaultdict(list)
    children: dict[str, list[int]] = defaultdict(list)
    for index, event in enumerate(events):
        ids[event.id].append(index)
        if event.source_line is not None:
            lines[event.source_line].append(index)
        if event.parent_id is not None:
            children[event.parent_id].append(index)
    affected: set[int] = set()
    unmapped: Counter[str] = Counter()
    for finding in assessment.report.findings:
        if finding.severity not in (Severity.ERROR, Severity.FATAL):
            continue
        source = finding.source
        matched = [] if source is None else ids.get(source.record_id or "", [])
        if not matched and source is not None and source.line is not None:
            matched = lines.get(source.line, [])
        if matched:
            affected.update(matched)
        else:
            unmapped[finding.code] += 1
    pending = list(affected)
    expanded: set[str] = set()
    while pending:
        index = pending.pop()
        eid = events[index].id
        if eid in expanded:
            continue
        expanded.add(eid)
        for child in children.get(eid, []):
            if child not in affected:
                affected.add(child)
                pending.append(child)
    source_lines = sorted({line for i in affected if (line := events[i].source_line) is not None})
    return {
        "status": "mapped",
        "parsed_events": len(events),
        "affected_events": len(affected),
        "outside_mapped_impact": len(events) - len(affected),
        "source_lines": source_lines[:MAX_IMPACT_LINES],
        "source_lines_truncated": len(source_lines) > MAX_IMPACT_LINES,
        "unmapped_by_code": dict(sorted(unmapped.items())),
        "limitation": "Outside mapped impact does not mean recoverable or safe to replay.",
    }


def _preview(assessment: SourceAssessment, policy: str) -> dict[str, Any]:
    findings = list(assessment.report.findings)
    proposal = plan(
        findings,
        assessment.events,
        profile=assessment.profile,
        source_hash=assessment.report.source_fingerprint,
        policy=policy,
        acknowledge_side_effects=False,
        input_format=assessment.format,
    )
    deltas = _deltas_for_plan(proposal, findings, assessment.events)
    return {
        "policy": policy,
        "plan_fingerprint": proposal.fingerprint,
        "source_sha256": proposal.source_hash,
        "step_count": len(proposal.steps),
        "blocked_count": len(proposal.blocked),
        "blocked_codes": sorted({item.code for item in proposal.blocked}),
        "kept_events": proposal.total_kept,
        "lost_records": proposal.total_lost,
        "loss_by_class": dict(sorted(proposal.loss_accounting.preview.items())),
        "steps": [
            {
                "action": d.action,
                "code": d.reason_code,
                "recipe": d.recipe,
                "source_line": d.source_line,
            }
            for d in deltas
        ],
        "applied": False,
    }


def _file_digest(path: Path, limit: int) -> str:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(min(65536, limit - size + 1)):
            size += len(chunk)
            if size > limit:
                raise ValueError("Snapshot limit exceeded")
            digest.update(chunk)
    return digest.hexdigest()


def _native_state(copy: Path | None, source: Path, adapter: str) -> dict[str, str]:
    """Inspect only an explicitly provided, closed Codex registry copy."""
    from sesslint.state_db import MAX_STATE_DB_BYTES, read_codex_state, rollout_uuid_from_name

    if copy is None:
        return {"status": "not-provided", "detail": "Native registry was not inspected."}
    live_roots = [Path.home() / ".codex"]
    override = os.environ.get("CODEX_HOME")
    if override:
        live_roots.append(Path(override))
    try:
        resolved = copy.resolve()
        if copy.is_symlink() or any(resolved.is_relative_to(p.resolve()) for p in live_roots):
            return {
                "status": "unverified",
                "detail": "Provide a closed copy outside agent storage.",
            }
        if adapter != "codex-rollout":
            return {
                "status": "unverified",
                "detail": "Registry comparison requires a Codex ledger.",
            }
        sidecars = tuple(Path(str(copy) + suffix) for suffix in ("-wal", "-shm", "-journal"))
        metadata = copy.stat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > MAX_STATE_DB_BYTES
        ) or any(p.exists() or p.is_symlink() for p in sidecars):
            return {
                "status": "unverified",
                "detail": "Provide a bounded regular copy without hard links or SQLite sidecars.",
            }
        before = _file_digest(copy, MAX_STATE_DB_BYTES)
        snapshot = read_codex_state(copy, immutable=True)
        after = _file_digest(copy, MAX_STATE_DB_BYTES)
        if (
            before != after
            or any(p.exists() or p.is_symlink() for p in sidecars)
            or not snapshot.membership_complete
        ):
            return {
                "status": "unverified",
                "detail": "Copy is changing, incomplete or unsupported.",
            }
        identity = rollout_uuid_from_name(source.name)
        if identity is None:
            return {
                "status": "unverified",
                "detail": "No supported rollout identity for comparison.",
            }
        present = (identity, identity) in snapshot.thread_rollout_pairs
        return {
            "status": "membership-matches" if present else "membership-mismatch",
            "detail": "Copied registry membership only; live application state is unverified.",
        }
    except (OSError, ValueError):
        return {"status": "unverified", "detail": "Copy could not be inspected."}


def triage(
    path: Path | str,
    *,
    format: str | None = None,
    profile: str = "neutral",
    policy: Literal["conservative", "salvage"] = "conservative",
    state_copy: Path | str | None = None,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> TriageReport:
    """Diagnose without writes; salvage comparison is explicit opt-in."""
    from sesslint.profiles import get_profile

    get_profile(profile)
    if policy not in ("conservative", "salvage"):
        raise ValueError("policy must be conservative or salvage")
    if type(max_file_bytes) is not int or max_file_bytes <= 0:
        raise ValueError("max_file_bytes must be a positive integer")
    assessment: SourceAssessment | None
    try:
        assessment = assess_source(
            path, format=format, profile=profile, max_file_bytes=max_file_bytes
        )
    except OSError:
        assessment = None
    report = assessment.report if assessment is not None else None
    findings = report.findings if report is not None else ()
    by_code = dict(sorted(Counter(f.code for f in findings).items()))
    # A file with no records has nothing to repair or compare (AC-04).
    empty_input = bool(findings) and all(finding_is_empty_input(f) for f in findings)
    adapter = assessment.format if assessment and assessment.format else "unknown"
    previews: tuple[dict[str, Any], ...] = ()
    impact: dict[str, Any] = {"status": "unverified"}
    status = "unreadable"
    if report is not None:
        skip_reasons = {item.reason for item in report.coverage.skipped}
        if report.limitation.startswith("Skipped:") or "cap-exceeded" in skip_reasons:
            status = "skipped"
        elif (
            report.limitation.startswith("Unsupported:")
            or "SL301" in by_code
            or "version-gated" in skip_reasons
        ):
            status = "unsupported"
        elif assessment is not None and not assessment.unchanged():
            status = "unstable"
        elif adapter == "unknown":
            status = "blocked"
        elif any(f.severity in (Severity.ERROR, Severity.FATAL) for f in findings):
            status = "blocked" if "SL203" in by_code else "needs-attention"
        else:
            status = "checked"
    if assessment is not None and status in ("checked", "needs-attention", "blocked"):
        if assessment.format:
            previews = (_preview(assessment, "conservative"),)
            if policy == "salvage":
                previews += (_preview(assessment, "salvage"),)
            impact = _impact(assessment)
    native = _native_state(
        Path(state_copy) if state_copy is not None else None, Path(path), adapter
    )
    if state_copy is not None and native["status"] != "membership-matches" and status == "checked":
        status = "needs-attention"
    if assessment and status not in ("skipped", "unsupported", "unreadable"):
        if not assessment.unchanged():
            status, previews, impact = "unstable", (), {"status": "unverified"}
    missing: list[dict[str, str]] = []
    if status in ("skipped", "unsupported"):
        missing.append(
            {"code": "coverage", "detail": "Applicable checks are incomplete; inspect coverage."}
        )
    for code in by_code:
        rationale = refusal_rationale_for(code)
        if empty_input:
            missing.append({"code": code, "detail": f"{EMPTY_INPUT_MESSAGE}."})
        elif rationale is not None:
            missing.append({"code": code, "detail": rationale.rationale})
    if "SL203" in by_code or "SL102" in by_code:
        missing.append(
            {
                "code": "external-state",
                "detail": (
                    "Verify actual tool side effects outside this ledger; "
                    "acknowledgement is not proof."
                ),
            }
        )
    missing.append(
        {"code": "native-resume", "detail": "Validate continuation in the originating application."}
    )
    if native["status"] != "membership-matches":
        missing.append({"code": "native-registry", "detail": native["detail"]})
    actions: tuple[dict[str, str], ...]
    if empty_input:
        actions = (
            {
                "id": "inspect-source",
                "detail": "Provide the session file itself; this input holds no records.",
                "command": "sesslint triage <source>",
            },
        )
    elif status in ("skipped", "unsupported", "unstable", "unreadable"):
        actions = (
            {
                "id": "inspect-source",
                "detail": "Provide a stable, readable, supported copy within the byte limit.",
                "command": "sesslint triage <source>",
            },
        )
    elif "SL203" in by_code or "SL102" in by_code:
        actions = (
            {
                "id": "verify-external-state",
                "detail": (
                    "Establish whether pending tools changed external state; "
                    "do not replay them automatically."
                ),
                "command": "",
            },
            {
                "id": "share-evidence",
                "detail": "Create a content-free support bundle for manual review.",
                "command": "sesslint bundle <source>",
            },
        )
    elif findings or native["status"] == "membership-mismatch":
        actions = (
            {
                "id": "review-findings",
                "detail": "Review codes, coverage and mapped impact before changing a copy.",
                "command": "sesslint check <source>",
            },
            {
                "id": "preview-repair",
                "detail": "Inspect preconditions and loss; blockers remain unresolved.",
                "command": "sesslint repair <source> --dry-run",
            },
            {
                "id": "share-evidence",
                "detail": "Create a content-free support bundle if the issue remains.",
                "command": "sesslint bundle <source>",
            },
        )
    else:
        actions = (
            {
                "id": "native-validation",
                "detail": (
                    "Supported structural checks passed; "
                    "validate resume separately in the originating application."
                ),
                "command": "",
            },
        )
    rows = tuple(
        {
            "code": f.code,
            "severity": f.severity.value,
            "repairability": f.repairability.value,
            "title": CODE_REGISTRY[f.code].name,
            "source_line": f.source.line if f.source else None,
        }
        for f in findings[:MAX_FINDINGS]
    )
    return TriageReport(
        status=status,
        source_sha256=report.source_fingerprint
        if report and assessment and assessment.readable_snapshot
        else None,
        adapter=adapter,
        profile=profile,
        assurance=report.assurance
        if report and status not in ("unstable", "skipped", "unsupported")
        else "A0",
        coverage=report.coverage.to_dict() if report else {"performed": [], "skipped": []},
        findings=rows,
        finding_count=len(findings),
        by_code=by_code,
        previews=previews,
        impact=impact,
        native_state=native,
        missing_evidence=tuple(missing),
        next_actions=actions,
    )
