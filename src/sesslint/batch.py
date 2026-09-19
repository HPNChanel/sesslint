"""Batch repair orchestration driven by per-file plans (repair-engine T-02).

Repairs a tree of deterministic-fixable session files in one audited pass.
Eligibility reuses the planner's own classification verbatim: a file is
attempted only when its computed plan has steps and zero blocked findings
(no SL203/manual/unknown/unsupported blockers). Every ineligible file is
reported with its blocking code+reason and never attempted — fail-closed,
non-overridable.

Outputs mirror the input's relative structure under ``--output-dir`` with
``<stem>.repaired<suffix>`` names; manifests land in ``--manifest-dir`` as
``<sha8-of-source-path>.manifest.json`` (deterministic, collision-free) or
stay adjacent to their output under the single-file convention. Batch has
no cross-file transaction: per-file atomicity is unchanged and partial
results are valid results.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from sesslint.progress import CancellationToken, ProgressCallback, ProgressEvent, check_token
from sesslint.progress import emit as emit_progress
from sesslint.repair import RepairPlan

# File enumeration reuses the stats walker verbatim (same built-in
# exclusions as scan_path: VCS internals + tool-generated files).
from sesslint.stats import _iter_files as iter_batch_files

BATCH_REPORT_VERSION = "sesslint.batch-repair/v1"


@dataclass(frozen=True)
class BatchRow:
    """One file's batch outcome (content-free: paths minimized, codes only)."""

    path: str
    outcome: str  # repaired | refused | skipped | eligible (dry-run)
    codes: tuple[str, ...] = ()
    reason: str | None = None
    output: str | None = None
    manifest: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"outcome": self.outcome, "path": self.path}
        if self.codes:
            d["codes"] = sorted(self.codes)
        if self.reason is not None:
            d["reason"] = self.reason
        if self.output is not None:
            d["output"] = self.output
        if self.manifest is not None:
            d["manifest"] = self.manifest
        return d


@dataclass(frozen=True)
class BatchRepairReport:
    """Deterministic batch summary: counts + per-file rows, no payloads."""

    rows: tuple[BatchRow, ...]
    version: str = BATCH_REPORT_VERSION

    @property
    def attempted(self) -> int:
        return sum(1 for r in self.rows if r.outcome in ("repaired", "refused", "eligible"))

    @property
    def repaired(self) -> int:
        return sum(1 for r in self.rows if r.outcome == "repaired")

    @property
    def refused(self) -> int:
        return sum(1 for r in self.rows if r.outcome == "refused")

    @property
    def skipped(self) -> int:
        return sum(1 for r in self.rows if r.outcome == "skipped")

    def to_dict(self, *, home: Path | None = None) -> dict[str, Any]:
        return {
            "counts": {
                "attempted": self.attempted,
                "refused": self.refused,
                "repaired": self.repaired,
                "skipped": self.skipped,
            },
            "rows": [r.to_dict() for r in self.rows],
            "version": self.version,
        }

    def to_json(self, *, home: Path | None = None) -> str:
        return json.dumps(self.to_dict(home=home), indent=2, sort_keys=True)

    def render_human(self, *, home: Path | None = None) -> str:
        lines = [
            f"Batch repair: {self.repaired} repaired, {self.refused} refused, "
            f"{self.skipped} skipped ({self.attempted} attempted)",
        ]
        for r in self.rows:
            tail = f" [{', '.join(sorted(r.codes))}]" if r.codes else ""
            reason = f" - {r.reason}" if r.reason else ""
            lines.append(f"  {r.outcome}: {r.path}{tail}{reason}")
        return "\n".join(lines)


def _output_for(src: Path, root: Path | None, out_dir: Path) -> Path:
    """Mirror the input's relative structure under out_dir."""
    name = src.stem + ".repaired" + (src.suffix or ".jsonl")
    if root is not None:
        try:
            rel = src.resolve().relative_to(root.resolve())
            return out_dir / rel.parent / name
        except (ValueError, OSError):
            pass
    return out_dir / name


def _plan_detail(
    src: Path,
    *,
    format: str | None,
    policy: str,
    profile: str,
    acknowledge_side_effects: bool,
) -> tuple[RepairPlan, list[Any], list[Any]]:
    """Plan for one file, returning (plan, findings, events) for preview surfaces."""
    import hashlib as _hl

    from sesslint.adapters.detect import FORMAT_CANONICAL, detect_format
    from sesslint.profiles.profile import resolve_effective_config
    from sesslint.repair.executor import load_source_for_format, run_all_checks
    from sesslint.repair.planner import plan as planner_plan

    if format in (None, "auto"):
        eff = resolve_effective_config(profile)
        det = detect_format(src, confidence_min=eff.confidence_min, margin_min=eff.margin_min)
        resolved = det.format or FORMAT_CANONICAL
    else:
        resolved = str(format)
    _hdr, events, stream_findings = load_source_for_format(src, resolved)
    check_findings = run_all_checks(events, profile=profile, source_path=src.name, adapter=resolved)
    all_findings = list(stream_findings) + list(check_findings)
    plan = planner_plan(
        findings=all_findings,
        events=events,
        profile=profile,
        policy=policy,
        source_hash=_hl.sha256(src.read_bytes()).hexdigest(),
        acknowledge_side_effects=acknowledge_side_effects,
        input_format=resolved,
    )
    return plan, all_findings, events


def _compute_plan(
    src: Path,
    *,
    format: str | None,
    policy: str,
    profile: str,
    acknowledge_side_effects: bool,
) -> RepairPlan:
    """Plan for one file using the same pipeline as ``api.repair`` (first half)."""
    plan, _findings, _events = _plan_detail(
        src,
        format=format,
        policy=policy,
        profile=profile,
        acknowledge_side_effects=acknowledge_side_effects,
    )
    return plan


def resolve_scan_report_files(
    report_path: Path | str,
    *,
    home: Path | None = None,
) -> tuple[list[Path], list[str]]:
    """Extract file paths from a ``sesslint.scan-report/v1`` JSON document.

    Only ``~/``-minimized and absolute paths resolve; ``.._<hash>/name``
    minimized entries are returned as unresolvable display strings (the
    parent directory is deliberately hashed — never invert it).
    """
    data = json.loads(Path(report_path).read_text(encoding="utf-8"))
    files = data.get("files", [])
    h = home if home is not None else Path.home()
    resolved: list[Path] = []
    unresolvable: list[str] = []
    for entry in files:
        disp = str(entry.get("path", ""))
        if disp == "~":
            resolved.append(h)
        elif disp.startswith("~/"):
            resolved.append(h / disp[2:])
        elif Path(disp).is_absolute() or disp.startswith("/") or (len(disp) > 1 and disp[1] == ":"):
            resolved.append(Path(disp))
        else:
            unresolvable.append(disp)
    return resolved, unresolvable


def repair_many(
    files: Sequence[Path | str],
    *,
    output_dir: Path | str,
    manifest_dir: Path | str | None = None,
    common_root: Path | str | None = None,
    policy: Literal["conservative", "salvage"] = "conservative",
    format: str | None = None,
    profile: str = "neutral",
    acknowledge_side_effects: bool = False,
    emit: Literal["auto", "canonical", "vendor"] = "auto",
    dry_run: bool = False,
    progress_cb: ProgressCallback | None = None,
    cancel_token: CancellationToken | None = None,
) -> BatchRepairReport:
    """Repair every eligible file in ``files`` into ``output_dir``.

    Files are processed in sorted-path order. Eligibility is the planner's
    own verdict: steps present and zero blocked findings. Refusals and
    skips are reported, never fatal to the batch.
    """
    from sesslint import api
    from sesslint.report import minimize_path

    out_dir = Path(output_dir)
    man_dir = Path(manifest_dir) if manifest_dir is not None else None
    root = Path(common_root) if common_root is not None else None

    ordered = sorted({Path(f) for f in files}, key=lambda p: str(p))
    total = len(ordered)
    rows: list[BatchRow] = []
    assigned: set[str] = set()

    for idx, src in enumerate(ordered):
        check_token(cancel_token)
        disp = minimize_path(src)
        emit_progress(
            progress_cb,
            ProgressEvent(phase="repair:batch", completed=idx, total=total, item=src.name),
        )

        if not src.is_file():
            rows.append(BatchRow(path=disp, outcome="skipped", reason="source-missing"))
            continue

        # --- eligibility: the planner's own classification, verbatim ---
        try:
            plan = _compute_plan(
                src,
                format=format,
                policy=policy,
                profile=profile,
                acknowledge_side_effects=acknowledge_side_effects,
            )
        except Exception as err:
            rows.append(
                BatchRow(
                    path=disp,
                    outcome="skipped",
                    codes=(str(getattr(err, "code", type(err).__name__)),),
                    reason="plan-failed",
                )
            )
            continue

        if plan.blocked:
            codes = tuple(sorted({b.code for b in plan.blocked}))
            detail = "; ".join(sorted({f"{b.code}:{b.reason}" for b in plan.blocked}))
            rows.append(BatchRow(path=disp, outcome="skipped", codes=codes, reason=detail))
            continue
        if not plan.steps:
            rows.append(BatchRow(path=disp, outcome="skipped", reason="no-repairable-findings"))
            continue

        # --- eligible ---
        if dry_run:
            rows.append(
                BatchRow(
                    path=disp,
                    outcome="eligible",
                    codes=tuple(sorted({s.recipe for s in plan.steps})),
                )
            )
            continue

        out_path = _output_for(src, root, out_dir)
        key = str(out_path)
        if key in assigned:  # flat-mode basename collision -> sha8 prefix
            sha8 = hashlib.sha256(str(src.resolve()).encode()).hexdigest()[:8]
            out_path = out_path.with_name(f"{sha8}-{out_path.name}")
            key = str(out_path)
        assigned.add(key)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            _, manifest = api.apply_plan(
                src,
                plan,
                output_path=out_path,
                acknowledge_side_effects=acknowledge_side_effects,
                emit=emit,
                progress_cb=progress_cb,
                cancel_token=cancel_token,
            )
        except Exception as err:
            rows.append(
                BatchRow(
                    path=disp,
                    outcome="refused",
                    codes=(str(getattr(err, "code", type(err).__name__)),),
                    reason=type(err).__name__,
                )
            )
            continue

        man_disp: str | None = None
        default_manifest = Path(str(out_path) + ".manifest.json")
        if man_dir is not None and default_manifest.is_file():
            # Relocation goes through the sanctioned atomic write path (repo
            # invariant: file mutation lives in atomic.py/executor.py only).
            from sesslint.atomic import atomic_write_text

            man_dir.mkdir(parents=True, exist_ok=True)
            sha8 = hashlib.sha256(str(src.resolve()).encode()).hexdigest()[:8]
            target = man_dir / f"{sha8}.manifest.json"
            atomic_write_text(target, default_manifest.read_text(encoding="utf-8"))
            default_manifest.unlink()
            man_disp = minimize_path(target)
        elif default_manifest.is_file():
            man_disp = minimize_path(default_manifest)

        codes = tuple(sorted({s.recipe for s in plan.steps}))
        rows.append(
            BatchRow(
                path=disp,
                outcome="repaired",
                codes=codes,
                output=minimize_path(out_path),
                manifest=man_disp,
            )
        )

    emit_progress(
        progress_cb,
        ProgressEvent(phase="repair:batch", completed=total, total=total, item=None),
    )
    return BatchRepairReport(rows=tuple(rows))


def get_batch_schema_path() -> Path:
    """Return the packaged ``sesslint.batch-repair/v1`` JSON Schema path."""
    return (
        Path(__file__).resolve().parent.parent.parent / "schemas" / "sesslint.batch-repair.v1.json"
    )


def load_batch_schema() -> dict[str, Any]:
    """Load the ``sesslint.batch-repair/v1`` JSON Schema document."""
    schema: dict[str, Any] = json.loads(get_batch_schema_path().read_text(encoding="utf-8"))
    return schema


__all__ = [
    "BATCH_REPORT_VERSION",
    "BatchRepairReport",
    "BatchRow",
    "get_batch_schema_path",
    "iter_batch_files",
    "load_batch_schema",
    "repair_many",
    "resolve_scan_report_files",
]
