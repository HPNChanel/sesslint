"""Structural repair preview — content-free delta list before writes (T-03).

``sesslint repair IN --preview`` runs detection+planning, then renders the
would-be outcome as structural deltas — which events get dropped, relinked,
deduplicated, or tail-discarded — so the operator can approve with evidence
instead of trust. Preview writes nothing: it composes with ``--json`` and is
incompatible with every flag that produces an artifact.

Delta rows are content-free: ``{action, event_id, kind, source_line,
reason_code, recipe}`` — bounded identifiers, ordinals and rule codes only,
never payload fields. Refusals render the same surface: blocked findings are
listed with their pinned code+reason so a refused preview stays informative.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal

from sesslint.repair import RepairPlan

PREVIEW_VERSION: Final[str] = "sesslint.preview/v1"

# Recipe name -> content-free delta action. New recipes must be classified
# here; unmapped recipes fail closed to ``drop`` (the most conservative
# description: something is removed).
RECIPE_ACTIONS: Final[dict[str, str]] = {
    "terminal-suffix-discard": "discard-tail",
    "torn-terminal-record-discard": "discard-tail",
    "torn-compaction-project": "discard-tail",
    "side-effect-unknown-truncate": "discard-tail",
    "identical-duplicate-collapse": "dedupe",
    "duplicate-projection-removal": "dedupe",
    "proven-unique-parent-restore": "relink",
    "compaction-projection-reunion": "relink",
    "orphan-result-drop": "drop",
    "unresolvable-branch-amputate": "drop",
    "identical-duplicate-drop": "dedupe",
    "seq-renumber": "normalize",
}

_MAX_ID = 80


def _bounded_id(value: Any) -> str | None:
    """Bounded identifier echo: strings only, length-capped, never payloads."""
    if not isinstance(value, str) or not value:
        return None
    return value if len(value) <= _MAX_ID else value[:_MAX_ID]


@dataclass(frozen=True)
class PreviewDelta:
    """One structural would-be change (content-free)."""

    action: str  # drop | relink | discard-tail | dedupe | normalize
    reason_code: str
    recipe: str
    event_id: str | None = None
    kind: str | None = None
    source_line: int | None = None
    seq: int = 0

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "action": self.action,
            "reason_code": self.reason_code,
            "recipe": self.recipe,
        }
        if self.event_id is not None:
            d["event_id"] = self.event_id
        if self.kind is not None:
            d["kind"] = self.kind
        if self.source_line is not None:
            d["source_line"] = self.source_line
        return d


@dataclass(frozen=True)
class PreviewBlocked:
    """A finding the plan could not address (code+reason only)."""

    code: str
    reason: str
    finding_fp: str

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "finding_fp": self.finding_fp, "reason": self.reason}


@dataclass(frozen=True)
class PreviewDoc:
    """Content-free preview document (``sesslint.preview/v1``)."""

    source: str
    steps: tuple[PreviewDelta, ...]
    blocked: tuple[PreviewBlocked, ...]
    plan_fingerprint: str
    policy: str
    version: str = PREVIEW_VERSION

    @property
    def refused(self) -> bool:
        """Preview represents a refusal surface (blocked findings present)."""
        return len(self.blocked) > 0

    def to_dict(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for d in self.steps:
            counts[d.action] = counts.get(d.action, 0) + 1
        return {
            "blocked": [b.to_dict() for b in self.blocked],
            "counts": counts,
            "plan_fingerprint": self.plan_fingerprint,
            "policy": self.policy,
            "schema": self.version,
            "source": self.source,
            "steps": [d.to_dict() for d in self.steps],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    def render_human(self) -> str:
        lines = [f"Preview: {self.source}"]
        lines.append(f"  plan fingerprint: {self.plan_fingerprint}  policy: {self.policy}")
        if not self.steps and not self.blocked:
            lines.append("  no changes planned")
        if self.steps:
            lines.append(f"  steps ({len(self.steps)}):")
            for d in self.steps:
                ident = d.event_id or "-"
                loc = f"line {d.source_line}" if d.source_line is not None else "line -"
                kind = d.kind or "-"
                lines.append(f"    {d.action}: {ident} ({kind}, {loc}) [{d.reason_code}]")
        if self.blocked:
            lines.append(f"  blocked ({len(self.blocked)}):")
            for b in self.blocked:
                lines.append(f"    [{b.code}] {b.reason}")
        return "\n".join(lines)


def _deltas_for_plan(
    plan: RepairPlan,
    findings: list[Any],
    events: list[Any],
) -> tuple[PreviewDelta, ...]:
    """Map plan steps to content-free delta rows (plan order, then action/line)."""
    fp_map = {f.fingerprint: f for f in findings}
    rows: list[PreviewDelta] = []
    for step in plan.steps:
        action = RECIPE_ACTIONS.get(step.recipe, "drop")
        finding = fp_map.get(step.target_finding_fp)
        reason_code = finding.code if finding is not None else "SL000"
        source_line: int | None = None
        if finding is not None and finding.source is not None:
            line = finding.source.line
            if isinstance(line, int) and not isinstance(line, bool) and line >= 1:
                source_line = line
        event_id: str | None = None
        kind: str | None = None
        idx = step.target_index
        if isinstance(idx, int) and not isinstance(idx, bool) and 0 <= idx < len(events):
            ev = events[idx]
            event_id = _bounded_id(getattr(ev, "id", None))
            kind = _bounded_id(getattr(ev, "kind", None))
        if event_id is None and finding is not None and finding.source is not None:
            event_id = _bounded_id(finding.source.record_id)
        rows.append(
            PreviewDelta(
                action=action,
                reason_code=reason_code,
                recipe=step.recipe,
                event_id=event_id,
                kind=kind,
                source_line=source_line,
                seq=step.seq,
            )
        )
    # Plan order first (seq), then (action, source_line) for stable ties.
    rows.sort(key=lambda r: (r.seq, r.action, r.source_line or 0))
    return tuple(rows)


def repair_preview(
    source_path: Path | str,
    *,
    format: str | None = None,
    policy: Literal["conservative", "salvage"] = "conservative",
    profile: str = "neutral",
    acknowledge_side_effects: bool = False,
) -> PreviewDoc:
    """Compute the structural repair preview for ``source_path`` (no writes).

    Runs the same detection+planning pipeline as ``api.repair`` but stops at
    the plan: steps become content-free delta rows and blocked findings are
    surfaced verbatim. Deterministic across runs on identical input.
    """
    from sesslint.batch import _plan_detail
    from sesslint.report import minimize_path

    src = Path(source_path)
    plan, findings, events = _plan_detail(
        src,
        format=format,
        policy=policy,
        profile=profile,
        acknowledge_side_effects=acknowledge_side_effects,
    )
    steps = _deltas_for_plan(plan, findings, events)
    blocked = tuple(
        PreviewBlocked(code=b.code, reason=b.reason, finding_fp=b.finding_fp) for b in plan.blocked
    )
    return PreviewDoc(
        source=minimize_path(src),
        steps=steps,
        blocked=blocked,
        plan_fingerprint=plan.fingerprint,
        policy=plan.policy,
    )


def get_preview_schema_path() -> Path:
    """Return the packaged ``sesslint.preview/v1`` JSON Schema path."""
    return Path(__file__).resolve().parent.parent.parent / "schemas" / "sesslint.preview.v1.json"


def load_preview_schema() -> dict[str, Any]:
    """Load the ``sesslint.preview/v1`` JSON Schema document."""
    schema: dict[str, Any] = json.loads(get_preview_schema_path().read_text(encoding="utf-8"))
    return schema


__all__ = [
    "PREVIEW_VERSION",
    "PreviewBlocked",
    "PreviewDelta",
    "PreviewDoc",
    "RECIPE_ACTIONS",
    "get_preview_schema_path",
    "load_preview_schema",
    "repair_preview",
]
