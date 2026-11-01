"""Planner-derived plan steps for verify test bundles.

``verify --plan`` only accepts steps the planner derives from the source now
(B20), so hand-built bundles take their step bodies from the planner instead
of inventing finding fingerprints or params.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from sesslint.repair.planner import plan
from sesslint.verify import _load_artifact_events, _run_detector_checks


def derived_steps(
    src_path: Path,
    *,
    recipe: str | None = None,
    profile: str = "neutral",
    policy: str = "conservative",
) -> list[dict[str, Any]]:
    """Return the planner's step dicts for ``src_path``, optionally one recipe only."""
    raw = src_path.read_bytes()
    _, events, stream_findings, fmt = _load_artifact_events(src_path, raw)
    findings = list(stream_findings) + _run_detector_checks(
        events, source_path=src_path.name, profile_name=profile, adapter=fmt
    )
    derived = plan(
        findings=findings,
        events=events,
        profile=profile,
        policy=policy,
        source_hash=hashlib.sha256(raw).hexdigest(),
        input_format=fmt,
    )
    steps = [s.to_dict() for s in derived.steps]
    if recipe is not None:
        steps = [s for s in steps if s["recipe"] == recipe]
    return steps
