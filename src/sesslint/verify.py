"""Verification engine for sesslint verify command (TASK-022).

Independently verifies source/plan/output hash bindings, in-memory transformation
audit via canonical JSON replay, declared loss totals, assurance level, and
idempotence convergence.

Safety Invariants:
- Read-only: zero file mutation primitives (strictly unmodifying).
- Zero imports of the mutator module.
- Total function: returns Verdict on all readable inputs without unhandled exceptions.
- Non-short-circuiting: evaluates all 7 checks in fixed deterministic sequence.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sesslint.canonical import (
    SessionEvent,
    SessionHeader,
    parse_session_event,
    parse_session_header,
    to_canonical_dict,
    to_canonical_json,
)
from sesslint.checks.checkpoint import check_checkpoint
from sesslint.checks.graph import check_graph
from sesslint.checks.identity import check_identities
from sesslint.checks.tool_pairing_1 import check_tool_pairing_1
from sesslint.checks.tool_pairing_2 import check_tool_pairing_2
from sesslint.finding import Finding
from sesslint.profiles import get_profile
from sesslint.repair.assurance import cap_assurance
from sesslint.repair.fingerprint import compute_plan_fingerprint
from sesslint.repair.planner import (
    PLAN_VERSION,
    Blocked,
    Loss,
    PlanStep,
    RepairPlan,
    plan,
)
from sesslint.repair.recipes_conservative import (
    register_all as register_all_conservative_recipes,
)
from sesslint.repair.recipes_salvage import (
    register_all as register_all_salvage_recipes,
)
from sesslint.repair.registry import get_recipe
from sesslint.report import parse_manifest

StrPath = str | os.PathLike[str]

# Unconditionally register all recipes at module load time
register_all_conservative_recipes()
register_all_salvage_recipes()


@dataclass(frozen=True, slots=True)
class Check:
    """Individual verification check result."""

    name: str
    ok: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize check result to dictionary."""
        return {
            "detail": self.detail,
            "name": self.name,
            "ok": self.ok,
        }


@dataclass(frozen=True, slots=True)
class Verdict:
    """Comprehensive, non-short-circuit verification verdict."""

    ok: bool
    checks: tuple[Check, ...]
    assurance: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize verdict to dictionary with sorted keys."""
        return {
            "assurance": self.assurance,
            "checks": [c.to_dict() for c in self.checks],
            "ok": self.ok,
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        """Serialize verdict to deterministic JSON with sorted keys."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


def _load_plan_from_dict(data: Mapping[str, Any]) -> RepairPlan:
    """Construct RepairPlan dataclass from dictionary without mutator module."""
    steps_list: list[PlanStep] = []
    for s in data.get("steps", []):
        steps_list.append(
            PlanStep(
                seq=int(s.get("seq", 0)),
                recipe=str(s.get("recipe", "")),
                target_finding_fp=str(s.get("target_finding_fp", "")),
                target_index=s.get("target_index"),
                params=dict(s.get("params", {})),
                lossy=bool(s.get("lossy", False)),
                loss=dict(s.get("loss", {})),
            )
        )

    blocked_list: list[Blocked] = []
    for b in data.get("blocked", []):
        blocked_list.append(
            Blocked(
                finding_fp=str(b.get("finding_fp", "")),
                code=str(b.get("code", "")),
                reason=str(b.get("reason", "")),
            )
        )

    loss_raw = data.get("loss_accounting", {})
    loss_preview = loss_raw.get("preview", {})
    loss = Loss(
        preview=dict(loss_preview),
        total_lost=int(loss_raw.get("total_lost", 0)),
        total_kept=int(loss_raw.get("total_kept", 0)),
    )

    fingerprint = data.get("fingerprint")
    if not fingerprint or not isinstance(fingerprint, str):
        fingerprint = compute_plan_fingerprint(data)

    return RepairPlan(
        source_hash=str(data.get("source_hash", "")),
        profile=str(data.get("profile", "neutral")),
        steps=tuple(steps_list),
        blocked=tuple(blocked_list),
        loss_accounting=loss,
        fingerprint=str(fingerprint),
        version=str(data.get("version", PLAN_VERSION)),
        policy=str(data.get("policy", "conservative")),
    )


def _parse_session_events(
    raw_bytes: bytes,
) -> tuple[SessionHeader | None, list[SessionEvent]]:
    """Parse session header and events from raw bytes in memory."""
    text = raw_bytes.decode("utf-8-sig").strip()
    if not text:
        return None, []

    # Single-document JSON format check (supports both compact and indented JSON)
    if text.startswith("{") and "events" in text:
        try:
            data = json.loads(text)
            if isinstance(data, Mapping) and "events" in data and isinstance(data["events"], list):
                from sesslint.adapters.canonical import load_canonical

                ev_list, _ = load_canonical(raw_bytes)
                hdr: SessionHeader | None = None
                hdr_dict = (
                    dict(data["header"])
                    if isinstance(data.get("header"), Mapping)
                    else {k: v for k, v in data.items() if k != "events"}
                )
                try:
                    hdr = parse_session_header(hdr_dict)
                except Exception:
                    if (
                        "schema_version" in hdr_dict
                        and "session_id" in hdr_dict
                        and "kind" not in hdr_dict
                    ):
                        hdr = SessionHeader(
                            schema_version=hdr_dict["schema_version"],
                            session_id=str(hdr_dict["session_id"]),
                            created_at=str(hdr_dict.get("created_at", "")),
                            title=str(hdr_dict["title"]) if "title" in hdr_dict else None,
                        )
                    else:
                        sess_id = str(ev_list.source.get("session_id", "canonical-session"))
                        created_at = str(ev_list.source.get("created_at", "2026-09-05T12:00:00Z"))
                        hdr = SessionHeader(
                            schema_version="sesslint.session/v1",
                            session_id=sess_id,
                            created_at=created_at,
                        )
                return hdr, list(ev_list)
        except Exception:
            pass

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return None, []

    header: SessionHeader | None = None
    events: list[SessionEvent] = []
    start_idx = 0

    try:
        first_obj = json.loads(lines[0])
        if (
            isinstance(first_obj, Mapping)
            and "schema_version" in first_obj
            and "session_id" in first_obj
            and "kind" not in first_obj
        ):
            try:
                header = parse_session_header(first_obj)
            except Exception:
                header = SessionHeader(
                    schema_version=first_obj["schema_version"],
                    session_id=str(first_obj["session_id"]),
                    created_at=str(first_obj.get("created_at", "")),
                    title=str(first_obj["title"]) if "title" in first_obj else None,
                )
            start_idx = 1
    except Exception:
        pass

    for line in lines[start_idx:]:
        obj = json.loads(line)
        if isinstance(obj, Mapping):
            events.append(parse_session_event(obj, seen_ids=None))
        else:
            raise ValueError("Event record line must be a JSON object mapping")

    return header, events


def _load_source_with_stream_findings(
    path: StrPath,
) -> tuple[SessionHeader | None, list[SessionEvent], list[Finding]]:
    """Load session header, events, and stream findings using io module."""
    from sesslint.io import iter_events, read_header

    p = Path(path)
    try:
        hdr = read_header(p)
        items = list(iter_events(p))
        events = [e for e in items if isinstance(e, SessionEvent)]
        stream_findings = [f for f in items if isinstance(f, Finding)]
        return hdr, events, stream_findings
    except Exception:
        try:
            text = p.read_text(encoding="utf-8-sig").strip()
            if text.startswith("{"):
                data = json.loads(text)
                if isinstance(data, Mapping) and "events" in data:
                    from sesslint.adapters.canonical import load_canonical

                    ev_list, can_findings = load_canonical(p)
                    hdr = SessionHeader(
                        schema_version="sesslint.session/v1",
                        session_id=str(ev_list.source.get("session_id", p.stem)),
                        created_at=str(ev_list.source.get("created_at", "2026-09-05T12:00:00Z")),
                    )
                    return hdr, list(ev_list), list(can_findings)
        except Exception:
            pass
        raise


def _run_detector_checks(
    events: Sequence[SessionEvent],
    *,
    profile_name: str = "neutral",
) -> list[Finding]:
    """Run detector checks directly from checks modules without importing mutator."""
    profile = get_profile(profile_name)
    enabled = set(profile.enabled_rules)
    findings: list[Finding] = []

    if "SL003" in enabled:
        findings.extend(check_identities(events, source_path="<repaired>"))

    graph_rules = {"SL004", "SL005", "SL006", "SL007"}
    if graph_rules & enabled:
        findings.extend(check_graph(events, source_path="<repaired>"))

    tp1_rules = {"SL101", "SL102", "SL103", "SL104"}
    if tp1_rules & enabled:
        findings.extend(check_tool_pairing_1(events, source_path="<repaired>"))

    tp2_rules = {"SL105", "SL106", "SL107", "SL108"}
    if tp2_rules & enabled:
        findings.extend(check_tool_pairing_2(events, source_path="<repaired>", profile=profile))

    cp_rules = {"SL201", "SL202", "SL203"}
    if cp_rules & enabled:
        findings.extend(
            check_checkpoint(
                events,
                source_path="<repaired>",
                checkpoint_sensitivity=profile.checkpoint_sensitivity,
            )
        )

    return [f for f in findings if f.code in enabled]


def verify(
    *,
    source_path: StrPath,
    output_path: StrPath,
    manifest_path: StrPath,
    plan_path: StrPath | None = None,
    acknowledge_side_effects: bool = False,
) -> Verdict:
    """Independently verify a repair manifest, hash bindings, replay, and idempotence.

    Non-short-circuiting: All 7 checks are strictly evaluated in sequence.
    Read-only: Never mutates or writes any files.
    Total function: Returns Verdict on all readable inputs; raises FileNotFoundError or
    OSError only when inputs cannot be read from the filesystem.
    """
    # Initialize recipe registry unconditionally at entry
    register_all_conservative_recipes()
    register_all_salvage_recipes()

    src_p = Path(source_path)
    out_p = Path(output_path)
    man_p = Path(manifest_path)

    for p, label in [(src_p, "Source"), (out_p, "Output"), (man_p, "Manifest")]:
        if not p.exists():
            raise FileNotFoundError(f"{label} file not found: {p}")
        if p.is_dir():
            raise IsADirectoryError(f"{label} path is a directory: {p}")

    source_bytes = src_p.read_bytes()
    output_bytes = out_p.read_bytes()
    manifest_bytes = man_p.read_bytes()

    # Safely parse manifest via parse_manifest (route verify through parse_manifest per RVW-008)
    manifest_dict: dict[str, Any] | None = None
    try:
        manifest_obj = parse_manifest(manifest_bytes.decode("utf-8-sig"))
        manifest_dict = manifest_obj.to_dict()
    except Exception:
        try:
            parsed_m = json.loads(manifest_bytes.decode("utf-8-sig"))
            if isinstance(parsed_m, dict):
                manifest_dict = parsed_m
        except Exception:
            manifest_dict = None

    plan_dict: dict[str, Any] | None = None
    plan_obj: RepairPlan | None = None
    actual_source_hash = hashlib.sha256(source_bytes).hexdigest()

    if plan_path is not None:
        pln_p = Path(plan_path)
        if not pln_p.exists():
            raise FileNotFoundError(f"Plan file not found: {pln_p}")
        if pln_p.is_dir():
            raise IsADirectoryError(f"Plan path is a directory: {pln_p}")
        plan_bytes = pln_p.read_bytes()
        try:
            parsed_p = json.loads(plan_bytes.decode("utf-8-sig"))
            if isinstance(parsed_p, dict):
                plan_dict = parsed_p
                plan_obj = _load_plan_from_dict(plan_dict)
        except Exception:
            plan_dict = None
            plan_obj = None
    else:
        # Reconstruct plan from source events and manifest policy/profile (RVW-024)
        target_policy = (
            str(manifest_dict.get("policy", "conservative"))
            if manifest_dict is not None and "policy" in manifest_dict
            else "conservative"
        )
        target_profile = (
            str(manifest_dict.get("profile", "neutral"))
            if manifest_dict is not None and "profile" in manifest_dict
            else "neutral"
        )
        try:
            try:
                _, src_events, stream_findings = _load_source_with_stream_findings(source_path)
            except Exception:
                _, src_events = _parse_session_events(source_bytes)
                stream_findings = []

            check_findings = _run_detector_checks(
                src_events,
                profile_name=target_profile,
            )
            findings = list(stream_findings) + list(check_findings)
            plan_obj = plan(
                findings=findings,
                events=src_events,
                profile=target_profile,
                policy=target_policy,
                source_hash=actual_source_hash,
                acknowledge_side_effects=acknowledge_side_effects,
            )
            plan_dict = plan_obj.to_dict()
        except Exception:
            plan_obj = None
            plan_dict = None

    # Check 1: source_hash
    if manifest_dict is None:
        c1 = Check(name="source_hash", ok=False, detail="manifest-invalid-json")
    else:
        in_place = bool(manifest_dict.get("in_place", False))
        if in_place:
            expected_src_hash = (
                manifest_dict.get("source_post_hash")
                or manifest_dict.get("output_fingerprint")
                or manifest_dict.get("output_hash")
            )
        else:
            expected_src_hash = manifest_dict.get("input_fingerprint") or manifest_dict.get(
                "source_pre_hash"
            )

        if expected_src_hash is None:
            c1 = Check(name="source_hash", ok=False, detail="field-missing")
        elif actual_source_hash == expected_src_hash:
            c1 = Check(name="source_hash", ok=True, detail="matched")
        else:
            c1 = Check(
                name="source_hash",
                ok=False,
                detail=f"mismatch: expected {expected_src_hash}, got {actual_source_hash}",
            )

    # Check 2: plan_fingerprint
    if plan_dict is None:
        c2 = Check(
            name="plan_fingerprint",
            ok=False,
            detail="invalid-plan-json" if plan_path is not None else "plan-missing",
        )
    else:
        declared_fp = plan_dict.get("fingerprint")
        recomputed_fp = compute_plan_fingerprint(plan_dict)

        if declared_fp is None:
            c2 = Check(name="plan_fingerprint", ok=False, detail="field-missing")
        elif recomputed_fp != declared_fp:
            c2 = Check(
                name="plan_fingerprint",
                ok=False,
                detail=f"plan-tampered: declared {declared_fp}, recomputed {recomputed_fp}",
            )
        elif manifest_dict is not None and "plan_fingerprint" in manifest_dict:
            manifest_fp = manifest_dict["plan_fingerprint"]
            if manifest_fp != recomputed_fp:
                c2 = Check(
                    name="plan_fingerprint",
                    ok=False,
                    detail=f"manifest-mismatch: expected {manifest_fp}, got {recomputed_fp}",
                )
            else:
                c2 = Check(name="plan_fingerprint", ok=True, detail="matched")
        else:
            c2 = Check(
                name="plan_fingerprint",
                ok=False,
                detail="manifest-missing-plan-fingerprint",
            )

    # Check 3: output_hash
    actual_output_hash = hashlib.sha256(output_bytes).hexdigest()
    if manifest_dict is None:
        c3 = Check(name="output_hash", ok=False, detail="manifest-invalid-json")
    else:
        expected_out_hash = manifest_dict.get("output_fingerprint") or manifest_dict.get(
            "output_hash"
        )
        if expected_out_hash is None:
            c3 = Check(name="output_hash", ok=False, detail="field-missing")
        elif actual_output_hash == expected_out_hash:
            c3 = Check(name="output_hash", ok=True, detail="matched")
        else:
            c3 = Check(
                name="output_hash",
                ok=False,
                detail=f"mismatch: expected {expected_out_hash}, got {actual_output_hash}",
            )

    # Check 4: transformation_audit
    source_header: SessionHeader | None = None
    source_events: list[SessionEvent] = []
    output_header: SessionHeader | None = None
    output_events: list[SessionEvent] = []

    try:
        try:
            source_header, source_events, _ = _load_source_with_stream_findings(source_path)
        except Exception:
            source_header, source_events = _parse_session_events(source_bytes)
    except Exception as err:
        c4 = Check(name="transformation_audit", ok=False, detail=f"source-parse-failed: {err}")
    else:
        try:
            try:
                output_header, output_events, _ = _load_source_with_stream_findings(output_path)
            except Exception:
                output_header, output_events = _parse_session_events(output_bytes)
        except Exception as err:
            c4 = Check(name="transformation_audit", ok=False, detail=f"output-parse-failed: {err}")
        else:
            if plan_obj is None:
                c4 = Check(name="transformation_audit", ok=False, detail="invalid-plan")
            elif not output_events and output_bytes.strip():
                c4 = Check(name="transformation_audit", ok=False, detail="output-events-empty")
            else:
                # RVW-021: Audit manifest actions against plan steps
                manifest_actions = (
                    manifest_dict.get("actions") if manifest_dict is not None else None
                )
                actions_audit_ok = True
                actions_audit_err = ""
                if manifest_actions is None:
                    actions_audit_ok = False
                    actions_audit_err = "manifest-missing-actions"
                elif not isinstance(manifest_actions, (list, tuple)):
                    actions_audit_ok = False
                    actions_audit_err = "manifest-actions-invalid-format"
                elif len(manifest_actions) != len(plan_obj.steps):
                    actions_audit_ok = False
                    actions_audit_err = (
                        f"manifest-actions-count-mismatch: expected {len(plan_obj.steps)}, "
                        f"got {len(manifest_actions)}"
                    )
                else:
                    act_kinds = [
                        str(
                            a.get("kind")
                            if isinstance(a, Mapping)
                            else getattr(a, "kind", None) or ""
                        )
                        for a in manifest_actions
                    ]
                    step_recipes = [s.recipe for s in plan_obj.steps]
                    if sorted(act_kinds) != sorted(step_recipes):
                        actions_audit_ok = False
                        actions_audit_err = "manifest-actions-recipes-mismatch"

                if not actions_audit_ok:
                    c4 = Check(name="transformation_audit", ok=False, detail=actions_audit_err)
                else:
                    working_events = [to_canonical_dict(e) for e in source_events]
                    sorted_steps = sorted(plan_obj.steps, key=lambda s: s.seq)
                    replay_err: str | None = None

                    for step in sorted_steps:
                        recipe = get_recipe(step.recipe)
                        if recipe is None or recipe.apply is None:
                            replay_err = f"recipe-missing: {step.recipe}"
                            break
                        try:
                            working_events = recipe.apply(working_events, step)
                        except Exception as err:
                            replay_err = f"recipe-apply-failed: {step.recipe} ({err})"
                            break

                    if replay_err is not None:
                        c4 = Check(name="transformation_audit", ok=False, detail=replay_err)
                    else:
                        replayed_events: list[SessionEvent] = []
                        schema_err: str | None = None
                        for idx, ev_dict in enumerate(working_events):
                            try:
                                replayed_events.append(parse_session_event(ev_dict, seen_ids=None))
                            except Exception as err:
                                schema_err = f"replayed-schema-invalid at index {idx}: {err}"
                                break

                        if schema_err is not None:
                            c4 = Check(name="transformation_audit", ok=False, detail=schema_err)
                        else:
                            replayed_canon = "\n".join(
                                to_canonical_json(to_canonical_dict(e)) for e in replayed_events
                            )
                            output_canon = "\n".join(
                                to_canonical_json(to_canonical_dict(e)) for e in output_events
                            )

                            if replayed_canon.encode("utf-8") != output_canon.encode("utf-8"):
                                c4 = Check(
                                    name="transformation_audit",
                                    ok=False,
                                    detail="events-mismatch: replay differs from output",
                                )
                            elif (
                                source_header is not None
                                and output_header is not None
                                and source_header.session_id != output_header.session_id
                            ):
                                c4 = Check(
                                    name="transformation_audit",
                                    ok=False,
                                    detail="header-mismatch: session_id mismatch",
                                )
                            else:
                                c4 = Check(name="transformation_audit", ok=True, detail="matched")

    # Check 5: loss_audit
    try:
        if plan_obj is None:
            c5 = Check(name="loss_audit", ok=False, detail="invalid-plan")
        elif manifest_dict is None:
            c5 = Check(name="loss_audit", ok=False, detail="manifest-invalid-json")
        else:
            sorted_steps = sorted(plan_obj.steps, key=lambda s: s.seq)
            recomputed_loss_items: list[str] = []
            recomputed_totals: dict[str, int] = {}
            for s in sorted_steps:
                if s.loss and isinstance(s.loss, Mapping):
                    for k, v in sorted(s.loss.items()):
                        if isinstance(v, bool):
                            continue
                        try:
                            v_int = int(v)
                            if v_int > 0:
                                recomputed_loss_items.append(f"{k}:{v_int}")
                                recomputed_totals[str(k)] = recomputed_totals.get(str(k), 0) + v_int
                        except (ValueError, TypeError):
                            continue

            if "declared_loss" in manifest_dict:
                raw_loss = manifest_dict["declared_loss"]
                if not isinstance(raw_loss, (list, tuple)) or not all(
                    isinstance(x, str) for x in raw_loss
                ):
                    c5 = Check(name="loss_audit", ok=False, detail="invalid-declared-loss-format")
                else:
                    manifest_loss = tuple(raw_loss)
                    recomp_tuple = tuple(recomputed_loss_items)
                    if manifest_loss == recomp_tuple:
                        c5 = Check(name="loss_audit", ok=True, detail="matched")
                    else:
                        c5 = Check(
                            name="loss_audit",
                            ok=False,
                            detail=f"mismatch: expected {manifest_loss}, got {recomp_tuple}",
                        )
            elif "loss_totals" in manifest_dict:
                manifest_totals = manifest_dict["loss_totals"]
                if isinstance(manifest_totals, Mapping):
                    try:
                        clean_m: dict[str, int] = {}
                        for k, v in manifest_totals.items():
                            if isinstance(v, bool):
                                raise TypeError("Boolean value is not a valid loss quantity")
                            v_int = int(v)
                            if v_int > 0:
                                clean_m[str(k)] = v_int
                        clean_r = {
                            str(k): int(v) for k, v in recomputed_totals.items() if int(v) > 0
                        }
                        if clean_m == clean_r:
                            c5 = Check(name="loss_audit", ok=True, detail="matched")
                        else:
                            c5 = Check(
                                name="loss_audit",
                                ok=False,
                                detail=f"mismatch: expected {clean_m}, got {clean_r}",
                            )
                    except (ValueError, TypeError):
                        c5 = Check(name="loss_audit", ok=False, detail="invalid-loss-totals-format")
                elif isinstance(manifest_totals, int) and not isinstance(manifest_totals, bool):
                    total_sum = sum(recomputed_totals.values())
                    if total_sum == manifest_totals:
                        c5 = Check(name="loss_audit", ok=True, detail="matched")
                    else:
                        c5 = Check(
                            name="loss_audit",
                            ok=False,
                            detail=f"mismatch: expected {manifest_totals}, got {total_sum}",
                        )
                else:
                    c5 = Check(name="loss_audit", ok=False, detail="invalid-loss-totals-format")
            else:
                c5 = Check(name="loss_audit", ok=False, detail="field-missing")
    except Exception as err:
        c5 = Check(name="loss_audit", ok=False, detail=f"invalid-loss-data: {err}")

    # Check 6: assurance_audit
    recomputed_assurance: str = "clean"
    if plan_obj is not None:
        try:
            recomputed_assurance = cap_assurance("clean", plan_obj)
        except Exception:
            recomputed_assurance = "unrepairable"

    if manifest_dict is None:
        c6 = Check(name="assurance_audit", ok=False, detail="manifest-invalid-json")
    elif plan_obj is None:
        c6 = Check(name="assurance_audit", ok=False, detail="plan-missing")
    elif "assurance" in manifest_dict:
        declared_assurance = str(manifest_dict["assurance"])
        if declared_assurance == recomputed_assurance:
            c6 = Check(name="assurance_audit", ok=True, detail="matched")
        else:
            c6 = Check(
                name="assurance_audit",
                ok=False,
                detail=f"mismatch: expected {declared_assurance}, got {recomputed_assurance}",
            )
    else:
        c6 = Check(name="assurance_audit", ok=False, detail="manifest-missing-assurance")

    # Check 7: idempotence
    try:
        _, fresh_output_events = _parse_session_events(output_bytes)
        if not fresh_output_events and output_bytes.strip():
            c7 = Check(name="idempotence", ok=False, detail="replan-failed: output-events-empty")
        else:
            target_policy = "conservative"
            target_profile = "neutral"
            if plan_obj is not None:
                target_policy = plan_obj.policy
                target_profile = plan_obj.profile
            elif manifest_dict is not None and "policy" in manifest_dict:
                target_policy = str(manifest_dict["policy"])

            findings = _run_detector_checks(fresh_output_events, profile_name=target_profile)
            fresh_plan = plan(
                findings=findings,
                events=fresh_output_events,
                profile=target_profile,
                policy=target_policy,
                source_hash=hashlib.sha256(output_bytes).hexdigest(),
                acknowledge_side_effects=acknowledge_side_effects,
            )
            if len(fresh_plan.steps) == 0:
                c7 = Check(name="idempotence", ok=True, detail="0-steps (converged)")
            else:
                c7 = Check(
                    name="idempotence",
                    ok=False,
                    detail=f"non-idempotent: {len(fresh_plan.steps)} steps remaining",
                )
    except Exception as err:
        c7 = Check(name="idempotence", ok=False, detail=f"replan-failed: {type(err).__name__}")

    checks = (c1, c2, c3, c4, c5, c6, c7)
    overall_ok = all(c.ok for c in checks)
    return Verdict(
        ok=overall_ok,
        checks=checks,
        assurance=recomputed_assurance,
    )


def render_verify_human(verdict: Verdict, *, color: bool = False) -> str:
    """Render verify Verdict to human-readable format."""
    green = "\033[32m" if color else ""
    red = "\033[31m" if color else ""
    bold = "\033[1m" if color else ""
    reset = "\033[0m" if color else ""

    status_str = f"{green}PASSED{reset}" if verdict.ok else f"{red}FAILED{reset}"
    lines = [
        f"Verification: {bold}{status_str}",
        f"Assurance: {verdict.assurance}",
        "Checks:",
    ]
    for c in verdict.checks:
        mark = f"{green}[PASS]{reset}" if c.ok else f"{red}[FAIL]{reset}"
        lines.append(f"  {mark} {c.name}: {c.detail}")
    return "\n".join(lines)


__all__ = [
    "Check",
    "Verdict",
    "render_verify_human",
    "verify",
]
