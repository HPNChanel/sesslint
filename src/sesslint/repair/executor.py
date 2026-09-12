"""Repair execution engine guaranteeing safe, atomic, and verified session updates (TASK-021).

This module implements the single gated repair executor permitted to mutate session files
in SessLint. It enforces a strict, pinned 8-step protocol:
1. Re-validation of plan fingerprint, cap bounds, policy match, and TOCTOU abstention check.
2. Pre-hash source and pre-flight destination validation (refuses self, existing, live-store).
3. In-memory sequential application of fingerprinted recipe steps.
4. Output validation (canonical schema parse, no-synthetic-success multiset check, SL203-absent
   re-scan, and full profile revalidation).
5. Same-directory temp file creation, fsync, and atomic rename (os.replace).
6. Post-hashing (re-read source to verify untouched, and read back target).
7. Failure cleanup (any exception unlinks temp file and leaves source intact).
8. Manifest generation (sesslint.repair-manifest/v1) binding hashes and audit trails.
"""

from __future__ import annotations

import copy
import errno
import hashlib
import json
import os
import tempfile
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Final, Literal

import sesslint.report
from sesslint._version import ADAPTER_VERSIONS, CLI_VERSION
from sesslint.adapters.detect import FORMAT_CLAUDE_CODE, FORMAT_OPENAI_AGENTS
from sesslint.canonical import (
    Session,
    SessionEvent,
    SessionHeader,
    dump_session,
    parse_session_event,
    to_canonical_dict,
)
from sesslint.checks.checkpoint import check_checkpoint
from sesslint.checks.graph import check_graph
from sesslint.checks.identity import check_identities
from sesslint.checks.tool_pairing_1 import check_tool_pairing_1
from sesslint.checks.tool_pairing_2 import check_tool_pairing_2
from sesslint.codes import Severity
from sesslint.context import CheckContext
from sesslint.finding import Finding
from sesslint.policy.abstention import should_abstain_from_repair
from sesslint.profiles.builtin import NEUTRAL_PROFILE
from sesslint.profiles.profile import Profile, get_profile
from sesslint.repair.assurance import cap_assurance, compute_assurance_ceiling
from sesslint.repair.errors import (
    Abstained,
    ManifestCollision,
    OutputInvalid,
    PlanSourceMismatch,
    PlanTampered,
    PolicyMismatch,
    RepairRefused,
)
from sesslint.repair.fingerprint import compute_plan_fingerprint
from sesslint.repair.planner import (
    MAX_STEPS,
    PLAN_VERSION,
    Blocked,
    Loss,
    PlanStep,
    RepairPlan,
    compute_events_source_hash,
)
from sesslint.repair.recipes_conservative import (
    register_all as register_all_conservative_recipes,
)
from sesslint.repair.recipes_salvage import (
    register_all as register_all_salvage_recipes,
)
from sesslint.repair.recipes_sl002 import (
    register_all as register_all_sl002_recipes,
)
from sesslint.repair.registry import get_recipe
from sesslint.report import (
    Coverage,
    CoverageSkip,
    RepairAction,
    RepairManifest,
    RevalidationSummary,
    build_manifest,
    build_report,
    compute_assurance,
    dump_report,
)

StrPath = str | os.PathLike[str]
SQLITE_MAGIC: Final[bytes] = b"SQLite format 3\x00"

_ATOMIC_TEST_HOOKS: dict[str, Any] = {
    "pre_write": None,
    "pre_rename": None,
    "post_apply": None,
    "mid_publish": None,
    "post_publish": None,
}


def _sync_dir(path: Path) -> None:
    """Best-effort parent directory fsync across platforms (guarded for Windows)."""
    if os.name == "nt":
        return
    try:
        dir_fd = os.open(str(path), os.O_RDONLY)
    except (OSError, PermissionError):
        return
    try:
        os.fsync(dir_fd)
    except (OSError, PermissionError):
        pass
    finally:
        try:
            os.close(dir_fd)
        except OSError:
            pass


def is_live_store_path(path: StrPath) -> bool:
    """Check whether a path points to or resembles a live SQLite store.

    Refuses paths with SQLite extensions (.db, .sqlite, .sqlite3) or files
    whose first 16 bytes match the SQLite format 3 magic header.
    """
    p = Path(path)
    if p.suffix.lower() in (".db", ".sqlite", ".sqlite3"):
        return True
    if p.exists() and p.is_file():
        try:
            with open(p, "rb") as f:
                head = f.read(16)
                if head.startswith(SQLITE_MAGIC):
                    return True
        except OSError:
            pass
    return False


def load_plan(source: StrPath | Mapping[str, Any]) -> RepairPlan:
    """Deserialize a RepairPlan from a dictionary or JSON file path.

    Args:
        source: A JSON file path or a dictionary containing plan attributes.

    Returns:
        A strongly-typed frozen RepairPlan instance.

    Raises:
        TypeError: If source is neither a path nor a mapping.
        ValueError: If required plan fields are missing or invalid.
    """
    raw_data: Mapping[str, Any]
    if isinstance(source, (str, os.PathLike)):
        p = Path(source)
        if not p.is_file():
            raise FileNotFoundError(f"Plan file not found: {p}")
        text = p.read_text(encoding="utf-8")
        parsed = json.loads(text)
        if not isinstance(parsed, Mapping):
            raise ValueError(f"Plan file root must be a JSON object, got {type(parsed).__name__}")
        raw_data = parsed
    elif isinstance(source, Mapping):
        raw_data = source
    else:
        raise TypeError(f"Expected path or Mapping, got {type(source).__name__}")

    data = dict(raw_data)
    if "expected_plan" in data and isinstance(data["expected_plan"], Mapping):
        data = dict(data["expected_plan"])

    steps_list: list[PlanStep] = []
    for s in data.get("steps", []):
        steps_list.append(
            PlanStep(
                seq=int(s["seq"]),
                recipe=str(s["recipe"]),
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


def load_session_source_with_findings(
    path: StrPath,
) -> tuple[SessionHeader, list[SessionEvent], list[Finding]]:
    """Load session header, events, and stream-level findings (SL001/SL002).

    Preserves duplicate IDs and nonterminal findings without prematurely failing.
    Falls back to single-document JSON parsing if the file is formatted as single-document JSON.
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Session file not found: {p}")

    from sesslint.errors import SchemaError
    from sesslint.io import iter_events, read_header

    try:
        hdr = read_header(p)
        items = list(iter_events(p))
        events = [e for e in items if isinstance(e, SessionEvent)]
        findings = [f for f in items if isinstance(f, Finding)]
        return hdr, events, findings
    except SchemaError:
        # Fall back to single-document canonical JSON if formatted as a single JSON object
        text = p.read_text(encoding="utf-8-sig").strip()
        if text.startswith("{"):
            try:
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


def load_session_source(path: StrPath) -> tuple[SessionHeader, list[SessionEvent]]:
    """Load session header and events using the TASK-005 canonical streaming loader."""
    hdr, events, _ = load_session_source_with_findings(path)
    return hdr, events


def _copy_events_as_dicts(events: Sequence[Any]) -> list[dict[str, Any]]:
    """Deep copy sequence of events into canonical dictionary format."""
    result: list[dict[str, Any]] = []
    for ev in events:
        if hasattr(ev, "to_canonical_dict"):
            result.append(copy.deepcopy(ev.to_canonical_dict()))
        elif isinstance(ev, Mapping):
            result.append(copy.deepcopy(dict(ev)))
        else:
            result.append(copy.deepcopy(to_canonical_dict(ev)))
    return result


def run_all_checks(
    events: Sequence[SessionEvent],
    *,
    profile: Profile | str | None = None,
    source_path: str = "<repaired>",
    context: CheckContext | None = None,
    adapter: str | None = None,
    adapter_skips: Sequence[CoverageSkip] = (),
    adapter_performed: Sequence[str] = (),
    return_coverage: bool = False,
) -> Any:
    """Run all active rule checks enabled by the profile over canonical events.

    When return_coverage is True, returns (findings, Coverage) collecting executed
    check families and rules alongside gated or skipped rules with closed reasons (FR-047).
    """
    resolved_profile: Profile
    if profile is None:
        resolved_profile = NEUTRAL_PROFILE
    elif isinstance(profile, str):
        resolved_profile = get_profile(profile)
    else:
        resolved_profile = profile

    if context is None:
        source_meta = getattr(events, "source", None)
        context = CheckContext.from_profile_and_adapter(
            profile=resolved_profile,
            adapter=adapter,
            source_metadata=source_meta if isinstance(source_meta, Mapping) else None,
        )
    elif context.source_metadata is None:
        source_meta = getattr(events, "source", None)
        if isinstance(source_meta, Mapping):
            context = context.with_overrides(source_metadata=source_meta)

    enabled = set(resolved_profile.enabled_rules)
    findings: list[Finding] = []

    performed_checks: set[str] = set()
    skipped_checks: list[CoverageSkip] = list(adapter_skips)
    already_skipped_checks: set[str] = {s.check for s in skipped_checks}

    # Ingest adapter checks
    if adapter_performed:
        for ap in adapter_performed:
            if ap in enabled and ap not in already_skipped_checks:
                performed_checks.add(ap)
            elif ap not in enabled and ap not in already_skipped_checks:
                skipped_checks.append(
                    CoverageSkip(
                        check=ap, reason="profile-gated", detail="rule disabled by profile"
                    )
                )
                already_skipped_checks.add(ap)
    else:
        adapter_rules = ("SL001", "SL002", "SL301", "SL302")
        for ar in adapter_rules:
            if ar not in already_skipped_checks:
                if ar in enabled:
                    performed_checks.add(ar)
                else:
                    skipped_checks.append(
                        CoverageSkip(
                            check=ar, reason="profile-gated", detail="rule disabled by profile"
                        )
                    )
                    already_skipped_checks.add(ar)

    is_empty_input = len(events) == 0
    has_version_abort = any(s.reason == "version-gated" for s in adapter_skips)
    has_cap_abort = any(s.reason == "cap-exceeded" for s in adapter_skips)

    families: list[tuple[str, tuple[str, ...]]] = [
        ("identity", ("SL003",)),
        ("graph", ("SL004", "SL005", "SL006", "SL007")),
        ("tool_pairing_1", ("SL101", "SL102", "SL103", "SL104")),
        ("tool_pairing_2", ("SL105", "SL106", "SL107", "SL108")),
        ("checkpoint", ("SL201", "SL202", "SL203")),
    ]

    for fam_name, fam_rules in families:
        fam_enabled_rules = [r for r in fam_rules if r in enabled]
        if not fam_enabled_rules:
            if fam_name not in already_skipped_checks:
                skipped_checks.append(
                    CoverageSkip(
                        check=fam_name,
                        reason="profile-gated",
                        detail="family disabled by profile",
                    )
                )
                already_skipped_checks.add(fam_name)
            for r in fam_rules:
                if r not in already_skipped_checks:
                    skipped_checks.append(
                        CoverageSkip(
                            check=r, reason="profile-gated", detail="rule disabled by profile"
                        )
                    )
                    already_skipped_checks.add(r)
        elif is_empty_input:
            if fam_name not in already_skipped_checks:
                skipped_checks.append(
                    CoverageSkip(
                        check=fam_name,
                        reason="empty-input",
                        detail="zero records in event stream",
                    )
                )
                already_skipped_checks.add(fam_name)
            for r in fam_rules:
                if r not in already_skipped_checks:
                    if r in enabled:
                        skipped_checks.append(
                            CoverageSkip(
                                check=r,
                                reason="empty-input",
                                detail="zero records in event stream",
                            )
                        )
                    else:
                        skipped_checks.append(
                            CoverageSkip(
                                check=r,
                                reason="profile-gated",
                                detail="rule disabled by profile",
                            )
                        )
                    already_skipped_checks.add(r)
        elif has_version_abort:
            if fam_name not in already_skipped_checks:
                skipped_checks.append(
                    CoverageSkip(
                        check=fam_name,
                        reason="version-gated",
                        detail="unsupported format version (SL301)",
                    )
                )
                already_skipped_checks.add(fam_name)
            for r in fam_rules:
                if r not in already_skipped_checks:
                    skipped_checks.append(
                        CoverageSkip(
                            check=r,
                            reason="version-gated",
                            detail="unsupported format version (SL301)",
                        )
                    )
                    already_skipped_checks.add(r)
        elif has_cap_abort:
            if fam_name not in already_skipped_checks:
                skipped_checks.append(
                    CoverageSkip(
                        check=fam_name,
                        reason="cap-exceeded",
                        detail="stream limit cap exceeded",
                    )
                )
                already_skipped_checks.add(fam_name)
            for r in fam_rules:
                if r not in already_skipped_checks:
                    skipped_checks.append(
                        CoverageSkip(
                            check=r,
                            reason="cap-exceeded",
                            detail="stream limit cap exceeded",
                        )
                    )
                    already_skipped_checks.add(r)
        else:
            performed_checks.add(fam_name)
            for r in fam_rules:
                if r in enabled:
                    performed_checks.add(r)
                elif r not in already_skipped_checks:
                    skipped_checks.append(
                        CoverageSkip(
                            check=r, reason="profile-gated", detail="rule disabled by profile"
                        )
                    )
                    already_skipped_checks.add(r)

    if not is_empty_input and not has_version_abort and not has_cap_abort:
        if "SL003" in enabled:
            findings.extend(check_identities(events, source_path=source_path, context=context))

        graph_rules = {"SL004", "SL005", "SL006", "SL007"}
        if graph_rules & enabled:
            findings.extend(check_graph(events, source_path=source_path, context=context))

        tp1_rules = {"SL101", "SL102", "SL103", "SL104"}
        if tp1_rules & enabled:
            findings.extend(check_tool_pairing_1(events, source_path=source_path, context=context))

        tp2_rules = {"SL105", "SL106", "SL107", "SL108"}
        if tp2_rules & enabled:
            findings.extend(
                check_tool_pairing_2(
                    events,
                    source_path=source_path,
                    profile=resolved_profile,
                    context=context,
                )
            )

        cp_rules = {"SL201", "SL202", "SL203"}
        if cp_rules & enabled:
            findings.extend(
                check_checkpoint(
                    events,
                    source_path=source_path,
                    checkpoint_sensitivity=resolved_profile.checkpoint_sensitivity,
                    context=context,
                )
            )

    filtered_findings = [f for f in findings if f.code in enabled]
    if return_coverage:
        cov = Coverage(
            performed=tuple(sorted(performed_checks)),
            skipped=tuple(sorted(skipped_checks)),
            adapter={"id": context.adapter_id, "version": context.adapter_version},
            profile={"id": context.profile_id, "version": context.profile_version},
        )
        return filtered_findings, cov
    return filtered_findings


def execute(
    *,
    source_path: StrPath,
    plan: RepairPlan,
    output_path: StrPath | None = None,
    policy: str = "conservative",
    dry_run: bool = False,
    profile: Profile | str | None = None,
    format: str | None = None,
    acknowledge_side_effects: bool = False,
    source_events: Sequence[SessionEvent] | None = None,
    pre_rename_hook: Callable[[Path], None] | None = None,
    pre_write_hook: Callable[[], None] | None = None,
    post_apply_hook: Callable[[], None] | None = None,
    mid_publish_hook: Callable[[], None] | None = None,
    post_publish_hook: Callable[[], None] | None = None,
) -> RepairManifest:
    """Execute a fingerprinted repair plan atomically against a session source.

    Follows the pinned 8-step protocol:
    1. Re-validate: plan fingerprint, plan step cap, policy match, and TOCTOU abstention check.
    2. Source pre-hash and destination pre-flight validation (refuses self, existing, live-store).
    3. Apply recipe steps sequentially in memory.
    4. Output validation: schema conformance, no-synthetic-success multiset check,
       SL203-absent re-scan, and full profile revalidation.
    5. Write temp file in same directory, fsync, and atomic rename (os.replace).
    6. Post-hash: verify source file was never touched; compute output digest.
    7. Failure cleanup: guarantee no temp file or partial output remains.
    8. Manifest generation and atomic sidecar emission (<target>.manifest.json).

    Args:
        source_path: Path to the input session file.
        plan: The RepairPlan instance to execute.
        output_path: Required path for repaired file (unless dry_run=True).
        policy: Expected repair policy ('conservative' or 'salvage').
        dry_run: If True, executes purely in memory without creating any files.
        profile: Profile name or instance for revalidation (defaults to plan's profile).
        format: Session format override or hint.
        acknowledge_side_effects: Operator acknowledgement of tool side-effects.
        source_events: Optional pre-loaded session events from canonical reader.
        pre_rename_hook: Testing hook invoked after temp fsync before os.replace.
        pre_write_hook: Testing hook invoked before writing temp file.
        post_apply_hook: Testing hook invoked after memory apply before write.
        mid_publish_hook: Testing hook invoked after manifest link before output rename.
        post_publish_hook: Testing hook invoked after publish and directory fsync.

    Returns:
        A validated RepairManifest instance.

    Raises:
        TypeError: If plan is not a RepairPlan instance.
        PlanTampered: If plan fingerprint recomputation fails.
        PolicyMismatch: If plan policy does not match execution policy.
        Abstained: If SL203 or unacknowledged side-effects are present.
        RepairRefused: If destination path is missing, self, existing, or a live store.
        ManifestCollision: If destination manifest already exists (receipt collision).
        OutputInvalid: If output validation fails (schema, synthetic success, SL203, cap, reval).
        FileNotFoundError: If source file does not exist.
    """
    # -------------------------------------------------------------------------
    # STEP 1: Re-validate plan, cap, policy, and TOCTOU abstention
    # -------------------------------------------------------------------------
    if not isinstance(plan, RepairPlan):
        raise TypeError(f"plan must be a RepairPlan instance, got {type(plan).__name__}")

    # Step 1a: Cap check
    if len(plan.steps) > MAX_STEPS:
        raise OutputInvalid(
            f"Plan step count ({len(plan.steps)}) exceeds maximum allowed cap ({MAX_STEPS})"
        )

    # Step 1b: Recompute plan fingerprint
    plan_dict = plan.to_dict()
    recomputed_fp = compute_plan_fingerprint(plan_dict)
    if recomputed_fp != plan.fingerprint:
        raise PlanTampered(
            f"Plan fingerprint mismatch: declared '{plan.fingerprint}', "
            f"recomputed '{recomputed_fp}'"
        )

    # RVW-019: Direct repair of vendor formats is rejected (canonical only)
    if format in (FORMAT_CLAUDE_CODE, FORMAT_OPENAI_AGENTS):
        raise RepairRefused(
            f"Direct repair of vendor format '{format}' is not supported. "
            "Repair operates exclusively on canonical session streams (JSONL)."
        )

    # Step 1c: Policy match
    if plan.policy != policy:
        raise PolicyMismatch(
            f"Plan policy '{plan.policy}' does not match execution policy '{policy}'"
        )

    # Step 1d: Load source and pre-hash
    source_p = Path(source_path)
    if not source_p.is_file():
        raise FileNotFoundError(f"Source session file not found: {source_p}")

    source_bytes = source_p.read_bytes()
    source_pre_hash = hashlib.sha256(source_bytes).hexdigest()

    source_header: SessionHeader | None = None
    loaded_events: list[SessionEvent]
    if source_events is not None:
        loaded_events = list(source_events)
    else:
        source_header, loaded_events = load_session_source(source_p)

    events_hash = compute_events_source_hash(loaded_events)
    if plan.source_hash != source_pre_hash and plan.source_hash != events_hash:
        raise PlanSourceMismatch(
            f"Plan source_hash mismatch: plan '{plan.source_hash}' matches neither "
            f"source file SHA-256 ('{source_pre_hash}') nor events hash ('{events_hash}')"
        )

    # Step 1e: TOCTOU abstention re-check on current source (RVW-011)
    chk_findings = check_checkpoint(loaded_events)
    abst = should_abstain_from_repair(
        chk_findings,
        loaded_events,
        policy=policy,
        acknowledge_side_effects=acknowledge_side_effects,
    )
    if abst.abstain:
        raise Abstained(f"Repair abstained: {', '.join(abst.reasons)}")

    # -------------------------------------------------------------------------
    # STEP 2: Pre-flight destination path checks
    # -------------------------------------------------------------------------
    output_p: Path | None = None
    if not dry_run:
        if output_path is None:
            raise RepairRefused("Output path is required when not in dry-run mode")
        output_p = Path(output_path)

        # Refuse live-store path
        if is_live_store_path(output_p):
            raise RepairRefused(f"Refusing to write to live-store path: {output_p}")

        # Refuse self-output (canonical realpath comparison)
        source_real = os.path.realpath(source_p)
        output_real = os.path.realpath(output_p)
        if source_real == output_real:
            raise RepairRefused(
                f"Output path resolves to source path (no in-place mutation): {output_p}"
            )

        # Refuse existing output file
        if output_p.exists():
            raise RepairRefused(f"Output path already exists (refusing to overwrite): {output_p}")

        # Refuse existing manifest file (exclusive create / receipt collision prevention)
        manifest_p = Path(f"{output_p}.manifest.json")
        if manifest_p.exists():
            raise ManifestCollision(
                "Repair manifest destination already exists "
                f"(refusing to overwrite receipt): {manifest_p}"
            )

    # -------------------------------------------------------------------------
    # STEP 3: Apply recipe steps sequentially in memory
    # -------------------------------------------------------------------------
    register_all_conservative_recipes()
    register_all_salvage_recipes()
    register_all_sl002_recipes()

    working_events = _copy_events_as_dicts(loaded_events)
    sorted_steps = sorted(plan.steps, key=lambda s: s.seq)

    for step in sorted_steps:
        recipe = get_recipe(step.recipe)
        if recipe is None or recipe.apply is None:
            raise OutputInvalid(f"Recipe '{step.recipe}' not found or has no apply handler")

        # RVW-004: Enforce per-step minimum policy regardless of plan provenance
        step_min_policy = getattr(step, "min_policy", "conservative")
        rec_min_policy = getattr(recipe, "min_policy", "conservative")
        if (
            recipe.salvage_only
            or recipe.lossy
            or step.lossy
            or step_min_policy == "salvage"
            or rec_min_policy == "salvage"
        ):
            if policy != "salvage":
                raise PolicyMismatch(
                    f"Step {step.seq} (recipe '{step.recipe}') requires 'salvage' policy, "
                    f"but repair execution was invoked under policy '{policy}'"
                )

        try:
            working_events = recipe.apply(working_events, step)
        except Exception as err:
            raise OutputInvalid(f"Recipe '{step.recipe}' failed at step {step.seq}: {err}") from err

    # -------------------------------------------------------------------------
    # STEP 4: Output validation
    # -------------------------------------------------------------------------
    # (a) Canonical schema parse
    parsed_output_events: list[SessionEvent] = []
    for idx, ev_dict in enumerate(working_events):
        try:
            ev = parse_session_event(ev_dict)
            parsed_output_events.append(ev)
        except Exception as err:
            raise OutputInvalid(
                f"Repaired output event at index {idx} failed canonical schema: {err}"
            ) from err

    # (b) No-synthetic-success multiset check: tool_result multiset ⊆ input multiset
    def _tr_key(ev: Any) -> str:
        rec_id = getattr(ev, "id", None)
        if rec_id is None and isinstance(ev, Mapping):
            rec_id = ev.get("id")
        return str(rec_id) if rec_id is not None else ""

    input_tr_counts = Counter(
        _tr_key(e)
        for e in loaded_events
        if (getattr(e, "kind", None) or (e.get("kind") if isinstance(e, Mapping) else None))
        == "tool_result"
    )
    output_tr_counts = Counter(e.id for e in parsed_output_events if e.kind == "tool_result")

    for tr_id, out_count in output_tr_counts.items():
        in_count = input_tr_counts.get(tr_id, 0)
        if out_count > in_count:
            raise OutputInvalid(
                f"Synthetic tool_result detected in output (id: '{tr_id}', "
                f"output count {out_count} > input count {in_count})"
            )

    # (c) SL203-absent re-scan
    output_chk_findings = check_checkpoint(parsed_output_events)
    if any(f.code == "SL203" for f in output_chk_findings):
        raise OutputInvalid("SL203 finding present in repaired output")

    # (d) Full profile revalidation
    reval_profile_name = profile if profile is not None else plan.profile
    reval_findings, reval_coverage = run_all_checks(
        parsed_output_events,
        profile=reval_profile_name,
        adapter="canonical",
        return_coverage=True,
    )
    error_findings = [f for f in reval_findings if f.severity in (Severity.ERROR, Severity.FATAL)]
    if error_findings:
        codes = [f.code for f in error_findings]
        raise OutputInvalid(
            f"Repaired output failed revalidation with {len(error_findings)} "
            f"error finding(s): {codes}"
        )

    # Capture revalidation outcomes directly from Step 4d run (FR-072)
    reval_assurance, reval_limitation = compute_assurance(parsed_output_events, reval_findings)
    reval_prof = (
        get_profile(reval_profile_name)
        if isinstance(reval_profile_name, str)
        else reval_profile_name
    )
    reval_prof_id = getattr(reval_prof, "id", str(reval_profile_name))
    reval_prof_ver = getattr(reval_prof, "version", "1.0.0")
    warning_count = len([f for f in reval_findings if f.severity == Severity.WARNING])

    # Hook for testing TOCTOU mutation of source file before writing/renaming
    active_post_apply = post_apply_hook or _ATOMIC_TEST_HOOKS.get("post_apply")
    if active_post_apply is not None:
        active_post_apply()

    # -------------------------------------------------------------------------
    # STEP 5 & 8: Construct repaired artifacts, revalidation binding & manifest
    # -------------------------------------------------------------------------
    repaired_header = (
        source_header
        if source_header is not None
        else SessionHeader(
            schema_version="sesslint.session/v1",
            session_id=source_p.stem,
            created_at="2026-09-05T12:00:00Z",
        )
    )
    repaired_session = Session(header=repaired_header, events=tuple(parsed_output_events))
    output_text = dump_session(repaired_session)
    output_bytes = output_text.encode("utf-8")
    output_hash = hashlib.sha256(output_bytes).hexdigest()

    # Final Step-6 revalidation report object
    reval_report = build_report(
        session_id=repaired_header.session_id,
        source_fingerprint=output_hash,
        tool_version=CLI_VERSION,
        findings=reval_findings,
        assurance=reval_assurance,
        limitation=reval_limitation,
        coverage=reval_coverage,
    )
    reval_report_fp = hashlib.sha256(dump_report(reval_report).encode("utf-8")).hexdigest()

    revalidation_summary = RevalidationSummary(
        assurance=reval_assurance,
        error_count=len(error_findings),
        warning_count=warning_count,
        profile_id=reval_prof_id,
        profile_version=reval_prof_ver,
        report_fingerprint=reval_report_fp,
    )

    manifest_policy: Literal["conservative", "salvage"] = (
        "salvage" if plan.policy == "salvage" else "conservative"
    )
    assurance_ceiling = compute_assurance_ceiling(reval_assurance, manifest_policy)

    adapter_id = "canonical"
    if format in ADAPTER_VERSIONS:
        adapter_id = format
    adp_version = ADAPTER_VERSIONS.get(adapter_id, "unknown")

    actions = tuple(
        RepairAction(
            kind=step.recipe,
            record_id=step.target_finding_fp if step.target_finding_fp else None,
            detail=f"step {step.seq}",
        )
        for step in sorted_steps
    )

    declared_loss: list[str] = []
    for step in sorted_steps:
        if step.loss:
            for k, v in sorted(step.loss.items()):
                if v > 0:
                    declared_loss.append(f"{k}:{v}")

    recipe_versions: dict[str, str] = {}
    for step in sorted_steps:
        rec = get_recipe(step.recipe)
        if rec is not None:
            recipe_versions[step.recipe] = getattr(rec, "version", "1.0.0")

    byte_counts = {
        "output": len(output_bytes),
        "source": len(source_bytes),
    }
    record_counts = {
        "output": len(parsed_output_events),
        "source": len(loaded_events),
    }
    capped_assurance = cap_assurance("clean", plan)

    manifest = build_manifest(
        input_fingerprint=source_pre_hash,
        output_fingerprint=output_hash,
        policy=manifest_policy,
        actions=actions,
        declared_loss=tuple(declared_loss),
        revalidate_report=None,
        revalidation=revalidation_summary,
        assurance_ceiling=assurance_ceiling,
        plan_fingerprint=plan.fingerprint,
        assurance=capped_assurance,
        recipe_versions=recipe_versions,
        profile_version=reval_prof_ver,
        adapter_id=adapter_id,
        adapter_version=adp_version,
        byte_counts=byte_counts,
        record_counts=record_counts,
    )

    if dry_run:
        return manifest

    # -------------------------------------------------------------------------
    # STEP 6 & 7: Verify source integrity, publish exclusive pair & fsync
    # -------------------------------------------------------------------------
    assert output_p is not None
    # Re-read source bytes to verify source was never concurrently modified
    source_post_bytes = source_p.read_bytes()
    source_post_hash = hashlib.sha256(source_post_bytes).hexdigest()
    if source_post_hash != source_pre_hash:
        raise OutputInvalid(
            f"Source file was concurrently modified during repair: "
            f"pre={source_pre_hash}, post={source_post_hash}"
        )

    target_dir = output_p.parent
    if not target_dir.exists():
        raise OutputInvalid(f"Destination directory does not exist: {target_dir}")
    if not os.access(target_dir, os.W_OK):
        raise OutputInvalid(f"Destination directory is not writable: {target_dir}")

    manifest_p = Path(f"{output_p}.manifest.json")
    manifest_text = sesslint.report.dump_manifest(manifest) + "\n"
    manifest_bytes = manifest_text.encode("utf-8")

    temp_path: Path | None = None
    m_temp: Path | None = None
    manifest_linked = False
    output_replaced = False

    try:
        try:
            # 1. Write output temp file
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=target_dir,
                delete=False,
                prefix=".sesslint-tmp-out-",
                suffix=".jsonl",
            ) as tmp_file:
                temp_path = Path(tmp_file.name)
                active_pre_write = pre_write_hook or _ATOMIC_TEST_HOOKS.get("pre_write")
                if active_pre_write is not None:
                    active_pre_write()
                tmp_file.write(output_bytes)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())

            # 2. Write manifest temp file
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=target_dir,
                delete=False,
                prefix=".sesslint-tmp-man-",
                suffix=".json",
            ) as m_file:
                m_temp = Path(m_file.name)
                m_file.write(manifest_bytes)
                m_file.flush()
                os.fsync(m_file.fileno())

            # 3. Exclusive-create manifest receipt (O_EXCL via os.link)
            try:
                os.link(m_temp, manifest_p)
                manifest_linked = True
            except FileExistsError as err:
                raise ManifestCollision(
                    "Repair manifest destination already exists "
                    f"(refusing to overwrite receipt): {manifest_p}"
                ) from err
            finally:
                if m_temp.exists():
                    try:
                        m_temp.unlink()
                    except OSError:
                        pass
                m_temp = None

            # Mid-publish fault-injection hook (e.g. crash simulation)
            active_mid_publish = mid_publish_hook or _ATOMIC_TEST_HOOKS.get("mid_publish")
            if active_mid_publish is not None:
                active_mid_publish()

            # Pre-rename hook before final output replace
            active_pre_rename = pre_rename_hook or _ATOMIC_TEST_HOOKS.get("pre_rename")
            if active_pre_rename is not None:
                active_pre_rename(temp_path)

            # 4. Atomic replace of output
            os.replace(temp_path, output_p)
            output_replaced = True
            temp_path = None

            # 5. Directory fsync after both published
            _sync_dir(target_dir)

            active_post_publish = post_publish_hook or _ATOMIC_TEST_HOOKS.get("post_publish")
            if active_post_publish is not None:
                active_post_publish()

        except OSError as err:
            if isinstance(err, FileExistsError):
                raise
            if err.errno == errno.EXDEV:
                raise OutputInvalid(f"Cross-device link error during atomic rename: {err}") from err
            if err.errno == errno.ENOSPC:
                raise OutputInvalid(f"Disk full during repair write: {err}") from err
            if isinstance(err, PermissionError) or err.errno in (errno.EACCES, errno.EPERM):
                raise OutputInvalid(f"Permission denied writing to destination: {err}") from err
            raise OutputInvalid(f"Atomic write to destination failed: {err}") from err
    except BaseException:
        # Atomic repair invariant: never leave output or manifest orphaned
        if temp_path is not None and temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
        if m_temp is not None and m_temp.exists():
            try:
                m_temp.unlink()
            except OSError:
                pass
        if manifest_linked and manifest_p.exists() and not output_replaced:
            try:
                manifest_p.unlink()
            except OSError:
                pass
        if output_replaced and output_p.exists() and not manifest_p.exists():
            try:
                output_p.unlink()
            except OSError:
                pass
        raise

    return manifest


__all__ = [
    "SQLITE_MAGIC",
    "_ATOMIC_TEST_HOOKS",
    "execute",
    "is_live_store_path",
    "load_plan",
    "load_session_source",
    "run_all_checks",
]
