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
from typing import TYPE_CHECKING, Any, Final, Literal

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
from sesslint.finding import Finding
from sesslint.policy.abstention import should_abstain_from_repair
from sesslint.profiles.builtin import NEUTRAL_PROFILE
from sesslint.profiles.profile import Profile, get_profile
from sesslint.repair.assurance import cap_assurance
from sesslint.repair.errors import (
    Abstained,
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

if TYPE_CHECKING:
    from sesslint.report import RepairManifest


StrPath = str | os.PathLike[str]
SQLITE_MAGIC: Final[bytes] = b"SQLite format 3\x00"


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
) -> list[Finding]:
    """Run all active rule checks enabled by the profile over canonical events."""
    resolved_profile: Profile
    if profile is None:
        resolved_profile = NEUTRAL_PROFILE
    elif isinstance(profile, str):
        resolved_profile = get_profile(profile)
    else:
        resolved_profile = profile

    enabled = set(resolved_profile.enabled_rules)
    findings: list[Finding] = []

    if "SL003" in enabled:
        findings.extend(check_identities(events, source_path=source_path))

    graph_rules = {"SL004", "SL005", "SL006", "SL007"}
    if graph_rules & enabled:
        findings.extend(check_graph(events, source_path=source_path))

    tp1_rules = {"SL101", "SL102", "SL103", "SL104"}
    if tp1_rules & enabled:
        findings.extend(check_tool_pairing_1(events, source_path=source_path))

    tp2_rules = {"SL105", "SL106", "SL107", "SL108"}
    if tp2_rules & enabled:
        findings.extend(
            check_tool_pairing_2(
                events,
                source_path=source_path,
                profile=resolved_profile,
            )
        )

    cp_rules = {"SL201", "SL202", "SL203"}
    if cp_rules & enabled:
        findings.extend(
            check_checkpoint(
                events,
                source_path=source_path,
                checkpoint_sensitivity=resolved_profile.checkpoint_sensitivity,
            )
        )

    return [f for f in findings if f.code in enabled]


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

    Returns:
        A validated RepairManifest instance.

    Raises:
        TypeError: If plan is not a RepairPlan instance.
        PlanTampered: If plan fingerprint recomputation fails.
        PolicyMismatch: If plan policy does not match execution policy.
        Abstained: If SL203 or unacknowledged side-effects are present.
        RepairRefused: If destination path is missing, self, existing, or a live store.
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
    reval_findings = run_all_checks(parsed_output_events, profile=reval_profile_name)
    error_findings = [f for f in reval_findings if f.severity in (Severity.ERROR, Severity.FATAL)]
    if error_findings:
        codes = [f.code for f in error_findings]
        raise OutputInvalid(
            f"Repaired output failed revalidation with {len(error_findings)} "
            f"error finding(s): {codes}"
        )

    # Hook for testing TOCTOU mutation of source file before writing/renaming
    if post_apply_hook is not None:
        post_apply_hook()

    # -------------------------------------------------------------------------
    # STEP 5: Write temp file in same directory, fsync, atomic rename (os.replace)
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

    temp_path: Path | None = None
    target_created = False
    output_hash: str

    if dry_run:
        output_hash = hashlib.sha256(output_bytes).hexdigest()
    else:
        assert output_p is not None
        target_dir = output_p.parent
        if not target_dir.exists():
            raise OutputInvalid(f"Destination directory does not exist: {target_dir}")
        if not os.access(target_dir, os.W_OK):
            raise OutputInvalid(f"Destination directory is not writable: {target_dir}")

        try:
            try:
                with tempfile.NamedTemporaryFile(
                    mode="wb",
                    dir=target_dir,
                    delete=False,
                    prefix=".sesslint-tmp-",
                    suffix=".jsonl",
                ) as tmp_file:
                    temp_path = Path(tmp_file.name)
                    if pre_write_hook is not None:
                        pre_write_hook()
                    tmp_file.write(output_bytes)
                    tmp_file.flush()
                    os.fsync(tmp_file.fileno())

                if pre_rename_hook is not None:
                    pre_rename_hook(temp_path)

                os.replace(temp_path, output_p)
                target_created = True
                temp_path = None  # rename succeeded
            except OSError as err:
                if err.errno == errno.EXDEV:
                    raise OutputInvalid(
                        f"Cross-device link error during atomic rename: {err}"
                    ) from err
                if err.errno == errno.ENOSPC:
                    raise OutputInvalid(f"Disk full during repair write: {err}") from err
                if isinstance(err, PermissionError) or err.errno in (errno.EACCES, errno.EPERM):
                    raise OutputInvalid(f"Permission denied writing to destination: {err}") from err
                raise OutputInvalid(f"Atomic write to destination failed: {err}") from err
        except BaseException:
            # STEP 7: Failure cleanup
            if temp_path is not None and temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass
            if target_created and output_p.exists():
                try:
                    output_p.unlink()
                except OSError:
                    pass
            raise

    # -------------------------------------------------------------------------
    # STEP 6: Post-hash verification
    # -------------------------------------------------------------------------
    if not dry_run:
        assert output_p is not None
        # Re-read source bytes to verify source was never modified
        source_post_bytes = source_p.read_bytes()
        source_post_hash = hashlib.sha256(source_post_bytes).hexdigest()
        if source_post_hash != source_pre_hash:
            if output_p.exists():
                try:
                    output_p.unlink()
                except OSError:
                    pass
            raise OutputInvalid(
                f"Source file was concurrently modified during repair: "
                f"pre={source_pre_hash}, post={source_post_hash}"
            )

        # Read back target bytes to compute exact output digest
        target_bytes = output_p.read_bytes()
        output_hash = hashlib.sha256(target_bytes).hexdigest()

    # -------------------------------------------------------------------------
    # STEP 8: Manifest generation per schema & atomic sidecar write
    # -------------------------------------------------------------------------
    from sesslint.report import (
        RepairAction,
        build_manifest,
        dump_manifest,
    )

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

    manifest_policy: Literal["conservative", "salvage"] = (
        "salvage" if plan.policy == "salvage" else "conservative"
    )

    recipe_versions: dict[str, str] = {}
    for step in sorted_steps:
        rec = get_recipe(step.recipe)
        if rec is not None:
            recipe_versions[step.recipe] = getattr(rec, "version", "1.0.0")

    reval_prof = (
        get_profile(reval_profile_name)
        if isinstance(reval_profile_name, str)
        else reval_profile_name
    )
    prof_version = getattr(reval_prof, "version", "1.0.0")
    adp_version = "1.0.0"

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
        plan_fingerprint=plan.fingerprint,
        assurance=capped_assurance,
        recipe_versions=recipe_versions,
        profile_version=prof_version,
        adapter_version=adp_version,
        byte_counts=byte_counts,
        record_counts=record_counts,
    )

    if not dry_run:
        assert output_p is not None
        target_dir = output_p.parent
        manifest_p = Path(f"{output_p}.manifest.json")

        m_temp: Path | None = None
        try:
            manifest_text = dump_manifest(manifest) + "\n"
            manifest_bytes = manifest_text.encode("utf-8")
            try:
                with tempfile.NamedTemporaryFile(
                    mode="wb",
                    dir=target_dir,
                    delete=False,
                    prefix=".sesslint-tmp-",
                    suffix=".json",
                ) as m_file:
                    m_temp = Path(m_file.name)
                    m_file.write(manifest_bytes)
                    m_file.flush()
                    os.fsync(m_file.fileno())

                os.replace(m_temp, manifest_p)
                m_temp = None
            except OSError as err:
                if err.errno == errno.ENOSPC:
                    raise OutputInvalid(f"Disk full writing repair manifest: {err}") from err
                if isinstance(err, PermissionError) or err.errno in (errno.EACCES, errno.EPERM):
                    raise OutputInvalid(
                        f"Permission denied writing repair manifest: {err}"
                    ) from err
                raise OutputInvalid(f"Failed to write repair manifest: {err}") from err
        except BaseException:
            if m_temp is not None and m_temp.exists():
                try:
                    m_temp.unlink()
                except OSError:
                    pass
            # Atomic repair invariant: never leave output file without valid manifest
            if output_p.exists():
                try:
                    output_p.unlink()
                except OSError:
                    pass
            raise

    return manifest


__all__ = [
    "SQLITE_MAGIC",
    "execute",
    "is_live_store_path",
    "load_plan",
    "load_session_source",
    "run_all_checks",
]
