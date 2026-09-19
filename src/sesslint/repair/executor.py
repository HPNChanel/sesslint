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
from sesslint._events import _copy_events_as_dicts_strict as _copy_events_as_dicts
from sesslint._version import ADAPTER_VERSIONS, CLI_VERSION
from sesslint.adapters.detect import (
    FORMAT_CLAUDE_CODE,
    FORMAT_CODEX_ROLLOUT,
    FORMAT_OPENAI_AGENTS,
)
from sesslint.atomic import atomic_write_bytes
from sesslint.canonical import (
    Session,
    SessionEvent,
    SessionHeader,
    dump_session,
    parse_session_event,
    reparse_identity_hashes,
)
from sesslint.checks.checkpoint import check_checkpoint
from sesslint.checks.runner import run_all_checks
from sesslint.codes import Severity
from sesslint.errors import AtomicWriteError
from sesslint.finding import Finding
from sesslint.policy.abstention import (
    check_step_scope,
    must_abstain,
    should_abstain_from_repair,
)
from sesslint.profiles.profile import Profile, get_profile
from sesslint.progress import (
    CancellationToken,
    ProgressCallback,
    ProgressEvent,
    check_token,
    emit,
)
from sesslint.repair.assurance import cap_assurance, compute_assurance_ceiling
from sesslint.repair.errors import (
    Abstained,
    ManifestCollision,
    OutputInvalid,
    PlanSourceMismatch,
    PlanTampered,
    PolicyMismatch,
    RepairRefused,
    VendorRepairRefused,
)
from sesslint.repair.fingerprint import compute_plan_fingerprint
from sesslint.repair.planner import (
    MAX_STEPS,
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
from sesslint.repair.writeback import emit_vendor_bytes
from sesslint.report import (
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


def _plan_requires_salvage(plan: RepairPlan) -> bool:
    """Check if plan contains salvage-class steps, lossy recipes, or declared loss (P0-03)."""
    if plan.policy == "salvage":
        return True
    if plan.loss_accounting.total_lost > 0:
        return True
    if any(v > 0 for v in plan.loss_accounting.preview.values() if v is not None):
        return True
    for step in plan.steps:
        if step.lossy:
            return True
        if any(v > 0 for v in step.loss.values() if v is not None):
            return True
        if getattr(step, "min_policy", "conservative") == "salvage":
            return True
        rec = get_recipe(step.recipe)
        if rec is not None and (
            getattr(rec, "salvage_only", False)
            or getattr(rec, "lossy", False)
            or getattr(rec, "min_policy", "conservative") == "salvage"
        ):
            return True
    return False


def load_plan(
    source: StrPath | Mapping[str, Any],
    *,
    policy: str | None = None,
) -> RepairPlan:
    """Deserialize a RepairPlan from a dictionary or JSON file path.

    Args:
        source: A JSON file path or a dictionary containing plan attributes.
        policy: Optional execution policy expectation ('conservative' or 'salvage').

    Returns:
        A strongly-typed frozen RepairPlan instance.

    Raises:
        TypeError: If source is neither a path nor a mapping.
        ValueError: If required plan fields are missing or invalid.
        PolicyMismatch: If plan contains salvage-class steps/loss under conservative policy.
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

    plan = RepairPlan.from_dict(raw_data)

    if policy is not None:
        if policy == "conservative" and _plan_requires_salvage(plan):
            raise PolicyMismatch(
                "Plan requires 'salvage' policy due to salvage-class steps or declared loss, "
                f"but invocation requested '{policy}' policy"
            )
        if plan.policy != policy:
            raise PolicyMismatch(
                f"Plan policy '{plan.policy}' does not match requested policy '{policy}'"
            )

    return plan


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
        from sesslint.adapters.canonical import CRITICAL_KEYS

        hdr_findings: list[Finding] = []
        hdr = read_header(p, dup_sink=hdr_findings, critical_keys=CRITICAL_KEYS)
        items = list(iter_events(p, critical_keys=CRITICAL_KEYS))
        events = [e for e in items if isinstance(e, SessionEvent)]
        findings = hdr_findings + [f for f in items if isinstance(f, Finding)]
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


def load_source_for_format(
    path: StrPath,
    format: str | None,
) -> tuple[SessionHeader | None, list[SessionEvent], list[Finding]]:
    """Load events (and stream findings) via the adapter matching ``format``.

    Vendor adapters return no session header and produce canonical events that
    carry provenance (``source_line``/``source_record_hash``) required for
    vendor write-back projection.
    """
    from sesslint.adapters.load import is_vendor_format, load_vendor_events

    if is_vendor_format(format):
        events, findings = load_vendor_events(Path(path), format)
        return None, events, findings
    hdr, events, findings = load_session_source_with_findings(Path(path))
    return hdr, events, findings


def execute(
    *,
    source_path: StrPath,
    plan: RepairPlan,
    output_path: StrPath | None = None,
    policy: str = "conservative",
    dry_run: bool = False,
    profile: Profile | str | None = None,
    format: str | None = None,
    emit_format: str | None = None,
    acknowledge_side_effects: bool = False,
    source_events: Sequence[SessionEvent] | None = None,
    source_findings: Sequence[Finding] | None = None,
    pre_rename_hook: Callable[[Path], None] | None = None,
    pre_write_hook: Callable[[], None] | None = None,
    post_apply_hook: Callable[[], None] | None = None,
    mid_publish_hook: Callable[[], None] | None = None,
    post_publish_hook: Callable[[], None] | None = None,
    progress_cb: ProgressCallback | None = None,
    cancel_token: CancellationToken | None = None,
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
        format: Input session format id ('canonical' or a vendor format id,
            or None for canonical).
        emit_format: Output artifact format id. 'canonical' (or None on canonical
            input) emits a canonical session stream; a vendor format id performs
            drop-only line-verbatim write-back and revalidates the emitted
            artifact through its adapter.
        acknowledge_side_effects: Operator acknowledgement of tool side-effects.
        source_events: Optional pre-loaded session events (must carry vendor
            provenance fields when emit_format is a vendor format).
        source_findings: Optional findings computed for the source (used to
            resolve which event-less source lines the plan explicitly discards).
        pre_rename_hook: Testing hook invoked after temp fsync before os.replace.
        pre_write_hook: Testing hook invoked before writing temp file.
        post_apply_hook: Testing hook invoked after memory apply before write.
        mid_publish_hook: Testing hook invoked after manifest link before output rename.
        post_publish_hook: Testing hook invoked after publish and directory fsync.
        progress_cb: Optional callback receiving ``ProgressEvent`` records
            (``repair:step`` per applied recipe step) — DW-T-13.
        cancel_token: Optional cooperative cancellation token checked at each
            step boundary and once before publish. ``OperationCancelled``
            propagates through the same failure-cleanup path as any other
            error: no partial output or manifest is left behind.

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

    # RVW-019: Emit resolution. Adapter input defaults to same-format
    # write-back (drop-only line-verbatim projection); 'canonical' emit
    # produces a canonical stream. Emitting adapter output from a canonical
    # source is a usage error: canonical events carry no source provenance.
    input_is_vendor = format in (
        FORMAT_CLAUDE_CODE,
        FORMAT_OPENAI_AGENTS,
        FORMAT_CODEX_ROLLOUT,
    )
    resolved_emit: str
    if emit_format in (None, "auto"):
        resolved_emit = "canonical"
        if input_is_vendor and format is not None:
            resolved_emit = format
    elif emit_format == "vendor":
        if not input_is_vendor or format is None:
            raise VendorRepairRefused(
                "Cannot emit vendor output for a canonical source: canonical "
                "events carry no vendor provenance. Omit --emit or use "
                "'--emit canonical'."
            )
        resolved_emit = format
    else:
        resolved_emit = str(emit_format)
    emit_is_vendor = resolved_emit in (
        FORMAT_CLAUDE_CODE,
        FORMAT_OPENAI_AGENTS,
        FORMAT_CODEX_ROLLOUT,
    )

    # Step 1c: Policy match & minimum policy gate (P0-03)
    if plan.policy != policy:
        raise PolicyMismatch(
            f"Plan policy '{plan.policy}' does not match execution policy '{policy}'"
        )
    if policy == "conservative" and _plan_requires_salvage(plan):
        raise PolicyMismatch(
            "Plan contains salvage-class steps or declared loss, which requires 'salvage' policy, "
            "but repair execution was invoked under policy 'conservative'"
        )

    # Step 1d: Load source and pre-hash
    source_p = Path(source_path)
    if not source_p.is_file():
        raise FileNotFoundError(f"Source session file not found: {source_p}")

    source_bytes = source_p.read_bytes()
    source_pre_hash = hashlib.sha256(source_bytes).hexdigest()

    source_header: SessionHeader | None = None
    loaded_events: list[SessionEvent]
    loaded_stream_findings: list[Finding] = []
    if source_events is not None:
        loaded_events = list(source_events)
    else:
        source_header, loaded_events, loaded_stream_findings = load_source_for_format(
            source_p, format
        )

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

    # Vendor write-back: physical lines the plan explicitly discards even though
    # they produced no canonical events (e.g. the torn terminal record that
    # produced only an SL002 finding). A no-event line NOT covered by an applied
    # step is kept verbatim — uninterpreted content is never silently dropped.
    drop_lines: frozenset[int] = frozenset()
    if emit_is_vendor:
        targeted_fps = {s.target_finding_fp for s in plan.steps if s.target_finding_fp}
        all_src_findings = list(source_findings or ()) + list(loaded_stream_findings)
        drop_lines = frozenset(
            f.source.line
            for f in all_src_findings
            if f.fingerprint in targeted_fps
            and f.source is not None
            and isinstance(f.source.line, int)
            and not isinstance(f.source.line, bool)
            and f.source.line >= 1
        )

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

    for step_idx, step in enumerate(sorted_steps):
        check_token(cancel_token)
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

        # DEV-013: Re-derive scoped abstention check per step (fail-closed against crafted plans)
        if policy == "conservative":
            reg_fn = getattr(recipe, "affected_region", None)
            if reg_fn is not None:
                is_disjoint, refusal_reason = check_step_scope(
                    step,
                    loaded_events,
                    recipe_region_fn=reg_fn,
                    findings=chk_findings,
                    excludes_execution_dependence=getattr(
                        recipe, "excludes_execution_dependence", False
                    ),
                )
                if not is_disjoint:
                    raise Abstained(
                        f"Repair abstained: step {step.seq} (recipe '{step.recipe}') "
                        f"scope unproven ({refusal_reason or 'side-effect-scope-unproven'})"
                    )
            else:
                # Recipe does not declare affected_region: keeps global gating
                global_abst = must_abstain(chk_findings, loaded_events)
                if global_abst.abstain:
                    raise Abstained(
                        f"Repair abstained: step {step.seq} (recipe '{step.recipe}') "
                        f"side-effect abstention"
                    )

        try:
            working_events = recipe.apply(working_events, step)
        except Exception as err:
            raise OutputInvalid(f"Recipe '{step.recipe}' failed at step {step.seq}: {err}") from err
        emit(
            progress_cb,
            ProgressEvent(
                phase="repair:step",
                completed=step_idx + 1,
                total=len(sorted_steps),
                item=step.recipe,
            ),
        )

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
    from sesslint.reference import reference_equivalent_if_clean

    reval_assurance, reval_limitation = compute_assurance(
        parsed_output_events,
        reval_findings,
        reference_equivalent=reference_equivalent_if_clean(parsed_output_events, reval_findings),
    )
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
    projection_summary: Any = None
    if emit_is_vendor:
        # Vendor write-back: emit byte-identical surviving source lines only.
        # Refuses (VendorProjectionRefused, R1-R6) on any provenance, drift,
        # rewrite, or ordering condition it cannot prove safe.
        output_bytes, projection_summary = emit_vendor_bytes(
            source_bytes,
            loaded_events,
            parsed_output_events,
            resolved_emit,
            drop_lines=drop_lines,
        )
        # Reload gate: the emitted artifact must re-parse through its own
        # adapter to exactly the repaired event set (by content identity) and
        # produce no error findings under the profile. Fail closed otherwise.
        from sesslint.adapters.load import reload_vendor_bytes

        emit_events, emit_adapter_findings = reload_vendor_bytes(resolved_emit, output_bytes)
        emit_check_findings = run_all_checks(
            emit_events,
            profile=reval_profile_name,
            adapter=resolved_emit,
        )
        emit_errors = [
            f
            for f in list(emit_adapter_findings) + list(emit_check_findings)
            if f.severity in (Severity.ERROR, Severity.FATAL)
        ]
        if emit_errors:
            raise OutputInvalid(
                f"Emitted {resolved_emit} artifact failed reload revalidation "
                f"with {len(emit_errors)} error finding(s): "
                f"{[f.code for f in emit_errors]}"
            )
        if reparse_identity_hashes(emit_events) != reparse_identity_hashes(parsed_output_events):
            raise OutputInvalid(
                "Emitted vendor artifact does not round-trip to the repaired "
                "event set (content identity mismatch after adapter reload)"
            )
    else:
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

    # adapter_id describes the format of the EMITTED artifact (the output that
    # output_fingerprint binds): 'canonical' for canonical emit, the vendor
    # format id for write-back emit.
    adapter_id = resolved_emit if resolved_emit in ADAPTER_VERSIONS else "canonical"
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
    if projection_summary is not None:
        record_counts["source_lines"] = (
            projection_summary.retained_lines + projection_summary.dropped_lines
        )
        record_counts["output_lines"] = projection_summary.retained_lines
        record_counts["dropped_lines"] = projection_summary.dropped_lines
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
    # Cooperative cancellation boundary: raising here — before any write —
    # leaves nothing to clean up (DW-T-13).
    check_token(cancel_token)
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

    m_temp: Path | None = None
    manifest_linked = False
    output_replaced = False

    try:
        try:
            # 1. Write manifest temp file
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

            # Exclusive-create manifest receipt (O_EXCL via os.link)
            try:
                os.link(m_temp, manifest_p)
                manifest_linked = True
            except FileExistsError as err:
                raise ManifestCollision(
                    "Repair manifest destination already exists "
                    f"(refusing to overwrite receipt): {manifest_p}"
                ) from err
            finally:
                if m_temp is not None and m_temp.exists():
                    try:
                        m_temp.unlink()
                    except OSError:
                        pass
                m_temp = None

            # Mid-publish fault-injection hook (e.g. crash simulation)
            active_mid_publish = mid_publish_hook or _ATOMIC_TEST_HOOKS.get("mid_publish")
            if active_mid_publish is not None:
                active_mid_publish()

            # 2. Atomic write of output via atomic_write_bytes (P2-01)
            active_pre_write = pre_write_hook or _ATOMIC_TEST_HOOKS.get("pre_write")
            active_pre_rename = pre_rename_hook or _ATOMIC_TEST_HOOKS.get("pre_rename")
            atomic_write_bytes(
                output_p,
                output_bytes,
                refuse_paths=[source_p],
                prefix=".sesslint-tmp-out-",
                pre_write_hook=active_pre_write,
                pre_rename_hook=active_pre_rename,
                sync_dir=True,
            )
            output_replaced = True

            active_post_publish = post_publish_hook or _ATOMIC_TEST_HOOKS.get("post_publish")
            if active_post_publish is not None:
                active_post_publish()

        except AtomicWriteError as err:
            cause = err.__cause__
            if isinstance(cause, OSError):
                if cause.errno == errno.EXDEV:
                    raise OutputInvalid(
                        f"Cross-device link error during atomic rename: {cause}"
                    ) from cause
                if cause.errno == errno.ENOSPC:
                    raise OutputInvalid(f"Disk full during repair write: {cause}") from cause
                if isinstance(cause, PermissionError) or cause.errno in (errno.EACCES, errno.EPERM):
                    raise OutputInvalid(
                        f"Permission denied writing to destination: {cause}"
                    ) from cause
            raise OutputInvalid(f"Atomic write to destination failed: {err}") from err
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
