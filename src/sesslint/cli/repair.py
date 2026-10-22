"""The ``sesslint repair`` subcommand."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Literal

from sesslint.cli._common import _handle_internal_error, _read_stdin_bytes
from sesslint.cli._options import (
    _add_seal_args,
    add_adapter_option,
    add_config_option,
    add_policy_option,
    add_profile_option,
    add_progress_json_option,
    cli_path,
)
from sesslint.cli._seal import _maybe_append_seal
from sesslint.errors import SesslintError

if TYPE_CHECKING:
    from sesslint.cli._context import CliContext

NAME: Final[str] = "repair"


def configure(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> argparse.ArgumentParser:
    sub = subparsers.add_parser(
        "repair",
        help=(
            "[writes: output file and manifest, lossy under --policy salvage] "
            "Safely repair a session file."
        ),
        description=(
            "[writes: output file and manifest, lossy under --policy salvage] "
            "Safely repair a session file with atomic execution."
        ),
    )
    sub.add_argument(
        "path",
        type=cli_path,
        nargs="*",
        default=None,
        help="Path(s) to source session file(s) or directories. Directories "
        "and multiple paths batch-repair into --output-dir (mirroring input "
        "structure). '-' reads the source from stdin (max 100 MB; still "
        "requires --output unless --dry-run).",
    )
    sub.add_argument(
        "-o",
        "--output",
        type=cli_path,
        default=None,
        dest="output",
        help="Path to output repaired session file",
    )
    sub.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Plan-only mode; do not write any files",
    )
    sub.add_argument(
        "--preview",
        action="store_true",
        default=False,
        help=(
            "Render the structural repair preview (sesslint.preview/v1): "
            "content-free delta rows per plan step, then exit without "
            "writing. Incompatible with --output/--plan-out/--apply-plan/"
            "batch modes."
        ),
    )
    add_policy_option(sub)
    add_adapter_option(sub)
    sub.add_argument(
        "--emit",
        choices=["auto", "canonical", "vendor"],
        default="auto",
        help=(
            "Output artifact format. 'auto' (default) emits the input's own "
            "format: vendor input produces a drop-only line-verbatim "
            "write-back; 'canonical' always emits the canonical session stream."
        ),
    )
    add_profile_option(sub)
    sub.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output manifest or plan in JSON format",
    )
    add_progress_json_option(sub)
    sub.add_argument(
        "--plan",
        "--apply-plan",
        type=cli_path,
        default=None,
        dest="plan",
        help=(
            "Apply a previously exported plan JSON (sesslint.plan/v1) without "
            "re-planning. The plan is authoritative: --policy/--profile/--adapter "
            "overrides are refused, and execution still re-validates the plan "
            "fingerprint and source binding."
        ),
    )
    sub.add_argument(
        "--plan-out",
        type=cli_path,
        default=None,
        dest="plan_out",
        help=(
            "Export the computed repair plan (sesslint.plan/v1) to PATH for "
            "review or later --apply-plan. Plan-only when --output is absent; "
            "with --output the exported plan is executed in the same run. "
            ""
        ),
    )
    sub.add_argument(
        "--from-scan",
        type=cli_path,
        default=None,
        metavar="REPORT.json",
        help=(
            "Batch-repair files listed in a sesslint scan JSON report; only "
            "'~/'-minimized and absolute paths resolve — '.._<hash>' entries "
            "are reported skipped."
        ),
    )
    sub.add_argument(
        "--output-dir",
        type=cli_path,
        default=None,
        metavar="DIR",
        help="Output root for batch repair modes (mirrors input structure).",
    )
    sub.add_argument(
        "--manifest-dir",
        type=cli_path,
        default=None,
        metavar="DIR",
        help=(
            "Manifest root for batch modes; manifests are named "
            "<sha8-of-source-path>.manifest.json. Default: adjacent to each "
            "output."
        ),
    )
    sub.add_argument(
        "--acknowledge-side-effects",
        action="store_true",
        default=False,
        help="Acknowledge tool side-effects for salvage policy",
    )
    sub.add_argument(
        "--include-content",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Embed raw transcript content in manifests (warning: emits raw sensitive data)",
    )
    add_config_option(sub)
    _add_seal_args(sub)
    return sub


def run(ctx: CliContext, args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    # Plan-authoritative conflicts (repair-engine T-01): applying an
    # exported plan forbids execution-shaping CLI overrides — env and
    # config-file values are folded silently, never refused (T-01).
    progress_cb = ctx.progress_callback(args)
    if getattr(args, "plan", None) is not None:
        _plan_overrides = [
            f"--{name}"
            for name in ("policy", "profile", "adapter")
            if ctx.settings.get(name) is not None and ctx.settings[name].source == "cli"
        ]
        if _plan_overrides:
            ctx.error(
                "Error: --apply-plan is authoritative for the exported plan; "
                "remove override(s): " + ", ".join(_plan_overrides)
            )
            return 2
        if getattr(args, "plan_out", None) is not None:
            ctx.error(
                "Error: --plan-out cannot be combined with --apply-plan "
                "(no plan is recomputed to export)."
            )
            return 2

    src_paths: list[Path] = list(getattr(args, "path", None) or [])
    # Batch mode: multiple positionals, any directory positional, or
    # --from-scan (repair-engine T-02). A lone '-' is the stdin single-file
    # path, never batch.
    _path_targets = [p for p in src_paths if str(p) != "-"]
    _is_batch = (
        getattr(args, "from_scan", None) is not None
        or len(_path_targets) > 1
        or any(p.is_dir() for p in _path_targets)
    )

    # --preview conflicts (repair-engine T-03): preview writes nothing, so
    # every write-implying or foreign-plan flag is a usage error.
    if getattr(args, "preview", False):
        _preview_conflicts: list[str] = []
        if args.output is not None:
            _preview_conflicts.append("--output")
        if getattr(args, "plan", None) is not None:
            _preview_conflicts.append("--apply-plan/--plan")
        if getattr(args, "plan_out", None) is not None:
            _preview_conflicts.append("--plan-out")
        if _is_batch:
            _preview_conflicts.append("batch modes")
        if getattr(args, "emit", "auto") != "auto":
            _preview_conflicts.append("--emit")
        if _preview_conflicts:
            ctx.error(
                "Error: --preview writes nothing; incompatible with "
                + ", ".join(_preview_conflicts)
            )
            return 2

    # Batch repair (repair-engine T-02): directories and multi-path
    # positionals plus --from-scan drive per-file plan eligibility under a
    # shared output root. Validated before the single-file flow (batch
    # never stages stdin and uses --output-dir, not --output).
    if _is_batch:
        if any(str(p) == "-" for p in src_paths):
            ctx.error("Error: '-' (stdin) cannot be combined with other repair inputs.")
            return 2
        if getattr(args, "seal", None) is not None:
            ctx.error(
                "Error: --seal applies to single-file repair only "
                "(batch modes produce no single subject artifact)."
            )
            return 2
        if args.output is not None:
            ctx.error(
                "Error: --output applies to single-file repair; batch modes use --output-dir."
            )
            return 2
        if getattr(args, "plan", None) is not None or getattr(args, "plan_out", None) is not None:
            ctx.error(
                "Error: --apply-plan/--plan-out are single-file options; "
                "batch computes plans internally per file."
            )
            return 2
        if getattr(args, "output_dir", None) is None:
            ctx.error("Error: batch repair requires --output-dir.")
            return 2

        from sesslint.batch import (
            BatchRepairReport,
            BatchRow,
            iter_batch_files,
            repair_many,
            resolve_scan_report_files,
        )
        from sesslint.scan import DEFAULT_MAX_FILES

        batch_files: list[Path] = []
        unresolvable: list[str] = []
        common_root: Path | None = None
        dir_paths = [p for p in _path_targets if p.is_dir()]
        if len(_path_targets) == 1 and dir_paths:
            common_root = dir_paths[0]
        for p in _path_targets:
            if p.is_dir():
                walked, _special = iter_batch_files([p], max_files=DEFAULT_MAX_FILES)
                batch_files.extend(walked)
            else:
                batch_files.append(p)
        if getattr(args, "from_scan", None) is not None:
            try:
                scan_files, unresolvable = resolve_scan_report_files(args.from_scan)
            except (OSError, ValueError, KeyError) as err:
                ctx.error(f"Error: cannot read scan report: {err}")
                return 2
            batch_files.extend(scan_files)

        batch_policy: Literal["conservative", "salvage"] = (
            "salvage" if getattr(args, "policy", "conservative") == "salvage" else "conservative"
        )
        batch_profile = getattr(args, "profile", "neutral")
        batch_format = getattr(args, "adapter", "auto")

        from sesslint.profiles.profile import get_profile as _get_profile

        try:
            _get_profile(batch_profile)
        except (KeyError, ValueError) as err:
            err_msg = err.args[0] if err.args else str(err)
            ctx.error(f"Error: {err_msg}")
            return 2

        try:
            batch_report = repair_many(
                batch_files,
                output_dir=args.output_dir,
                manifest_dir=getattr(args, "manifest_dir", None),
                common_root=common_root,
                policy=batch_policy,
                format=batch_format if batch_format != "auto" else None,
                profile=batch_profile,
                acknowledge_side_effects=getattr(args, "acknowledge_side_effects", False),
                emit=getattr(args, "emit", "auto"),
                dry_run=bool(args.dry_run),
                progress_cb=progress_cb,
            )
        except Exception as err:
            return _handle_internal_error(err, args)

        if unresolvable:
            merged = list(batch_report.rows) + [
                BatchRow(path=d, outcome="skipped", reason="unresolvable-path")
                for d in sorted(unresolvable)
            ]
            batch_report = BatchRepairReport(rows=tuple(sorted(merged, key=lambda r: r.path)))

        if getattr(args, "json", False):
            print(batch_report.to_json())
        else:
            print(batch_report.render_human())
        return 0 if batch_report.refused == 0 and batch_report.skipped == 0 else 1

    if not src_paths:
        ctx.error(
            "Error: repair requires a source path, or batch inputs "
            "(multiple paths, directories, or --from-scan with --output-dir)."
        )
        return 2

    # --plan-out without --output implies plan-only export mode.
    plan_only = bool(args.dry_run) or (
        getattr(args, "plan_out", None) is not None and args.output is None
    )
    if getattr(args, "seal", None) is not None and (plan_only or getattr(args, "preview", False)):
        ctx.error(
            "Error: --seal requires a completed repair — incompatible with "
            "--dry-run, plan-only export, or --preview (nothing is produced)."
        )
        return 2
    if not plan_only and not getattr(args, "preview", False) and args.output is None:
        ctx.error(
            "Error: --output is required unless --dry-run, --plan-out, or --preview is specified."
        )
        return 2

    # `-` reads the source session from stdin (ux T-06): the one-shot
    # buffer is staged through a private temp file so the full 8-step
    # executor protocol (pre/post hashing, atomic publish, write-back
    # projection) applies unchanged. The staged file is deleted before
    # the command returns.
    stdin_tmp: Any = None
    src_path: Path = src_paths[0]
    # Salvage commands in blocked-finding detail name the source as the
    # operator typed it ('-' for stdin), not the private staging copy.
    from sesslint._hints import STDIN_LABEL, hint_options
    from sesslint.report import hint_path

    hint_src = STDIN_LABEL if str(src_path) == "-" else hint_path(src_path)
    if str(src_path) == "-":
        import tempfile

        from sesslint.io import DEFAULT_MAX_FILE_BYTES

        stdin_data = _read_stdin_bytes()
        if len(stdin_data) > DEFAULT_MAX_FILE_BYTES:
            ctx.error(
                f"Error: stdin exceeds maximum supported size ({DEFAULT_MAX_FILE_BYTES} bytes)."
            )
            return 2
        stdin_tmp = tempfile.TemporaryDirectory(prefix="sesslint-stdin-")
        src_path = Path(stdin_tmp.name) / "stdin.jsonl"
        src_path.write_bytes(stdin_data)

    if src_path.is_dir():
        ctx.error(f"Error: repair operates on a single session file, not a directory: {src_path}")
        return 2
    if not src_path.is_file():
        ctx.error(f"Error: Source file not found: {src_path}")
        return 2

    policy_opt: Literal["conservative", "salvage"] = (
        "salvage" if getattr(args, "policy", "conservative") == "salvage" else "conservative"
    )
    profile_opt = getattr(args, "profile", "neutral")
    ack_side_effects = getattr(args, "acknowledge_side_effects", False)
    format_opt = getattr(args, "adapter", "auto")
    hint_opts = hint_options(format_opt, profile_opt)

    from sesslint.adapters.detect import VALID_FORMAT_OPTIONS
    from sesslint.profiles.profile import get_profile

    if format_opt not in VALID_FORMAT_OPTIONS:
        ctx.error(f"Error: Unsupported format option: {format_opt}")
        return 2

    # Vendor formats are supported via drop-only line-verbatim write-back
    # (emit='auto'|'vendor'); emit='canonical' exports a canonical repaired
    # stream. Unsafe projections refuse via VendorProjectionRefused (R1-R6).

    try:
        get_profile(profile_opt)
    except (KeyError, ValueError) as err:
        err_msg = err.args[0] if err.args else str(err)
        ctx.error(f"Error: {err_msg}")
        return 2

    if getattr(args, "preview", False):
        # Structural preview (repair T-03): detection+planning rendered as
        # content-free deltas; blocked findings still surface. No writes.
        from sesslint.preview import repair_preview

        try:
            preview_doc = repair_preview(
                src_path,
                format=format_opt if format_opt != "auto" else None,
                policy=policy_opt,
                profile=profile_opt,
                acknowledge_side_effects=ack_side_effects,
            )
        except (FileNotFoundError, OSError) as err:
            ctx.error(f"File error: {err}")
            return 2
        except (ValueError, KeyError) as err:
            err_msg = err.args[0] if err.args else str(err)
            ctx.error(f"Error: {err_msg}")
            return 2
        except SesslintError as err:
            ctx.error(f"Error: {err}")
            return 2
        except Exception as err:
            return _handle_internal_error(err, args)

        if getattr(args, "json", False):
            print(preview_doc.to_json())
        else:
            print(preview_doc.render_human())
        return 1 if preview_doc.refused else 0

    from sesslint import api
    from sesslint.repair import (
        Abstained,
        OutputInvalid,
        PlanSourceMismatch,
        PlanTampered,
        PolicyMismatch,
        RepairRefused,
        VendorRepairRefused,
    )
    from sesslint.report import dump_manifest

    try:
        if getattr(args, "plan_out", None) is not None:
            # Export-first composition (repair T-01): compute the plan,
            # write the sesslint.plan/v1 document, then either stop
            # (plan-only) or apply the just-exported plan.
            plan_obj = api.plan_repair(
                src_path,
                policy=policy_opt,
                format=format_opt if format_opt != "auto" else None,
                profile=profile_opt,
                acknowledge_side_effects=ack_side_effects,
            )
            try:
                from sesslint.atomic import atomic_write_text

                # Never let the plan document replace the session it
                # describes, nor the repaired output about to be written (B18).
                plan_refuse: list[Path] = [src_path]
                if args.output is not None:
                    plan_refuse.append(Path(args.output))
                atomic_write_text(
                    Path(args.plan_out),
                    json.dumps(plan_obj.to_dict(), indent=2, sort_keys=True) + chr(10),
                    refuse_paths=plan_refuse,
                    overwrite=False,
                )
            except OSError as err:
                ctx.error(f"Error writing plan to {args.plan_out}: {err}")
                return 2
            if plan_only:
                if not getattr(args, "json", False):
                    print(f"Plan written to: {args.plan_out}")
                plan_obj, manifest = plan_obj, None
            else:
                plan_obj, manifest = api.apply_plan(
                    src_path,
                    plan_obj,
                    output_path=args.output,
                    acknowledge_side_effects=ack_side_effects,
                    emit=getattr(args, "emit", "auto"),
                    progress_cb=progress_cb,
                )
        elif getattr(args, "plan", None) is not None:
            # Plan-authoritative apply: policy/profile derive from the
            # plan document; executor re-validates all bindings.
            plan_obj, manifest = api.apply_plan(
                src_path,
                args.plan,
                output_path=args.output,
                acknowledge_side_effects=ack_side_effects,
                emit=getattr(args, "emit", "auto"),
                dry_run=plan_only,
                progress_cb=progress_cb,
            )
        else:
            plan_obj, manifest = api.repair(
                source_path=src_path,
                output_path=args.output,
                policy=policy_opt,
                format=format_opt if format_opt != "auto" else None,
                profile=profile_opt,
                dry_run=plan_only,
                acknowledge_side_effects=ack_side_effects,
                emit=getattr(args, "emit", "auto"),
                progress_cb=progress_cb,
            )

        if plan_only:
            if getattr(args, "json", False):
                print(json.dumps(plan_obj.to_dict(), indent=2, sort_keys=True))
            else:
                print(f"Plan fingerprint: {plan_obj.fingerprint}")
                print(f"Policy: {plan_obj.policy}")
                print(f"Proposed steps: {len(plan_obj.steps)}")
                print(f"Blocked findings: {len(plan_obj.blocked)}")
                for blocked in plan_obj.blocked:
                    print(
                        f"  [{blocked.code}] {blocked.describe(path=hint_src, options=hint_opts)}"
                    )
            return 0

        if manifest is not None:
            if getattr(args, "json", False):
                print(dump_manifest(manifest))
            else:
                print(f"Repair successful. Output: {args.output}")
                print(f"Manifest written to: {args.output}.manifest.json")
                print(f"Output fingerprint: {manifest.output_fingerprint}")
                print(f"Idempotency key: {manifest.idempotency_key}")
                if manifest.declared_loss:
                    ctx.error(
                        "Declared loss: "
                        + ", ".join(manifest.declared_loss)
                        + " (salvage repair — see manifest for detail)"
                    )
            if manifest.adapter_id == "canonical":
                # A canonical artifact emitted from a vendor source cannot
                # be dropped back into the vendor's session store.
                try:
                    from sesslint.adapters.detect import detect_format
                    from sesslint.adapters.load import is_vendor_format

                    _src_fmt = detect_format(src_path).format
                except Exception:
                    _src_fmt = None
                if is_vendor_format(_src_fmt):
                    ctx.info(
                        f"Note: output is canonical sesslint format, not "
                        f"{_src_fmt}; it cannot be placed back into the "
                        "vendor session store."
                    )
        if getattr(args, "seal", None) is not None and manifest is None:
            # The plan-only paths returned earlier; reaching here without
            # a manifest means no outcome artifact exists to seal.
            ctx.error("Error: --seal requires a completed repair with a manifest.")
            return 2
        if manifest is not None:
            seal_rc = _maybe_append_seal(
                ctx,
                args,
                tool="repair",
                artifact_sha256=manifest.output_fingerprint,
                artifact_bytes=None,
                artifact_path=args.output,
                verdict="repaired",
                codes={},
                report_bytes=dump_manifest(manifest).encode("utf-8"),
            )
            if seal_rc is not None:
                return seal_rc
        return 0
    except VendorRepairRefused as err:
        # Vendor-format refusal (auto-detected inside api.repair) is a usage
        # error, preserving the exit-2 contract previously produced by the
        # removed CLI pre-sniff.
        ctx.error(f"Error: {err}")
        return 2
    except (
        PlanTampered,
        Abstained,
        PolicyMismatch,
        OutputInvalid,
        RepairRefused,
        PlanSourceMismatch,
    ) as err:
        if getattr(args, "json", False):
            err_code = getattr(err, "code", type(err).__name__)
            print(
                json.dumps(
                    {
                        "error": {
                            "code": err_code,
                            "kind": type(err).__name__,
                            "message": str(err),
                        },
                        "ok": False,
                    },
                    sort_keys=True,
                )
            )
        else:
            err_code = getattr(err, "code", type(err).__name__)
            ctx.error(f"Repair refused [{err_code}]: {err}")
            # A plan with no step names every blocked finding with its
            # documented refusal and any salvage command (SL101 doc contract).
            for blocked in getattr(err, "blocked", ()):
                ctx.error(
                    f"  [{blocked.code}] {blocked.describe(path=hint_src, options=hint_opts)}"
                )
        return 1
    except (ValueError, KeyError) as err:
        # Invalid or undetectable input is a usage error, not an internal
        # fault (e.g. source parses as neither canonical nor vendor).
        err_msg = err.args[0] if err.args else str(err)
        ctx.error(f"Error: {err_msg}")
        return 2
    except FileNotFoundError as err:
        ctx.error(f"File error: {err}")
        return 2
    except SesslintError as err:
        # Schema/adapter failures on the source artifact are input
        # problems, not internal faults.
        ctx.error(f"Error: {err}")
        return 2
    except Exception as err:
        return _handle_internal_error(err, args)
    finally:
        finish = getattr(progress_cb, "finish", None)
        if callable(finish):
            finish()
        if stdin_tmp is not None:
            stdin_tmp.cleanup()
