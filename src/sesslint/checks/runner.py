"""Shared detector-execution runner for canonical event streams (DW-T-07).

Single authoritative implementation of "run all profile-enabled detectors over
canonical events", consumed by the check path (`api.check_file`), the repair
executor's revalidation step, and the independent `verify` engine alike.

Guarantees:
- Pure and side-effect-free: canonical events + profile in, findings (and
  optional Coverage) out. No file I/O, no mutation.
- Deterministic: detector order, finding order, and enabled-rule filtering are
  fixed by the profile and the pinned family list (FR-093/FR-094).
"""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from typing import Any

from sesslint.canonical import SessionEvent
from sesslint.checks.accounting import check_accounting
from sesslint.checks.checkpoint import check_checkpoint
from sesslint.checks.graph import check_graph
from sesslint.checks.identity import check_identities
from sesslint.checks.ordering import check_ordering
from sesslint.checks.size import SIZE_MIN_RECORDS, check_size_anomaly
from sesslint.checks.tool_pairing_1 import check_tool_pairing_1
from sesslint.checks.tool_pairing_2 import check_tool_pairing_2
from sesslint.context import CheckContext
from sesslint.finding import Finding
from sesslint.profiles.builtin import NEUTRAL_PROFILE
from sesslint.profiles.profile import Profile, get_profile
from sesslint.report import Coverage, CoverageSkip


def run_all_checks(
    events: Sequence[SessionEvent],
    *,
    profile: Profile | str | None = None,
    source_path: str = "<repaired>",
    context: CheckContext | None = None,
    adapter: str | None = None,
    adapter_skips: Sequence[CoverageSkip] = (),
    adapter_performed: Sequence[str] = (),
    deselected_rules: Collection[str] = (),
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
    deselected = set(deselected_rules)
    findings: list[Finding] = []

    performed_checks: set[str] = set()
    skipped_checks: list[CoverageSkip] = list(adapter_skips)
    already_skipped_checks: set[str] = {s.check for s in skipped_checks}

    def _gate_skip(check: str, detail: str) -> CoverageSkip:
        """Coverage skip for a gated rule, distinguishing user deselection."""
        if check in deselected:
            return CoverageSkip(
                check=check,
                reason="deselected",
                detail="rule deselected via --select/--ignore",
            )
        return CoverageSkip(check=check, reason="profile-gated", detail=detail)

    # Ingest adapter checks
    if adapter_performed:
        for ap in adapter_performed:
            if ap in enabled and ap not in already_skipped_checks:
                performed_checks.add(ap)
            elif ap not in enabled and ap not in already_skipped_checks:
                skipped_checks.append(_gate_skip(ap, "rule disabled by profile"))
                already_skipped_checks.add(ap)
    else:
        adapter_rules = ("SL001", "SL002", "SL301", "SL302")
        for ar in adapter_rules:
            if ar not in already_skipped_checks:
                if ar in enabled:
                    performed_checks.add(ar)
                else:
                    skipped_checks.append(_gate_skip(ar, "rule disabled by profile"))
                    already_skipped_checks.add(ar)

    is_empty_input = len(events) == 0
    has_version_abort = any(s.reason == "version-gated" for s in adapter_skips)
    has_cap_abort = any(s.reason == "cap-exceeded" for s in adapter_skips)

    families: list[tuple[str, tuple[str, ...]]] = [
        ("identity", ("SL003",)),
        ("graph", ("SL004", "SL005", "SL006", "SL007")),
        ("ordering", ("SL008",)),
        ("tool_pairing_1", ("SL101", "SL102", "SL103", "SL104")),
        ("tool_pairing_2", ("SL105", "SL106", "SL107", "SL108")),
        ("checkpoint", ("SL201", "SL202", "SL203", "SL205")),
        ("accounting", ("SL204",)),
        ("size", ("SL011",)),
    ]

    for fam_name, fam_rules in families:
        fam_enabled_rules = [r for r in fam_rules if r in enabled]
        if not fam_enabled_rules:
            if fam_name not in already_skipped_checks:
                fam_skip = (
                    CoverageSkip(
                        check=fam_name,
                        reason="deselected",
                        detail="family deselected via --select/--ignore",
                    )
                    if all(r in deselected for r in fam_rules)
                    else CoverageSkip(
                        check=fam_name,
                        reason="profile-gated",
                        detail="family disabled by profile",
                    )
                )
                skipped_checks.append(fam_skip)
                already_skipped_checks.add(fam_name)
            for r in fam_rules:
                if r not in already_skipped_checks:
                    skipped_checks.append(_gate_skip(r, "rule disabled by profile"))
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
                        skipped_checks.append(_gate_skip(r, "rule disabled by profile"))
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
                    skipped_checks.append(_gate_skip(r, "rule disabled by profile"))
                    already_skipped_checks.add(r)

    if not is_empty_input and not has_version_abort and not has_cap_abort:
        if "SL003" in enabled:
            findings.extend(check_identities(events, source_path=source_path, context=context))

        graph_rules = {"SL004", "SL005", "SL006", "SL007"}
        if graph_rules & enabled:
            findings.extend(check_graph(events, source_path=source_path, context=context))

        if "SL008" in enabled:
            findings.extend(check_ordering(events, source_path=source_path, context=context))

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

        cp_rules = {"SL201", "SL202", "SL203", "SL205"}
        if cp_rules & enabled:
            findings.extend(
                check_checkpoint(
                    events,
                    source_path=source_path,
                    checkpoint_sensitivity=resolved_profile.checkpoint_sensitivity,
                    context=context,
                )
            )

        if "SL204" in enabled:
            findings.extend(check_accounting(events, source_path=source_path, context=context))

        if "SL011" in enabled:
            if len(events) < SIZE_MIN_RECORDS:
                # Size distribution is meaningless below the minimum —
                # the family ran but could not evaluate (FR-047 honesty).
                performed_checks.discard("size")
                performed_checks.discard("SL011")
                skipped_checks.append(
                    CoverageSkip(
                        check="size",
                        reason="adapter-not-applicable",
                        detail="fewer than 8 records — size distribution not meaningful",
                    )
                )
                skipped_checks.append(
                    CoverageSkip(
                        check="SL011",
                        reason="adapter-not-applicable",
                        detail="fewer than 8 records — size distribution not meaningful",
                    )
                )
            else:
                findings.extend(
                    check_size_anomaly(events, source_path=source_path, context=context)
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


__all__ = [
    "run_all_checks",
]
