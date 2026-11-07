//! Shared detector-execution runner for canonical event streams (DW-T-07).
//!
//! Port of `src/sesslint/checks/runner.py` lines 1–37
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! Single authoritative implementation of "run all profile-enabled detectors
//! over canonical events", consumed by the check path (`api.check_file`), the
//! repair executor's revalidation step, and the independent `verify` engine
//! alike.
//!
//! Guarantees:
//!
//! * Pure and side-effect-free: canonical events + profile in, findings (and
//!   optional Coverage) out. No file I/O, no mutation.
//! * Deterministic: detector order, finding order, and enabled-rule filtering
//!   are fixed by the profile and the pinned family list (FR-093/FR-094).
//!
//! Lines 1–37 are the module docstring and imports. `run_all_checks` starts
//! at line 40 and is not defined in this module. [`IMPORT_PATHS`] records the
//! pin import paths in source order. This module does not call the detectors.
//! It does not construct `Coverage` or a finding. Nothing here returns findings.

/// Import paths from pin `runner.py` lines 19–37, in source order.
///
/// A comma import stays left to right: `SIZE_MIN_RECORDS` then
/// `check_size_anomaly`, `Profile` then `get_profile`, `Coverage` then
/// `CoverageSkip`. These strings are not calls.
pub const IMPORT_PATHS: [&str; 22] = [
    "sesslint.canonical.SessionEvent",
    "sesslint.checks.accounting.check_accounting",
    "sesslint.checks.checkpoint.check_checkpoint",
    "sesslint.checks.compaction_snapshot.check_compaction_snapshot",
    "sesslint.checks.context_pressure.check_context_pressure",
    "sesslint.checks.durable_prefix.check_durable_prefix",
    "sesslint.checks.foreign_shape.check_foreign_shape",
    "sesslint.checks.graph.check_graph",
    "sesslint.checks.identity.check_identities",
    "sesslint.checks.ordering.check_ordering",
    "sesslint.checks.size.SIZE_MIN_RECORDS",
    "sesslint.checks.size.check_size_anomaly",
    "sesslint.checks.tool_pairing_1.check_tool_pairing_1",
    "sesslint.checks.tool_pairing_2.check_tool_pairing_2",
    "sesslint.checks.writers.check_writers",
    "sesslint.context.CheckContext",
    "sesslint.finding.Finding",
    "sesslint.profiles.builtin.NEUTRAL_PROFILE",
    "sesslint.profiles.profile.Profile",
    "sesslint.profiles.profile.get_profile",
    "sesslint.report.Coverage",
    "sesslint.report.CoverageSkip",
];

#[cfg(test)]
mod tests {
    #[test]
    fn import_paths_match_the_pin_in_order() {
        assert_eq!(
            super::IMPORT_PATHS,
            [
                "sesslint.canonical.SessionEvent",
                "sesslint.checks.accounting.check_accounting",
                "sesslint.checks.checkpoint.check_checkpoint",
                "sesslint.checks.compaction_snapshot.check_compaction_snapshot",
                "sesslint.checks.context_pressure.check_context_pressure",
                "sesslint.checks.durable_prefix.check_durable_prefix",
                "sesslint.checks.foreign_shape.check_foreign_shape",
                "sesslint.checks.graph.check_graph",
                "sesslint.checks.identity.check_identities",
                "sesslint.checks.ordering.check_ordering",
                "sesslint.checks.size.SIZE_MIN_RECORDS",
                "sesslint.checks.size.check_size_anomaly",
                "sesslint.checks.tool_pairing_1.check_tool_pairing_1",
                "sesslint.checks.tool_pairing_2.check_tool_pairing_2",
                "sesslint.checks.writers.check_writers",
                "sesslint.context.CheckContext",
                "sesslint.finding.Finding",
                "sesslint.profiles.builtin.NEUTRAL_PROFILE",
                "sesslint.profiles.profile.Profile",
                "sesslint.profiles.profile.get_profile",
                "sesslint.report.Coverage",
                "sesslint.report.CoverageSkip",
            ]
        );
    }
}
