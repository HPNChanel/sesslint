//! Shared detector-execution runner for canonical event streams (DW-T-07).
//!
//! Port of `src/sesslint/checks/runner.py` lines 1–37 and 40–493
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! Single authoritative implementation of "run all profile-enabled detectors
//! over canonical events", consumed by the check path (`api.check_file`), the
//! repair executor's revalidation step, and the independent `verify` engine
//! alike.
//!
//! Guarantees:
//!
//! * Pure and side-effect-free: canonical events + profile in, findings out.
//!   No file I/O, no mutation, no wall clock.
//! * Deterministic: detector order, finding order, and enabled-rule filtering
//!   are fixed by the profile and the pinned family list (FR-093/FR-094).
//! * [`run_all_checks`] does not construct `sesslint.report.Coverage`. When
//!   `return_coverage` is true the error [`COVERAGE_UNAVAILABLE`] is returned
//!   after the detector calls. Detector errors propagate before that stop.
//!
//! [`IMPORT_PATHS`] records the pin import paths in source order. This module
//! calls the detector functions named there. It does not reimplement them.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use serde_json::{Number, Value};

use model::events::EventValue;
use model::finding::Finding;
use model::version::{ADAPTER_VERSIONS, PROFILE_VERSIONS};

use crate::accounting::check_accounting;
use crate::builtin::NEUTRAL_PROFILE;
use crate::checkpoint::check_checkpoint;
use crate::compaction_snapshot::check_compaction_snapshot;
use crate::context::{CheckContext, SourceMetadataOverride};
use crate::context_pressure::check_context_pressure;
use crate::durable_prefix::check_durable_prefix;
use crate::foreign_shape::check_foreign_shape;
use crate::graph::check_graph;
use crate::identity::check_identities;
use crate::ordering::check_ordering;
use crate::profile::{get_profile, Profile};
use crate::size::{check_size_anomaly, SIZE_MIN_RECORDS};
use crate::tool_pairing_1::check_tool_pairing_1;
use crate::tool_pairing_2::{check_tool_pairing_2, RuleSeverityProfile};
use crate::writers::check_writers;

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

/// `sesslint.report.Coverage` is not a dependency of this crate.
pub const COVERAGE_UNAVAILABLE: &str = "sesslint.report.Coverage is not available";

const FAMILIES: &[(&str, &[&str])] = &[
    ("identity", &["SL003"]),
    ("graph", &["SL004", "SL005", "SL006", "SL007"]),
    ("ordering", &["SL008"]),
    ("writers", &["SL010"]),
    ("tool_pairing_1", &["SL101", "SL102", "SL103", "SL104"]),
    ("tool_pairing_2", &["SL105", "SL106", "SL107", "SL108"]),
    (
        "checkpoint",
        &["SL201", "SL202", "SL203", "SL205", "SL206", "SL208"],
    ),
    ("accounting", &["SL204", "SL207"]),
    ("size", &["SL011"]),
    ("shape", &["SL305"]),
];

const CHECKPOINT_CALL_RULES: &[&str] = &["SL201", "SL202", "SL203", "SL205"];
const GRAPH_RULES: &[&str] = &["SL004", "SL005", "SL006", "SL007"];
const PAIRING_1_RULES: &[&str] = &["SL101", "SL102", "SL103", "SL104"];
const PAIRING_2_RULES: &[&str] = &["SL105", "SL106", "SL107", "SL108"];
const ADAPTER_RULES: &[&str] = &["SL001", "SL002", "SL009", "SL301", "SL302"];

const NO_WRITER_MARKERS: &str = "adapter emits no writer markers";
const DURABLE_PREFIX_ONLY: &str = "durable-prefix boundary applies to codex-rollout streams only";
const SNAPSHOT_ONLY: &str = "compaction snapshot markers apply to codex-rollout streams only";
const CODEX_CHECKPOINT_ONLY: &str =
    "codex-scoped checkpoint rules apply to codex-rollout streams only";
const REPLAY_ONLY: &str = "replay-vocabulary check applies to codex-rollout streams only";
const DECLARED_WINDOW_ONLY: &str = "declared-window pressure applies to codex-rollout streams only";
const SIZE_VENDOR_NORMAL: &str = "record-size variance is vendor-normal on codex-rollout \
envelopes (bulk payload records are routine)";
const SIZE_NOT_MEANINGFUL: &str = "fewer than 8 records \u{2014} size distribution not meaningful";
const SL203_SUFFIX: &str = " exposes no checkpoint mechanism \u{2014} \
continuation after compaction is vendor-normal";
const UNKNOWN_METADATA: &str = "unknown metadata advisory applies to Claude and Codex only";
const ZERO_RECORDS: &str = "zero records in event stream";
const RULE_DISABLED: &str = "rule disabled by profile";
const FAMILY_DESELECTED: &str = "family deselected via --select/--ignore";
const FAMILY_DISABLED: &str = "family disabled by profile";
const RULE_DESELECTED: &str = "rule deselected via --select/--ignore";
const VERSION_DETAIL: &str = "unsupported format version (SL301)";
const CAP_DETAIL: &str = "stream limit cap exceeded";

/// Failure from [`run_all_checks`]. [`Display`] is the message only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerError {
    message: String,
}

impl RunnerError {
    fn coverage_unavailable() -> Self {
        Self {
            message: COVERAGE_UNAVAILABLE.to_owned(),
        }
    }

    fn from_display(error: impl fmt::Display) -> Self {
        Self {
            message: error.to_string(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for RunnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for RunnerError {}

/// Python `profile: Profile | str | None`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ProfileArg<'a> {
    /// Python `None`, resolved to [`NEUTRAL_PROFILE`].
    Absent,
    /// Python `str`, resolved by [`get_profile`].
    Name(&'a str),
    /// Python `Profile` instance.
    Profile(&'a Profile),
}

/// Python `getattr(events, "source", None)` and the mapping test.
///
/// A [`Value::Bool`] stays a bool. It is not an int.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventSource<'a> {
    /// The sequence has no `source` attribute.
    Absent,
    /// `source` is present and is not a mapping.
    NotAMapping,
    /// `source` is a mapping.
    Mapping(&'a BTreeMap<String, Value>),
}

/// One adapter skip supplied by the caller.
///
/// The pin types this as `CoverageSkip`. This crate does not construct
/// `sesslint.report.Coverage`. `version-gated` and `cap-exceeded` on `reason`
/// decide whether detector calls run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdapterSkip<'a> {
    pub check: &'a str,
    pub reason: &'a str,
    pub detail: &'a str,
}

/// Arguments of pin `run_all_checks`. Field defaults match the pin.
#[derive(Clone, Copy, Debug)]
pub struct RunAllChecksInput<'a> {
    pub events: &'a [EventValue],
    pub event_source: EventSource<'a>,
    pub profile: ProfileArg<'a>,
    pub source_path: &'a str,
    pub context: Option<&'a CheckContext>,
    pub adapter: Option<&'a str>,
    pub adapter_skips: &'a [AdapterSkip<'a>],
    pub adapter_performed: &'a [&'a str],
    pub deselected_rules: &'a [&'a str],
    pub return_coverage: bool,
}

impl<'a> RunAllChecksInput<'a> {
    /// Python defaults: neutral profile, source path `"<repaired>"`, no context.
    pub fn new(events: &'a [EventValue]) -> Self {
        Self {
            events,
            event_source: EventSource::Absent,
            profile: ProfileArg::Absent,
            source_path: "<repaired>",
            context: None,
            adapter: None,
            adapter_skips: &[],
            adapter_performed: &[],
            deselected_rules: &[],
            return_coverage: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SkipNote {
    check: String,
    reason: String,
    detail: String,
}

struct Ledger {
    performed: BTreeSet<String>,
    skipped: Vec<SkipNote>,
    already_skipped: BTreeSet<String>,
}

impl Ledger {
    fn from_adapter_skips(skips: &[AdapterSkip<'_>]) -> Self {
        let mut ledger = Self {
            performed: BTreeSet::new(),
            skipped: Vec::with_capacity(skips.len()),
            already_skipped: BTreeSet::new(),
        };
        for skip in skips {
            ledger.already_skipped.insert(skip.check.to_owned());
            ledger.push(skip.check, skip.reason, skip.detail);
        }
        ledger
    }

    fn push(&mut self, check: &str, reason: &str, detail: &str) {
        self.skipped.push(SkipNote {
            check: check.to_owned(),
            reason: reason.to_owned(),
            detail: detail.to_owned(),
        });
    }

    fn push_gate(&mut self, check: &str, detail: &str, deselected: &BTreeSet<&str>) {
        if deselected.contains(check) {
            self.push(check, "deselected", RULE_DESELECTED);
        } else {
            self.push(check, "profile-gated", detail);
        }
    }

    fn remember(&mut self, check: &str) {
        self.already_skipped.insert(check.to_owned());
    }

    fn gate_new(&mut self, check: &str, detail: &str, deselected: &BTreeSet<&str>) {
        if self.already_skipped.contains(check) {
            return;
        }
        self.push_gate(check, detail, deselected);
        self.remember(check);
    }
}

enum ResolvedContext<'a> {
    Borrowed(&'a CheckContext),
    Owned(CheckContext),
}

impl<'a> ResolvedContext<'a> {
    fn get(&self) -> &CheckContext {
        match self {
            Self::Borrowed(context) => context,
            Self::Owned(context) => context,
        }
    }
}

/// Run all active rule checks enabled by the profile over canonical events.
///
/// When `return_coverage` is false, returns the pin's filtered findings.
/// When it is true, detector calls still run first and a detector error is
/// propagated. The successful path does not construct `Coverage`; it returns
/// [`COVERAGE_UNAVAILABLE`].
///
/// # Errors
///
/// A profile name resolves through [`get_profile`] and that error is
/// propagated. Each named detector in [`IMPORT_PATHS`] is called when the pin
/// calls it. The detector's [`Display`] is preserved. An empty finding list is
/// not substituted for a detector error.
pub fn run_all_checks(input: &RunAllChecksInput<'_>) -> Result<Vec<Finding>, RunnerError> {
    let profile = resolve_profile(input.profile)?;
    let resolved = resolve_context(input, profile.as_ref());
    let context = resolved.get();
    let enabled = enabled_rules(profile.as_ref());
    let deselected = rule_set(input.deselected_rules);
    let mut ledger = Ledger::from_adapter_skips(input.adapter_skips);
    record_adapter_rules(
        &mut ledger,
        input.adapter,
        input.adapter_performed,
        &enabled,
        &deselected,
    );
    record_missing_sl306(&mut ledger, &enabled, &deselected);
    let is_empty_input = input.events.is_empty();
    let has_version_abort = has_reason(input.adapter_skips, "version-gated");
    let has_cap_abort = has_reason(input.adapter_skips, "cap-exceeded");
    record_families(
        &mut ledger,
        &enabled,
        &deselected,
        is_empty_input,
        has_version_abort,
        has_cap_abort,
    );
    let mut findings = Vec::new();
    if !is_empty_input && !has_version_abort && !has_cap_abort {
        run_detectors(
            &mut findings,
            &mut ledger,
            input,
            profile.as_ref(),
            context,
            &enabled,
        )?;
    }
    let filtered = filter_enabled(findings, &enabled);
    if input.return_coverage {
        observe_ledger(&ledger);
        return Err(RunnerError::coverage_unavailable());
    }
    Ok(filtered)
}

fn resolve_profile(profile: ProfileArg<'_>) -> Result<std::borrow::Cow<'_, Profile>, RunnerError> {
    match profile {
        ProfileArg::Absent => Ok(std::borrow::Cow::Borrowed(&NEUTRAL_PROFILE)),
        ProfileArg::Name(name) => get_profile(name)
            .map(std::borrow::Cow::Owned)
            .map_err(RunnerError::from_display),
        ProfileArg::Profile(profile) => Ok(std::borrow::Cow::Borrowed(profile)),
    }
}

fn resolve_context<'a>(input: &'a RunAllChecksInput<'a>, profile: &Profile) -> ResolvedContext<'a> {
    let metadata = owned_source(input.event_source);
    match input.context {
        None => ResolvedContext::Owned(context_from_profile(profile, input.adapter, metadata)),
        Some(context) if context.source_metadata().is_none() => match metadata {
            Some(map) => ResolvedContext::Owned(context.with_overrides(
                None,
                None,
                None,
                None,
                SourceMetadataOverride::Explicit(Some(map)),
            )),
            None => ResolvedContext::Borrowed(context),
        },
        Some(context) => ResolvedContext::Borrowed(context),
    }
}

fn owned_source(source: EventSource<'_>) -> Option<BTreeMap<String, Value>> {
    match source {
        EventSource::Mapping(map) => Some(map.clone()),
        EventSource::Absent | EventSource::NotAMapping => None,
    }
}

fn context_from_profile(
    profile: &Profile,
    adapter: Option<&str>,
    source_metadata: Option<BTreeMap<String, Value>>,
) -> CheckContext {
    let profile_version = if profile.version.is_empty() {
        registered(PROFILE_VERSIONS, &profile.name)
            .unwrap_or("unknown")
            .to_owned()
    } else {
        profile.version.clone()
    };
    let adapter_id = match adapter.map(str::trim).filter(|text| !text.is_empty()) {
        Some(text) => text.to_owned(),
        None => "unknown".to_owned(),
    };
    let adapter_version = if adapter_id == "unknown" {
        "unknown".to_owned()
    } else {
        registered(ADAPTER_VERSIONS, &adapter_id)
            .unwrap_or("unknown")
            .to_owned()
    };
    CheckContext::new(
        adapter_id,
        adapter_version,
        profile.name.as_str(),
        profile_version,
        source_metadata,
        profile.timestamp_skew_ms,
    )
}

fn registered<'a>(table: &[(&'a str, &'a str)], id: &str) -> Option<&'a str> {
    table
        .iter()
        .find_map(|(key, version)| (*key == id).then_some(*version))
}

fn enabled_rules(profile: &Profile) -> BTreeSet<&str> {
    profile.enabled_rules.iter().map(String::as_str).collect()
}

fn rule_set<'a>(rules: &'a [&'a str]) -> BTreeSet<&'a str> {
    rules.iter().copied().collect()
}

fn has_reason(skips: &[AdapterSkip<'_>], reason: &str) -> bool {
    skips.iter().any(|skip| skip.reason == reason)
}

fn record_adapter_rules(
    ledger: &mut Ledger,
    adapter: Option<&str>,
    adapter_performed: &[&str],
    enabled: &BTreeSet<&str>,
    deselected: &BTreeSet<&str>,
) {
    if !adapter_performed.is_empty() {
        record_performed_adapter(ledger, adapter_performed, enabled, deselected);
        return;
    }
    let mut rules: Vec<&str> = ADAPTER_RULES.to_vec();
    if matches!(adapter, Some("claude-code-jsonl" | "codex-rollout")) {
        rules.push("SL306");
    }
    for rule in rules {
        record_default_adapter_rule(ledger, rule, enabled, deselected);
    }
}

fn record_performed_adapter(
    ledger: &mut Ledger,
    adapter_performed: &[&str],
    enabled: &BTreeSet<&str>,
    deselected: &BTreeSet<&str>,
) {
    for rule in adapter_performed {
        if enabled.contains(*rule) && !ledger.already_skipped.contains(*rule) {
            ledger.performed.insert((*rule).to_owned());
        } else if !enabled.contains(*rule) && !ledger.already_skipped.contains(*rule) {
            ledger.push_gate(rule, RULE_DISABLED, deselected);
            ledger.remember(rule);
        }
    }
}

fn record_default_adapter_rule(
    ledger: &mut Ledger,
    rule: &str,
    enabled: &BTreeSet<&str>,
    deselected: &BTreeSet<&str>,
) {
    if ledger.already_skipped.contains(rule) {
        return;
    }
    if enabled.contains(rule) {
        ledger.performed.insert(rule.to_owned());
    } else {
        ledger.push_gate(rule, RULE_DISABLED, deselected);
        ledger.remember(rule);
    }
}

fn record_missing_sl306(
    ledger: &mut Ledger,
    enabled: &BTreeSet<&str>,
    deselected: &BTreeSet<&str>,
) {
    if ledger.performed.contains("SL306") || ledger.already_skipped.contains("SL306") {
        return;
    }
    if enabled.contains("SL306") {
        ledger.push("SL306", "adapter-not-applicable", UNKNOWN_METADATA);
    } else {
        ledger.push_gate("SL306", RULE_DISABLED, deselected);
    }
}

fn record_families(
    ledger: &mut Ledger,
    enabled: &BTreeSet<&str>,
    deselected: &BTreeSet<&str>,
    is_empty_input: bool,
    has_version_abort: bool,
    has_cap_abort: bool,
) {
    for &(family, rules) in FAMILIES {
        if !any_enabled(rules, enabled) {
            record_disabled_family(ledger, family, rules, deselected);
        } else if is_empty_input {
            record_empty_family(ledger, family, rules, enabled, deselected);
        } else if has_version_abort {
            record_abort_family(ledger, family, rules, "version-gated", VERSION_DETAIL);
        } else if has_cap_abort {
            record_abort_family(ledger, family, rules, "cap-exceeded", CAP_DETAIL);
        } else {
            record_ran_family(ledger, family, rules, enabled, deselected);
        }
    }
}

fn record_disabled_family(
    ledger: &mut Ledger,
    family: &str,
    rules: &[&str],
    deselected: &BTreeSet<&str>,
) {
    if !ledger.already_skipped.contains(family) {
        if rules.iter().all(|rule| deselected.contains(*rule)) {
            ledger.push(family, "deselected", FAMILY_DESELECTED);
        } else {
            ledger.push(family, "profile-gated", FAMILY_DISABLED);
        }
        ledger.remember(family);
    }
    for rule in rules {
        ledger.gate_new(rule, RULE_DISABLED, deselected);
    }
}

fn record_empty_family(
    ledger: &mut Ledger,
    family: &str,
    rules: &[&str],
    enabled: &BTreeSet<&str>,
    deselected: &BTreeSet<&str>,
) {
    if !ledger.already_skipped.contains(family) {
        ledger.push(family, "empty-input", ZERO_RECORDS);
        ledger.remember(family);
    }
    for rule in rules {
        if ledger.already_skipped.contains(*rule) {
            continue;
        }
        if enabled.contains(*rule) {
            ledger.push(rule, "empty-input", ZERO_RECORDS);
        } else {
            ledger.push_gate(rule, RULE_DISABLED, deselected);
        }
        ledger.remember(rule);
    }
}

fn record_abort_family(
    ledger: &mut Ledger,
    family: &str,
    rules: &[&str],
    reason: &str,
    detail: &str,
) {
    if !ledger.already_skipped.contains(family) {
        ledger.push(family, reason, detail);
        ledger.remember(family);
    }
    for rule in rules {
        if !ledger.already_skipped.contains(*rule) {
            ledger.push(rule, reason, detail);
            ledger.remember(rule);
        }
    }
}

fn record_ran_family(
    ledger: &mut Ledger,
    family: &str,
    rules: &[&str],
    enabled: &BTreeSet<&str>,
    deselected: &BTreeSet<&str>,
) {
    ledger.performed.insert(family.to_owned());
    for rule in rules {
        if enabled.contains(*rule) {
            ledger.performed.insert((*rule).to_owned());
        } else {
            ledger.gate_new(rule, RULE_DISABLED, deselected);
        }
    }
}

fn run_detectors(
    findings: &mut Vec<Finding>,
    ledger: &mut Ledger,
    input: &RunAllChecksInput<'_>,
    profile: &Profile,
    context: &CheckContext,
    enabled: &BTreeSet<&str>,
) -> Result<(), RunnerError> {
    run_identity_graph_ordering(findings, input, context, enabled)?;
    run_writers(findings, ledger, input, context, enabled)?;
    run_pairing(findings, input, context, enabled)?;
    run_checkpoint_family(findings, ledger, input, profile, context, enabled)?;
    run_shape_accounting_size(findings, ledger, input, context, enabled)?;
    Ok(())
}

fn run_identity_graph_ordering(
    findings: &mut Vec<Finding>,
    input: &RunAllChecksInput<'_>,
    context: &CheckContext,
    enabled: &BTreeSet<&str>,
) -> Result<(), RunnerError> {
    if enabled.contains("SL003") {
        extend_findings(
            findings,
            check_identities(input.events, Some(input.source_path), None, Some(context)),
        )?;
    }
    if any_enabled(GRAPH_RULES, enabled) {
        extend_findings(
            findings,
            check_graph(input.events, Some(input.source_path), None, Some(context)),
        )?;
    }
    if enabled.contains("SL008") {
        extend_findings(
            findings,
            check_ordering(
                input.events,
                Some(input.source_path),
                None,
                Some(context),
                None,
            ),
        )?;
    }
    Ok(())
}

fn run_writers(
    findings: &mut Vec<Finding>,
    ledger: &mut Ledger,
    input: &RunAllChecksInput<'_>,
    context: &CheckContext,
    enabled: &BTreeSet<&str>,
) -> Result<(), RunnerError> {
    if !enabled.contains("SL010") {
        return Ok(());
    }
    if writer_markers_present(context) {
        return extend_findings(
            findings,
            check_writers(input.events, Some(input.source_path), Some(context)),
        );
    }
    mark_adapter_skip(ledger, "writers", NO_WRITER_MARKERS);
    mark_adapter_skip(ledger, "SL010", NO_WRITER_MARKERS);
    Ok(())
}

fn run_pairing(
    findings: &mut Vec<Finding>,
    input: &RunAllChecksInput<'_>,
    context: &CheckContext,
    enabled: &BTreeSet<&str>,
) -> Result<(), RunnerError> {
    if any_enabled(PAIRING_1_RULES, enabled) {
        extend_findings(
            findings,
            check_tool_pairing_1(input.events, Some(input.source_path), None, Some(context)),
        )?;
    }
    if any_enabled(PAIRING_2_RULES, enabled) {
        // The pin passes the resolved Profile object: not None and not str.
        extend_findings(
            findings,
            check_tool_pairing_2(
                input.events,
                Some(input.source_path),
                None,
                RuleSeverityProfile::Other,
                Some(context),
            ),
        )?;
    }
    Ok(())
}

fn run_checkpoint_family(
    findings: &mut Vec<Finding>,
    ledger: &mut Ledger,
    input: &RunAllChecksInput<'_>,
    profile: &Profile,
    context: &CheckContext,
    enabled: &BTreeSet<&str>,
) -> Result<(), RunnerError> {
    run_checkpoint_call(findings, ledger, input, profile, context, enabled)?;
    run_durable_prefix(findings, ledger, input, context, enabled)?;
    run_compaction_snapshot(findings, ledger, input, context, enabled)?;
    Ok(())
}

fn run_checkpoint_call(
    findings: &mut Vec<Finding>,
    ledger: &mut Ledger,
    input: &RunAllChecksInput<'_>,
    profile: &Profile,
    context: &CheckContext,
    enabled: &BTreeSet<&str>,
) -> Result<(), RunnerError> {
    if !any_enabled(CHECKPOINT_CALL_RULES, enabled) {
        return Ok(());
    }
    extend_findings(
        findings,
        check_checkpoint(
            input.events,
            Some(input.source_path),
            None,
            Some(profile.checkpoint_sensitivity.as_str()),
            Some(context),
            None,
        ),
    )?;
    if enabled.contains("SL203")
        && !context.compaction_checkpoint_capable()
        && !findings.iter().any(|finding| finding.code() == "SL203")
    {
        mark_adapter_skip(ledger, "SL203", &sl203_detail(context.adapter_id()));
    }
    Ok(())
}

fn run_durable_prefix(
    findings: &mut Vec<Finding>,
    ledger: &mut Ledger,
    input: &RunAllChecksInput<'_>,
    context: &CheckContext,
    enabled: &BTreeSet<&str>,
) -> Result<(), RunnerError> {
    if !enabled.contains("SL206") {
        return Ok(());
    }
    if context.adapter_id() == "codex-rollout" {
        return extend_findings(
            findings,
            check_durable_prefix(input.events, Some(input.source_path), Some(context)),
        );
    }
    mark_adapter_skip(ledger, "SL206", DURABLE_PREFIX_ONLY);
    if !any_enabled(CHECKPOINT_CALL_RULES, enabled) {
        mark_adapter_skip(ledger, "checkpoint", DURABLE_PREFIX_ONLY);
    }
    Ok(())
}

fn run_compaction_snapshot(
    findings: &mut Vec<Finding>,
    ledger: &mut Ledger,
    input: &RunAllChecksInput<'_>,
    context: &CheckContext,
    enabled: &BTreeSet<&str>,
) -> Result<(), RunnerError> {
    if !enabled.contains("SL208") {
        return Ok(());
    }
    if context.adapter_id() == "codex-rollout" {
        return extend_findings(
            findings,
            check_compaction_snapshot(input.events, Some(input.source_path), Some(context)),
        );
    }
    mark_adapter_skip(ledger, "SL208", SNAPSHOT_ONLY);
    if !any_enabled(CHECKPOINT_CALL_RULES, enabled) && !enabled.contains("SL206") {
        mark_adapter_skip(ledger, "checkpoint", CODEX_CHECKPOINT_ONLY);
    }
    Ok(())
}

fn run_shape_accounting_size(
    findings: &mut Vec<Finding>,
    ledger: &mut Ledger,
    input: &RunAllChecksInput<'_>,
    context: &CheckContext,
    enabled: &BTreeSet<&str>,
) -> Result<(), RunnerError> {
    run_foreign_shape(findings, ledger, input, context, enabled)?;
    if enabled.contains("SL204") {
        extend_findings(
            findings,
            check_accounting(input.events, Some(input.source_path), None, Some(context)),
        )?;
    }
    run_context_pressure(findings, ledger, input, context, enabled)?;
    run_size(findings, ledger, input, context, enabled)?;
    Ok(())
}

fn run_foreign_shape(
    findings: &mut Vec<Finding>,
    ledger: &mut Ledger,
    input: &RunAllChecksInput<'_>,
    context: &CheckContext,
    enabled: &BTreeSet<&str>,
) -> Result<(), RunnerError> {
    if !enabled.contains("SL305") {
        return Ok(());
    }
    if context.adapter_id() == "codex-rollout" {
        return extend_findings(
            findings,
            check_foreign_shape(input.events, Some(input.source_path), Some(context)),
        );
    }
    mark_adapter_skip(ledger, "shape", REPLAY_ONLY);
    mark_adapter_skip(ledger, "SL305", REPLAY_ONLY);
    Ok(())
}

fn run_context_pressure(
    findings: &mut Vec<Finding>,
    ledger: &mut Ledger,
    input: &RunAllChecksInput<'_>,
    context: &CheckContext,
    enabled: &BTreeSet<&str>,
) -> Result<(), RunnerError> {
    if !enabled.contains("SL207") {
        return Ok(());
    }
    if context.adapter_id() == "codex-rollout" {
        return extend_findings(
            findings,
            check_context_pressure(input.events, Some(input.source_path), Some(context)),
        );
    }
    mark_adapter_skip(ledger, "SL207", DECLARED_WINDOW_ONLY);
    if !enabled.contains("SL204") {
        mark_adapter_skip(ledger, "accounting", DECLARED_WINDOW_ONLY);
    }
    Ok(())
}

fn run_size(
    findings: &mut Vec<Finding>,
    ledger: &mut Ledger,
    input: &RunAllChecksInput<'_>,
    context: &CheckContext,
    enabled: &BTreeSet<&str>,
) -> Result<(), RunnerError> {
    if !enabled.contains("SL011") {
        return Ok(());
    }
    if context.adapter_id() == "codex-rollout" {
        mark_adapter_skip(ledger, "size", SIZE_VENDOR_NORMAL);
        mark_adapter_skip(ledger, "SL011", SIZE_VENDOR_NORMAL);
        return Ok(());
    }
    if below_size_minimum(input.events.len()) {
        mark_adapter_skip(ledger, "size", SIZE_NOT_MEANINGFUL);
        mark_adapter_skip(ledger, "SL011", SIZE_NOT_MEANINGFUL);
        return Ok(());
    }
    extend_findings(
        findings,
        check_size_anomaly(input.events, input.source_path, Some(context)),
    )
}

fn mark_adapter_skip(ledger: &mut Ledger, check: &str, detail: &str) {
    ledger.performed.remove(check);
    ledger.push(check, "adapter-not-applicable", detail);
}

fn sl203_detail(adapter_id: &str) -> String {
    let mut detail = String::with_capacity(adapter_id.len() + SL203_SUFFIX.len());
    detail.push_str(adapter_id);
    detail.push_str(SL203_SUFFIX);
    detail
}

fn any_enabled(rules: &[&str], enabled: &BTreeSet<&str>) -> bool {
    rules.iter().any(|rule| enabled.contains(*rule))
}

fn below_size_minimum(event_count: usize) -> bool {
    match i64::try_from(event_count) {
        Ok(event_count) => event_count < SIZE_MIN_RECORDS,
        Err(_) => false,
    }
}

/// Python truthiness. [`Value::Bool`] is matched on its own and is not an int.
fn json_truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number_truthy(number),
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(object)) => !object.is_empty(),
    }
}

fn number_truthy(number: &Number) -> bool {
    if let Some(int) = number.as_i64() {
        int != 0
    } else if let Some(unsigned) = number.as_u64() {
        unsigned != 0
    } else if let Some(float) = number.as_f64() {
        float != 0.0
    } else {
        true
    }
}

fn writer_markers_present(context: &CheckContext) -> bool {
    let Some(metadata) = context.source_metadata() else {
        return false;
    };
    if metadata.is_empty() {
        return false;
    }
    json_truthy(metadata.get("writer_markers"))
}

fn extend_findings<E>(
    findings: &mut Vec<Finding>,
    result: Result<Vec<Finding>, E>,
) -> Result<(), RunnerError>
where
    E: fmt::Display,
{
    match result {
        Ok(more) => {
            findings.extend(more);
            Ok(())
        }
        Err(error) => Err(RunnerError::from_display(error)),
    }
}

fn filter_enabled(findings: Vec<Finding>, enabled: &BTreeSet<&str>) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|finding| enabled.contains(finding.code()))
        .collect()
}

fn observe_ledger(ledger: &Ledger) {
    for name in &ledger.performed {
        let _ = name.as_str();
    }
    for name in &ledger.already_skipped {
        let _ = name.as_str();
    }
    for note in &ledger.skipped {
        let _ = note.check.as_str();
        let _ = note.reason.as_str();
        let _ = note.detail.as_str();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        json_truthy, run_all_checks, writer_markers_present, AdapterSkip, ProfileArg,
        RunAllChecksInput, COVERAGE_UNAVAILABLE,
    };
    use crate::context::CheckContext;
    use crate::profile::{OrderedMap, Profile};
    use model::events::EventValue;
    use serde_json::{Number, Value};
    use std::collections::BTreeMap;

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

    fn profile_with(rules: &[&str]) -> Profile {
        Profile::new(
            "custom",
            "custom",
            ["canonical"],
            rules.iter().copied(),
            OrderedMap::new(),
            "default",
        )
    }

    #[test]
    fn empty_neutral_input_returns_no_findings() {
        let findings = run_all_checks(&RunAllChecksInput::new(&[])).expect("empty stream");
        assert!(findings.is_empty());
    }

    #[test]
    fn return_coverage_stops_without_constructing_coverage() {
        let mut input = RunAllChecksInput::new(&[]);
        input.return_coverage = true;
        let error = run_all_checks(&input).expect_err("coverage stop");
        assert_eq!(error.to_string(), COVERAGE_UNAVAILABLE);
        assert_eq!(
            error.to_string(),
            "sesslint.report.Coverage is not available"
        );
    }

    #[test]
    fn profile_name_propagates_get_profile() {
        let mut input = RunAllChecksInput::new(&[]);
        input.profile = ProfileArg::Name("neutral");
        let error = run_all_checks(&input).expect_err("profile name");
        assert_eq!(
            error.to_string(),
            "sesslint.profiles.builtin is not available"
        );
    }

    #[test]
    fn enabled_pairing_two_propagates_the_detector_error() {
        let events = [EventValue::Other];
        let profile = profile_with(&["SL105"]);
        let mut input = RunAllChecksInput::new(&events);
        input.profile = ProfileArg::Profile(&profile);
        let error = run_all_checks(&input).expect_err("pairing");
        assert_eq!(error.to_string(), "sesslint.profiles is not available");
    }

    #[test]
    fn return_coverage_does_not_hide_a_detector_error() {
        let events = [EventValue::Other];
        let profile = profile_with(&["SL105", "SL106", "SL107", "SL108"]);
        let mut input = RunAllChecksInput::new(&events);
        input.profile = ProfileArg::Profile(&profile);
        input.return_coverage = true;
        let error = run_all_checks(&input).expect_err("detector before coverage");
        assert_eq!(error.to_string(), "sesslint.profiles is not available");
    }

    #[test]
    fn version_and_cap_aborts_do_not_call_the_detector() {
        let events = [EventValue::Other];
        let profile = profile_with(&["SL105"]);
        for reason in ["version-gated", "cap-exceeded"] {
            let skips = [AdapterSkip {
                check: "SL301",
                reason,
                detail: "",
            }];
            let mut input = RunAllChecksInput::new(&events);
            input.profile = ProfileArg::Profile(&profile);
            input.adapter_skips = &skips;
            let findings = run_all_checks(&input).expect(reason);
            assert!(findings.is_empty(), "{reason}");
        }
    }

    #[test]
    fn deselection_does_not_skip_an_enabled_detector() {
        let events = [EventValue::Other];
        let profile = profile_with(&["SL105"]);
        let mut input = RunAllChecksInput::new(&events);
        input.profile = ProfileArg::Profile(&profile);
        input.deselected_rules = &["SL105"];
        let error = run_all_checks(&input).expect_err("still called");
        assert_eq!(error.to_string(), "sesslint.profiles is not available");
    }

    #[test]
    fn a_bool_marker_is_not_read_as_an_int() {
        assert!(json_truthy(Some(&Value::Bool(true))));
        assert!(!json_truthy(Some(&Value::Bool(false))));
        assert!(json_truthy(Some(&Value::Number(Number::from(1)))));
        assert!(!json_truthy(Some(&Value::Number(Number::from(0)))));
        assert!(!json_truthy(None));
        assert_ne!(Value::Bool(true), Value::Number(Number::from(1)));

        let mut present_meta = BTreeMap::new();
        present_meta.insert("writer_markers".to_owned(), Value::Bool(true));
        let present = CheckContext::new(
            "unknown",
            "unknown",
            "custom",
            "1.0.0",
            Some(present_meta),
            2000,
        );
        assert!(writer_markers_present(&present));

        let mut absent_meta = BTreeMap::new();
        absent_meta.insert("writer_markers".to_owned(), Value::Bool(false));
        let absent = CheckContext::new(
            "unknown",
            "unknown",
            "custom",
            "1.0.0",
            Some(absent_meta),
            2000,
        );
        assert!(!writer_markers_present(&absent));
    }
}
