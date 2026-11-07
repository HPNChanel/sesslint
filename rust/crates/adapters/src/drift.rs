//! Mid-file schema drift tracking (SL304, DEV-T05).
//!
//! Port of `src/sesslint/adapters/drift.py`
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` lines 1–267.
//!
//! Per-file tracker driven by adapters during record decode. Two drift kinds
//! are recorded:
//!
//! - `version`: a normalized schema-version marker changes mid-stream while
//!   both the previous and the observed marker are individually supported.
//!   Compatible application-release bumps never reach the tracker (adapters
//!   only observe explicit schema markers).
//! - `signature`: a record's envelope `type` is discriminative for a
//!   different vendor format — evidence of a spliced file. Shared vocabulary
//!   (`user`, `assistant`, `message`, `compaction`, ...) is non-discriminative
//!   and never fires.
//!
//! Precedence (documented in `docs/codes/SL304.md`): when SL301 fires anywhere
//! in the file, detection already failed — all buffered SL304 transitions are
//! discarded at flush time so the unsupported version is reported once and
//! never double-reported.
//!
//! Transitions are deduplicated by `(kind, previous, observed)` keeping the
//! first occurrence, and capped at [`MAX_DRIFT_TRANSITIONS`] per file.
//! Evidence is structural only (bounded markers via [`safe_discriminator`]);
//! payload content never enters findings.
//!
//! Gaps vs Python (recorded, not papered over):
//! - [`DriftTracker::into_findings`] calls [`make_finding`] with the fingerprint
//!   omitted. That builds the source, template, and evidence, then reaches
//!   `sesslint.determinism.canonical_json_bytes`, which is not in this crate.
//!   A non-empty flush returns [`FindingError`] whose Display is
//!   `sesslint.determinism.canonical_json_bytes is not available`. No digest
//!   is invented. An empty buffer or an SL301 suppression returns before that
//!   call. A rejected [`SourceRef`] returns before it too.
//! - Line, ordinal, and byte coordinates are `i64`. Python `int` is unbounded.
//!   `bool` is not an `int` here, so a boolean coordinate cannot be passed.
//! - A Rust `&str` cannot contain a lone surrogate.
//! - Only [`crate::safe_value::PyValue::Str`] passes the `isinstance(..., str)`
//!   check. A Python `str` subclass still passes `isinstance`. Callers map
//!   those to [`crate::safe_value::PyValue::Str`]. [`crate::safe_value::PyValue::Other`]
//!   does not fire.

use std::collections::BTreeSet;

use model::codes::{Repairability, Severity, SL304};
use model::errors::FindingError;
use model::finding::{make_finding, Finding, MakeFindingInput, PyValue, SourceLine, SourceRef};

use crate::safe_value::{safe_discriminator, PyValue as SafeValue};

/// Python: `MAX_DRIFT_TRANSITIONS`.
pub const MAX_DRIFT_TRANSITIONS: usize = 8;

/// Envelope `type` values that identify exactly one vendor format.
///
/// Python: `FOREIGN_SIGNATURE_TYPES`. A record carrying one inside a stream
/// of a different format is a foreign signature. Types shared across formats
/// are deliberately absent. Declaration order is the pinned dict order.
pub const FOREIGN_SIGNATURE_TYPES: &[(&str, &str)] = &[
    // claude-code-jsonl discriminative envelope types
    ("summary", "claude-code-jsonl"),
    ("user_message", "claude-code-jsonl"),
    ("assistant_message", "claude-code-jsonl"),
    ("tool_use", "claude-code-jsonl"),
    // openai-agents discriminative item types
    ("tool_call", "openai-agents"),
    ("function_call", "openai-agents"),
    ("function_call_output", "openai-agents"),
    ("handoff", "openai-agents"),
    ("checkpoint", "openai-agents"),
    // codex-rollout discriminative envelope types
    ("session_meta", "codex-rollout"),
    ("event_msg", "codex-rollout"),
    ("turn_context", "codex-rollout"),
    ("world_state", "codex-rollout"),
    ("inter_agent_communication_metadata", "codex-rollout"),
    ("token_usage_record", "codex-rollout"),
    ("response_item", "codex-rollout"),
    ("compacted", "codex-rollout"),
];

/// Python `__all__`, in that order.
pub const ALL: [&str; 3] = [
    "FOREIGN_SIGNATURE_TYPES",
    "MAX_DRIFT_TRANSITIONS",
    "DriftTracker",
];

const SIGNATURE_MESSAGE: &str =
    "Format signature changes mid-file on line {line} for record {record_id}";

const VERSION_MESSAGE: &str =
    "Schema version marker changes mid-file on line {line} for record {record_id}";

/// One buffered drift observation with record coordinates.
///
/// Python: `_Transition`. Frozen there; fields stay private here.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Transition {
    kind: String,
    previous: String,
    observed: String,
    field: String,
    observed_format: Option<String>,
    line: Option<i64>,
    record_id: Option<String>,
    record_ordinal: Option<i64>,
    byte_offset: Option<i64>,
    byte_end: Option<i64>,
}

/// Accumulate schema-drift transitions for one file parse.
///
/// Adapters call [`Self::observe_version`] for schema-version markers and
/// [`Self::observe_signature`] for envelope type values. When SL301 fires
/// (an unsupported version marker), [`Self::note_unsupported_version`]
/// suppresses all buffered output so detection failures are reported once.
#[derive(Debug)]
pub struct DriftTracker {
    format_label: String,
    version_baseline: Option<String>,
    transitions: Vec<Transition>,
    seen: BTreeSet<(String, String, String)>,
    sl301_seen: bool,
}

impl DriftTracker {
    /// Python: `DriftTracker(format_label)`.
    pub fn new(format_label: &str) -> Self {
        Self {
            format_label: format_label.to_owned(),
            version_baseline: None,
            transitions: Vec::new(),
            seen: BTreeSet::new(),
            sl301_seen: false,
        }
    }

    /// Record that SL301 fired for this file; suppresses all SL304 output.
    pub fn note_unsupported_version(&mut self) {
        self.sl301_seen = true;
    }

    /// Observe a schema-version marker.
    ///
    /// Python: `observe_version`. `version_norm` is the adapter-normalized
    /// marker. When `supported` is false the adapter's version predicate
    /// rejected it (SL301 territory) — the tracker suppresses rather than
    /// comparing. Otherwise the marker is chained: the first supported marker
    /// sets the baseline, each later differing marker records a transition and
    /// becomes the new baseline. The baseline moves before dedup and the cap,
    /// so a dropped transition still advances it.
    ///
    /// `line`, `record_id`, `record_ordinal`, `byte_offset`, and `byte_end`
    /// are the Python keyword arguments. `None` is the Python default.
    #[allow(clippy::too_many_arguments)] // pinned keyword list, in that order
    pub fn observe_version(
        &mut self,
        version_norm: &str,
        supported: bool,
        field: &str,
        line: Option<i64>,
        record_id: Option<&str>,
        record_ordinal: Option<i64>,
        byte_offset: Option<i64>,
        byte_end: Option<i64>,
    ) {
        if !supported {
            self.sl301_seen = true;
            return;
        }
        if self.version_baseline.as_deref() == Some(version_norm) {
            return;
        }
        // `None` means this call established the baseline. `Some` is the marker
        // that just ended, and it is recorded against the new baseline.
        let Some(previous) = self.version_baseline.replace(version_norm.to_owned()) else {
            return;
        };
        self.record(
            "version",
            &previous,
            version_norm,
            field,
            None,
            line,
            record_id,
            record_ordinal,
            byte_offset,
            byte_end,
        );
    }

    /// Observe an envelope `type` value.
    ///
    /// Python: `observe_signature`. Fires only when `raw_type` is a
    /// discriminative envelope type of a format different from this stream.
    /// Unknown or shared-vocabulary types never fire. Non-strings never fire.
    ///
    /// The trailing coordinates match `observe_version`. `None` is the default.
    #[allow(clippy::too_many_arguments)] // pinned keyword list, in that order
    pub fn observe_signature(
        &mut self,
        raw_type: SafeValue<'_>,
        line: Option<i64>,
        record_id: Option<&str>,
        record_ordinal: Option<i64>,
        byte_offset: Option<i64>,
        byte_end: Option<i64>,
    ) {
        let SafeValue::Str(raw_type) = raw_type else {
            return;
        };
        let Some(observed_format) = foreign_signature_format(raw_type) else {
            return;
        };
        if observed_format == self.format_label {
            return;
        }
        let previous = self.format_label.clone();
        self.record(
            "signature",
            &previous,
            raw_type,
            "type",
            Some(observed_format),
            line,
            record_id,
            record_ordinal,
            byte_offset,
            byte_end,
        );
    }

    /// Materialize buffered transitions as SL304 findings.
    ///
    /// Python: `into_findings`. Returns an empty list when SL301 fired
    /// anywhere in the file — the unsupported version already fails detection,
    /// so emitting drift diagnostics would double-report the same root cause.
    /// An empty buffer also returns before [`make_finding`], and does not read
    /// `path_str`.
    ///
    /// A buffered transition builds evidence with [`safe_discriminator`], then
    /// [`SourceRef`], then [`make_finding`]. The omitted fingerprint fails
    /// closed with `sesslint.determinism.canonical_json_bytes is not available`
    /// after those steps. A bad source fails first and does not ask for a digest.
    pub fn into_findings(&self, path_str: &str) -> Result<Vec<Finding>, FindingError> {
        if self.sl301_seen {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(self.transitions.len());
        for transition in &self.transitions {
            out.push(finding_from_transition(path_str, transition)?);
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)] // same coordinate list as the public methods
    fn record(
        &mut self,
        kind: &str,
        previous: &str,
        observed: &str,
        field: &str,
        observed_format: Option<&str>,
        line: Option<i64>,
        record_id: Option<&str>,
        record_ordinal: Option<i64>,
        byte_offset: Option<i64>,
        byte_end: Option<i64>,
    ) {
        let key = (kind.to_owned(), previous.to_owned(), observed.to_owned());
        if !self.seen.insert(key) {
            return;
        }
        if self.transitions.len() >= MAX_DRIFT_TRANSITIONS {
            return;
        }
        self.transitions.push(Transition {
            kind: kind.to_owned(),
            previous: previous.to_owned(),
            observed: observed.to_owned(),
            field: field.to_owned(),
            observed_format: observed_format.map(str::to_owned),
            line,
            record_id: record_id.map(str::to_owned),
            record_ordinal,
            byte_offset,
            byte_end,
        });
    }
}

/// Python `FOREIGN_SIGNATURE_TYPES.get`. Exact key match, first declaration wins.
fn foreign_signature_format(raw_type: &str) -> Option<&'static str> {
    FOREIGN_SIGNATURE_TYPES
        .iter()
        .find_map(|(name, format_label)| (*name == raw_type).then_some(*format_label))
}

fn message_template_for(kind: &str) -> &'static str {
    if kind == "signature" {
        SIGNATURE_MESSAGE
    } else {
        VERSION_MESSAGE
    }
}

fn finding_from_transition(
    path_str: &str,
    transition: &Transition,
) -> Result<Finding, FindingError> {
    let evidence = transition_evidence(transition);
    let source = SourceRef::try_new(
        path_str,
        transition.line.map(SourceLine::Int),
        transition.record_id.as_deref(),
    )?;
    make_finding(&MakeFindingInput {
        code: PyValue::string(SL304),
        severity: PyValue::severity(Severity::Warning),
        repairability: PyValue::repairability(Repairability::Manual),
        message_template: PyValue::string(message_template_for(&transition.kind)),
        template_args: PyValue::None,
        source: PyValue::source(source),
        related_ids: PyValue::tuple(Vec::new()),
        evidence,
        fingerprint: PyValue::None,
        adapter_id: None,
        adapter_version: None,
        profile_id: None,
        profile_version: None,
        ordinal: None,
        context: None,
    })
}

/// Evidence dict in Python insertion order. Only the two markers are passed
/// through [`safe_discriminator`]. `field` and `observed_format` are stored raw.
fn transition_evidence(transition: &Transition) -> PyValue {
    let (previous_marker, _) = safe_discriminator(SafeValue::Str(&transition.previous));
    let (observed_marker, _) = safe_discriminator(SafeValue::Str(&transition.observed));
    let mut entries = vec![
        pair("drift_kind", PyValue::string(&transition.kind)),
        pair("previous_marker", PyValue::string(previous_marker)),
        pair("observed_marker", PyValue::string(observed_marker)),
        pair("field", PyValue::string(&transition.field)),
    ];
    if let Some(ordinal) = transition.record_ordinal {
        entries.push(pair("record_index", PyValue::int(ordinal)));
    }
    if let Some(observed_format) = &transition.observed_format {
        entries.push(pair("observed_format", PyValue::string(observed_format)));
    }
    if let Some(byte_offset) = transition.byte_offset {
        entries.push(pair("byte_offset", PyValue::int(byte_offset)));
    }
    if let Some(byte_end) = transition.byte_end {
        entries.push(pair("byte_end", PyValue::int(byte_end)));
    }
    PyValue::map(entries)
}

fn pair(key: &str, value: PyValue) -> (PyValue, PyValue) {
    (PyValue::string(key), value)
}

#[cfg(test)]
mod tests {
    use super::{
        foreign_signature_format, message_template_for, transition_evidence, DriftTracker,
        Transition, ALL, FOREIGN_SIGNATURE_TYPES, MAX_DRIFT_TRANSITIONS, SIGNATURE_MESSAGE,
        VERSION_MESSAGE,
    };
    use crate::safe_value::PyValue as SafeValue;
    use model::finding::{PyValue, FINGERPRINT_CODEC_UNAVAILABLE};

    fn version(tracker: &mut DriftTracker, marker: &str, supported: bool, field: &str) {
        tracker.observe_version(marker, supported, field, None, None, None, None, None);
    }

    fn signature(tracker: &mut DriftTracker, raw: &str) {
        tracker.observe_signature(SafeValue::Str(raw), None, None, None, None, None);
    }

    fn signature_value(tracker: &mut DriftTracker, raw: SafeValue<'_>) {
        tracker.observe_signature(raw, None, None, None, None, None);
    }

    fn sorted_signature_names() -> Vec<&'static str> {
        let mut names: Vec<&str> = FOREIGN_SIGNATURE_TYPES
            .iter()
            .map(|(name, _)| *name)
            .collect();
        names.sort_unstable();
        names
    }

    #[test]
    fn export_list_matches_python_all() {
        assert_eq!(
            ALL,
            [
                "FOREIGN_SIGNATURE_TYPES",
                "MAX_DRIFT_TRANSITIONS",
                "DriftTracker",
            ]
        );
        assert_eq!(MAX_DRIFT_TRANSITIONS, 8);
    }

    #[test]
    fn foreign_signature_table_matches_the_pin() {
        assert_eq!(
            FOREIGN_SIGNATURE_TYPES,
            [
                ("summary", "claude-code-jsonl"),
                ("user_message", "claude-code-jsonl"),
                ("assistant_message", "claude-code-jsonl"),
                ("tool_use", "claude-code-jsonl"),
                ("tool_call", "openai-agents"),
                ("function_call", "openai-agents"),
                ("function_call_output", "openai-agents"),
                ("handoff", "openai-agents"),
                ("checkpoint", "openai-agents"),
                ("session_meta", "codex-rollout"),
                ("event_msg", "codex-rollout"),
                ("turn_context", "codex-rollout"),
                ("world_state", "codex-rollout"),
                ("inter_agent_communication_metadata", "codex-rollout"),
                ("token_usage_record", "codex-rollout"),
                ("response_item", "codex-rollout"),
                ("compacted", "codex-rollout"),
            ]
        );
        for (name, label) in FOREIGN_SIGNATURE_TYPES {
            assert_eq!(foreign_signature_format(name), Some(*label));
        }
        for shared in ["user", "assistant", "message", "compaction", "Summary", ""] {
            assert_eq!(foreign_signature_format(shared), None);
        }
    }

    #[test]
    fn message_templates_match_the_pin() {
        assert_eq!(
            message_template_for("signature"),
            "Format signature changes mid-file on line {line} for record {record_id}"
        );
        assert_eq!(message_template_for("signature"), SIGNATURE_MESSAGE);
        assert_eq!(
            message_template_for("version"),
            "Schema version marker changes mid-file on line {line} for record {record_id}"
        );
        assert_eq!(message_template_for("version"), VERSION_MESSAGE);
        assert_eq!(message_template_for("other"), VERSION_MESSAGE);
    }

    #[test]
    fn version_chain_baselines_then_records_the_first_difference() {
        let mut tracker = DriftTracker::new("claude-code-jsonl");
        version(&mut tracker, "1", true, "schemaVersion");
        version(&mut tracker, "1", true, "schemaVersion");
        version(&mut tracker, "0.1", true, "schemaVersion");
        assert_eq!(tracker.version_baseline.as_deref(), Some("0.1"));
        assert_eq!(tracker.transitions.len(), 1);
        assert_eq!(
            tracker.transitions[0],
            Transition {
                kind: "version".to_owned(),
                previous: "1".to_owned(),
                observed: "0.1".to_owned(),
                field: "schemaVersion".to_owned(),
                observed_format: None,
                line: None,
                record_id: None,
                record_ordinal: None,
                byte_offset: None,
                byte_end: None,
            }
        );
        assert_eq!(
            transition_evidence(&tracker.transitions[0]),
            PyValue::map(vec![
                pair_owned("drift_kind", PyValue::string("version")),
                pair_owned("previous_marker", PyValue::string("1")),
                pair_owned("observed_marker", PyValue::string("0.1")),
                pair_owned("field", PyValue::string("schemaVersion")),
            ])
        );
    }

    #[test]
    fn version_field_and_coordinates_belong_to_the_new_marker() {
        let mut tracker = DriftTracker::new("codex-rollout");
        tracker.observe_version(
            "1",
            true,
            "schemaVersion",
            Some(1),
            Some("baseline"),
            Some(1),
            Some(0),
            Some(4),
        );
        tracker.observe_version(
            "2",
            true,
            "rollout_version",
            Some(4),
            Some("r2"),
            Some(0),
            Some(-1),
            Some(0),
        );
        let stored = &tracker.transitions[0];
        assert_eq!(stored.field, "rollout_version");
        assert_eq!(stored.line, Some(4));
        assert_eq!(stored.record_id.as_deref(), Some("r2"));
        assert_eq!(stored.record_ordinal, Some(0));
        assert_eq!(stored.byte_offset, Some(-1));
        assert_eq!(stored.byte_end, Some(0));
        assert_eq!(stored.observed_format, None);
        assert_eq!(
            transition_evidence(stored),
            PyValue::map(vec![
                pair_owned("drift_kind", PyValue::string("version")),
                pair_owned("previous_marker", PyValue::string("1")),
                pair_owned("observed_marker", PyValue::string("2")),
                pair_owned("field", PyValue::string("rollout_version")),
                pair_owned("record_index", PyValue::int(0)),
                pair_owned("byte_offset", PyValue::int(-1)),
                pair_owned("byte_end", PyValue::int(0)),
            ])
        );
    }

    #[test]
    fn string_equality_not_numeric_equality_opens_a_transition() {
        let mut tracker = DriftTracker::new("canonical");
        version(&mut tracker, "1", true, "version");
        version(&mut tracker, "1.0", true, "version");
        version(&mut tracker, "01", true, "version");
        assert_eq!(tracker.transitions.len(), 2);
        assert_eq!(tracker.transitions[0].previous, "1");
        assert_eq!(tracker.transitions[0].observed, "1.0");
        assert_eq!(tracker.transitions[1].previous, "1.0");
        assert_eq!(tracker.transitions[1].observed, "01");
        assert_eq!(tracker.version_baseline.as_deref(), Some("01"));
    }

    #[test]
    fn duplicate_version_key_keeps_the_first_field_and_still_moves_baseline() {
        let mut tracker = DriftTracker::new("canonical");
        version(&mut tracker, "1", true, "field-a");
        version(&mut tracker, "2", true, "field-a");
        version(&mut tracker, "1", true, "field-b");
        version(&mut tracker, "2", true, "field-c");
        assert_eq!(tracker.transitions.len(), 2);
        assert_eq!(tracker.transitions[0].field, "field-a");
        assert_eq!(tracker.transitions[0].previous, "1");
        assert_eq!(tracker.transitions[0].observed, "2");
        assert_eq!(tracker.transitions[1].field, "field-b");
        assert_eq!(tracker.version_baseline.as_deref(), Some("2"));
        assert_eq!(tracker.seen.len(), 2);
    }

    #[test]
    fn unsupported_marker_sets_sl301_without_moving_or_comparing() {
        let mut tracker = DriftTracker::new("codex-rollout");
        version(&mut tracker, "1", true, "version");
        version(&mut tracker, "1", false, "version");
        assert!(tracker.sl301_seen);
        assert_eq!(tracker.version_baseline.as_deref(), Some("1"));
        assert!(tracker.transitions.is_empty());
        version(&mut tracker, "2", true, "version");
        signature(&mut tracker, "summary");
        assert_eq!(tracker.transitions.len(), 2);
        assert!(tracker.into_findings("").expect("suppressed").is_empty());
        assert!(tracker.into_findings("  ").expect("path unread").is_empty());
    }

    #[test]
    fn unsupported_before_any_baseline_does_not_record() {
        let mut tracker = DriftTracker::new("canonical");
        version(&mut tracker, "9.9", false, "version");
        assert!(tracker.version_baseline.is_none());
        assert!(tracker.sl301_seen);
        version(&mut tracker, "1", true, "version");
        assert_eq!(tracker.version_baseline.as_deref(), Some("1"));
        assert!(tracker.transitions.is_empty());
        assert!(tracker.into_findings("x").expect("suppressed").is_empty());
    }

    #[test]
    fn note_unsupported_version_suppresses_a_buffered_transition() {
        let mut tracker = DriftTracker::new("claude-code-jsonl");
        signature(&mut tracker, "turn_context");
        assert_eq!(tracker.transitions.len(), 1);
        tracker.note_unsupported_version();
        signature(&mut tracker, "session_meta");
        assert_eq!(tracker.transitions.len(), 2);
        assert!(tracker.into_findings("x").expect("suppressed").is_empty());
    }

    #[test]
    fn signature_fires_only_for_a_foreign_discriminative_type() {
        let mut tracker = DriftTracker::new("claude-code-jsonl");
        signature(&mut tracker, "turn_context");
        signature(&mut tracker, "summary");
        signature(&mut tracker, "user");
        signature(&mut tracker, "assistant");
        signature(&mut tracker, "message");
        signature(&mut tracker, "compaction");
        signature(&mut tracker, "nonsense-xyz");
        signature(&mut tracker, "Summary");
        signature_value(&mut tracker, SafeValue::Int);
        signature_value(&mut tracker, SafeValue::Bool);
        signature_value(&mut tracker, SafeValue::None);
        signature_value(&mut tracker, SafeValue::Float);
        signature_value(&mut tracker, SafeValue::List(0));
        signature_value(&mut tracker, SafeValue::Dict(1));
        signature_value(&mut tracker, SafeValue::Bytes(3));
        signature_value(&mut tracker, SafeValue::Other("str"));
        assert_eq!(tracker.transitions.len(), 1);
        let stored = &tracker.transitions[0];
        assert_eq!(stored.kind, "signature");
        assert_eq!(stored.previous, "claude-code-jsonl");
        assert_eq!(stored.observed, "turn_context");
        assert_eq!(stored.field, "type");
        assert_eq!(stored.observed_format.as_deref(), Some("codex-rollout"));
        assert_eq!(
            transition_evidence(stored),
            PyValue::map(vec![
                pair_owned("drift_kind", PyValue::string("signature")),
                pair_owned("previous_marker", PyValue::string("claude-code-jsonl")),
                pair_owned("observed_marker", PyValue::string("turn_context")),
                pair_owned("field", PyValue::string("type")),
                pair_owned("observed_format", PyValue::string("codex-rollout")),
            ])
        );
    }

    #[test]
    fn native_signature_is_silent_and_foreign_format_is_recorded() {
        for (name, label) in FOREIGN_SIGNATURE_TYPES {
            let mut native = DriftTracker::new(label);
            signature(&mut native, name);
            assert!(native.transitions.is_empty());
            let mut foreign = DriftTracker::new("canonical");
            signature(&mut foreign, name);
            assert_eq!(foreign.transitions.len(), 1);
            assert_eq!(foreign.transitions[0].observed, *name);
            assert_eq!(
                foreign.transitions[0].observed_format.as_deref(),
                Some(*label)
            );
            assert_eq!(foreign.transitions[0].previous, "canonical");
        }
    }

    #[test]
    fn signature_dedup_keeps_the_first_coordinates() {
        let mut tracker = DriftTracker::new("canonical");
        tracker.observe_signature(
            SafeValue::Str("turn_context"),
            Some(3),
            Some("r1"),
            Some(3),
            Some(10),
            Some(20),
        );
        tracker.observe_signature(
            SafeValue::Str("turn_context"),
            Some(9),
            Some("later"),
            Some(9),
            Some(90),
            Some(99),
        );
        assert_eq!(tracker.transitions.len(), 1);
        assert_eq!(tracker.transitions[0].line, Some(3));
        assert_eq!(tracker.transitions[0].record_id.as_deref(), Some("r1"));
        assert_eq!(tracker.transitions[0].record_ordinal, Some(3));
        assert_eq!(tracker.transitions[0].byte_offset, Some(10));
        assert_eq!(tracker.transitions[0].byte_end, Some(20));
        assert_eq!(
            transition_evidence(&tracker.transitions[0]),
            PyValue::map(vec![
                pair_owned("drift_kind", PyValue::string("signature")),
                pair_owned("previous_marker", PyValue::string("canonical")),
                pair_owned("observed_marker", PyValue::string("turn_context")),
                pair_owned("field", PyValue::string("type")),
                pair_owned("record_index", PyValue::int(3)),
                pair_owned("observed_format", PyValue::string("codex-rollout")),
                pair_owned("byte_offset", PyValue::int(10)),
                pair_owned("byte_end", PyValue::int(20)),
            ])
        );
    }

    #[test]
    fn version_and_signature_keys_do_not_collapse() {
        let mut tracker = DriftTracker::new("1");
        version(&mut tracker, "1", true, "version");
        version(&mut tracker, "turn_context", true, "version");
        signature(&mut tracker, "turn_context");
        assert_eq!(tracker.transitions.len(), 2);
        assert_eq!(tracker.transitions[0].kind, "version");
        assert_eq!(tracker.transitions[0].previous, "1");
        assert_eq!(tracker.transitions[0].observed, "turn_context");
        assert_eq!(tracker.transitions[1].kind, "signature");
        assert_eq!(tracker.transitions[1].previous, "1");
        assert_eq!(tracker.transitions[1].observed, "turn_context");
    }

    #[test]
    fn identical_signatures_collapse_and_the_cap_keeps_the_first_eight() {
        let mut tracker = DriftTracker::new("canonical");
        for _ in 0..3 {
            signature(&mut tracker, "turn_context");
        }
        for name in sorted_signature_names() {
            signature(&mut tracker, name);
        }
        let stored: Vec<&str> = tracker
            .transitions
            .iter()
            .map(|transition| transition.observed.as_str())
            .collect();
        assert_eq!(
            stored,
            [
                "turn_context",
                "assistant_message",
                "checkpoint",
                "compacted",
                "event_msg",
                "function_call",
                "function_call_output",
                "handoff",
            ]
        );
        assert_eq!(
            tracker.transitions.len(),
            FOREIGN_SIGNATURE_TYPES.len().min(MAX_DRIFT_TRANSITIONS)
        );
        assert!(tracker.transitions.len() <= MAX_DRIFT_TRANSITIONS);
        assert!(tracker.seen.contains(&key(
            "signature",
            "canonical",
            "inter_agent_communication_metadata"
        )));
        assert!(!tracker
            .transitions
            .iter()
            .any(|transition| transition.observed == "inter_agent_communication_metadata"));
        assert!(tracker
            .transitions
            .iter()
            .all(|transition| { transition.kind == "signature" && transition.field == "type" }));
    }

    #[test]
    fn cap_drop_still_advances_the_version_baseline_and_marks_the_key_seen() {
        let mut tracker = DriftTracker::new("canonical");
        for name in sorted_signature_names()
            .into_iter()
            .take(MAX_DRIFT_TRANSITIONS)
        {
            signature(&mut tracker, name);
        }
        assert_eq!(tracker.transitions.len(), MAX_DRIFT_TRANSITIONS);
        assert_eq!(tracker.seen.len(), MAX_DRIFT_TRANSITIONS);
        version(&mut tracker, "1", true, "version");
        version(&mut tracker, "2", true, "version");
        assert_eq!(tracker.version_baseline.as_deref(), Some("2"));
        assert_eq!(tracker.transitions.len(), MAX_DRIFT_TRANSITIONS);
        assert!(tracker
            .transitions
            .iter()
            .all(|transition| transition.kind == "signature"));
        assert!(tracker.seen.contains(&key("version", "1", "2")));
        assert_eq!(tracker.seen.len(), MAX_DRIFT_TRANSITIONS + 1);
        version(&mut tracker, "2", true, "version");
        assert_eq!(tracker.seen.len(), MAX_DRIFT_TRANSITIONS + 1);
        assert_eq!(tracker.version_baseline.as_deref(), Some("2"));
    }

    #[test]
    fn markers_outside_the_allowlist_are_shaped_and_the_field_stays_raw() {
        let mut tracker = DriftTracker::new("canonical");
        version(&mut tracker, "claude code", true, "schema version");
        version(&mut tracker, "1 2", true, "schema version");
        let evidence = transition_evidence(&tracker.transitions[0]);
        assert_eq!(
            evidence,
            PyValue::map(vec![
                pair_owned("drift_kind", PyValue::string("version")),
                pair_owned("previous_marker", PyValue::string("<str:len=11>")),
                pair_owned("observed_marker", PyValue::string("<str:len=3>")),
                pair_owned("field", PyValue::string("schema version")),
            ])
        );
    }

    #[test]
    fn empty_buffer_does_not_read_the_path_or_call_make_finding() {
        let tracker = DriftTracker::new("canonical");
        assert!(tracker
            .into_findings("")
            .expect("no transitions")
            .is_empty());
        assert!(tracker.into_findings("  ").expect("path unread").is_empty());
        let mut baselined = DriftTracker::new("canonical");
        version(&mut baselined, "1", true, "version");
        assert!(baselined
            .into_findings("")
            .expect("baseline only")
            .is_empty());
    }

    #[test]
    fn flush_of_a_valid_transition_stops_at_the_missing_codec() {
        let mut tracker = DriftTracker::new("claude-code-jsonl");
        tracker.observe_signature(
            SafeValue::Str("turn_context"),
            Some(3),
            Some("  r1  "),
            Some(3),
            None,
            None,
        );
        tracker.observe_version(
            "1",
            true,
            "version",
            Some(0),
            Some("later"),
            None,
            None,
            None,
        );
        let err = tracker.into_findings("x").expect_err("codec");
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(err.message(), FINGERPRINT_CODEC_UNAVAILABLE);
    }

    #[test]
    fn rejected_source_fails_before_the_missing_codec() {
        let mut bad_line = DriftTracker::new("canonical");
        bad_line.observe_signature(
            SafeValue::Str("summary"),
            Some(0),
            Some("r1"),
            None,
            None,
            None,
        );
        let line_err = bad_line.into_findings("x").expect_err("line");
        assert!(line_err.to_string().contains("SourceRef.line"));
        assert_ne!(line_err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);

        let mut bad_path = DriftTracker::new("canonical");
        signature(&mut bad_path, "summary");
        let path_err = bad_path.into_findings("  ").expect_err("path");
        assert!(path_err.to_string().contains("SourceRef.path"));
        assert_ne!(path_err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);

        let mut bad_record = DriftTracker::new("canonical");
        bad_record.observe_signature(
            SafeValue::Str("summary"),
            None,
            Some("   "),
            None,
            None,
            None,
        );
        let record_err = bad_record.into_findings("x").expect_err("record");
        assert!(record_err.to_string().contains("SourceRef.record_id"));
        assert_ne!(record_err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
    }

    fn pair_owned(key: &str, value: PyValue) -> (PyValue, PyValue) {
        (PyValue::string(key), value)
    }

    fn key(kind: &str, previous: &str, observed: &str) -> (String, String, String) {
        (kind.to_owned(), previous.to_owned(), observed.to_owned())
    }
}
