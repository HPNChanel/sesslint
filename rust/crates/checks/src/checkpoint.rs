//! Checkpoint and continuation integrity checks (SL201, SL202, SL203).
//!
//! Port of `src/sesslint/checks/checkpoint.py` lines 1–685 and 688–990
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! This slice ports helpers through [`coverage_pointer`]. It does not port
//! `check_compaction_coverage`, `check_checkpoint`, or `__all__`.
//!
//! [`compute_checkpoint_fingerprint`] hashes locally. It is not a finding
//! digest and does not call [`make_finding`].
//!
//! Under the cap, [`cap_checkpoint_findings`] returns the stably sorted list
//! and does not call [`make_finding`]. Over the cap, [`make_finding`] is
//! called with the fingerprint omitted and returns
//! [`FINGERPRINT_CODEC_UNAVAILABLE`]. That error is propagated. This module
//! does not append a synthetic overflow finding and does not return the kept
//! prefix as if that finding existed.
//!
//! [`checkpoint_gap_records`] does not call [`make_finding`].
//! [`check_checkpoint_gap`] uses that list. An empty list calls
//! [`cap_checkpoint_findings`]. A non-empty list calls [`make_finding`] once,
//! with the fingerprint omitted, and returns
//! [`FINGERPRINT_CODEC_UNAVAILABLE`]. It does not keep a prefix, invent a
//! digest, or call [`cap_checkpoint_findings`] on that path.
//!
//! [`checkpoint_divergence_records`] does not call [`make_finding`].
//! [`check_checkpoint_divergence`] uses that list. An empty list calls
//! [`cap_checkpoint_findings`] with [`SL202`]. A non-empty list calls
//! [`make_finding`] once, with the fingerprint omitted, and returns
//! [`FINGERPRINT_CODEC_UNAVAILABLE`]. It does not invent a digest or call
//! [`cap_checkpoint_findings`] on that path.
//!
//! [`unsafe_continuation_record`] does not call [`make_finding`].
//! [`check_unsafe_continuation`] returns `Ok([])` when there is no record and
//! does not call [`cap_checkpoint_findings`]. One record calls [`make_finding`]
//! once, with the fingerprint omitted, and returns
//! [`FINGERPRINT_CODEC_UNAVAILABLE`]. Adapter `codex-rollout` returns `Ok([])`
//! before events and priors are read.
//!
//! [`coverage_pointer`] does not call [`make_finding`].
//!
//! Sort key is `(code, overflow flag, source.record_id or "", fingerprint)`.
//! Overflow is 1 only when evidence `overflow` is JSON true. This module
//! does not fall back to `correlation_id` and does not call
//! [`crate::graph::cap_finding_sort_key`] or a pairing sort key.
//!
//! [`safe_id`] and [`resolve_source_coords`] are owned copies. This module
//! does not call [`crate::graph::safe_id`] or
//! [`crate::graph::resolve_source_coords`].
//!
//! # Recorded gaps
//!
//! * Python `int` is unbounded. Counts and checkpoint sequence arithmetic
//!   that do not fit in `i64` are [`PYTHON_INT_UNBOUNDED`], not a wrap and
//!   not a panic.
//! * [`EvidenceLookup::Borrowed`] is a failed borrow, not a missing
//!   `overflow` key ([`BORROWED_LOOKUP`]).
//! * [`EvidenceLookup::NotAMap`] is 0 for the overflow flag. Python would
//!   call `.get` on a non-mapping. [`Finding::try_new`] only stores a
//!   mapping or `None`.
//! * A float's Python `str` is not matched
//!   ([`PYTHON_FLOAT_STR_UNREPRESENTABLE`]). A list or mapping `str` is
//!   [`PYTHON_STR_UNREPRESENTABLE`]. A Python repr is not invented.
//! * [`SessionEvent::kind`] is a `String`. Python `None` on that attribute
//!   is [`EventValue::Other`]: missing kind on a non-mapping, and this
//!   branch does not read a mapping.
//! * Overflow [`make_finding`] does not produce a digest
//!   ([`FINGERPRINT_CODEC_UNAVAILABLE`]).
//! * A list of events has no `source` attribute.
//!   [`extract_run_state_projection`] and
//!   [`extract_run_state_checkpoints`] do not scan events.
//!   [`checkpoint_gap_records`] walks events for checkpoint and run-start
//!   kinds only.
//! * [`CheckContext::source_metadata`] is a [`BTreeMap`]. That candidate's
//!   own key order is sorted. A serde_json object nested inside a value
//!   keeps [`serde_json::Map`] order. This slice does not scan events to
//!   recover insertion order.
//! * [`extract_run_state_checkpoints`] does not call
//!   [`extract_run_state_projection`] or [`make_finding`].
//!   [`checkpoint_gap_records`] calls both extractors and does not call
//!   [`make_finding`].
//! * A float nested in an attached `run_state` projection has no
//!   [`PyValue`] form. [`check_checkpoint_gap`] returns
//!   [`PYTHON_FLOAT_STR_UNREPRESENTABLE`] for that evidence and does not
//!   call [`make_finding`].
//! * A seq string with a non-ASCII character is
//!   [`PYTHON_ISDIGIT_UNICODE`]. Python `str.isdigit` accepts Unicode Nd.
//!   This slice does not guess a Unicode numeric value.
//! * A bool is not an int. An SL201 `at_index` of true does not become 1.
//!   An SL202 `seq` of true does not equal checkpoint seq 1. A float `seq`
//!   does not equal an int seq.
//! * A trigger index below 0 selects the first event index strictly greater
//!   than it. Index `-1` starts at event 0. Negative indexes do not wrap.
//! * [`EvidenceLookup::Borrowed`] while reading a prior finding is
//!   [`BORROWED_LOOKUP`], not a missing key.
//! * A float nested in a divergence `run_state` projection has no [`PyValue`]
//!   form. [`check_checkpoint_divergence`] returns
//!   [`PYTHON_FLOAT_STR_UNREPRESENTABLE`] and does not call [`make_finding`].
//! * [`coverage_pointer`] uses [`str::trim`]. Python `str.strip` also treats
//!   U+001C..=U+001F as space. A string of only those controls stays present.
//!   A failed payload-map borrow is [`BORROWED_LOOKUP`]. A non-string
//!   `covered_through_id` is `None`.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use model::canonical::{MapLookup, Payload, SessionEvent};
use model::codes::{Repairability, Severity, SL201, SL202, SL203};
use model::errors::FindingError;
use model::events::{
    EventField, EventMapping, EventValue, PYTHON_FLOAT_STR_UNREPRESENTABLE,
    PYTHON_STR_UNREPRESENTABLE,
};
use model::finding::{
    enforce_content_free_text, make_finding, Evidence, EvidenceLookup, Finding, MakeFindingInput,
    PyValue, SourceLine, SourceRef, FINGERPRINT_CODEC_UNAVAILABLE,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::context::CheckContext;

/// Python: `MAX_CHECKPOINT_FINDINGS`.
pub const MAX_CHECKPOINT_FINDINGS: i64 = 500;

/// Python: `_KIND_CHECKPOINT`.
pub const KIND_CHECKPOINT: &str = "checkpoint";

/// Python: `_KIND_RUN_START`. Membership only, source order.
pub const KIND_RUN_START: &[&str] = &["run_start", "run-start", "continuation"];

/// Python: `_KIND_COMPACTION`.
pub const KIND_COMPACTION: &str = "compaction_boundary";

/// Python: `_TOOL_KINDS`. Membership only, source order.
pub const TOOL_KINDS: &[&str] = &["tool_call", "tool_use", "tool_result"];

/// Python: `_MSG_SL201`.
pub const MSG_SL201: &str = "Checkpoint gap detected for record {record_id}";

/// Python: `_MSG_SL202`.
pub const MSG_SL202: &str = "Checkpoint divergence detected for record {record_id}";

/// Python: `_MSG_SL203`.
pub const MSG_SL203: &str = "Unsafe continuation across loss detected for record {record_id}";

/// Python: `_MSG_SL205`.
pub const MSG_SL205: &str = "Compaction coverage gap detected for record {record_id}";

/// Python: `_MSG_OVERFLOW`.
pub const MSG_OVERFLOW: &str = "Checkpoint check finding cap reached; remaining records truncated";

/// Python evidence `variant` for the overflow summary.
pub const VARIANT_OVERFLOW: &str = "overflow-summary";

/// Python `int` is unbounded; an `i64` overflow is not a wrap.
pub const PYTHON_INT_UNBOUNDED: &str =
    "Python ints are unbounded; an i64 overflow is not a wrap and not a panic";

/// [`EvidenceLookup::Borrowed`] is not a missing key.
pub const BORROWED_LOOKUP: &str = "A borrowed map lookup is not a missing key";

/// Python `str.isdigit` accepts Unicode Nd. This slice accepts ASCII `0`–`9`.
pub const PYTHON_ISDIGIT_UNICODE: &str = "seq string parsing accepts ASCII digits only. Python str.isdigit accepts Unicode Nd digits such as U+0661; those are rejected and are not treated as digits";

/// Failure from this slice. [`Display`] is the message only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointError {
    BorrowedLookup,
    PythonIntUnbounded,
    PythonFloatStr,
    PythonStr,
    PythonIsdigitUnicode,
    Finding(FindingError),
}

impl CheckpointError {
    pub fn message(&self) -> &str {
        match self {
            Self::BorrowedLookup => BORROWED_LOOKUP,
            Self::PythonIntUnbounded => PYTHON_INT_UNBOUNDED,
            Self::PythonFloatStr => PYTHON_FLOAT_STR_UNREPRESENTABLE,
            Self::PythonStr => PYTHON_STR_UNREPRESENTABLE,
            Self::PythonIsdigitUnicode => PYTHON_ISDIGIT_UNICODE,
            Self::Finding(error) => error.message(),
        }
    }
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for CheckpointError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Finding(error) => Some(error),
            Self::BorrowedLookup
            | Self::PythonIntUnbounded
            | Self::PythonFloatStr
            | Self::PythonStr
            | Self::PythonIsdigitUnicode => None,
        }
    }
}

impl From<FindingError> for CheckpointError {
    fn from(error: FindingError) -> Self {
        Self::Finding(error)
    }
}

/// Python `str(x)` inputs for [`compute_checkpoint_fingerprint`].
///
/// `str(True)` is `True`. A bool is not an int.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum CheckpointItem {
    Str(String),
    Bool(bool),
    Int(i64),
}

impl CheckpointItem {
    fn python_str(&self) -> String {
        match self {
            Self::Str(text) => text.clone(),
            Self::Bool(true) => "True".to_owned(),
            Self::Bool(false) => "False".to_owned(),
            Self::Int(number) => number.to_string(),
        }
    }

    /// A float is [`PYTHON_FLOAT_STR_UNREPRESENTABLE`]. A list or mapping is
    /// [`PYTHON_STR_UNREPRESENTABLE`]. `None` is not an item.
    pub fn from_field(field: &EventField) -> Result<Self, CheckpointError> {
        match field {
            EventField::Str(text) => Ok(Self::Str(text.clone())),
            EventField::Bool(flag) => Ok(Self::Bool(*flag)),
            EventField::Int(number) => Ok(Self::Int(*number)),
            EventField::Float(_) => Err(CheckpointError::PythonFloatStr),
            EventField::List(_) | EventField::Mapping(_) => Err(CheckpointError::PythonStr),
            EventField::Null => Err(CheckpointError::PythonStr),
        }
    }
}

impl From<&str> for CheckpointItem {
    fn from(value: &str) -> Self {
        Self::Str(value.to_owned())
    }
}

impl From<String> for CheckpointItem {
    fn from(value: String) -> Self {
        Self::Str(value)
    }
}

impl From<bool> for CheckpointItem {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<i64> for CheckpointItem {
    fn from(value: i64) -> Self {
        Self::Int(value)
    }
}

/// Python: `(checkpoint_id, seq, state_hash)`.
pub type CheckpointFields = (Option<String>, Option<i64>, Option<String>);

/// Python: `_safe_id`.
///
/// `None` is `"<redacted>"`. Any [`enforce_content_free_text`] error with
/// context `"id"` is `"<redacted>"`. Success keeps the original text,
/// including spaces.
pub fn safe_id(id_str: Option<&str>) -> String {
    match id_str {
        None => "<redacted>".to_owned(),
        Some(text) => match enforce_content_free_text(text, "id") {
            Ok(()) => text.to_owned(),
            Err(_) => "<redacted>".to_owned(),
        },
    }
}

/// Python: `_source_record_id`.
///
/// `None` stays `None`. Strip only to test emptiness. A whitespace-only
/// value is `None`. A non-empty strip returns [`safe_id`] of the original
/// text, so `"  a  "` stays `"  a  "`.
pub fn source_record_id(id_str: Option<&str>) -> Option<String> {
    let text = id_str?;
    if text.trim().is_empty() {
        None
    } else {
        Some(safe_id(Some(text)))
    }
}

/// Python: `compute_checkpoint_fingerprint`.
///
/// `sha256("{code}|{comma-join of sorted unique str(items)}")` then the
/// first 16 lowercase hex characters. Duplicates collapse. This does not
/// call [`make_finding`].
pub fn compute_checkpoint_fingerprint(
    code: &str,
    items: impl IntoIterator<Item = CheckpointItem>,
) -> String {
    let mut unique = BTreeSet::new();
    for item in items {
        unique.insert(item.python_str());
    }
    let mut content = String::from(code);
    content.push('|');
    let mut first = true;
    for item in &unique {
        if !first {
            content.push(',');
        }
        first = false;
        content.push_str(item);
    }
    hex16(Sha256::digest(content.as_bytes()))
}

/// Python: `_cap_finding_sort_key`.
///
/// `(code, 1 if evidence overflow is exactly JSON true else 0, record id,
/// fingerprint)`. Missing, `false`, `1`, and the string `"true"` are 0.
/// Record id is `source.record_id`, or `""` when it is missing. This does
/// not read `correlation_id`.
pub fn cap_finding_sort_key(
    finding: &Finding,
) -> Result<(String, i32, String, String), CheckpointError> {
    let is_overflow = overflow_flag(finding)?;
    let rec_id = finding.source().record_id().unwrap_or("").to_owned();
    Ok((
        finding.code().to_owned(),
        is_overflow,
        rec_id,
        finding.fingerprint().to_owned(),
    ))
}

/// Python: `cap_checkpoint_findings`.
///
/// Omitted `max_findings` is [`MAX_CHECKPOINT_FINDINGS`]. Omitted
/// `source_path` is `"<canonical>"`. Omitted `context` is
/// [`CheckContext::default`]. Comparison is the Python `<=`. A negative max
/// is not special-cased: an empty list with `max_findings == -1` takes the
/// overflow path because `0 <= -1` is false.
pub fn cap_checkpoint_findings(
    findings: Vec<Finding>,
    code: &str,
    max_findings: Option<i64>,
    source_path: Option<&str>,
    context: Option<&CheckContext>,
) -> Result<Vec<Finding>, CheckpointError> {
    let max_findings = max_findings.unwrap_or(MAX_CHECKPOINT_FINDINGS);

    let mut keyed = Vec::new();
    for finding in findings {
        let key = cap_finding_sort_key(&finding)?;
        keyed.push((key, finding));
    }
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    let sorted: Vec<Finding> = keyed.into_iter().map(|(_, finding)| finding).collect();

    let total_count = usize_to_i64(sorted.len())?;
    if total_count <= max_findings {
        return Ok(sorted);
    }

    let truncated_count = total_count
        .checked_sub(max_findings)
        .ok_or(CheckpointError::PythonIntUnbounded)?;
    let ctx = context.cloned().unwrap_or_default();
    let norm_source_path = source_path.unwrap_or("<canonical>").replace('\\', "/");
    let source = SourceRef::try_new(&norm_source_path, None, None)?;
    match make_finding(&MakeFindingInput {
        code: PyValue::string(code),
        severity: PyValue::severity(Severity::Warning),
        repairability: PyValue::repairability(Repairability::Manual),
        message_template: PyValue::string(MSG_OVERFLOW),
        template_args: PyValue::None,
        source: PyValue::source(source),
        related_ids: PyValue::tuple(Vec::new()),
        evidence: PyValue::map(vec![
            (PyValue::string("cap"), PyValue::int(max_findings)),
            (PyValue::string("overflow"), PyValue::bool_value(true)),
            (PyValue::string("total_count"), PyValue::int(total_count)),
            (
                PyValue::string("truncated_count"),
                PyValue::int(truncated_count),
            ),
            (
                PyValue::string("variant"),
                PyValue::string(VARIANT_OVERFLOW),
            ),
        ]),
        fingerprint: PyValue::None,
        adapter_id: Some(ctx.adapter_id().to_owned()),
        adapter_version: Some(ctx.adapter_version().to_owned()),
        profile_id: Some(ctx.profile_id().to_owned()),
        profile_version: Some(ctx.profile_version().to_owned()),
        ordinal: None,
        context: None,
    }) {
        Err(error) => Err(error.into()),
        Ok(_finding) => Err(CheckpointError::Finding(FindingError::new(
            FINGERPRINT_CODEC_UNAVAILABLE,
        ))),
    }
}

/// Python: `_resolve_source_coords`.
///
/// If `default_path` is not exactly `"<canonical>"`, use it. If it is
/// `"<canonical>"` and location is missing or Python-falsy, use
/// `"<canonical>"`. Else the string form of the location, then replace
/// backslashes. A line is kept only for a non-bool int ≥ 1.
pub fn resolve_source_coords(
    event: &EventValue,
    default_path: &str,
) -> Result<(String, Option<i64>), CheckpointError> {
    let first_loc = source_field(event, "source_location");
    let resolved_path = if default_path != "<canonical>" {
        default_path.to_owned()
    } else if let Some(field) = first_loc.as_ref() {
        match location_text(field)? {
            Some(text) => text,
            None => default_path.to_owned(),
        }
    } else {
        default_path.to_owned()
    }
    .replace('\\', "/");

    let raw_line = source_field(event, "source_line");
    let line_num = match raw_line {
        Some(EventField::Int(number)) if number >= 1 => Some(number),
        _ => None,
    };
    Ok((resolved_path, line_num))
}

/// Python: `_get_event_kind`.
///
/// A [`SessionEvent`] uses its `kind` field only. [`EventValue::Other`] is
/// missing kind on a non-mapping (`None` stays `None`) and does not read a
/// mapping. A mapping uses `kind`. Bool true is `"True"`. An int is decimal.
/// A float or list is a typed error. An empty string is kept.
pub fn get_event_kind(event: &EventValue) -> Result<Option<String>, CheckpointError> {
    match event {
        EventValue::Session(session) => {
            optional_python_str(Some(&EventField::Str(session.kind.clone())))
        }
        EventValue::Mapping(mapping) => optional_python_str(mapping.get("kind")),
        EventValue::Other => Ok(None),
    }
}

/// Python: `_get_event_id`.
///
/// A [`SessionEvent`] returns its id string, including empty. A mapping
/// returns the raw id, including a non-string. Missing is `None`. This does
/// not stringify.
pub fn get_event_id(event: &EventValue) -> Option<EventField> {
    match event {
        EventValue::Session(session) => Some(EventField::Str(session.id.clone())),
        EventValue::Mapping(mapping) => match mapping.get("id") {
            None | Some(EventField::Null) => None,
            Some(value) => Some(value.clone()),
        },
        EventValue::Other => None,
    }
}

/// Python: `_extract_checkpoint_fields`.
///
/// Returns `(checkpoint_id, seq, state_hash)`. A payload `seq` of `None`
/// still falls through to the event `seq` field. A payload `seq` of `0`
/// does not. A bool `seq` is kept as the chosen value and then rejected by
/// the int test.
pub fn extract_checkpoint_fields(event: &EventValue) -> Result<CheckpointFields, CheckpointError> {
    let mut chk_id: Option<EventField> = None;
    let mut seq: Option<EventField> = None;
    let mut state_hash: Option<EventField> = None;

    match event {
        EventValue::Session(session) => {
            if session.payload.is_map() {
                pull_payload_fields(&session.payload, &mut chk_id, &mut seq, &mut state_hash)?;
            }
        }
        EventValue::Mapping(mapping) => {
            if let Some(EventField::Mapping(payload)) = mapping.get("payload") {
                pull_mapping_payload_fields(payload, &mut chk_id, &mut seq, &mut state_hash);
            }
        }
        EventValue::Other => {}
    }

    if chk_id.is_none() {
        chk_id = event_attr_then_mapping(event, session_checkpoint_id, "checkpoint_id");
    }
    if seq.is_none() {
        seq = event_attr_then_mapping(event, session_seq, "seq");
    }
    if state_hash.is_none() {
        state_hash = event_attr_then_mapping(event, session_state_hash, "state_hash");
    }

    let chk_id_str = match chk_id.as_ref() {
        None => None,
        Some(field) => python_str_keep_original(field)?,
    };
    let seq_val = match seq.as_ref() {
        Some(EventField::Int(number)) => Some(*number),
        _ => None,
    };
    let hash_str = match state_hash.as_ref() {
        None => None,
        Some(field) => python_str_keep_original(field)?,
    };
    Ok((chk_id_str, seq_val, hash_str))
}

/// Python: `_extract_run_state_projection`.
///
/// An explicit mapping argument, including an empty one, returns a copy and
/// does not look further. Otherwise look at `context.source_metadata` when
/// it is a mapping. A list of events has no `source` attribute.
pub fn extract_run_state_projection(
    context: Option<&CheckContext>,
    events: Option<&[EventValue]>,
    run_state_projection: Option<&EventMapping>,
) -> Result<Option<EventMapping>, CheckpointError> {
    if let Some(projection) = run_state_projection {
        return Ok(Some(projection.clone()));
    }
    // A list of events has no `source` attribute. Do not scan events.
    let _ = events;

    let Some(meta) = context.and_then(CheckContext::source_metadata) else {
        return Ok(None);
    };

    if let Some(Value::Object(cached_proj)) = meta.get("run_state_projection") {
        if json_truthy(cached_proj.get("keys")) || json_truthy(cached_proj.get("checkpoints")) {
            return Ok(Some(json_object_to_mapping(cached_proj)?));
        }
    }
    if meta.contains_key("keys")
        && meta.contains_key("shapes")
        && (json_truthy(meta.get("keys")) || json_truthy(meta.get("checkpoints")))
    {
        return Ok(Some(btree_to_mapping(meta)?));
    }
    Ok(None)
}

/// Python: `_extract_run_state_checkpoints`.
///
/// Does not call [`extract_run_state_projection`]. A list of events has no
/// `.source`. Do not scan `events`. An empty checkpoints list is a found
/// sequence: later fallbacks are not read. A string or bytes `checkpoints`
/// value is not a sequence of items.
///
/// `source_metadata` is a [`BTreeMap`], so that candidate's own key order
/// is sorted. A serde_json object nested inside a value keeps
/// [`serde_json::Map`] order. Do not scan events to recover insertion order.
///
/// Each record has keys `hash`, `id`, `index`, `seq` in that order. This
/// function does not call [`make_finding`].
pub fn extract_run_state_checkpoints(
    context: Option<&CheckContext>,
    events: Option<&[EventValue]>,
    run_state_projection: Option<&EventMapping>,
) -> Result<Vec<EventMapping>, CheckpointError> {
    // A list of events has no `source` attribute. Do not scan events.
    let _ = events;

    let mut raw_list: Option<RawCheckpointList<'_>> = None;
    let meta = context.and_then(CheckContext::source_metadata);
    if let Some(candidate) = meta {
        raw_list = sequence_from_candidate(candidate);
    }

    if raw_list.is_none() {
        if let Some(projection) = run_state_projection {
            if let Some(items) = field_as_sequence(projection.get("checkpoints")) {
                raw_list = Some(RawCheckpointList::Fields(items));
            }
        }
    }

    if raw_list.is_none() {
        if let Some(candidate) = meta {
            if let Some(Value::Object(rsp)) = candidate.get("run_state_projection") {
                if let Some(items) = json_as_sequence(rsp.get("checkpoints")) {
                    raw_list = Some(RawCheckpointList::Json(items));
                }
            }
        }
    }

    let Some(raw_list) = raw_list else {
        return Ok(Vec::new());
    };
    if raw_list.is_empty() {
        return Ok(Vec::new());
    }

    match raw_list {
        RawCheckpointList::Json(items) => records_from_json_items(items),
        RawCheckpointList::Fields(items) => records_from_field_items(items),
    }
}

/// One SL201 gap. Does not call [`make_finding`].
///
/// Evidence key order is [`CheckpointGapRecord::evidence_keys`]: `at_index`,
/// `expected_seq`, `found_seq`, then `sensitivity` when present, then
/// `source` when present, then `run_state` when the projection result is
/// [`Some`], including an empty mapping.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckpointGapRecord {
    pub code: &'static str,
    pub severity: Severity,
    pub repairability: Repairability,
    pub message_template: &'static str,
    pub path: String,
    pub line: Option<i64>,
    pub record_id: Option<String>,
    pub at_index: i64,
    pub expected_seq: i64,
    pub found_seq: Option<i64>,
    pub source: Option<String>,
    pub sensitivity: Option<String>,
    pub run_state: Option<EventMapping>,
    pub adapter_id: String,
    pub adapter_version: String,
    pub profile_id: String,
    pub profile_version: String,
}

impl CheckpointGapRecord {
    /// Evidence keys in insertion order.
    pub fn evidence_keys(&self) -> Vec<&'static str> {
        let mut keys = Vec::with_capacity(6);
        keys.push("at_index");
        keys.push("expected_seq");
        keys.push("found_seq");
        if self.sensitivity.is_some() {
            keys.push("sensitivity");
        }
        if self.source.is_some() {
            keys.push("source");
        }
        if self.run_state.is_some() {
            keys.push("run_state");
        }
        keys
    }
}

/// Gap rows for [`check_checkpoint_gap`], before the cap.
///
/// Omitted `source_path` is `"<canonical>"`. Omitted
/// `checkpoint_sensitivity` is `"default"`. Omitted `context` is
/// [`CheckContext::default`]. Typed errors from the two run-state
/// extractors propagate before any row. Does not call [`make_finding`].
pub fn checkpoint_gap_records(
    events: &[EventValue],
    source_path: Option<&str>,
    checkpoint_sensitivity: Option<&str>,
    context: Option<&CheckContext>,
    run_state_projection: Option<&EventMapping>,
) -> Result<Vec<CheckpointGapRecord>, CheckpointError> {
    let source_path = source_path.unwrap_or("<canonical>");
    let sensitivity = checkpoint_sensitivity.unwrap_or("default");
    let owned_ctx;
    let ctx = match context {
        Some(value) => value,
        None => {
            owned_ctx = CheckContext::default();
            &owned_ctx
        }
    };
    let projection = extract_run_state_projection(Some(ctx), Some(events), run_state_projection)?;
    let rs_checkpoints =
        extract_run_state_checkpoints(Some(ctx), Some(events), run_state_projection)?;
    let event_seqs = event_checkpoint_seqs(events)?;
    let min_event_seq = event_seqs.iter().next().copied();
    let sorted = sort_run_state(rs_checkpoints)?;
    let build = GapCtx {
        events,
        source_path,
        sensitivity,
        context: ctx,
        projection: projection.as_ref(),
        event_seqs: &event_seqs,
    };
    let mut records = Vec::new();
    let last_rs_seq = build.append_run_state(&mut records, &sorted)?;
    let last_checkpoint_seq = seed_last_checkpoint_seq(&sorted, min_event_seq, last_rs_seq)?;
    let has_seen_checkpoint = !sorted.is_empty();
    build.append_events(&mut records, has_seen_checkpoint, last_checkpoint_seq)?;
    Ok(records)
}

/// Python: `check_checkpoint_gap`.
///
/// An empty gap list calls [`cap_checkpoint_findings`] and returns that
/// result. A non-empty list calls [`make_finding`] once with the fingerprint
/// omitted and returns [`FINGERPRINT_CODEC_UNAVAILABLE`]. The kept prefix is
/// not returned. A digest is not invented. [`cap_checkpoint_findings`] is
/// not called on that path.
pub fn check_checkpoint_gap(
    events: &[EventValue],
    source_path: Option<&str>,
    max_findings: Option<i64>,
    checkpoint_sensitivity: Option<&str>,
    context: Option<&CheckContext>,
    run_state_projection: Option<&EventMapping>,
) -> Result<Vec<Finding>, CheckpointError> {
    let records = checkpoint_gap_records(
        events,
        source_path,
        checkpoint_sensitivity,
        context,
        run_state_projection,
    )?;
    match records.first() {
        None => cap_checkpoint_findings(Vec::new(), SL201, max_findings, source_path, context),
        Some(record) => emit_first_gap(record),
    }
}

/// One SL202 divergence. Does not call [`make_finding`].
///
/// Run-state evidence keys are `hash_a`, `hash_b`, `seq`, `source`, then
/// `run_state` when the projection result is [`Some`], including an empty
/// mapping. Event evidence omits `source` and appends `run_state` in the same
/// case. `hash_a` and `hash_b` are the first 16 characters. A shorter hash
/// stays whole. The seen-seq map stores the full hash.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckpointDivergenceRecord {
    pub code: &'static str,
    pub severity: Severity,
    pub repairability: Repairability,
    pub message_template: &'static str,
    pub path: String,
    pub line: Option<i64>,
    pub record_id: Option<String>,
    pub hash_a: String,
    pub hash_b: String,
    pub seq: i64,
    pub source: Option<String>,
    pub run_state: Option<EventMapping>,
    pub adapter_id: String,
    pub adapter_version: String,
    pub profile_id: String,
    pub profile_version: String,
}

impl CheckpointDivergenceRecord {
    /// Evidence keys in insertion order.
    pub fn evidence_keys(&self) -> Vec<&'static str> {
        let mut keys = Vec::with_capacity(5);
        keys.push("hash_a");
        keys.push("hash_b");
        keys.push("seq");
        if self.source.is_some() {
            keys.push("source");
        }
        if self.run_state.is_some() {
            keys.push("run_state");
        }
        keys
    }
}

/// Divergence rows for [`check_checkpoint_divergence`], before the cap.
///
/// Omitted `source_path` is `"<canonical>"`. Omitted `context` is
/// [`CheckContext::default`]. Typed errors from the two run-state extractors
/// propagate before any row. Does not call [`make_finding`].
pub fn checkpoint_divergence_records(
    events: &[EventValue],
    source_path: Option<&str>,
    context: Option<&CheckContext>,
    run_state_projection: Option<&EventMapping>,
) -> Result<Vec<CheckpointDivergenceRecord>, CheckpointError> {
    let source_path = source_path.unwrap_or("<canonical>");
    let mut slot = None;
    let ctx = borrowed_context(context, &mut slot);
    let projection = extract_run_state_projection(Some(ctx), Some(events), run_state_projection)?;
    let rs_checkpoints =
        extract_run_state_checkpoints(Some(ctx), Some(events), run_state_projection)?;
    let sorted = sort_run_state(rs_checkpoints)?;
    let build = DivergenceBuild {
        source_path,
        context: ctx,
        projection: projection.as_ref(),
    };
    let mut seen = BTreeMap::new();
    let mut records = Vec::new();
    push_run_state_divergence(&mut seen, &mut records, &build, &sorted)?;
    push_event_divergence(&mut seen, &mut records, &build, events)?;
    Ok(records)
}

/// Python: `check_checkpoint_divergence`.
///
/// An empty divergence list calls [`cap_checkpoint_findings`] with [`SL202`].
/// A non-empty list calls [`make_finding`] once with the fingerprint omitted
/// and returns [`FINGERPRINT_CODEC_UNAVAILABLE`]. A digest is not invented.
/// [`cap_checkpoint_findings`] is not called on that path.
pub fn check_checkpoint_divergence(
    events: &[EventValue],
    source_path: Option<&str>,
    max_findings: Option<i64>,
    context: Option<&CheckContext>,
    run_state_projection: Option<&EventMapping>,
) -> Result<Vec<Finding>, CheckpointError> {
    let records =
        checkpoint_divergence_records(events, source_path, context, run_state_projection)?;
    match records.first() {
        None => cap_checkpoint_findings(Vec::new(), SL202, max_findings, source_path, context),
        Some(record) => emit_divergence(record),
    }
}

/// Supplied SL201 priors. [`None`] recomputes via [`checkpoint_gap_records`].
///
/// An empty slice is supplied: it is not recomputed. [`Sl201Prior::Findings`]
/// reads evidence. A bool `at_index` is not an int.
#[derive(Clone, Copy, Debug)]
pub enum Sl201Prior<'a> {
    Records(&'a [CheckpointGapRecord]),
    Findings(&'a [Finding]),
}

/// Supplied SL202 priors. [`None`] recomputes via
/// [`checkpoint_divergence_records`].
///
/// An empty slice is supplied: it is not recomputed. A run-state row uses
/// index `-1`. Every exact checkpoint whose seq equals the prior seq is a
/// trigger, not only the first.
#[derive(Clone, Copy, Debug)]
pub enum Sl202Prior<'a> {
    Records(&'a [CheckpointDivergenceRecord]),
    Findings(&'a [Finding]),
}

/// The one SL203 continuation, or nothing. Does not call [`make_finding`].
///
/// Evidence keys are `caused_by`, then `first_unsafe_index`. `caused_by` is
/// the unique causes whose trigger index is strictly less than the unsafe
/// index, sorted by Unicode code point: `SL201`, `SL202`, `compaction`.
#[derive(Clone, Debug, PartialEq)]
pub struct UnsafeContinuationRecord {
    pub code: &'static str,
    pub severity: Severity,
    pub repairability: Repairability,
    pub message_template: &'static str,
    pub path: String,
    pub line: Option<i64>,
    pub record_id: Option<String>,
    pub caused_by: Vec<String>,
    pub first_unsafe_index: i64,
    pub adapter_id: String,
    pub adapter_version: String,
    pub profile_id: String,
    pub profile_version: String,
}

impl UnsafeContinuationRecord {
    /// Evidence keys in insertion order.
    pub fn evidence_keys(&self) -> Vec<&'static str> {
        vec!["caused_by", "first_unsafe_index"]
    }
}

/// Python: `check_unsafe_continuation`, before [`make_finding`].
///
/// Adapter `codex-rollout` returns [`None`] before events and priors are
/// read. Omitted priors use [`checkpoint_gap_records`] and
/// [`checkpoint_divergence_records`]. This does not call
/// [`check_checkpoint_gap`] or [`check_checkpoint_divergence`]. Does not call
/// [`make_finding`].
pub fn unsafe_continuation_record<'a>(
    events: &[EventValue],
    source_path: Option<&str>,
    prior_sl201: Option<Sl201Prior<'a>>,
    prior_sl202: Option<Sl202Prior<'a>>,
    context: Option<&CheckContext>,
) -> Result<Option<UnsafeContinuationRecord>, CheckpointError> {
    let source_path = source_path.unwrap_or("<canonical>");
    let mut slot = None;
    let ctx = borrowed_context(context, &mut slot);
    if ctx.adapter_id() == "codex-rollout" {
        return Ok(None);
    }
    let mut triggers = Vec::new();
    extend_sl201(&mut triggers, events, source_path, ctx, prior_sl201)?;
    extend_sl202(&mut triggers, events, source_path, ctx, prior_sl202)?;
    append_compaction_triggers(&mut triggers, events, ctx)?;
    finish_continuation(&triggers, events, source_path, ctx)
}

/// Python: `check_unsafe_continuation`.
///
/// No record is `Ok([])` and does not call [`cap_checkpoint_findings`]. One
/// record calls [`make_finding`] once with the fingerprint omitted and
/// returns [`FINGERPRINT_CODEC_UNAVAILABLE`]. The finding is not returned.
pub fn check_unsafe_continuation<'a>(
    events: &[EventValue],
    source_path: Option<&str>,
    prior_sl201: Option<Sl201Prior<'a>>,
    prior_sl202: Option<Sl202Prior<'a>>,
    context: Option<&CheckContext>,
) -> Result<Vec<Finding>, CheckpointError> {
    match unsafe_continuation_record(events, source_path, prior_sl201, prior_sl202, context)? {
        None => Ok(Vec::new()),
        Some(record) => emit_continuation(&record),
    }
}

/// Python: `_coverage_pointer`.
///
/// A [`SessionEvent`] reads `extra_fields`. A mapping reads the
/// `extra_fields` key. `covered_through_id` is returned only when it is a
/// string whose trim is nonempty. The original string is kept, including
/// surrounding spaces. A non-string is [`None`], not a typed error. Does not
/// call [`make_finding`].
pub fn coverage_pointer(event: &EventValue) -> Result<Option<String>, CheckpointError> {
    match event {
        EventValue::Session(session) => coverage_from_payload(&session.extra_fields),
        EventValue::Mapping(mapping) => Ok(coverage_from_event_mapping(mapping)),
        EventValue::Other => Ok(None),
    }
}

const CAUSE_COMPACTION: &str = "compaction";

fn borrowed_context<'a>(
    context: Option<&'a CheckContext>,
    slot: &'a mut Option<CheckContext>,
) -> &'a CheckContext {
    match context {
        Some(value) => value,
        None => slot.get_or_insert_with(CheckContext::default),
    }
}

struct DivergenceBuild<'a> {
    source_path: &'a str,
    context: &'a CheckContext,
    projection: Option<&'a EventMapping>,
}

struct DivergenceSpot<'a> {
    path: &'a str,
    line: Option<i64>,
    record_id: Option<&'a str>,
    source: Option<&'static str>,
}

impl DivergenceBuild<'_> {
    fn make(
        &self,
        spot: DivergenceSpot<'_>,
        hash_a: String,
        hash_b: String,
        seq: i64,
    ) -> CheckpointDivergenceRecord {
        CheckpointDivergenceRecord {
            code: SL202,
            severity: Severity::Error,
            repairability: Repairability::Manual,
            message_template: MSG_SL202,
            path: spot.path.to_owned(),
            line: spot.line,
            record_id: spot.record_id.map(str::to_owned),
            hash_a,
            hash_b,
            seq,
            source: spot.source.map(str::to_owned),
            run_state: self.projection.cloned(),
            adapter_id: self.context.adapter_id().to_owned(),
            adapter_version: self.context.adapter_version().to_owned(),
            profile_id: self.context.profile_id().to_owned(),
            profile_version: self.context.profile_version().to_owned(),
        }
    }
}

fn push_run_state_divergence(
    seen: &mut BTreeMap<i64, String>,
    records: &mut Vec<CheckpointDivergenceRecord>,
    build: &DivergenceBuild<'_>,
    sorted: &[EventMapping],
) -> Result<(), CheckpointError> {
    for record in sorted {
        let raw_id = normalized_id(record)?;
        let record_id = source_record_id(raw_id.as_deref());
        let seq = normalized_seq(record)?;
        let state_hash = divergence_hash(record)?;
        let (Some(seq), Some(state_hash)) = (seq, state_hash) else {
            continue;
        };
        note_hash(
            seen,
            records,
            build,
            seq,
            state_hash,
            DivergenceSpot {
                path: build.source_path,
                line: Some(1),
                record_id: record_id.as_deref(),
                source: Some("run_state"),
            },
        );
    }
    Ok(())
}

fn push_event_divergence(
    seen: &mut BTreeMap<i64, String>,
    records: &mut Vec<CheckpointDivergenceRecord>,
    build: &DivergenceBuild<'_>,
    events: &[EventValue],
) -> Result<(), CheckpointError> {
    for (index, event) in events.iter().enumerate() {
        if !raw_kind_is_checkpoint(event) {
            continue;
        }
        let index = usize_to_i64(index)?;
        let (_id, seq, state_hash) = extract_checkpoint_fields(event)?;
        let (Some(seq), Some(state_hash)) = (seq, state_hash) else {
            continue;
        };
        let ev_id = event_id_string(event, index)?;
        let record_id = source_record_id(Some(&ev_id));
        let (path, line) = resolve_source_coords(event, build.source_path)?;
        note_hash(
            seen,
            records,
            build,
            seq,
            state_hash,
            DivergenceSpot {
                path: &path,
                line,
                record_id: record_id.as_deref(),
                source: None,
            },
        );
    }
    Ok(())
}

fn note_hash(
    seen: &mut BTreeMap<i64, String>,
    records: &mut Vec<CheckpointDivergenceRecord>,
    build: &DivergenceBuild<'_>,
    seq: i64,
    state_hash: String,
    spot: DivergenceSpot<'_>,
) {
    if let Some(previous) = seen.get(&seq) {
        if previous != &state_hash {
            let hash_a = hash_prefix(previous);
            let hash_b = hash_prefix(&state_hash);
            records.push(build.make(spot, hash_a, hash_b, seq));
        }
    } else {
        seen.insert(seq, state_hash);
    }
}

fn hash_prefix(hash: &str) -> String {
    hash.chars().take(16).collect()
}

fn divergence_hash(record: &EventMapping) -> Result<Option<String>, CheckpointError> {
    match record.get("hash") {
        None | Some(EventField::Null) => Ok(None),
        Some(EventField::Str(text)) => Ok(Some(text.clone())),
        Some(EventField::Float(_)) => Err(CheckpointError::PythonFloatStr),
        Some(_) => Err(CheckpointError::PythonStr),
    }
}

fn extend_sl201(
    triggers: &mut Vec<(i64, &'static str)>,
    events: &[EventValue],
    source_path: &str,
    context: &CheckContext,
    prior: Option<Sl201Prior<'_>>,
) -> Result<(), CheckpointError> {
    match prior {
        Some(Sl201Prior::Records(records)) => {
            for record in records {
                triggers.push(sl201_record_trigger(record));
            }
            Ok(())
        }
        Some(Sl201Prior::Findings(findings)) => {
            for finding in findings {
                if let Some(trigger) = sl201_finding_trigger(finding)? {
                    triggers.push(trigger);
                }
            }
            Ok(())
        }
        None => {
            let records =
                checkpoint_gap_records(events, Some(source_path), None, Some(context), None)?;
            for record in &records {
                triggers.push(sl201_record_trigger(record));
            }
            Ok(())
        }
    }
}

fn extend_sl202(
    triggers: &mut Vec<(i64, &'static str)>,
    events: &[EventValue],
    source_path: &str,
    context: &CheckContext,
    prior: Option<Sl202Prior<'_>>,
) -> Result<(), CheckpointError> {
    match prior {
        Some(Sl202Prior::Records(records)) => {
            for record in records {
                append_sl202_record(triggers, record, events)?;
            }
            Ok(())
        }
        Some(Sl202Prior::Findings(findings)) => {
            for finding in findings {
                append_sl202_finding(triggers, finding, events)?;
            }
            Ok(())
        }
        None => {
            let records =
                checkpoint_divergence_records(events, Some(source_path), Some(context), None)?;
            for record in &records {
                append_sl202_record(triggers, record, events)?;
            }
            Ok(())
        }
    }
}

fn sl201_record_trigger(record: &CheckpointGapRecord) -> (i64, &'static str) {
    if record.source.as_deref() == Some("run_state") {
        (-1, SL201)
    } else {
        (record.at_index, SL201)
    }
}

fn sl201_finding_trigger(
    finding: &Finding,
) -> Result<Option<(i64, &'static str)>, CheckpointError> {
    let Some(evidence) = finding.evidence() else {
        return Ok(None);
    };
    if evidence_text_eq(evidence, "source", "run_state")? {
        return Ok(Some((-1, SL201)));
    }
    match evidence.map_string("at_index") {
        EvidenceLookup::Borrowed => Err(CheckpointError::BorrowedLookup),
        EvidenceLookup::Present(value) => Ok(non_bool_int(&value).map(|index| (index, SL201))),
        EvidenceLookup::Absent | EvidenceLookup::NotAMap => Ok(None),
    }
}

fn append_sl202_record(
    triggers: &mut Vec<(i64, &'static str)>,
    record: &CheckpointDivergenceRecord,
    events: &[EventValue],
) -> Result<(), CheckpointError> {
    if record.source.as_deref() == Some("run_state") {
        triggers.push((-1, SL202));
        return Ok(());
    }
    append_checkpoint_seq_matches(triggers, events, record.seq)
}

fn append_sl202_finding(
    triggers: &mut Vec<(i64, &'static str)>,
    finding: &Finding,
    events: &[EventValue],
) -> Result<(), CheckpointError> {
    let Some(evidence) = finding.evidence() else {
        return Ok(());
    };
    if evidence_text_eq(evidence, "source", "run_state")? {
        triggers.push((-1, SL202));
        return Ok(());
    }
    let seq = match evidence.map_string("seq") {
        EvidenceLookup::Borrowed => return Err(CheckpointError::BorrowedLookup),
        EvidenceLookup::Present(value) => non_bool_int(&value),
        EvidenceLookup::Absent | EvidenceLookup::NotAMap => None,
    };
    if let Some(seq) = seq {
        append_checkpoint_seq_matches(triggers, events, seq)?;
    }
    Ok(())
}

fn append_checkpoint_seq_matches(
    triggers: &mut Vec<(i64, &'static str)>,
    events: &[EventValue],
    seq: i64,
) -> Result<(), CheckpointError> {
    for (index, event) in events.iter().enumerate() {
        if !raw_kind_is_checkpoint(event) {
            continue;
        }
        let (_id, event_seq, _hash) = extract_checkpoint_fields(event)?;
        if event_seq == Some(seq) {
            triggers.push((usize_to_i64(index)?, SL202));
        }
    }
    Ok(())
}

fn append_compaction_triggers(
    triggers: &mut Vec<(i64, &'static str)>,
    events: &[EventValue],
    context: &CheckContext,
) -> Result<(), CheckpointError> {
    let mut checkpoint_indices = Vec::new();
    let mut compaction_indices = Vec::new();
    for (index, event) in events.iter().enumerate() {
        let index = usize_to_i64(index)?;
        match get_event_kind(event)? {
            Some(kind) if kind == KIND_CHECKPOINT => checkpoint_indices.push(index),
            Some(kind) if kind == KIND_COMPACTION => compaction_indices.push(index),
            _ => {}
        }
    }
    if !context.compaction_checkpoint_capable() {
        compaction_indices.clear();
    }
    for index in compaction_indices {
        let next = checkpoint_indices
            .iter()
            .copied()
            .filter(|checkpoint| *checkpoint > index)
            .min();
        let fire = match next {
            None => true,
            Some(next) => tool_between(events, index, next)?,
        };
        if fire {
            triggers.push((index, CAUSE_COMPACTION));
        }
    }
    Ok(())
}

fn tool_between(
    events: &[EventValue],
    start_after: i64,
    next: i64,
) -> Result<bool, CheckpointError> {
    let start = start_after
        .checked_add(1)
        .ok_or(CheckpointError::PythonIntUnbounded)?;
    if start < 0 || start >= next {
        return Ok(false);
    }
    let start_index = usize::try_from(start).map_err(|_| CheckpointError::PythonIntUnbounded)?;
    let end_index = usize::try_from(next).map_err(|_| CheckpointError::PythonIntUnbounded)?;
    let end_index = end_index.min(events.len());
    for event in events.iter().take(end_index).skip(start_index) {
        let kind = get_event_kind(event)?;
        if kind.as_deref().is_some_and(is_tool_kind) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn finish_continuation(
    triggers: &[(i64, &'static str)],
    events: &[EventValue],
    source_path: &str,
    context: &CheckContext,
) -> Result<Option<UnsafeContinuationRecord>, CheckpointError> {
    let Some(min_trigger) = triggers.iter().map(|(index, _)| *index).min() else {
        return Ok(None);
    };
    let Some((unsafe_index, unsafe_event)) = first_unsafe_tool(events, min_trigger)? else {
        return Ok(None);
    };
    let mut causes = BTreeSet::new();
    for (index, cause) in triggers {
        if *index < unsafe_index {
            causes.insert(*cause);
        }
    }
    let ev_id = event_id_string(unsafe_event, unsafe_index)?;
    let (path, line) = resolve_source_coords(unsafe_event, source_path)?;
    Ok(Some(UnsafeContinuationRecord {
        code: SL203,
        severity: Severity::Error,
        repairability: Repairability::Manual,
        message_template: MSG_SL203,
        path,
        line,
        record_id: source_record_id(Some(&ev_id)),
        caused_by: causes.into_iter().map(str::to_owned).collect(),
        first_unsafe_index: unsafe_index,
        adapter_id: context.adapter_id().to_owned(),
        adapter_version: context.adapter_version().to_owned(),
        profile_id: context.profile_id().to_owned(),
        profile_version: context.profile_version().to_owned(),
    }))
}

fn first_unsafe_tool(
    events: &[EventValue],
    min_trigger: i64,
) -> Result<Option<(i64, &EventValue)>, CheckpointError> {
    let start = if min_trigger < 0 {
        0
    } else {
        min_trigger
            .checked_add(1)
            .ok_or(CheckpointError::PythonIntUnbounded)?
    };
    let start_index = usize::try_from(start).map_err(|_| CheckpointError::PythonIntUnbounded)?;
    for (index, event) in events.iter().enumerate().skip(start_index) {
        if raw_kind_in_tools(event) {
            return Ok(Some((usize_to_i64(index)?, event)));
        }
    }
    Ok(None)
}

fn raw_kind_in_tools(event: &EventValue) -> bool {
    match event {
        EventValue::Session(session) => is_tool_kind(&session.kind),
        EventValue::Mapping(mapping) => match mapping.get("kind") {
            Some(EventField::Str(text)) => is_tool_kind(text),
            _ => false,
        },
        EventValue::Other => false,
    }
}

fn is_tool_kind(kind: &str) -> bool {
    TOOL_KINDS.contains(&kind)
}

fn evidence_text_eq(
    evidence: &Evidence,
    key: &str,
    expected: &str,
) -> Result<bool, CheckpointError> {
    match evidence.map_string(key) {
        EvidenceLookup::Borrowed => Err(CheckpointError::BorrowedLookup),
        EvidenceLookup::Present(value) => Ok(value.as_str() == Some(expected)),
        EvidenceLookup::Absent | EvidenceLookup::NotAMap => Ok(false),
    }
}

fn non_bool_int(value: &Evidence) -> Option<i64> {
    if value.as_bool().is_some() {
        None
    } else {
        value.as_int()
    }
}

fn coverage_from_payload(extra: &Payload) -> Result<Option<String>, CheckpointError> {
    let Some(coverage) = payload_field(extra, "coverage")? else {
        return Ok(None);
    };
    if !coverage.is_map() {
        return Ok(None);
    }
    let Some(pointer) = payload_field(&coverage, "covered_through_id")? else {
        return Ok(None);
    };
    Ok(pointer.as_str().and_then(pointer_text))
}

fn coverage_from_event_mapping(mapping: &EventMapping) -> Option<String> {
    let extra = match mapping.get("extra_fields") {
        Some(EventField::Mapping(extra)) => extra,
        _ => return None,
    };
    let coverage = match extra.get("coverage") {
        Some(EventField::Mapping(coverage)) => coverage,
        _ => return None,
    };
    match coverage.get("covered_through_id") {
        Some(EventField::Str(text)) => pointer_text(text),
        _ => None,
    }
}

fn payload_field(map: &Payload, key: &str) -> Result<Option<Payload>, CheckpointError> {
    match map.map_string(key) {
        MapLookup::Borrowed => Err(CheckpointError::BorrowedLookup),
        MapLookup::Present(value) => Ok(Some(value)),
        MapLookup::Absent | MapLookup::NotAMap => Ok(None),
    }
}

fn pointer_text(text: &str) -> Option<String> {
    if text.trim().is_empty() {
        None
    } else {
        Some(text.to_owned())
    }
}

fn emit_divergence(record: &CheckpointDivergenceRecord) -> Result<Vec<Finding>, CheckpointError> {
    let evidence = divergence_evidence(record)?;
    let source = SourceRef::try_new(
        &record.path,
        record.line.map(SourceLine::Int),
        record.record_id.as_deref(),
    )?;
    omitted_fingerprint(make_finding(&MakeFindingInput {
        code: PyValue::string(record.code),
        severity: PyValue::severity(record.severity),
        repairability: PyValue::repairability(record.repairability),
        message_template: PyValue::string(record.message_template),
        template_args: PyValue::None,
        source: PyValue::source(source),
        related_ids: PyValue::tuple(Vec::new()),
        evidence,
        fingerprint: PyValue::None,
        adapter_id: Some(record.adapter_id.clone()),
        adapter_version: Some(record.adapter_version.clone()),
        profile_id: Some(record.profile_id.clone()),
        profile_version: Some(record.profile_version.clone()),
        ordinal: None,
        context: None,
    }))
}

fn emit_continuation(record: &UnsafeContinuationRecord) -> Result<Vec<Finding>, CheckpointError> {
    let evidence = continuation_evidence(record);
    let source = SourceRef::try_new(
        &record.path,
        record.line.map(SourceLine::Int),
        record.record_id.as_deref(),
    )?;
    omitted_fingerprint(make_finding(&MakeFindingInput {
        code: PyValue::string(record.code),
        severity: PyValue::severity(record.severity),
        repairability: PyValue::repairability(record.repairability),
        message_template: PyValue::string(record.message_template),
        template_args: PyValue::None,
        source: PyValue::source(source),
        related_ids: PyValue::tuple(Vec::new()),
        evidence,
        fingerprint: PyValue::None,
        adapter_id: Some(record.adapter_id.clone()),
        adapter_version: Some(record.adapter_version.clone()),
        profile_id: Some(record.profile_id.clone()),
        profile_version: Some(record.profile_version.clone()),
        ordinal: None,
        context: None,
    }))
}

fn omitted_fingerprint(
    result: Result<Finding, FindingError>,
) -> Result<Vec<Finding>, CheckpointError> {
    match result {
        Err(error) => Err(error.into()),
        Ok(_finding) => Err(CheckpointError::Finding(FindingError::new(
            FINGERPRINT_CODEC_UNAVAILABLE,
        ))),
    }
}

fn divergence_evidence(record: &CheckpointDivergenceRecord) -> Result<PyValue, CheckpointError> {
    let keys = record.evidence_keys();
    let mut entries = Vec::with_capacity(keys.len());
    for key in keys {
        entries.push((PyValue::string(key), divergence_value(record, key)?));
    }
    Ok(PyValue::map(entries))
}

fn divergence_value(
    record: &CheckpointDivergenceRecord,
    key: &str,
) -> Result<PyValue, CheckpointError> {
    match key {
        "hash_a" => Ok(PyValue::string(record.hash_a.clone())),
        "hash_b" => Ok(PyValue::string(record.hash_b.clone())),
        "seq" => Ok(PyValue::int(record.seq)),
        "source" => match &record.source {
            Some(text) => Ok(PyValue::string(text.clone())),
            None => Err(CheckpointError::PythonStr),
        },
        "run_state" => match &record.run_state {
            Some(projection) => mapping_to_py(projection),
            None => Err(CheckpointError::PythonStr),
        },
        _ => Err(CheckpointError::PythonStr),
    }
}

fn continuation_evidence(record: &UnsafeContinuationRecord) -> PyValue {
    let causes = record
        .caused_by
        .iter()
        .cloned()
        .map(PyValue::string)
        .collect();
    PyValue::map(vec![
        (PyValue::string("caused_by"), PyValue::list(causes)),
        (
            PyValue::string("first_unsafe_index"),
            PyValue::int(record.first_unsafe_index),
        ),
    ])
}

struct GapParts<'a> {
    path: &'a str,
    line: Option<i64>,
    record_id: Option<&'a str>,
    at_index: i64,
    expected_seq: i64,
    found_seq: Option<i64>,
    source: Option<&'static str>,
    sensitivity: Option<&'static str>,
}

struct GapCtx<'a> {
    events: &'a [EventValue],
    source_path: &'a str,
    sensitivity: &'a str,
    context: &'a CheckContext,
    projection: Option<&'a EventMapping>,
    event_seqs: &'a BTreeSet<i64>,
}

impl GapCtx<'_> {
    fn push(&self, records: &mut Vec<CheckpointGapRecord>, parts: GapParts<'_>) {
        records.push(CheckpointGapRecord {
            code: SL201,
            severity: Severity::Error,
            repairability: Repairability::Manual,
            message_template: MSG_SL201,
            path: parts.path.to_owned(),
            line: parts.line,
            record_id: parts.record_id.map(str::to_owned),
            at_index: parts.at_index,
            expected_seq: parts.expected_seq,
            found_seq: parts.found_seq,
            source: parts.source.map(str::to_owned),
            sensitivity: parts.sensitivity.map(str::to_owned),
            run_state: self.projection.cloned(),
            adapter_id: self.context.adapter_id().to_owned(),
            adapter_version: self.context.adapter_version().to_owned(),
            profile_id: self.context.profile_id().to_owned(),
            profile_version: self.context.profile_version().to_owned(),
        });
    }

    fn append_run_state(
        &self,
        records: &mut Vec<CheckpointGapRecord>,
        sorted: &[EventMapping],
    ) -> Result<Option<i64>, CheckpointError> {
        let mut last_rs_seq: Option<i64> = None;
        for record in sorted {
            let seq = normalized_seq(record)?;
            let index = normalized_index(record)?;
            let raw_id = normalized_id(record)?;
            let rec_id = source_record_id(raw_id.as_deref());
            let covered = seq.is_some_and(|value| self.event_seqs.contains(&value));
            let missing_hash = normalized_hash_missing(record);
            if missing_hash && !covered {
                self.push(
                    records,
                    GapParts {
                        path: self.source_path,
                        line: Some(1),
                        record_id: rec_id.as_deref(),
                        at_index: index,
                        expected_seq: next_seq(last_rs_seq)?,
                        found_seq: seq,
                        source: Some("run_state"),
                        sensitivity: None,
                    },
                );
            }
            if let Some(value) = seq {
                // A covered seq emits neither gap, then still advances `last_rs_seq`.
                if !covered {
                    if let Some(last) = last_rs_seq {
                        if seq_jumps(value, last)? {
                            self.push(
                                records,
                                GapParts {
                                    path: self.source_path,
                                    line: Some(1),
                                    record_id: rec_id.as_deref(),
                                    at_index: index,
                                    expected_seq: next_seq(Some(last))?,
                                    found_seq: Some(value),
                                    source: Some("run_state"),
                                    sensitivity: None,
                                },
                            );
                        }
                    }
                }
                last_rs_seq = Some(value);
            } else if self.sensitivity == "high" {
                self.push(
                    records,
                    GapParts {
                        path: self.source_path,
                        line: Some(1),
                        record_id: rec_id.as_deref(),
                        at_index: index,
                        expected_seq: next_seq(last_rs_seq)?,
                        found_seq: None,
                        source: Some("run_state"),
                        sensitivity: Some("high"),
                    },
                );
            }
        }
        Ok(last_rs_seq)
    }

    fn append_events(
        &self,
        records: &mut Vec<CheckpointGapRecord>,
        mut has_seen_checkpoint: bool,
        mut last_checkpoint_seq: Option<i64>,
    ) -> Result<(), CheckpointError> {
        for (idx, event) in self.events.iter().enumerate() {
            let idx = usize_to_i64(idx)?;
            let kind = get_event_kind(event)?.unwrap_or_else(|| "unknown".to_owned());
            let run_start = is_run_start_kind(&kind);
            if !run_start && kind != KIND_CHECKPOINT {
                continue;
            }
            let ev_id = event_id_string(event, idx)?;
            let rec_id = source_record_id(Some(&ev_id));
            let (path, line) = resolve_source_coords(event, self.source_path)?;
            if run_start {
                if !has_seen_checkpoint {
                    self.push(
                        records,
                        GapParts {
                            path: &path,
                            line,
                            record_id: rec_id.as_deref(),
                            at_index: idx,
                            expected_seq: 0,
                            found_seq: None,
                            source: None,
                            sensitivity: None,
                        },
                    );
                }
                continue;
            }
            let (_chk_id, seq, state_hash) = extract_checkpoint_fields(event)?;
            has_seen_checkpoint = true;
            if state_hash.as_ref().is_none_or(String::is_empty) {
                self.push(
                    records,
                    GapParts {
                        path: &path,
                        line,
                        record_id: rec_id.as_deref(),
                        at_index: idx,
                        expected_seq: next_seq(last_checkpoint_seq)?,
                        found_seq: seq,
                        source: None,
                        sensitivity: None,
                    },
                );
            }
            if let Some(value) = seq {
                if let Some(last) = last_checkpoint_seq {
                    if seq_jumps(value, last)? {
                        self.push(
                            records,
                            GapParts {
                                path: &path,
                                line,
                                record_id: rec_id.as_deref(),
                                at_index: idx,
                                expected_seq: next_seq(Some(last))?,
                                found_seq: Some(value),
                                source: None,
                                sensitivity: None,
                            },
                        );
                    }
                }
                last_checkpoint_seq = Some(value);
            } else if self.sensitivity == "high" {
                // A null seq does not advance `last_checkpoint_seq`.
                self.push(
                    records,
                    GapParts {
                        path: &path,
                        line,
                        record_id: rec_id.as_deref(),
                        at_index: idx,
                        expected_seq: next_seq(last_checkpoint_seq)?,
                        found_seq: None,
                        source: None,
                        sensitivity: Some("high"),
                    },
                );
            }
        }
        Ok(())
    }
}

fn emit_first_gap(record: &CheckpointGapRecord) -> Result<Vec<Finding>, CheckpointError> {
    let evidence = gap_evidence(record)?;
    let source = SourceRef::try_new(
        &record.path,
        record.line.map(SourceLine::Int),
        record.record_id.as_deref(),
    )?;
    match make_finding(&MakeFindingInput {
        code: PyValue::string(record.code),
        severity: PyValue::severity(record.severity),
        repairability: PyValue::repairability(record.repairability),
        message_template: PyValue::string(record.message_template),
        template_args: PyValue::None,
        source: PyValue::source(source),
        related_ids: PyValue::tuple(Vec::new()),
        evidence,
        fingerprint: PyValue::None,
        adapter_id: Some(record.adapter_id.clone()),
        adapter_version: Some(record.adapter_version.clone()),
        profile_id: Some(record.profile_id.clone()),
        profile_version: Some(record.profile_version.clone()),
        ordinal: None,
        context: None,
    }) {
        Err(error) => Err(error.into()),
        Ok(_finding) => Err(CheckpointError::Finding(FindingError::new(
            FINGERPRINT_CODEC_UNAVAILABLE,
        ))),
    }
}

fn gap_evidence(record: &CheckpointGapRecord) -> Result<PyValue, CheckpointError> {
    let keys = record.evidence_keys();
    let mut entries = Vec::with_capacity(keys.len());
    for key in keys {
        entries.push((PyValue::string(key), evidence_value(record, key)?));
    }
    Ok(PyValue::map(entries))
}

fn evidence_value(record: &CheckpointGapRecord, key: &str) -> Result<PyValue, CheckpointError> {
    match key {
        "at_index" => Ok(PyValue::int(record.at_index)),
        "expected_seq" => Ok(PyValue::int(record.expected_seq)),
        "found_seq" => Ok(match record.found_seq {
            Some(seq) => PyValue::int(seq),
            None => PyValue::None,
        }),
        "sensitivity" => match &record.sensitivity {
            Some(text) => Ok(PyValue::string(text.clone())),
            None => Err(CheckpointError::PythonStr),
        },
        "source" => match &record.source {
            Some(text) => Ok(PyValue::string(text.clone())),
            None => Err(CheckpointError::PythonStr),
        },
        "run_state" => match &record.run_state {
            Some(projection) => mapping_to_py(projection),
            None => Err(CheckpointError::PythonStr),
        },
        _ => Err(CheckpointError::PythonStr),
    }
}

fn mapping_to_py(mapping: &EventMapping) -> Result<PyValue, CheckpointError> {
    let mut entries = Vec::with_capacity(mapping.entries().len());
    for (key, value) in mapping.entries() {
        entries.push((PyValue::string(key.clone()), field_to_py(value)?));
    }
    Ok(PyValue::map(entries))
}

fn field_to_py(field: &EventField) -> Result<PyValue, CheckpointError> {
    match field {
        EventField::Null => Ok(PyValue::None),
        EventField::Bool(flag) => Ok(PyValue::bool_value(*flag)),
        EventField::Int(number) => Ok(PyValue::int(*number)),
        EventField::Float(_) => Err(CheckpointError::PythonFloatStr),
        EventField::Str(text) => Ok(PyValue::string(text.clone())),
        EventField::List(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(field_to_py(item)?);
            }
            Ok(PyValue::list(out))
        }
        EventField::Mapping(mapping) => mapping_to_py(mapping),
    }
}

fn event_checkpoint_seqs(events: &[EventValue]) -> Result<BTreeSet<i64>, CheckpointError> {
    let mut seqs = BTreeSet::new();
    for event in events {
        if !raw_kind_is_checkpoint(event) {
            continue;
        }
        let (_id, seq, _hash) = extract_checkpoint_fields(event)?;
        if let Some(seq) = seq {
            seqs.insert(seq);
        }
    }
    Ok(seqs)
}

/// Kind test for the event-checkpoint seq set only.
///
/// A [`SessionEvent`] uses its `kind` string. A mapping has no kind
/// attribute, so this reads the `kind` key and compares with `==`. It does
/// not stringify. Bool `true` is not [`KIND_CHECKPOINT`].
fn raw_kind_is_checkpoint(event: &EventValue) -> bool {
    match event {
        EventValue::Session(session) => session.kind == KIND_CHECKPOINT,
        EventValue::Mapping(mapping) => match mapping.get("kind") {
            Some(EventField::Str(text)) => text == KIND_CHECKPOINT,
            _ => false,
        },
        EventValue::Other => false,
    }
}

fn sort_run_state(records: Vec<EventMapping>) -> Result<Vec<EventMapping>, CheckpointError> {
    let mut keyed = Vec::with_capacity(records.len());
    for record in records {
        let seq = normalized_seq(&record)?;
        let index = normalized_index(&record)?;
        // Null seqs sort last. `false < true` matches Python `False < True`.
        keyed.push(((seq.is_none(), seq.unwrap_or(0), index), record));
    }
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(keyed.into_iter().map(|(_, record)| record).collect())
}

/// When `min_event_seq` is present and nothing is strictly smaller, the
/// baseline stays absent. This does not fall through to `last_rs_seq`.
fn seed_last_checkpoint_seq(
    sorted: &[EventMapping],
    min_event_seq: Option<i64>,
    last_rs_seq: Option<i64>,
) -> Result<Option<i64>, CheckpointError> {
    if sorted.is_empty() {
        return Ok(None);
    }
    if let Some(min_seq) = min_event_seq {
        let mut preceding: Option<i64> = None;
        for record in sorted {
            if let Some(seq) = normalized_seq(record)? {
                if seq < min_seq {
                    preceding = Some(match preceding {
                        Some(current) => current.max(seq),
                        None => seq,
                    });
                }
            }
        }
        return Ok(preceding);
    }
    Ok(last_rs_seq)
}

fn normalized_seq(record: &EventMapping) -> Result<Option<i64>, CheckpointError> {
    match record.get("seq") {
        None | Some(EventField::Null) | Some(EventField::Bool(_)) => Ok(None),
        Some(EventField::Int(number)) => Ok(Some(*number)),
        Some(EventField::Float(_)) => Err(CheckpointError::PythonFloatStr),
        Some(EventField::Str(_) | EventField::List(_) | EventField::Mapping(_)) => {
            Err(CheckpointError::PythonStr)
        }
    }
}

fn normalized_index(record: &EventMapping) -> Result<i64, CheckpointError> {
    match record.get("index") {
        Some(EventField::Int(number)) => Ok(*number),
        Some(EventField::Float(_)) => Err(CheckpointError::PythonFloatStr),
        _ => Err(CheckpointError::PythonStr),
    }
}

fn normalized_id(record: &EventMapping) -> Result<Option<String>, CheckpointError> {
    match record.get("id") {
        None | Some(EventField::Null) => Ok(None),
        Some(field) => Ok(Some(python_id_string(field)?)),
    }
}

fn normalized_hash_missing(record: &EventMapping) -> bool {
    match record.get("hash") {
        None | Some(EventField::Null) => true,
        Some(EventField::Str(text)) => text.is_empty(),
        Some(_) => false,
    }
}

fn next_seq(last: Option<i64>) -> Result<i64, CheckpointError> {
    match last {
        Some(seq) => seq
            .checked_add(1)
            .ok_or(CheckpointError::PythonIntUnbounded),
        None => Ok(0),
    }
}

fn seq_jumps(seq: i64, last: i64) -> Result<bool, CheckpointError> {
    let delta = seq
        .checked_sub(last)
        .ok_or(CheckpointError::PythonIntUnbounded)?;
    Ok(delta > 1)
}

fn event_id_string(event: &EventValue, index: i64) -> Result<String, CheckpointError> {
    match get_event_id(event) {
        None => Ok(format!("<event:{index}>")),
        Some(field) => python_id_string(&field),
    }
}

fn python_id_string(field: &EventField) -> Result<String, CheckpointError> {
    match field {
        EventField::Null => Ok("None".to_owned()),
        EventField::Bool(true) => Ok("True".to_owned()),
        EventField::Bool(false) => Ok("False".to_owned()),
        EventField::Int(number) => Ok(number.to_string()),
        EventField::Str(text) => Ok(text.clone()),
        EventField::Float(_) => Err(CheckpointError::PythonFloatStr),
        EventField::List(_) | EventField::Mapping(_) => Err(CheckpointError::PythonStr),
    }
}

fn is_run_start_kind(kind: &str) -> bool {
    KIND_RUN_START.contains(&kind)
}

enum RawCheckpointList<'a> {
    Json(&'a [Value]),
    Fields(&'a [EventField]),
}

impl RawCheckpointList<'_> {
    fn is_empty(&self) -> bool {
        match self {
            Self::Json(items) => items.is_empty(),
            Self::Fields(items) => items.is_empty(),
        }
    }
}

fn sequence_from_candidate(candidate: &BTreeMap<String, Value>) -> Option<RawCheckpointList<'_>> {
    if let Some(items) = json_as_sequence(candidate.get("checkpoints")) {
        return Some(RawCheckpointList::Json(items));
    }
    if let Some(Value::Object(run_state)) = candidate.get("run_state") {
        if let Some(items) = json_as_sequence(run_state.get("checkpoints")) {
            return Some(RawCheckpointList::Json(items));
        }
    }
    if let Some(Value::Object(inner)) = candidate.get("metadata") {
        if let Some(items) = json_as_sequence(inner.get("checkpoints")) {
            return Some(RawCheckpointList::Json(items));
        }
        if let Some(Value::Object(run_state)) = inner.get("run_state") {
            if let Some(items) = json_as_sequence(run_state.get("checkpoints")) {
                return Some(RawCheckpointList::Json(items));
            }
        }
    }
    None
}

fn json_as_sequence(value: Option<&Value>) -> Option<&[Value]> {
    match value {
        Some(Value::Array(items)) => Some(items.as_slice()),
        _ => None,
    }
}

fn field_as_sequence(value: Option<&EventField>) -> Option<&[EventField]> {
    match value {
        Some(EventField::List(items)) => Some(items.as_slice()),
        _ => None,
    }
}

fn records_from_json_items(items: &[Value]) -> Result<Vec<EventMapping>, CheckpointError> {
    let mut out = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let index = usize_to_i64(index)?;
        let event = match item {
            Value::Object(object) => EventValue::Mapping(json_object_to_mapping(object)?),
            _ => EventValue::Other,
        };
        out.push(record_from_event_value(&event, index)?);
    }
    Ok(out)
}

fn records_from_field_items(items: &[EventField]) -> Result<Vec<EventMapping>, CheckpointError> {
    let mut out = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let index = usize_to_i64(index)?;
        let event = match item {
            EventField::Mapping(mapping) => EventValue::Mapping(mapping.clone()),
            _ => EventValue::Other,
        };
        out.push(record_from_event_value(&event, index)?);
    }
    Ok(out)
}

fn record_from_event_value(item: &EventValue, index: i64) -> Result<EventMapping, CheckpointError> {
    let (chk_id, seq, state_hash) = match item {
        EventValue::Mapping(mapping) => mapping_run_state_fields(mapping),
        EventValue::Session(session) => session_run_state_fields(session),
        EventValue::Other => (None, None, None),
    };
    let chk_id_str = match chk_id.as_ref() {
        None => run_state_synth_id(index),
        Some(field) => match python_str_keep_original(field)? {
            Some(text) => text,
            None => run_state_synth_id(index),
        },
    };
    let seq_val = parse_run_state_seq(seq.as_ref())?;
    let hash_str = run_state_hash_str(state_hash.as_ref())?;
    Ok(run_state_record(hash_str, chk_id_str, index, seq_val))
}

fn mapping_run_state_fields(
    mapping: &EventMapping,
) -> (Option<EventField>, Option<EventField>, Option<EventField>) {
    let chk_id = match mapping.get("id") {
        None | Some(EventField::Null) => mapping.get("checkpoint_id").cloned(),
        Some(value) => Some(value.clone()),
    };
    let seq = if mapping_contains(mapping, "seq") {
        mapping.get("seq").cloned()
    } else if mapping_contains(mapping, "checkpoint_seq") {
        mapping.get("checkpoint_seq").cloned()
    } else {
        None
    };
    let state_hash = match mapping.get("hash") {
        None | Some(EventField::Null) => match mapping.get("state_hash") {
            None | Some(EventField::Null) => mapping.get("payload_hash").cloned(),
            Some(value) => Some(value.clone()),
        },
        Some(value) => Some(value.clone()),
    };
    (chk_id, seq, state_hash)
}

fn session_run_state_fields(
    session: &SessionEvent,
) -> (Option<EventField>, Option<EventField>, Option<EventField>) {
    // Fields the struct does not have stay missing. Do not read extra_fields.
    (
        Some(EventField::Str(session.id.clone())),
        Some(EventField::Int(session.seq)),
        None,
    )
}

fn run_state_synth_id(index: i64) -> String {
    format!("chk-runstate-{index}")
}

fn parse_run_state_seq(seq: Option<&EventField>) -> Result<Option<i64>, CheckpointError> {
    match seq {
        None
        | Some(EventField::Null)
        | Some(EventField::Bool(_))
        | Some(EventField::Float(_))
        | Some(EventField::List(_))
        | Some(EventField::Mapping(_)) => Ok(None),
        Some(EventField::Int(number)) => Ok(Some(*number)),
        Some(EventField::Str(text)) => parse_run_state_seq_str(text),
    }
}

fn parse_run_state_seq_str(text: &str) -> Result<Option<i64>, CheckpointError> {
    let stripped = text.trim();
    if stripped.is_empty() {
        return Ok(None);
    }
    if !stripped.is_ascii() {
        return Err(CheckpointError::PythonIsdigitUnicode);
    }
    if !stripped.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(None);
    }
    stripped
        .parse::<i64>()
        .map(Some)
        .map_err(|_| CheckpointError::PythonIntUnbounded)
}

fn run_state_hash_str(field: Option<&EventField>) -> Result<Option<String>, CheckpointError> {
    let Some(text) = optional_python_str(field)? else {
        return Ok(None);
    };
    let stripped = text.trim();
    if stripped.is_empty() || matches!(stripped, "<NoneType>" | "<null>" | "None" | "null") {
        Ok(None)
    } else {
        Ok(Some(stripped.to_owned()))
    }
}

fn run_state_record(
    hash: Option<String>,
    id: String,
    index: i64,
    seq: Option<i64>,
) -> EventMapping {
    EventMapping::new(vec![
        (
            "hash".to_owned(),
            match hash {
                Some(text) => EventField::Str(text),
                None => EventField::Null,
            },
        ),
        ("id".to_owned(), EventField::Str(id)),
        ("index".to_owned(), EventField::Int(index)),
        (
            "seq".to_owned(),
            match seq {
                Some(number) => EventField::Int(number),
                None => EventField::Null,
            },
        ),
    ])
}

fn overflow_flag(finding: &Finding) -> Result<i32, CheckpointError> {
    let Some(evidence) = finding.evidence() else {
        return Ok(0);
    };
    match evidence.map_string("overflow") {
        EvidenceLookup::Borrowed => Err(CheckpointError::BorrowedLookup),
        EvidenceLookup::Present(value) if value.as_bool() == Some(true) => Ok(1),
        EvidenceLookup::Present(_) | EvidenceLookup::Absent | EvidenceLookup::NotAMap => Ok(0),
    }
}

fn source_field(event: &EventValue, field: &str) -> Option<EventField> {
    match event {
        EventValue::Session(session) => match field {
            "source_location" => session.source_location.clone().map(EventField::Str),
            "source_line" => session.source_line.map(EventField::Int),
            _ => None,
        },
        EventValue::Mapping(mapping) => mapping.get(field).cloned(),
        EventValue::Other => None,
    }
}

fn location_text(field: &EventField) -> Result<Option<String>, CheckpointError> {
    match field {
        EventField::Null | EventField::Bool(false) => Ok(None),
        EventField::Bool(true) => Ok(Some("True".to_owned())),
        EventField::Int(0) => Ok(None),
        EventField::Int(number) => Ok(Some(number.to_string())),
        EventField::Str(text) if text.is_empty() => Ok(None),
        EventField::Str(text) => Ok(Some(text.clone())),
        EventField::Float(number) if *number == 0.0 => Ok(None),
        EventField::Float(_) => Err(CheckpointError::PythonFloatStr),
        EventField::List(items) if items.is_empty() => Ok(None),
        EventField::Mapping(mapping) if mapping.entries().is_empty() => Ok(None),
        EventField::List(_) | EventField::Mapping(_) => Err(CheckpointError::PythonStr),
    }
}

fn optional_python_str(value: Option<&EventField>) -> Result<Option<String>, CheckpointError> {
    match value {
        None | Some(EventField::Null) => Ok(None),
        Some(EventField::Bool(true)) => Ok(Some("True".to_owned())),
        Some(EventField::Bool(false)) => Ok(Some("False".to_owned())),
        Some(EventField::Int(number)) => Ok(Some(number.to_string())),
        Some(EventField::Str(text)) => Ok(Some(text.clone())),
        Some(EventField::Float(_)) => Err(CheckpointError::PythonFloatStr),
        Some(EventField::List(_) | EventField::Mapping(_)) => Err(CheckpointError::PythonStr),
    }
}

fn python_str_keep_original(field: &EventField) -> Result<Option<String>, CheckpointError> {
    let text = match field {
        EventField::Null => return Ok(None),
        EventField::Bool(true) => "True".to_owned(),
        EventField::Bool(false) => "False".to_owned(),
        EventField::Int(number) => number.to_string(),
        EventField::Str(text) => text.clone(),
        EventField::Float(_) => return Err(CheckpointError::PythonFloatStr),
        EventField::List(_) | EventField::Mapping(_) => return Err(CheckpointError::PythonStr),
    };
    if text.trim().is_empty() {
        Ok(None)
    } else {
        Ok(Some(text))
    }
}

fn pull_payload_fields(
    payload: &Payload,
    chk_id: &mut Option<EventField>,
    seq: &mut Option<EventField>,
    state_hash: &mut Option<EventField>,
) -> Result<(), CheckpointError> {
    *chk_id = payload_get_field(payload, "checkpoint_id")?;
    if chk_id.is_none() {
        *chk_id = payload_get_field(payload, "id")?;
    }
    if payload_contains(payload, "seq")? {
        *seq = payload_get_field(payload, "seq")?;
    } else if payload_contains(payload, "checkpoint_seq")? {
        *seq = payload_get_field(payload, "checkpoint_seq")?;
    }
    *state_hash = payload_get_field(payload, "state_hash")?;
    if state_hash.is_none() {
        *state_hash = payload_get_field(payload, "hash")?;
    }
    Ok(())
}

fn pull_mapping_payload_fields(
    payload: &EventMapping,
    chk_id: &mut Option<EventField>,
    seq: &mut Option<EventField>,
    state_hash: &mut Option<EventField>,
) {
    *chk_id = mapping_get_non_null(payload, "checkpoint_id");
    if chk_id.is_none() {
        *chk_id = mapping_get_non_null(payload, "id");
    }
    if mapping_contains(payload, "seq") {
        *seq = mapping_get_non_null(payload, "seq");
    } else if mapping_contains(payload, "checkpoint_seq") {
        *seq = mapping_get_non_null(payload, "checkpoint_seq");
    }
    *state_hash = mapping_get_non_null(payload, "state_hash");
    if state_hash.is_none() {
        *state_hash = mapping_get_non_null(payload, "hash");
    }
}

fn event_attr_then_mapping(
    event: &EventValue,
    session_attr: fn(&SessionEvent) -> Option<EventField>,
    key: &str,
) -> Option<EventField> {
    match event {
        EventValue::Session(session) => session_attr(session),
        EventValue::Mapping(mapping) => mapping_get_non_null(mapping, key),
        EventValue::Other => None,
    }
}

fn session_checkpoint_id(_session: &SessionEvent) -> Option<EventField> {
    None
}

fn session_seq(session: &SessionEvent) -> Option<EventField> {
    Some(EventField::Int(session.seq))
}

fn session_state_hash(_session: &SessionEvent) -> Option<EventField> {
    None
}

fn payload_contains(payload: &Payload, key: &str) -> Result<bool, CheckpointError> {
    match payload.map_string(key) {
        MapLookup::Borrowed => Err(CheckpointError::BorrowedLookup),
        MapLookup::Present(_) => Ok(true),
        MapLookup::Absent | MapLookup::NotAMap => Ok(false),
    }
}

fn payload_get_field(payload: &Payload, key: &str) -> Result<Option<EventField>, CheckpointError> {
    match payload.map_string(key) {
        MapLookup::Borrowed => Err(CheckpointError::BorrowedLookup),
        MapLookup::NotAMap | MapLookup::Absent => Ok(None),
        MapLookup::Present(value) => match payload_as_field(&value)? {
            EventField::Null => Ok(None),
            field => Ok(Some(field)),
        },
    }
}

fn payload_as_field(payload: &Payload) -> Result<EventField, CheckpointError> {
    if payload.is_null() {
        return Ok(EventField::Null);
    }
    if let Some(flag) = payload.as_bool() {
        return Ok(EventField::Bool(flag));
    }
    if let Some(number) = payload.as_int() {
        return Ok(EventField::Int(number));
    }
    if let Some(number) = payload.as_float() {
        return Ok(EventField::Float(number));
    }
    if let Some(text) = payload.as_str() {
        return Ok(EventField::Str(text.to_owned()));
    }
    if payload.is_list() || payload.is_tuple() {
        return Ok(EventField::List(Vec::new()));
    }
    if payload.is_map() {
        return Ok(EventField::Mapping(EventMapping::new(Vec::new())));
    }
    Err(CheckpointError::PythonStr)
}

fn mapping_contains(mapping: &EventMapping, key: &str) -> bool {
    mapping
        .entries()
        .iter()
        .any(|(entry_key, _)| entry_key == key)
}

fn mapping_get_non_null(mapping: &EventMapping, key: &str) -> Option<EventField> {
    match mapping.get(key) {
        None | Some(EventField::Null) => None,
        Some(value) => Some(value.clone()),
    }
}

fn json_truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => {
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
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(object)) => !object.is_empty(),
    }
}

fn json_object_to_mapping(
    object: &serde_json::Map<String, Value>,
) -> Result<EventMapping, CheckpointError> {
    let mut entries = Vec::new();
    for (key, value) in object {
        entries.push((key.clone(), json_to_field(value)?));
    }
    Ok(EventMapping::new(entries))
}

fn btree_to_mapping(meta: &BTreeMap<String, Value>) -> Result<EventMapping, CheckpointError> {
    let mut entries = Vec::new();
    for (key, value) in meta {
        entries.push((key.clone(), json_to_field(value)?));
    }
    Ok(EventMapping::new(entries))
}

fn json_to_field(value: &Value) -> Result<EventField, CheckpointError> {
    match value {
        Value::Null => Ok(EventField::Null),
        Value::Bool(flag) => Ok(EventField::Bool(*flag)),
        Value::Number(number) => {
            if let Some(int) = number.as_i64() {
                Ok(EventField::Int(int))
            } else if let Some(unsigned) = number.as_u64() {
                i64::try_from(unsigned)
                    .map(EventField::Int)
                    .map_err(|_| CheckpointError::PythonIntUnbounded)
            } else if let Some(float) = number.as_f64() {
                Ok(EventField::Float(float))
            } else {
                Err(CheckpointError::PythonIntUnbounded)
            }
        }
        Value::String(text) => Ok(EventField::Str(text.clone())),
        Value::Array(items) => {
            let mut out = Vec::new();
            for item in items {
                out.push(json_to_field(item)?);
            }
            Ok(EventField::List(out))
        }
        Value::Object(object) => Ok(EventField::Mapping(json_object_to_mapping(object)?)),
    }
}

fn usize_to_i64(value: usize) -> Result<i64, CheckpointError> {
    i64::try_from(value).map_err(|_| CheckpointError::PythonIntUnbounded)
}

fn hex16(digest: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = digest.as_ref();
    let mut out = String::with_capacity(16);
    for byte in bytes.iter().take(8) {
        out.push(char::from(HEX[usize::from(*byte >> 4)]));
        out.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        cap_checkpoint_findings, cap_finding_sort_key, check_checkpoint_divergence,
        check_checkpoint_gap, check_unsafe_continuation, checkpoint_divergence_records,
        checkpoint_gap_records, compute_checkpoint_fingerprint, coverage_pointer,
        extract_checkpoint_fields, extract_run_state_checkpoints, extract_run_state_projection,
        get_event_id, get_event_kind, resolve_source_coords, safe_id, source_record_id,
        unsafe_continuation_record, CheckpointError, CheckpointItem, Sl201Prior, Sl202Prior,
        KIND_CHECKPOINT, KIND_COMPACTION, KIND_RUN_START, MAX_CHECKPOINT_FINDINGS, MSG_OVERFLOW,
        MSG_SL201, MSG_SL202, MSG_SL203, MSG_SL205, PYTHON_INT_UNBOUNDED, TOOL_KINDS,
        VARIANT_OVERFLOW,
    };
    use crate::context::CheckContext;
    use model::canonical::{Payload, SessionEvent};
    use model::codes::{Repairability, Severity, SL201, SL202, SL203};
    use model::events::{
        EventField, EventMapping, EventValue, PYTHON_FLOAT_STR_UNREPRESENTABLE,
        PYTHON_STR_UNREPRESENTABLE,
    };
    use model::finding::{
        Finding, FindingInput, PyValue, SourceRef, FINGERPRINT_CODEC_UNAVAILABLE, SCHEMA_VERSION,
    };
    use serde_json::{json, Map, Value};
    use std::collections::BTreeMap;

    fn is_lower_hex16(text: &str) -> bool {
        text.len() == 16 && text.chars().all(|ch| matches!(ch, '0'..='9' | 'a'..='f'))
    }

    fn finding(
        code: &str,
        record_id: Option<&str>,
        fingerprint: &str,
        evidence: PyValue,
    ) -> Finding {
        let source = SourceRef::try_new("<canonical>", None, record_id).unwrap();
        Finding::try_new(FindingInput {
            code: PyValue::string(code),
            severity: PyValue::severity(Severity::Warning),
            repairability: PyValue::repairability(Repairability::Manual),
            message: PyValue::string("synthetic checkpoint marker"),
            source: PyValue::source(source),
            related_ids: PyValue::tuple(Vec::new()),
            fingerprint: PyValue::string(fingerprint),
            schema_version: PyValue::string(SCHEMA_VERSION),
            message_template: PyValue::None,
            evidence,
        })
        .unwrap()
    }

    fn session(id: &str) -> SessionEvent {
        SessionEvent::new(id, None, 0, "2024-02-29T00:00:00Z", "assistant", "message")
    }

    fn kinded(id: &str, kind: &str) -> EventValue {
        EventValue::from_session(SessionEvent::new(
            id,
            None,
            0,
            "2024-02-29T00:00:00Z",
            "assistant",
            kind,
        ))
    }

    fn checkpoint_session(id: &str, seq: i64, hash: Option<&str>) -> EventValue {
        let mut event = SessionEvent::new(
            id,
            None,
            seq,
            "2024-02-29T00:00:00Z",
            "assistant",
            "checkpoint",
        );
        if let Some(hash) = hash {
            event.payload =
                Payload::map(vec![(Payload::string("state_hash"), Payload::string(hash))]);
        }
        EventValue::from_session(event)
    }

    fn checkpoint_mapping(id: &str, seq: Option<i64>, hash: Option<&str>) -> EventValue {
        let mut entries = vec![
            ("kind".to_owned(), EventField::Str("checkpoint".to_owned())),
            ("id".to_owned(), EventField::Str(id.to_owned())),
        ];
        if let Some(seq) = seq {
            entries.push(("seq".to_owned(), EventField::Int(seq)));
        }
        if let Some(hash) = hash {
            entries.push(("state_hash".to_owned(), EventField::Str(hash.to_owned())));
        }
        EventValue::Mapping(EventMapping::new(entries))
    }

    fn assert_codec(err: CheckpointError) {
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(err.message(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!is_lower_hex16(&err.to_string()));
    }

    fn synth_context() -> CheckContext {
        CheckContext::new(
            "synth-adapter-01",
            "9.9.9-synth",
            "synth-profile-01",
            "2026.01-synth",
            None,
            2000,
        )
    }

    #[test]
    fn constants_match_the_pin() {
        assert_eq!(MAX_CHECKPOINT_FINDINGS, 500);
        assert_eq!(KIND_CHECKPOINT, "checkpoint");
        assert_eq!(KIND_RUN_START, ["run_start", "run-start", "continuation"]);
        assert_eq!(KIND_COMPACTION, "compaction_boundary");
        assert_eq!(TOOL_KINDS, ["tool_call", "tool_use", "tool_result"]);
        assert_eq!(MSG_SL201, "Checkpoint gap detected for record {record_id}");
        assert_eq!(
            MSG_SL202,
            "Checkpoint divergence detected for record {record_id}"
        );
        assert_eq!(
            MSG_SL203,
            "Unsafe continuation across loss detected for record {record_id}"
        );
        assert_eq!(
            MSG_SL205,
            "Compaction coverage gap detected for record {record_id}"
        );
        assert_eq!(
            MSG_OVERFLOW,
            "Checkpoint check finding cap reached; remaining records truncated"
        );
        assert_eq!(VARIANT_OVERFLOW, "overflow-summary");
    }

    #[test]
    fn safe_id_none_is_redacted() {
        assert_eq!(safe_id(None), "<redacted>");
    }

    #[test]
    fn safe_id_keeps_surrounding_spaces() {
        assert_eq!(safe_id(Some("  a  ")), "  a  ");
    }

    #[test]
    fn source_record_id_keeps_surrounding_spaces() {
        assert_eq!(source_record_id(Some("  a  ")).as_deref(), Some("  a  "));
    }

    #[test]
    fn source_record_id_whitespace_only_is_none() {
        assert_eq!(source_record_id(None), None);
        assert_eq!(source_record_id(Some("")), None);
        assert_eq!(source_record_id(Some("   ")), None);
        assert_eq!(source_record_id(Some("\t")), None);
    }

    #[test]
    fn fingerprint_sl201_collapses_duplicates() {
        let digest = compute_checkpoint_fingerprint(
            SL201,
            [
                CheckpointItem::from("b"),
                CheckpointItem::from("a"),
                CheckpointItem::from("a"),
            ],
        );
        assert_eq!(digest, "c7bb30314b28cf0c");
        assert!(is_lower_hex16(&digest));
        assert_eq!(
            compute_checkpoint_fingerprint(SL201, [CheckpointItem::from("a")]),
            compute_checkpoint_fingerprint(
                SL201,
                [CheckpointItem::from("a"), CheckpointItem::from("a")]
            )
        );
    }

    #[test]
    fn fingerprint_float_or_list_item_is_a_typed_error() {
        let float_err = CheckpointItem::from_field(&EventField::Float(1.5)).unwrap_err();
        assert_eq!(float_err.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        assert!(matches!(float_err, CheckpointError::PythonFloatStr));
        let list_err = CheckpointItem::from_field(&EventField::List(Vec::new())).unwrap_err();
        assert_eq!(list_err.to_string(), PYTHON_STR_UNREPRESENTABLE);
        assert!(matches!(list_err, CheckpointError::PythonStr));
    }

    #[test]
    fn fingerprint_bool_true_and_negative_int_are_python_str() {
        let with_true = compute_checkpoint_fingerprint(SL201, [CheckpointItem::from(true)]);
        let with_true_text = compute_checkpoint_fingerprint(SL201, [CheckpointItem::from("True")]);
        assert_eq!(with_true, with_true_text);
        let with_neg = compute_checkpoint_fingerprint(SL201, [CheckpointItem::from(-7_i64)]);
        let with_neg_text = compute_checkpoint_fingerprint(SL201, [CheckpointItem::from("-7")]);
        assert_eq!(with_neg, with_neg_text);
    }

    #[test]
    fn cap_under_the_limit_sorts_and_does_not_call_make_finding() {
        let first = finding(
            SL201,
            Some("evt-b-synthetic"),
            "bbbbbbbbbbbbbbbb",
            PyValue::None,
        );
        let second = finding(
            SL201,
            Some("evt-a-synthetic"),
            "aaaaaaaaaaaaaaaa",
            PyValue::None,
        );
        let out = cap_checkpoint_findings(
            vec![first, second],
            SL201,
            None,
            None,
            Some(&CheckContext::default()),
        )
        .unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].source().record_id(), Some("evt-a-synthetic"));
        assert_eq!(out[1].source().record_id(), Some("evt-b-synthetic"));
        assert_eq!(out[0].fingerprint(), "aaaaaaaaaaaaaaaa");
        assert_eq!(out[1].fingerprint(), "bbbbbbbbbbbbbbbb");
    }

    #[test]
    fn cap_of_empty_list_at_default_max_returns_empty() {
        let out = cap_checkpoint_findings(Vec::new(), SL201, None, None, None).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn cap_over_the_limit_returns_the_codec_error() {
        let item = finding(
            SL201,
            Some("evt-a-synthetic"),
            "aaaaaaaaaaaaaaaa",
            PyValue::None,
        );
        let err = cap_checkpoint_findings(vec![item], SL201, Some(0), None, None).unwrap_err();
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(err.message(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!is_lower_hex16(&err.to_string()));
        assert!(matches!(err, CheckpointError::Finding(_)));
    }

    #[test]
    fn empty_list_with_max_minus_one_returns_the_codec_error() {
        let err =
            cap_checkpoint_findings(Vec::new(), SL201, Some(-1), Some("a\\b"), None).unwrap_err();
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!is_lower_hex16(&err.to_string()));
    }

    #[test]
    fn sort_key_uses_record_id_and_does_not_read_correlation_id() {
        let with_corr = finding(
            SL201,
            Some("evt-b-synthetic"),
            "bbbbbbbbbbbbbbbb",
            PyValue::map(vec![(
                PyValue::string("correlation_id"),
                PyValue::string("aaa-corr-synthetic"),
            )]),
        );
        let with_record = finding(
            SL201,
            Some("evt-a-synthetic"),
            "aaaaaaaaaaaaaaaa",
            PyValue::map(vec![(
                PyValue::string("correlation_id"),
                PyValue::string("zzz-corr-synthetic"),
            )]),
        );
        let out =
            cap_checkpoint_findings(vec![with_corr, with_record], SL201, None, None, None).unwrap();
        assert_eq!(out[0].source().record_id(), Some("evt-a-synthetic"));
        assert_eq!(out[1].source().record_id(), Some("evt-b-synthetic"));
        let missing = finding(
            SL201,
            None,
            "cccccccccccccccc",
            PyValue::map(vec![(
                PyValue::string("correlation_id"),
                PyValue::string("zzz-corr-synthetic"),
            )]),
        );
        let key = cap_finding_sort_key(&missing).unwrap();
        assert_eq!(key.2, "");
        assert_eq!(key.1, 0);
    }

    #[test]
    fn overflow_flag_is_one_only_for_json_true() {
        let overflow = finding(
            SL201,
            Some("evt-a-synthetic"),
            "aaaaaaaaaaaaaaaa",
            PyValue::map(vec![(
                PyValue::string("overflow"),
                PyValue::bool_value(true),
            )]),
        );
        let as_false = finding(
            SL201,
            Some("evt-a-synthetic"),
            "aaaaaaaaaaaaaaaa",
            PyValue::map(vec![(
                PyValue::string("overflow"),
                PyValue::bool_value(false),
            )]),
        );
        let as_int = finding(
            SL201,
            Some("evt-a-synthetic"),
            "aaaaaaaaaaaaaaaa",
            PyValue::map(vec![(PyValue::string("overflow"), PyValue::int(1))]),
        );
        let as_text = finding(
            SL201,
            Some("evt-a-synthetic"),
            "aaaaaaaaaaaaaaaa",
            PyValue::map(vec![(PyValue::string("overflow"), PyValue::string("true"))]),
        );
        assert_eq!(cap_finding_sort_key(&overflow).unwrap().1, 1);
        assert_eq!(cap_finding_sort_key(&as_false).unwrap().1, 0);
        assert_eq!(cap_finding_sort_key(&as_int).unwrap().1, 0);
        assert_eq!(cap_finding_sort_key(&as_text).unwrap().1, 0);
    }

    #[test]
    fn bool_line_is_dropped_line_1_is_kept() {
        let bool_line = EventValue::Mapping(EventMapping::new(vec![(
            "source_line".to_owned(),
            EventField::Bool(true),
        )]));
        let (_path, line) = resolve_source_coords(&bool_line, "<canonical>").unwrap();
        assert_eq!(line, None);

        let mut event = session("evt-line-synthetic");
        event.source_line = Some(1);
        let (_path, line) =
            resolve_source_coords(&EventValue::from_session(event), "<canonical>").unwrap();
        assert_eq!(line, Some(1));
    }

    #[test]
    fn location_falsy_and_typed_errors() {
        let empty = EventValue::Mapping(EventMapping::new(vec![(
            "source_location".to_owned(),
            EventField::Str(String::new()),
        )]));
        let (path, _) = resolve_source_coords(&empty, "<canonical>").unwrap();
        assert_eq!(path, "<canonical>");

        let true_loc = EventValue::Mapping(EventMapping::new(vec![(
            "source_location".to_owned(),
            EventField::Bool(true),
        )]));
        let (path, _) = resolve_source_coords(&true_loc, "<canonical>").unwrap();
        assert_eq!(path, "True");

        let int_loc = EventValue::Mapping(EventMapping::new(vec![(
            "source_location".to_owned(),
            EventField::Int(-3),
        )]));
        let (path, _) = resolve_source_coords(&int_loc, "<canonical>").unwrap();
        assert_eq!(path, "-3");

        let slash = EventValue::Mapping(EventMapping::new(vec![(
            "source_location".to_owned(),
            EventField::Str("a\\b".to_owned()),
        )]));
        let (path, _) = resolve_source_coords(&slash, "<canonical>").unwrap();
        assert_eq!(path, "a/b");

        let kept = EventValue::Mapping(EventMapping::new(vec![(
            "source_location".to_owned(),
            EventField::Str("kept".to_owned()),
        )]));
        let (path, _) = resolve_source_coords(&kept, "other").unwrap();
        assert_eq!(path, "other");

        let float_err = resolve_source_coords(
            &EventValue::Mapping(EventMapping::new(vec![(
                "source_location".to_owned(),
                EventField::Float(1.5),
            )])),
            "<canonical>",
        )
        .unwrap_err();
        assert_eq!(float_err.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);

        let list_err = resolve_source_coords(
            &EventValue::Mapping(EventMapping::new(vec![(
                "source_location".to_owned(),
                EventField::List(vec![EventField::Str("a".to_owned())]),
            )])),
            "<canonical>",
        )
        .unwrap_err();
        assert_eq!(list_err.to_string(), PYTHON_STR_UNREPRESENTABLE);
    }

    #[test]
    fn session_event_kind_none_is_none() {
        assert_eq!(get_event_kind(&EventValue::Other).unwrap(), None);
        let mut event = session("evt-kind-synthetic");
        event.extra_fields =
            Payload::map(vec![(Payload::string("kind"), Payload::bool_value(true))]);
        assert_eq!(
            get_event_kind(&EventValue::from_session(event))
                .unwrap()
                .as_deref(),
            Some("message")
        );
    }

    #[test]
    fn mapping_bool_kind_is_true() {
        let mapping = EventMapping::new(vec![("kind".to_owned(), EventField::Bool(true))]);
        assert_eq!(
            get_event_kind(&EventValue::Mapping(mapping))
                .unwrap()
                .as_deref(),
            Some("True")
        );
        let empty = EventMapping::new(vec![("kind".to_owned(), EventField::Str(String::new()))]);
        assert_eq!(
            get_event_kind(&EventValue::Mapping(empty))
                .unwrap()
                .as_deref(),
            Some("")
        );
        let int_kind = EventMapping::new(vec![("kind".to_owned(), EventField::Int(-4))]);
        assert_eq!(
            get_event_kind(&EventValue::Mapping(int_kind))
                .unwrap()
                .as_deref(),
            Some("-4")
        );
        let float_err = get_event_kind(&EventValue::Mapping(EventMapping::new(vec![(
            "kind".to_owned(),
            EventField::Float(1.0),
        )])))
        .unwrap_err();
        assert_eq!(float_err.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        let list_err = get_event_kind(&EventValue::Mapping(EventMapping::new(vec![(
            "kind".to_owned(),
            EventField::List(Vec::new()),
        )])))
        .unwrap_err();
        assert_eq!(list_err.to_string(), PYTHON_STR_UNREPRESENTABLE);
    }

    #[test]
    fn get_event_id_keeps_raw_values() {
        let empty = session("");
        assert_eq!(
            get_event_id(&EventValue::from_session(empty)),
            Some(EventField::Str(String::new()))
        );
        let mapping = EventMapping::new(vec![("id".to_owned(), EventField::Int(0))]);
        assert_eq!(
            get_event_id(&EventValue::Mapping(mapping)),
            Some(EventField::Int(0))
        );
        let missing = EventMapping::new(Vec::new());
        assert_eq!(get_event_id(&EventValue::Mapping(missing)), None);
    }

    #[test]
    fn payload_seq_zero_wins_over_event_seq() {
        let mut event = session("evt-seq-synthetic");
        event.seq = 9;
        event.payload = Payload::map(vec![(Payload::string("seq"), Payload::int(0))]);
        let (_id, seq, _hash) =
            extract_checkpoint_fields(&EventValue::from_session(event)).unwrap();
        assert_eq!(seq, Some(0));
    }

    #[test]
    fn missing_payload_seq_falls_through_to_event_seq() {
        let mut event = session("evt-seq-synthetic");
        event.seq = 9;
        let (_id, seq, _hash) =
            extract_checkpoint_fields(&EventValue::from_session(event)).unwrap();
        assert_eq!(seq, Some(9));
    }

    #[test]
    fn bool_seq_does_not_become_an_int() {
        let mut event = session("evt-seq-synthetic");
        event.seq = 9;
        event.payload = Payload::map(vec![(Payload::string("seq"), Payload::bool_value(true))]);
        let (_id, seq, _hash) =
            extract_checkpoint_fields(&EventValue::from_session(event)).unwrap();
        assert_eq!(seq, None);
    }

    #[test]
    fn payload_checkpoint_id_keeps_spaces() {
        let mut event = session("evt-id-synthetic");
        event.payload = Payload::map(vec![(
            Payload::string("checkpoint_id"),
            Payload::string("  id-synth  "),
        )]);
        let (chk_id, _seq, _hash) =
            extract_checkpoint_fields(&EventValue::from_session(event)).unwrap();
        assert_eq!(chk_id.as_deref(), Some("  id-synth  "));
    }

    #[test]
    fn payload_null_seq_falls_through_and_float_id_is_typed_error() {
        let mut event = session("evt-seq-synthetic");
        event.seq = 4;
        event.payload = Payload::map(vec![(Payload::string("seq"), Payload::null())]);
        let (_id, seq, _hash) =
            extract_checkpoint_fields(&EventValue::from_session(event)).unwrap();
        assert_eq!(seq, Some(4));

        let mapping = EventValue::Mapping(EventMapping::new(vec![(
            "payload".to_owned(),
            EventField::Mapping(EventMapping::new(vec![(
                "checkpoint_id".to_owned(),
                EventField::Float(1.0),
            )])),
        )]));
        let err = extract_checkpoint_fields(&mapping).unwrap_err();
        assert_eq!(err.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
    }

    #[test]
    fn explicit_empty_projection_returns_empty_copy() {
        let empty = EventMapping::new(Vec::new());
        let out = extract_run_state_projection(None, Some(&[]), Some(&empty)).unwrap();
        assert_eq!(out, Some(EventMapping::new(Vec::new())));
    }

    #[test]
    fn metadata_projection_with_non_empty_keys_is_returned() {
        let mut proj = Map::new();
        proj.insert("keys".to_owned(), json!(["k-synth"]));
        proj.insert("checkpoints".to_owned(), json!([]));
        let mut meta = BTreeMap::new();
        meta.insert("run_state_projection".to_owned(), Value::Object(proj));
        let ctx = CheckContext::create(None, None, None, None, Some(meta));
        let out = extract_run_state_projection(Some(&ctx), None, None)
            .unwrap()
            .unwrap();
        assert!(out.get("keys").is_some());
        match out.get("keys") {
            Some(EventField::List(items)) => {
                assert_eq!(items, &vec![EventField::Str("k-synth".to_owned())]);
            }
            other => panic!("expected keys list, got {other:?}"),
        }
    }

    #[test]
    fn empty_keys_and_empty_checkpoints_return_none() {
        let mut proj = Map::new();
        proj.insert("keys".to_owned(), json!([]));
        proj.insert("checkpoints".to_owned(), json!([]));
        let mut meta = BTreeMap::new();
        meta.insert("run_state_projection".to_owned(), Value::Object(proj));
        let ctx = CheckContext::create(None, None, None, None, Some(meta));
        let out = extract_run_state_projection(Some(&ctx), Some(&[]), None).unwrap();
        assert_eq!(out, None);
    }

    fn ctx_meta(value: Value) -> CheckContext {
        let Value::Object(object) = value else {
            panic!("expected object metadata");
        };
        CheckContext::create(None, None, None, None, Some(object.into_iter().collect()))
    }

    fn mapping_chk(entries: Vec<(&str, EventField)>) -> EventField {
        EventField::Mapping(EventMapping::new(
            entries
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        ))
    }

    fn record_keys(record: &EventMapping) -> Vec<&str> {
        record.keys().collect()
    }

    fn record_id(record: &EventMapping) -> &str {
        match record.get("id") {
            Some(EventField::Str(text)) => text,
            other => panic!("expected string id, got {other:?}"),
        }
    }

    fn record_hash(record: &EventMapping) -> Option<&str> {
        match record.get("hash") {
            Some(EventField::Null) | None => None,
            Some(EventField::Str(text)) => Some(text.as_str()),
            other => panic!("expected string or null hash, got {other:?}"),
        }
    }

    fn record_seq(record: &EventMapping) -> Option<i64> {
        match record.get("seq") {
            Some(EventField::Null) | None => None,
            Some(EventField::Int(number)) => Some(*number),
            other => panic!("expected int or null seq, got {other:?}"),
        }
    }

    fn record_index(record: &EventMapping) -> i64 {
        match record.get("index") {
            Some(EventField::Int(number)) => *number,
            other => panic!("expected int index, got {other:?}"),
        }
    }

    #[test]
    fn run_state_no_candidates_and_no_projection_returns_empty() {
        let out = extract_run_state_checkpoints(None, None, None).unwrap();
        assert!(out.is_empty());
        let ctx = CheckContext::create(None, None, None, None, None);
        let out = extract_run_state_checkpoints(Some(&ctx), None, None).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn run_state_empty_checkpoints_do_not_read_projection() {
        let ctx = ctx_meta(json!({"checkpoints": []}));
        let projection = EventMapping::new(vec![(
            "checkpoints".to_owned(),
            EventField::List(vec![mapping_chk(vec![(
                "id",
                EventField::Str("proj-chk-synth".to_owned()),
            )])]),
        )]);
        let out = extract_run_state_checkpoints(Some(&ctx), None, Some(&projection)).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn run_state_string_checkpoints_fall_through_to_run_state() {
        let ctx = ctx_meta(json!({
            "checkpoints": "not-a-sequence",
            "run_state": {"checkpoints": [{"id": "rs-chk-synth"}]}
        }));
        let out = extract_run_state_checkpoints(Some(&ctx), None, None).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(record_id(&out[0]), "rs-chk-synth");
    }

    #[test]
    fn run_state_direct_checkpoints_win_over_run_state() {
        let ctx = ctx_meta(json!({
            "checkpoints": [{"id": "direct-chk-synth"}],
            "run_state": {"checkpoints": [{"id": "rs-chk-synth"}]}
        }));
        let out = extract_run_state_checkpoints(Some(&ctx), None, None).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(record_id(&out[0]), "direct-chk-synth");
    }

    #[test]
    fn run_state_nested_metadata_checkpoints_when_top_has_no_sequence() {
        let ctx = ctx_meta(json!({
            "metadata": {"checkpoints": [{"id": "nested-chk-synth"}]}
        }));
        let out = extract_run_state_checkpoints(Some(&ctx), None, None).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(record_id(&out[0]), "nested-chk-synth");
    }

    #[test]
    fn run_state_nested_metadata_run_state_when_metadata_checkpoints_absent() {
        let ctx = ctx_meta(json!({
            "metadata": {"run_state": {"checkpoints": [{"id": "meta-rs-chk-synth"}]}}
        }));
        let out = extract_run_state_checkpoints(Some(&ctx), None, None).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(record_id(&out[0]), "meta-rs-chk-synth");
    }

    #[test]
    fn run_state_explicit_projection_only_when_metadata_has_no_sequence() {
        let ctx = ctx_meta(json!({"other": "no-sequence"}));
        let projection = EventMapping::new(vec![(
            "checkpoints".to_owned(),
            EventField::List(vec![mapping_chk(vec![(
                "id",
                EventField::Str("proj-chk-synth".to_owned()),
            )])]),
        )]);
        let out = extract_run_state_checkpoints(Some(&ctx), None, Some(&projection)).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(record_id(&out[0]), "proj-chk-synth");

        let ctx_direct = ctx_meta(json!({"checkpoints": [{"id": "direct-chk-synth"}]}));
        let out =
            extract_run_state_checkpoints(Some(&ctx_direct), None, Some(&projection)).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(record_id(&out[0]), "direct-chk-synth");
    }

    #[test]
    fn run_state_metadata_projection_only_when_argument_has_no_sequence() {
        let ctx = ctx_meta(json!({
            "run_state_projection": {"checkpoints": [{"id": "meta-proj-chk-synth"}]}
        }));
        let out = extract_run_state_checkpoints(Some(&ctx), None, None).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(record_id(&out[0]), "meta-proj-chk-synth");

        let projection = EventMapping::new(vec![(
            "checkpoints".to_owned(),
            EventField::List(vec![mapping_chk(vec![(
                "id",
                EventField::Str("arg-proj-chk-synth".to_owned()),
            )])]),
        )]);
        let out = extract_run_state_checkpoints(Some(&ctx), None, Some(&projection)).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(record_id(&out[0]), "arg-proj-chk-synth");

        let empty_proj = EventMapping::new(Vec::new());
        let out = extract_run_state_checkpoints(Some(&ctx), None, Some(&empty_proj)).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(record_id(&out[0]), "meta-proj-chk-synth");
    }

    #[test]
    fn run_state_mapping_id_wins_over_checkpoint_id() {
        let ctx = ctx_meta(json!({
            "checkpoints": [{"id": "id-synth", "checkpoint_id": "checkpoint-id-synth"}]
        }));
        let out = extract_run_state_checkpoints(Some(&ctx), None, None).unwrap();
        assert_eq!(record_id(&out[0]), "id-synth");

        let ctx_missing = ctx_meta(json!({
            "checkpoints": [{"checkpoint_id": "checkpoint-id-synth"}]
        }));
        let out = extract_run_state_checkpoints(Some(&ctx_missing), None, None).unwrap();
        assert_eq!(record_id(&out[0]), "checkpoint-id-synth");
    }

    #[test]
    fn run_state_whitespace_id_and_kept_spaces() {
        let ctx = ctx_meta(json!({"checkpoints": [{"id": "   "}]}));
        let out = extract_run_state_checkpoints(Some(&ctx), None, None).unwrap();
        assert_eq!(record_id(&out[0]), "chk-runstate-0");

        let ctx_kept = ctx_meta(json!({"checkpoints": [{"id": "  id-synth  "}]}));
        let out = extract_run_state_checkpoints(Some(&ctx_kept), None, None).unwrap();
        assert_eq!(record_id(&out[0]), "  id-synth  ");
    }

    #[test]
    fn run_state_seq_null_absent_zero_and_bool() {
        let ctx_null = ctx_meta(json!({
            "checkpoints": [{"seq": null, "checkpoint_seq": 9}]
        }));
        let out = extract_run_state_checkpoints(Some(&ctx_null), None, None).unwrap();
        assert_eq!(record_seq(&out[0]), None);

        let ctx_absent = ctx_meta(json!({
            "checkpoints": [{"checkpoint_seq": 4}]
        }));
        let out = extract_run_state_checkpoints(Some(&ctx_absent), None, None).unwrap();
        assert_eq!(record_seq(&out[0]), Some(4));

        let ctx_zero = ctx_meta(json!({"checkpoints": [{"seq": 0}]}));
        let out = extract_run_state_checkpoints(Some(&ctx_zero), None, None).unwrap();
        assert_eq!(record_seq(&out[0]), Some(0));

        let ctx_bool = ctx_meta(json!({"checkpoints": [{"seq": true}]}));
        let out = extract_run_state_checkpoints(Some(&ctx_bool), None, None).unwrap();
        assert_eq!(record_seq(&out[0]), None);
    }

    #[test]
    fn run_state_hash_empty_state_hash_strip_and_null_string() {
        let ctx_empty = ctx_meta(json!({
            "checkpoints": [{"hash": "", "state_hash": "state-synth"}]
        }));
        let out = extract_run_state_checkpoints(Some(&ctx_empty), None, None).unwrap();
        assert_eq!(record_hash(&out[0]), None);

        let ctx_state = ctx_meta(json!({
            "checkpoints": [{"state_hash": "state-synth"}]
        }));
        let out = extract_run_state_checkpoints(Some(&ctx_state), None, None).unwrap();
        assert_eq!(record_hash(&out[0]), Some("state-synth"));

        let ctx_spaces = ctx_meta(json!({"checkpoints": [{"hash": "  ab  "}]}));
        let out = extract_run_state_checkpoints(Some(&ctx_spaces), None, None).unwrap();
        assert_eq!(record_hash(&out[0]), Some("ab"));

        let ctx_null = ctx_meta(json!({"checkpoints": [{"hash": "null"}]}));
        let out = extract_run_state_checkpoints(Some(&ctx_null), None, None).unwrap();
        assert_eq!(record_hash(&out[0]), None);
    }

    #[test]
    fn run_state_string_and_null_items_emit_rows() {
        let ctx = ctx_meta(json!({"checkpoints": ["item-synth", null]}));
        let out = extract_run_state_checkpoints(Some(&ctx), None, None).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(record_id(&out[0]), "chk-runstate-0");
        assert_eq!(record_index(&out[0]), 0);
        assert_eq!(record_seq(&out[0]), None);
        assert_eq!(record_hash(&out[0]), None);
        assert_eq!(record_id(&out[1]), "chk-runstate-1");
        assert_eq!(record_index(&out[1]), 1);
        assert_eq!(record_seq(&out[1]), None);
        assert_eq!(record_hash(&out[1]), None);
    }

    #[test]
    fn run_state_ascii_seq_string_and_negative_string() {
        let ctx = ctx_meta(json!({
            "checkpoints": [{"seq": " 007 "}, {"seq": "-3"}]
        }));
        let out = extract_run_state_checkpoints(Some(&ctx), None, None).unwrap();
        assert_eq!(record_seq(&out[0]), Some(7));
        assert_eq!(record_seq(&out[1]), None);
    }

    #[test]
    fn run_state_float_id_is_typed_error() {
        let ctx = ctx_meta(json!({"checkpoints": [{"id": 1.5}]}));
        let err = extract_run_state_checkpoints(Some(&ctx), None, None).unwrap_err();
        assert_eq!(err.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        assert!(matches!(err, CheckpointError::PythonFloatStr));
    }

    #[test]
    fn run_state_output_key_order_is_hash_id_index_seq() {
        let ctx = ctx_meta(json!({
            "checkpoints": [{"id": "id-synth", "seq": 1, "hash": "ab"}]
        }));
        let out = extract_run_state_checkpoints(Some(&ctx), None, None).unwrap();
        assert_eq!(record_keys(&out[0]), ["hash", "id", "index", "seq"]);
        assert_eq!(out[0].entries().len(), 4);
    }

    #[test]
    fn run_state_events_are_not_scanned() {
        let event_chk = EventValue::Mapping(EventMapping::new(vec![(
            "checkpoints".to_owned(),
            EventField::List(vec![mapping_chk(vec![(
                "id",
                EventField::Str("event-chk-synth".to_owned()),
            )])]),
        )]));
        let events = [event_chk];
        let out = extract_run_state_checkpoints(None, Some(&events), None).unwrap();
        assert!(out.is_empty());

        let mut event = session("evt-chk-synth");
        event.kind = "checkpoint".to_owned();
        let events = [EventValue::from_session(event)];
        let ctx = ctx_meta(json!({"checkpoints": []}));
        let out = extract_run_state_checkpoints(Some(&ctx), Some(&events), None).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn empty_events_and_no_projection_return_empty() {
        let records = checkpoint_gap_records(&[], None, None, None, None).unwrap();
        assert!(records.is_empty());
        let findings = check_checkpoint_gap(&[], None, None, None, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn empty_events_with_max_minus_one_return_codec_error() {
        let records = checkpoint_gap_records(&[], None, None, None, None).unwrap();
        assert!(records.is_empty());
        let err = check_checkpoint_gap(&[], None, Some(-1), None, None, None).unwrap_err();
        assert_codec(err);
    }

    #[test]
    fn run_start_without_checkpoint_emits_gap_and_codec_error() {
        let events = [
            kinded("evt-run-synth", "run_start"),
            kinded("evt-hyphen-synth", "run-start"),
            kinded("evt-cont-synth", "continuation"),
        ];
        let ctx = synth_context();
        let records = checkpoint_gap_records(&events, None, None, Some(&ctx), None).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].at_index, 0);
        assert_eq!(records[0].expected_seq, 0);
        assert_eq!(records[0].found_seq, None);
        assert!(records[0].source.is_none());
        assert_eq!(records[0].line, None);
        assert_eq!(records[0].path, "<canonical>");
        assert_eq!(records[0].record_id.as_deref(), Some("evt-run-synth"));
        assert_eq!(records[0].code, SL201);
        assert_eq!(records[0].severity, Severity::Error);
        assert_eq!(records[0].repairability, Repairability::Manual);
        assert_eq!(records[0].message_template, MSG_SL201);
        assert_eq!(records[0].adapter_id, "synth-adapter-01");
        assert_eq!(records[0].adapter_version, "9.9.9-synth");
        assert_eq!(records[0].profile_id, "synth-profile-01");
        assert_eq!(records[0].profile_version, "2026.01-synth");
        assert_eq!(
            records[0].evidence_keys().as_slice(),
            ["at_index", "expected_seq", "found_seq"].as_slice()
        );
        assert_eq!(records[1].at_index, 1);
        assert_eq!(records[2].at_index, 2);
        assert_eq!(records[1].found_seq, None);
        assert_eq!(records[2].found_seq, None);
        assert!(records[1].source.is_none());
        assert!(records[2].source.is_none());
        let err = check_checkpoint_gap(&events, None, None, None, Some(&ctx), None).unwrap_err();
        assert_codec(err);
    }

    #[test]
    fn bool_true_kind_is_not_a_checkpoint() {
        let events = [
            EventValue::Mapping(EventMapping::new(vec![
                ("kind".to_owned(), EventField::Bool(true)),
                (
                    "id".to_owned(),
                    EventField::Str("evt-bool-synth".to_owned()),
                ),
            ])),
            kinded("evt-run-synth", "run_start"),
        ];
        let records = checkpoint_gap_records(&events, None, None, None, None).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].at_index, 1);
        assert!(records[0].source.is_none());
    }

    #[test]
    fn checkpoint_before_run_start_suppresses_resumption_gap() {
        let events = [
            checkpoint_session("evt-chk-synth", 0, Some("ab")),
            kinded("evt-run-synth", "run_start"),
        ];
        let records = checkpoint_gap_records(&events, None, None, None, None).unwrap();
        assert!(records.is_empty());
        let findings = check_checkpoint_gap(&events, None, None, None, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn non_empty_run_state_list_makes_run_start_silent() {
        let ctx = ctx_meta(json!({
            "checkpoints": [{"id": "rs-null-synth", "hash": "ab", "seq": null}]
        }));
        let events = [kinded("evt-run-synth", "run_start")];
        let records =
            checkpoint_gap_records(&events, None, Some("default"), Some(&ctx), None).unwrap();
        assert!(records.is_empty());
        let findings =
            check_checkpoint_gap(&events, None, None, Some("default"), Some(&ctx), None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn missing_event_hash_emits_found_seq_without_source() {
        let events = [
            checkpoint_session("evt-chk-synth", 3, None),
            kinded("evt-run-synth", "run_start"),
        ];
        let records = checkpoint_gap_records(&events, None, None, None, None).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].at_index, 0);
        assert_eq!(records[0].expected_seq, 0);
        assert_eq!(records[0].found_seq, Some(3));
        assert!(records[0].source.is_none());
        assert!(records[0].sensitivity.is_none());
        let err = check_checkpoint_gap(&events, None, None, None, None, None).unwrap_err();
        assert_codec(err);
    }

    #[test]
    fn event_seq_jump_fires_only_when_delta_exceeds_one() {
        let jumped = [
            checkpoint_session("evt-chk-0-synth", 0, Some("ab")),
            checkpoint_session("evt-chk-2-synth", 2, Some("cd")),
        ];
        let records = checkpoint_gap_records(&jumped, None, None, None, None).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].at_index, 1);
        assert_eq!(records[0].expected_seq, 1);
        assert_eq!(records[0].found_seq, Some(2));
        assert!(records[0].source.is_none());
        let err = check_checkpoint_gap(&jumped, None, None, None, None, None).unwrap_err();
        assert_codec(err);

        let adjacent = [
            checkpoint_session("evt-chk-0-synth", 0, Some("ab")),
            checkpoint_session("evt-chk-1-synth", 1, Some("cd")),
        ];
        let records = checkpoint_gap_records(&adjacent, None, None, None, None).unwrap();
        assert!(records.is_empty());
        let findings = check_checkpoint_gap(&adjacent, None, None, None, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn high_sensitivity_null_seq_emits_and_default_does_not() {
        let events = [
            checkpoint_session("evt-chk-0-synth", 0, Some("ab")),
            checkpoint_mapping("evt-sens-synth", None, Some("cd")),
            checkpoint_session("evt-chk-2-synth", 2, Some("ef")),
        ];
        let high = checkpoint_gap_records(&events, None, Some("high"), None, None).unwrap();
        assert_eq!(high.len(), 2);
        assert_eq!(high[0].at_index, 1);
        assert_eq!(high[0].expected_seq, 1);
        assert_eq!(high[0].found_seq, None);
        assert_eq!(high[0].sensitivity.as_deref(), Some("high"));
        assert!(high[0].source.is_none());
        assert_eq!(
            high[0].evidence_keys().as_slice(),
            ["at_index", "expected_seq", "found_seq", "sensitivity"].as_slice()
        );
        assert_eq!(high[1].at_index, 2);
        assert_eq!(high[1].expected_seq, 1);
        assert_eq!(high[1].found_seq, Some(2));
        assert!(high[1].sensitivity.is_none());
        assert!(high[1].source.is_none());

        let defaulted = checkpoint_gap_records(&events, None, Some("default"), None, None).unwrap();
        assert_eq!(defaulted.len(), 1);
        assert!(defaulted[0].sensitivity.is_none());
        assert_eq!(defaulted[0].found_seq, Some(2));

        let upper = checkpoint_gap_records(&events, None, Some("HIGH"), None, None).unwrap();
        assert_eq!(upper.len(), 1);
        assert!(upper.iter().all(|record| record.sensitivity.is_none()));
    }

    #[test]
    fn covered_run_state_seq_skips_missing_hash_and_still_advances() {
        let ctx = ctx_meta(json!({
            "checkpoints": [
                {"id": "rs-covered-synth", "seq": 1, "hash": ""},
                {"id": "rs-open-synth", "seq": 3, "hash": ""}
            ]
        }));
        let events = [checkpoint_session("evt-chk-synth", 1, Some("ab"))];
        let records = checkpoint_gap_records(&events, None, None, Some(&ctx), None).unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|record| record.found_seq != Some(1)));
        assert_eq!(records[0].at_index, 1);
        assert_eq!(records[0].expected_seq, 2);
        assert_eq!(records[0].found_seq, Some(3));
        assert_eq!(records[0].source.as_deref(), Some("run_state"));
        assert_eq!(records[1].expected_seq, 2);
        assert_eq!(records[1].found_seq, Some(3));
        let err = check_checkpoint_gap(&events, None, None, None, Some(&ctx), None).unwrap_err();
        assert_codec(err);
    }

    #[test]
    fn uncovered_empty_hash_uses_original_index_and_line_one() {
        let ctx = ctx_meta(json!({
            "checkpoints": [
                {"id": "rs-late-synth", "seq": 5, "hash": ""},
                {"id": "rs-early-synth", "seq": 1, "hash": ""}
            ]
        }));
        let empty = EventMapping::new(Vec::new());
        let records =
            checkpoint_gap_records(&[], Some("a\\b"), None, Some(&ctx), Some(&empty)).unwrap();
        assert_eq!(records[0].at_index, 1);
        assert_eq!(records[0].expected_seq, 0);
        assert_eq!(records[0].found_seq, Some(1));
        assert_eq!(records[0].source.as_deref(), Some("run_state"));
        assert_eq!(records[0].line, Some(1));
        assert_eq!(records[0].path, "a\\b");
        assert_eq!(records[0].run_state.as_ref(), Some(&empty));
        assert_eq!(
            records[0].evidence_keys().as_slice(),
            [
                "at_index",
                "expected_seq",
                "found_seq",
                "source",
                "run_state"
            ]
            .as_slice()
        );
        assert_eq!(records[1].at_index, 0);
        assert_eq!(records[1].found_seq, Some(5));
        assert_eq!(records[2].at_index, 0);
        assert_eq!(records[2].expected_seq, 2);
        let err = check_checkpoint_gap(&[], Some("a\\b"), None, None, Some(&ctx), Some(&empty))
            .unwrap_err();
        assert_codec(err);
    }

    #[test]
    fn null_run_state_seqs_sort_after_numbered_seqs() {
        let ctx = ctx_meta(json!({
            "checkpoints": [
                {"id": "rs-null-synth", "seq": null, "hash": "ab"},
                {"id": "rs-num-synth", "seq": 4, "hash": ""}
            ]
        }));
        let records = checkpoint_gap_records(&[], None, Some("high"), Some(&ctx), None).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].at_index, 1);
        assert_eq!(records[0].expected_seq, 0);
        assert_eq!(records[0].found_seq, Some(4));
        assert!(records[0].sensitivity.is_none());
        assert_eq!(records[0].source.as_deref(), Some("run_state"));
        assert_eq!(records[1].at_index, 0);
        assert_eq!(records[1].expected_seq, 5);
        assert_eq!(records[1].found_seq, None);
        assert_eq!(records[1].sensitivity.as_deref(), Some("high"));
        assert_eq!(records[1].source.as_deref(), Some("run_state"));
        assert_eq!(
            records[1].evidence_keys().as_slice(),
            [
                "at_index",
                "expected_seq",
                "found_seq",
                "sensitivity",
                "source"
            ]
            .as_slice()
        );
    }

    #[test]
    fn null_run_state_seq_can_emit_missing_hash_and_sensitivity() {
        let ctx = ctx_meta(json!({
            "checkpoints": [{"id": "rs-null-synth", "hash": ""}]
        }));
        let high = checkpoint_gap_records(&[], None, Some("high"), Some(&ctx), None).unwrap();
        assert_eq!(high.len(), 2);
        assert_eq!(high[0].found_seq, None);
        assert!(high[0].sensitivity.is_none());
        assert_eq!(high[0].source.as_deref(), Some("run_state"));
        assert_eq!(high[1].found_seq, None);
        assert_eq!(high[1].sensitivity.as_deref(), Some("high"));
        assert_eq!(high[1].source.as_deref(), Some("run_state"));

        let defaulted =
            checkpoint_gap_records(&[], None, Some("default"), Some(&ctx), None).unwrap();
        assert_eq!(defaulted.len(), 1);
        assert!(defaulted[0].sensitivity.is_none());
        assert_eq!(defaulted[0].source.as_deref(), Some("run_state"));
    }

    #[test]
    fn min_event_seq_without_smaller_run_state_does_not_jump() {
        let ctx = ctx_meta(json!({
            "checkpoints": [{"id": "rs-base-synth", "seq": 10, "hash": "ab"}]
        }));
        let events = [
            checkpoint_session("evt-high-synth", 12, Some("ab")),
            checkpoint_session("evt-low-synth", 0, Some("cd")),
        ];
        let records = checkpoint_gap_records(&events, None, None, Some(&ctx), None).unwrap();
        assert!(records.is_empty());
        let findings = check_checkpoint_gap(&events, None, None, None, Some(&ctx), None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn explicit_empty_projection_attaches_run_state() {
        let events = [kinded("evt-run-synth", "run_start")];
        let empty = EventMapping::new(Vec::new());
        let records = checkpoint_gap_records(&events, None, None, None, Some(&empty)).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].at_index, 0);
        assert!(records[0].source.is_none());
        assert_eq!(records[0].run_state.as_ref(), Some(&empty));
        assert_eq!(
            records[0].evidence_keys().as_slice(),
            ["at_index", "expected_seq", "found_seq", "run_state"].as_slice()
        );
        let err = check_checkpoint_gap(&events, None, None, None, None, Some(&empty)).unwrap_err();
        assert_codec(err);
    }

    #[test]
    fn float_run_state_id_is_typed_error_and_does_not_call_make_finding() {
        let ctx = ctx_meta(json!({"checkpoints": [{"id": 1.5}]}));
        let err = checkpoint_gap_records(&[], None, None, Some(&ctx), None).unwrap_err();
        assert_eq!(err.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        assert!(matches!(err, CheckpointError::PythonFloatStr));
        let err = check_checkpoint_gap(&[], None, None, None, Some(&ctx), None).unwrap_err();
        assert_eq!(err.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        assert!(matches!(err, CheckpointError::PythonFloatStr));
    }

    #[test]
    fn i64_overflow_is_unbounded_not_a_panic() {
        let add_ctx = ctx_meta(json!({
            "checkpoints": [
                {"id": "rs-max-synth", "seq": i64::MAX, "hash": "ab"},
                {"id": "rs-null-synth", "hash": ""}
            ]
        }));
        let err = checkpoint_gap_records(&[], None, None, Some(&add_ctx), None).unwrap_err();
        assert_eq!(err.to_string(), PYTHON_INT_UNBOUNDED);
        assert!(matches!(err, CheckpointError::PythonIntUnbounded));
        let err = check_checkpoint_gap(&[], None, None, None, Some(&add_ctx), None).unwrap_err();
        assert_eq!(err.to_string(), PYTHON_INT_UNBOUNDED);

        let sub_ctx = ctx_meta(json!({
            "checkpoints": [
                {"id": "rs-neg-synth", "seq": -1, "hash": "ab"},
                {"id": "rs-max-synth", "seq": i64::MAX, "hash": "cd"}
            ]
        }));
        let err = checkpoint_gap_records(&[], None, None, Some(&sub_ctx), None).unwrap_err();
        assert_eq!(err.to_string(), PYTHON_INT_UNBOUNDED);
        assert!(matches!(err, CheckpointError::PythonIntUnbounded));

        let events = [
            checkpoint_session("evt-neg-synth", -1, Some("ab")),
            checkpoint_session("evt-max-synth", i64::MAX, Some("cd")),
        ];
        let err = checkpoint_gap_records(&events, None, None, None, None).unwrap_err();
        assert_eq!(err.to_string(), PYTHON_INT_UNBOUNDED);
        let err = check_checkpoint_gap(&events, None, None, None, None, None).unwrap_err();
        assert_eq!(err.to_string(), PYTHON_INT_UNBOUNDED);
        assert!(matches!(err, CheckpointError::PythonIntUnbounded));
    }

    fn checkpoint_id(id: EventField, seq: i64, hash: &str) -> EventValue {
        EventValue::Mapping(EventMapping::new(vec![
            ("kind".to_owned(), EventField::Str("checkpoint".to_owned())),
            ("id".to_owned(), id),
            ("seq".to_owned(), EventField::Int(seq)),
            ("state_hash".to_owned(), EventField::Str(hash.to_owned())),
        ]))
    }

    fn tool_mapping(id: &str, kind: &str) -> EventValue {
        EventValue::Mapping(EventMapping::new(vec![
            ("kind".to_owned(), EventField::Str(kind.to_owned())),
            ("id".to_owned(), EventField::Str(id.to_owned())),
        ]))
    }

    fn codex_rollout() -> CheckContext {
        CheckContext::new("codex-rollout", "unknown", "unknown", "unknown", None, 2000)
    }

    fn claude_jsonl() -> CheckContext {
        CheckContext::new(
            "claude-code-jsonl",
            "unknown",
            "unknown",
            "unknown",
            None,
            2000,
        )
    }

    #[test]
    fn divergence_of_empty_events_is_empty() {
        let records = checkpoint_divergence_records(&[], None, None, None).unwrap();
        assert!(records.is_empty());
        let findings = check_checkpoint_divergence(&[], None, None, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn divergence_of_empty_events_with_max_minus_one_is_the_codec_error() {
        let err = check_checkpoint_divergence(&[], None, Some(-1), None, None).unwrap_err();
        assert_codec(err);
    }

    #[test]
    fn same_seq_and_same_hash_emits_no_divergence() {
        let events = [
            checkpoint_session("evt-a-synth", 3, Some("same-hash-synth")),
            checkpoint_session("evt-b-synth", 3, Some("same-hash-synth")),
        ];
        let records = checkpoint_divergence_records(&events, None, None, None).unwrap();
        assert!(records.is_empty());
        let findings = check_checkpoint_divergence(&events, None, None, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn different_hashes_keep_the_first_full_hash_as_baseline() {
        let hash_a = "0123456789abcdefEXTRA";
        let hash_b = "fedcba9876543210EXTRA";
        let hash_c = "abcdefabcdefabcdEXTRA";
        let prefix_a = "0123456789abcdef";
        let prefix_b = "fedcba9876543210";
        let prefix_c = "abcdefabcdefabcd";
        let pair = [
            checkpoint_session("evt-a-synth", 9, Some(hash_a)),
            checkpoint_session("evt-b-synth", 9, Some(hash_b)),
        ];
        let records = checkpoint_divergence_records(&pair, None, None, None).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].hash_a, prefix_a);
        assert_eq!(records[0].hash_b, prefix_b);
        assert_eq!(records[0].seq, 9);
        assert!(records[0].source.is_none());
        assert_eq!(records[0].code, SL202);
        assert_eq!(records[0].severity, Severity::Error);
        assert_eq!(records[0].repairability, Repairability::Manual);
        assert_eq!(records[0].message_template, MSG_SL202);
        assert_eq!(
            records[0].evidence_keys(),
            ["hash_a", "hash_b", "seq"].as_slice()
        );
        let err = check_checkpoint_divergence(&pair, None, None, None, None).unwrap_err();
        assert_codec(err);

        let repeated = [
            checkpoint_session("evt-a-synth", 9, Some(hash_a)),
            checkpoint_session("evt-b-synth", 9, Some(hash_b)),
            checkpoint_session("evt-a2-synth", 9, Some(hash_a)),
        ];
        let records = checkpoint_divergence_records(&repeated, None, None, None).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].hash_a, prefix_a);
        assert_eq!(records[0].hash_b, prefix_b);

        let third = [
            checkpoint_session("evt-a-synth", 9, Some(hash_a)),
            checkpoint_session("evt-b-synth", 9, Some(hash_b)),
            checkpoint_session("evt-c-synth", 9, Some(hash_c)),
        ];
        let records = checkpoint_divergence_records(&third, None, None, None).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].hash_a, prefix_a);
        assert_eq!(records[0].hash_b, prefix_b);
        assert_eq!(records[1].hash_a, prefix_a);
        assert_eq!(records[1].hash_b, prefix_c);
    }

    #[test]
    fn hash_shorter_than_16_characters_is_not_padded() {
        let events = [
            checkpoint_session("evt-a-synth", 5, Some("ab")),
            checkpoint_session("evt-b-synth", 5, Some("cd")),
        ];
        let records = checkpoint_divergence_records(&events, None, None, None).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].hash_a, "ab");
        assert_eq!(records[0].hash_b, "cd");
    }

    #[test]
    fn null_seq_null_hash_and_bool_kind_are_skipped() {
        let events = [
            EventValue::Mapping(EventMapping::new(vec![
                ("kind".to_owned(), EventField::Bool(true)),
                (
                    "id".to_owned(),
                    EventField::Str("evt-bool-synth".to_owned()),
                ),
                ("seq".to_owned(), EventField::Int(2)),
                ("state_hash".to_owned(), EventField::Str("cccc".to_owned())),
            ])),
            checkpoint_mapping("evt-null-seq-synth", None, Some("aaaa")),
            checkpoint_mapping("evt-null-hash-synth", Some(2), None),
            checkpoint_session("evt-one-synth", 2, Some("bbbb")),
        ];
        let records = checkpoint_divergence_records(&events, None, None, None).unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn event_id_bool_true_stringifies_and_missing_id_uses_the_index() {
        let bool_id = [
            checkpoint_session("evt-a-synth", 1, Some("aaaa")),
            checkpoint_id(EventField::Bool(true), 1, "bbbb"),
        ];
        let records = checkpoint_divergence_records(&bool_id, None, None, None).unwrap();
        assert_eq!(records[0].record_id.as_deref(), Some("True"));

        let missing = [
            EventValue::Mapping(EventMapping::new(vec![
                ("kind".to_owned(), EventField::Str("checkpoint".to_owned())),
                ("seq".to_owned(), EventField::Int(1)),
                ("state_hash".to_owned(), EventField::Str("aaaa".to_owned())),
            ])),
            EventValue::Mapping(EventMapping::new(vec![
                ("kind".to_owned(), EventField::Str("checkpoint".to_owned())),
                ("seq".to_owned(), EventField::Int(1)),
                ("state_hash".to_owned(), EventField::Str("bbbb".to_owned())),
            ])),
        ];
        let records = checkpoint_divergence_records(&missing, None, None, None).unwrap();
        assert_eq!(records[0].record_id.as_deref(), Some("<event:1>"));
    }

    #[test]
    fn float_or_list_event_id_is_the_existing_typed_error() {
        let float_id = [checkpoint_id(EventField::Float(1.5), 1, "ab")];
        let err = checkpoint_divergence_records(&float_id, None, None, None).unwrap_err();
        assert_eq!(err.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        assert!(matches!(err, CheckpointError::PythonFloatStr));
        let err = check_checkpoint_divergence(&float_id, None, None, None, None).unwrap_err();
        assert_eq!(err.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);

        let list_id = [checkpoint_id(EventField::List(Vec::new()), 1, "ab")];
        let err = checkpoint_divergence_records(&list_id, None, None, None).unwrap_err();
        assert_eq!(err.to_string(), PYTHON_STR_UNREPRESENTABLE);
        assert!(matches!(err, CheckpointError::PythonStr));
    }

    #[test]
    fn run_state_divergence_uses_source_run_state_and_line_one() {
        let ctx = ctx_meta(json!({
            "checkpoints": [
                {"id": "rs-a-synth", "seq": 4, "hash": "aaaaaaaaaaaaaaaa1111"},
                {"id": "rs-b-synth", "seq": 4, "hash": "bbbbbbbbbbbbbbbb2222"}
            ]
        }));
        let records = checkpoint_divergence_records(&[], Some("a\\b"), Some(&ctx), None).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].source.as_deref(), Some("run_state"));
        assert_eq!(records[0].line, Some(1));
        assert_eq!(records[0].path, "a\\b");
        assert_eq!(records[0].record_id.as_deref(), Some("rs-b-synth"));
        assert_eq!(records[0].hash_a, "aaaaaaaaaaaaaaaa");
        assert_eq!(records[0].hash_b, "bbbbbbbbbbbbbbbb");
        assert_eq!(records[0].seq, 4);
        assert_eq!(
            records[0].evidence_keys(),
            ["hash_a", "hash_b", "seq", "source"].as_slice()
        );
        let err =
            check_checkpoint_divergence(&[], Some("a\\b"), None, Some(&ctx), None).unwrap_err();
        assert_codec(err);

        let empty = EventMapping::new(Vec::new());
        let events = [
            checkpoint_session("evt-same-synth", 4, Some("aaaaaaaaaaaaaaaa1111")),
            checkpoint_session("evt-diff-synth", 4, Some("bbbbbbbbbbbbbbbb2222")),
        ];
        let continued = ctx_meta(json!({
            "checkpoints": [{"id": "rs-a-synth", "seq": 4, "hash": "aaaaaaaaaaaaaaaa1111"}]
        }));
        let records =
            checkpoint_divergence_records(&events, None, Some(&continued), Some(&empty)).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].hash_a, "aaaaaaaaaaaaaaaa");
        assert_eq!(records[0].hash_b, "bbbbbbbbbbbbbbbb");
        assert!(records[0].source.is_none());
        assert_eq!(records[0].record_id.as_deref(), Some("evt-diff-synth"));
        assert_eq!(records[0].run_state.as_ref(), Some(&empty));
        assert_eq!(
            records[0].evidence_keys(),
            ["hash_a", "hash_b", "seq", "run_state"].as_slice()
        );
    }

    #[test]
    fn codex_rollout_unsafe_continuation_is_empty_before_events() {
        let events = [
            EventValue::Mapping(EventMapping::new(vec![(
                "kind".to_owned(),
                EventField::Float(1.5),
            )])),
            kinded("evt-tool-synth", "tool_call"),
        ];
        let ctx = codex_rollout();
        let record = unsafe_continuation_record(&events, None, None, None, Some(&ctx)).unwrap();
        assert!(record.is_none());
        let findings = check_unsafe_continuation(&events, None, None, None, Some(&ctx)).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn compaction_without_a_later_checkpoint_emits_sl203() {
        let events = [
            kinded("evt-compact-synth", "compaction_boundary"),
            kinded("evt-tool-synth", "tool_call"),
        ];
        let record = unsafe_continuation_record(&events, None, None, None, None)
            .unwrap()
            .unwrap();
        assert_eq!(record.caused_by, ["compaction"]);
        assert_eq!(record.first_unsafe_index, 1);
        assert_eq!(record.code, SL203);
        assert_eq!(record.severity, Severity::Error);
        assert_eq!(record.repairability, Repairability::Manual);
        assert_eq!(record.message_template, MSG_SL203);
        assert_eq!(
            record.evidence_keys(),
            ["caused_by", "first_unsafe_index"].as_slice()
        );
        let err = check_unsafe_continuation(&events, None, None, None, None).unwrap_err();
        assert_codec(err);
    }

    #[test]
    fn checkpoint_after_compaction_with_no_tool_between_emits_nothing() {
        let events = [
            kinded("evt-compact-synth", "compaction_boundary"),
            EventValue::Mapping(EventMapping::new(vec![
                ("kind".to_owned(), EventField::Bool(true)),
                (
                    "id".to_owned(),
                    EventField::Str("evt-bool-synth".to_owned()),
                ),
            ])),
            checkpoint_session("evt-chk-synth", 0, Some("ab")),
            kinded("evt-tool-synth", "tool_call"),
        ];
        let record = unsafe_continuation_record(&events, None, None, None, None).unwrap();
        assert!(record.is_none());
        let findings = check_unsafe_continuation(&events, None, None, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn tool_between_compaction_and_the_next_checkpoint_emits_compaction() {
        let events = [
            kinded("evt-compact-synth", "compaction_boundary"),
            tool_mapping("evt-tool-synth", "tool_use"),
            checkpoint_session("evt-chk-synth", 0, Some("ab")),
        ];
        let record = unsafe_continuation_record(&events, None, None, None, None)
            .unwrap()
            .unwrap();
        assert_eq!(record.caused_by, ["compaction"]);
        assert_eq!(record.first_unsafe_index, 1);
        assert_eq!(record.record_id.as_deref(), Some("evt-tool-synth"));
        let err = check_unsafe_continuation(&events, None, None, None, None).unwrap_err();
        assert_codec(err);
    }

    #[test]
    fn claude_code_jsonl_drops_compaction_and_keeps_sl201() {
        let compact = [
            kinded("evt-compact-synth", "compaction_boundary"),
            kinded("evt-tool-synth", "tool_call"),
        ];
        let ctx = claude_jsonl();
        let record = unsafe_continuation_record(&compact, None, None, None, Some(&ctx)).unwrap();
        assert!(record.is_none());
        let findings = check_unsafe_continuation(&compact, None, None, None, Some(&ctx)).unwrap();
        assert!(findings.is_empty());

        let kept = [
            kinded("evt-run-synth", "run_start"),
            kinded("evt-tool-synth", "tool_call"),
        ];
        let record = unsafe_continuation_record(&kept, None, None, None, Some(&ctx))
            .unwrap()
            .unwrap();
        assert_eq!(record.caused_by, ["SL201"]);
    }

    #[test]
    fn omitted_sl201_run_start_gap_emits_before_make_finding() {
        let events = [
            kinded("evt-run-synth", "run_start"),
            kinded("evt-tool-synth", "tool_call"),
        ];
        let record = unsafe_continuation_record(&events, None, None, None, None)
            .unwrap()
            .unwrap();
        assert_eq!(record.caused_by, ["SL201"]);
        assert_eq!(record.first_unsafe_index, 1);
        assert_eq!(record.code, SL203);
        let err = check_unsafe_continuation(&events, None, None, None, None).unwrap_err();
        assert_codec(err);
    }

    #[test]
    fn run_state_sl201_trigger_uses_index_minus_one() {
        let ctx = ctx_meta(json!({
            "checkpoints": [{"id": "rs-open-synth", "seq": 1, "hash": ""}]
        }));
        let events = [kinded("evt-tool-synth", "tool_call")];
        let record = unsafe_continuation_record(&events, None, None, None, Some(&ctx))
            .unwrap()
            .unwrap();
        assert_eq!(record.first_unsafe_index, 0);
        assert_eq!(record.caused_by, ["SL201"]);
    }

    #[test]
    fn caused_by_orders_sl201_before_compaction() {
        let events = [
            kinded("evt-run-synth", "run_start"),
            kinded("evt-compact-synth", "compaction_boundary"),
            kinded("evt-tool-synth", "tool_call"),
        ];
        let record = unsafe_continuation_record(&events, None, None, None, None)
            .unwrap()
            .unwrap();
        assert_eq!(record.caused_by, ["SL201", "compaction"]);
        assert_eq!(record.first_unsafe_index, 2);
    }

    #[test]
    fn caused_by_orders_sl201_sl202_then_compaction() {
        let events = [
            kinded("evt-run-synth", "run_start"),
            checkpoint_session("evt-a-synth", 1, Some("aaaa")),
            checkpoint_session("evt-b-synth", 1, Some("bbbb")),
            kinded("evt-compact-synth", "compaction_boundary"),
            kinded("evt-tool-synth", "tool_call"),
        ];
        let record = unsafe_continuation_record(&events, None, None, None, None)
            .unwrap()
            .unwrap();
        assert_eq!(record.caused_by, ["SL201", "SL202", "compaction"]);
        assert_eq!(record.first_unsafe_index, 4);
    }

    #[test]
    fn provided_priors_are_not_recomputed() {
        let events = [
            kinded("evt-run-synth", "run_start"),
            kinded("evt-tool-synth", "tool_call"),
        ];
        let record = unsafe_continuation_record(
            &events,
            None,
            Some(Sl201Prior::Records(&[])),
            Some(Sl202Prior::Records(&[])),
            None,
        )
        .unwrap();
        assert!(record.is_none());

        let ctx = ctx_meta(json!({
            "checkpoints": [
                {"id": "rs-a-synth", "seq": 1, "hash": "aaaaaaaaaaaaaaaa"},
                {"id": "rs-b-synth", "seq": 1, "hash": "bbbbbbbbbbbbbbbb"}
            ]
        }));
        let priors = checkpoint_divergence_records(&[], None, Some(&ctx), None).unwrap();
        assert_eq!(priors[0].source.as_deref(), Some("run_state"));
        let events = [kinded("evt-tool-synth", "tool_call")];
        let record = unsafe_continuation_record(
            &events,
            None,
            Some(Sl201Prior::Records(&[])),
            Some(Sl202Prior::Records(&priors)),
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(record.first_unsafe_index, 0);
        assert_eq!(record.caused_by, ["SL202"]);
    }

    #[test]
    fn finding_priors_treat_run_state_as_minus_one_and_bool_as_not_an_int() {
        let run_state = finding(
            SL201,
            Some("evt-prior-synth"),
            "aaaaaaaaaaaaaaaa",
            PyValue::map(vec![
                (PyValue::string("source"), PyValue::string("run_state")),
                (PyValue::string("at_index"), PyValue::int(5)),
            ]),
        );
        let events = [kinded("evt-tool-synth", "tool_call")];
        let priors = [run_state];
        let record = unsafe_continuation_record(
            &events,
            None,
            Some(Sl201Prior::Findings(&priors)),
            Some(Sl202Prior::Records(&[])),
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(record.first_unsafe_index, 0);
        assert_eq!(record.caused_by, ["SL201"]);

        let bool_index = finding(
            SL201,
            Some("evt-prior-synth"),
            "aaaaaaaaaaaaaaaa",
            PyValue::map(vec![(
                PyValue::string("at_index"),
                PyValue::bool_value(true),
            )]),
        );
        let events = [
            kinded("evt-other-synth", "message"),
            kinded("evt-other-2-synth", "message"),
            kinded("evt-tool-synth", "tool_call"),
        ];
        let priors = [bool_index];
        let record = unsafe_continuation_record(
            &events,
            None,
            Some(Sl201Prior::Findings(&priors)),
            Some(Sl202Prior::Records(&[])),
            None,
        )
        .unwrap();
        assert!(record.is_none());
    }

    #[test]
    fn bool_true_kind_is_not_an_unsafe_tool() {
        let events = [
            kinded("evt-compact-synth", "compaction_boundary"),
            EventValue::Mapping(EventMapping::new(vec![
                ("kind".to_owned(), EventField::Bool(true)),
                (
                    "id".to_owned(),
                    EventField::Str("evt-bool-synth".to_owned()),
                ),
            ])),
            kinded("evt-tool-synth", "tool_call"),
        ];
        let record = unsafe_continuation_record(&events, None, None, None, None)
            .unwrap()
            .unwrap();
        assert_eq!(record.first_unsafe_index, 2);
        assert_eq!(record.record_id.as_deref(), Some("evt-tool-synth"));
        assert_eq!(record.caused_by, ["compaction"]);
    }

    #[test]
    fn float_kind_between_compaction_and_checkpoint_is_typed() {
        let events = [
            kinded("evt-compact-synth", "compaction_boundary"),
            EventValue::Mapping(EventMapping::new(vec![
                ("kind".to_owned(), EventField::Float(1.5)),
                (
                    "id".to_owned(),
                    EventField::Str("evt-float-synth".to_owned()),
                ),
            ])),
            checkpoint_session("evt-chk-synth", 0, Some("ab")),
        ];
        let err = unsafe_continuation_record(&events, None, None, None, None).unwrap_err();
        assert_eq!(err.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        assert!(matches!(err, CheckpointError::PythonFloatStr));
    }

    #[test]
    fn coverage_pointer_keeps_spaces_and_rejects_blank_or_non_string() {
        let mut event = session("evt-cov-synth");
        event.extra_fields = Payload::map(vec![(
            Payload::string("coverage"),
            Payload::map(vec![(
                Payload::string("covered_through_id"),
                Payload::string("  id-synth  "),
            )]),
        )]);
        let kept = coverage_pointer(&EventValue::from_session(event)).unwrap();
        assert_eq!(kept.as_deref(), Some("  id-synth  "));

        let mut blank = session("evt-blank-synth");
        blank.extra_fields = Payload::map(vec![(
            Payload::string("coverage"),
            Payload::map(vec![(
                Payload::string("covered_through_id"),
                Payload::string("   "),
            )]),
        )]);
        assert_eq!(
            coverage_pointer(&EventValue::from_session(blank)).unwrap(),
            None
        );

        let mut tabbed = session("evt-tab-synth");
        tabbed.extra_fields = Payload::map(vec![(
            Payload::string("coverage"),
            Payload::map(vec![(
                Payload::string("covered_through_id"),
                Payload::string("\t"),
            )]),
        )]);
        assert_eq!(
            coverage_pointer(&EventValue::from_session(tabbed)).unwrap(),
            None
        );

        let mut number = session("evt-num-synth");
        number.extra_fields = Payload::map(vec![(
            Payload::string("coverage"),
            Payload::map(vec![(
                Payload::string("covered_through_id"),
                Payload::int(7),
            )]),
        )]);
        assert_eq!(
            coverage_pointer(&EventValue::from_session(number)).unwrap(),
            None
        );

        let mut text = session("evt-text-synth");
        text.extra_fields = Payload::string("nope");
        assert_eq!(
            coverage_pointer(&EventValue::from_session(text)).unwrap(),
            None
        );

        let mapping = EventValue::Mapping(EventMapping::new(vec![(
            "extra_fields".to_owned(),
            EventField::Mapping(EventMapping::new(vec![(
                "coverage".to_owned(),
                EventField::Mapping(EventMapping::new(vec![(
                    "covered_through_id".to_owned(),
                    EventField::Str("  id-synth  ".to_owned()),
                )])),
            )])),
        )]));
        assert_eq!(
            coverage_pointer(&mapping).unwrap().as_deref(),
            Some("  id-synth  ")
        );

        let non_string = EventValue::Mapping(EventMapping::new(vec![(
            "extra_fields".to_owned(),
            EventField::Mapping(EventMapping::new(vec![(
                "coverage".to_owned(),
                EventField::Mapping(EventMapping::new(vec![(
                    "covered_through_id".to_owned(),
                    EventField::Bool(true),
                )])),
            )])),
        )]));
        assert_eq!(coverage_pointer(&non_string).unwrap(), None);
    }
}
