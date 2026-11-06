//! Checkpoint and continuation integrity checks (SL201, SL202, SL203).
//!
//! Port of `src/sesslint/checks/checkpoint.py` lines 1–262
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! This slice is constants and helpers through
//! [`extract_run_state_projection`]. It does not port `check_` functions,
//! SL201/SL202/SL203 detection, or `__all__`.
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
//! * Python `int` is unbounded. Counts that do not fit in `i64` are
//!   [`PYTHON_INT_UNBOUNDED`], not a wrap and not a panic.
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
//! * A list of events has no `source` attribute. This slice does not scan
//!   events for a run-state projection.
//! * [`CheckContext::source_metadata`] is a [`BTreeMap`]. Copy order is
//!   that map's key order, not a Python `dict` insertion order.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use model::canonical::{MapLookup, Payload, SessionEvent};
use model::codes::{Repairability, Severity};
use model::errors::FindingError;
use model::events::{
    EventField, EventMapping, EventValue, PYTHON_FLOAT_STR_UNREPRESENTABLE,
    PYTHON_STR_UNREPRESENTABLE,
};
use model::finding::{
    enforce_content_free_text, make_finding, EvidenceLookup, Finding, MakeFindingInput, PyValue,
    SourceRef, FINGERPRINT_CODEC_UNAVAILABLE,
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

/// Failure from this slice. [`Display`] is the message only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointError {
    BorrowedLookup,
    PythonIntUnbounded,
    PythonFloatStr,
    PythonStr,
    Finding(FindingError),
}

impl CheckpointError {
    pub fn message(&self) -> &str {
        match self {
            Self::BorrowedLookup => BORROWED_LOOKUP,
            Self::PythonIntUnbounded => PYTHON_INT_UNBOUNDED,
            Self::PythonFloatStr => PYTHON_FLOAT_STR_UNREPRESENTABLE,
            Self::PythonStr => PYTHON_STR_UNREPRESENTABLE,
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
            | Self::PythonStr => None,
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
        cap_checkpoint_findings, cap_finding_sort_key, compute_checkpoint_fingerprint,
        extract_checkpoint_fields, extract_run_state_projection, get_event_id, get_event_kind,
        resolve_source_coords, safe_id, source_record_id, CheckpointError, CheckpointItem,
        KIND_CHECKPOINT, KIND_COMPACTION, KIND_RUN_START, MAX_CHECKPOINT_FINDINGS, MSG_OVERFLOW,
        MSG_SL201, MSG_SL202, MSG_SL203, MSG_SL205, TOOL_KINDS, VARIANT_OVERFLOW,
    };
    use crate::context::CheckContext;
    use model::canonical::{Payload, SessionEvent};
    use model::codes::{Repairability, Severity, SL201};
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
}
