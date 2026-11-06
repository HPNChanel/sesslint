//! Generic tool-pairing integrity checks part 1 (SL101, SL102, SL103, SL104).
//!
//! Port of `src/sesslint/checks/tool_pairing_1.py` lines 1–496
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! This slice stops after [`check_reused`]. It does not port
//! `check_multi_results`, `check_tool_pairing_1`, or `__all__`.
//!
//! This module implements four vendor-neutral tool-pairing rules over canonical events:
//! - SL101 (Orphan tool result): tool_result has no matching tool call.
//!   Severity: error, Repairability: manual.
//!   Rationale: An orphan tool result may represent unverified external state execution
//!   without a proven antecedent request; conservative repair cannot synthesize a call.
//! - SL102 (Dangling tool call): tool call has no matching tool_result.
//!   Severity: error, Repairability: manual.
//!   Rationale: A dangling tool call leaves execution state unresolved; conservative repair
//!   refuses to synthesize fake tool outputs.
//! - SL103 (Reused tool-call ID): Multiple distinct tool calls share a correlation identifier.
//!   Severity: error, Repairability: manual.
//!   Rationale: Reused call identifiers create ambiguity in request-response pairing that
//!   cannot be automatically disambiguated without operator choice.
//! - SL104 (Multiple tool results): Multiple tool_result events match a single tool call.
//!   Severity: error, Repairability: manual.
//!   Rationale: Duplicate or competing responses indicate dropped connections or race conditions
//!   in the upstream environment; manual selection is required.
//!
//! Pairing Keys & Scope:
//! - Tool events are identified strictly by `kind in CALL_KINDS` or `kind in RESULT_KINDS`.
//! - Other event kinds (messages, checkpoints, etc.) are ignored.
//! - The join key is `correlation_id`.
//! - If `correlation_id is None`:
//!     - A tool call is unpairable and flagged as SL102 (dangling-call).
//!     - A tool result is unpairable and flagged as SL101 (orphan-result).
//! - An empty string `""` or whitespace correlation_id is treated as a real key.
//! - When a correlation identifier has both multiple calls and multiple results,
//!   both SL103 and SL104 fire.
//!
//! [`compute_pairing_fingerprint`] hashes locally. It is not a finding digest
//! and does not call [`make_finding`] or [`model::canonical::compute_content_hash`].
//!
//! Pairing sort key is `(code, overflow flag, record id, fingerprint)`. This
//! module does not call [`crate::graph::cap_finding_sort_key`]. Graph does not
//! fall through to evidence `correlation_id`.
//!
//! Under the cap, [`cap_pairing_findings`] returns the sorted list and does
//! not call [`make_finding`]. Over the cap, [`make_finding`] is called with
//! the fingerprint omitted and returns [`FINGERPRINT_CODEC_UNAVAILABLE`].
//! That error is propagated. This module does not append a synthetic overflow
//! finding and does not return the kept prefix as if that finding existed.
//!
//! [`ToolPairingIndexer`] partitions tool events and does not call
//! [`make_finding`]. It does not emit SL101 through SL104. It does not use
//! [`model::events::event_corr_id`].
//!
//! [`record_orphans`], [`record_dangling`], and [`record_reused`] collect
//! records and do not call [`make_finding`]. [`check_orphans`],
//! [`check_dangling`], and [`check_reused`] call [`make_finding`] only when
//! that list is non-empty. The omitted fingerprint returns
//! [`FINGERPRINT_CODEC_UNAVAILABLE`]. An empty list still calls
//! [`cap_pairing_findings`]. Default max 500 returns `Ok([])`.
//! `max_findings == -1` takes the overflow path because `0 <= -1` is false.
//! Today the first real record returns the codec error before cap. This
//! slice does not append an overflow finding and does not invent a digest.
//! Correlation walks sort a copy of the indexer key lists. They do not
//! iterate the [`HashMap`]. This slice does not call
//! [`crate::graph::cap_finding_sort_key`] or
//! [`model::canonical::compute_content_hash`].
//!
//! # Recorded gaps
//!
//! * Python `int` is unbounded. Counts that do not fit in `i64` are
//!   [`PYTHON_INT_UNBOUNDED`], not a wrap and not a panic.
//! * [`EvidenceLookup::Borrowed`] is a failed borrow, not a missing
//!   `overflow` / `correlation_id` key ([`BORROWED_LOOKUP`]).
//! * [`EvidenceLookup::NotAMap`] is [`EVIDENCE_NOT_A_MAP`]. Python would
//!   call `.get` on a non-mapping. [`Finding::try_new`] only stores a
//!   mapping or `None`, so this is not reachable from a constructed
//!   finding.
//! * Overflow [`make_finding`] does not produce a digest
//!   ([`FINGERPRINT_CODEC_UNAVAILABLE`]).
//! * Offender [`make_finding`] does not produce a digest
//!   ([`FINGERPRINT_CODEC_UNAVAILABLE`]).
//! * A float `source_location`, `correlation_id`, or event `id` is
//!   [`model::events::PYTHON_FLOAT_STR_UNREPRESENTABLE`]. Rust `Display`
//!   is not used.
//! * A list or mapping `source_location`, `correlation_id`, or event `id`
//!   is [`model::events::PYTHON_STR_UNREPRESENTABLE`]. A Python repr is not
//!   invented.
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;

use model::canonical::SessionEvent;
use model::codes::{Repairability, Severity, SL101, SL102, SL103};
use model::errors::FindingError;
use model::events::{
    EventField, EventValue, PYTHON_FLOAT_STR_UNREPRESENTABLE, PYTHON_STR_UNREPRESENTABLE,
};
use model::finding::{
    enforce_content_free_text, make_finding, EvidenceLookup, Finding, MakeFindingInput, PyValue,
    SourceLine, SourceRef, FINGERPRINT_CODEC_UNAVAILABLE,
};
use sha2::{Digest, Sha256};

use crate::context::CheckContext;

/// Python: `MAX_PAIRING_FINDINGS`.
pub const MAX_PAIRING_FINDINGS: i64 = 500;

/// Python: `MAX_INDEX_SAMPLE_SIZE`.
pub const MAX_INDEX_SAMPLE_SIZE: i64 = 32;

/// Python: `MAX_PAIRING_SAMPLE_SIZE`.
pub const MAX_PAIRING_SAMPLE_SIZE: i64 = MAX_INDEX_SAMPLE_SIZE;

/// Python: `_KIND_TOOL_USE`.
pub const KIND_TOOL_USE: &str = "tool_use";

/// Python: `_KIND_TOOL_CALL`.
pub const KIND_TOOL_CALL: &str = "tool_call";

/// Python: `_KIND_TOOL_RESULT`.
pub const KIND_TOOL_RESULT: &str = "tool_result";

/// Python: `CALL_KINDS`. Membership is exact.
pub const CALL_KINDS: &[&str] = &[KIND_TOOL_CALL, KIND_TOOL_USE];

/// Python: `RESULT_KINDS`. Membership is exact.
pub const RESULT_KINDS: &[&str] = &[KIND_TOOL_RESULT];

/// Python: `_MSG_SL101`.
pub const MSG_SL101: &str = "Orphan tool result detected for record {record_id}";

/// Python: `_MSG_SL102`.
pub const MSG_SL102: &str = "Dangling tool call detected for record {record_id}";

/// Python: `_MSG_SL103`.
pub const MSG_SL103: &str = "Reused tool-call ID detected for record {record_id}";

/// Python: `_MSG_SL104`.
pub const MSG_SL104: &str = "Multiple tool results detected for record {record_id}";

/// Python: `_MSG_OVERFLOW`.
pub const MSG_OVERFLOW: &str =
    "Tool pairing check finding cap reached; remaining records truncated";

/// Python `int` is unbounded; an `i64` overflow is not a wrap.
pub const PYTHON_INT_UNBOUNDED: &str =
    "Python ints are unbounded; an i64 overflow is not a wrap and not a panic";

/// [`EvidenceLookup::Borrowed`] is not a missing key.
pub const BORROWED_LOOKUP: &str = "A borrowed map lookup is not a missing key";

/// [`EvidenceLookup::NotAMap`]: Python would call `.get` on a non-mapping.
pub const EVIDENCE_NOT_A_MAP: &str =
    "Evidence is not a mapping; Python would call .get on a non-mapping";

/// Failure from this slice. [`Display`] is the message only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolPairing1Error {
    BorrowedLookup,
    EvidenceNotAMap,
    PythonIntUnbounded,
    PythonFloatStr,
    PythonStr,
    Finding(FindingError),
}

impl ToolPairing1Error {
    pub fn message(&self) -> &str {
        match self {
            Self::BorrowedLookup => BORROWED_LOOKUP,
            Self::EvidenceNotAMap => EVIDENCE_NOT_A_MAP,
            Self::PythonIntUnbounded => PYTHON_INT_UNBOUNDED,
            Self::PythonFloatStr => PYTHON_FLOAT_STR_UNREPRESENTABLE,
            Self::PythonStr => PYTHON_STR_UNREPRESENTABLE,
            Self::Finding(error) => error.message(),
        }
    }
}

impl fmt::Display for ToolPairing1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for ToolPairing1Error {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Finding(error) => Some(error),
            Self::BorrowedLookup
            | Self::EvidenceNotAMap
            | Self::PythonIntUnbounded
            | Self::PythonFloatStr
            | Self::PythonStr => None,
        }
    }
}

impl From<FindingError> for ToolPairing1Error {
    fn from(error: FindingError) -> Self {
        Self::Finding(error)
    }
}

/// Python: `_safe_id`.
///
/// `None` returns `"<redacted>"`. Any [`enforce_content_free_text`] error
/// with context `"id"` returns `"<redacted>"`. On success the original
/// text is kept, including surrounding spaces.
pub fn safe_id(id_str: Option<&str>) -> String {
    let Some(text) = id_str else {
        return "<redacted>".to_owned();
    };
    match enforce_content_free_text(text, "id") {
        Ok(()) => text.to_owned(),
        Err(_) => "<redacted>".to_owned(),
    }
}

/// Python: `_source_record_id`.
///
/// `None` and whitespace-only text return `None`. Strip is only the
/// emptiness test. A non-empty strip returns [`safe_id`] of the original
/// text, not the stripped text.
pub fn source_record_id(id_str: Option<&str>) -> Option<String> {
    let text = id_str?;
    if text.trim().is_empty() {
        return None;
    }
    Some(safe_id(Some(text)))
}

/// Python: `compute_pairing_fingerprint`.
///
/// `sha256("{code}|{comma-join of sorted unique items}")` then the first
/// 16 lowercase hex characters. Python uses `set` then `sorted`, so
/// duplicates collapse. This does not call [`make_finding`].
pub fn compute_pairing_fingerprint(
    code: &str,
    items: impl IntoIterator<Item = impl AsRef<str>>,
) -> String {
    let mut unique = HashSet::new();
    for item in items {
        unique.insert(item.as_ref().to_owned());
    }
    let mut sorted_items: Vec<String> = unique.into_iter().collect();
    sorted_items.sort();
    let mut content = String::from(code);
    content.push('|');
    let mut first = true;
    for item in &sorted_items {
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
/// `(code, 1 if evidence overflow is JSON true else 0, record id, fingerprint)`.
/// A bool is not another truthy value. Missing, `false`, `1`, and the
/// string `"true"` are 0. Record id is `source.record_id`, or `""` when
/// it is missing. An empty string is falsy, so then read evidence key
/// `correlation_id` when that value is a string.
pub fn cap_finding_sort_key(
    finding: &Finding,
) -> Result<(String, i32, String, String), ToolPairing1Error> {
    let is_overflow = overflow_flag(finding)?;
    let rec_id = record_id_for_sort(finding)?;
    Ok((
        finding.code().to_owned(),
        is_overflow,
        rec_id,
        finding.fingerprint().to_owned(),
    ))
}

/// Python: `cap_pairing_findings`.
///
/// Omitted `max_findings` is [`MAX_PAIRING_FINDINGS`]. Omitted `source_path`
/// is `"<canonical>"`. Omitted `context` is [`CheckContext::default`].
/// Comparison is the Python `<=`. A negative max is not special-cased: an
/// empty list with `max_findings == -1` takes the overflow path because
/// `0 <= -1` is false.
pub fn cap_pairing_findings(
    findings: Vec<Finding>,
    code: &str,
    max_findings: Option<i64>,
    source_path: Option<&str>,
    context: Option<&CheckContext>,
) -> Result<Vec<Finding>, ToolPairing1Error> {
    let max_findings = max_findings.unwrap_or(MAX_PAIRING_FINDINGS);

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
        .ok_or(ToolPairing1Error::PythonIntUnbounded)?;
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
                PyValue::string("overflow-summary"),
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
        Ok(_finding) => Err(ToolPairing1Error::Finding(FindingError::new(
            FINGERPRINT_CODEC_UNAVAILABLE,
        ))),
    }
}

/// Python: `_resolve_source_coords`.
///
/// `source_location` is the event attribute, else a mapping key. When
/// `default_path` is not exactly `"<canonical>"`, the path is
/// `default_path`. When `default_path` is `"<canonical>"` and the location
/// is missing or falsy, the path is `"<canonical>"`. Otherwise the path is
/// the string form of the location. Backslashes are then replaced.
/// A line is kept only when it is a non-bool int ≥ 1.
pub fn resolve_source_coords(
    event: &EventValue,
    default_path: &str,
) -> Result<(String, Option<i64>), ToolPairing1Error> {
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

/// Python: `_ToolPairingIndexer`.
///
/// Single-pass indexer partitioning tool events by `correlation_id`.
/// Group order is first-seen key order, not [`HashMap`] or `BTreeMap`
/// iteration. Stored pairs are `(index, event)` in encounter order.
#[derive(Debug)]
pub struct ToolPairingIndexer<'a> {
    source_path: String,
    uses_order: Vec<String>,
    uses_by_corr: HashMap<String, Vec<(usize, &'a EventValue)>>,
    results_order: Vec<String>,
    results_by_corr: HashMap<String, Vec<(usize, &'a EventValue)>>,
    null_uses: Vec<(usize, &'a EventValue)>,
    null_results: Vec<(usize, &'a EventValue)>,
}

impl<'a> ToolPairingIndexer<'a> {
    /// Python: `_ToolPairingIndexer.__init__`.
    ///
    /// Omitted `source_path` is `"<canonical>"`. A [`SessionEvent`] uses
    /// `kind` and `correlation_id` fields. A mapping uses those keys.
    /// Other values are ignored. Kind membership is exact. `None`, missing,
    /// and JSON null correlation ids go to the null bucket.
    pub fn new(
        events: &'a [EventValue],
        source_path: Option<&str>,
    ) -> Result<Self, ToolPairing1Error> {
        let mut indexer = Self {
            source_path: source_path.unwrap_or("<canonical>").to_owned(),
            uses_order: Vec::new(),
            uses_by_corr: HashMap::new(),
            results_order: Vec::new(),
            results_by_corr: HashMap::new(),
            null_uses: Vec::new(),
            null_results: Vec::new(),
        };
        for (idx, ev) in events.iter().enumerate() {
            let (raw_kind, corr) = kind_and_corr(ev);
            let Some(kind) = string_kind(raw_kind.as_ref()) else {
                continue;
            };
            if is_call_kind(kind) {
                match corr_key(corr.as_ref())? {
                    None => indexer.null_uses.push((idx, ev)),
                    Some(key) => push_group(
                        &mut indexer.uses_order,
                        &mut indexer.uses_by_corr,
                        key,
                        idx,
                        ev,
                    ),
                }
            } else if is_result_kind(kind) {
                match corr_key(corr.as_ref())? {
                    None => indexer.null_results.push((idx, ev)),
                    Some(key) => push_group(
                        &mut indexer.results_order,
                        &mut indexer.results_by_corr,
                        key,
                        idx,
                        ev,
                    ),
                }
            }
        }
        Ok(indexer)
    }

    pub fn source_path(&self) -> &str {
        &self.source_path
    }

    pub fn uses_keys(&self) -> &[String] {
        &self.uses_order
    }

    pub fn results_keys(&self) -> &[String] {
        &self.results_order
    }

    pub fn uses(&self, corr: &str) -> &[(usize, &'a EventValue)] {
        self.uses_by_corr
            .get(corr)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn results(&self, corr: &str) -> &[(usize, &'a EventValue)] {
        self.results_by_corr
            .get(corr)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn null_uses(&self) -> &[(usize, &'a EventValue)] {
        &self.null_uses
    }

    pub fn null_results(&self) -> &[(usize, &'a EventValue)] {
        &self.null_results
    }
}

fn overflow_flag(finding: &Finding) -> Result<i32, ToolPairing1Error> {
    let Some(evidence) = finding.evidence() else {
        return Ok(0);
    };
    match evidence.map_string("overflow") {
        EvidenceLookup::Borrowed => Err(ToolPairing1Error::BorrowedLookup),
        EvidenceLookup::NotAMap => Err(ToolPairing1Error::EvidenceNotAMap),
        EvidenceLookup::Present(value) if value.as_bool() == Some(true) => Ok(1),
        EvidenceLookup::Present(_) | EvidenceLookup::Absent => Ok(0),
    }
}

fn record_id_for_sort(finding: &Finding) -> Result<String, ToolPairing1Error> {
    if let Some(id) = finding.source().record_id() {
        if !id.is_empty() {
            return Ok(id.to_owned());
        }
    }
    let Some(evidence) = finding.evidence() else {
        return Ok(String::new());
    };
    match evidence.map_string("correlation_id") {
        EvidenceLookup::Borrowed => Err(ToolPairing1Error::BorrowedLookup),
        EvidenceLookup::NotAMap => Err(ToolPairing1Error::EvidenceNotAMap),
        EvidenceLookup::Absent => Ok(String::new()),
        EvidenceLookup::Present(value) => match value.as_str() {
            Some(text) => Ok(text.to_owned()),
            None => Ok(String::new()),
        },
    }
}

fn source_field(event: &EventValue, field: &str) -> Option<EventField> {
    match event {
        EventValue::Session(session) => session_source_field(session, field),
        EventValue::Mapping(mapping) => mapping.get(field).cloned(),
        EventValue::Other => None,
    }
}

fn session_source_field(session: &SessionEvent, field: &str) -> Option<EventField> {
    match field {
        "source_location" => session.source_location.clone().map(EventField::Str),
        "source_line" => session.source_line.map(EventField::Int),
        _ => None,
    }
}

fn location_text(field: &EventField) -> Result<Option<String>, ToolPairing1Error> {
    match field {
        EventField::Null | EventField::Bool(false) => Ok(None),
        EventField::Bool(true) => Ok(Some("True".to_owned())),
        EventField::Int(0) => Ok(None),
        EventField::Int(number) => Ok(Some(number.to_string())),
        EventField::Str(text) if text.is_empty() => Ok(None),
        EventField::Str(text) => Ok(Some(text.clone())),
        EventField::Float(number) if *number == 0.0 => Ok(None),
        EventField::Float(_) => Err(ToolPairing1Error::PythonFloatStr),
        EventField::List(items) if items.is_empty() => Ok(None),
        EventField::Mapping(mapping) if mapping.entries().is_empty() => Ok(None),
        EventField::List(_) | EventField::Mapping(_) => Err(ToolPairing1Error::PythonStr),
    }
}

fn kind_and_corr(event: &EventValue) -> (Option<EventField>, Option<EventField>) {
    match event {
        EventValue::Session(session) => (
            Some(EventField::Str(session.kind.clone())),
            session
                .correlation_id
                .as_deref()
                .map(|text| EventField::Str(text.to_owned())),
        ),
        EventValue::Mapping(mapping) => (
            mapping.get("kind").cloned(),
            mapping.get("correlation_id").cloned(),
        ),
        EventValue::Other => (None, None),
    }
}

fn string_kind(kind: Option<&EventField>) -> Option<&str> {
    match kind {
        Some(EventField::Str(text)) => Some(text.as_str()),
        _ => None,
    }
}

fn is_call_kind(kind: &str) -> bool {
    CALL_KINDS.contains(&kind)
}

fn is_result_kind(kind: &str) -> bool {
    RESULT_KINDS.contains(&kind)
}

fn corr_key(corr: Option<&EventField>) -> Result<Option<String>, ToolPairing1Error> {
    match corr {
        None | Some(EventField::Null) => Ok(None),
        Some(EventField::Str(text)) => Ok(Some(text.clone())),
        Some(EventField::Bool(true)) => Ok(Some("True".to_owned())),
        Some(EventField::Bool(false)) => Ok(Some("False".to_owned())),
        Some(EventField::Int(number)) => Ok(Some(number.to_string())),
        Some(EventField::Float(_)) => Err(ToolPairing1Error::PythonFloatStr),
        Some(EventField::List(_) | EventField::Mapping(_)) => Err(ToolPairing1Error::PythonStr),
    }
}

fn push_group<'a>(
    order: &mut Vec<String>,
    by_corr: &mut HashMap<String, Vec<(usize, &'a EventValue)>>,
    key: String,
    idx: usize,
    event: &'a EventValue,
) {
    if !by_corr.contains_key(&key) {
        order.push(key.clone());
    }
    by_corr.entry(key).or_default().push((idx, event));
}

fn usize_to_i64(value: usize) -> Result<i64, ToolPairing1Error> {
    i64::try_from(value).map_err(|_| ToolPairing1Error::PythonIntUnbounded)
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

const REDACTED_ID: &str = "<redacted>";
const CODEX_ROLLOUT: &str = "codex-rollout";

/// One orphan tool result that would emit SL101. Does not call [`make_finding`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrphanRecord {
    pub path: String,
    pub line: Option<i64>,
    pub record_id: Option<String>,
    pub related_ids: Vec<String>,
    pub correlation_id: Option<String>,
    pub index: i64,
    pub result_id: String,
}

/// One dangling tool call that would emit SL102. Does not call [`make_finding`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DanglingRecord {
    pub path: String,
    pub line: Option<i64>,
    pub record_id: Option<String>,
    pub related_ids: Vec<String>,
    pub correlation_id: Option<String>,
    pub event_id: String,
    pub index: i64,
}

/// One reused correlation id that would emit SL103. Does not call [`make_finding`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReusedRecord {
    pub path: String,
    pub line: Option<i64>,
    pub record_id: Option<String>,
    pub related_ids: Vec<String>,
    pub call_ids: Vec<String>,
    pub call_indexes: Vec<i64>,
    pub correlation_id: String,
    pub count: i64,
    pub event_ids: Vec<String>,
    pub truncated: bool,
}

/// Python: `check_orphans` record walk. Does not call [`make_finding`].
///
/// Keys are a sorted copy of the indexer result-key list minus the use-key
/// set. Encounter order inside a key is kept. Null results are skipped
/// only when `adapter_id` is exactly `"codex-rollout"`.
pub fn record_orphans(
    indexer: &ToolPairingIndexer<'_>,
    source_path: &str,
    adapter_id: &str,
) -> Result<Vec<OrphanRecord>, ToolPairing1Error> {
    let mut records = Vec::new();
    let use_keys = key_set(indexer.uses_keys());
    let mut orphan_corrs: Vec<String> = indexer
        .results_keys()
        .iter()
        .filter(|key| !use_keys.contains(key.as_str()))
        .cloned()
        .collect();
    orphan_corrs.sort();
    for corr in &orphan_corrs {
        let safe_corr = safe_id(Some(corr));
        for &(idx, ev) in indexer.results(corr) {
            records.push(orphan_record(
                ev,
                idx,
                Some(safe_corr.clone()),
                source_path,
            )?);
        }
    }
    if adapter_id != CODEX_ROLLOUT {
        for &(idx, ev) in indexer.null_results() {
            records.push(orphan_record(ev, idx, None, source_path)?);
        }
    }
    Ok(records)
}

/// Python: `check_orphans`.
///
/// Context `None` is [`CheckContext::default`]. A non-empty record list
/// calls [`make_finding`] with the fingerprint omitted; the first record
/// returns [`FINGERPRINT_CODEC_UNAVAILABLE`]. An empty list still calls
/// [`cap_pairing_findings`].
pub fn check_orphans(
    events: &[EventValue],
    source_path: Option<&str>,
    max_findings: Option<i64>,
    context: Option<&CheckContext>,
) -> Result<Vec<Finding>, ToolPairing1Error> {
    let source_path = source_path.unwrap_or("<canonical>");
    let owned_ctx;
    let ctx = match context {
        Some(value) => value,
        None => {
            owned_ctx = CheckContext::default();
            &owned_ctx
        }
    };
    let indexer = ToolPairingIndexer::new(events, Some(source_path))?;
    let records = record_orphans(&indexer, source_path, ctx.adapter_id())?;
    let mut findings = Vec::new();
    for record in &records {
        findings.push(orphan_finding(record, ctx)?);
    }
    cap_pairing_findings(findings, SL101, max_findings, Some(source_path), Some(ctx))
}

/// Python: `check_dangling` record walk. Does not call [`make_finding`].
///
/// Keys are a sorted copy of the indexer use-key list minus the result-key
/// set. Null uses always record, including when `adapter_id` is
/// `"codex-rollout"`.
pub fn record_dangling(
    indexer: &ToolPairingIndexer<'_>,
    source_path: &str,
) -> Result<Vec<DanglingRecord>, ToolPairing1Error> {
    let mut records = Vec::new();
    let result_keys = key_set(indexer.results_keys());
    let mut dangling_corrs: Vec<String> = indexer
        .uses_keys()
        .iter()
        .filter(|key| !result_keys.contains(key.as_str()))
        .cloned()
        .collect();
    dangling_corrs.sort();
    for corr in &dangling_corrs {
        let safe_corr = safe_id(Some(corr));
        for &(idx, ev) in indexer.uses(corr) {
            records.push(dangling_record(
                ev,
                idx,
                Some(safe_corr.clone()),
                source_path,
            )?);
        }
    }
    for &(idx, ev) in indexer.null_uses() {
        records.push(dangling_record(ev, idx, None, source_path)?);
    }
    Ok(records)
}

/// Python: `check_dangling`.
///
/// Context `None` is [`CheckContext::default`]. Null uses always flag.
/// There is no codex exception on this function.
pub fn check_dangling(
    events: &[EventValue],
    source_path: Option<&str>,
    max_findings: Option<i64>,
    context: Option<&CheckContext>,
) -> Result<Vec<Finding>, ToolPairing1Error> {
    let source_path = source_path.unwrap_or("<canonical>");
    let owned_ctx;
    let ctx = match context {
        Some(value) => value,
        None => {
            owned_ctx = CheckContext::default();
            &owned_ctx
        }
    };
    let indexer = ToolPairingIndexer::new(events, Some(source_path))?;
    let records = record_dangling(&indexer, source_path)?;
    let mut findings = Vec::new();
    for record in &records {
        findings.push(dangling_finding(record, ctx)?);
    }
    cap_pairing_findings(findings, SL102, max_findings, Some(source_path), Some(ctx))
}

/// Python: `check_reused` record walk. Does not call [`make_finding`].
///
/// One record per correlation id whose use list length is greater than 1.
/// Keys are a sorted copy of the indexer use-key list. A single use is
/// silent. The id sample is truncated to [`MAX_INDEX_SAMPLE_SIZE`].
pub fn record_reused(
    indexer: &ToolPairingIndexer<'_>,
    source_path: &str,
) -> Result<Vec<ReusedRecord>, ToolPairing1Error> {
    let mut records = Vec::new();
    let mut use_corrs = indexer.uses_keys().to_vec();
    use_corrs.sort();
    let sample_cap = sample_cap()?;
    for corr in &use_corrs {
        let occ = indexer.uses(corr);
        if occ.len() <= 1 {
            continue;
        }
        let mut call_indexes = Vec::new();
        let mut call_ids = Vec::new();
        for &(idx, ev) in occ {
            call_indexes.push(usize_to_i64(idx)?);
            let ev_id = event_id_text(ev, idx, "call")?;
            call_ids.push(safe_id(Some(&ev_id)));
        }
        let safe_corr = safe_id(Some(corr));
        let first_ev = occ[0].1;
        let first_ev_id = call_ids.first().map(String::as_str);
        let rec_id = source_record_id(first_ev_id);
        let (path, line) = resolve_source_coords(first_ev, source_path)?;
        let sample_indexes = call_indexes.iter().copied().take(sample_cap).collect();
        let sample_ids: Vec<String> = call_ids.iter().take(sample_cap).cloned().collect();
        let count = usize_to_i64(occ.len())?;
        let truncated = count > MAX_INDEX_SAMPLE_SIZE;
        records.push(ReusedRecord {
            path,
            line,
            record_id: rec_id,
            related_ids: sample_ids.clone(),
            call_ids: sample_ids.clone(),
            call_indexes: sample_indexes,
            correlation_id: safe_corr,
            count,
            event_ids: sample_ids,
            truncated,
        });
    }
    Ok(records)
}

/// Python: `check_reused`.
///
/// Context `None` is [`CheckContext::default`]. A single use is silent.
pub fn check_reused(
    events: &[EventValue],
    source_path: Option<&str>,
    max_findings: Option<i64>,
    context: Option<&CheckContext>,
) -> Result<Vec<Finding>, ToolPairing1Error> {
    let source_path = source_path.unwrap_or("<canonical>");
    let owned_ctx;
    let ctx = match context {
        Some(value) => value,
        None => {
            owned_ctx = CheckContext::default();
            &owned_ctx
        }
    };
    let indexer = ToolPairingIndexer::new(events, Some(source_path))?;
    let records = record_reused(&indexer, source_path)?;
    let mut findings = Vec::new();
    for record in &records {
        findings.push(reused_finding(record, ctx)?);
    }
    cap_pairing_findings(findings, SL103, max_findings, Some(source_path), Some(ctx))
}

fn key_set(keys: &[String]) -> HashSet<&str> {
    keys.iter().map(String::as_str).collect()
}

fn sample_cap() -> Result<usize, ToolPairing1Error> {
    usize::try_from(MAX_INDEX_SAMPLE_SIZE).map_err(|_| ToolPairing1Error::PythonIntUnbounded)
}

fn id_field(event: &EventValue) -> Option<EventField> {
    match event {
        EventValue::Session(session) => Some(EventField::Str(session.id.clone())),
        EventValue::Mapping(mapping) => mapping.get("id").cloned(),
        EventValue::Other => None,
    }
}

fn event_id_text(event: &EventValue, idx: usize, kind: &str) -> Result<String, ToolPairing1Error> {
    match corr_key(id_field(event).as_ref())? {
        Some(text) => Ok(text),
        None => Ok(format!("<{kind}:{}>", usize_to_i64(idx)?)),
    }
}

fn related_corr(safe_corr: &str) -> Vec<String> {
    if safe_corr == REDACTED_ID {
        Vec::new()
    } else {
        vec![safe_corr.to_owned()]
    }
}

fn orphan_record(
    ev: &EventValue,
    idx: usize,
    correlation_id: Option<String>,
    source_path: &str,
) -> Result<OrphanRecord, ToolPairing1Error> {
    let ev_id_str = event_id_text(ev, idx, "result")?;
    let safe_ev_id = safe_id(Some(&ev_id_str));
    let rec_id = source_record_id(Some(&ev_id_str));
    let (path, line) = resolve_source_coords(ev, source_path)?;
    let related_ids = match &correlation_id {
        Some(corr) => related_corr(corr),
        None => Vec::new(),
    };
    Ok(OrphanRecord {
        path,
        line,
        record_id: rec_id,
        related_ids,
        correlation_id,
        index: usize_to_i64(idx)?,
        result_id: safe_ev_id,
    })
}

fn dangling_record(
    ev: &EventValue,
    idx: usize,
    correlation_id: Option<String>,
    source_path: &str,
) -> Result<DanglingRecord, ToolPairing1Error> {
    let ev_id_str = event_id_text(ev, idx, "call")?;
    let safe_ev_id = safe_id(Some(&ev_id_str));
    let rec_id = source_record_id(Some(&ev_id_str));
    let (path, line) = resolve_source_coords(ev, source_path)?;
    let related_ids = match &correlation_id {
        Some(corr) => related_corr(corr),
        None => Vec::new(),
    };
    Ok(DanglingRecord {
        path,
        line,
        record_id: rec_id,
        related_ids,
        correlation_id,
        event_id: safe_ev_id,
        index: usize_to_i64(idx)?,
    })
}

fn py_strings(items: &[String]) -> Vec<PyValue> {
    items
        .iter()
        .map(|item| PyValue::string(item.clone()))
        .collect()
}

fn orphan_evidence(record: &OrphanRecord) -> PyValue {
    let correlation_id = match &record.correlation_id {
        Some(text) => PyValue::string(text.clone()),
        None => PyValue::None,
    };
    PyValue::map(vec![
        (PyValue::string("correlation_id"), correlation_id),
        (PyValue::string("index"), PyValue::int(record.index)),
        (
            PyValue::string("result_id"),
            PyValue::string(record.result_id.clone()),
        ),
    ])
}

fn dangling_evidence(record: &DanglingRecord) -> PyValue {
    let correlation_id = match &record.correlation_id {
        Some(text) => PyValue::string(text.clone()),
        None => PyValue::None,
    };
    PyValue::map(vec![
        (PyValue::string("correlation_id"), correlation_id),
        (
            PyValue::string("event_id"),
            PyValue::string(record.event_id.clone()),
        ),
        (PyValue::string("index"), PyValue::int(record.index)),
    ])
}

fn reused_evidence(record: &ReusedRecord) -> PyValue {
    PyValue::map(vec![
        (
            PyValue::string("call_ids"),
            PyValue::list(py_strings(&record.call_ids)),
        ),
        (
            PyValue::string("call_indexes"),
            PyValue::list(
                record
                    .call_indexes
                    .iter()
                    .copied()
                    .map(PyValue::int)
                    .collect(),
            ),
        ),
        (
            PyValue::string("correlation_id"),
            PyValue::string(record.correlation_id.clone()),
        ),
        (PyValue::string("count"), PyValue::int(record.count)),
        (
            PyValue::string("event_ids"),
            PyValue::list(py_strings(&record.event_ids)),
        ),
        (
            PyValue::string("truncated"),
            PyValue::bool_value(record.truncated),
        ),
    ])
}

fn pairing_source(
    path: &str,
    line: Option<i64>,
    record_id: Option<&str>,
) -> Result<SourceRef, ToolPairing1Error> {
    Ok(SourceRef::try_new(
        path,
        line.map(SourceLine::Int),
        record_id,
    )?)
}

fn context_fields(
    ctx: &CheckContext,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    (
        Some(ctx.adapter_id().to_owned()),
        Some(ctx.adapter_version().to_owned()),
        Some(ctx.profile_id().to_owned()),
        Some(ctx.profile_version().to_owned()),
    )
}

fn orphan_finding(record: &OrphanRecord, ctx: &CheckContext) -> Result<Finding, ToolPairing1Error> {
    let source = pairing_source(&record.path, record.line, record.record_id.as_deref())?;
    let (adapter_id, adapter_version, profile_id, profile_version) = context_fields(ctx);
    Ok(make_finding(&MakeFindingInput {
        code: PyValue::string(SL101),
        severity: PyValue::severity(Severity::Error),
        repairability: PyValue::repairability(Repairability::Manual),
        message_template: PyValue::string(MSG_SL101),
        template_args: PyValue::None,
        source: PyValue::source(source),
        related_ids: PyValue::tuple(py_strings(&record.related_ids)),
        evidence: orphan_evidence(record),
        fingerprint: PyValue::None,
        adapter_id,
        adapter_version,
        profile_id,
        profile_version,
        ordinal: None,
        context: None,
    })?)
}

fn dangling_finding(
    record: &DanglingRecord,
    ctx: &CheckContext,
) -> Result<Finding, ToolPairing1Error> {
    let source = pairing_source(&record.path, record.line, record.record_id.as_deref())?;
    let (adapter_id, adapter_version, profile_id, profile_version) = context_fields(ctx);
    Ok(make_finding(&MakeFindingInput {
        code: PyValue::string(SL102),
        severity: PyValue::severity(Severity::Error),
        repairability: PyValue::repairability(Repairability::Manual),
        message_template: PyValue::string(MSG_SL102),
        template_args: PyValue::None,
        source: PyValue::source(source),
        related_ids: PyValue::tuple(py_strings(&record.related_ids)),
        evidence: dangling_evidence(record),
        fingerprint: PyValue::None,
        adapter_id,
        adapter_version,
        profile_id,
        profile_version,
        ordinal: None,
        context: None,
    })?)
}

fn reused_finding(record: &ReusedRecord, ctx: &CheckContext) -> Result<Finding, ToolPairing1Error> {
    let source = pairing_source(&record.path, record.line, record.record_id.as_deref())?;
    let (adapter_id, adapter_version, profile_id, profile_version) = context_fields(ctx);
    Ok(make_finding(&MakeFindingInput {
        code: PyValue::string(SL103),
        severity: PyValue::severity(Severity::Error),
        repairability: PyValue::repairability(Repairability::Manual),
        message_template: PyValue::string(MSG_SL103),
        template_args: PyValue::None,
        source: PyValue::source(source),
        related_ids: PyValue::tuple(py_strings(&record.related_ids)),
        evidence: reused_evidence(record),
        fingerprint: PyValue::None,
        adapter_id,
        adapter_version,
        profile_id,
        profile_version,
        ordinal: None,
        context: None,
    })?)
}

#[cfg(test)]
mod tests {
    use super::{
        cap_finding_sort_key, cap_pairing_findings, check_dangling, check_orphans, check_reused,
        compute_pairing_fingerprint, record_dangling, record_orphans, record_reused,
        resolve_source_coords, safe_id, source_record_id, ToolPairing1Error, ToolPairingIndexer,
        CALL_KINDS, KIND_TOOL_CALL, KIND_TOOL_RESULT, KIND_TOOL_USE, MAX_INDEX_SAMPLE_SIZE,
        MAX_PAIRING_FINDINGS, MAX_PAIRING_SAMPLE_SIZE, MSG_OVERFLOW, MSG_SL101, MSG_SL102,
        MSG_SL103, MSG_SL104, RESULT_KINDS,
    };
    use crate::context::CheckContext;
    use model::canonical::SessionEvent;
    use model::codes::{Repairability, Severity, SL103};
    use model::events::{
        EventField, EventMapping, EventValue, PYTHON_FLOAT_STR_UNREPRESENTABLE,
        PYTHON_STR_UNREPRESENTABLE,
    };
    use model::finding::{
        Finding, FindingInput, PyValue, SourceRef, FINGERPRINT_CODEC_UNAVAILABLE, SCHEMA_VERSION,
    };

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
            message: PyValue::string("synthetic pairing marker"),
            source: PyValue::source(source),
            related_ids: PyValue::tuple(Vec::new()),
            fingerprint: PyValue::string(fingerprint),
            schema_version: PyValue::string(SCHEMA_VERSION),
            message_template: PyValue::None,
            evidence,
        })
        .unwrap()
    }

    fn session(kind: &str, corr: Option<&str>) -> EventValue {
        let mut event = SessionEvent::new(
            "evt-synthetic",
            None,
            0,
            "2024-02-29T00:00:00Z",
            "assistant",
            kind,
        );
        event.correlation_id = corr.map(str::to_owned);
        EventValue::from_session(event)
    }

    fn session_named(id: &str, kind: &str, corr: Option<&str>) -> EventValue {
        let mut event = SessionEvent::new(id, None, 0, "2024-02-29T00:00:00Z", "assistant", kind);
        event.correlation_id = corr.map(str::to_owned);
        EventValue::from_session(event)
    }

    fn mapping(entries: &[(&str, EventField)]) -> EventValue {
        EventValue::Mapping(EventMapping::new(
            entries
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone()))
                .collect(),
        ))
    }

    fn adapter_ctx(adapter_id: &str) -> CheckContext {
        CheckContext::new(adapter_id, "unknown", "unknown", "unknown", None, 2000)
    }

    fn silent_pair() -> [EventValue; 2] {
        [
            session(KIND_TOOL_CALL, Some("corr-synth")),
            session(KIND_TOOL_RESULT, Some("corr-synth")),
        ]
    }

    fn field_str(value: &str) -> EventField {
        EventField::Str(value.to_owned())
    }

    fn assert_codec_unavailable(err: ToolPairing1Error) {
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(err.message(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!is_lower_hex16(&err.to_string()));
        assert!(matches!(err, ToolPairing1Error::Finding(_)));
    }

    #[test]
    fn constants_match_the_pin() {
        assert_eq!(MAX_PAIRING_FINDINGS, 500);
        assert_eq!(MAX_INDEX_SAMPLE_SIZE, 32);
        assert_eq!(MAX_PAIRING_SAMPLE_SIZE, 32);
        assert_eq!(KIND_TOOL_CALL, "tool_call");
        assert_eq!(KIND_TOOL_USE, "tool_use");
        assert_eq!(KIND_TOOL_RESULT, "tool_result");
        assert_eq!(CALL_KINDS, &["tool_call", "tool_use"]);
        assert_eq!(RESULT_KINDS, &["tool_result"]);
        assert_eq!(
            MSG_SL101,
            "Orphan tool result detected for record {record_id}"
        );
        assert_eq!(
            MSG_SL102,
            "Dangling tool call detected for record {record_id}"
        );
        assert_eq!(
            MSG_SL103,
            "Reused tool-call ID detected for record {record_id}"
        );
        assert_eq!(
            MSG_SL104,
            "Multiple tool results detected for record {record_id}"
        );
        assert_eq!(
            MSG_OVERFLOW,
            "Tool pairing check finding cap reached; remaining records truncated"
        );
    }

    #[test]
    fn safe_id_none_is_redacted_and_content_free_text_is_kept() {
        assert_eq!(safe_id(None), "<redacted>");
        assert_eq!(safe_id(Some("evt-a-synthetic")), "evt-a-synthetic");
        assert_eq!(safe_id(Some("  a  ")), "  a  ");
        assert_eq!(safe_id(Some("sk-0123456789abcdef")), "<redacted>");
    }

    #[test]
    fn source_record_id_strips_only_to_test_emptiness() {
        assert_eq!(source_record_id(None), None);
        assert_eq!(source_record_id(Some("")), None);
        assert_eq!(source_record_id(Some("   ")), None);
        assert_eq!(source_record_id(Some("\t")), None);
        assert_eq!(source_record_id(Some("  a  ")).as_deref(), Some("  a  "));
        assert_eq!(
            source_record_id(Some("evt-a-synthetic")).as_deref(),
            Some("evt-a-synthetic")
        );
    }

    #[test]
    fn fingerprint_example_collapses_duplicates() {
        assert_eq!(
            compute_pairing_fingerprint("SL103", ["b", "a", "a"]),
            "ca1fec8c15a52b35"
        );
        assert_eq!(
            compute_pairing_fingerprint("SL103", ["a", "b"]),
            "ca1fec8c15a52b35"
        );
        assert!(is_lower_hex16(&compute_pairing_fingerprint(
            "SL103",
            ["b", "a", "a"]
        )));
    }

    #[test]
    fn cap_under_the_limit_sorts_and_does_not_call_make_finding() {
        let first = finding(
            SL103,
            Some("evt-b-synthetic"),
            "bbbbbbbbbbbbbbbb",
            PyValue::None,
        );
        let second = finding(
            SL103,
            Some("evt-a-synthetic"),
            "aaaaaaaaaaaaaaaa",
            PyValue::None,
        );
        let out = cap_pairing_findings(
            vec![first, second],
            SL103,
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
        assert!(is_lower_hex16(out[0].fingerprint()));
        assert!(is_lower_hex16(out[1].fingerprint()));
    }

    #[test]
    fn cap_over_the_limit_returns_the_codec_error() {
        let item = finding(
            SL103,
            Some("evt-a-synthetic"),
            "aaaaaaaaaaaaaaaa",
            PyValue::None,
        );
        let err = cap_pairing_findings(vec![item], SL103, Some(0), None, None).unwrap_err();
        assert_codec_unavailable(err);
        let empty_err =
            cap_pairing_findings(Vec::new(), SL103, Some(-1), Some("a\\b"), None).unwrap_err();
        assert_codec_unavailable(empty_err);
    }

    #[test]
    fn overflow_flag_is_one_only_for_json_true() {
        let overflow = finding(
            SL103,
            Some("evt-a-synthetic"),
            "aaaaaaaaaaaaaaaa",
            PyValue::map(vec![(
                PyValue::string("overflow"),
                PyValue::bool_value(true),
            )]),
        );
        let missing = finding(
            SL103,
            Some("evt-a-synthetic"),
            "bbbbbbbbbbbbbbbb",
            PyValue::None,
        );
        let as_false = finding(
            SL103,
            Some("evt-a-synthetic"),
            "cccccccccccccccc",
            PyValue::map(vec![(
                PyValue::string("overflow"),
                PyValue::bool_value(false),
            )]),
        );
        let as_one = finding(
            SL103,
            Some("evt-a-synthetic"),
            "dddddddddddddddd",
            PyValue::map(vec![(PyValue::string("overflow"), PyValue::int(1))]),
        );
        let as_text = finding(
            SL103,
            Some("evt-a-synthetic"),
            "eeeeeeeeeeeeeeee",
            PyValue::map(vec![(PyValue::string("overflow"), PyValue::string("true"))]),
        );
        assert_eq!(cap_finding_sort_key(&overflow).unwrap().1, 1);
        assert_eq!(cap_finding_sort_key(&missing).unwrap().1, 0);
        assert_eq!(cap_finding_sort_key(&as_false).unwrap().1, 0);
        assert_eq!(cap_finding_sort_key(&as_one).unwrap().1, 0);
        assert_eq!(cap_finding_sort_key(&as_text).unwrap().1, 0);
    }

    #[test]
    fn empty_record_id_falls_through_to_a_string_correlation_id() {
        let missing = finding(
            SL103,
            None,
            "aaaaaaaaaaaaaaaa",
            PyValue::map(vec![(
                PyValue::string("correlation_id"),
                PyValue::string("evt-z-synthetic"),
            )]),
        );
        let present = finding(
            SL103,
            Some("evt-a-synthetic"),
            "bbbbbbbbbbbbbbbb",
            PyValue::None,
        );
        let out = cap_pairing_findings(vec![missing, present], SL103, None, None, None).unwrap();
        assert_eq!(out[0].source().record_id(), Some("evt-a-synthetic"));
        assert_eq!(out[1].source().record_id(), None);
        assert_eq!(cap_finding_sort_key(&out[1]).unwrap().2, "evt-z-synthetic");
    }

    #[test]
    fn bool_line_is_omitted() {
        let ev = mapping(&[
            ("kind", field_str(KIND_TOOL_CALL)),
            ("source_line", EventField::Bool(true)),
            ("source_location", field_str("a\\b")),
        ]);
        let (path, line) = resolve_source_coords(&ev, "<canonical>").unwrap();
        assert_eq!(path, "a/b");
        assert_eq!(line, None);
        let int_line = mapping(&[("source_line", EventField::Int(4))]);
        assert_eq!(
            resolve_source_coords(&int_line, "<canonical>").unwrap().1,
            Some(4)
        );
        let zero = mapping(&[("source_line", EventField::Int(0))]);
        assert_eq!(resolve_source_coords(&zero, "<canonical>").unwrap().1, None);
        let float_line = mapping(&[("source_line", EventField::Float(3.0))]);
        assert_eq!(
            resolve_source_coords(&float_line, "<canonical>").unwrap().1,
            None
        );
    }

    #[test]
    fn location_string_forms_and_typed_errors() {
        let true_loc = mapping(&[("source_location", EventField::Bool(true))]);
        assert_eq!(
            resolve_source_coords(&true_loc, "<canonical>").unwrap().0,
            "True"
        );
        let false_loc = mapping(&[("source_location", EventField::Bool(false))]);
        assert_eq!(
            resolve_source_coords(&false_loc, "<canonical>").unwrap().0,
            "<canonical>"
        );
        let neg = mapping(&[("source_location", EventField::Int(-3))]);
        assert_eq!(resolve_source_coords(&neg, "<canonical>").unwrap().0, "-3");
        let float_err = resolve_source_coords(
            &mapping(&[("source_location", EventField::Float(1.5))]),
            "<canonical>",
        )
        .unwrap_err();
        assert_eq!(float_err.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        assert!(matches!(float_err, ToolPairing1Error::PythonFloatStr));
        let list_err = resolve_source_coords(
            &mapping(&[("source_location", EventField::List(vec![field_str("a")]))]),
            "<canonical>",
        )
        .unwrap_err();
        assert_eq!(list_err.to_string(), PYTHON_STR_UNREPRESENTABLE);
        let skipped = resolve_source_coords(
            &mapping(&[("source_location", EventField::Float(1.5))]),
            "kept\\path",
        )
        .unwrap();
        assert_eq!(skipped.0, "kept/path");
    }

    #[test]
    fn null_correlation_goes_to_the_null_bucket() {
        let events = [
            session(KIND_TOOL_CALL, None),
            mapping(&[
                ("kind", field_str(KIND_TOOL_RESULT)),
                ("correlation_id", EventField::Null),
            ]),
            mapping(&[("kind", field_str(KIND_TOOL_USE))]),
        ];
        let indexer = ToolPairingIndexer::new(&events, None).unwrap();
        assert_eq!(indexer.null_uses().len(), 2);
        assert_eq!(indexer.null_uses()[0].0, 0);
        assert_eq!(indexer.null_uses()[1].0, 2);
        assert_eq!(indexer.null_results().len(), 1);
        assert_eq!(indexer.null_results()[0].0, 1);
        assert!(indexer.uses_keys().is_empty());
        assert!(indexer.results_keys().is_empty());
        assert_eq!(indexer.source_path(), "<canonical>");
    }

    #[test]
    fn empty_string_correlation_is_kept_as_a_key() {
        let events = [
            session(KIND_TOOL_CALL, Some("")),
            mapping(&[
                ("kind", field_str(KIND_TOOL_RESULT)),
                ("correlation_id", field_str("")),
            ]),
            session(KIND_TOOL_USE, Some("  ")),
        ];
        let indexer = ToolPairingIndexer::new(&events, None).unwrap();
        assert!(indexer.null_uses().is_empty());
        assert!(indexer.null_results().is_empty());
        assert_eq!(indexer.uses_keys(), &["", "  "]);
        assert_eq!(indexer.results_keys(), &[""]);
        assert_eq!(indexer.uses("").len(), 1);
        assert_eq!(indexer.uses("")[0].0, 0);
        assert_eq!(indexer.uses("  ")[0].0, 2);
        assert_eq!(indexer.results("").len(), 1);
    }

    #[test]
    fn message_event_and_other_kinds_are_ignored() {
        let events = [
            session("message", Some("corr-synthetic")),
            mapping(&[
                ("kind", field_str("Tool_Use")),
                ("correlation_id", field_str("corr-synthetic")),
            ]),
            EventValue::Other,
            session(KIND_TOOL_CALL, Some("b")),
            session(KIND_TOOL_CALL, Some("a")),
            session(KIND_TOOL_CALL, Some("b")),
        ];
        let indexer = ToolPairingIndexer::new(&events, Some("src.jsonl")).unwrap();
        assert!(indexer.null_uses().is_empty());
        assert!(indexer.null_results().is_empty());
        assert_eq!(indexer.uses_keys(), &["b", "a"]);
        assert_eq!(
            indexer
                .uses("b")
                .iter()
                .map(|item| item.0)
                .collect::<Vec<_>>(),
            vec![3, 5]
        );
        assert_eq!(indexer.uses("a")[0].0, 4);
        assert_eq!(indexer.source_path(), "src.jsonl");
    }

    #[test]
    fn bool_and_int_correlation_keys_use_python_str() {
        let events = [
            mapping(&[
                ("kind", field_str(KIND_TOOL_CALL)),
                ("correlation_id", EventField::Bool(true)),
            ]),
            mapping(&[
                ("kind", field_str(KIND_TOOL_CALL)),
                ("correlation_id", EventField::Int(-7)),
            ]),
        ];
        let indexer = ToolPairingIndexer::new(&events, None).unwrap();
        assert_eq!(indexer.uses_keys(), &["True", "-7"]);
    }

    #[test]
    fn float_and_container_correlation_are_typed_errors() {
        let float_err = ToolPairingIndexer::new(
            &[mapping(&[
                ("kind", field_str(KIND_TOOL_CALL)),
                ("correlation_id", EventField::Float(1.5)),
            ])],
            None,
        )
        .unwrap_err();
        assert_eq!(float_err.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        assert!(matches!(float_err, ToolPairing1Error::PythonFloatStr));
        let list_err = ToolPairingIndexer::new(
            &[mapping(&[
                ("kind", field_str(KIND_TOOL_RESULT)),
                ("correlation_id", EventField::List(vec![field_str("a")])),
            ])],
            None,
        )
        .unwrap_err();
        assert_eq!(list_err.to_string(), PYTHON_STR_UNREPRESENTABLE);
        assert!(matches!(list_err, ToolPairing1Error::PythonStr));
    }

    #[test]
    fn paired_call_and_result_are_silent() {
        let events = silent_pair();
        assert!(check_orphans(&events, None, None, None).unwrap().is_empty());
        assert!(check_dangling(&events, None, None, None)
            .unwrap()
            .is_empty());
        assert!(check_reused(&events, None, None, None).unwrap().is_empty());
    }

    #[test]
    fn result_without_a_call_is_an_orphan() {
        let events = [session(KIND_TOOL_RESULT, Some("corr-synth"))];
        assert_codec_unavailable(check_orphans(&events, None, None, None).unwrap_err());
        assert!(check_dangling(&events, None, None, None)
            .unwrap()
            .is_empty());
        assert!(check_reused(&events, None, None, None).unwrap().is_empty());
    }

    #[test]
    fn call_without_a_result_is_dangling() {
        let events = [session(KIND_TOOL_CALL, Some("corr-synth"))];
        assert!(check_orphans(&events, None, None, None).unwrap().is_empty());
        assert_codec_unavailable(check_dangling(&events, None, None, None).unwrap_err());
        assert!(check_reused(&events, None, None, None).unwrap().is_empty());
    }

    #[test]
    fn null_result_on_the_default_adapter_is_an_orphan() {
        let events = [session(KIND_TOOL_RESULT, None)];
        assert_codec_unavailable(check_orphans(&events, None, None, None).unwrap_err());
        let indexer = ToolPairingIndexer::new(&events, None).unwrap();
        let records = record_orphans(&indexer, "<canonical>", "unknown").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].correlation_id, None);
        assert!(records[0].related_ids.is_empty());
        assert_eq!(records[0].result_id, "evt-synthetic");
    }

    #[test]
    fn null_result_on_codex_rollout_is_silent() {
        let events = [session(KIND_TOOL_RESULT, None)];
        let ctx = adapter_ctx("codex-rollout");
        assert!(check_orphans(&events, None, None, Some(&ctx))
            .unwrap()
            .is_empty());
        let indexer = ToolPairingIndexer::new(&events, None).unwrap();
        assert!(record_orphans(&indexer, "<canonical>", "codex-rollout")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn declared_orphan_still_flags_on_codex_rollout() {
        let events = [session(KIND_TOOL_RESULT, Some("corr-synth"))];
        let ctx = adapter_ctx("codex-rollout");
        assert_codec_unavailable(check_orphans(&events, None, None, Some(&ctx)).unwrap_err());
    }

    #[test]
    fn null_call_on_codex_rollout_is_still_dangling() {
        let events = [session(KIND_TOOL_CALL, None)];
        let ctx = adapter_ctx("codex-rollout");
        assert!(check_orphans(&events, None, None, Some(&ctx))
            .unwrap()
            .is_empty());
        assert_codec_unavailable(check_dangling(&events, None, None, Some(&ctx)).unwrap_err());
        assert!(check_reused(&events, None, None, Some(&ctx))
            .unwrap()
            .is_empty());
        let indexer = ToolPairingIndexer::new(&events, None).unwrap();
        let records = record_dangling(&indexer, "<canonical>").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].correlation_id, None);
        assert!(records[0].related_ids.is_empty());
    }

    #[test]
    fn two_calls_and_one_result_are_reused() {
        let events = [
            session_named("call-a-synth", KIND_TOOL_CALL, Some("corr-synth")),
            session_named("call-b-synth", KIND_TOOL_CALL, Some("corr-synth")),
            session_named("res-a-synth", KIND_TOOL_RESULT, Some("corr-synth")),
        ];
        assert!(check_orphans(&events, None, None, None).unwrap().is_empty());
        assert!(check_dangling(&events, None, None, None)
            .unwrap()
            .is_empty());
        assert_codec_unavailable(check_reused(&events, None, None, None).unwrap_err());
        let indexer = ToolPairingIndexer::new(&events, None).unwrap();
        let records = record_reused(&indexer, "<canonical>").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].count, 2);
        assert!(!records[0].truncated);
        assert_eq!(
            records[0].call_ids,
            vec!["call-a-synth".to_owned(), "call-b-synth".to_owned()]
        );
        assert_eq!(records[0].event_ids, records[0].call_ids);
        assert_eq!(records[0].call_indexes, vec![0, 1]);
        assert_eq!(records[0].related_ids, records[0].call_ids);
        assert_eq!(records[0].record_id.as_deref(), Some("call-a-synth"));
        assert_eq!(records[0].correlation_id, "corr-synth");
    }

    #[test]
    fn empty_input_with_max_findings_negative_one_is_codec_error() {
        assert!(check_orphans(&[], None, None, None).unwrap().is_empty());
        assert!(check_dangling(&[], None, None, None).unwrap().is_empty());
        assert!(check_reused(&[], None, None, None).unwrap().is_empty());
        assert_codec_unavailable(check_orphans(&[], None, Some(-1), None).unwrap_err());
        assert_codec_unavailable(check_dangling(&[], None, Some(-1), None).unwrap_err());
        assert_codec_unavailable(check_reused(&[], None, Some(-1), None).unwrap_err());
    }

    #[test]
    fn two_orphan_correlation_ids_are_sorted_and_the_first_is_the_codec_error() {
        let events = [
            session(KIND_TOOL_RESULT, Some("z-corr-synth")),
            session(KIND_TOOL_RESULT, Some("a-corr-synth")),
        ];
        let indexer = ToolPairingIndexer::new(&events, None).unwrap();
        assert_eq!(indexer.results_keys(), &["z-corr-synth", "a-corr-synth"]);
        let records = record_orphans(&indexer, "<canonical>", "unknown").unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].correlation_id.as_deref(), Some("a-corr-synth"));
        assert_eq!(records[0].index, 1);
        assert_eq!(records[0].related_ids, vec!["a-corr-synth".to_owned()]);
        assert_eq!(records[1].correlation_id.as_deref(), Some("z-corr-synth"));
        assert_eq!(records[1].index, 0);
        assert_codec_unavailable(check_orphans(&events, None, None, None).unwrap_err());
    }

    #[test]
    fn missing_and_null_ids_use_placeholders_and_typed_ids_match_python_str() {
        let events = [
            mapping(&[
                ("kind", field_str(KIND_TOOL_RESULT)),
                ("correlation_id", field_str("a-corr-synth")),
            ]),
            mapping(&[
                ("kind", field_str(KIND_TOOL_RESULT)),
                ("correlation_id", field_str("b-corr-synth")),
                ("id", EventField::Null),
            ]),
            mapping(&[
                ("kind", field_str(KIND_TOOL_CALL)),
                ("correlation_id", field_str("c-corr-synth")),
                ("id", EventField::Bool(true)),
            ]),
            mapping(&[
                ("kind", field_str(KIND_TOOL_CALL)),
                ("correlation_id", field_str("d-corr-synth")),
                ("id", EventField::Int(-3)),
            ]),
        ];
        let indexer = ToolPairingIndexer::new(&events, None).unwrap();
        let orphans = record_orphans(&indexer, "<canonical>", "unknown").unwrap();
        assert_eq!(orphans[0].result_id, "<result:0>");
        assert_eq!(orphans[0].record_id.as_deref(), Some("<result:0>"));
        assert_eq!(orphans[1].result_id, "<result:1>");
        let dangling = record_dangling(&indexer, "<canonical>").unwrap();
        assert_eq!(dangling[0].event_id, "True");
        assert_eq!(dangling[1].event_id, "-3");
    }

    #[test]
    fn float_and_container_event_ids_are_typed_errors() {
        let float_err = check_orphans(
            &[mapping(&[
                ("kind", field_str(KIND_TOOL_RESULT)),
                ("correlation_id", field_str("corr-synth")),
                ("id", EventField::Float(1.5)),
            ])],
            None,
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(float_err.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        assert!(matches!(float_err, ToolPairing1Error::PythonFloatStr));
        let list_err = check_dangling(
            &[mapping(&[
                ("kind", field_str(KIND_TOOL_CALL)),
                ("correlation_id", field_str("corr-synth")),
                ("id", EventField::List(vec![field_str("a")])),
            ])],
            None,
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(list_err.to_string(), PYTHON_STR_UNREPRESENTABLE);
        assert!(matches!(list_err, ToolPairing1Error::PythonStr));
        let map_err = record_reused(
            &ToolPairingIndexer::new(
                &[
                    mapping(&[
                        ("kind", field_str(KIND_TOOL_CALL)),
                        ("correlation_id", field_str("corr-synth")),
                        (
                            "id",
                            EventField::Mapping(EventMapping::new(vec![(
                                "k".to_owned(),
                                field_str("v"),
                            )])),
                        ),
                    ]),
                    session(KIND_TOOL_CALL, Some("corr-synth")),
                ],
                None,
            )
            .unwrap(),
            "<canonical>",
        )
        .unwrap_err();
        assert_eq!(map_err.to_string(), PYTHON_STR_UNREPRESENTABLE);
    }

    #[test]
    fn redacted_correlation_clears_related_ids_and_reused_keeps_a_redacted_sample() {
        let orphan_events = [session(KIND_TOOL_RESULT, Some("sk-0123456789abcdef"))];
        let indexer = ToolPairingIndexer::new(&orphan_events, None).unwrap();
        let orphans = record_orphans(&indexer, "<canonical>", "unknown").unwrap();
        assert_eq!(orphans[0].correlation_id.as_deref(), Some("<redacted>"));
        assert!(orphans[0].related_ids.is_empty());

        let reused_events = [
            session_named("sk-0123456789abcdef", KIND_TOOL_CALL, Some("corr-synth")),
            session_named("call-b-synth", KIND_TOOL_CALL, Some("corr-synth")),
        ];
        let reused_indexer = ToolPairingIndexer::new(&reused_events, None).unwrap();
        let reused = record_reused(&reused_indexer, "<canonical>").unwrap();
        assert_eq!(reused[0].call_ids[0], "<redacted>");
        assert_eq!(reused[0].related_ids[0], "<redacted>");
        assert_eq!(reused[0].record_id.as_deref(), Some("<redacted>"));
    }

    #[test]
    fn reused_sample_truncates_at_thirty_two_and_count_is_full_length() {
        let mut events = Vec::new();
        for offset in 0..33 {
            events.push(session_named(
                &format!("call-{offset}-synth"),
                KIND_TOOL_CALL,
                Some("corr-synth"),
            ));
        }
        let indexer = ToolPairingIndexer::new(&events, None).unwrap();
        let records = record_reused(&indexer, "<canonical>").unwrap();
        assert_eq!(records[0].count, 33);
        assert!(records[0].truncated);
        assert_eq!(records[0].call_ids.len(), 32);
        assert_eq!(records[0].call_indexes.len(), 32);
        assert_eq!(records[0].event_ids, records[0].call_ids);
        assert_eq!(records[0].related_ids, records[0].call_ids);
        assert_eq!(records[0].call_ids[0], "call-0-synth");
        assert_eq!(records[0].call_ids[31], "call-31-synth");
        assert_eq!(records[0].call_indexes[31], 31);
    }
}
