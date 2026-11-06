//! Side-effect abstention data (TASK-017, DEV-013).
//!
//! Port of `src/sesslint/policy/abstention.py` lines 1–400
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! Stops at the end of `check_step_scope`. `SL203` is the exact code `"SL203"`.
//! A finding with that code blocks [`check_step_scope`] even when the affected
//! region is disjoint. This slice does not add a bypass, delete, or skip for it.
//!
//! # Recorded gaps
//!
//! * A bool is not an i64. `True` is not `1` ([`PYTHON_BOOL_IS_NOT_INT`]).
//!   [`AffectedRegion::new`] and an evidence index (`record_ordinal`,
//!   `at_index`, `index`, `first_unsafe_index`) return
//!   [`AbstentionError::PythonBoolAsInt`]. Python `isinstance(True, int)` is
//!   true; this crate does not store that bool as `1`.
//! * A float's Python `str` is not matched
//!   (`model::events::PYTHON_FLOAT_STR_UNREPRESENTABLE`). Stringifying a float
//!   side-effect value, or a truthy float tool name, returns
//!   [`AbstentionError::PythonFloatStr`] and does not panic. A falsy float
//!   (`0.0` / `-0.0`) is skipped by Python `or` and is not stringified. A float
//!   or list `kind` is `model::events::event_kind`'s error, propagated unchanged.
//! * Python `str` of a list or mapping is not matched
//!   (`model::events::PYTHON_STR_UNREPRESENTABLE`).
//! * A [`Payload`] list or tuple is not a mapping and is skipped. A scalar is
//!   skipped. A map is read with [`Payload::map_string`]: the last duplicate
//!   string key wins and keys are not sorted. [`MapLookup::Borrowed`] and
//!   [`EvidenceLookup::Borrowed`] are failed borrows, not missing keys, and
//!   return [`AbstentionError::BorrowedLookup`]. Derived `Debug` is not scraped.
//! * A container value at a looked-up payload key has no public length. It
//!   fails closed with [`AbstentionError::PythonStr`]. Python tool-name `or`
//!   treats an empty list, tuple, or map as missing; that emptiness is not
//!   visible here. `EventMapping` lookups still see empty containers.
//! * Correlation ids are grouped without `HashMap` iteration. Python builds a
//!   set and its iteration order is not a contract. This crate walks each id
//!   in the order it first appears in the event list. Reasons stay in append
//!   order.
//! * The affected-region tool walk uses ascending indices. Python set order is
//!   not a contract. An `extract_side_effects` error still propagates.
//! * Identical results compare [`event_content_fingerprint`] strings. A
//!   non-empty `content_hash` is compared. An error propagates and is not
//!   treated as identical. Nothing is hashed.
//! * [`check_step_scope`] takes the caller step as a generic value. No planner
//!   type is imported.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use model::canonical::{CanonicalUnavailable, MapLookup, Payload, READ_ONLY_TOOL_NAMES};
use model::events::{
    event_content_fingerprint, event_corr_id, event_id, event_kind, EventError, EventField,
    EventMapping, EventValue, PYTHON_FLOAT_STR_UNREPRESENTABLE, PYTHON_STR_UNREPRESENTABLE,
};
use model::finding::{Evidence, EvidenceLookup, Finding};

/// Python: `TOOL_KINDS`, source literal order.
///
/// Membership only. Frozenset iteration is not a contract.
pub const TOOL_KINDS: &[&str] = &["tool_call", "tool_use", "tool_result"];

/// Python: `SAFE_SIDE_EFFECT`.
pub const SAFE_SIDE_EFFECT: &str = "none";

/// Python `bool` is an `int` subclass. This crate does not treat `True` as `1`.
pub const PYTHON_BOOL_IS_NOT_INT: &str = "A bool is not an i64; True is not 1";

/// Inclusive spans wider than this are not materialized.
///
/// Python would attempt the allocation. A span whose length does not fit in
/// `i64`, including a walk that would pass `i64::MAX`, uses the same refusal.
pub const MAX_INCLUSIVE_SPAN: u64 = 1_048_576;

/// [`Payload`] map entries are not readable from this crate.
pub const PAYLOAD_MAP_LOOKUP_UNAVAILABLE: &str =
    "Payload map lookup is not available outside the model crate";

/// Inclusive index span cannot be materialized.
pub const RANGE_SPAN_TOO_LARGE: &str = "inclusive index span cannot be materialized";

/// [`MapLookup::Borrowed`] or [`EvidenceLookup::Borrowed`] is not a missing key.
pub const BORROWED_LOOKUP: &str = "A borrowed map lookup is not a missing key";

/// Python: the fail-closed reason from `check_step_scope`.
pub const SIDE_EFFECT_SCOPE_UNPROVEN: &str = "side-effect-scope-unproven";

/// Exact detector code. Not a prefix and not a repaired alias.
const SL203_CODE: &str = "SL203";

/// Failure from this slice. [`Display`] is the message only, except an
/// [`AbstentionError::Event`] which displays the propagated event error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbstentionError {
    Event(EventError),
    PythonBoolAsInt,
    PythonFloatStr,
    PythonStr,
    PayloadMapLookup,
    BorrowedLookup,
    RangeSpan,
}

impl AbstentionError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::Event(error) => error.message(),
            Self::PythonBoolAsInt => PYTHON_BOOL_IS_NOT_INT,
            Self::PythonFloatStr => PYTHON_FLOAT_STR_UNREPRESENTABLE,
            Self::PythonStr => PYTHON_STR_UNREPRESENTABLE,
            Self::PayloadMapLookup => PAYLOAD_MAP_LOOKUP_UNAVAILABLE,
            Self::BorrowedLookup => BORROWED_LOOKUP,
            Self::RangeSpan => RANGE_SPAN_TOO_LARGE,
        }
    }
}

impl fmt::Display for AbstentionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for AbstentionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Event(error) => Some(error),
            Self::PythonBoolAsInt
            | Self::PythonFloatStr
            | Self::PythonStr
            | Self::PayloadMapLookup
            | Self::BorrowedLookup
            | Self::RangeSpan => None,
        }
    }
}

impl From<EventError> for AbstentionError {
    fn from(error: EventError) -> Self {
        Self::Event(error)
    }
}

/// Integer input that keeps a Python `bool` distinct from an `i64`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PyInt {
    Int(i64),
    Bool(bool),
}

/// `ranges` argument for [`AffectedRegion::new`].
///
/// [`RangesInput::Pair`] is one `(start, end)` tuple of ints and is stored as
/// one range. [`RangesInput::Sequence`] is a sequence of pairs and is not
/// wrapped, including when it holds two pairs (a tuple of tuples).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RangesInput {
    Pair(PyInt, PyInt),
    Sequence(Vec<(PyInt, PyInt)>),
}

/// One field of [`Abstention::to_dict`], in Python literal order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AbstentionDictValue {
    Bool(bool),
    Reasons(Vec<String>),
}

/// Decision indicating whether automated repair must abstain.
///
/// `reasons` keeps constructor order. [`Abstention::to_dict`] does not sort them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Abstention {
    abstain: bool,
    reasons: Vec<String>,
}

impl Abstention {
    pub fn new(abstain: bool, reasons: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            abstain,
            reasons: reasons.into_iter().map(Into::into).collect(),
        }
    }

    pub fn abstain(&self) -> bool {
        self.abstain
    }

    pub fn reasons(&self) -> &[String] {
        &self.reasons
    }

    /// Python: `Abstention.to_dict`. Fields are `abstain`, then `reasons`.
    pub fn to_dict(&self) -> Vec<(&'static str, AbstentionDictValue)> {
        vec![
            ("abstain", AbstentionDictValue::Bool(self.abstain)),
            (
                "reasons",
                AbstentionDictValue::Reasons(self.reasons.clone()),
            ),
        ]
    }
}

/// Affected record region declared by a repair recipe for a plan step.
///
/// Indices and ids are sets. Range order is the normalized input order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AffectedRegion {
    indices: BTreeSet<i64>,
    ids: BTreeSet<String>,
    ranges: Vec<(i64, i64)>,
    unproven: bool,
}

impl AffectedRegion {
    /// Build a region.
    ///
    /// A [`PyInt::Bool`] is an error. It is not stored as `0` or `1`.
    pub fn new(
        indices: impl IntoIterator<Item = PyInt>,
        ids: impl IntoIterator<Item = impl Into<String>>,
        ranges: RangesInput,
        unproven: bool,
    ) -> Result<Self, AbstentionError> {
        Ok(Self {
            indices: collect_ints(indices)?,
            ids: ids.into_iter().map(Into::into).collect(),
            ranges: normalize_ranges(ranges)?,
            unproven,
        })
    }

    pub fn indices(&self) -> &BTreeSet<i64> {
        &self.indices
    }

    pub fn ids(&self) -> &BTreeSet<String> {
        &self.ids
    }

    pub fn ranges(&self) -> &[(i64, i64)] {
        &self.ranges
    }

    pub fn unproven(&self) -> bool {
        self.unproven
    }

    /// Union `indices` with every inclusive range.
    ///
    /// `total_len` clamps each range before the walk: start to at least `0`,
    /// end to at most `total_len - 1`. Explicit indices are not clamped.
    /// `start > end` adds nothing. `total_len == 0` makes the end limit `-1`.
    /// A span that would pass through `i64::MAX`, overflow, or exceed
    /// [`MAX_INCLUSIVE_SPAN`] returns [`AbstentionError::RangeSpan`].
    pub fn all_indices(&self, total_len: Option<i64>) -> Result<BTreeSet<i64>, AbstentionError> {
        let mut covered = self.indices.clone();
        for &(start, end) in &self.ranges {
            let (start, end) = match total_len {
                Some(total) => clamp_range(start, end, total)?,
                None => (start, end),
            };
            insert_inclusive(&mut covered, start, end)?;
        }
        Ok(covered)
    }
}

/// Record indices and identifiers whose execution state is ambiguous.
///
/// This slice does not fill the value from findings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AmbiguousEvents {
    indices: BTreeSet<i64>,
    ids: BTreeSet<String>,
    reasons: Vec<String>,
}

impl AmbiguousEvents {
    pub fn new(
        indices: impl IntoIterator<Item = i64>,
        ids: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self::with_reasons(indices, ids, std::iter::empty::<String>())
    }

    pub fn with_reasons(
        indices: impl IntoIterator<Item = i64>,
        ids: impl IntoIterator<Item = impl Into<String>>,
        reasons: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            indices: indices.into_iter().collect(),
            ids: ids.into_iter().map(Into::into).collect(),
            reasons: reasons.into_iter().map(Into::into).collect(),
        }
    }

    pub fn indices(&self) -> &BTreeSet<i64> {
        &self.indices
    }

    pub fn ids(&self) -> &BTreeSet<String> {
        &self.ids
    }

    pub fn reasons(&self) -> &[String] {
        &self.reasons
    }
}

/// Python: `_extract_side_effects`.
///
/// `raw_kind` of `None` calls [`event_kind`] and propagates its error. A float
/// or list kind is that error, not `"unknown"`. An empty side-effect string is
/// present and stays empty.
pub fn extract_side_effects(
    ev: &EventValue,
    raw_kind: Option<&str>,
) -> Result<String, AbstentionError> {
    let resolved;
    let kind = match raw_kind {
        Some(text) => Some(text),
        None => {
            resolved = event_kind(ev)?;
            resolved.as_deref()
        }
    };

    let mut raw_se = attribute_side_effects(ev);
    if raw_se.is_none() {
        raw_se = mapping_key_side_effects(ev);
    }
    if raw_se.is_none() {
        raw_se = side_effects_from_event_payload(ev)?;
    }
    if raw_se.is_none() {
        raw_se = side_effects_from_event_extra(ev)?;
    }

    if raw_se.is_none() && kind == Some("tool_result") {
        raw_se = Some(EventField::Str(SAFE_SIDE_EFFECT.to_owned()));
    } else if raw_se.is_none() && matches!(kind, Some("tool_call" | "tool_use")) {
        let tool_name = lowered_tool_name(ev)?;
        if READ_ONLY_TOOL_NAMES.contains(&tool_name.as_str()) {
            raw_se = Some(EventField::Str(SAFE_SIDE_EFFECT.to_owned()));
        }
    }

    match raw_se {
        None => Ok("unknown".to_owned()),
        Some(value) => present_python_str(&value),
    }
}

fn collect_ints(values: impl IntoIterator<Item = PyInt>) -> Result<BTreeSet<i64>, AbstentionError> {
    let mut out = BTreeSet::new();
    for value in values {
        out.insert(require_int(value)?);
    }
    Ok(out)
}

fn require_int(value: PyInt) -> Result<i64, AbstentionError> {
    match value {
        PyInt::Int(number) => Ok(number),
        PyInt::Bool(_) => Err(AbstentionError::PythonBoolAsInt),
    }
}

fn normalize_ranges(ranges: RangesInput) -> Result<Vec<(i64, i64)>, AbstentionError> {
    match ranges {
        RangesInput::Pair(start, end) => Ok(vec![(require_int(start)?, require_int(end)?)]),
        RangesInput::Sequence(pairs) => {
            let mut out = Vec::with_capacity(pairs.len());
            for (start, end) in pairs {
                out.push((require_int(start)?, require_int(end)?));
            }
            Ok(out)
        }
    }
}

fn clamp_range(start: i64, end: i64, total_len: i64) -> Result<(i64, i64), AbstentionError> {
    let end_limit = match total_len.checked_sub(1) {
        Some(limit) => limit,
        None => return Err(AbstentionError::RangeSpan),
    };
    Ok((start.max(0), end.min(end_limit)))
}

fn insert_inclusive(out: &mut BTreeSet<i64>, start: i64, end: i64) -> Result<(), AbstentionError> {
    if start > end {
        return Ok(());
    }
    let span = match end
        .checked_sub(start)
        .and_then(|delta| delta.checked_add(1))
    {
        Some(span) => span,
        None => return Err(AbstentionError::RangeSpan),
    };
    let span = u64::try_from(span).map_err(|_| AbstentionError::RangeSpan)?;
    if span > MAX_INCLUSIVE_SPAN {
        return Err(AbstentionError::RangeSpan);
    }
    let mut left = span;
    let mut value = start;
    while left > 0 {
        out.insert(value);
        left -= 1;
        if let Some(next) = value.checked_add(1) {
            value = next;
        }
    }
    Ok(())
}

fn attribute_side_effects(ev: &EventValue) -> Option<EventField> {
    match ev {
        EventValue::Session(event) => event.side_effects.clone().map(EventField::Str),
        EventValue::Mapping(_) | EventValue::Other => None,
    }
}

fn mapping_key_side_effects(ev: &EventValue) -> Option<EventField> {
    match ev {
        EventValue::Mapping(mapping) => mapped_side_effects(mapping),
        EventValue::Session(_) | EventValue::Other => None,
    }
}

fn side_effects_in(mapping: Option<EventMapping>) -> Option<EventField> {
    mapping.as_ref().and_then(mapped_side_effects)
}

fn float_is_falsy(value: f64) -> bool {
    let bits = value.to_bits();
    bits == 0 || bits == (1_u64 << 63)
}

fn mapped_side_effects(mapping: &EventMapping) -> Option<EventField> {
    match mapping.get("side_effects") {
        Some(EventField::Null) | None => None,
        Some(value) => Some(value.clone()),
    }
}

fn side_effects_from_event_payload(ev: &EventValue) -> Result<Option<EventField>, AbstentionError> {
    match ev {
        EventValue::Session(event) => side_effects_from_payload(&event.payload),
        EventValue::Mapping(mapping) => Ok(side_effects_in(nested_mapping(mapping, "payload"))),
        EventValue::Other => Ok(None),
    }
}

fn side_effects_from_event_extra(ev: &EventValue) -> Result<Option<EventField>, AbstentionError> {
    match ev {
        EventValue::Session(event) => side_effects_from_payload(&event.extra_fields),
        EventValue::Mapping(mapping) => {
            Ok(side_effects_in(nested_mapping(mapping, "extra_fields")))
        }
        EventValue::Other => Ok(None),
    }
}

fn nested_mapping(mapping: &EventMapping, key: &str) -> Option<EventMapping> {
    match mapping.get(key) {
        Some(EventField::Mapping(child)) => Some(child.clone()),
        _ => None,
    }
}

fn side_effects_from_payload(payload: &Payload) -> Result<Option<EventField>, AbstentionError> {
    if !payload.is_map() {
        return Ok(None);
    }
    match payload.map_string("side_effects") {
        MapLookup::Borrowed => Err(AbstentionError::BorrowedLookup),
        MapLookup::NotAMap | MapLookup::Absent => Ok(None),
        MapLookup::Present(value) if value.is_null() => Ok(None),
        MapLookup::Present(value) => Ok(Some(payload_as_event_field(&value)?)),
    }
}

fn payload_as_event_field(value: &Payload) -> Result<EventField, AbstentionError> {
    if let Some(flag) = value.as_bool() {
        return Ok(EventField::Bool(flag));
    }
    if let Some(number) = value.as_int() {
        return Ok(EventField::Int(number));
    }
    if let Some(number) = value.as_float() {
        return Ok(EventField::Float(number));
    }
    if let Some(text) = value.as_str() {
        return Ok(EventField::Str(text.to_owned()));
    }
    Err(AbstentionError::PythonStr)
}

fn lowered_tool_name(ev: &EventValue) -> Result<String, AbstentionError> {
    let mut tool_name = String::new();
    match ev {
        EventValue::Mapping(mapping) => {
            if let Some(payload) = nested_mapping(mapping, "payload") {
                tool_name =
                    first_truthy(&[payload.get("name"), payload.get("tool_name")])?.to_lowercase();
            }
        }
        EventValue::Session(event) => {
            tool_name =
                first_truthy_payload(&event.payload, &["name", "tool_name"])?.to_lowercase();
        }
        EventValue::Other => {}
    }
    if tool_name.is_empty() {
        tool_name = event_name(ev)?.to_lowercase();
    }
    Ok(tool_name)
}

fn first_truthy_payload(payload: &Payload, keys: &[&str]) -> Result<String, AbstentionError> {
    if !payload.is_map() {
        return Ok(String::new());
    }
    for key in keys {
        match payload.map_string(key) {
            MapLookup::Borrowed => return Err(AbstentionError::BorrowedLookup),
            MapLookup::NotAMap | MapLookup::Absent => {}
            MapLookup::Present(value) => {
                if let Some(text) = truthy_payload(&value)? {
                    return Ok(text);
                }
            }
        }
    }
    Ok(String::new())
}

fn truthy_payload(value: &Payload) -> Result<Option<String>, AbstentionError> {
    if value.is_null() {
        return Ok(None);
    }
    if let Some(false) = value.as_bool() {
        return Ok(None);
    }
    if let Some(true) = value.as_bool() {
        return Ok(Some("True".to_owned()));
    }
    if let Some(0) = value.as_int() {
        return Ok(None);
    }
    if let Some(number) = value.as_int() {
        return Ok(Some(number.to_string()));
    }
    if let Some(number) = value.as_float() {
        if float_is_falsy(number) {
            return Ok(None);
        }
        return Err(AbstentionError::PythonFloatStr);
    }
    if let Some(text) = value.as_str() {
        if text.is_empty() {
            return Ok(None);
        }
        return Ok(Some(text.to_owned()));
    }
    Err(AbstentionError::PythonStr)
}

fn event_name(ev: &EventValue) -> Result<String, AbstentionError> {
    match ev {
        EventValue::Mapping(mapping) => first_truthy(&[mapping.get("name")]),
        EventValue::Session(_) | EventValue::Other => Ok(String::new()),
    }
}

fn first_truthy(fields: &[Option<&EventField>]) -> Result<String, AbstentionError> {
    for field in fields {
        if let Some(text) = truthy_text(*field)? {
            return Ok(text);
        }
    }
    Ok(String::new())
}

fn truthy_text(field: Option<&EventField>) -> Result<Option<String>, AbstentionError> {
    let Some(field) = field else {
        return Ok(None);
    };
    match field {
        EventField::Null | EventField::Bool(false) => Ok(None),
        EventField::Bool(true) => Ok(Some("True".to_owned())),
        EventField::Int(0) => Ok(None),
        EventField::Int(number) => Ok(Some(number.to_string())),
        EventField::Float(value) if float_is_falsy(*value) => Ok(None),
        EventField::Float(_) => Err(AbstentionError::PythonFloatStr),
        EventField::Str(text) if text.is_empty() => Ok(None),
        EventField::Str(text) => Ok(Some(text.clone())),
        EventField::List(items) if items.is_empty() => Ok(None),
        EventField::Mapping(mapping) if mapping.entries().is_empty() => Ok(None),
        EventField::List(_) | EventField::Mapping(_) => Err(AbstentionError::PythonStr),
    }
}

fn present_python_str(field: &EventField) -> Result<String, AbstentionError> {
    match field {
        EventField::Bool(true) => Ok("True".to_owned()),
        EventField::Bool(false) => Ok("False".to_owned()),
        EventField::Int(number) => Ok(number.to_string()),
        EventField::Str(text) => Ok(text.clone()),
        EventField::Float(_) => Err(AbstentionError::PythonFloatStr),
        EventField::Null | EventField::List(_) | EventField::Mapping(_) => {
            Err(AbstentionError::PythonStr)
        }
    }
}

/// Callback that proves the affected region of one repair step.
///
/// `Step` is the caller's step value. This crate does not import a planner type.
/// The callback may borrow data for `'a`.
pub type RecipeRegionFn<'a, Step> =
    dyn Fn(&Step, &[EventValue]) -> Result<Option<AffectedRegion>, AbstentionError> + 'a;

/// Python: `find_ambiguous_events`.
///
/// Branch order follows the pin. Reason strings keep the pin's index numbers
/// and stay in append order.
pub fn find_ambiguous_events(
    events: &[EventValue],
    findings: Option<&[Finding]>,
) -> Result<AmbiguousEvents, AbstentionError> {
    let mut ambiguous_indices = BTreeSet::new();
    let mut ambiguous_ids = BTreeSet::new();
    let mut reasons = Vec::new();

    if let Some(findings) = findings {
        for finding in findings {
            if finding.code() != SL203_CODE {
                continue;
            }
            if let Some(record_id) = finding.source().record_id() {
                if !record_id.is_empty() {
                    ambiguous_ids.insert(record_id.to_owned());
                }
            }
            let Some(evidence) = finding.evidence() else {
                continue;
            };
            if !evidence.is_map() {
                continue;
            }
            for key in ["record_ordinal", "at_index", "index"] {
                if let Some(value) = lookup_evidence(evidence, key)? {
                    if let Some(index) = bounded_evidence_index(&value, events.len())? {
                        ambiguous_indices.insert(index);
                    }
                }
            }
            if let Some(value) = lookup_evidence(evidence, "first_unsafe_index")? {
                if let Some(first_unsafe) = evidence_int(&value)? {
                    mark_tools_from(
                        events,
                        first_unsafe,
                        &mut ambiguous_indices,
                        &mut ambiguous_ids,
                    )?;
                }
            }
        }
    }

    // Python builds `set(calls) | set(results)` and iterates that set. Set
    // order is not a contract. Groups stay in the order each correlation id
    // first appears in `events`. Reasons stay in append order. No `HashMap`.
    let mut groups: Vec<CorrGroup> = Vec::new();
    for (index, ev) in events.iter().enumerate() {
        let kind = event_kind(ev)?;
        let id = event_id(ev)?;
        let corr = event_corr_id(ev)?;
        let side_effects = extract_side_effects(ev, kind.as_deref())?;
        let site = ToolSite {
            index,
            id,
            side_effects,
        };
        match kind.as_deref() {
            Some("tool_call" | "tool_use") => {
                if let Some(corr) = corr {
                    push_group(&mut groups, corr, site, true);
                } else {
                    ambiguous_indices.insert(usize_index(index)?);
                    add_id(&mut ambiguous_ids, &site.id);
                    reasons.push(format!("unpaired-call-no-correlation at index {index}"));
                }
            }
            Some("tool_result") => {
                if let Some(corr) = corr {
                    push_group(&mut groups, corr, site, false);
                } else {
                    ambiguous_indices.insert(usize_index(index)?);
                    add_id(&mut ambiguous_ids, &site.id);
                    reasons.push(format!("orphan-result-no-correlation at index {index}"));
                }
            }
            _ => {}
        }
    }

    for group in &groups {
        classify_correlation(
            group,
            events,
            &mut ambiguous_indices,
            &mut ambiguous_ids,
            &mut reasons,
        )?;
    }

    for (index, ev) in events.iter().enumerate() {
        let id = event_id(ev)?;
        let index = usize_index(index)?;
        if ambiguous_indices.contains(&index) {
            add_id(&mut ambiguous_ids, &id);
        }
        if let Some(text) = nonempty_id(&id) {
            if ambiguous_ids.contains(text) {
                ambiguous_indices.insert(index);
            }
        }
    }

    Ok(AmbiguousEvents::with_reasons(
        ambiguous_indices,
        ambiguous_ids,
        reasons,
    ))
}

/// Python: `check_step_scope`.
///
/// `(true, None)` when the step's region provably misses ambiguous execution
/// and unexcluded side effects. `(false, "side-effect-scope-unproven")` when
/// the proof fails. A region-callback error and an [`AffectedRegion::all_indices`]
/// error become that pair. Other input errors propagate.
pub fn check_step_scope<Step>(
    step: &Step,
    events: &[EventValue],
    recipe_region_fn: Option<&RecipeRegionFn<'_, Step>>,
    findings: Option<&[Finding]>,
    excludes_execution_dependence: bool,
    ambiguous: Option<&AmbiguousEvents>,
) -> Result<(bool, Option<&'static str>), AbstentionError> {
    let Some(recipe_region_fn) = recipe_region_fn else {
        return Ok((false, Some(SIDE_EFFECT_SCOPE_UNPROVEN)));
    };
    let region = match recipe_region_fn(step, events) {
        Ok(Some(region)) if !region.unproven() => region,
        Ok(_) | Err(_) => return Ok((false, Some(SIDE_EFFECT_SCOPE_UNPROVEN))),
    };
    if findings.is_some_and(|findings| findings.iter().any(|finding| finding.code() == SL203_CODE))
    {
        return Ok((false, Some(SIDE_EFFECT_SCOPE_UNPROVEN)));
    }

    let computed;
    let ambiguous_set = if let Some(ambiguous) = ambiguous {
        ambiguous
    } else {
        computed = find_ambiguous_events(events, findings)?;
        &computed
    };

    let Ok(total_len) = i64::try_from(events.len()) else {
        return Ok((false, Some(SIDE_EFFECT_SCOPE_UNPROVEN)));
    };
    let mut aff_indices = match region.all_indices(Some(total_len)) {
        Ok(indices) => indices,
        Err(_) => return Ok((false, Some(SIDE_EFFECT_SCOPE_UNPROVEN))),
    };
    let mut aff_ids = region.ids().clone();
    for &index in &aff_indices {
        if let Some(ev) = event_at(events, index) {
            add_id(&mut aff_ids, &event_id(ev)?);
        }
    }
    for (index, ev) in events.iter().enumerate() {
        let id = event_id(ev)?;
        if let Some(text) = nonempty_id(&id) {
            if aff_ids.contains(text) {
                aff_indices.insert(usize_index(index)?);
            }
        }
    }

    if !aff_indices.is_disjoint(ambiguous_set.indices())
        || !aff_ids.is_disjoint(ambiguous_set.ids())
    {
        return Ok((false, Some(SIDE_EFFECT_SCOPE_UNPROVEN)));
    }

    // Python iterates the affected-index set. That order is not a contract.
    // Ascending `i64` order is the recorded gap.
    for &index in &aff_indices {
        let Some(ev) = event_at(events, index) else {
            continue;
        };
        let kind = event_kind(ev)?;
        if kind
            .as_deref()
            .is_some_and(|text| TOOL_KINDS.contains(&text))
        {
            let side_effects = extract_side_effects(ev, kind.as_deref())?;
            if side_effects != SAFE_SIDE_EFFECT && !excludes_execution_dependence {
                return Ok((false, Some(SIDE_EFFECT_SCOPE_UNPROVEN)));
            }
        }
    }

    Ok((true, None))
}

struct ToolSite {
    index: usize,
    id: Option<String>,
    side_effects: String,
}

struct CorrGroup {
    corr: String,
    calls: Vec<ToolSite>,
    results: Vec<ToolSite>,
}

fn push_group(groups: &mut Vec<CorrGroup>, corr: String, site: ToolSite, call: bool) {
    if let Some(group) = groups.iter_mut().find(|group| group.corr == corr) {
        if call {
            group.calls.push(site);
        } else {
            group.results.push(site);
        }
        return;
    }
    let mut group = CorrGroup {
        corr,
        calls: Vec::new(),
        results: Vec::new(),
    };
    if call {
        group.calls.push(site);
    } else {
        group.results.push(site);
    }
    groups.push(group);
}

fn classify_correlation(
    group: &CorrGroup,
    events: &[EventValue],
    ambiguous_indices: &mut BTreeSet<i64>,
    ambiguous_ids: &mut BTreeSet<String>,
    reasons: &mut Vec<String>,
) -> Result<(), AbstentionError> {
    if group.calls.len() > 1 {
        for site in group.calls.iter().chain(group.results.iter()) {
            mark_site(site, ambiguous_indices, ambiguous_ids)?;
        }
        reasons.push(format!("reused-correlation-{}", group.corr));
    } else if group.calls.len() == 1 && group.results.is_empty() {
        let call = &group.calls[0];
        mark_site(call, ambiguous_indices, ambiguous_ids)?;
        let index = usize_index(call.index)?;
        reasons.push(format!("dangling-call-{} at index {index}", group.corr));
    } else if group.calls.is_empty() && !group.results.is_empty() {
        for site in &group.results {
            mark_site(site, ambiguous_indices, ambiguous_ids)?;
        }
        reasons.push(format!("orphan-result-{}", group.corr));
    } else if group.results.len() > 1 {
        classify_duplicate_results(group, events, ambiguous_indices, ambiguous_ids, reasons)?;
    } else if group.calls.len() == 1 && group.results.len() == 1 {
        classify_one_pair(group, events, ambiguous_indices, ambiguous_ids, reasons)?;
    }
    Ok(())
}

fn classify_duplicate_results(
    group: &CorrGroup,
    events: &[EventValue],
    ambiguous_indices: &mut BTreeSet<i64>,
    ambiguous_ids: &mut BTreeSet<String>,
    reasons: &mut Vec<String>,
) -> Result<(), AbstentionError> {
    let Some(first) = group.results.first() else {
        return Ok(());
    };
    let first_hash = content_fingerprint(event_at_site(events, first)?)?;
    let mut identical = true;
    for result in group.results.iter().skip(1) {
        let hash = content_fingerprint(event_at_site(events, result)?)?;
        if hash != first_hash {
            identical = false;
            break;
        }
    }
    if !identical {
        for site in group.calls.iter().chain(group.results.iter()) {
            mark_site(site, ambiguous_indices, ambiguous_ids)?;
        }
        return Ok(());
    }
    if let Some(call) = group.calls.first() {
        if call.side_effects == "unknown" {
            mark_site(call, ambiguous_indices, ambiguous_ids)?;
            for result in &group.results {
                mark_site(result, ambiguous_indices, ambiguous_ids)?;
            }
            reasons.push(format!("unknown-side-effects-{}", group.corr));
        }
    }
    for result in &group.results {
        if execution_is_unknown(event_at_site(events, result)?)? {
            mark_site(result, ambiguous_indices, ambiguous_ids)?;
            let index = usize_index(result.index)?;
            reasons.push(format!("unknown-execution-{} at index {index}", group.corr));
        }
    }
    Ok(())
}

fn classify_one_pair(
    group: &CorrGroup,
    events: &[EventValue],
    ambiguous_indices: &mut BTreeSet<i64>,
    ambiguous_ids: &mut BTreeSet<String>,
    reasons: &mut Vec<String>,
) -> Result<(), AbstentionError> {
    let Some(call) = group.calls.first() else {
        return Ok(());
    };
    let Some(result) = group.results.first() else {
        return Ok(());
    };
    let call_index = usize_index(call.index)?;
    let result_index = usize_index(result.index)?;
    if result.index < call.index {
        mark_site(call, ambiguous_indices, ambiguous_ids)?;
        mark_site(result, ambiguous_indices, ambiguous_ids)?;
        reasons.push(format!(
            "reversed-pairing-{} at indices ({result_index}, {call_index})",
            group.corr
        ));
    }
    if call.side_effects == "unknown" {
        mark_site(call, ambiguous_indices, ambiguous_ids)?;
        mark_site(result, ambiguous_indices, ambiguous_ids)?;
        reasons.push(format!(
            "unknown-side-effects-{} at index {call_index}",
            group.corr
        ));
    }
    if execution_is_unknown(event_at_site(events, result)?)? {
        mark_site(call, ambiguous_indices, ambiguous_ids)?;
        mark_site(result, ambiguous_indices, ambiguous_ids)?;
        reasons.push(format!(
            "unknown-execution-{} at index {result_index}",
            group.corr
        ));
    }
    Ok(())
}

fn mark_site(
    site: &ToolSite,
    indices: &mut BTreeSet<i64>,
    ids: &mut BTreeSet<String>,
) -> Result<(), AbstentionError> {
    indices.insert(usize_index(site.index)?);
    add_id(ids, &site.id);
    Ok(())
}

fn event_at_site<'a>(
    events: &'a [EventValue],
    site: &ToolSite,
) -> Result<&'a EventValue, AbstentionError> {
    events.get(site.index).ok_or(AbstentionError::RangeSpan)
}

fn content_fingerprint(ev: &EventValue) -> Result<String, AbstentionError> {
    let hash = event_content_fingerprint(ev)?;
    if hash.is_empty() {
        return Err(AbstentionError::Event(EventError::from(
            CanonicalUnavailable::payload_content_hash(),
        )));
    }
    Ok(hash)
}

fn execution_is_unknown(ev: &EventValue) -> Result<bool, AbstentionError> {
    match ev {
        EventValue::Session(event) => payload_string_is(&event.payload, "execution", "unknown"),
        EventValue::Mapping(mapping) => match mapping.get("payload") {
            Some(EventField::Mapping(payload)) => Ok(matches!(
                payload.get("execution"),
                Some(EventField::Str(text)) if text == "unknown"
            )),
            _ => Ok(false),
        },
        EventValue::Other => Ok(false),
    }
}

fn payload_string_is(
    payload: &Payload,
    key: &str,
    expected: &str,
) -> Result<bool, AbstentionError> {
    if !payload.is_map() {
        return Ok(false);
    }
    match payload.map_string(key) {
        MapLookup::Borrowed => Err(AbstentionError::BorrowedLookup),
        MapLookup::NotAMap | MapLookup::Absent => Ok(false),
        MapLookup::Present(value) => Ok(value.as_str() == Some(expected)),
    }
}

fn lookup_evidence(evidence: &Evidence, key: &str) -> Result<Option<Evidence>, AbstentionError> {
    match evidence.map_string(key) {
        EvidenceLookup::Borrowed => Err(AbstentionError::BorrowedLookup),
        EvidenceLookup::NotAMap | EvidenceLookup::Absent => Ok(None),
        EvidenceLookup::Present(value) => Ok(Some(value)),
    }
}

fn bounded_evidence_index(value: &Evidence, len: usize) -> Result<Option<i64>, AbstentionError> {
    match evidence_int(value)? {
        Some(number) if index_in_range(number, len) => Ok(Some(number)),
        Some(_) | None => Ok(None),
    }
}

fn evidence_int(value: &Evidence) -> Result<Option<i64>, AbstentionError> {
    if let Some(number) = value.as_int() {
        return Ok(Some(number));
    }
    if evidence_is_bool(value) {
        return Err(AbstentionError::PythonBoolAsInt);
    }
    Ok(None)
}

fn evidence_is_bool(value: &Evidence) -> bool {
    value == &Evidence::bool_value(true) || value == &Evidence::bool_value(false)
}

fn index_in_range(index: i64, len: usize) -> bool {
    match usize::try_from(index) {
        Ok(index) => index < len,
        Err(_) => false,
    }
}

fn mark_tools_from(
    events: &[EventValue],
    first_unsafe: i64,
    indices: &mut BTreeSet<i64>,
    ids: &mut BTreeSet<String>,
) -> Result<(), AbstentionError> {
    let start = if first_unsafe < 0 { 0 } else { first_unsafe };
    let Ok(start) = usize::try_from(start) else {
        return Ok(());
    };
    if start >= events.len() {
        return Ok(());
    }
    for (index, ev) in events.iter().enumerate().skip(start) {
        let kind = event_kind(ev)?;
        if kind
            .as_deref()
            .is_some_and(|text| TOOL_KINDS.contains(&text))
        {
            indices.insert(usize_index(index)?);
            add_id(ids, &event_id(ev)?);
        }
    }
    Ok(())
}

fn add_id(ids: &mut BTreeSet<String>, id: &Option<String>) {
    if let Some(text) = nonempty_id(id) {
        ids.insert(text.to_owned());
    }
}

fn nonempty_id(id: &Option<String>) -> Option<&str> {
    id.as_deref().filter(|text| !text.is_empty())
}

fn usize_index(index: usize) -> Result<i64, AbstentionError> {
    i64::try_from(index).map_err(|_| AbstentionError::RangeSpan)
}

fn event_at(events: &[EventValue], index: i64) -> Option<&EventValue> {
    usize::try_from(index)
        .ok()
        .and_then(|index| events.get(index))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::error::Error;

    use model::canonical::{CanonicalUnavailable, Payload, SessionEvent};
    use model::codes::{Repairability, Severity};
    use model::events::{
        EventError, EventField, EventMapping, EventValue, PYTHON_FLOAT_STR_UNREPRESENTABLE,
        PYTHON_STR_UNREPRESENTABLE,
    };
    use model::finding::{Finding, FindingInput, PyValue, SourceLine, SourceRef, SCHEMA_VERSION};

    use super::{
        check_step_scope, extract_side_effects, find_ambiguous_events, Abstention,
        AbstentionDictValue, AbstentionError, AffectedRegion, AmbiguousEvents, PyInt, RangesInput,
        MAX_INCLUSIVE_SPAN, PYTHON_BOOL_IS_NOT_INT, RANGE_SPAN_TOO_LARGE, SAFE_SIDE_EFFECT,
        SIDE_EFFECT_SCOPE_UNPROVEN, TOOL_KINDS,
    };

    #[test]
    fn tool_kinds_keep_source_order_for_membership() {
        assert_eq!(
            TOOL_KINDS,
            ["tool_call", "tool_use", "tool_result"].as_slice()
        );
        assert!(TOOL_KINDS.contains(&"tool_call"));
        assert!(TOOL_KINDS.contains(&"tool_use"));
        assert!(TOOL_KINDS.contains(&"tool_result"));
        assert!(!TOOL_KINDS.contains(&"message"));
        assert_eq!(SAFE_SIDE_EFFECT, "none");
    }

    #[test]
    fn abstention_to_dict_keeps_reason_order() {
        let decision = Abstention::new(true, ["zeta", "alpha", "zeta"]);
        assert!(decision.abstain());
        assert_eq!(
            decision.reasons(),
            ["zeta".to_owned(), "alpha".to_owned(), "zeta".to_owned()]
        );
        let dict = decision.to_dict();
        assert_eq!(dict.len(), 2);
        assert_eq!(dict[0].0, "abstain");
        assert_eq!(dict[0].1, AbstentionDictValue::Bool(true));
        assert_eq!(dict[1].0, "reasons");
        assert_eq!(
            dict[1].1,
            AbstentionDictValue::Reasons(vec![
                "zeta".to_owned(),
                "alpha".to_owned(),
                "zeta".to_owned()
            ])
        );
    }

    #[test]
    fn single_pair_becomes_inclusive_indices() {
        let region = region_pair(1, 3);
        assert_eq!(region.ranges(), &[(1, 3)]);
        assert_eq!(region.all_indices(None).unwrap(), BTreeSet::from([1, 2, 3]));
    }

    #[test]
    fn two_pairs_are_not_wrapped_into_one() {
        let region = AffectedRegion::new(
            std::iter::empty::<PyInt>(),
            std::iter::empty::<String>(),
            RangesInput::Sequence(vec![
                (PyInt::Int(1), PyInt::Int(2)),
                (PyInt::Int(4), PyInt::Int(4)),
            ]),
            false,
        )
        .unwrap();
        assert_eq!(region.ranges(), &[(1, 2), (4, 4)]);
        assert_eq!(region.all_indices(None).unwrap(), BTreeSet::from([1, 2, 4]));
        assert!(!region.all_indices(None).unwrap().contains(&3));
    }

    #[test]
    fn total_len_clamps_the_range_and_keeps_explicit_indices() {
        let region = AffectedRegion::new(
            [PyInt::Int(9)],
            std::iter::empty::<String>(),
            RangesInput::Pair(PyInt::Int(-2), PyInt::Int(10)),
            false,
        )
        .unwrap();
        assert_eq!(
            region.all_indices(Some(4)).unwrap(),
            BTreeSet::from([0, 1, 2, 3, 9])
        );
        assert!(region_pair(0, 5).all_indices(Some(0)).unwrap().is_empty());
    }

    #[test]
    fn start_greater_than_end_adds_nothing() {
        let region = AffectedRegion::new(
            [PyInt::Int(2)],
            std::iter::empty::<String>(),
            RangesInput::Pair(PyInt::Int(5), PyInt::Int(1)),
            false,
        )
        .unwrap();
        assert_eq!(region.all_indices(None).unwrap(), BTreeSet::from([2]));
        assert!(region_pair(i64::MAX, i64::MAX - 1)
            .all_indices(None)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn bool_is_not_an_i64() {
        let pair = AffectedRegion::new(
            std::iter::empty::<PyInt>(),
            std::iter::empty::<String>(),
            RangesInput::Pair(PyInt::Bool(true), PyInt::Bool(false)),
            false,
        )
        .unwrap_err();
        assert_eq!(pair, AbstentionError::PythonBoolAsInt);
        assert_eq!(pair.to_string(), PYTHON_BOOL_IS_NOT_INT);
        let index = AffectedRegion::new(
            [PyInt::Bool(true)],
            std::iter::empty::<String>(),
            RangesInput::Sequence(Vec::new()),
            false,
        )
        .unwrap_err();
        assert_eq!(index, AbstentionError::PythonBoolAsInt);
        assert!(Error::source(&index).is_none());
    }

    #[test]
    fn i64_max_end_returns_range_span_instead_of_panicking() {
        let err = region_pair(0, i64::MAX).all_indices(None).unwrap_err();
        assert_eq!(err, AbstentionError::RangeSpan);
        assert_eq!(err.to_string(), RANGE_SPAN_TOO_LARGE);
        assert_eq!(
            region_pair(i64::MAX, i64::MAX).all_indices(None).unwrap(),
            BTreeSet::from([i64::MAX])
        );
        assert_eq!(
            region_pair(0, i64::MAX).all_indices(Some(3)).unwrap(),
            BTreeSet::from([0, 1, 2])
        );
        let over_cap = i64::try_from(MAX_INCLUSIVE_SPAN).unwrap();
        assert_eq!(
            region_pair(0, over_cap).all_indices(None).unwrap_err(),
            AbstentionError::RangeSpan
        );
        assert_eq!(
            region_pair(0, 1).all_indices(Some(i64::MIN)).unwrap_err(),
            AbstentionError::RangeSpan
        );
    }

    #[test]
    fn explicit_side_effects_string_is_unchanged_including_empty() {
        let keep = event_with(vec![
            (
                "side_effects".to_owned(),
                EventField::Str("keep-me".to_owned()),
            ),
            (
                "payload".to_owned(),
                EventField::Mapping(side_effects_map("from-payload")),
            ),
        ]);
        assert_eq!(extract_side_effects(&keep, None).unwrap(), "keep-me");

        let empty = event_with(vec![
            ("side_effects".to_owned(), EventField::Str(String::new())),
            ("kind".to_owned(), EventField::Str("tool_call".to_owned())),
            (
                "payload".to_owned(),
                EventField::Mapping(EventMapping::new(vec![(
                    "name".to_owned(),
                    EventField::Str("read".to_owned()),
                )])),
            ),
        ]);
        assert_eq!(extract_side_effects(&empty, None).unwrap(), "");

        let number = event_with(vec![("side_effects".to_owned(), EventField::Int(-12))]);
        assert_eq!(extract_side_effects(&number, None).unwrap(), "-12");
        let yes = event_with(vec![("side_effects".to_owned(), EventField::Bool(true))]);
        assert_eq!(extract_side_effects(&yes, None).unwrap(), "True");
        let no = event_with(vec![("side_effects".to_owned(), EventField::Bool(false))]);
        assert_eq!(extract_side_effects(&no, None).unwrap(), "False");
    }

    #[test]
    fn tool_result_without_side_effects_returns_none() {
        let ev = event_with(vec![(
            "kind".to_owned(),
            EventField::Str("tool_result".to_owned()),
        )]);
        assert_eq!(extract_side_effects(&ev, None).unwrap(), "none");
        assert_eq!(extract_side_effects(&ev, None).unwrap(), SAFE_SIDE_EFFECT);
    }

    #[test]
    fn tool_call_named_read_returns_none() {
        assert_eq!(
            extract_side_effects(&tool_event("tool_call", "read"), None).unwrap(),
            "none"
        );
        assert_eq!(
            extract_side_effects(&tool_event("tool_call", "Read"), None).unwrap(),
            "none"
        );
        assert_eq!(
            extract_side_effects(&tool_event("tool_use", "read"), None).unwrap(),
            "none"
        );
        let explicit = event_with(vec![
            ("kind".to_owned(), EventField::Str("tool_call".to_owned())),
            (
                "side_effects".to_owned(),
                EventField::Str("possible".to_owned()),
            ),
            (
                "payload".to_owned(),
                EventField::Mapping(EventMapping::new(vec![(
                    "name".to_owned(),
                    EventField::Str("read".to_owned()),
                )])),
            ),
        ]);
        assert_eq!(extract_side_effects(&explicit, None).unwrap(), "possible");
    }

    #[test]
    fn tool_call_named_bash_returns_unknown() {
        assert_eq!(
            extract_side_effects(&tool_event("tool_call", "bash"), None).unwrap(),
            "unknown"
        );
    }

    #[test]
    fn payload_side_effects_used_only_when_top_level_is_missing() {
        let top = event_with(vec![
            ("side_effects".to_owned(), EventField::Str("top".to_owned())),
            (
                "payload".to_owned(),
                EventField::Mapping(side_effects_map("from-payload")),
            ),
        ]);
        assert_eq!(extract_side_effects(&top, None).unwrap(), "top");

        let missing = event_with(vec![(
            "payload".to_owned(),
            EventField::Mapping(side_effects_map("from-payload")),
        )]);
        assert_eq!(
            extract_side_effects(&missing, None).unwrap(),
            "from-payload"
        );

        let null_top = event_with(vec![
            ("side_effects".to_owned(), EventField::Null),
            (
                "payload".to_owned(),
                EventField::Mapping(side_effects_map("from-payload")),
            ),
        ]);
        assert_eq!(
            extract_side_effects(&null_top, None).unwrap(),
            "from-payload"
        );

        let extra_only = event_with(vec![(
            "extra_fields".to_owned(),
            EventField::Mapping(side_effects_map("from-extra")),
        )]);
        assert_eq!(
            extract_side_effects(&extra_only, None).unwrap(),
            "from-extra"
        );
        let payload_wins = event_with(vec![
            (
                "payload".to_owned(),
                EventField::Mapping(side_effects_map("from-payload")),
            ),
            (
                "extra_fields".to_owned(),
                EventField::Mapping(side_effects_map("from-extra")),
            ),
        ]);
        assert_eq!(
            extract_side_effects(&payload_wins, None).unwrap(),
            "from-payload"
        );
    }

    #[test]
    fn float_or_list_kind_returns_event_kind_error_not_unknown() {
        let float_kind = event_with(vec![("kind".to_owned(), EventField::Float(1.0))]);
        let err = extract_side_effects(&float_kind, None).unwrap_err();
        assert_eq!(err, AbstentionError::Event(EventError::PythonFloatStr));
        assert_eq!(err.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        assert_ne!(err.to_string(), "unknown");
        assert!(Error::source(&err).is_some());

        let list_kind = event_with(vec![(
            "kind".to_owned(),
            EventField::List(vec![EventField::Str("tool_result".to_owned())]),
        )]);
        let list_err = extract_side_effects(&list_kind, None).unwrap_err();
        assert_eq!(list_err, AbstentionError::Event(EventError::PythonStr));
        assert_eq!(list_err.to_string(), PYTHON_STR_UNREPRESENTABLE);
        assert_ne!(list_err.to_string(), "unknown");

        assert_eq!(
            extract_side_effects(&float_kind, Some("tool_result")).unwrap(),
            "none"
        );
    }

    #[test]
    fn falsy_tool_name_falls_through_and_last_duplicate_wins() {
        let empty_name = tool_payload(vec![
            ("name".to_owned(), EventField::Str(String::new())),
            ("tool_name".to_owned(), EventField::Str("read".to_owned())),
        ]);
        assert_eq!(extract_side_effects(&empty_name, None).unwrap(), "none");

        let zero = tool_payload(vec![
            ("name".to_owned(), EventField::Int(0)),
            ("tool_name".to_owned(), EventField::Str("bash".to_owned())),
        ]);
        assert_eq!(extract_side_effects(&zero, None).unwrap(), "unknown");

        let flag = tool_payload(vec![
            ("name".to_owned(), EventField::Bool(false)),
            ("tool_name".to_owned(), EventField::Str("read".to_owned())),
        ]);
        assert_eq!(extract_side_effects(&flag, None).unwrap(), "none");

        let falsy_float = tool_payload(vec![
            ("name".to_owned(), EventField::Float(0.0)),
            ("tool_name".to_owned(), EventField::Str("read".to_owned())),
        ]);
        assert_eq!(extract_side_effects(&falsy_float, None).unwrap(), "none");

        let truthy_float = tool_payload(vec![("name".to_owned(), EventField::Float(1.0))]);
        assert_eq!(
            extract_side_effects(&truthy_float, None).unwrap_err(),
            AbstentionError::PythonFloatStr
        );

        let last = tool_payload(vec![
            ("name".to_owned(), EventField::Str("bash".to_owned())),
            ("name".to_owned(), EventField::Str("read".to_owned())),
        ]);
        assert_eq!(extract_side_effects(&last, None).unwrap(), "none");

        let event_name = event_with(vec![
            ("kind".to_owned(), EventField::Str("tool_call".to_owned())),
            ("name".to_owned(), EventField::Str("read".to_owned())),
        ]);
        assert_eq!(extract_side_effects(&event_name, None).unwrap(), "none");
    }

    #[test]
    fn float_side_effects_value_is_a_typed_error() {
        let ev = event_with(vec![("side_effects".to_owned(), EventField::Float(1.5))]);
        let err = extract_side_effects(&ev, None).unwrap_err();
        assert_eq!(err, AbstentionError::PythonFloatStr);
        assert_eq!(err.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        assert_ne!(err.to_string(), "unknown");
        assert_ne!(err.to_string(), "1.5");
    }

    #[test]
    fn session_event_empty_side_effects_stays_empty() {
        let mut event = session("tool_call");
        event.side_effects = Some(String::new());
        event.payload = Payload::map(vec![(
            Payload::string("side_effects"),
            Payload::string("possible"),
        )]);
        assert_eq!(
            extract_side_effects(&EventValue::from_session(event), None).unwrap(),
            ""
        );
    }

    #[test]
    fn session_event_scalar_payload_is_not_a_mapping() {
        let mut event = session("tool_result");
        event.side_effects = None;
        event.payload = Payload::string("synthetic");
        event.extra_fields = Payload::null();
        assert_eq!(
            extract_side_effects(&EventValue::from_session(event), None).unwrap(),
            "none"
        );
    }

    #[test]
    fn session_event_map_payload_is_read_and_list_payload_is_skipped() {
        let mut event = session("tool_call");
        event.payload = Payload::map(vec![
            (Payload::string("side_effects"), Payload::string("first")),
            (
                Payload::string("side_effects"),
                Payload::string("from-payload"),
            ),
        ]);
        assert_eq!(
            extract_side_effects(&EventValue::from_session(event), None).unwrap(),
            "from-payload"
        );

        let mut named = session("tool_call");
        named.payload = Payload::map(vec![
            (Payload::string("name"), Payload::string("bash")),
            (Payload::string("name"), Payload::string("read")),
        ]);
        assert_eq!(
            extract_side_effects(&EventValue::from_session(named), None).unwrap(),
            "none"
        );

        let mut listed = session("tool_call");
        listed.payload = Payload::list(vec![Payload::string("side_effects")]);
        listed.extra_fields = Payload::map(vec![(
            Payload::string("side_effects"),
            Payload::string("from-extra"),
        )]);
        assert_eq!(
            extract_side_effects(&EventValue::from_session(listed), None).unwrap(),
            "from-extra"
        );

        let mut tupled = session("tool_result");
        tupled.payload = Payload::tuple(vec![Payload::string("keep")]);
        tupled.extra_fields = Payload::tuple(Vec::new());
        assert_eq!(
            extract_side_effects(&EventValue::from_session(tupled), None).unwrap(),
            "none"
        );

        let empty_map = session("tool_call");
        assert_eq!(
            extract_side_effects(&EventValue::from_session(empty_map), None).unwrap(),
            "unknown"
        );
    }

    #[test]
    fn sl203_record_id_is_added_and_disjoint_region_abstains() {
        let events = vec![event_with(vec![
            ("kind".to_owned(), EventField::Str("message".to_owned())),
            ("id".to_owned(), EventField::Str("evt-other".to_owned())),
        ])];
        let finding = finding_with("SL203", Some("rec-sl203"), PyValue::None);
        let found = find_ambiguous_events(&events, Some(std::slice::from_ref(&finding))).unwrap();
        assert!(found.ids().contains("rec-sl203"));
        assert!(found.indices().is_empty());
        assert!(found.reasons().is_empty());

        let other = finding_with("SL001", Some("rec-sl203"), PyValue::None);
        let ignored = find_ambiguous_events(&events, Some(std::slice::from_ref(&other))).unwrap();
        assert!(ignored.ids().is_empty());

        let region = AffectedRegion::new(
            [PyInt::Int(0)],
            std::iter::empty::<String>(),
            RangesInput::Sequence(Vec::new()),
            false,
        )
        .unwrap();
        let step = 7_i64;
        let callback = |_step: &i64, _events: &[EventValue]| Ok(Some(region.clone()));
        let allowed = check_step_scope(&step, &events, Some(&callback), None, false, None).unwrap();
        assert_eq!(allowed, (true, None));
        let still_allowed =
            check_step_scope(&step, &events, Some(&callback), Some(&[other]), false, None).unwrap();
        assert_eq!(still_allowed, (true, None));
        let abstained = check_step_scope(
            &step,
            &events,
            Some(&callback),
            Some(&[finding]),
            false,
            None,
        )
        .unwrap();
        assert_eq!(abstained, (false, Some(SIDE_EFFECT_SCOPE_UNPROVEN)));
    }

    #[test]
    fn scope_fails_closed_without_a_proven_region() {
        let step = 4_i64;
        let events: [EventValue; 0] = [];
        let missing = check_step_scope(&step, &events, None, None, false, None).unwrap();
        assert_eq!(missing, (false, Some(SIDE_EFFECT_SCOPE_UNPROVEN)));

        let broken = |_step: &i64, _events: &[EventValue]| Err(AbstentionError::RangeSpan);
        let callback_error =
            check_step_scope(&step, &events, Some(&broken), None, false, None).unwrap();
        assert_eq!(callback_error, (false, Some(SIDE_EFFECT_SCOPE_UNPROVEN)));

        let absent = |_step: &i64, _events: &[EventValue]| Ok(None);
        let none_region =
            check_step_scope(&step, &events, Some(&absent), None, false, None).unwrap();
        assert_eq!(none_region, (false, Some(SIDE_EFFECT_SCOPE_UNPROVEN)));

        let unproven = AffectedRegion::new(
            std::iter::empty::<PyInt>(),
            std::iter::empty::<String>(),
            RangesInput::Sequence(Vec::new()),
            true,
        )
        .unwrap();
        let unproven_fn = |_step: &i64, _events: &[EventValue]| Ok(Some(unproven.clone()));
        let unproven_region =
            check_step_scope(&step, &events, Some(&unproven_fn), None, false, None).unwrap();
        assert_eq!(unproven_region, (false, Some(SIDE_EFFECT_SCOPE_UNPROVEN)));
    }

    #[test]
    fn pairing_reasons_follow_the_pin() {
        let dangling = find_ambiguous_events(
            &[tool_corr(
                "tool_call",
                "bash",
                "c-dangle",
                "call-dangle",
                None,
            )],
            None,
        )
        .unwrap();
        assert_eq!(dangling.indices(), &BTreeSet::from([0]));
        assert!(dangling.ids().contains("call-dangle"));
        assert_eq!(
            dangling.reasons(),
            ["dangling-call-c-dangle at index 0".to_owned()]
        );

        let orphan = find_ambiguous_events(
            &[tool_corr(
                "tool_result",
                "bash",
                "c-orphan",
                "result-orphan",
                None,
            )],
            None,
        )
        .unwrap();
        assert_eq!(orphan.indices(), &BTreeSet::from([0]));
        assert!(orphan.ids().contains("result-orphan"));
        assert_eq!(orphan.reasons(), ["orphan-result-c-orphan".to_owned()]);

        let reused = find_ambiguous_events(
            &[
                tool_corr("tool_call", "bash", "c-reuse", "call-a", None),
                tool_corr("tool_call", "bash", "c-reuse", "call-b", None),
            ],
            None,
        )
        .unwrap();
        assert_eq!(reused.indices(), &BTreeSet::from([0, 1]));
        assert_eq!(
            reused.ids(),
            &BTreeSet::from(["call-a".to_owned(), "call-b".to_owned()])
        );
        assert_eq!(reused.reasons(), ["reused-correlation-c-reuse".to_owned()]);

        let reversed = find_ambiguous_events(
            &[
                result_execution("result-rev", "c-rev", EventField::Str("unknown".to_owned())),
                tool_corr("tool_call", "bash", "c-rev", "call-rev", Some("unknown")),
            ],
            None,
        )
        .unwrap();
        assert_eq!(reversed.indices(), &BTreeSet::from([0, 1]));
        assert!(reversed.ids().contains("result-rev"));
        assert!(reversed.ids().contains("call-rev"));
        assert_eq!(
            reversed.reasons(),
            [
                "reversed-pairing-c-rev at indices (0, 1)".to_owned(),
                "unknown-side-effects-c-rev at index 1".to_owned(),
                "unknown-execution-c-rev at index 0".to_owned(),
            ]
        );

        let flag = find_ambiguous_events(
            &[
                tool_corr("tool_call", "read", "c-flag", "call-flag", Some("none")),
                result_execution("result-flag", "c-flag", EventField::Bool(true)),
            ],
            None,
        )
        .unwrap();
        assert!(flag.indices().is_empty());
        assert!(flag.ids().is_empty());
        assert!(flag.reasons().is_empty());
    }

    #[test]
    fn identical_content_hash_abc_is_not_conflicting() {
        let events = hash_pair(Some("abc"), Some("abc"), "none");
        let found = find_ambiguous_events(&events, None).unwrap();
        assert!(found.indices().is_empty());
        assert!(found.ids().is_empty());
        assert!(found.reasons().is_empty());
    }

    #[test]
    fn different_content_hashes_are_conflicting() {
        let events = hash_pair(Some("abc"), Some("def"), "none");
        let found = find_ambiguous_events(&events, None).unwrap();
        assert_eq!(found.indices(), &BTreeSet::from([0, 1, 2]));
        assert_eq!(
            found.ids(),
            &BTreeSet::from([
                "call-hash".to_owned(),
                "res-left".to_owned(),
                "res-right".to_owned()
            ])
        );
        assert!(found.reasons().is_empty());
    }

    #[test]
    fn missing_content_hash_propagates_unavailable_and_is_not_a_digest() {
        let events = hash_pair(None, None, "none");
        let err = find_ambiguous_events(&events, None).unwrap_err();
        assert_eq!(
            err,
            AbstentionError::Event(EventError::from(
                CanonicalUnavailable::payload_content_hash()
            ))
        );
        assert_eq!(
            err.to_string(),
            "sesslint._canonical_codec.payload_content_hash is not available"
        );
        assert!(!err.to_string().chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn read_only_tool_inside_the_region_is_allowed() {
        let events = vec![
            tool_corr("tool_call", "read", "c-read", "call-read", None),
            tool_corr("tool_result", "read", "c-read", "result-read", None),
        ];
        let region = AffectedRegion::new(
            [PyInt::Int(0)],
            std::iter::empty::<String>(),
            RangesInput::Sequence(Vec::new()),
            false,
        )
        .unwrap();
        let callback = |_step: &i64, _events: &[EventValue]| Ok(Some(region.clone()));
        let allowed =
            check_step_scope(&1_i64, &events, Some(&callback), None, false, None).unwrap();
        assert_eq!(allowed, (true, None));
    }

    #[test]
    fn excludes_execution_dependence_allows_a_non_none_side_effect() {
        let events = vec![
            tool_corr(
                "tool_call",
                "bash",
                "c-effect",
                "call-effect",
                Some("possible"),
            ),
            tool_corr("tool_result", "bash", "c-effect", "result-effect", None),
        ];
        let region = AffectedRegion::new(
            [PyInt::Int(0)],
            std::iter::empty::<String>(),
            RangesInput::Sequence(Vec::new()),
            false,
        )
        .unwrap();
        let callback = |_step: &i64, _events: &[EventValue]| Ok(Some(region.clone()));
        let blocked =
            check_step_scope(&2_i64, &events, Some(&callback), None, false, None).unwrap();
        assert_eq!(blocked, (false, Some(SIDE_EFFECT_SCOPE_UNPROVEN)));
        let allowed = check_step_scope(&2_i64, &events, Some(&callback), None, true, None).unwrap();
        assert_eq!(allowed, (true, None));
    }

    #[test]
    fn first_unsafe_index_walks_tool_events_and_skips_other_values() {
        let events = vec![
            event_with(vec![
                ("kind".to_owned(), EventField::Str("message".to_owned())),
                ("id".to_owned(), EventField::Str("evt-msg".to_owned())),
            ]),
            tool_corr("tool_call", "read", "c-safe", "call-safe", Some("none")),
            tool_corr("tool_result", "read", "c-safe", "result-safe", None),
        ];
        let finding = finding_with(
            "SL203",
            None,
            PyValue::map(vec![
                (PyValue::string("first_unsafe_index"), PyValue::int(1)),
                (PyValue::string("record_ordinal"), PyValue::int(0)),
                (PyValue::string("at_index"), PyValue::string("skipped")),
                (PyValue::string("index"), PyValue::int(9)),
            ]),
        );
        let found = find_ambiguous_events(&events, Some(std::slice::from_ref(&finding))).unwrap();
        assert_eq!(found.indices(), &BTreeSet::from([0, 1, 2]));
        assert!(found.ids().contains("evt-msg"));
        assert!(found.ids().contains("call-safe"));
        assert!(found.ids().contains("result-safe"));
        assert!(found.reasons().is_empty());
    }

    #[test]
    fn bool_evidence_index_returns_python_bool_as_int() {
        let finding = finding_with(
            "SL203",
            None,
            PyValue::map(vec![(PyValue::string("index"), PyValue::bool_value(true))]),
        );
        let err = find_ambiguous_events(&[], Some(&[finding])).unwrap_err();
        assert_eq!(err, AbstentionError::PythonBoolAsInt);
        assert_eq!(err.to_string(), PYTHON_BOOL_IS_NOT_INT);
        assert_ne!(err.to_string(), "1");
    }

    #[test]
    fn ambiguous_events_keep_reason_order_and_default_empty() {
        let empty = AmbiguousEvents::new([2, 2, 1], ["evt-b", "evt-a"]);
        assert!(empty.reasons().is_empty());
        assert_eq!(empty.indices(), &BTreeSet::from([1, 2]));
        assert_eq!(
            empty.ids(),
            &BTreeSet::from(["evt-a".to_owned(), "evt-b".to_owned()])
        );
        let kept = AmbiguousEvents::with_reasons(
            std::iter::empty::<i64>(),
            std::iter::empty::<String>(),
            ["zeta", "alpha"],
        );
        assert_eq!(kept.reasons(), ["zeta".to_owned(), "alpha".to_owned()]);
    }

    fn event_with(entries: Vec<(String, EventField)>) -> EventValue {
        EventValue::Mapping(EventMapping::new(entries))
    }

    fn side_effects_map(text: &str) -> EventMapping {
        EventMapping::new(vec![(
            "side_effects".to_owned(),
            EventField::Str(text.to_owned()),
        )])
    }

    fn tool_event(kind: &str, name: &str) -> EventValue {
        event_with(vec![
            ("kind".to_owned(), EventField::Str(kind.to_owned())),
            (
                "payload".to_owned(),
                EventField::Mapping(EventMapping::new(vec![(
                    "name".to_owned(),
                    EventField::Str(name.to_owned()),
                )])),
            ),
        ])
    }

    fn tool_payload(entries: Vec<(String, EventField)>) -> EventValue {
        event_with(vec![
            ("kind".to_owned(), EventField::Str("tool_call".to_owned())),
            (
                "payload".to_owned(),
                EventField::Mapping(EventMapping::new(entries)),
            ),
        ])
    }

    fn region_pair(start: i64, end: i64) -> AffectedRegion {
        AffectedRegion::new(
            std::iter::empty::<PyInt>(),
            std::iter::empty::<String>(),
            RangesInput::Pair(PyInt::Int(start), PyInt::Int(end)),
            false,
        )
        .unwrap()
    }

    fn session(kind: &str) -> SessionEvent {
        SessionEvent::new(
            "evt-synthetic",
            None,
            1,
            "2024-02-29T00:00:00Z",
            "assistant",
            kind,
        )
    }

    fn tool_corr(
        kind: &str,
        name: &str,
        corr: &str,
        id: &str,
        side_effects: Option<&str>,
    ) -> EventValue {
        let mut entries = vec![
            ("kind".to_owned(), EventField::Str(kind.to_owned())),
            ("id".to_owned(), EventField::Str(id.to_owned())),
            (
                "correlation_id".to_owned(),
                EventField::Str(corr.to_owned()),
            ),
            (
                "payload".to_owned(),
                EventField::Mapping(EventMapping::new(vec![(
                    "name".to_owned(),
                    EventField::Str(name.to_owned()),
                )])),
            ),
        ];
        if let Some(side_effects) = side_effects {
            entries.push((
                "side_effects".to_owned(),
                EventField::Str(side_effects.to_owned()),
            ));
        }
        event_with(entries)
    }

    fn result_execution(id: &str, corr: &str, execution: EventField) -> EventValue {
        event_with(vec![
            ("kind".to_owned(), EventField::Str("tool_result".to_owned())),
            ("id".to_owned(), EventField::Str(id.to_owned())),
            (
                "correlation_id".to_owned(),
                EventField::Str(corr.to_owned()),
            ),
            (
                "payload".to_owned(),
                EventField::Mapping(EventMapping::new(vec![("execution".to_owned(), execution)])),
            ),
        ])
    }

    fn hash_pair(left: Option<&str>, right: Option<&str>, side_effects: &str) -> Vec<EventValue> {
        let mut call = session("tool_call");
        call.id = "call-hash".to_owned();
        call.correlation_id = Some("c-hash".to_owned());
        call.side_effects = Some(side_effects.to_owned());
        let mut first = session("tool_result");
        first.id = "res-left".to_owned();
        first.correlation_id = Some("c-hash".to_owned());
        first.content_hash = left.map(str::to_owned);
        let mut second = session("tool_result");
        second.id = "res-right".to_owned();
        second.correlation_id = Some("c-hash".to_owned());
        second.content_hash = right.map(str::to_owned);
        vec![
            EventValue::from_session(call),
            EventValue::from_session(first),
            EventValue::from_session(second),
        ]
    }

    fn finding_with(code: &str, record_id: Option<&str>, evidence: PyValue) -> Finding {
        let source = SourceRef::try_new("a.jsonl", Some(SourceLine::Int(1)), record_id).unwrap();
        Finding::try_new(FindingInput {
            code: PyValue::string(code),
            severity: PyValue::severity(Severity::Error),
            repairability: PyValue::repairability(Repairability::Manual),
            message: PyValue::string("synthetic marker"),
            source: PyValue::source(source),
            related_ids: PyValue::tuple(Vec::new()),
            fingerprint: PyValue::string("0123456789abcdef"),
            schema_version: PyValue::string(SCHEMA_VERSION),
            message_template: PyValue::None,
            evidence,
        })
        .unwrap()
    }
}
