//! Side-effect abstention data (TASK-017, DEV-013).
//!
//! Port of `src/sesslint/policy/abstention.py` lines 1–142
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! Stops before `find_ambiguous_events`. The Python module docstring describes
//! the SL203 global gate. This slice does not implement that gate and does not
//! add a bypass for it.
//!
//! # Recorded gaps
//!
//! * A bool is not an i64. `True` is not `1` ([`PYTHON_BOOL_IS_NOT_INT`]).
//!   [`AffectedRegion::new`] returns [`AbstentionError::PythonBoolAsInt`].
//! * A float's Python `str` is not matched
//!   (`model::events::PYTHON_FLOAT_STR_UNREPRESENTABLE`). Stringifying a float
//!   side-effect value, or a truthy float tool name, returns
//!   [`AbstentionError::PythonFloatStr`] and does not panic. A falsy float
//!   (`0.0` / `-0.0`) is skipped by Python `or` and is not stringified. A float
//!   or list `kind` is `model::events::event_kind`'s error, propagated unchanged.
//! * Python `str` of a list or mapping is not matched
//!   (`model::events::PYTHON_STR_UNREPRESENTABLE`).
//! * `Payload` map entries are private to `model`. Derived `Debug` can recurse
//!   forever through a cyclic map key, and `model::canonical::validate_depth`
//!   does not walk keys, so this crate does not scrape `Debug`. A non-scalar
//!   `SessionEvent` `payload` or `extra_fields` returns
//!   [`AbstentionError::PayloadMapLookup`] instead of treating the container as
//!   empty. `EventMapping` lookups use last-duplicate string-key wins and do
//!   not sort keys. A scalar payload is not a mapping and is skipped.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use model::canonical::{Payload, READ_ONLY_TOOL_NAMES};
use model::events::{
    event_kind, EventError, EventField, EventMapping, EventValue, PYTHON_FLOAT_STR_UNREPRESENTABLE,
    PYTHON_STR_UNREPRESENTABLE,
};

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

/// Failure from this slice. [`Display`] is the message only, except an
/// [`AbstentionError::Event`] which displays the propagated event error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbstentionError {
    Event(EventError),
    PythonBoolAsInt,
    PythonFloatStr,
    PythonStr,
    PayloadMapLookup,
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
        raw_se = side_effects_in(payload_mapping(ev)?);
    }
    if raw_se.is_none() {
        raw_se = side_effects_in(extra_mapping(ev)?);
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

fn payload_mapping(ev: &EventValue) -> Result<Option<EventMapping>, AbstentionError> {
    match ev {
        EventValue::Session(event) => event_mapping_from_payload(&event.payload),
        EventValue::Mapping(mapping) => Ok(nested_mapping(mapping, "payload")),
        EventValue::Other => Ok(None),
    }
}

fn extra_mapping(ev: &EventValue) -> Result<Option<EventMapping>, AbstentionError> {
    match ev {
        EventValue::Session(event) => event_mapping_from_payload(&event.extra_fields),
        EventValue::Mapping(mapping) => Ok(nested_mapping(mapping, "extra_fields")),
        EventValue::Other => Ok(None),
    }
}

fn nested_mapping(mapping: &EventMapping, key: &str) -> Option<EventMapping> {
    match mapping.get(key) {
        Some(EventField::Mapping(child)) => Some(child.clone()),
        _ => None,
    }
}

fn event_mapping_from_payload(payload: &Payload) -> Result<Option<EventMapping>, AbstentionError> {
    if is_scalar_payload(payload) {
        Ok(None)
    } else {
        Err(AbstentionError::PayloadMapLookup)
    }
}

fn is_scalar_payload(payload: &Payload) -> bool {
    payload.is_null()
        || payload.as_bool().is_some()
        || payload.as_int().is_some()
        || payload.as_float().is_some()
        || payload.as_str().is_some()
}

fn lowered_tool_name(ev: &EventValue) -> Result<String, AbstentionError> {
    let mut tool_name = String::new();
    if let Some(payload) = payload_mapping(ev)? {
        tool_name = first_truthy(&[payload.get("name"), payload.get("tool_name")])?.to_lowercase();
    }
    if tool_name.is_empty() {
        tool_name = event_name(ev)?.to_lowercase();
    }
    Ok(tool_name)
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::error::Error;

    use model::canonical::{Payload, SessionEvent};
    use model::events::{
        EventError, EventField, EventMapping, EventValue, PYTHON_FLOAT_STR_UNREPRESENTABLE,
        PYTHON_STR_UNREPRESENTABLE,
    };

    use super::{
        extract_side_effects, Abstention, AbstentionDictValue, AbstentionError, AffectedRegion,
        AmbiguousEvents, PyInt, RangesInput, MAX_INCLUSIVE_SPAN, PAYLOAD_MAP_LOOKUP_UNAVAILABLE,
        PYTHON_BOOL_IS_NOT_INT, RANGE_SPAN_TOO_LARGE, SAFE_SIDE_EFFECT, TOOL_KINDS,
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
    fn session_event_map_payload_is_not_treated_as_empty() {
        let event = session("tool_call");
        let err = extract_side_effects(&EventValue::from_session(event), None).unwrap_err();
        assert_eq!(err, AbstentionError::PayloadMapLookup);
        assert_eq!(err.to_string(), PAYLOAD_MAP_LOOKUP_UNAVAILABLE);
        assert_ne!(err.to_string(), "none");
        assert_ne!(err.to_string(), "unknown");
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
}
