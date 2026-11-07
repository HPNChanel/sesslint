//! Salvage repair recipes through orphan-target validation (TASK-020).
//!
//! Port of `src/sesslint/repair/recipes_salvage.py` lines 1–331
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! The slice stops before `apply_orphan_result_drop_with_loss` (line 332).
//! `apply_orphan_result_drop`, `affected_region_orphan_result_drop`,
//! `sl101_orphan_present`, `register_all`, and `__all__` are not ported.
//! `sesslint.policy.abstention.AffectedRegion` is not constructed.
//! This crate does not depend on `checks`.
//!
//! A bool is not an int. It is never used as a list index or a slice bound.
//! When the pin would use that bool to select an event, the function returns
//! [`PreconditionFailed`](crate::recipes_conservative::PreconditionFailed) and
//! does not return a transformed list. `str(True)` stays `True`.
//!
//! [`to_event_dict`](model::events::to_event_dict) and
//! [`copy_events_as_dicts`](model::events::copy_events_as_dicts) are in the
//! `model` crate. A mapping is copied. A [`SessionEvent`](model::canonical::SessionEvent)
//! or any other value stops with
//! `sesslint._canonical_codec.normalize_canonical is not available` and is not
//! `Ok`. Inputs are not mutated.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use model::events::{
    copy_events_as_dicts, event_corr_id, event_id, event_kind, event_parent_id, to_event_dict,
    EventError, EventField, EventMapping, EventValue,
};

use crate::preconditions::{
    PreconditionError, _find_component_indices, _find_torn_compaction_dropped_indices,
};
use crate::recipes_conservative::PreconditionFailed;

/// Python `MAX_COMPONENT_SIZE`.
pub const MAX_COMPONENT_SIZE: usize = 10_000;

/// Python `_CALL_KINDS`. Membership only.
const CALL_KINDS: [&str; 2] = ["tool_call", "tool_use"];

/// Value read from `target_index`.
///
/// [`IndexValue::Bool`] is not an int. [`IndexValue::Float`] keeps the IEEE
/// bits so `-0.0` and `NaN` stay distinct from a real int.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexValue {
    /// Python `None`.
    None,
    /// Python `int`. Not a bool.
    Int(i64),
    /// Python `bool`. Not an int.
    Bool(bool),
    /// Bit pattern of a Python `float`.
    Float(u64),
    /// Present, and not `None`, `bool`, `int`, or `float`.
    ///
    /// `type_name` is the Python type name used in a comparison `TypeError`.
    /// It is not an event field.
    Other(&'static str),
}

/// `params` as these recipes read it.
///
/// [`ParamMap::NotMapping`] is falsy and is not a `Mapping`, matching `None`.
/// A truthy non-mapping is not represented.
#[derive(Debug, Clone, PartialEq)]
pub enum ParamMap {
    /// Python `collections.abc.Mapping`.
    Mapping(EventMapping),
    /// Not a mapping.
    NotMapping,
}

/// Step fields this slice reads.
///
/// This is not [`crate::planner::PlanStep`]. A bool index has to remain a
/// bool, and [`PlanStep`](crate::planner::PlanStep) stores `target_index` as
/// `Option<i128>`.
#[derive(Debug, Clone, PartialEq)]
pub struct SalvageStep {
    /// Python `PlanStep.target_index`.
    pub target_index: IndexValue,
    /// Python `PlanStep.params`.
    pub params: ParamMap,
}

/// One loss-class count, in insertion order.
///
/// The Python value is a one-entry `dict`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LossDelta {
    entries: Vec<(String, i64)>,
}

impl LossDelta {
    fn one(class: &str, count: i64) -> Self {
        Self {
            entries: vec![(class.to_owned(), count)],
        }
    }

    /// Loss class names and counts, in the order the pin inserts them.
    pub fn entries(&self) -> &[(String, i64)] {
        &self.entries
    }
}

/// Python `TypeError` raised while resolving an index.
///
/// [`Display`](fmt::Display) is the message only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexTypeError {
    message: String,
}

impl IndexTypeError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for IndexTypeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for IndexTypeError {}

/// Failure from a salvage recipe in this slice.
///
/// [`Display`](fmt::Display) is the message only. A precondition displays the
/// [`PreconditionFailed`] message. An event-helper failure displays the
/// [`EventError`](model::events::EventError) text. An index `TypeError`
/// displays that message. An unavailable helper displays its own sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SalvageError {
    /// Python `PreconditionFailed`.
    Precondition(PreconditionFailed),
    /// `_event_*`, `_to_event_dict`, or `_copy_events_as_dicts` failed.
    Event(EventError),
    /// Python `TypeError` from a comparison, a list index, or a slice.
    Type(IndexTypeError),
    /// A precondition helper returned `{module.function} is not available`.
    Unavailable(&'static str),
}

impl fmt::Display for SalvageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Precondition(error) => error.fmt(formatter),
            Self::Event(error) => error.fmt(formatter),
            Self::Type(error) => error.fmt(formatter),
            Self::Unavailable(message) => formatter.write_str(message),
        }
    }
}

impl Error for SalvageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Event(error) => Some(error),
            Self::Precondition(_) | Self::Type(_) | Self::Unavailable(_) => None,
        }
    }
}

impl From<EventError> for SalvageError {
    fn from(error: EventError) -> Self {
        Self::Event(error)
    }
}

impl From<PreconditionFailed> for SalvageError {
    fn from(error: PreconditionFailed) -> Self {
        Self::Precondition(error)
    }
}

impl From<PreconditionError> for SalvageError {
    fn from(error: PreconditionError) -> Self {
        match error {
            PreconditionError::Event(error) => Self::Event(error),
            PreconditionError::Value(message) => {
                Self::Precondition(PreconditionFailed::new(message))
            }
            PreconditionError::Unavailable(message) => Self::Unavailable(message),
        }
    }
}

/// Drop the weakly connected parent component that contains `step`'s target.
///
/// Python: `apply_unresolvable_branch_amputate_with_loss`. An empty session is
/// refused before the index is read. A `None` index may be resolved from a
/// truthy `root_id` or else `record_id`. A bool index is refused. It is not
/// `0` or `1`. A float that the pin would format with `str(float)` is
/// [`EventError::PythonFloatStr`]. A float the pin would use as a list index
/// is a `TypeError`. The component walk is
/// [`_find_component_indices`](crate::preconditions::_find_component_indices).
/// Kept events are copied with [`to_event_dict`](model::events::to_event_dict).
/// The input slice is not mutated.
///
/// # Errors
///
/// Returns [`SalvageError::Precondition`] for an empty session, a bad index, a
/// component larger than [`MAX_COMPONENT_SIZE`], a checkpoint, or a component
/// that is the whole session. Returns [`SalvageError::Event`] when an event
/// read or a kept-event copy fails. Returns [`SalvageError::Type`] when the
/// index is not ordered or cannot be used as a list index. This function does
/// not panic, and it does not return `Ok` on those failures.
pub fn apply_unresolvable_branch_amputate_with_loss(
    events: &[EventValue],
    step: &SalvageStep,
) -> Result<(Vec<EventMapping>, LossDelta), SalvageError> {
    if events.is_empty() {
        return Err(failed("Cannot amputate an empty session"));
    }
    let seed = accept_amputate_index(resolve_amputate_seed(events, step)?, events.len())?;
    let component = _find_component_indices(events, seed)?;
    if component.len() > MAX_COMPONENT_SIZE {
        let size = component.len();
        return Err(failed(format!(
            "Component size ({size}) exceeds limit of {MAX_COMPONENT_SIZE}"
        )));
    }
    for index in &component {
        let event = event_at_i64(events, *index)?;
        if event_kind(event)?.as_deref() == Some("checkpoint") {
            return Err(failed("Branch contains a checkpoint; cannot amputate"));
        }
    }
    if component.len() >= events.len() {
        return Err(failed("Amputating entire session is forbidden"));
    }
    let dropped = component.iter().copied().collect::<BTreeSet<_>>();
    let out = copy_kept_i64(events, &dropped)?;
    Ok((
        out,
        LossDelta::one("amputated-branch", try_count(component.len())?),
    ))
}

/// Python: `apply_unresolvable_branch_amputate`.
///
/// The loss count is discarded. A failure from
/// [`apply_unresolvable_branch_amputate_with_loss`] is returned unchanged.
///
/// # Errors
///
/// See [`apply_unresolvable_branch_amputate_with_loss`]. This function does
/// not panic.
pub fn apply_unresolvable_branch_amputate(
    events: &[EventValue],
    step: &SalvageStep,
) -> Result<Vec<EventMapping>, SalvageError> {
    Ok(apply_unresolvable_branch_amputate_with_loss(events, step)?.0)
}

/// Drop a compaction boundary and the minority orphaned side.
///
/// Python: `apply_torn_compaction_project_with_loss`. An empty session is
/// refused first. An out-of-range int, an out-of-range bool, a missing index,
/// or an out-of-range float searches for one `compaction_boundary`. An
/// in-range bool is refused and does not select an event. An in-range float
/// is a list-index `TypeError`. `ValueError` from
/// [`_find_torn_compaction_dropped_indices`](crate::preconditions::_find_torn_compaction_dropped_indices)
/// becomes [`PreconditionFailed`]. The input slice is not mutated.
///
/// # Errors
///
/// Returns [`SalvageError::Precondition`] for an empty session, a bad index, a
/// non-boundary, or a boundary that splits nothing. Returns
/// [`SalvageError::Event`] when a kind read, a correlation read, or a kept
/// copy fails. Returns [`SalvageError::Type`] for an unordered index or an
/// in-range float. This function does not panic, and it does not return `Ok`
/// on those failures.
pub fn apply_torn_compaction_project_with_loss(
    events: &[EventValue],
    step: &SalvageStep,
) -> Result<(Vec<EventMapping>, LossDelta), SalvageError> {
    if events.is_empty() {
        return Err(failed("Cannot project across compaction in empty session"));
    }
    let boundary = locate_boundary(events, resolve_boundary_index(step))?;
    let event = require_event(events, boundary)?;
    if event_kind(event)?.as_deref() != Some("compaction_boundary") {
        return Err(failed(format!(
            "Event at index {boundary} is not a compaction_boundary"
        )));
    }
    let dropped = _find_torn_compaction_dropped_indices(events, try_i64(boundary)?)?;
    let out = copy_kept_usize(events, &dropped)?;
    Ok((
        out,
        LossDelta::one("projected-orphans", try_count(dropped.len())?),
    ))
}

/// Python: `apply_torn_compaction_project`.
///
/// # Errors
///
/// See [`apply_torn_compaction_project_with_loss`]. This function does not
/// panic.
pub fn apply_torn_compaction_project(
    events: &[EventValue],
    step: &SalvageStep,
) -> Result<Vec<EventMapping>, SalvageError> {
    Ok(apply_torn_compaction_project_with_loss(events, step)?.0)
}

/// Keep the prefix before the first unsafe tool event.
///
/// Python: `apply_side_effect_unknown_truncate_with_loss`. An empty session is
/// refused before the cut is read. `first_unsafe_index or cut_index` uses
/// Python truthiness: `0`, `False`, `0.0`, and `""` fall through. A bool cut
/// is not a slice bound. `False` uses the pin's empty-root message. `True`
/// uses the pin's out-of-bounds message when `len <= 1`, and is refused when
/// the pin would slice. The prefix is copied with
/// [`copy_events_as_dicts`](model::events::copy_events_as_dicts). The input
/// slice is not mutated.
///
/// # Errors
///
/// Returns [`SalvageError::Precondition`] for an empty session, a missing cut,
/// `cut <= 0`, an out-of-range cut, or a bool the pin would use as a slice.
/// Returns [`SalvageError::Event`] when the prefix copy fails or a float cut
/// would be rendered with `str(float)`. Returns [`SalvageError::Type`] for an
/// unordered cut or an in-range float slice. This function does not panic,
/// and it does not return `Ok` on those failures.
pub fn apply_side_effect_unknown_truncate_with_loss(
    events: &[EventValue],
    step: &SalvageStep,
) -> Result<(Vec<EventMapping>, LossDelta), SalvageError> {
    if events.is_empty() {
        return Err(failed("Cannot truncate an empty session"));
    }
    let cut = accept_cut(resolve_cut(step), events.len())?;
    let out = copy_events_as_dicts(&events[..cut])?;
    let dropped = try_count(events.len() - cut)?;
    Ok((out, LossDelta::one("truncated-side-effects", dropped)))
}

/// Python: `apply_side_effect_unknown_truncate`.
///
/// # Errors
///
/// See [`apply_side_effect_unknown_truncate_with_loss`]. This function does
/// not panic.
pub fn apply_side_effect_unknown_truncate(
    events: &[EventValue],
    step: &SalvageStep,
) -> Result<Vec<EventMapping>, SalvageError> {
    Ok(apply_side_effect_unknown_truncate_with_loss(events, step)?.0)
}

/// Resolve one orphan `tool_result` index, or `None` when it is ambiguous.
///
/// Python: `_resolve_orphan_target_index`. Identity keys are tried in order
/// `result_id`, `event_id`, `record_id`. A unique `correlation_id` is next.
/// A bool, float, or other `target_index` returns `None` and does not scan
/// orphans. A real int is returned even when it is out of range. The input
/// slice is not mutated.
///
/// # Errors
///
/// Returns [`SalvageError::Event`] when `str()` of a param or an event read
/// fails. This function does not panic. `Ok(None)` is an unresolved target,
/// not a repaired session.
pub fn _resolve_orphan_target_index(
    events: &[EventValue],
    step: &SalvageStep,
) -> Result<Option<i64>, SalvageError> {
    if let ParamMap::Mapping(mapping) = &step.params {
        if let Some(found) = find_param_id(events, mapping)? {
            return Ok(Some(found));
        }
        if let Some(found) = find_param_corr(events, mapping)? {
            return Ok(Some(found));
        }
    }
    finish_resolve(events, step.target_index)
}

/// Indexes of `tool_result` events whose correlation has no tool call.
///
/// Python: `_find_orphan_result_indices`. Kind is read before correlation.
/// A non-call does not read correlation. `None` correlation is an orphan.
/// `""` is a real correlation. The input slice is not mutated.
///
/// # Errors
///
/// Returns [`SalvageError::Event`] when a required kind or correlation read
/// fails. This function does not panic.
pub fn _find_orphan_result_indices(events: &[EventValue]) -> Result<Vec<i64>, SalvageError> {
    let mut call_corrs = BTreeSet::new();
    for event in events {
        if is_call_kind(event_kind(event)?.as_deref()) {
            if let Some(corr) = event_corr_id(event)? {
                call_corrs.insert(corr);
            }
        }
    }
    let mut orphans = Vec::new();
    for (index, event) in events.iter().enumerate() {
        if event_kind(event)?.as_deref() != Some("tool_result") {
            continue;
        }
        let corr = event_corr_id(event)?;
        let orphan = match &corr {
            None => true,
            Some(value) => !call_corrs.contains(value),
        };
        if orphan {
            orphans.push(try_i64(index)?);
        }
    }
    Ok(orphans)
}

/// Fail closed unless `events[index]` is a droppable orphan result.
///
/// Python: `_validate_orphan_target`. Bounds are checked before any event
/// read. Kind is read before correlation. `str(correlation_id)` runs only
/// when both sides are not `None`. Call kinds are read before their
/// correlation. A matching call is refused before the target id is read.
/// An empty id does not scan children. The input slice is not mutated.
/// `Ok(())` means the target passed these checks. It is not a dropped list.
///
/// # Errors
///
/// Returns [`SalvageError::Precondition`] for a bad index, a non-result, a
/// correlation mismatch, a matching call, or a child. Returns
/// [`SalvageError::Event`] when a required read or `str()` fails. This
/// function does not panic, and it does not return `Ok` on those failures.
pub fn _validate_orphan_target(
    events: &[EventValue],
    index: i64,
    step: &SalvageStep,
) -> Result<(), SalvageError> {
    let Some(position) = try_usize(index, events.len()) else {
        return Err(failed(format!(
            "orphan-result-drop: invalid target index {index}"
        )));
    };
    let target = require_event(events, position)?;
    if event_kind(target)?.as_deref() != Some("tool_result") {
        return Err(failed(format!(
            "orphan-result-drop: event at index {index} is not a tool_result"
        )));
    }
    let corr = event_corr_id(target)?;
    if params_truthy(&step.params) {
        reject_corr_mismatch(&step.params, corr.as_deref())?;
    }
    if let Some(corr) = corr.as_deref() {
        reject_matching_call(events, index, corr)?;
    }
    let target_id = event_id(target)?;
    if let Some(target_id) = target_id.as_deref().filter(|value| !value.is_empty()) {
        reject_children(events, target_id)?;
    }
    Ok(())
}

fn failed(message: impl Into<String>) -> SalvageError {
    SalvageError::Precondition(PreconditionFailed::new(message))
}

fn try_i64(index: usize) -> Result<i64, SalvageError> {
    i64::try_from(index).map_err(|_| failed("event index does not fit in a signed integer"))
}

fn try_count(count: usize) -> Result<i64, SalvageError> {
    i64::try_from(count).map_err(|_| failed("loss count does not fit in a signed integer"))
}

fn try_usize(index: i64, len: usize) -> Option<usize> {
    if index < 0 {
        return None;
    }
    let index = usize::try_from(index).ok()?;
    if index < len {
        Some(index)
    } else {
        None
    }
}

fn require_event(events: &[EventValue], index: usize) -> Result<&EventValue, SalvageError> {
    events
        .get(index)
        .ok_or_else(|| SalvageError::Type(IndexTypeError::new("list index out of range")))
}

fn event_at_i64(events: &[EventValue], index: i64) -> Result<&EventValue, SalvageError> {
    let Some(position) = try_usize(index, events.len()) else {
        return Err(SalvageError::Type(IndexTypeError::new(
            "list index out of range",
        )));
    };
    require_event(events, position)
}

fn params_truthy(params: &ParamMap) -> bool {
    match params {
        ParamMap::Mapping(mapping) => !mapping.entries().is_empty(),
        ParamMap::NotMapping => false,
    }
}

fn param<'a>(params: &'a ParamMap, key: &str) -> Option<&'a EventField> {
    match params {
        ParamMap::Mapping(mapping) => mapping.get(key),
        ParamMap::NotMapping => None,
    }
}

fn py_truthy(field: &EventField) -> bool {
    match field {
        EventField::Null => false,
        EventField::Bool(flag) => *flag,
        EventField::Int(number) => *number != 0,
        EventField::Float(number) => *number != 0.0,
        EventField::Str(text) => !text.is_empty(),
        EventField::List(items) => !items.is_empty(),
        EventField::Mapping(mapping) => !mapping.entries().is_empty(),
    }
}

fn python_or<'a>(
    first: Option<&'a EventField>,
    second: Option<&'a EventField>,
) -> Option<&'a EventField> {
    if let Some(value) = first {
        if py_truthy(value) {
            return Some(value);
        }
    }
    second
}

fn python_str(field: &EventField) -> Result<String, SalvageError> {
    match field {
        EventField::Null => Ok("None".to_owned()),
        EventField::Bool(true) => Ok("True".to_owned()),
        EventField::Bool(false) => Ok("False".to_owned()),
        EventField::Int(number) => Ok(number.to_string()),
        EventField::Str(text) => Ok(text.clone()),
        EventField::Float(_) => Err(EventError::PythonFloatStr.into()),
        EventField::List(_) | EventField::Mapping(_) => Err(EventError::PythonStr.into()),
    }
}

fn repr_bool(value: bool) -> &'static str {
    if value {
        "True"
    } else {
        "False"
    }
}

fn resolved_from(index: IndexValue) -> Resolved {
    match index {
        IndexValue::None => Resolved::Missing,
        IndexValue::Int(value) => Resolved::Int(value),
        IndexValue::Bool(value) => Resolved::Bool(value),
        IndexValue::Float(bits) => Resolved::Float(f64::from_bits(bits)),
        IndexValue::Other(type_name) => Resolved::Unorderable(type_name),
    }
}

fn field_as_resolved(field: &EventField) -> Resolved {
    match field {
        EventField::Null => Resolved::Missing,
        EventField::Int(index) => Resolved::Int(*index),
        EventField::Bool(value) => Resolved::Bool(*value),
        EventField::Float(number) => Resolved::Float(*number),
        EventField::Str(_) => Resolved::Unorderable("str"),
        EventField::List(_) => Resolved::Unorderable("list"),
        EventField::Mapping(_) => Resolved::Unorderable("dict"),
    }
}

fn is_call_kind(kind: Option<&str>) -> bool {
    kind.is_some_and(|value| CALL_KINDS.contains(&value))
}

fn comparison_type(type_name: &str, operator: &str) -> SalvageError {
    SalvageError::Type(IndexTypeError::new(format!(
        "'{operator}' not supported between instances of '{type_name}' and 'int'"
    )))
}

fn list_index_float() -> SalvageError {
    SalvageError::Type(IndexTypeError::new(
        "list indices must be integers or slices, not float",
    ))
}

fn slice_index_type() -> SalvageError {
    SalvageError::Type(IndexTypeError::new(
        "slice indices must be integers or None or have an __index__ method",
    ))
}

fn invalid_amputate(shown: &str) -> SalvageError {
    failed(format!("Invalid target_index {shown} for amputation"))
}

fn invalid_boundary(shown: &str) -> SalvageError {
    failed(format!("Invalid compaction boundary index {shown}"))
}

/// Python range of a bool without using it as an index.
///
/// `False` is in range when `len > 0`. `True` is in range when `len > 1`.
fn bool_in_range(value: bool, len: usize) -> bool {
    match value {
        false => len > 0,
        true => len > 1,
    }
}

fn exact_len_f64(len: usize) -> Option<f64> {
    let number = len as f64;
    if number.is_finite() && number >= 0.0 && number as usize == len {
        Some(number)
    } else {
        None
    }
}

fn float_place(number: f64, len: usize) -> Result<FloatPlace, SalvageError> {
    if number < 0.0 {
        return Ok(FloatPlace::Before);
    }
    let Some(len_f) = exact_len_f64(len) else {
        return Err(failed("session length cannot be compared with a float"));
    };
    if number >= len_f {
        Ok(FloatPlace::After)
    } else {
        Ok(FloatPlace::Inside)
    }
}

fn resolve_amputate_seed(
    events: &[EventValue],
    step: &SalvageStep,
) -> Result<Resolved, SalvageError> {
    if !matches!(step.target_index, IndexValue::None) {
        return Ok(resolved_from(step.target_index));
    }
    if !params_truthy(&step.params) {
        return Ok(Resolved::Missing);
    }
    let Some(anchor) = python_or(
        param(&step.params, "root_id"),
        param(&step.params, "record_id"),
    ) else {
        return Ok(Resolved::Missing);
    };
    if matches!(anchor, EventField::Null) {
        return Ok(Resolved::Missing);
    }
    let wanted = python_str(anchor)?;
    for (index, event) in events.iter().enumerate() {
        if event_id(event)?.as_deref() == Some(wanted.as_str()) {
            return Ok(Resolved::Int(try_i64(index)?));
        }
    }
    Ok(Resolved::Missing)
}

fn accept_amputate_index(resolved: Resolved, len: usize) -> Result<i64, SalvageError> {
    match resolved {
        Resolved::Missing => Err(invalid_amputate("None")),
        Resolved::Int(index) => {
            if try_usize(index, len).is_some() {
                Ok(index)
            } else {
                Err(invalid_amputate(&index.to_string()))
            }
        }
        Resolved::Bool(value) => Err(invalid_amputate(repr_bool(value))),
        Resolved::Float(number) => match float_place(number, len)? {
            FloatPlace::Inside => Err(list_index_float()),
            FloatPlace::Before | FloatPlace::After => Err(EventError::PythonFloatStr.into()),
        },
        Resolved::Unorderable(type_name) => Err(comparison_type(type_name, "<")),
    }
}

fn copy_kept_i64(
    events: &[EventValue],
    dropped: &BTreeSet<i64>,
) -> Result<Vec<EventMapping>, SalvageError> {
    let mut out = Vec::new();
    for (index, event) in events.iter().enumerate() {
        if !dropped.contains(&try_i64(index)?) {
            out.push(to_event_dict(event)?);
        }
    }
    Ok(out)
}

fn resolve_boundary_index(step: &SalvageStep) -> Resolved {
    if !matches!(step.target_index, IndexValue::None) {
        return resolved_from(step.target_index);
    }
    if !params_truthy(&step.params) {
        return Resolved::Missing;
    }
    match param(&step.params, "boundary_index") {
        Some(field) => field_as_resolved(field),
        None => Resolved::Missing,
    }
}

fn locate_boundary(events: &[EventValue], resolved: Resolved) -> Result<usize, SalvageError> {
    match boundary_range(resolved, events.len())? {
        RangeStatus::Ready(index) => Ok(index),
        RangeStatus::Refuse(error) => Err(error),
        RangeStatus::NeedsFallback { failure } => match unique_boundary(events)? {
            Some(index) => Ok(index),
            None => Err(failure),
        },
    }
}

fn boundary_range(resolved: Resolved, len: usize) -> Result<RangeStatus, SalvageError> {
    match resolved {
        Resolved::Missing => Ok(RangeStatus::NeedsFallback {
            failure: invalid_boundary("None"),
        }),
        Resolved::Int(index) => {
            if let Some(position) = try_usize(index, len) {
                Ok(RangeStatus::Ready(position))
            } else {
                Ok(RangeStatus::NeedsFallback {
                    failure: invalid_boundary(&index.to_string()),
                })
            }
        }
        Resolved::Bool(value) => {
            let failure = invalid_boundary(repr_bool(value));
            if bool_in_range(value, len) {
                Ok(RangeStatus::Refuse(failure))
            } else {
                Ok(RangeStatus::NeedsFallback { failure })
            }
        }
        Resolved::Float(number) => match float_place(number, len)? {
            FloatPlace::Inside => Ok(RangeStatus::Refuse(list_index_float())),
            FloatPlace::Before | FloatPlace::After => Ok(RangeStatus::NeedsFallback {
                failure: EventError::PythonFloatStr.into(),
            }),
        },
        Resolved::Unorderable(type_name) => {
            Ok(RangeStatus::Refuse(comparison_type(type_name, "<")))
        }
    }
}

fn unique_boundary(events: &[EventValue]) -> Result<Option<usize>, SalvageError> {
    let mut found = Vec::new();
    for (index, event) in events.iter().enumerate() {
        if event_kind(event)?.as_deref() == Some("compaction_boundary") {
            found.push(index);
        }
    }
    if found.len() == 1 {
        Ok(found.first().copied())
    } else {
        Ok(None)
    }
}

fn copy_kept_usize(
    events: &[EventValue],
    dropped: &BTreeSet<usize>,
) -> Result<Vec<EventMapping>, SalvageError> {
    let mut out = Vec::new();
    for (index, event) in events.iter().enumerate() {
        if !dropped.contains(&index) {
            out.push(to_event_dict(event)?);
        }
    }
    Ok(out)
}

fn resolve_cut(step: &SalvageStep) -> Resolved {
    if !matches!(step.target_index, IndexValue::None) {
        return resolved_from(step.target_index);
    }
    if !params_truthy(&step.params) {
        return Resolved::Missing;
    }
    match python_or(
        param(&step.params, "first_unsafe_index"),
        param(&step.params, "cut_index"),
    ) {
        Some(field) => field_as_resolved(field),
        None => Resolved::Missing,
    }
}

fn accept_cut(resolved: Resolved, len: usize) -> Result<usize, SalvageError> {
    match resolved {
        Resolved::Missing => Err(failed("Truncate recipe requires a valid target_index")),
        Resolved::Int(cut) => accept_int_cut(cut, len),
        Resolved::Bool(false) => Err(failed(
            "Cannot truncate at index False: would empty or violate session root",
        )),
        Resolved::Bool(true) => {
            if len <= 1 {
                Err(failed(format!(
                    "Cut index True is out of bounds for session of length {len}"
                )))
            } else {
                Err(failed("Cannot truncate at index True: bool is not an int"))
            }
        }
        Resolved::Float(number) => {
            if number <= 0.0 {
                return Err(EventError::PythonFloatStr.into());
            }
            match float_place(number, len)? {
                FloatPlace::Before | FloatPlace::After => Err(EventError::PythonFloatStr.into()),
                FloatPlace::Inside => Err(slice_index_type()),
            }
        }
        Resolved::Unorderable(type_name) => Err(comparison_type(type_name, "<=")),
    }
}

fn accept_int_cut(cut: i64, len: usize) -> Result<usize, SalvageError> {
    if cut <= 0 {
        return Err(failed(format!(
            "Cannot truncate at index {cut}: would empty or violate session root"
        )));
    }
    let Some(position) = try_usize(cut, len) else {
        return Err(failed(format!(
            "Cut index {cut} is out of bounds for session of length {len}"
        )));
    };
    Ok(position)
}

fn find_param_id(
    events: &[EventValue],
    mapping: &EventMapping,
) -> Result<Option<i64>, SalvageError> {
    for key in ["result_id", "event_id", "record_id"] {
        let Some(rid) = mapping.get(key) else {
            continue;
        };
        if matches!(rid, EventField::Null) {
            continue;
        }
        let wanted = python_str(rid)?;
        for (index, event) in events.iter().enumerate() {
            if event_id(event)?.as_deref() == Some(wanted.as_str()) {
                return Ok(Some(try_i64(index)?));
            }
        }
    }
    Ok(None)
}

fn find_param_corr(
    events: &[EventValue],
    mapping: &EventMapping,
) -> Result<Option<i64>, SalvageError> {
    let Some(corr) = mapping.get("correlation_id") else {
        return Ok(None);
    };
    if matches!(corr, EventField::Null) {
        return Ok(None);
    }
    let wanted = python_str(corr)?;
    let mut found = Vec::new();
    for (index, event) in events.iter().enumerate() {
        if event_kind(event)?.as_deref() != Some("tool_result") {
            continue;
        }
        if event_corr_id(event)?.as_deref() == Some(wanted.as_str()) {
            found.push(index);
        }
    }
    if found.len() == 1 {
        Ok(Some(try_i64(found[0])?))
    } else {
        Ok(None)
    }
}

fn finish_resolve(events: &[EventValue], target: IndexValue) -> Result<Option<i64>, SalvageError> {
    match target {
        IndexValue::Int(index) => Ok(Some(index)),
        IndexValue::None => {
            let orphans = _find_orphan_result_indices(events)?;
            if orphans.len() == 1 {
                Ok(orphans.first().copied())
            } else {
                Ok(None)
            }
        }
        IndexValue::Bool(_) | IndexValue::Float(_) | IndexValue::Other(_) => Ok(None),
    }
}

fn reject_corr_mismatch(params: &ParamMap, corr: Option<&str>) -> Result<(), SalvageError> {
    let Some(p_corr) = param(params, "correlation_id") else {
        return Ok(());
    };
    if matches!(p_corr, EventField::Null) {
        return Ok(());
    }
    let Some(corr) = corr else {
        return Ok(());
    };
    if python_str(p_corr)? != corr {
        return Err(failed(
            "orphan-result-drop: target correlation does not match finding evidence",
        ));
    }
    Ok(())
}

fn reject_matching_call(events: &[EventValue], index: i64, corr: &str) -> Result<(), SalvageError> {
    for event in events {
        let kind = event_kind(event)?;
        if is_call_kind(kind.as_deref()) && event_corr_id(event)?.as_deref() == Some(corr) {
            return Err(failed(format!(
                "orphan-result-drop: result at index {index} is not an orphan (a matching tool call exists)"
            )));
        }
    }
    Ok(())
}

fn reject_children(events: &[EventValue], target_id: &str) -> Result<(), SalvageError> {
    for event in events {
        if event_parent_id(event)?.as_deref() == Some(target_id) {
            return Err(failed(
                "orphan-result-drop: result has dependent child events; dropping it would create missing parents",
            ));
        }
    }
    Ok(())
}

enum Resolved {
    Missing,
    Int(i64),
    Bool(bool),
    Float(f64),
    Unorderable(&'static str),
}

enum FloatPlace {
    Before,
    Inside,
    After,
}

enum RangeStatus {
    Ready(usize),
    NeedsFallback { failure: SalvageError },
    Refuse(SalvageError),
}

#[cfg(test)]
mod tests {
    use model::canonical::{SessionEvent, NORMALIZE_CANONICAL_UNAVAILABLE};
    use model::events::{
        EventField, EventMapping, EventValue, PYTHON_FLOAT_STR_UNREPRESENTABLE,
        PYTHON_STR_UNREPRESENTABLE,
    };

    use super::{
        _find_orphan_result_indices, _resolve_orphan_target_index, _validate_orphan_target,
        apply_side_effect_unknown_truncate, apply_side_effect_unknown_truncate_with_loss,
        apply_torn_compaction_project, apply_torn_compaction_project_with_loss,
        apply_unresolvable_branch_amputate, apply_unresolvable_branch_amputate_with_loss,
        IndexValue, LossDelta, ParamMap, SalvageError, SalvageStep, MAX_COMPONENT_SIZE,
    };

    fn text(value: impl Into<String>) -> EventField {
        EventField::Str(value.into())
    }

    fn mapping(entries: Vec<(&str, EventField)>) -> EventMapping {
        EventMapping::new(
            entries
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        )
    }

    fn ev(entries: Vec<(&str, EventField)>) -> EventValue {
        EventValue::Mapping(mapping(entries))
    }

    fn message(id: &str, parent: Option<&str>) -> EventValue {
        let mut entries = vec![("kind", text("message")), ("id", text(id))];
        if let Some(parent) = parent {
            entries.push(("parent_id", text(parent)));
        }
        ev(entries)
    }

    fn kind_id(kind: &str, id: &str, parent: Option<&str>) -> EventValue {
        let mut entries = vec![("kind", text(kind)), ("id", text(id))];
        if let Some(parent) = parent {
            entries.push(("parent_id", text(parent)));
        }
        ev(entries)
    }

    fn tool(kind: &str, id: &str, corr: Option<&str>, parent: Option<&str>) -> EventValue {
        let mut entries = vec![("kind", text(kind)), ("id", text(id))];
        if let Some(corr) = corr {
            entries.push(("correlation_id", text(corr)));
        }
        if let Some(parent) = parent {
            entries.push(("parent_id", text(parent)));
        }
        ev(entries)
    }

    fn no_params() -> ParamMap {
        ParamMap::Mapping(EventMapping::new(Vec::new()))
    }

    fn params(entries: Vec<(&str, EventField)>) -> ParamMap {
        ParamMap::Mapping(mapping(entries))
    }

    fn step(index: IndexValue, params: ParamMap) -> SalvageStep {
        SalvageStep {
            target_index: index,
            params,
        }
    }

    fn at(index: i64) -> SalvageStep {
        step(IndexValue::Int(index), no_params())
    }

    fn entries_of(events: &[EventValue]) -> Vec<Vec<(String, EventField)>> {
        events
            .iter()
            .map(|event| match event {
                EventValue::Mapping(mapping) => mapping.entries().to_vec(),
                EventValue::Session(_) | EventValue::Other => Vec::new(),
            })
            .collect()
    }

    fn ids(events: &[EventMapping]) -> Vec<String> {
        events
            .iter()
            .map(|event| match event.get("id") {
                Some(EventField::Str(value)) => value.clone(),
                _ => String::new(),
            })
            .collect()
    }

    fn loss_pair(loss: &LossDelta) -> (String, i64) {
        let entry = loss.entries().first().expect("one loss class");
        assert_eq!(loss.entries().len(), 1);
        entry.clone()
    }

    fn assert_precondition(error: SalvageError, message: &str) {
        match error {
            SalvageError::Precondition(error) => assert_eq!(error.to_string(), message),
            other => panic!("expected PreconditionFailed, got {other}"),
        }
    }

    fn chain(len: usize) -> Vec<EventValue> {
        let mut events = Vec::with_capacity(len);
        for index in 0..len {
            let id = format!("evt-{index}");
            let mut entries = vec![("kind", text("message")), ("id", text(id))];
            if index > 0 {
                entries.push(("parent_id", text(format!("evt-{}", index - 1))));
            }
            events.push(ev(entries));
        }
        events
    }

    fn projection() -> Vec<EventValue> {
        vec![
            tool("tool_call", "evt-call", Some("corr-synthetic"), None),
            kind_id("compaction_boundary", "evt-boundary", Some("evt-call")),
            tool(
                "tool_result",
                "evt-result",
                Some("corr-synthetic"),
                Some("evt-call"),
            ),
        ]
    }

    #[test]
    fn amputate_refuses_empty_bad_index_checkpoint_entire_session_and_size() {
        let empty: Vec<EventValue> = Vec::new();
        let error = apply_unresolvable_branch_amputate(&empty, &at(0))
            .expect_err("empty session is refused");
        assert_precondition(error, "Cannot amputate an empty session");
        let error = apply_unresolvable_branch_amputate_with_loss(
            &empty,
            &step(IndexValue::Bool(true), no_params()),
        )
        .expect_err("empty wins over a bool index");
        assert_precondition(error, "Cannot amputate an empty session");

        let events = vec![message("evt-root", None)];
        let before = entries_of(&events);
        let error =
            apply_unresolvable_branch_amputate(&events, &at(99)).expect_err("99 is out of range");
        assert_precondition(error, "Invalid target_index 99 for amputation");
        let error = apply_unresolvable_branch_amputate(&events, &at(-1))
            .expect_err("negative is out of range");
        assert_precondition(error, "Invalid target_index -1 for amputation");
        let error =
            apply_unresolvable_branch_amputate(&events, &step(IndexValue::None, no_params()))
                .expect_err("missing index");
        assert_precondition(error, "Invalid target_index None for amputation");
        let error = apply_unresolvable_branch_amputate(&events, &at(0))
            .expect_err("one event is the whole session");
        assert_precondition(error, "Amputating entire session is forbidden");
        assert_eq!(entries_of(&events), before);

        let branched = vec![
            kind_id("checkpoint", "evt-cp", None),
            message("evt-child", Some("evt-cp")),
            message("evt-keep", None),
        ];
        let error = apply_unresolvable_branch_amputate(&branched, &at(1))
            .expect_err("checkpoint blocks amputation");
        assert_precondition(error, "Branch contains a checkpoint; cannot amputate");

        let huge = chain(MAX_COMPONENT_SIZE + 1);
        let error = apply_unresolvable_branch_amputate_with_loss(&huge, &at(0))
            .expect_err("oversized component is refused before the entire-session check");
        assert_precondition(
            error,
            &format!(
                "Component size ({}) exceeds limit of {MAX_COMPONENT_SIZE}",
                MAX_COMPONENT_SIZE + 1
            ),
        );
    }

    #[test]
    fn amputate_copies_events_outside_the_component() {
        let events = vec![
            message("evt-keep", None),
            message("evt-root", None),
            message("evt-leaf", Some("evt-root")),
            kind_id("checkpoint", "evt-cp", None),
        ];
        let before = entries_of(&events);
        let (out, loss) = apply_unresolvable_branch_amputate_with_loss(&events, &at(1))
            .expect("mapping component is copied");
        assert_eq!(ids(&out), ["evt-keep", "evt-cp"]);
        assert_eq!(loss_pair(&loss), ("amputated-branch".to_owned(), 2));
        assert_eq!(out[0].entries(), entries_of(&events)[0].as_slice());
        let listed = apply_unresolvable_branch_amputate(&events, &at(1))
            .expect("wrapper returns the copied list");
        assert_eq!(ids(&listed), ["evt-keep", "evt-cp"]);
        assert_eq!(entries_of(&events), before);

        let by_id = step(
            IndexValue::None,
            params(vec![("root_id", text("evt-leaf"))]),
        );
        let (out, loss) = apply_unresolvable_branch_amputate_with_loss(&events, &by_id)
            .expect("root_id selects the leaf component");
        assert_eq!(ids(&out), ["evt-keep", "evt-cp"]);
        assert_eq!(loss_pair(&loss), ("amputated-branch".to_owned(), 2));

        let explicit = step(
            IndexValue::Int(0),
            params(vec![("root_id", text("evt-root"))]),
        );
        let (out, _) = apply_unresolvable_branch_amputate_with_loss(&events, &explicit)
            .expect("an int target ignores root_id");
        assert_eq!(ids(&out), ["evt-root", "evt-leaf", "evt-cp"]);
    }

    #[test]
    fn amputate_bool_is_not_an_index_and_str_of_bool_is_true() {
        let events = vec![
            message("evt-a", None),
            message("evt-b", None),
            message("evt-c", None),
        ];
        let error =
            apply_unresolvable_branch_amputate(&events, &step(IndexValue::Bool(true), no_params()))
                .expect_err("True is not index 1");
        assert_precondition(error, "Invalid target_index True for amputation");
        let error = apply_unresolvable_branch_amputate(
            &events,
            &step(IndexValue::Bool(false), no_params()),
        )
        .expect_err("False is not index 0");
        assert_precondition(error, "Invalid target_index False for amputation");

        let named = vec![
            ev(vec![
                ("kind", text("message")),
                ("id", EventField::Bool(true)),
            ]),
            message("evt-keep", None),
        ];
        let (out, loss) = apply_unresolvable_branch_amputate_with_loss(
            &named,
            &step(
                IndexValue::None,
                params(vec![("root_id", EventField::Bool(true))]),
            ),
        )
        .expect("str(True) matches id True and not index 1");
        assert_eq!(ids(&out), ["evt-keep"]);
        assert_eq!(loss_pair(&loss), ("amputated-branch".to_owned(), 1));

        let error = apply_unresolvable_branch_amputate(
            &named,
            &step(
                IndexValue::None,
                params(vec![("root_id", EventField::Int(1))]),
            ),
        )
        .expect_err("str(1) does not match id True");
        assert_precondition(error, "Invalid target_index None for amputation");

        let zero = vec![message("0", None), message("evt-keep", None)];
        let (out, loss) = apply_unresolvable_branch_amputate_with_loss(
            &zero,
            &step(
                IndexValue::None,
                params(vec![("record_id", EventField::Int(0))]),
            ),
        )
        .expect("falsy record_id 0 is still an id string");
        assert_eq!(ids(&out), ["evt-keep"]);
        assert_eq!(loss_pair(&loss), ("amputated-branch".to_owned(), 1));

        let (out, _) = apply_unresolvable_branch_amputate_with_loss(
            &zero,
            &step(
                IndexValue::None,
                params(vec![
                    ("root_id", EventField::Float(0.0)),
                    ("record_id", text("0")),
                ]),
            ),
        )
        .expect("falsy 0.0 falls through to record_id");
        assert_eq!(ids(&out), ["evt-keep"]);
    }

    #[test]
    fn amputate_event_errors_and_copy_seam_are_not_ok() {
        let float_id = vec![ev(vec![
            ("kind", text("message")),
            ("id", EventField::Float(1.5)),
        ])];
        let error = apply_unresolvable_branch_amputate(&float_id, &at(99))
            .expect_err("out of range returns before id reads");
        assert_precondition(error, "Invalid target_index 99 for amputation");

        let error = apply_unresolvable_branch_amputate_with_loss(&float_id, &at(0))
            .expect_err("component id read fails");
        assert_eq!(error.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);

        let ordered = vec![
            kind_id("checkpoint", "evt-cp", None),
            ev(vec![
                ("kind", EventField::Float(1.5)),
                ("id", text("evt-float")),
                ("parent_id", text("evt-cp")),
            ]),
        ];
        let error = apply_unresolvable_branch_amputate(&ordered, &at(0))
            .expect_err("checkpoint is seen before the neighbor kind");
        assert_precondition(error, "Branch contains a checkpoint; cannot amputate");
        let error = apply_unresolvable_branch_amputate(&ordered, &at(1))
            .expect_err("seed kind is read before the checkpoint neighbor");
        assert_eq!(error.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);

        let wide = vec![message("evt-a", None), message("evt-b", None)];
        let error = apply_unresolvable_branch_amputate(
            &wide,
            &step(IndexValue::Float(1.5f64.to_bits()), no_params()),
        )
        .expect_err("in-range float is not an index");
        assert_eq!(
            error.to_string(),
            "list indices must be integers or slices, not float"
        );
        let error = apply_unresolvable_branch_amputate(
            &wide,
            &step(IndexValue::Float(99.0f64.to_bits()), no_params()),
        )
        .expect_err("out-of-range float is not rendered");
        assert_eq!(error.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        let error =
            apply_unresolvable_branch_amputate(&wide, &step(IndexValue::Other("str"), no_params()))
                .expect_err("a string index cannot be ordered");
        assert_eq!(
            error.to_string(),
            "'<' not supported between instances of 'str' and 'int'"
        );

        let mut kept = SessionEvent::new(
            "evt-keep",
            None,
            0,
            "2026-01-01T00:00:00Z",
            "synthetic",
            "message",
        );
        kept.correlation_id = None;
        let mixed = vec![EventValue::from_session(kept), message("evt-branch", None)];
        let error = apply_unresolvable_branch_amputate_with_loss(&mixed, &at(1))
            .expect_err("copying a SessionEvent stops");
        assert_eq!(error.to_string(), NORMALIZE_CANONICAL_UNAVAILABLE);
        assert!(matches!(error, SalvageError::Event(_)));

        let mut dropped = SessionEvent::new(
            "evt-branch",
            None,
            0,
            "2026-01-01T00:00:00Z",
            "synthetic",
            "message",
        );
        dropped.correlation_id = None;
        let mixed = vec![message("evt-keep", None), EventValue::from_session(dropped)];
        let (out, loss) = apply_unresolvable_branch_amputate_with_loss(&mixed, &at(1))
            .expect("a dropped SessionEvent is not copied");
        assert_eq!(ids(&out), ["evt-keep"]);
        assert_eq!(loss_pair(&loss), ("amputated-branch".to_owned(), 1));
    }

    #[test]
    fn torn_projects_mappings_and_refuses_bad_boundaries() {
        let empty: Vec<EventValue> = Vec::new();
        let error =
            apply_torn_compaction_project(&empty, &at(0)).expect_err("empty session is refused");
        assert_precondition(error, "Cannot project across compaction in empty session");

        let message_only = vec![message("evt-note", None)];
        let error = apply_torn_compaction_project(&message_only, &at(0))
            .expect_err("a message is not a boundary");
        assert_precondition(error, "Event at index 0 is not a compaction_boundary");

        let bare = vec![
            message("evt-note", None),
            kind_id("compaction_boundary", "evt-boundary", Some("evt-note")),
        ];
        let error = apply_torn_compaction_project(&bare, &at(1))
            .expect_err("a boundary with no split is refused");
        assert_precondition(
            error,
            "Compaction boundary at index 1 has no split pairs or orphaned halves",
        );

        let events = projection();
        let before = entries_of(&events);
        let (out, loss) = apply_torn_compaction_project_with_loss(&events, &at(1))
            .expect("tie keeps the leading call");
        assert_eq!(ids(&out), ["evt-call"]);
        assert_eq!(loss_pair(&loss), ("projected-orphans".to_owned(), 2));
        assert_eq!(out[0].entries(), entries_of(&events)[0].as_slice());
        let listed = apply_torn_compaction_project(&events, &at(1)).expect("wrapper copies");
        assert_eq!(ids(&listed), ["evt-call"]);
        assert_eq!(entries_of(&events), before);

        let (out, _) = apply_torn_compaction_project_with_loss(&events, &at(99))
            .expect("one boundary replaces an out-of-range index");
        assert_eq!(ids(&out), ["evt-call"]);
        let (out, _) =
            apply_torn_compaction_project_with_loss(&events, &step(IndexValue::None, no_params()))
                .expect("a missing index uses the only boundary");
        assert_eq!(ids(&out), ["evt-call"]);

        let two = vec![
            kind_id("compaction_boundary", "evt-a", None),
            kind_id("compaction_boundary", "evt-b", None),
        ];
        let error =
            apply_torn_compaction_project(&two, &at(50)).expect_err("two boundaries do not guess");
        assert_precondition(error, "Invalid compaction boundary index 50");
        let error = apply_torn_compaction_project(&two, &step(IndexValue::None, no_params()))
            .expect_err("missing index with two boundaries");
        assert_precondition(error, "Invalid compaction boundary index None");
    }

    #[test]
    fn torn_bool_float_and_kind_errors_do_not_invent_success() {
        let events = projection();
        let error =
            apply_torn_compaction_project(&events, &step(IndexValue::Bool(true), no_params()))
                .expect_err("True is not boundary index 1");
        assert_precondition(error, "Invalid compaction boundary index True");
        let error =
            apply_torn_compaction_project(&events, &step(IndexValue::Bool(false), no_params()))
                .expect_err("False is not boundary index 0");
        assert_precondition(error, "Invalid compaction boundary index False");

        let only = vec![kind_id("compaction_boundary", "evt-boundary", None)];
        let error =
            apply_torn_compaction_project(&only, &step(IndexValue::Bool(true), no_params()))
                .expect_err("out-of-range True still searches");
        assert_precondition(
            error,
            "Compaction boundary at index 0 has no split pairs or orphaned halves",
        );

        let error = apply_torn_compaction_project(
            &events,
            &step(IndexValue::Float(0.5f64.to_bits()), no_params()),
        )
        .expect_err("an in-range float is not an index");
        assert_eq!(
            error.to_string(),
            "list indices must be integers or slices, not float"
        );
        let (out, _) = apply_torn_compaction_project_with_loss(
            &events,
            &step(
                IndexValue::None,
                params(vec![("boundary_index", EventField::Float(99.0))]),
            ),
        )
        .expect("an out-of-range float searches for one boundary");
        assert_eq!(ids(&out), ["evt-call"]);
        let notes = vec![message("evt-a", None), message("evt-b", None)];
        let error = apply_torn_compaction_project(
            &notes,
            &step(IndexValue::Float((-1.5f64).to_bits()), no_params()),
        )
        .expect_err("a failed float search is not rendered with str(float)");
        assert_eq!(error.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);

        let scanned = vec![
            kind_id("compaction_boundary", "evt-a", None),
            kind_id("compaction_boundary", "evt-b", None),
            ev(vec![("kind", EventField::Float(1.5))]),
        ];
        let error = apply_torn_compaction_project(&scanned, &at(99))
            .expect_err("kind scan finishes before the invalid-index message");
        assert_eq!(error.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);

        let float_kind = vec![
            ev(vec![("kind", EventField::Float(1.5))]),
            kind_id("compaction_boundary", "evt-boundary", None),
        ];
        let error = apply_torn_compaction_project(&float_kind, &at(1))
            .expect_err("inner kind read fails before the no-split message");
        assert_eq!(error.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);

        let mut call = SessionEvent::new(
            "evt-call",
            None,
            0,
            "2026-01-01T00:00:00Z",
            "synthetic",
            "tool_call",
        );
        call.correlation_id = Some("corr-synthetic".to_owned());
        let session_kept = vec![
            EventValue::from_session(call),
            kind_id("compaction_boundary", "evt-boundary", Some("evt-call")),
            tool(
                "tool_result",
                "evt-result",
                Some("corr-synthetic"),
                Some("evt-call"),
            ),
        ];
        let error = apply_torn_compaction_project_with_loss(&session_kept, &at(1))
            .expect_err("the kept SessionEvent is not copied");
        assert_eq!(error.to_string(), NORMALIZE_CANONICAL_UNAVAILABLE);
    }

    #[test]
    fn truncate_honors_truthiness_and_refuses_bool_slices() {
        let empty: Vec<EventValue> = Vec::new();
        let error = apply_side_effect_unknown_truncate(&empty, &at(1))
            .expect_err("empty session is refused");
        assert_precondition(error, "Cannot truncate an empty session");
        let error = apply_side_effect_unknown_truncate(
            &empty,
            &step(
                IndexValue::None,
                params(vec![("cut_index", EventField::Int(1))]),
            ),
        )
        .expect_err("empty wins over params");
        assert_precondition(error, "Cannot truncate an empty session");

        let events = vec![
            message("evt-0", None),
            message("evt-1", Some("evt-0")),
            message("evt-2", Some("evt-1")),
            message("evt-3", Some("evt-2")),
        ];
        let before = entries_of(&events);
        let error =
            apply_side_effect_unknown_truncate(&events, &step(IndexValue::None, no_params()))
                .expect_err("missing cut");
        assert_precondition(error, "Truncate recipe requires a valid target_index");
        let error =
            apply_side_effect_unknown_truncate(&events, &at(0)).expect_err("zero empties the root");
        assert_precondition(
            error,
            "Cannot truncate at index 0: would empty or violate session root",
        );
        let error = apply_side_effect_unknown_truncate(&events, &at(-2))
            .expect_err("negative empties the root");
        assert_precondition(
            error,
            "Cannot truncate at index -2: would empty or violate session root",
        );
        let error =
            apply_side_effect_unknown_truncate(&events, &at(5)).expect_err("five is past the end");
        assert_precondition(
            error,
            "Cut index 5 is out of bounds for session of length 4",
        );

        let (out, loss) = apply_side_effect_unknown_truncate_with_loss(&events, &at(2))
            .expect("prefix mappings are copied");
        assert_eq!(ids(&out), ["evt-0", "evt-1"]);
        assert_eq!(loss_pair(&loss), ("truncated-side-effects".to_owned(), 2));
        assert_eq!(out[0].entries(), entries_of(&events)[0].as_slice());
        let listed = apply_side_effect_unknown_truncate(&events, &at(2)).expect("wrapper");
        assert_eq!(ids(&listed), ["evt-0", "evt-1"]);
        assert_eq!(entries_of(&events), before);

        let (out, _) = apply_side_effect_unknown_truncate_with_loss(
            &events,
            &step(
                IndexValue::None,
                params(vec![
                    ("first_unsafe_index", EventField::Int(0)),
                    ("cut_index", EventField::Int(2)),
                ]),
            ),
        )
        .expect("falsy 0 falls through to cut_index");
        assert_eq!(ids(&out), ["evt-0", "evt-1"]);
        let (out, _) = apply_side_effect_unknown_truncate_with_loss(
            &events,
            &step(
                IndexValue::None,
                params(vec![
                    ("first_unsafe_index", EventField::Bool(false)),
                    ("cut_index", EventField::Int(2)),
                ]),
            ),
        )
        .expect("falsy False falls through and is not a slice");
        assert_eq!(ids(&out), ["evt-0", "evt-1"]);
        let error =
            apply_side_effect_unknown_truncate(&events, &step(IndexValue::Bool(true), no_params()))
                .expect_err("True is not slice bound 1");
        assert_precondition(error, "Cannot truncate at index True: bool is not an int");
        let error = apply_side_effect_unknown_truncate(
            &events[..1],
            &step(IndexValue::Bool(true), no_params()),
        )
        .expect_err("True is out of range when len is 1");
        assert_precondition(
            error,
            "Cut index True is out of bounds for session of length 1",
        );
        let error = apply_side_effect_unknown_truncate(
            &events,
            &step(IndexValue::Bool(false), no_params()),
        )
        .expect_err("False is <= 0");
        assert_precondition(
            error,
            "Cannot truncate at index False: would empty or violate session root",
        );

        let error = apply_side_effect_unknown_truncate(
            &events,
            &step(
                IndexValue::None,
                params(vec![("cut_index", text("not-an-index"))]),
            ),
        )
        .expect_err("a string cut is not ordered");
        assert_eq!(
            error.to_string(),
            "'<=' not supported between instances of 'str' and 'int'"
        );
        let error = apply_side_effect_unknown_truncate(
            &events,
            &step(IndexValue::Float(1.0f64.to_bits()), no_params()),
        )
        .expect_err("1.0 is not slice bound 1");
        assert_eq!(
            error.to_string(),
            "slice indices must be integers or None or have an __index__ method"
        );
        let error = apply_side_effect_unknown_truncate(
            &events,
            &step(IndexValue::Float((-1.5f64).to_bits()), no_params()),
        )
        .expect_err("a negative float is not rendered");
        assert_eq!(error.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);

        let mut head = SessionEvent::new(
            "evt-session",
            None,
            0,
            "2026-01-01T00:00:00Z",
            "synthetic",
            "message",
        );
        head.correlation_id = None;
        let session_prefix = vec![EventValue::from_session(head), message("evt-tail", None)];
        let error = apply_side_effect_unknown_truncate_with_loss(&session_prefix, &at(1))
            .expect_err("copying the SessionEvent prefix stops");
        assert_eq!(error.to_string(), NORMALIZE_CANONICAL_UNAVAILABLE);
        let other = vec![message("evt-0", None), EventValue::Other];
        let (out, _) = apply_side_effect_unknown_truncate_with_loss(&other, &at(1))
            .expect("a dropped Other value is not copied");
        assert_eq!(ids(&out), ["evt-0"]);
    }

    #[test]
    fn orphan_resolution_is_identity_first_and_bool_is_not_an_int() {
        let events = vec![
            message("evt-a", None),
            tool("tool_call", "evt-call", Some("corr-known"), Some("evt-a")),
            tool(
                "tool_result",
                "evt-paired",
                Some("corr-known"),
                Some("evt-call"),
            ),
            tool(
                "tool_result",
                "evt-orphan",
                Some("corr-orphan"),
                Some("evt-a"),
            ),
        ];
        let before = entries_of(&events);
        let found = _resolve_orphan_target_index(
            &events,
            &step(
                IndexValue::Int(0),
                params(vec![("result_id", text("evt-orphan"))]),
            ),
        )
        .expect("result_id wins over target_index");
        assert_eq!(found, Some(3));
        let found = _resolve_orphan_target_index(
            &events,
            &step(
                IndexValue::None,
                params(vec![
                    ("result_id", text("missing")),
                    ("event_id", text("evt-a")),
                ]),
            ),
        )
        .expect("a missing result_id falls through");
        assert_eq!(found, Some(0));
        let found = _resolve_orphan_target_index(
            &events,
            &step(
                IndexValue::Int(1),
                params(vec![("correlation_id", text("corr-orphan"))]),
            ),
        )
        .expect("a unique correlation wins over target_index");
        assert_eq!(found, Some(3));

        let two = vec![
            tool("tool_result", "evt-one", Some("corr-same"), None),
            tool("tool_result", "evt-two", Some("corr-same"), None),
        ];
        let found = _resolve_orphan_target_index(
            &two,
            &step(
                IndexValue::Int(1),
                params(vec![("correlation_id", text("corr-same"))]),
            ),
        )
        .expect("two correlation matches fall through to the int");
        assert_eq!(found, Some(1));

        let found =
            _resolve_orphan_target_index(&events, &step(IndexValue::Bool(true), no_params()))
                .expect("bool target does not scan orphans");
        assert_eq!(found, None);
        let found = _resolve_orphan_target_index(
            &events,
            &step(IndexValue::Float(1.0f64.to_bits()), no_params()),
        )
        .expect("float target is not an int");
        assert_eq!(found, None);
        let found = _resolve_orphan_target_index(&events, &step(IndexValue::Int(99), no_params()))
            .expect("an int target is returned even when it is out of range");
        assert_eq!(found, Some(99));
        let found =
            _resolve_orphan_target_index(&events, &step(IndexValue::None, ParamMap::NotMapping))
                .expect("one orphan is the fallback");
        assert_eq!(found, Some(3));
        let found = _resolve_orphan_target_index(&two, &step(IndexValue::None, no_params()))
            .expect("two orphans are ambiguous");
        assert_eq!(found, None);
        assert_eq!(entries_of(&events), before);

        let error = _resolve_orphan_target_index(
            &events,
            &step(
                IndexValue::None,
                params(vec![("result_id", EventField::Float(1.5))]),
            ),
        )
        .expect_err("str(float) fails closed");
        assert_eq!(error.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        let error = _resolve_orphan_target_index(
            &events,
            &step(
                IndexValue::None,
                params(vec![("result_id", EventField::List(vec![text("evt-a")]))]),
            ),
        )
        .expect_err("str(list) is not representable");
        assert_eq!(error.to_string(), PYTHON_STR_UNREPRESENTABLE);

        let bool_id = vec![
            ev(vec![
                ("kind", text("tool_result")),
                ("id", EventField::Bool(true)),
            ]),
            tool("tool_result", "evt-other", None, None),
        ];
        let found = _resolve_orphan_target_index(
            &bool_id,
            &step(
                IndexValue::None,
                params(vec![("result_id", EventField::Bool(true))]),
            ),
        )
        .expect("str(True) matches id True");
        assert_eq!(found, Some(0));
        let found = _resolve_orphan_target_index(
            &bool_id,
            &step(IndexValue::None, params(vec![("result_id", text("1"))])),
        )
        .expect("str(True) is not 1, and two orphans are ambiguous");
        assert_eq!(found, None);
    }

    #[test]
    fn orphan_indexes_and_validation_fail_closed() {
        let events = vec![
            message("evt-a", None),
            tool("tool_use", "evt-use", Some("corr-known"), Some("evt-a")),
            tool(
                "tool_result",
                "evt-paired",
                Some("corr-known"),
                Some("evt-use"),
            ),
            tool(
                "tool_result",
                "evt-orphan",
                Some("corr-orphan"),
                Some("evt-a"),
            ),
            tool("tool_result", "evt-none", None, Some("evt-a")),
        ];
        let orphans = _find_orphan_result_indices(&events).expect("orphan scan");
        assert_eq!(orphans, vec![3, 4]);

        let empty_corr = vec![
            tool("tool_call", "evt-call", Some(""), None),
            tool("tool_result", "evt-empty", Some(""), Some("evt-call")),
            tool("tool_result", "evt-bare", None, Some("evt-call")),
        ];
        let orphans = _find_orphan_result_indices(&empty_corr).expect("empty correlation");
        assert_eq!(orphans, vec![2]);

        let ignored = vec![
            ev(vec![
                ("kind", text("message")),
                ("id", text("evt-note")),
                ("correlation_id", EventField::Float(1.5)),
            ]),
            tool("tool_result", "evt-orphan", Some("corr-orphan"), None),
        ];
        let orphans =
            _find_orphan_result_indices(&ignored).expect("a non-call does not read correlation");
        assert_eq!(orphans, vec![1]);
        let error = _find_orphan_result_indices(&[ev(vec![
            ("kind", text("tool_call")),
            ("correlation_id", EventField::Float(1.5)),
        ])])
        .expect_err("a call reads correlation");
        assert_eq!(error.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);

        let plain = step(IndexValue::Int(3), no_params());
        _validate_orphan_target(&events, 3, &plain).expect("orphan result passes");
        let error = _validate_orphan_target(&events, -1, &plain)
            .expect_err("negative index does not read events");
        assert_precondition(error, "orphan-result-drop: invalid target index -1");
        let error = _validate_orphan_target(&events, 99, &plain).expect_err("out of range");
        assert_precondition(error, "orphan-result-drop: invalid target index 99");
        let error = _validate_orphan_target(&events, 0, &plain).expect_err("not a result");
        assert_precondition(
            error,
            "orphan-result-drop: event at index 0 is not a tool_result",
        );

        let mismatch = step(
            IndexValue::Int(3),
            params(vec![("correlation_id", text("corr-other"))]),
        );
        let error = _validate_orphan_target(&events, 3, &mismatch).expect_err("mismatch");
        assert_precondition(
            error,
            "orphan-result-drop: target correlation does not match finding evidence",
        );
        let matched = step(
            IndexValue::Int(3),
            params(vec![("correlation_id", EventField::Bool(true))]),
        );
        let renamed = vec![tool("tool_result", "evt-orphan", Some("True"), None)];
        _validate_orphan_target(&renamed, 0, &matched).expect("str(True) matches correlation True");
        let error = _validate_orphan_target(
            &events,
            3,
            &step(
                IndexValue::Int(3),
                params(vec![("correlation_id", EventField::Bool(true))]),
            ),
        )
        .expect_err("str(True) is not the orphan correlation");
        assert_precondition(
            error,
            "orphan-result-drop: target correlation does not match finding evidence",
        );

        let error =
            _validate_orphan_target(&events, 2, &at(2)).expect_err("tool_use pairs the result");
        assert_precondition(
            error,
            "orphan-result-drop: result at index 2 is not an orphan (a matching tool call exists)",
        );

        let child = vec![
            tool("tool_result", "evt-orphan", Some("corr-orphan"), None),
            message("evt-child", Some("evt-orphan")),
        ];
        let error = _validate_orphan_target(&child, 0, &at(0)).expect_err("child blocks the drop");
        assert_precondition(
            error,
            "orphan-result-drop: result has dependent child events; dropping it would create missing parents",
        );

        let blank = vec![
            ev(vec![
                ("kind", text("tool_result")),
                ("id", text("")),
                ("correlation_id", text("corr-orphan")),
            ]),
            ev(vec![
                ("kind", text("message")),
                ("parent_id", EventField::Float(1.5)),
            ]),
        ];
        _validate_orphan_target(&blank, 0, &at(0)).expect("an empty id does not scan children");

        let float_later = vec![
            tool("tool_call", "evt-call", Some("corr-orphan"), None),
            ev(vec![("kind", EventField::Float(1.5))]),
            tool("tool_result", "evt-orphan", Some("corr-orphan"), None),
        ];
        let error = _validate_orphan_target(&float_later, 2, &at(2))
            .expect_err("the matching call is reported before a later kind");
        assert_precondition(
            error,
            "orphan-result-drop: result at index 2 is not an orphan (a matching tool call exists)",
        );
        let float_first = vec![
            ev(vec![("kind", EventField::Float(1.5))]),
            tool("tool_call", "evt-call", Some("corr-orphan"), None),
            tool("tool_result", "evt-orphan", Some("corr-orphan"), None),
        ];
        let error = _validate_orphan_target(&float_first, 2, &at(2))
            .expect_err("a kind error precedes the orphan refusal");
        assert_eq!(error.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
    }
}
