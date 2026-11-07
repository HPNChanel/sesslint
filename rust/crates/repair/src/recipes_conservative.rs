//! Conservative repair recipes, first three transforms (TASK-019).
//!
//! Port of `src/sesslint/repair/recipes_conservative.py` lines 1–260
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! [`apply_terminal_suffix_discard`] copies the prefix when the cut is a real
//! int and the suffix contains no checkpoint. [`apply_identical_duplicate_collapse`]
//! collapses one adjacent pair whose kinds match and whose fingerprints match.
//! [`apply_proven_unique_parent_restore`] resolves the target index and parent
//! id, then stops. The next Python call is
//! `find_qualifying_parent_candidates`. That function lives in
//! `sesslint.checks.graph`. This crate does not depend on `checks`.
//!
//! `register_all` is out of this slice. `register_recipe` is not called.
//! `sesslint.policy.abstention.AffectedRegion` is not constructed.
//!
//! A bool is not an int. Event-helper errors propagate.
//! [`event_content_fingerprint`](model::events::event_content_fingerprint)
//! returns a non-empty `content_hash` when one is present. Otherwise its
//! error is returned as that error. Inputs are not mutated.

use std::error::Error;
use std::fmt;

use model::events::{
    copy_events_as_dicts, event_content_fingerprint, event_id, event_kind, event_parent_id,
    EventError, EventField, EventMapping, EventValue,
};

/// `sesslint.checks.graph.find_qualifying_parent_candidates` is not available.
pub const FIND_QUALIFYING_PARENT_CANDIDATES_UNAVAILABLE: &str =
    "sesslint.checks.graph.find_qualifying_parent_candidates is not available";

const INVALID_CUT: &str = "terminal-suffix-discard: missing or invalid cut index";
const COLLAPSE_NEEDS_TWO: &str = "identical-duplicate-collapse: requires at least 2 events";
const NO_ELIGIBLE_PAIR: &str = "identical-duplicate-collapse: no eligible duplicate pair found";
const FINGERPRINTS_DIFFER: &str = "identical-duplicate-collapse: event content fingerprints differ";
const INVALID_TARGET: &str = "proven-unique-parent-restore: missing or invalid target_index";
const MISSING_PARENT: &str = "proven-unique-parent-restore: missing parent_id";

/// Value read from `target_index`.
///
/// [`IndexValue::Bool`] is not an int. [`IndexValue::Other`] is present and is
/// neither `None`, `bool`, nor `int`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexValue {
    /// Python `None`, including a missing attribute.
    None,
    /// Python `int`. Not a bool.
    Int(i64),
    /// Python `bool`. Not an int.
    Bool(bool),
    /// Present, and not `None`, `bool`, or `int`.
    Other,
}

/// `params` as these recipes read it.
///
/// [`ParamMap::NotMapping`] is any non-mapping, including `None`.
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
pub struct RecipeStep {
    /// Python `PlanStep.target_index`.
    pub target_index: IndexValue,
    /// Python `PlanStep.params`.
    pub params: ParamMap,
}

/// Direct application rejected the events.
///
/// Python: `PreconditionFailed(ValueError)`. [`Display`](fmt::Display) is the
/// message only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreconditionFailed {
    message: String,
}

impl PreconditionFailed {
    /// Build the exception with the Python message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The `ValueError` message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Python: `isinstance(err, ValueError)`.
    pub const fn is_value_error(&self) -> bool {
        true
    }
}

impl fmt::Display for PreconditionFailed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for PreconditionFailed {}

/// The qualifying-parent walk cannot run in this crate.
///
/// [`Display`](fmt::Display) is [`FIND_QUALIFYING_PARENT_CANDIDATES_UNAVAILABLE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParentCandidatesUnavailable;

impl ParentCandidatesUnavailable {
    /// Seam sentence. This is the Display text.
    pub const fn message(self) -> &'static str {
        FIND_QUALIFYING_PARENT_CANDIDATES_UNAVAILABLE
    }
}

impl fmt::Display for ParentCandidatesUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(FIND_QUALIFYING_PARENT_CANDIDATES_UNAVAILABLE)
    }
}

impl Error for ParentCandidatesUnavailable {}

/// Failure from a conservative recipe in this slice.
///
/// [`Display`](fmt::Display) is the message only. A precondition displays the
/// [`PreconditionFailed`] message. An event-helper failure displays the
/// [`EventError`](model::events::EventError) text. The parent-candidate seam
/// displays [`FIND_QUALIFYING_PARENT_CANDIDATES_UNAVAILABLE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConservativeError {
    /// Python `PreconditionFailed`.
    Precondition(PreconditionFailed),
    /// [`event_kind`](model::events::event_kind), [`event_id`](model::events::event_id),
    /// [`event_parent_id`](model::events::event_parent_id),
    /// [`event_content_fingerprint`](model::events::event_content_fingerprint),
    /// [`copy_events_as_dicts`](model::events::copy_events_as_dicts), or `str()`
    /// of a parent id this crate cannot render.
    Event(EventError),
    /// `find_qualifying_parent_candidates` is not available.
    ParentCandidates(ParentCandidatesUnavailable),
}

impl fmt::Display for ConservativeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Precondition(error) => error.fmt(formatter),
            Self::Event(error) => error.fmt(formatter),
            Self::ParentCandidates(error) => error.fmt(formatter),
        }
    }
}

impl Error for ConservativeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Event(error) => Some(error),
            Self::Precondition(_) | Self::ParentCandidates(_) => None,
        }
    }
}

impl From<EventError> for ConservativeError {
    fn from(error: EventError) -> Self {
        Self::Event(error)
    }
}

impl From<PreconditionFailed> for ConservativeError {
    fn from(error: PreconditionFailed) -> Self {
        Self::Precondition(error)
    }
}

impl From<ParentCandidatesUnavailable> for ConservativeError {
    fn from(error: ParentCandidatesUnavailable) -> Self {
        Self::ParentCandidates(error)
    }
}

/// Drop trailing events after the cut index.
///
/// Python: `apply_terminal_suffix_discard`. The cut is `step.target_index`.
/// When that value is [`IndexValue::None`] and `params` is a mapping,
/// `params["cut_index"]` is used only when it is a real int.
/// [`IndexValue::Bool`] and [`EventField::Bool`] fail the int check.
///
/// The suffix is walked with [`event_kind`](model::events::event_kind) before
/// the prefix is copied. A checkpoint in that suffix is
/// [`PreconditionFailed`]. The input slice is not mutated.
///
/// # Errors
///
/// Returns [`ConservativeError::Precondition`] for a missing cut, a non-int
/// cut, a bool cut, `cut <= 0`, `cut >= len(events)`, or a checkpoint in the
/// suffix. Returns [`ConservativeError::Event`] when kind or the prefix copy
/// fails. This function does not panic.
pub fn apply_terminal_suffix_discard(
    events: &[EventValue],
    step: &RecipeStep,
) -> Result<Vec<EventMapping>, ConservativeError> {
    let cut = resolve_terminal_cut(step)?;
    if cut <= 0 {
        return Err(precondition(format!(
            "terminal-suffix-discard: cut at index {cut} would empty session (refused)"
        ))
        .into());
    }
    let Some(cut_index) = checked_index(cut, events.len()) else {
        let len = events.len();
        return Err(precondition(format!(
            "terminal-suffix-discard: cut at index {cut} >= session length {len}"
        ))
        .into());
    };
    reject_suffix_checkpoint(events, cut_index)?;
    Ok(copy_events_as_dicts(&events[..cut_index])?)
}

/// Python: `terminal_suffix_discard = apply_terminal_suffix_discard`.
pub use apply_terminal_suffix_discard as terminal_suffix_discard;

/// Collapse two adjacent identical events into one.
///
/// Python: `apply_identical_duplicate_collapse`. Fewer than two events fails
/// before any fingerprint read. A real int index comes from `target_index`,
/// otherwise from the first real int among `at_index`, `index`, and
/// `first_index`. A bool index is not that int. An int outside the session
/// fails with the pin's out-of-bounds message.
///
/// Kinds are compared before fingerprints. A fingerprint error is returned
/// and the list is not collapsed. When a pair matches, the later event is
/// removed from a copy. `parent_id` is rewritten only when both ids are
/// non-empty and different. The input slice is not mutated.
///
/// # Errors
///
/// Returns [`ConservativeError::Precondition`] for a short list, an out-of-range
/// index, a kind mismatch, a boundary kind, differing fingerprints, or no
/// eligible pair. Returns [`ConservativeError::Event`] when kind, id,
/// fingerprint, or the copy fails. This function does not panic.
pub fn apply_identical_duplicate_collapse(
    events: &[EventValue],
    step: &RecipeStep,
) -> Result<Vec<EventMapping>, ConservativeError> {
    if events.len() < 2 {
        return Err(precondition(COLLAPSE_NEEDS_TWO).into());
    }
    if let Some(index) = collapse_index(step) {
        return collapse_at_index(events, index);
    }
    collapse_scan(events)
}

/// Python: `identical_duplicate_collapse = apply_identical_duplicate_collapse`.
pub use apply_identical_duplicate_collapse as identical_duplicate_collapse;

/// Reattach a missing parent when one candidate qualifies.
///
/// Python: `apply_proven_unique_parent_restore`, through `str(parent_id)`.
/// Index resolution follows the pin, including the range check. A bool index
/// is not an int. `parent_id` comes from `params["parent_id"]` or
/// `params["parent_fingerprint_prefix"]` using Python truthiness, otherwise
/// from [`event_parent_id`](model::events::event_parent_id).
///
/// `str()` of a float, list, or mapping parent id is
/// [`ConservativeError::Event`]. It is not [`Debug`](fmt::Debug). The next
/// call is `find_qualifying_parent_candidates`. This function returns
/// [`ParentCandidatesUnavailable`] instead of that call. It does not invent
/// candidates, copy events, or return a rewritten list.
///
/// # Errors
///
/// Returns [`ConservativeError::Precondition`] for an invalid target or a
/// missing parent id. Returns [`ConservativeError::Event`] when the parent id
/// cannot be rendered or [`event_parent_id`](model::events::event_parent_id)
/// fails. Returns [`ConservativeError::ParentCandidates`] once the parent id
/// is ready for the graph walk. This function does not panic.
pub fn apply_proven_unique_parent_restore(
    events: &[EventValue],
    step: &RecipeStep,
) -> Result<Vec<EventMapping>, ConservativeError> {
    let target_idx = resolve_restore_index(step, events.len())?;
    let Some(child) = events.get(target_idx) else {
        return Err(precondition(INVALID_TARGET).into());
    };
    let missing_parent_id = require_parent_id(step, child)?;
    Err(parent_candidates_unavailable(
        events,
        child,
        target_idx,
        &missing_parent_id,
    ))
}

/// Python: `proven_unique_parent_restore = apply_proven_unique_parent_restore`.
pub use apply_proven_unique_parent_restore as proven_unique_parent_restore;

fn precondition(message: impl Into<String>) -> PreconditionFailed {
    PreconditionFailed::new(message)
}

fn resolve_terminal_cut(step: &RecipeStep) -> Result<i64, PreconditionFailed> {
    match step.target_index {
        IndexValue::Int(cut) => Ok(cut),
        IndexValue::None => cut_from_params(&step.params),
        IndexValue::Bool(_) | IndexValue::Other => Err(precondition(INVALID_CUT)),
    }
}

fn cut_from_params(params: &ParamMap) -> Result<i64, PreconditionFailed> {
    let ParamMap::Mapping(mapping) = params else {
        return Err(precondition(INVALID_CUT));
    };
    match mapping.get("cut_index") {
        Some(EventField::Int(cut)) => Ok(*cut),
        _ => Err(precondition(INVALID_CUT)),
    }
}

fn reject_suffix_checkpoint(
    events: &[EventValue],
    cut_index: usize,
) -> Result<(), ConservativeError> {
    for (index, event) in events.iter().enumerate().skip(cut_index) {
        if event_kind(event)?.as_deref() == Some("checkpoint") {
            return Err(precondition(format!(
                "terminal-suffix-discard: checkpoint at index {index} cannot be discarded"
            ))
            .into());
        }
    }
    Ok(())
}

fn checked_index(index: i64, len: usize) -> Option<usize> {
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

fn collapse_index(step: &RecipeStep) -> Option<i64> {
    match step.target_index {
        IndexValue::Int(index) => Some(index),
        IndexValue::Bool(_) | IndexValue::Other => None,
        IndexValue::None => first_param_int(&step.params, &["at_index", "index", "first_index"]),
    }
}

fn first_param_int(params: &ParamMap, keys: &[&str]) -> Option<i64> {
    let ParamMap::Mapping(mapping) = params else {
        return None;
    };
    for key in keys {
        if let Some(EventField::Int(value)) = mapping.get(key) {
            return Some(*value);
        }
    }
    None
}

fn collapse_at_index(
    events: &[EventValue],
    index: i64,
) -> Result<Vec<EventMapping>, ConservativeError> {
    let Some(position) = checked_index(index, events.len()) else {
        return Err(precondition(format!(
            "identical-duplicate-collapse: target index {index} out of bounds"
        ))
        .into());
    };
    let pairs = adjacent_candidates(position, events.len());
    for &(keep_i, drop_i) in &pairs {
        let Some((left, right)) = pair_refs(events, keep_i, drop_i) else {
            continue;
        };
        if eligible(left, right)? {
            return collapse_pair(events, keep_i, drop_i);
        }
    }
    let Some(&(keep_i, drop_i)) = pairs.first() else {
        return Err(precondition(NO_ELIGIBLE_PAIR).into());
    };
    let Some((left, right)) = pair_refs(events, keep_i, drop_i) else {
        return Err(precondition(NO_ELIGIBLE_PAIR).into());
    };
    indexed_failure(left, right)
}

fn collapse_scan(events: &[EventValue]) -> Result<Vec<EventMapping>, ConservativeError> {
    let last = events.len().saturating_sub(1);
    for index in 0..last {
        let Some((left, right)) = pair_refs(events, index, index + 1) else {
            break;
        };
        if eligible(left, right)? {
            return collapse_pair(events, index, index + 1);
        }
    }
    Err(precondition(NO_ELIGIBLE_PAIR).into())
}

fn adjacent_candidates(index: usize, len: usize) -> Vec<(usize, usize)> {
    let mut pairs = Vec::new();
    if index < len.saturating_sub(1) {
        pairs.push((index, index + 1));
    }
    if index > 0 {
        pairs.push((index - 1, index));
    }
    pairs
}

fn pair_refs(
    events: &[EventValue],
    keep_i: usize,
    drop_i: usize,
) -> Option<(&EventValue, &EventValue)> {
    Some((events.get(keep_i)?, events.get(drop_i)?))
}

fn eligible(left: &EventValue, right: &EventValue) -> Result<bool, ConservativeError> {
    let (left_kind, right_kind) = pair_kinds(left, right)?;
    if left_kind == right_kind && !boundary_kind(left_kind.as_deref()) {
        let left_fingerprint = event_content_fingerprint(left)?;
        let right_fingerprint = event_content_fingerprint(right)?;
        return Ok(left_fingerprint == right_fingerprint);
    }
    Ok(false)
}

fn pair_kinds(
    left: &EventValue,
    right: &EventValue,
) -> Result<(Option<String>, Option<String>), ConservativeError> {
    Ok((event_kind(left)?, event_kind(right)?))
}

fn boundary_kind(kind: Option<&str>) -> bool {
    matches!(kind, Some("checkpoint" | "compaction_boundary"))
}

fn indexed_failure(
    left: &EventValue,
    right: &EventValue,
) -> Result<Vec<EventMapping>, ConservativeError> {
    let (left_kind, right_kind) = pair_kinds(left, right)?;
    if left_kind != right_kind {
        let left_label = kind_label(&left_kind);
        let right_label = kind_label(&right_kind);
        return Err(precondition(format!(
            "identical-duplicate-collapse: kind mismatch between '{left_label}' and '{right_label}'"
        ))
        .into());
    }
    if let Some(kind) = left_kind.as_deref() {
        if boundary_kind(Some(kind)) {
            return Err(precondition(format!(
                "identical-duplicate-collapse: cannot collapse boundary kind '{kind}'"
            ))
            .into());
        }
    }
    let left_fingerprint = event_content_fingerprint(left)?;
    let right_fingerprint = event_content_fingerprint(right)?;
    if left_fingerprint != right_fingerprint {
        return Err(precondition(FINGERPRINTS_DIFFER).into());
    }
    Err(precondition(NO_ELIGIBLE_PAIR).into())
}

fn kind_label(kind: &Option<String>) -> String {
    match kind {
        Some(text) => text.clone(),
        None => "None".to_owned(),
    }
}

fn collapse_pair(
    events: &[EventValue],
    keep_i: usize,
    drop_i: usize,
) -> Result<Vec<EventMapping>, ConservativeError> {
    let mut copied = copy_events_as_dicts(events)?;
    if keep_i >= drop_i || drop_i >= copied.len() {
        return Err(precondition(NO_ELIGIBLE_PAIR).into());
    }
    let dropped = copied.remove(drop_i);
    let Some(kept) = copied.get(keep_i) else {
        return Err(precondition(NO_ELIGIBLE_PAIR).into());
    };
    let kept_id = event_id(&EventValue::Mapping(kept.clone()))?;
    let dropped_id = event_id(&EventValue::Mapping(dropped))?;
    rewrite_parent_links(&mut copied, kept_id.as_deref(), dropped_id.as_deref());
    Ok(copied)
}

fn rewrite_parent_links(
    events: &mut [EventMapping],
    kept_id: Option<&str>,
    dropped_id: Option<&str>,
) {
    let (Some(kept_id), Some(dropped_id)) = (kept_id, dropped_id) else {
        return;
    };
    if kept_id.is_empty() || dropped_id.is_empty() || kept_id == dropped_id {
        return;
    }
    for event in events {
        if parent_matches(event, dropped_id) {
            replace_parent(event, kept_id);
        }
    }
}

fn parent_matches(event: &EventMapping, dropped_id: &str) -> bool {
    matches!(event.get("parent_id"), Some(EventField::Str(parent)) if parent == dropped_id)
}

fn replace_parent(event: &mut EventMapping, kept_id: &str) {
    let mut entries = event.entries().to_vec();
    if let Some((_, value)) = entries.iter_mut().rev().find(|(key, _)| key == "parent_id") {
        *value = EventField::Str(kept_id.to_owned());
    }
    *event = EventMapping::new(entries);
}

enum ResolvedIndex {
    Int(i64),
    Invalid,
}

fn resolve_restore_index(step: &RecipeStep, len: usize) -> Result<usize, PreconditionFailed> {
    match resolved_restore_index(step) {
        Some(ResolvedIndex::Int(index)) => checked_index(index, len).ok_or_else(invalid_target),
        Some(ResolvedIndex::Invalid) | None => Err(invalid_target()),
    }
}

fn invalid_target() -> PreconditionFailed {
    precondition(INVALID_TARGET)
}

fn resolved_restore_index(step: &RecipeStep) -> Option<ResolvedIndex> {
    match step.target_index {
        IndexValue::Int(index) => Some(ResolvedIndex::Int(index)),
        IndexValue::Bool(_) | IndexValue::Other => Some(ResolvedIndex::Invalid),
        IndexValue::None => restore_index_param(&step.params),
    }
}

fn restore_index_param(params: &ParamMap) -> Option<ResolvedIndex> {
    let ParamMap::Mapping(mapping) = params else {
        return None;
    };
    let mut chosen = mapping.get("index");
    if is_none_field(chosen) {
        chosen = mapping.get("at_index");
    }
    match chosen {
        None | Some(EventField::Null) => None,
        Some(EventField::Int(index)) => Some(ResolvedIndex::Int(*index)),
        Some(_) => Some(ResolvedIndex::Invalid),
    }
}

fn is_none_field(value: Option<&EventField>) -> bool {
    matches!(value, None | Some(EventField::Null))
}

fn require_parent_id(step: &RecipeStep, child: &EventValue) -> Result<String, ConservativeError> {
    if let Some(value) = truthy_param_parent(&step.params) {
        return render_parent(value).map_err(ConservativeError::Event);
    }
    match event_parent_id(child)? {
        Some(parent) if !parent.is_empty() => Ok(parent),
        _ => Err(precondition(MISSING_PARENT).into()),
    }
}

fn truthy_param_parent(params: &ParamMap) -> Option<&EventField> {
    let ParamMap::Mapping(mapping) = params else {
        return None;
    };
    param_or(mapping, "parent_id", "parent_fingerprint_prefix")
        .filter(|value| field_truthy(Some(value)))
}

fn param_or<'a>(mapping: &'a EventMapping, left: &str, right: &str) -> Option<&'a EventField> {
    let left_value = mapping.get(left);
    if field_truthy(left_value) {
        left_value
    } else {
        mapping.get(right)
    }
}

/// Python truthiness. `0`, `0.0`, `False`, `""`, an empty list, and an empty
/// mapping are false. NaN is true. This does not format the value.
fn field_truthy(value: Option<&EventField>) -> bool {
    match value {
        None | Some(EventField::Null) => false,
        Some(EventField::Bool(flag)) => *flag,
        Some(EventField::Int(number)) => *number != 0,
        Some(EventField::Float(number)) => float_truthy(*number),
        Some(EventField::Str(text)) => !text.is_empty(),
        Some(EventField::List(items)) => !items.is_empty(),
        Some(EventField::Mapping(mapping)) => !mapping.entries().is_empty(),
    }
}

fn float_truthy(number: f64) -> bool {
    number.is_nan() || number.abs() > 0.0
}

/// Python `str` for scalars this crate can render.
///
/// Floats, lists, and mappings return [`EventError`]. This is not
/// [`Debug`](fmt::Debug).
fn render_parent(value: &EventField) -> Result<String, EventError> {
    match value {
        EventField::Null => Ok("None".to_owned()),
        EventField::Bool(true) => Ok("True".to_owned()),
        EventField::Bool(false) => Ok("False".to_owned()),
        EventField::Int(number) => Ok(number.to_string()),
        EventField::Str(text) => Ok(text.clone()),
        EventField::Float(_) => Err(EventError::PythonFloatStr),
        EventField::List(_) | EventField::Mapping(_) => Err(EventError::PythonStr),
    }
}

fn parent_candidates_unavailable(
    _events: &[EventValue],
    _child: &EventValue,
    _target_idx: usize,
    _missing_parent_id: &str,
) -> ConservativeError {
    ConservativeError::ParentCandidates(ParentCandidatesUnavailable)
}

#[cfg(test)]
mod tests {
    use model::events::{
        EventError, EventField, EventMapping, EventValue,
        DETERMINISM_CANONICAL_JSON_BYTES_UNAVAILABLE, PYTHON_FLOAT_STR_UNREPRESENTABLE,
        PYTHON_STR_UNREPRESENTABLE,
    };

    use super::{
        apply_identical_duplicate_collapse, apply_proven_unique_parent_restore,
        apply_terminal_suffix_discard, identical_duplicate_collapse, proven_unique_parent_restore,
        render_parent, terminal_suffix_discard, ConservativeError, IndexValue, ParamMap,
        ParentCandidatesUnavailable, PreconditionFailed, RecipeStep,
        FIND_QUALIFYING_PARENT_CANDIDATES_UNAVAILABLE,
    };

    fn bare(entries: Vec<(&str, EventField)>) -> EventMapping {
        EventMapping::new(
            entries
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        )
    }

    fn ev(entries: Vec<(&str, EventField)>) -> EventValue {
        EventValue::Mapping(bare(entries))
    }

    fn text(value: &str) -> EventField {
        EventField::Str(value.to_owned())
    }

    fn params_of(entries: Vec<(&str, EventField)>) -> ParamMap {
        ParamMap::Mapping(bare(entries))
    }

    fn make_step(target_index: IndexValue, params: ParamMap) -> RecipeStep {
        RecipeStep {
            target_index,
            params,
        }
    }

    fn note(id: &str) -> EventValue {
        ev(vec![("kind", text("note")), ("id", text(id))])
    }

    fn hashed(kind: &str, id: &str, hash: &str, parent: Option<&str>) -> EventValue {
        let mut entries = vec![
            ("kind", text(kind)),
            ("id", text(id)),
            ("content_hash", text(hash)),
        ];
        if let Some(parent) = parent {
            entries.push(("parent_id", text(parent)));
        }
        ev(entries)
    }

    fn with_parent(id: &str, parent: &str) -> EventValue {
        ev(vec![
            ("kind", text("note")),
            ("id", text(id)),
            ("parent_id", text(parent)),
        ])
    }

    fn mappings(events: &[EventValue]) -> Vec<EventMapping> {
        events
            .iter()
            .map(|event| match event {
                EventValue::Mapping(mapping) => mapping.clone(),
                EventValue::Session(_) | EventValue::Other => EventMapping::new(Vec::new()),
            })
            .collect()
    }

    fn field_str<'a>(mapping: &'a EventMapping, key: &str) -> Option<&'a str> {
        match mapping.get(key) {
            Some(EventField::Str(value)) => Some(value.as_str()),
            _ => None,
        }
    }

    fn assert_cut_message(step: &RecipeStep, expected: &str) {
        let events = vec![note("evt-a"), note("evt-b")];
        let error = terminal_suffix_discard(&events, step).expect_err("cut");
        assert_eq!(error.to_string(), expected);
        assert!(matches!(error, ConservativeError::Precondition(_)));
    }

    #[test]
    fn precondition_failed_display_is_the_message_only() {
        let error =
            PreconditionFailed::new("terminal-suffix-discard: missing or invalid cut index");
        assert_eq!(
            error.to_string(),
            "terminal-suffix-discard: missing or invalid cut index"
        );
        assert_eq!(error.to_string(), error.message());
        assert!(error.is_value_error());
        let wrapped = ConservativeError::from(error);
        assert_eq!(
            wrapped.to_string(),
            "terminal-suffix-discard: missing or invalid cut index"
        );
    }

    #[test]
    fn cut_missing_bool_and_non_int_fail_the_int_check() {
        assert_cut_message(
            &make_step(IndexValue::None, ParamMap::NotMapping),
            "terminal-suffix-discard: missing or invalid cut index",
        );
        assert_cut_message(
            &make_step(IndexValue::None, params_of(vec![])),
            "terminal-suffix-discard: missing or invalid cut index",
        );
        assert_cut_message(
            &make_step(
                IndexValue::None,
                params_of(vec![("cut_index", EventField::Bool(true))]),
            ),
            "terminal-suffix-discard: missing or invalid cut index",
        );
        assert_cut_message(
            &make_step(
                IndexValue::None,
                params_of(vec![("cut_index", EventField::Bool(false))]),
            ),
            "terminal-suffix-discard: missing or invalid cut index",
        );
        assert_cut_message(
            &make_step(IndexValue::None, params_of(vec![("cut_index", text("1"))])),
            "terminal-suffix-discard: missing or invalid cut index",
        );
        assert_cut_message(
            &make_step(
                IndexValue::Bool(true),
                params_of(vec![("cut_index", EventField::Int(1))]),
            ),
            "terminal-suffix-discard: missing or invalid cut index",
        );
        assert_cut_message(
            &make_step(
                IndexValue::Other,
                params_of(vec![("cut_index", EventField::Int(1))]),
            ),
            "terminal-suffix-discard: missing or invalid cut index",
        );
    }

    #[test]
    fn cut_at_or_below_zero_refuses_to_empty_the_session() {
        for cut in [0_i64, -1, -4] {
            let expected = format!(
                "terminal-suffix-discard: cut at index {cut} would empty session (refused)"
            );
            assert_cut_message(
                &make_step(IndexValue::Int(cut), ParamMap::NotMapping),
                &expected,
            );
            assert_cut_message(
                &make_step(
                    IndexValue::None,
                    params_of(vec![("cut_index", EventField::Int(cut))]),
                ),
                &expected,
            );
        }
        let empty: Vec<EventValue> = Vec::new();
        let error = apply_terminal_suffix_discard(
            &empty,
            &make_step(IndexValue::Int(0), ParamMap::NotMapping),
        )
        .expect_err("zero on empty");
        assert_eq!(
            error.to_string(),
            "terminal-suffix-discard: cut at index 0 would empty session (refused)"
        );
    }

    #[test]
    fn cut_at_or_past_the_session_length_is_refused() {
        let events = vec![note("evt-a"), note("evt-b")];
        let error = apply_terminal_suffix_discard(
            &events,
            &make_step(IndexValue::Int(2), ParamMap::NotMapping),
        )
        .expect_err("end");
        assert_eq!(
            error.to_string(),
            "terminal-suffix-discard: cut at index 2 >= session length 2"
        );
        let error = apply_terminal_suffix_discard(
            &events,
            &make_step(
                IndexValue::None,
                params_of(vec![("cut_index", EventField::Int(5))]),
            ),
        )
        .expect_err("past");
        assert_eq!(
            error.to_string(),
            "terminal-suffix-discard: cut at index 5 >= session length 2"
        );
        let error = apply_terminal_suffix_discard(
            &[],
            &make_step(IndexValue::Int(1), ParamMap::NotMapping),
        )
        .expect_err("empty session length");
        assert_eq!(
            error.to_string(),
            "terminal-suffix-discard: cut at index 1 >= session length 0"
        );
    }

    #[test]
    fn checkpoint_in_the_suffix_cannot_be_discarded() {
        let events = vec![
            note("evt-a"),
            note("evt-b"),
            note("evt-c"),
            ev(vec![("kind", text("checkpoint")), ("id", text("evt-d"))]),
        ];
        let error = apply_terminal_suffix_discard(
            &events,
            &make_step(IndexValue::Int(1), ParamMap::NotMapping),
        )
        .expect_err("checkpoint");
        assert_eq!(
            error.to_string(),
            "terminal-suffix-discard: checkpoint at index 3 cannot be discarded"
        );
    }

    #[test]
    fn suffix_kind_error_propagates_and_is_not_a_cut_message() {
        let events = vec![
            note("evt-a"),
            ev(vec![
                ("kind", EventField::Float(1.5)),
                ("id", text("evt-b")),
            ]),
        ];
        let error = apply_terminal_suffix_discard(
            &events,
            &make_step(IndexValue::Int(1), ParamMap::NotMapping),
        )
        .expect_err("kind");
        assert_eq!(error.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        assert!(matches!(error, ConservativeError::Event(_)));
    }

    #[test]
    fn prefix_copy_without_a_checkpoint_leaves_the_input_unchanged() {
        let events = vec![note("evt-a"), note("evt-b"), note("evt-c")];
        let snapshot = mappings(&events);
        let step = make_step(IndexValue::Int(2), ParamMap::NotMapping);
        let mut output = apply_terminal_suffix_discard(&events, &step).expect("prefix");
        assert_eq!(output, snapshot[..2].to_vec());
        assert_eq!(field_str(&output[0], "id"), Some("evt-a"));
        assert_eq!(field_str(&output[1], "id"), Some("evt-b"));
        output[0].push("marker", EventField::Int(1));
        assert_eq!(mappings(&events), snapshot);
        assert!(snapshot[0].get("marker").is_none());

        let from_params = make_step(
            IndexValue::None,
            params_of(vec![("cut_index", EventField::Int(2))]),
        );
        let output = terminal_suffix_discard(&events, &from_params).expect("params cut");
        assert_eq!(output, snapshot[..2].to_vec());

        let bool_param_ignored = make_step(
            IndexValue::Int(2),
            params_of(vec![("cut_index", EventField::Bool(true))]),
        );
        let output =
            apply_terminal_suffix_discard(&events, &bool_param_ignored).expect("target wins");
        assert_eq!(output, snapshot[..2].to_vec());
        assert_eq!(mappings(&events), snapshot);
    }

    #[test]
    fn collapse_requires_two_events_before_any_fingerprint() {
        let step = make_step(IndexValue::None, ParamMap::NotMapping);
        let one = vec![note("evt-only")];
        let error = identical_duplicate_collapse(&one, &step).expect_err("one");
        assert_eq!(
            error.to_string(),
            "identical-duplicate-collapse: requires at least 2 events"
        );
        let error = apply_identical_duplicate_collapse(&[], &step).expect_err("zero");
        assert_eq!(
            error.to_string(),
            "identical-duplicate-collapse: requires at least 2 events"
        );
    }

    #[test]
    fn fingerprint_seam_does_not_collapse() {
        let events = vec![note("evt-a"), note("evt-b")];
        let snapshot = mappings(&events);
        let error = apply_identical_duplicate_collapse(
            &events,
            &make_step(IndexValue::None, ParamMap::NotMapping),
        )
        .expect_err("fingerprint");
        assert_eq!(
            error.to_string(),
            DETERMINISM_CANONICAL_JSON_BYTES_UNAVAILABLE
        );
        assert!(matches!(
            &error,
            ConservativeError::Event(EventError::DeterminismCanonicalJsonBytes)
        ));
        assert_ne!(
            error.to_string(),
            "identical-duplicate-collapse: event content fingerprints differ"
        );
        assert_eq!(mappings(&events), snapshot);
    }

    #[test]
    fn collapse_index_out_of_bounds_uses_the_pin_message() {
        let events = vec![note("evt-a"), note("evt-b")];
        let error = apply_identical_duplicate_collapse(
            &events,
            &make_step(IndexValue::Int(9), ParamMap::NotMapping),
        )
        .expect_err("high");
        assert_eq!(
            error.to_string(),
            "identical-duplicate-collapse: target index 9 out of bounds"
        );
        let error = apply_identical_duplicate_collapse(
            &events,
            &make_step(
                IndexValue::None,
                params_of(vec![("at_index", EventField::Int(-2))]),
            ),
        )
        .expect_err("negative");
        assert_eq!(
            error.to_string(),
            "identical-duplicate-collapse: target index -2 out of bounds"
        );
    }

    #[test]
    fn bool_param_index_is_skipped_and_kind_mismatch_uses_the_pin_message() {
        let events = vec![
            hashed("note", "evt-a", "hash-left", None),
            hashed("note", "evt-b", "hash-right", None),
            hashed("tool_result", "evt-c", "hash-other", None),
        ];
        let error = apply_identical_duplicate_collapse(
            &events,
            &make_step(
                IndexValue::None,
                params_of(vec![
                    ("at_index", EventField::Bool(true)),
                    ("index", EventField::Int(0)),
                ]),
            ),
        )
        .expect_err("skipped bool");
        assert_eq!(
            error.to_string(),
            "identical-duplicate-collapse: event content fingerprints differ"
        );

        let missing_kind = vec![ev(vec![("id", text("evt-a"))]), note("evt-b")];
        let error = apply_identical_duplicate_collapse(
            &missing_kind,
            &make_step(IndexValue::Int(0), ParamMap::NotMapping),
        )
        .expect_err("none kind");
        assert_eq!(
            error.to_string(),
            "identical-duplicate-collapse: kind mismatch between 'None' and 'note'"
        );
    }

    #[test]
    fn boundary_kind_is_reported_before_a_fingerprint_read() {
        let checkpoint = vec![
            ev(vec![("kind", text("checkpoint")), ("id", text("evt-a"))]),
            ev(vec![("kind", text("checkpoint")), ("id", text("evt-b"))]),
        ];
        let error = apply_identical_duplicate_collapse(
            &checkpoint,
            &make_step(IndexValue::Int(0), ParamMap::NotMapping),
        )
        .expect_err("checkpoint");
        assert_eq!(
            error.to_string(),
            "identical-duplicate-collapse: cannot collapse boundary kind 'checkpoint'"
        );

        let boundary = vec![
            ev(vec![
                ("kind", text("compaction_boundary")),
                ("id", text("evt-a")),
            ]),
            ev(vec![
                ("kind", text("compaction_boundary")),
                ("id", text("evt-b")),
            ]),
        ];
        let error = apply_identical_duplicate_collapse(
            &boundary,
            &make_step(IndexValue::Int(1), ParamMap::NotMapping),
        )
        .expect_err("boundary");
        assert_eq!(
            error.to_string(),
            "identical-duplicate-collapse: cannot collapse boundary kind 'compaction_boundary'"
        );
    }

    #[test]
    fn differing_fingerprints_use_the_pin_message() {
        let events = vec![
            hashed("note", "evt-a", "hash-left", None),
            hashed("note", "evt-b", "hash-right", None),
        ];
        let error = apply_identical_duplicate_collapse(
            &events,
            &make_step(IndexValue::Int(0), ParamMap::NotMapping),
        )
        .expect_err("differ");
        assert_eq!(
            error.to_string(),
            "identical-duplicate-collapse: event content fingerprints differ"
        );
        assert!(matches!(error, ConservativeError::Precondition(_)));
    }

    #[test]
    fn primary_pair_supplies_the_mismatch_after_the_second_pair_fails() {
        let events = vec![
            hashed("note", "evt-a", "hash-left", None),
            hashed("tool_result", "evt-b", "hash-mid", None),
            hashed("note", "evt-c", "hash-left", None),
        ];
        let error = apply_identical_duplicate_collapse(
            &events,
            &make_step(IndexValue::Int(1), ParamMap::NotMapping),
        )
        .expect_err("primary");
        assert_eq!(
            error.to_string(),
            "identical-duplicate-collapse: kind mismatch between 'tool_result' and 'note'"
        );
    }

    #[test]
    fn indexed_collapse_keeps_the_following_pair_ahead_of_the_previous_pair() {
        let events = vec![
            hashed("note", "evt-a", "hash-same", None),
            hashed("note", "evt-b", "hash-same", None),
            hashed("note", "evt-c", "hash-same", Some("evt-b")),
        ];
        let snapshot = mappings(&events);
        let output = identical_duplicate_collapse(
            &events,
            &make_step(IndexValue::Int(1), ParamMap::NotMapping),
        )
        .expect("following pair");
        assert_eq!(output.len(), 2);
        assert_eq!(field_str(&output[0], "id"), Some("evt-a"));
        assert_eq!(field_str(&output[1], "id"), Some("evt-b"));
        assert_eq!(mappings(&events), snapshot);
    }

    #[test]
    fn scan_collapses_the_first_matching_adjacent_pair() {
        let events = vec![
            hashed("note", "evt-kept", "hash-same", None),
            hashed("note", "evt-drop", "hash-same", None),
            hashed("note", "evt-child", "hash-same", Some("evt-drop")),
        ];
        let snapshot = mappings(&events);
        let output = apply_identical_duplicate_collapse(
            &events,
            &make_step(IndexValue::Bool(true), ParamMap::NotMapping),
        )
        .expect("scan");
        assert_eq!(output.len(), 2);
        assert_eq!(field_str(&output[0], "id"), Some("evt-kept"));
        assert_eq!(field_str(&output[1], "id"), Some("evt-child"));
        assert_eq!(field_str(&output[1], "parent_id"), Some("evt-kept"));
        assert_eq!(mappings(&events), snapshot);
    }

    #[test]
    fn parent_restore_rejects_a_missing_bool_or_out_of_range_index() {
        let events = vec![with_parent("evt-child", "parent-synthetic")];
        let cases = [
            make_step(IndexValue::None, ParamMap::NotMapping),
            make_step(IndexValue::Bool(false), ParamMap::NotMapping),
            make_step(IndexValue::Other, ParamMap::NotMapping),
            make_step(IndexValue::Int(-1), ParamMap::NotMapping),
            make_step(IndexValue::Int(1), ParamMap::NotMapping),
            make_step(
                IndexValue::None,
                params_of(vec![
                    ("index", EventField::Bool(false)),
                    ("at_index", EventField::Int(0)),
                ]),
            ),
        ];
        for case in cases {
            let error = apply_proven_unique_parent_restore(&events, &case).expect_err("index");
            assert_eq!(
                error.to_string(),
                "proven-unique-parent-restore: missing or invalid target_index"
            );
            assert!(matches!(error, ConservativeError::Precondition(_)));
        }
    }

    #[test]
    fn parent_restore_missing_parent_id_stops_before_the_graph_seam() {
        let events = vec![note("evt-child")];
        let error = apply_proven_unique_parent_restore(
            &events,
            &make_step(IndexValue::Int(0), ParamMap::NotMapping),
        )
        .expect_err("missing parent");
        assert_eq!(
            error.to_string(),
            "proven-unique-parent-restore: missing parent_id"
        );
        let error = apply_proven_unique_parent_restore(
            &events,
            &make_step(
                IndexValue::Int(0),
                params_of(vec![
                    ("parent_id", text("")),
                    ("parent_fingerprint_prefix", text("")),
                ]),
            ),
        )
        .expect_err("empty params");
        assert_eq!(
            error.to_string(),
            "proven-unique-parent-restore: missing parent_id"
        );
    }

    #[test]
    fn unrenderable_parent_id_is_an_event_error_and_not_debug() {
        assert_eq!(
            render_parent(&EventField::Bool(true)).expect("true"),
            "True"
        );
        assert_eq!(render_parent(&EventField::Int(12)).expect("int"), "12");
        let float_error = render_parent(&EventField::Float(1.5)).expect_err("float");
        assert_eq!(float_error.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        assert_ne!(
            float_error.to_string(),
            format!("{:?}", EventField::Float(1.5))
        );
        let list_error =
            render_parent(&EventField::List(vec![EventField::Int(1)])).expect_err("list");
        assert_eq!(list_error.to_string(), PYTHON_STR_UNREPRESENTABLE);

        let events = vec![with_parent("evt-child", "parent-synthetic")];
        let error = proven_unique_parent_restore(
            &events,
            &make_step(
                IndexValue::Int(0),
                params_of(vec![("parent_id", EventField::Float(1.5))]),
            ),
        )
        .expect_err("float parent");
        assert_eq!(error.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        assert!(matches!(error, ConservativeError::Event(_)));
        let error = apply_proven_unique_parent_restore(
            &events,
            &make_step(
                IndexValue::None,
                params_of(vec![
                    ("index", EventField::Null),
                    ("at_index", EventField::Int(0)),
                    ("parent_id", text("")),
                    (
                        "parent_fingerprint_prefix",
                        EventField::List(vec![EventField::Int(1)]),
                    ),
                ]),
            ),
        )
        .expect_err("list prefix");
        assert_eq!(error.to_string(), PYTHON_STR_UNREPRESENTABLE);
    }

    #[test]
    fn parent_restore_stops_at_the_graph_seam() {
        let events = vec![with_parent("evt-child", "parent-synthetic")];
        let snapshot = mappings(&events);
        let error = proven_unique_parent_restore(
            &events,
            &make_step(IndexValue::Int(0), ParamMap::NotMapping),
        )
        .expect_err("seam");
        assert_eq!(
            error.to_string(),
            FIND_QUALIFYING_PARENT_CANDIDATES_UNAVAILABLE
        );
        assert_eq!(error.to_string(), ParentCandidatesUnavailable.message());
        assert!(matches!(error, ConservativeError::ParentCandidates(_)));
        assert_eq!(mappings(&events), snapshot);

        let from_prefix = make_step(
            IndexValue::None,
            params_of(vec![
                ("index", EventField::Int(0)),
                ("parent_id", EventField::Int(0)),
                ("parent_fingerprint_prefix", text("prefix-synthetic")),
            ]),
        );
        let error = apply_proven_unique_parent_restore(&events, &from_prefix).expect_err("prefix");
        assert_eq!(
            error.to_string(),
            FIND_QUALIFYING_PARENT_CANDIDATES_UNAVAILABLE
        );

        let from_event = make_step(
            IndexValue::None,
            params_of(vec![
                ("at_index", EventField::Int(0)),
                ("parent_id", text("")),
            ]),
        );
        let error = apply_proven_unique_parent_restore(&events, &from_event).expect_err("event");
        assert_eq!(
            error.to_string(),
            FIND_QUALIFYING_PARENT_CANDIDATES_UNAVAILABLE
        );

        let from_true = make_step(
            IndexValue::Int(0),
            params_of(vec![("parent_id", EventField::Bool(true))]),
        );
        let bare_events = vec![note("evt-child")];
        let error = apply_proven_unique_parent_restore(&bare_events, &from_true).expect_err("true");
        assert_eq!(
            error.to_string(),
            FIND_QUALIFYING_PARENT_CANDIDATES_UNAVAILABLE
        );
    }
}
