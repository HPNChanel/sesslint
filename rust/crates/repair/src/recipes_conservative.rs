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

use std::collections::BTreeSet;
use std::convert::Infallible;

use model::events::event_corr_id;

// Port of `src/sesslint/repair/recipes_conservative.py` lines 268-528
// @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//
// `apply_compaction_projection_reunion` and `apply_duplicate_projection_removal`
// return a [`copy_events_as_dicts`](model::events::copy_events_as_dicts) list
// when the pin returns one. A fingerprint error is returned. It is not a
// differing-fingerprint precondition. A bool is not an int.
//
// `affected_region_identical_duplicate_collapse` runs the pin's pure checks.
// Every return in the pin constructs `sesslint.policy.abstention.AffectedRegion`.
// This crate cannot construct that type. `register_all` is not in this slice.

const REUNION_MISSING_CORR: &str = "compaction-projection-reunion: missing correlation_id";
const REMOVAL_MISSING_CORR: &str = "duplicate-projection-removal: missing correlation_id";
const REUNION_PAIR_HEAD: &str = "compaction-projection-reunion: pair for correlation '";
const REUNION_PAIR_TAIL: &str = "' must have exactly 1 call and 1 result";
const REUNION_ENDPOINT: &str = concat!(
    "compaction-projection-reunion: boundary sits at pair endpoint ",
    "(not strictly between)"
);
const REUNION_BOUNDARY_HEAD: &str = concat!(
    "compaction-projection-reunion: expected exactly 1 boundary strictly ",
    "between pair, found "
);
const REMOVAL_COUNT_HEAD: &str = concat!(
    "duplicate-projection-removal: expected at least 2 results for ",
    "correlation '"
);
const REMOVAL_DIFFER: &str = concat!(
    "duplicate-projection-removal: projection fingerprints differ ",
    "(refusing near-match collapse)"
);

/// `sesslint.policy.abstention.AffectedRegion` is not available in this crate.
pub const AFFECTED_REGION_UNAVAILABLE: &str =
    "sesslint.policy.abstention.AffectedRegion is not available";

/// `sesslint.policy.abstention.AffectedRegion` cannot be constructed here.
///
/// [`Display`](fmt::Display) is [`AFFECTED_REGION_UNAVAILABLE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AffectedRegionUnavailable;

impl AffectedRegionUnavailable {
    /// Seam sentence. This is the Display text.
    pub const fn message(self) -> &'static str {
        AFFECTED_REGION_UNAVAILABLE
    }
}

impl fmt::Display for AffectedRegionUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(AFFECTED_REGION_UNAVAILABLE)
    }
}

impl Error for AffectedRegionUnavailable {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DuplicateSpan {
    indices: BTreeSet<usize>,
    ids: BTreeSet<String>,
    ranges: (usize, usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum IdenticalDuplicateRegion {
    Unproven,
    Exception(EventError),
    Proven(DuplicateSpan),
}

enum BoundaryHint<'a> {
    Absent,
    Field(&'a EventField),
    Index(usize),
}

enum PairMatch {
    Found(usize, usize),
    None,
    Stop(IdenticalDuplicateRegion),
}

/// Relocate one compaction boundary to just after a tool pair.
///
/// Python: `apply_compaction_projection_reunion`. A truthy `correlation_id`
/// param is rendered with `str`. `False`, `0`, `""`, `None`, and empty
/// containers fall through. An in-range int `target_index` then supplies
/// [`event_corr_id`](model::events::event_corr_id). [`IndexValue::Bool`] is
/// not that index. `True` as a param renders as `True`, not `1`.
///
/// Calls are `tool_call` or `tool_use`. Results are `tool_result`. Both
/// cardinalities must be 1. A `boundary_index` equal to either pair endpoint
/// is refused before the between-pair count. A bool boundary index is not
/// equal to an int endpoint. A float uses Python `==`. Exactly one
/// `compaction_boundary` strictly between the pair is popped and inserted at
/// the original later-pair index. The list is a
/// [`copy_events_as_dicts`](model::events::copy_events_as_dicts) copy. The
/// input slice is not mutated.
///
/// # Errors
///
/// Returns [`ConservativeError::Precondition`] for a missing correlation id,
/// an unclean pair, an endpoint boundary, or a boundary count other than 1.
/// Returns [`ConservativeError::Event`] when kind, correlation id, `str()` of
/// the correlation id, or the copy fails. This function does not panic.
pub fn apply_compaction_projection_reunion(
    events: &[EventValue],
    step: &RecipeStep,
) -> Result<Vec<EventMapping>, ConservativeError> {
    let corr = resolve_correlation(events, step, REUNION_MISSING_CORR)?;
    let calls = matching_indexes(events, |event| is_call(event, &corr))?;
    let results = matching_indexes(events, |event| is_result(event, &corr))?;
    let Some(call_index) = single_index(&calls) else {
        return Err(pair_error(&corr));
    };
    let Some(result_index) = single_index(&results) else {
        return Err(pair_error(&corr));
    };
    let min_idx = call_index.min(result_index);
    let max_idx = call_index.max(result_index);
    let hint = boundary_hint(step, events)?;
    if hint_hits_endpoint(&hint, min_idx, max_idx) {
        return Err(precondition(REUNION_ENDPOINT).into());
    }
    if endpoint_is_boundary(events, min_idx)? || endpoint_is_boundary(events, max_idx)? {
        return Err(precondition(REUNION_ENDPOINT).into());
    }
    let boundaries = boundaries_between(events, min_idx, max_idx)?;
    let Some(boundary_at) = only_usize(&boundaries) else {
        return Err(boundary_count_error(boundaries.len()));
    };
    let mut out = copy_events_as_dicts(events)?;
    if !relocate_boundary(&mut out, boundary_at, max_idx) {
        return Err(boundary_count_error(boundaries.len()));
    }
    Ok(out)
}

/// Python: `compaction_projection_reunion = apply_compaction_projection_reunion`.
pub use apply_compaction_projection_reunion as compaction_projection_reunion;

/// Drop a later duplicate `tool_result` for one correlation id.
///
/// Python: `apply_duplicate_projection_removal`. Correlation resolution
/// matches [`apply_compaction_projection_reunion`]. At least two results must
/// share that id. The kept fingerprint is the first result.
/// [`event_content_fingerprint`](model::events::event_content_fingerprint)
/// errors are returned. They are not the differing-fingerprint precondition.
/// A bool `target_index` is not an int, so it does not select a result row.
///
/// The chosen row is removed from a
/// [`copy_events_as_dicts`](model::events::copy_events_as_dicts) copy.
/// `parent_id` is rewritten only when both ids are non-empty and different.
/// The input slice is not mutated.
///
/// # Errors
///
/// Returns [`ConservativeError::Precondition`] for a missing correlation id,
/// fewer than two results, or fingerprints that both succeed and differ.
/// Returns [`ConservativeError::Event`] when kind, correlation id, id,
/// fingerprint, `str()`, or the copy fails. This function does not panic.
pub fn apply_duplicate_projection_removal(
    events: &[EventValue],
    step: &RecipeStep,
) -> Result<Vec<EventMapping>, ConservativeError> {
    let corr = resolve_correlation(events, step, REMOVAL_MISSING_CORR)?;
    let results = matching_indexes(events, |event| is_result(event, &corr))?;
    if results.len() < 2 {
        return Err(removal_count_error(&corr, results.len()));
    }
    let (drop_idx, dropped) = select_duplicate(step.target_index, &results)?;
    let Some(&(_, kept)) = results.first() else {
        return Err(removal_count_error(&corr, results.len()));
    };
    let kept_id = event_id(kept)?;
    let dropped_id = event_id(dropped)?;
    let mut out = copy_events_as_dicts(events)?;
    if !remove_copied(&mut out, drop_idx) {
        return Err(removal_count_error(&corr, results.len()));
    }
    rewrite_parent_links(&mut out, kept_id.as_deref(), dropped_id.as_deref());
    Ok(out)
}

/// Python: `duplicate_projection_removal = apply_duplicate_projection_removal`.
pub use apply_duplicate_projection_removal as duplicate_projection_removal;

/// Run the identical-duplicate region checks, then stop.
///
/// Python: `affected_region_identical_duplicate_collapse`. Argument order is
/// `step`, then `events`. The checks follow the pin: length, index
/// resolution, adjacent pairs, kinds, fingerprints, ids, and child
/// `parent_id` links. [`IndexValue::Bool`] is not an int. A fingerprint error
/// stops that walk. It is not a mismatch that selects a later pair.
///
/// Every return in the pin constructs
/// `sesslint.policy.abstention.AffectedRegion`. This crate cannot construct
/// that type and does not invent a region. Each of those returns is
/// [`AffectedRegionUnavailable`]. Display is [`AFFECTED_REGION_UNAVAILABLE`].
/// This is not `true`.
///
/// # Errors
///
/// Always returns [`AffectedRegionUnavailable`] after the checks that apply.
/// This function does not panic.
pub fn affected_region_identical_duplicate_collapse(
    step: &RecipeStep,
    events: &[EventValue],
) -> Result<Infallible, AffectedRegionUnavailable> {
    Err(refuse_identical_region(identical_duplicate_region_parts(
        step, events,
    )))
}

fn refuse_identical_region(region: IdenticalDuplicateRegion) -> AffectedRegionUnavailable {
    match region {
        IdenticalDuplicateRegion::Proven(span) => {
            let _checked = (
                span.indices.len(),
                span.ids.len(),
                span.ranges.0,
                span.ranges.1,
            );
            AffectedRegionUnavailable
        }
        IdenticalDuplicateRegion::Exception(error) => {
            let _checked = error.message().len();
            AffectedRegionUnavailable
        }
        IdenticalDuplicateRegion::Unproven => AffectedRegionUnavailable,
    }
}

fn resolve_correlation(
    events: &[EventValue],
    step: &RecipeStep,
    missing: &str,
) -> Result<String, ConservativeError> {
    if let Some(raw) = param_field(&step.params, "correlation_id") {
        if field_truthy(Some(raw)) {
            return render_parent(raw).map_err(ConservativeError::from);
        }
    }
    if let Some(index) = strict_index(step.target_index, events.len()) {
        if let Some(event) = events.get(index) {
            if let Some(corr) = event_corr_id(event)? {
                if !corr.is_empty() {
                    return Ok(corr);
                }
            }
        }
    }
    Err(precondition(missing).into())
}

/// An int index inside the slice. [`IndexValue::Bool`] is not an int.
fn strict_index(index: IndexValue, len: usize) -> Option<usize> {
    match index {
        IndexValue::Int(value) => checked_index(value, len),
        IndexValue::None | IndexValue::Bool(_) | IndexValue::Other => None,
    }
}

fn param_field<'a>(params: &'a ParamMap, key: &str) -> Option<&'a EventField> {
    match params {
        ParamMap::Mapping(mapping) => mapping.get(key),
        ParamMap::NotMapping => None,
    }
}

fn present_field<'a>(params: &'a ParamMap, key: &str) -> Option<&'a EventField> {
    match param_field(params, key) {
        Some(EventField::Null) | None => None,
        Some(field) => Some(field),
    }
}

fn is_call(event: &EventValue, corr: &str) -> Result<bool, EventError> {
    let kind = event_kind(event)?;
    if !matches!(kind.as_deref(), Some("tool_call" | "tool_use")) {
        return Ok(false);
    }
    Ok(event_corr_id(event)?.as_deref() == Some(corr))
}

fn is_result(event: &EventValue, corr: &str) -> Result<bool, EventError> {
    let kind = event_kind(event)?;
    if kind.as_deref() != Some("tool_result") {
        return Ok(false);
    }
    Ok(event_corr_id(event)?.as_deref() == Some(corr))
}

fn matching_indexes(
    events: &[EventValue],
    pred: impl Fn(&EventValue) -> Result<bool, EventError>,
) -> Result<Vec<(usize, &EventValue)>, ConservativeError> {
    let mut matched = Vec::new();
    for (index, event) in events.iter().enumerate() {
        if pred(event)? {
            matched.push((index, event));
        }
    }
    Ok(matched)
}

fn single_index(items: &[(usize, &EventValue)]) -> Option<usize> {
    match items.len() {
        1 => items.first().map(|(index, _)| *index),
        _ => None,
    }
}

fn boundary_hint<'a>(
    step: &'a RecipeStep,
    events: &[EventValue],
) -> Result<BoundaryHint<'a>, ConservativeError> {
    if let Some(field) = present_field(&step.params, "boundary_index") {
        return Ok(BoundaryHint::Field(field));
    }
    target_boundary_hint(step.target_index, events)
}

fn target_boundary_hint<'a>(
    target: IndexValue,
    events: &[EventValue],
) -> Result<BoundaryHint<'a>, ConservativeError> {
    let Some(index) = strict_index(target, events.len()) else {
        return Ok(BoundaryHint::Absent);
    };
    let Some(event) = events.get(index) else {
        return Ok(BoundaryHint::Absent);
    };
    if event_kind(event)?.as_deref() == Some("compaction_boundary") {
        return Ok(BoundaryHint::Index(index));
    }
    Ok(BoundaryHint::Absent)
}

fn hint_hits_endpoint(hint: &BoundaryHint<'_>, min_idx: usize, max_idx: usize) -> bool {
    match hint {
        BoundaryHint::Absent => false,
        BoundaryHint::Index(index) => *index == min_idx || *index == max_idx,
        BoundaryHint::Field(field) => {
            field_equals_index(field, min_idx) || field_equals_index(field, max_idx)
        }
    }
}

fn field_equals_index(field: &EventField, index: usize) -> bool {
    match field {
        EventField::Int(value) => index_equals(*value, index),
        EventField::Float(value) => float_equals_index(*value, index),
        EventField::Bool(_)
        | EventField::Null
        | EventField::Str(_)
        | EventField::List(_)
        | EventField::Mapping(_) => false,
    }
}

#[allow(
    clippy::float_cmp,
    clippy::cast_precision_loss,
    reason = "Python == of a float boundary_index against an int endpoint"
)]
fn float_equals_index(value: f64, index: usize) -> bool {
    let Ok(index) = i64::try_from(index) else {
        return false;
    };
    value == index as f64
}

fn index_equals(value: i64, index: usize) -> bool {
    usize::try_from(value).ok() == Some(index)
}

fn index_equals_value(target: IndexValue, index: usize) -> bool {
    match target {
        IndexValue::Int(value) => index_equals(value, index),
        IndexValue::None | IndexValue::Bool(_) | IndexValue::Other => false,
    }
}

fn endpoint_is_boundary(events: &[EventValue], index: usize) -> Result<bool, ConservativeError> {
    let Some(event) = events.get(index) else {
        return Ok(false);
    };
    Ok(event_kind(event)?.as_deref() == Some("compaction_boundary"))
}

fn boundaries_between(
    events: &[EventValue],
    min_idx: usize,
    max_idx: usize,
) -> Result<Vec<usize>, ConservativeError> {
    let mut found = Vec::new();
    let start = min_idx.saturating_add(1);
    if start >= max_idx {
        return Ok(found);
    }
    for index in start..max_idx {
        let Some(event) = events.get(index) else {
            break;
        };
        if event_kind(event)?.as_deref() == Some("compaction_boundary") {
            found.push(index);
        }
    }
    Ok(found)
}

fn only_usize(items: &[usize]) -> Option<usize> {
    match items.len() {
        1 => items.first().copied(),
        _ => None,
    }
}

/// Pop `from`, then insert at the original `to` (the pin's `max_idx`).
fn relocate_boundary(events: &mut Vec<EventMapping>, from: usize, to: usize) -> bool {
    if from >= events.len() || from >= to || to > events.len() {
        return false;
    }
    let event = events.remove(from);
    if to > events.len() {
        events.insert(from, event);
        return false;
    }
    events.insert(to, event);
    true
}

fn pair_error(corr: &str) -> ConservativeError {
    precondition(format!("{REUNION_PAIR_HEAD}{corr}{REUNION_PAIR_TAIL}")).into()
}

fn boundary_count_error(found: usize) -> ConservativeError {
    precondition(format!("{REUNION_BOUNDARY_HEAD}{found}")).into()
}

fn removal_count_error(corr: &str, found: usize) -> ConservativeError {
    precondition(format!("{REMOVAL_COUNT_HEAD}{corr}', found {found}")).into()
}

fn select_duplicate<'a>(
    target: IndexValue,
    results: &[(usize, &'a EventValue)],
) -> Result<(usize, &'a EventValue), ConservativeError> {
    let Some(&(_, kept)) = results.first() else {
        return Err(precondition(REMOVAL_DIFFER).into());
    };
    let kept_fingerprint = event_content_fingerprint(kept)?;
    if let Some(chosen) = targeted_later(target, results) {
        return same_fingerprint(chosen, &kept_fingerprint);
    }
    for &candidate in results.iter().skip(1) {
        let fingerprint = event_content_fingerprint(candidate.1)?;
        if fingerprint == kept_fingerprint {
            return Ok(candidate);
        }
    }
    Err(precondition(REMOVAL_DIFFER).into())
}

fn targeted_later<'a>(
    target: IndexValue,
    results: &[(usize, &'a EventValue)],
) -> Option<(usize, &'a EventValue)> {
    if matches!(target, IndexValue::None) {
        return None;
    }
    results
        .iter()
        .skip(1)
        .find(|item| index_equals_value(target, item.0))
        .copied()
}

fn same_fingerprint<'a>(
    candidate: (usize, &'a EventValue),
    kept_fingerprint: &str,
) -> Result<(usize, &'a EventValue), ConservativeError> {
    let fingerprint = event_content_fingerprint(candidate.1)?;
    if fingerprint != kept_fingerprint {
        return Err(precondition(REMOVAL_DIFFER).into());
    }
    Ok(candidate)
}

fn remove_copied(events: &mut Vec<EventMapping>, index: usize) -> bool {
    if index >= events.len() {
        return false;
    }
    events.remove(index);
    true
}

fn identical_duplicate_region_parts(
    step: &RecipeStep,
    events: &[EventValue],
) -> IdenticalDuplicateRegion {
    if events.len() < 2 {
        return IdenticalDuplicateRegion::Unproven;
    }
    // `collapse_index` is the pin's idx rule: a bool is not an int, so it scans.
    if let Some(index) = collapse_index(step) {
        let Some(position) = checked_index(index, events.len()) else {
            return IdenticalDuplicateRegion::Unproven;
        };
        let pairs = adjacent_candidates(position, events.len());
        return region_from_pairs(events, &pairs);
    }
    let last = events.len().saturating_sub(1);
    let pairs: Vec<(usize, usize)> = (0..last).map(|index| (index, index + 1)).collect();
    region_from_pairs(events, &pairs)
}

fn region_from_pairs(events: &[EventValue], pairs: &[(usize, usize)]) -> IdenticalDuplicateRegion {
    match first_matching_pair(events, pairs) {
        PairMatch::Found(keep_i, drop_i) => finish_region(events, keep_i, drop_i),
        PairMatch::None => IdenticalDuplicateRegion::Unproven,
        PairMatch::Stop(outcome) => outcome,
    }
}

fn first_matching_pair(events: &[EventValue], pairs: &[(usize, usize)]) -> PairMatch {
    for &(keep_i, drop_i) in pairs {
        match matching_pair(events, keep_i, drop_i) {
            Ok(true) => return PairMatch::Found(keep_i, drop_i),
            Ok(false) => {}
            Err(outcome) => return PairMatch::Stop(outcome),
        }
    }
    PairMatch::None
}

fn matching_pair(
    events: &[EventValue],
    keep_i: usize,
    drop_i: usize,
) -> Result<bool, IdenticalDuplicateRegion> {
    let Some((left, right)) = pair_refs(events, keep_i, drop_i) else {
        return Err(IdenticalDuplicateRegion::Unproven);
    };
    match eligible(left, right) {
        Ok(matched) => Ok(matched),
        Err(ConservativeError::Event(error)) => Err(IdenticalDuplicateRegion::Exception(error)),
        Err(ConservativeError::Precondition(_) | ConservativeError::ParentCandidates(_)) => {
            Err(IdenticalDuplicateRegion::Unproven)
        }
    }
}

fn finish_region(events: &[EventValue], keep_i: usize, drop_i: usize) -> IdenticalDuplicateRegion {
    let Some(kept_event) = events.get(keep_i) else {
        return IdenticalDuplicateRegion::Unproven;
    };
    let Some(dropped_event) = events.get(drop_i) else {
        return IdenticalDuplicateRegion::Unproven;
    };
    let kept_id = match event_id(kept_event) {
        Ok(id) => id,
        Err(error) => return IdenticalDuplicateRegion::Exception(error),
    };
    let dropped_id = match event_id(dropped_event) {
        Ok(id) => id,
        Err(error) => return IdenticalDuplicateRegion::Exception(error),
    };
    let mut indices = BTreeSet::from([keep_i, drop_i]);
    let mut ids = BTreeSet::new();
    if let Some(id) = nonempty_id(kept_id) {
        ids.insert(id);
    }
    if let Some(dropped_text) = nonempty_id(dropped_id) {
        ids.insert(dropped_text.clone());
        if let Err(outcome) = children_of(events, &dropped_text, &mut indices, &mut ids) {
            return outcome;
        }
    }
    IdenticalDuplicateRegion::Proven(DuplicateSpan {
        indices,
        ids,
        ranges: (keep_i.min(drop_i), keep_i.max(drop_i)),
    })
}

fn children_of(
    events: &[EventValue],
    dropped_id: &str,
    indices: &mut BTreeSet<usize>,
    ids: &mut BTreeSet<String>,
) -> Result<(), IdenticalDuplicateRegion> {
    for (index, event) in events.iter().enumerate() {
        match event_parent_id(event) {
            Ok(Some(parent)) if parent == dropped_id => {
                indices.insert(index);
                match event_id(event) {
                    Ok(Some(child_id)) if !child_id.is_empty() => {
                        ids.insert(child_id);
                    }
                    Ok(_) => {}
                    Err(error) => return Err(IdenticalDuplicateRegion::Exception(error)),
                }
            }
            Ok(_) => {}
            Err(error) => return Err(IdenticalDuplicateRegion::Exception(error)),
        }
    }
    Ok(())
}

fn nonempty_id(id: Option<String>) -> Option<String> {
    id.filter(|text| !text.is_empty())
}

#[cfg(test)]
mod tests_recipes_02 {
    use std::error::Error;

    use model::canonical::SessionEvent;
    use model::events::{
        copy_events_as_dicts, EventError, EventField, EventMapping, EventValue,
        DETERMINISM_CANONICAL_JSON_BYTES_UNAVAILABLE, PYTHON_FLOAT_STR_UNREPRESENTABLE,
        PYTHON_STR_UNREPRESENTABLE,
    };

    use super::{
        affected_region_identical_duplicate_collapse, apply_compaction_projection_reunion,
        apply_duplicate_projection_removal, compaction_projection_reunion,
        duplicate_projection_removal, identical_duplicate_region_parts, AffectedRegionUnavailable,
        ConservativeError, DuplicateSpan, IdenticalDuplicateRegion, IndexValue, ParamMap,
        RecipeStep, AFFECTED_REGION_UNAVAILABLE,
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

    fn none_step() -> RecipeStep {
        make_step(IndexValue::None, ParamMap::NotMapping)
    }

    fn target_step(index: i64) -> RecipeStep {
        make_step(IndexValue::Int(index), ParamMap::NotMapping)
    }

    fn row(kind: &str, id: &str, corr: Option<&str>, parent: Option<&str>) -> EventValue {
        let mut entries = vec![("kind", text(kind)), ("id", text(id))];
        if let Some(corr) = corr {
            entries.push(("correlation_id", text(corr)));
        }
        if let Some(parent) = parent {
            entries.push(("parent_id", text(parent)));
        }
        ev(entries)
    }

    fn result(id: &str, hash: &str, parent: Option<&str>) -> EventValue {
        let mut entries = vec![
            ("kind", text("tool_result")),
            ("id", text(id)),
            ("correlation_id", text("corr-synthetic")),
            ("content_hash", text(hash)),
        ];
        if let Some(parent) = parent {
            entries.push(("parent_id", text(parent)));
        }
        ev(entries)
    }

    fn note(id: &str, hash: &str, parent: Option<&str>) -> EventValue {
        let mut entries = vec![
            ("kind", text("note")),
            ("id", text(id)),
            ("content_hash", text(hash)),
        ];
        if let Some(parent) = parent {
            entries.push(("parent_id", text(parent)));
        }
        ev(entries)
    }

    fn field_str<'a>(mapping: &'a EventMapping, key: &str) -> Option<&'a str> {
        match mapping.get(key) {
            Some(EventField::Str(value)) => Some(value.as_str()),
            _ => None,
        }
    }

    fn ids(mappings: &[EventMapping]) -> Vec<Option<&str>> {
        mappings
            .iter()
            .map(|mapping| field_str(mapping, "id"))
            .collect()
    }

    fn snapshot(events: &[EventValue]) -> Vec<EventMapping> {
        events
            .iter()
            .map(|event| match event {
                EventValue::Mapping(mapping) => mapping.clone(),
                EventValue::Session(_) | EventValue::Other => EventMapping::new(Vec::new()),
            })
            .collect()
    }

    fn as_events(mappings: &[EventMapping]) -> Vec<EventValue> {
        mappings.iter().cloned().map(EventValue::Mapping).collect()
    }

    fn corr_step(target: IndexValue, corr: &str) -> RecipeStep {
        make_step(target, params_of(vec![("correlation_id", text(corr))]))
    }

    fn with_boundary(corr: &str, boundary: EventField) -> RecipeStep {
        make_step(
            IndexValue::None,
            params_of(vec![
                ("correlation_id", text(corr)),
                ("boundary_index", boundary),
            ]),
        )
    }

    fn precondition_text(result: Result<Vec<EventMapping>, ConservativeError>) -> String {
        let error = result.expect_err("precondition");
        assert!(matches!(error, ConservativeError::Precondition(_)));
        error.to_string()
    }

    fn assert_seam(step: &RecipeStep, events: &[EventValue]) {
        let error = affected_region_identical_duplicate_collapse(step, events)
            .expect_err("AffectedRegion is not available");
        assert_eq!(
            error.to_string(),
            "sesslint.policy.abstention.AffectedRegion is not available"
        );
        assert_eq!(error.to_string(), AFFECTED_REGION_UNAVAILABLE);
        assert_eq!(error.message(), error.to_string());
        assert_eq!(error, AffectedRegionUnavailable);
        assert!(Error::source(&error).is_none());
        assert_ne!(error.to_string(), "true");
        assert!(!error.to_string().contains("unproven"));
        assert!(!error.to_string().contains("evt-"));
    }

    fn moved_after(events: &[EventValue], from: usize, to: usize) -> Vec<EventMapping> {
        let mut copied = copy_events_as_dicts(events).expect("copy");
        let boundary = copied.remove(from);
        copied.insert(to, boundary);
        copied
    }

    #[test]
    fn reunion_moves_boundary_after_the_pair_and_leaves_the_input() {
        let events = vec![
            row("tool_call", "evt-call", Some("corr-synthetic"), None),
            row(
                "compaction_boundary",
                "evt-boundary",
                None,
                Some("evt-call"),
            ),
            row("message", "evt-mid", None, Some("evt-call")),
            row(
                "tool_result",
                "evt-result",
                Some("corr-synthetic"),
                Some("evt-call"),
            ),
            row("message", "evt-tail", None, Some("evt-result")),
        ];
        let before = snapshot(&events);
        let step = corr_step(IndexValue::Int(0), "corr-synthetic");
        let mut output = apply_compaction_projection_reunion(&events, &step).expect("move");
        assert_eq!(
            ids(&output),
            vec![
                Some("evt-call"),
                Some("evt-mid"),
                Some("evt-result"),
                Some("evt-boundary"),
                Some("evt-tail"),
            ]
        );
        assert_eq!(output, moved_after(&events, 1, 3));
        assert_eq!(
            compaction_projection_reunion(&events, &step).expect("alias"),
            output
        );
        output[0].push("marker", EventField::Int(1));
        assert_eq!(before, snapshot(&events));
    }

    #[test]
    fn reunion_accepts_tool_use_when_the_result_comes_first() {
        let events = vec![
            row("tool_result", "evt-result", Some("corr-synthetic"), None),
            row("message", "evt-mid", None, None),
            row("compaction_boundary", "evt-boundary", None, None),
            row("tool_use", "evt-call", Some("corr-synthetic"), None),
        ];
        let before = snapshot(&events);
        let output =
            apply_compaction_projection_reunion(&events, &target_step(3)).expect("reverse");
        assert_eq!(
            ids(&output),
            vec![
                Some("evt-result"),
                Some("evt-mid"),
                Some("evt-call"),
                Some("evt-boundary"),
            ]
        );
        assert_eq!(output, moved_after(&events, 2, 3));
        assert_eq!(before, snapshot(&events));
    }

    #[test]
    fn reunion_correlation_truthiness_and_bool_index() {
        let events = vec![
            row("message", "evt-note", None, None),
            row("tool_call", "evt-call", Some("corr-synthetic"), None),
            row("compaction_boundary", "evt-boundary", None, None),
            row("tool_result", "evt-result", Some("corr-synthetic"), None),
        ];
        let from_target = make_step(IndexValue::Int(1), ParamMap::NotMapping);
        let output = apply_compaction_projection_reunion(&events, &from_target).expect("target");
        assert_eq!(
            ids(&output),
            vec![
                Some("evt-note"),
                Some("evt-call"),
                Some("evt-result"),
                Some("evt-boundary"),
            ]
        );

        let falsy = make_step(
            IndexValue::Int(1),
            params_of(vec![
                ("correlation_id", EventField::Int(0)),
                ("ignored", text("nope")),
            ]),
        );
        assert_eq!(
            ids(&apply_compaction_projection_reunion(&events, &falsy).expect("falsy int")),
            ids(&output)
        );
        let empty = make_step(
            IndexValue::Int(1),
            params_of(vec![("correlation_id", text(""))]),
        );
        assert!(apply_compaction_projection_reunion(&events, &empty).is_ok());
        let false_param = make_step(
            IndexValue::Int(1),
            params_of(vec![("correlation_id", EventField::Bool(false))]),
        );
        assert!(apply_compaction_projection_reunion(&events, &false_param).is_ok());

        let bool_index = make_step(IndexValue::Bool(true), ParamMap::NotMapping);
        assert_eq!(
            precondition_text(apply_compaction_projection_reunion(&events, &bool_index)),
            "compaction-projection-reunion: missing correlation_id"
        );
        assert_eq!(
            precondition_text(apply_compaction_projection_reunion(&events, &none_step())),
            "compaction-projection-reunion: missing correlation_id"
        );

        let rendered = vec![
            row("tool_call", "evt-call", Some("True"), None),
            row("compaction_boundary", "evt-boundary", None, None),
            row("tool_result", "evt-result", Some("True"), None),
        ];
        let true_param = make_step(
            IndexValue::None,
            params_of(vec![("correlation_id", EventField::Bool(true))]),
        );
        assert!(apply_compaction_projection_reunion(&rendered, &true_param).is_ok());
        let numeric = corr_step(IndexValue::None, "1");
        assert_eq!(
            precondition_text(apply_compaction_projection_reunion(&rendered, &numeric)),
            "compaction-projection-reunion: pair for correlation '1' must have exactly 1 call and 1 result"
        );

        let zero_events = vec![
            ev(vec![
                ("kind", text("tool_call")),
                ("id", text("evt-call")),
                ("correlation_id", EventField::Int(0)),
            ]),
            row("compaction_boundary", "evt-boundary", None, None),
            ev(vec![
                ("kind", text("tool_result")),
                ("id", text("evt-result")),
                ("correlation_id", EventField::Int(0)),
            ]),
        ];
        let zero_step = make_step(IndexValue::Int(0), ParamMap::NotMapping);
        assert!(apply_compaction_projection_reunion(&zero_events, &zero_step).is_ok());
    }

    #[test]
    fn reunion_refuses_unclean_pairs_and_boundary_counts() {
        let step = corr_step(IndexValue::None, "corr-synthetic");
        let two_calls = vec![
            row("tool_call", "evt-a", Some("corr-synthetic"), None),
            row("tool_use", "evt-b", Some("corr-synthetic"), None),
            row("tool_result", "evt-c", Some("corr-synthetic"), None),
        ];
        assert_eq!(
            precondition_text(apply_compaction_projection_reunion(&two_calls, &step)),
            "compaction-projection-reunion: pair for correlation 'corr-synthetic' must have exactly 1 call and 1 result"
        );
        let no_result = vec![
            row("tool_call", "evt-a", Some("corr-synthetic"), None),
            row("message", "evt-b", Some("corr-synthetic"), None),
        ];
        assert_eq!(
            precondition_text(apply_compaction_projection_reunion(&no_result, &step)),
            "compaction-projection-reunion: pair for correlation 'corr-synthetic' must have exactly 1 call and 1 result"
        );
        let adjacent = vec![
            row("tool_call", "evt-call", Some("corr-synthetic"), None),
            row("tool_result", "evt-result", Some("corr-synthetic"), None),
        ];
        assert_eq!(
            precondition_text(apply_compaction_projection_reunion(&adjacent, &step)),
            "compaction-projection-reunion: expected exactly 1 boundary strictly between pair, found 0"
        );
        let two_boundaries = vec![
            row("tool_call", "evt-call", Some("corr-synthetic"), None),
            row("compaction_boundary", "evt-b1", None, None),
            row("compaction_boundary", "evt-b2", None, None),
            row("tool_result", "evt-result", Some("corr-synthetic"), None),
        ];
        assert_eq!(
            precondition_text(apply_compaction_projection_reunion(&two_boundaries, &step)),
            "compaction-projection-reunion: expected exactly 1 boundary strictly between pair, found 2"
        );
        let endpoint = vec![
            row("tool_call", "evt-call", Some("corr-synthetic"), None),
            row("compaction_boundary", "evt-boundary", None, None),
            row("tool_result", "evt-result", Some("corr-synthetic"), None),
        ];
        let hinted = with_boundary("corr-synthetic", EventField::Int(0));
        assert_eq!(
            precondition_text(apply_compaction_projection_reunion(&endpoint, &hinted)),
            "compaction-projection-reunion: boundary sits at pair endpoint (not strictly between)"
        );
        let on_boundary = with_boundary("corr-synthetic", EventField::Int(1));
        assert!(apply_compaction_projection_reunion(&endpoint, &on_boundary).is_ok());
    }

    #[test]
    fn reunion_bool_boundary_index_is_not_an_int() {
        let min_one = vec![
            row("message", "evt-note", None, None),
            row("tool_call", "evt-call", Some("corr-synthetic"), None),
            row("compaction_boundary", "evt-boundary", None, None),
            row("tool_result", "evt-result", Some("corr-synthetic"), None),
        ];
        let moved = vec![
            Some("evt-note"),
            Some("evt-call"),
            Some("evt-result"),
            Some("evt-boundary"),
        ];
        for boundary in [
            EventField::Bool(true),
            EventField::Float(1.5),
            EventField::Str("1".to_owned()),
            EventField::Null,
        ] {
            let output = apply_compaction_projection_reunion(
                &min_one,
                &with_boundary("corr-synthetic", boundary),
            )
            .expect("not an int endpoint");
            assert_eq!(ids(&output), moved);
        }
        for boundary in [
            EventField::Float(1.0),
            EventField::Int(1),
            EventField::Int(3),
        ] {
            assert_eq!(
                precondition_text(apply_compaction_projection_reunion(
                    &min_one,
                    &with_boundary("corr-synthetic", boundary),
                )),
                "compaction-projection-reunion: boundary sits at pair endpoint (not strictly between)"
            );
        }

        let min_zero = vec![
            row("tool_call", "evt-call", Some("corr-synthetic"), None),
            row("compaction_boundary", "evt-boundary", None, None),
            row("tool_result", "evt-result", Some("corr-synthetic"), None),
        ];
        let output = apply_compaction_projection_reunion(
            &min_zero,
            &with_boundary("corr-synthetic", EventField::Bool(false)),
        )
        .expect("false is not zero");
        assert_eq!(
            ids(&output),
            vec![Some("evt-call"), Some("evt-result"), Some("evt-boundary")]
        );
        assert_eq!(
            precondition_text(apply_compaction_projection_reunion(
                &min_zero,
                &with_boundary("corr-synthetic", EventField::Int(0)),
            )),
            "compaction-projection-reunion: boundary sits at pair endpoint (not strictly between)"
        );
    }

    #[test]
    fn reunion_errors_are_event_errors_not_pair_messages() {
        let pair_message =
            "compaction-projection-reunion: pair for correlation 'corr-synthetic' must have exactly 1 call and 1 result";
        let events = vec![
            ev(vec![
                ("kind", text("message")),
                ("id", text("evt-float")),
                ("correlation_id", EventField::Float(1.5)),
            ]),
            row("tool_call", "evt-call", Some("corr-synthetic"), None),
            row("compaction_boundary", "evt-boundary", None, None),
            row("tool_result", "evt-result", Some("corr-synthetic"), None),
        ];
        assert!(apply_compaction_projection_reunion(
            &events,
            &corr_step(IndexValue::None, "corr-synthetic")
        )
        .is_ok());

        let float_call = vec![
            ev(vec![
                ("kind", text("tool_call")),
                ("id", text("evt-call")),
                ("correlation_id", EventField::Float(1.5)),
            ]),
            row("compaction_boundary", "evt-boundary", None, None),
            row("tool_result", "evt-result", Some("corr-synthetic"), None),
        ];
        let error = apply_compaction_projection_reunion(
            &float_call,
            &corr_step(IndexValue::None, "corr-synthetic"),
        )
        .expect_err("float correlation");
        assert_eq!(error.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        assert!(matches!(
            error,
            ConservativeError::Event(EventError::PythonFloatStr)
        ));
        assert_ne!(error.to_string(), pair_message);

        let float_param = make_step(
            IndexValue::None,
            params_of(vec![("correlation_id", EventField::Float(1.5))]),
        );
        let error = apply_compaction_projection_reunion(&events, &float_param).expect_err("param");
        assert_eq!(error.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        let list_param = make_step(
            IndexValue::None,
            params_of(vec![(
                "correlation_id",
                EventField::List(vec![EventField::Int(1)]),
            )]),
        );
        let error = apply_compaction_projection_reunion(&events, &list_param).expect_err("list");
        assert_eq!(error.to_string(), PYTHON_STR_UNREPRESENTABLE);

        let mut call = SessionEvent::new(
            "evt-call",
            None,
            0,
            "2026-01-01T00:00:00Z",
            "tool",
            "tool_call",
        );
        call.correlation_id = Some("corr-synthetic".to_owned());
        let mut result = SessionEvent::new(
            "evt-result",
            None,
            2,
            "2026-01-01T00:00:00Z",
            "tool",
            "tool_result",
        );
        result.correlation_id = Some("corr-synthetic".to_owned());
        let session_events = vec![
            EventValue::from_session(call),
            row("compaction_boundary", "evt-boundary", None, None),
            EventValue::from_session(result),
        ];
        let error = apply_compaction_projection_reunion(
            &session_events,
            &corr_step(IndexValue::None, "corr-synthetic"),
        )
        .expect_err("copy");
        let direct = copy_events_as_dicts(&session_events).expect_err("direct");
        assert_eq!(error.to_string(), direct.to_string());
        assert!(matches!(error, ConservativeError::Event(_)));
        assert_ne!(error.to_string(), pair_message);
    }

    #[test]
    fn removal_rewrites_child_parent_and_keeps_equal_ids() {
        let events = vec![
            row("tool_call", "evt-call", Some("corr-synthetic"), None),
            result("evt-kept", "hash-same", Some("evt-call")),
            result("evt-drop", "hash-same", Some("evt-call")),
            row("message", "evt-child", None, Some("evt-drop")),
        ];
        let before = snapshot(&events);
        let step = corr_step(IndexValue::Int(2), "corr-synthetic");
        let output = apply_duplicate_projection_removal(&events, &step).expect("drop");
        assert_eq!(
            ids(&output),
            vec![Some("evt-call"), Some("evt-kept"), Some("evt-child")]
        );
        assert_eq!(field_str(&output[2], "parent_id"), Some("evt-kept"));
        assert_eq!(field_str(&output[1], "parent_id"), Some("evt-call"));
        assert_eq!(
            duplicate_projection_removal(&events, &step).expect("alias"),
            output
        );
        assert_eq!(before, snapshot(&events));
        let again = as_events(&output);
        assert_eq!(
            precondition_text(apply_duplicate_projection_removal(&again, &step)),
            "duplicate-projection-removal: expected at least 2 results for correlation 'corr-synthetic', found 1"
        );

        let same_id = vec![
            result("evt-same", "hash-same", None),
            result("evt-same", "hash-same", None),
            row("message", "evt-child", None, Some("evt-same")),
        ];
        let output = apply_duplicate_projection_removal(
            &same_id,
            &corr_step(IndexValue::None, "corr-synthetic"),
        )
        .expect("same id");
        assert_eq!(ids(&output), vec![Some("evt-same"), Some("evt-child")]);
        assert_eq!(field_str(&output[1], "parent_id"), Some("evt-same"));

        let nameless = vec![
            ev(vec![
                ("kind", text("tool_result")),
                ("correlation_id", text("corr-synthetic")),
                ("content_hash", text("hash-same")),
            ]),
            ev(vec![
                ("kind", text("tool_result")),
                ("correlation_id", text("corr-synthetic")),
                ("content_hash", text("hash-same")),
            ]),
            row("message", "evt-child", None, Some("evt-other")),
        ];
        let output = apply_duplicate_projection_removal(
            &nameless,
            &corr_step(IndexValue::None, "corr-synthetic"),
        )
        .expect("nameless");
        assert_eq!(field_str(&output[1], "parent_id"), Some("evt-other"));
        assert_eq!(output.len(), 2);
    }

    #[test]
    fn removal_target_bool_and_fingerprint_selection() {
        let events = vec![
            result("evt-kept", "hash-a", None),
            result("evt-early", "hash-a", None),
            result("evt-later", "hash-a", None),
            row("message", "evt-child", None, Some("evt-later")),
        ];
        let scanned = apply_duplicate_projection_removal(
            &events,
            &corr_step(IndexValue::None, "corr-synthetic"),
        )
        .expect("scan");
        assert_eq!(
            ids(&scanned),
            vec![Some("evt-kept"), Some("evt-later"), Some("evt-child")]
        );
        assert_eq!(field_str(&scanned[2], "parent_id"), Some("evt-later"));
        let targeted = apply_duplicate_projection_removal(
            &events,
            &corr_step(IndexValue::Int(2), "corr-synthetic"),
        )
        .expect("target later");
        assert_eq!(
            ids(&targeted),
            vec![Some("evt-kept"), Some("evt-early"), Some("evt-child")]
        );
        assert_eq!(field_str(&targeted[2], "parent_id"), Some("evt-kept"));

        let mixed = vec![
            result("evt-kept", "hash-a", None),
            result("evt-other", "hash-b", None),
            result("evt-match", "hash-a", None),
            row("message", "evt-child", None, Some("evt-match")),
        ];
        let before = snapshot(&mixed);
        assert_eq!(
            precondition_text(apply_duplicate_projection_removal(
                &mixed,
                &corr_step(IndexValue::Int(1), "corr-synthetic")
            )),
            "duplicate-projection-removal: projection fingerprints differ (refusing near-match collapse)"
        );
        assert_eq!(before, snapshot(&mixed));
        let from_bool = apply_duplicate_projection_removal(
            &mixed,
            &corr_step(IndexValue::Bool(true), "corr-synthetic"),
        )
        .expect("bool is not 1");
        assert_eq!(
            ids(&from_bool),
            vec![Some("evt-kept"), Some("evt-other"), Some("evt-child")]
        );
        assert_eq!(field_str(&from_bool[2], "parent_id"), Some("evt-kept"));
    }

    #[test]
    fn removal_messages_for_difference_and_short_lists() {
        let step = corr_step(IndexValue::None, "corr-synthetic");
        let differ = vec![
            result("evt-kept", "hash-left", None),
            result("evt-drop", "hash-right", None),
        ];
        let before = snapshot(&differ);
        assert_eq!(
            precondition_text(apply_duplicate_projection_removal(&differ, &step)),
            "duplicate-projection-removal: projection fingerprints differ (refusing near-match collapse)"
        );
        assert_eq!(before, snapshot(&differ));
        let one = vec![result("evt-only", "hash-left", None)];
        assert_eq!(
            precondition_text(apply_duplicate_projection_removal(&one, &step)),
            "duplicate-projection-removal: expected at least 2 results for correlation 'corr-synthetic', found 1"
        );
        let none = vec![row("message", "evt-note", Some("corr-synthetic"), None)];
        assert_eq!(
            precondition_text(apply_duplicate_projection_removal(&none, &step)),
            "duplicate-projection-removal: expected at least 2 results for correlation 'corr-synthetic', found 0"
        );
        assert_eq!(
            precondition_text(apply_duplicate_projection_removal(&differ, &none_step())),
            "duplicate-projection-removal: missing correlation_id"
        );
    }

    #[test]
    fn removal_fingerprint_error_is_not_a_difference() {
        let gap = ev(vec![
            ("kind", text("tool_result")),
            ("id", text("evt-gap")),
            ("correlation_id", text("corr-synthetic")),
        ]);
        let events = vec![
            result("evt-kept", "hash-a", None),
            gap,
            result("evt-match", "hash-a", None),
        ];
        let before = snapshot(&events);
        let error = apply_duplicate_projection_removal(
            &events,
            &corr_step(IndexValue::None, "corr-synthetic"),
        )
        .expect_err("gap fingerprint");
        assert_eq!(
            error.to_string(),
            DETERMINISM_CANONICAL_JSON_BYTES_UNAVAILABLE
        );
        assert!(matches!(
            error,
            ConservativeError::Event(EventError::DeterminismCanonicalJsonBytes)
        ));
        assert_ne!(
            error.to_string(),
            "duplicate-projection-removal: projection fingerprints differ (refusing near-match collapse)"
        );
        assert_eq!(before, snapshot(&events));
        let error = apply_duplicate_projection_removal(
            &events,
            &corr_step(IndexValue::Int(1), "corr-synthetic"),
        )
        .expect_err("targeted gap");
        assert_eq!(
            error.to_string(),
            DETERMINISM_CANONICAL_JSON_BYTES_UNAVAILABLE
        );
        let output = apply_duplicate_projection_removal(
            &events,
            &corr_step(IndexValue::Int(2), "corr-synthetic"),
        )
        .expect("target skips the gap");
        assert_eq!(ids(&output), vec![Some("evt-kept"), Some("evt-gap")]);

        let mut first = SessionEvent::new(
            "evt-kept",
            None,
            0,
            "2026-01-01T00:00:00Z",
            "tool",
            "tool_result",
        );
        first.correlation_id = Some("corr-synthetic".to_owned());
        first.content_hash = Some("hash-same".to_owned());
        let mut second = SessionEvent::new(
            "evt-drop",
            None,
            1,
            "2026-01-01T00:00:00Z",
            "tool",
            "tool_result",
        );
        second.correlation_id = Some("corr-synthetic".to_owned());
        second.content_hash = Some("hash-same".to_owned());
        let session_events = vec![
            EventValue::from_session(first),
            EventValue::from_session(second),
        ];
        let error = apply_duplicate_projection_removal(
            &session_events,
            &corr_step(IndexValue::None, "corr-synthetic"),
        )
        .expect_err("session copy");
        let direct = copy_events_as_dicts(&session_events).expect_err("direct");
        assert_eq!(error.to_string(), direct.to_string());
        assert!(matches!(error, ConservativeError::Event(_)));
        assert_ne!(
            error.to_string(),
            "duplicate-projection-removal: projection fingerprints differ (refusing near-match collapse)"
        );
    }

    fn proven_span(
        indices: Vec<usize>,
        ids: &[&str],
        ranges: (usize, usize),
    ) -> IdenticalDuplicateRegion {
        IdenticalDuplicateRegion::Proven(DuplicateSpan {
            indices: indices.into_iter().collect(),
            ids: ids.iter().map(|id| (*id).to_owned()).collect(),
            ranges,
        })
    }

    #[test]
    fn region_proven_children_display_the_seam() {
        let events = vec![
            note("evt-kept", "hash-same", None),
            note("evt-drop", "hash-same", None),
            note("evt-child", "hash-other", Some("evt-drop")),
            ev(vec![
                ("kind", text("message")),
                ("parent_id", text("evt-drop")),
            ]),
        ];
        let before = snapshot(&events);
        let step = none_step();
        assert_eq!(
            identical_duplicate_region_parts(&step, &events),
            proven_span(
                vec![0, 1, 2, 3],
                &["evt-kept", "evt-drop", "evt-child"],
                (0, 1)
            )
        );
        assert_eq!(
            identical_duplicate_region_parts(
                &make_step(IndexValue::Int(0), ParamMap::NotMapping),
                &events
            ),
            proven_span(
                vec![0, 1, 2, 3],
                &["evt-kept", "evt-drop", "evt-child"],
                (0, 1)
            )
        );
        assert_seam(&step, &events);
        assert_eq!(before, snapshot(&events));

        let nameless = vec![
            ev(vec![
                ("id", text("evt-a")),
                ("content_hash", text("hash-same")),
            ]),
            ev(vec![
                ("id", text("evt-b")),
                ("content_hash", text("hash-same")),
            ]),
        ];
        assert_eq!(
            identical_duplicate_region_parts(&none_step(), &nameless),
            proven_span(vec![0, 1], &["evt-a", "evt-b"], (0, 1))
        );
        assert_seam(&none_step(), &nameless);
    }

    #[test]
    fn region_bool_scans_and_int_params_do_not() {
        let events = vec![
            note("evt-0", "hash-same", None),
            note("evt-1", "hash-same", None),
            note("evt-2", "hash-same", Some("evt-1")),
        ];
        let scanned = proven_span(vec![0, 1, 2], &["evt-0", "evt-1", "evt-2"], (0, 1));
        let indexed = proven_span(vec![1, 2], &["evt-1", "evt-2"], (1, 2));
        assert_eq!(
            identical_duplicate_region_parts(
                &make_step(IndexValue::Int(1), ParamMap::NotMapping),
                &events
            ),
            indexed
        );
        assert_eq!(
            identical_duplicate_region_parts(
                &make_step(IndexValue::Bool(true), ParamMap::NotMapping),
                &events
            ),
            scanned
        );
        assert_eq!(
            identical_duplicate_region_parts(
                &make_step(IndexValue::Other, ParamMap::NotMapping),
                &events
            ),
            scanned
        );
        let bool_hides_param = make_step(
            IndexValue::Bool(true),
            params_of(vec![("index", EventField::Int(1))]),
        );
        assert_eq!(
            identical_duplicate_region_parts(&bool_hides_param, &events),
            scanned
        );
        let param_index = make_step(
            IndexValue::None,
            params_of(vec![
                ("at_index", EventField::Bool(true)),
                ("index", EventField::Int(1)),
            ]),
        );
        assert_eq!(
            identical_duplicate_region_parts(&param_index, &events),
            indexed
        );
        let only_bool_param = make_step(
            IndexValue::None,
            params_of(vec![("at_index", EventField::Bool(false))]),
        );
        assert_eq!(
            identical_duplicate_region_parts(&only_bool_param, &events),
            scanned
        );
        let first_index = make_step(
            IndexValue::None,
            params_of(vec![("first_index", EventField::Int(1))]),
        );
        assert_eq!(
            identical_duplicate_region_parts(&first_index, &events),
            indexed
        );
        assert_seam(&bool_hides_param, &events);
        assert_seam(&param_index, &events);
    }

    #[test]
    fn region_short_and_boundary_kinds_are_unproven() {
        assert_eq!(
            identical_duplicate_region_parts(&none_step(), &[]),
            IdenticalDuplicateRegion::Unproven
        );
        assert_seam(&none_step(), &[]);
        let one = vec![note("evt-only", "hash-same", None)];
        assert_eq!(
            identical_duplicate_region_parts(&none_step(), &one),
            IdenticalDuplicateRegion::Unproven
        );
        assert_seam(&none_step(), &one);

        let bare_notes = vec![
            row("note", "evt-a", None, None),
            row("note", "evt-b", None, None),
        ];
        let high = make_step(IndexValue::Int(9), ParamMap::NotMapping);
        assert_eq!(
            identical_duplicate_region_parts(&high, &bare_notes),
            IdenticalDuplicateRegion::Unproven
        );
        let negative = make_step(IndexValue::Int(-1), ParamMap::NotMapping);
        assert_eq!(
            identical_duplicate_region_parts(&negative, &bare_notes),
            IdenticalDuplicateRegion::Unproven
        );
        assert_eq!(
            identical_duplicate_region_parts(&none_step(), &bare_notes),
            IdenticalDuplicateRegion::Exception(EventError::DeterminismCanonicalJsonBytes)
        );
        assert_seam(&high, &bare_notes);
        assert_seam(&none_step(), &bare_notes);

        let checkpoints = vec![
            ev(vec![("kind", text("checkpoint")), ("id", text("evt-a"))]),
            ev(vec![("kind", text("checkpoint")), ("id", text("evt-b"))]),
        ];
        assert_eq!(
            identical_duplicate_region_parts(&none_step(), &checkpoints),
            IdenticalDuplicateRegion::Unproven
        );
        let boundaries = vec![
            ev(vec![
                ("kind", text("compaction_boundary")),
                ("id", text("evt-a")),
            ]),
            ev(vec![
                ("kind", text("compaction_boundary")),
                ("id", text("evt-b")),
            ]),
        ];
        assert_eq!(
            identical_duplicate_region_parts(
                &make_step(IndexValue::Int(0), ParamMap::NotMapping),
                &boundaries
            ),
            IdenticalDuplicateRegion::Unproven
        );
        let mismatch = vec![
            note("evt-a", "hash-same", None),
            ev(vec![
                ("kind", text("tool_result")),
                ("id", text("evt-b")),
                ("content_hash", text("hash-same")),
            ]),
        ];
        assert_eq!(
            identical_duplicate_region_parts(&none_step(), &mismatch),
            IdenticalDuplicateRegion::Unproven
        );
        assert_seam(&none_step(), &checkpoints);
    }

    #[test]
    fn region_errors_do_not_select_a_later_pair() {
        let blocked = vec![
            row("note", "evt-a", None, None),
            note("evt-b", "hash-same", None),
            note("evt-c", "hash-same", None),
        ];
        assert_eq!(
            identical_duplicate_region_parts(&none_step(), &blocked),
            IdenticalDuplicateRegion::Exception(EventError::DeterminismCanonicalJsonBytes)
        );
        let seam_text = affected_region_identical_duplicate_collapse(&none_step(), &blocked)
            .expect_err("seam")
            .to_string();
        assert_eq!(
            seam_text,
            "sesslint.policy.abstention.AffectedRegion is not available"
        );
        assert!(!seam_text.contains("canonical_json"));
        assert!(!seam_text.contains("representable"));
        assert_ne!(seam_text, "true");

        let float_id = vec![
            ev(vec![
                ("kind", text("note")),
                ("id", EventField::Float(1.5)),
                ("content_hash", text("hash-same")),
            ]),
            note("evt-b", "hash-same", None),
        ];
        assert_eq!(
            identical_duplicate_region_parts(&none_step(), &float_id),
            IdenticalDuplicateRegion::Exception(EventError::PythonFloatStr)
        );
        assert_seam(&none_step(), &float_id);

        let float_parent = vec![
            note("evt-kept", "hash-same", None),
            note("evt-drop", "hash-same", None),
            ev(vec![
                ("kind", text("message")),
                ("id", text("evt-child")),
                ("parent_id", EventField::Float(1.5)),
            ]),
        ];
        assert_eq!(
            identical_duplicate_region_parts(&none_step(), &float_parent),
            IdenticalDuplicateRegion::Exception(EventError::PythonFloatStr)
        );
        assert_seam(&none_step(), &float_parent);

        let others = vec![EventValue::Other, EventValue::Other];
        assert_eq!(
            identical_duplicate_region_parts(&none_step(), &others),
            IdenticalDuplicateRegion::Exception(EventError::PythonStrHash)
        );
        assert_seam(&none_step(), &others);
    }
}

// Port of `src/sesslint/repair/recipes_conservative.py` lines 531-773
// @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//
// The three region functions run the pin's pure checks. Every return in the
// pin constructs `sesslint.policy.abstention.AffectedRegion`. This crate
// cannot construct that type and does not invent one. `register_all` is not
// in this slice. `sesslint.checks` is not called.

// Pure-check trace. Not `sesslint.policy.abstention.AffectedRegion`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CheckSpan {
    indices: BTreeSet<usize>,
    ids: BTreeSet<String>,
    ranges: Vec<(usize, usize)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckFailure {
    Unproven,
    Exception(EventError),
}

/// Run the proven-unique-parent region checks, then stop.
///
/// Python: `affected_region_proven_unique_parent_restore`. Argument order is
/// `step`, then `events`. Empty input is unproven before params are read.
/// [`IndexValue::Bool`] is not an int. A falsy `index` param falls through to
/// `at_index`. A truthy non-int does not. A truthy `parent_id` or
/// `parent_fingerprint_prefix` wins; otherwise the target's parent id is
/// used. One exact id match wins. A prefix match runs only when no id is
/// equal. An event-helper error stops that walk.
///
/// Every return in the pin constructs
/// `sesslint.policy.abstention.AffectedRegion`. This crate cannot construct
/// that type and does not invent a region. Each of those returns is
/// [`AffectedRegionUnavailable`]. Display is [`AFFECTED_REGION_UNAVAILABLE`].
/// This is not `true`. `find_qualifying_parent_candidates` is not called.
///
/// # Errors
///
/// Always returns [`AffectedRegionUnavailable`] after the checks that apply.
/// This function does not panic.
pub fn affected_region_proven_unique_parent_restore(
    step: &RecipeStep,
    events: &[EventValue],
) -> Result<Infallible, AffectedRegionUnavailable> {
    Err(refuse_check(proven_unique_parent_restore_check(
        step, events,
    )))
}

/// Run the compaction-projection region checks, then stop.
///
/// Python: `affected_region_compaction_projection_reunion`. Argument order is
/// `step`, then `events`. A truthy `correlation_id` param is rendered with
/// `str`. Falsy values fall through to an in-range int `target_index`.
/// [`IndexValue::Bool`] is not that index. Calls are `tool_call` or
/// `tool_use`. Results are `tool_result`. Both cardinalities must be 1.
/// Exactly one `compaction_boundary` must sit strictly between the pair. Ids
/// in that closed span keep an empty string. `None` is omitted.
///
/// Every return in the pin constructs
/// `sesslint.policy.abstention.AffectedRegion`. This crate cannot construct
/// that type and does not invent a region. Each of those returns is
/// [`AffectedRegionUnavailable`]. Display is [`AFFECTED_REGION_UNAVAILABLE`].
/// This is not `true`.
///
/// # Errors
///
/// Always returns [`AffectedRegionUnavailable`] after the checks that apply.
/// This function does not panic.
pub fn affected_region_compaction_projection_reunion(
    step: &RecipeStep,
    events: &[EventValue],
) -> Result<Infallible, AffectedRegionUnavailable> {
    Err(refuse_check(compaction_projection_reunion_check(
        step, events,
    )))
}

/// Run the duplicate-projection region checks, then stop.
///
/// Python: `affected_region_duplicate_projection_removal`. Argument order is
/// `step`, then `events`. Correlation resolution matches
/// [`affected_region_compaction_projection_reunion`]. At least two
/// `tool_result` rows must share that id. The kept fingerprint is the first
/// result. [`IndexValue::Bool`] is not an int, so it does not select a later
/// row. A selected row whose fingerprint differs is unproven and does not
/// fall through. A fingerprint error stops that walk. Matching calls and
/// children of the dropped id are included. Ranges stay empty.
///
/// Every return in the pin constructs
/// `sesslint.policy.abstention.AffectedRegion`. This crate cannot construct
/// that type and does not invent a region. Each of those returns is
/// [`AffectedRegionUnavailable`]. Display is [`AFFECTED_REGION_UNAVAILABLE`].
/// This is not `true`.
///
/// # Errors
///
/// Always returns [`AffectedRegionUnavailable`] after the checks that apply.
/// This function does not panic.
pub fn affected_region_duplicate_projection_removal(
    step: &RecipeStep,
    events: &[EventValue],
) -> Result<Infallible, AffectedRegionUnavailable> {
    Err(refuse_check(duplicate_projection_removal_check(
        step, events,
    )))
}

fn refuse_check(outcome: Result<CheckSpan, CheckFailure>) -> AffectedRegionUnavailable {
    match outcome {
        Ok(span) => {
            let _checked = (span.indices.len(), span.ids.len(), span.ranges.len());
            AffectedRegionUnavailable
        }
        Err(CheckFailure::Exception(error)) => {
            let _checked = error.message().len();
            AffectedRegionUnavailable
        }
        Err(CheckFailure::Unproven) => AffectedRegionUnavailable,
    }
}

fn proven_unique_parent_restore_check(
    step: &RecipeStep,
    events: &[EventValue],
) -> Result<CheckSpan, CheckFailure> {
    if events.is_empty() {
        return Err(CheckFailure::Unproven);
    }
    let Some(target_idx) = restore_region_index(step, events.len()) else {
        return Err(CheckFailure::Unproven);
    };
    let Some(target_ev) = events.get(target_idx) else {
        return Err(CheckFailure::Unproven);
    };
    let parent_id = match restore_region_parent(step, target_ev).map_err(CheckFailure::Exception)?
    {
        Some(parent) if !parent.is_empty() => parent,
        Some(_) | None => return Err(CheckFailure::Unproven),
    };
    let parent_indices = parent_indexes(events, &parent_id).map_err(CheckFailure::Exception)?;
    let Some(parent_idx) = only_usize(&parent_indices) else {
        return Err(CheckFailure::Unproven);
    };
    let Some(parent_ev) = events.get(parent_idx) else {
        return Err(CheckFailure::Unproven);
    };
    let child_id = event_id(target_ev).map_err(CheckFailure::Exception)?;
    let parent_ev_id = event_id(parent_ev).map_err(CheckFailure::Exception)?;
    let mut ids = BTreeSet::new();
    insert_nonempty(&mut ids, child_id.as_deref());
    insert_nonempty(&mut ids, parent_ev_id.as_deref());
    ids.insert(parent_id);
    Ok(CheckSpan {
        indices: BTreeSet::from([target_idx, parent_idx]),
        ids,
        ranges: Vec::new(),
    })
}

fn compaction_projection_reunion_check(
    step: &RecipeStep,
    events: &[EventValue],
) -> Result<CheckSpan, CheckFailure> {
    if events.is_empty() {
        return Err(CheckFailure::Unproven);
    }
    let corr = required_corr(events, step)?;
    let calls =
        indexes_where(events, |event| is_call(event, &corr)).map_err(CheckFailure::Exception)?;
    let results =
        indexes_where(events, |event| is_result(event, &corr)).map_err(CheckFailure::Exception)?;
    let Some(call_index) = only_usize(&calls) else {
        return Err(CheckFailure::Unproven);
    };
    let Some(result_index) = only_usize(&results) else {
        return Err(CheckFailure::Unproven);
    };
    let min_idx = call_index.min(result_index);
    let max_idx = call_index.max(result_index);
    let boundaries = match boundaries_between(events, min_idx, max_idx) {
        Ok(found) => found,
        Err(ConservativeError::Event(error)) => return Err(CheckFailure::Exception(error)),
        Err(ConservativeError::Precondition(_) | ConservativeError::ParentCandidates(_)) => {
            return Err(CheckFailure::Unproven);
        }
    };
    if boundaries.len() != 1 {
        return Err(CheckFailure::Unproven);
    }
    let indices = (min_idx..=max_idx).collect();
    let ids = ids_present(events, &indices).map_err(CheckFailure::Exception)?;
    Ok(CheckSpan {
        indices,
        ids,
        ranges: vec![(min_idx, max_idx)],
    })
}

fn duplicate_projection_removal_check(
    step: &RecipeStep,
    events: &[EventValue],
) -> Result<CheckSpan, CheckFailure> {
    if events.is_empty() {
        return Err(CheckFailure::Unproven);
    }
    let corr = required_corr(events, step)?;
    let results =
        indexes_where(events, |event| is_result(event, &corr)).map_err(CheckFailure::Exception)?;
    if results.len() < 2 {
        return Err(CheckFailure::Unproven);
    }
    let Some(&keep_idx) = results.first() else {
        return Err(CheckFailure::Unproven);
    };
    let Some(kept) = events.get(keep_idx) else {
        return Err(CheckFailure::Unproven);
    };
    let kept_fingerprint = event_content_fingerprint(kept).map_err(CheckFailure::Exception)?;
    let drop_idx = match chosen_drop(step.target_index, events, &results, &kept_fingerprint) {
        Ok(Some(index)) => index,
        Ok(None) => return Err(CheckFailure::Unproven),
        Err(error) => return Err(CheckFailure::Exception(error)),
    };
    let Some(dropped) = events.get(drop_idx) else {
        return Err(CheckFailure::Unproven);
    };
    finish_duplicate(events, &corr, keep_idx, kept, drop_idx, dropped)
}

fn finish_duplicate(
    events: &[EventValue],
    corr: &str,
    keep_idx: usize,
    kept: &EventValue,
    drop_idx: usize,
    dropped: &EventValue,
) -> Result<CheckSpan, CheckFailure> {
    let kept_id = event_id(kept).map_err(CheckFailure::Exception)?;
    let dropped_id = event_id(dropped).map_err(CheckFailure::Exception)?;
    let mut indices = BTreeSet::from([keep_idx, drop_idx]);
    let mut ids = BTreeSet::new();
    insert_nonempty(&mut ids, kept_id.as_deref());
    insert_nonempty(&mut ids, dropped_id.as_deref());
    add_matching_calls(events, corr, &mut indices, &mut ids).map_err(CheckFailure::Exception)?;
    if let Some(dropped_text) = dropped_id.as_deref().filter(|text| !text.is_empty()) {
        add_dropped_children(events, dropped_text, &mut indices, &mut ids)
            .map_err(CheckFailure::Exception)?;
    }
    Ok(CheckSpan {
        indices,
        ids,
        ranges: Vec::new(),
    })
}

fn required_corr(events: &[EventValue], step: &RecipeStep) -> Result<String, CheckFailure> {
    match region_correlation(events, step).map_err(CheckFailure::Exception)? {
        Some(corr) if !corr.is_empty() => Ok(corr),
        Some(_) | None => Err(CheckFailure::Unproven),
    }
}

/// `target_index`, else a truthy `index` or `at_index` int.
///
/// [`IndexValue::Bool`] and [`EventField::Bool`] are not ints. `0`, `False`,
/// and `""` are falsy, so `index` falls through to `at_index`.
fn restore_region_index(step: &RecipeStep, len: usize) -> Option<usize> {
    match step.target_index {
        IndexValue::Int(value) => checked_index(value, len),
        IndexValue::Bool(_) | IndexValue::Other => None,
        IndexValue::None => restore_region_param_index(&step.params, len),
    }
}

fn restore_region_param_index(params: &ParamMap, len: usize) -> Option<usize> {
    let ParamMap::Mapping(mapping) = params else {
        return None;
    };
    match param_or(mapping, "index", "at_index") {
        Some(EventField::Int(value)) => checked_index(*value, len),
        _ => None,
    }
}

fn restore_region_parent(
    step: &RecipeStep,
    event: &EventValue,
) -> Result<Option<String>, EventError> {
    if let Some(value) = truthy_param_parent(&step.params) {
        return render_parent(value).map(Some);
    }
    event_parent_id(event)
}

/// Exact `_event_id` equality, then `startswith` when that list is empty.
fn parent_indexes(events: &[EventValue], parent_id: &str) -> Result<Vec<usize>, EventError> {
    let exact = indexes_where(events, |event| {
        Ok(event_id(event)?.as_deref() == Some(parent_id))
    })?;
    if !exact.is_empty() {
        return Ok(exact);
    }
    indexes_where(events, |event| match event_id(event)? {
        Some(id) => Ok(id.starts_with(parent_id)),
        None => Ok(false),
    })
}

fn indexes_where(
    events: &[EventValue],
    mut pred: impl FnMut(&EventValue) -> Result<bool, EventError>,
) -> Result<Vec<usize>, EventError> {
    let mut found = Vec::new();
    for (index, event) in events.iter().enumerate() {
        if pred(event)? {
            found.push(index);
        }
    }
    Ok(found)
}

/// Truthy `correlation_id`, else an in-range int target.
///
/// [`IndexValue::Bool`] is not an int. It does not select `events[0]` or
/// `events[1]`.
fn region_correlation(
    events: &[EventValue],
    step: &RecipeStep,
) -> Result<Option<String>, EventError> {
    if let Some(raw) = param_field(&step.params, "correlation_id") {
        if field_truthy(Some(raw)) {
            return render_parent(raw).map(Some);
        }
    }
    let Some(index) = strict_index(step.target_index, events.len()) else {
        return Ok(None);
    };
    let Some(event) = events.get(index) else {
        return Ok(None);
    };
    event_corr_id(event)
}

/// Ids for which `_event_id` is not `None`, including `""`.
fn ids_present(
    events: &[EventValue],
    indices: &BTreeSet<usize>,
) -> Result<BTreeSet<String>, EventError> {
    let mut ids = BTreeSet::new();
    for index in indices {
        if let Some(event) = events.get(*index) {
            if let Some(id) = event_id(event)? {
                ids.insert(id);
            }
        }
    }
    Ok(ids)
}

fn chosen_drop(
    target: IndexValue,
    events: &[EventValue],
    results: &[usize],
    kept_fingerprint: &str,
) -> Result<Option<usize>, EventError> {
    if let Some(target_int) = int_target(target) {
        if let Some(drop_idx) = results
            .iter()
            .skip(1)
            .copied()
            .find(|&index| index_equals(target_int, index))
        {
            let Some(event) = events.get(drop_idx) else {
                return Ok(None);
            };
            if event_content_fingerprint(event)? != kept_fingerprint {
                return Ok(None);
            }
            return Ok(Some(drop_idx));
        }
    }
    for index in results.iter().skip(1).copied() {
        let Some(event) = events.get(index) else {
            continue;
        };
        if event_content_fingerprint(event)? == kept_fingerprint {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

/// [`IndexValue::Bool`] is not an int.
fn int_target(index: IndexValue) -> Option<i64> {
    match index {
        IndexValue::Int(value) => Some(value),
        IndexValue::None | IndexValue::Bool(_) | IndexValue::Other => None,
    }
}

fn add_matching_calls(
    events: &[EventValue],
    corr: &str,
    indices: &mut BTreeSet<usize>,
    ids: &mut BTreeSet<String>,
) -> Result<(), EventError> {
    for (index, event) in events.iter().enumerate() {
        if !is_call(event, corr)? {
            continue;
        }
        indices.insert(index);
        insert_nonempty(ids, event_id(event)?.as_deref());
    }
    Ok(())
}

fn add_dropped_children(
    events: &[EventValue],
    dropped_id: &str,
    indices: &mut BTreeSet<usize>,
    ids: &mut BTreeSet<String>,
) -> Result<(), EventError> {
    for (index, event) in events.iter().enumerate() {
        if event_parent_id(event)?.as_deref() != Some(dropped_id) {
            continue;
        }
        indices.insert(index);
        insert_nonempty(ids, event_id(event)?.as_deref());
    }
    Ok(())
}

fn insert_nonempty(ids: &mut BTreeSet<String>, id: Option<&str>) {
    if let Some(text) = id.filter(|text| !text.is_empty()) {
        ids.insert(text.to_owned());
    }
}

#[cfg(test)]
mod tests_recipes_03 {
    use std::error::Error;
    use std::convert::Infallible;

    use model::canonical::SessionEvent;
    use model::events::{
        EventError, EventField, EventMapping, EventValue, DETERMINISM_CANONICAL_JSON_BYTES_UNAVAILABLE,
    };

    use super::{
        affected_region_compaction_projection_reunion,
        affected_region_duplicate_projection_removal, affected_region_proven_unique_parent_restore,
        compaction_projection_reunion_check, duplicate_projection_removal_check,
        proven_unique_parent_restore_check, AffectedRegionUnavailable, CheckFailure, CheckSpan,
        IndexValue, ParamMap, RecipeStep, AFFECTED_REGION_UNAVAILABLE,
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

    fn none_step() -> RecipeStep {
        make_step(IndexValue::None, ParamMap::NotMapping)
    }

    fn target_step(index: i64) -> RecipeStep {
        make_step(IndexValue::Int(index), ParamMap::NotMapping)
    }

    fn note(id: &str, parent: Option<&str>) -> EventValue {
        let mut entries = vec![("kind", text("note")), ("id", text(id))];
        if let Some(parent) = parent {
            entries.push(("parent_id", text(parent)));
        }
        ev(entries)
    }

    fn row(kind: &str, id: &str, corr: Option<&str>, parent: Option<&str>) -> EventValue {
        let mut entries = vec![("kind", text(kind)), ("id", text(id))];
        if let Some(corr) = corr {
            entries.push(("correlation_id", text(corr)));
        }
        if let Some(parent) = parent {
            entries.push(("parent_id", text(parent)));
        }
        ev(entries)
    }

    fn tool_result(id: &str, hash: &str) -> EventValue {
        ev(vec![
            ("kind", text("tool_result")),
            ("id", text(id)),
            ("correlation_id", text("corr-synthetic")),
            ("content_hash", text(hash)),
        ])
    }

    fn proven(
        indices: &[usize],
        ids: &[&str],
        ranges: &[(usize, usize)],
    ) -> Result<CheckSpan, CheckFailure> {
        Ok(CheckSpan {
            indices: indices.iter().copied().collect(),
            ids: ids.iter().map(|id| (*id).to_owned()).collect(),
            ranges: ranges.to_vec(),
        })
    }

    fn unproven() -> Result<CheckSpan, CheckFailure> {
        Err(CheckFailure::Unproven)
    }

    fn stopped(error: EventError) -> Result<CheckSpan, CheckFailure> {
        Err(CheckFailure::Exception(error))
    }

    fn snapshot(events: &[EventValue]) -> Vec<EventMapping> {
        events
            .iter()
            .map(|event| match event {
                EventValue::Mapping(mapping) => mapping.clone(),
                EventValue::Session(_) | EventValue::Other => EventMapping::new(Vec::new()),
            })
            .collect()
    }

    fn assert_seam(
        step: &RecipeStep,
        events: &[EventValue],
        call: fn(&RecipeStep, &[EventValue]) -> Result<Infallible, AffectedRegionUnavailable>,
    ) {
        let error = call(step, events).expect_err("AffectedRegion is not available");
        let text = error.to_string();
        assert_eq!(
            text,
            "sesslint.policy.abstention.AffectedRegion is not available"
        );
        assert_eq!(text, AFFECTED_REGION_UNAVAILABLE);
        assert_eq!(error.message(), text);
        assert_eq!(error, AffectedRegionUnavailable);
        assert!(Error::source(&error).is_none());
        assert_ne!(text, "true");
        assert!(!text.contains("unproven"));
        assert!(!text.contains("evt-"));
        assert!(!text.contains("representable"));
        assert!(!text.contains(DETERMINISM_CANONICAL_JSON_BYTES_UNAVAILABLE));
    }

    fn session(id: &str, parent: Option<&str>, kind: &str) -> SessionEvent {
        SessionEvent::new(
            id,
            parent.map(str::to_owned),
            0,
            "2026-01-01T00:00:00Z",
            "user",
            kind,
        )
    }

    #[test]
    fn parent_restore_empty_index_and_bool_are_unproven() {
        let events = vec![
            note("evt-parent", None),
            note("evt-child", Some("evt-parent")),
        ];
        let before = snapshot(&events);
        assert_eq!(
            proven_unique_parent_restore_check(&none_step(), &[]),
            unproven()
        );
        assert_seam(
            &none_step(),
            &[],
            affected_region_proven_unique_parent_restore,
        );
        let float_parent = make_step(
            IndexValue::None,
            params_of(vec![("parent_id", EventField::Float(1.5))]),
        );
        assert_eq!(
            proven_unique_parent_restore_check(&float_parent, &[]),
            unproven()
        );
        assert_eq!(
            proven_unique_parent_restore_check(&none_step(), &events),
            unproven()
        );
        assert_eq!(
            proven_unique_parent_restore_check(&target_step(-1), &events),
            unproven()
        );
        assert_eq!(
            proven_unique_parent_restore_check(&target_step(9), &events),
            unproven()
        );
        let bool_target = make_step(
            IndexValue::Bool(true),
            params_of(vec![("index", EventField::Int(1))]),
        );
        assert_eq!(
            proven_unique_parent_restore_check(&bool_target, &events),
            unproven()
        );
        let other_target = make_step(
            IndexValue::Other,
            params_of(vec![("index", EventField::Int(1))]),
        );
        assert_eq!(
            proven_unique_parent_restore_check(&other_target, &events),
            unproven()
        );
        let bool_at = make_step(
            IndexValue::None,
            params_of(vec![("at_index", EventField::Bool(true))]),
        );
        assert_eq!(
            proven_unique_parent_restore_check(&bool_at, &events),
            unproven()
        );
        let only_first = make_step(
            IndexValue::None,
            params_of(vec![("first_index", EventField::Int(1))]),
        );
        assert_eq!(
            proven_unique_parent_restore_check(&only_first, &events),
            unproven()
        );
        let text_index = make_step(
            IndexValue::None,
            params_of(vec![
                ("index", text("1")),
                ("at_index", EventField::Int(1)),
            ]),
        );
        assert_eq!(
            proven_unique_parent_restore_check(&text_index, &events),
            unproven()
        );
        assert_eq!(
            proven_unique_parent_restore_check(&target_step(1), &[note("evt-child", None)]),
            unproven()
        );
        assert_seam(&bool_target, &events, affected_region_proven_unique_parent_restore);
        assert_seam(&text_index, &events, affected_region_proven_unique_parent_restore);
        assert_eq!(before, snapshot(&events));
    }

    #[test]
    fn parent_restore_param_or_is_truthiness() {
        let events = vec![
            note("evt-ignored", None),
            note("evt-parent", None),
            note("evt-child", Some("evt-parent")),
        ];
        let proved = proven(&[1, 2], &["evt-child", "evt-parent"], &[]);
        let from_at = make_step(
            IndexValue::None,
            params_of(vec![
                ("index", EventField::Int(0)),
                ("at_index", EventField::Int(2)),
            ]),
        );
        assert_eq!(
            proven_unique_parent_restore_check(&from_at, &events),
            proved.clone()
        );
        let false_index = make_step(
            IndexValue::None,
            params_of(vec![
                ("index", EventField::Bool(false)),
                ("at_index", EventField::Int(2)),
            ]),
        );
        assert_eq!(
            proven_unique_parent_restore_check(&false_index, &events),
            proved.clone()
        );
        let true_hides = make_step(
            IndexValue::None,
            params_of(vec![
                ("index", EventField::Bool(true)),
                ("at_index", EventField::Int(2)),
            ]),
        );
        assert_eq!(
            proven_unique_parent_restore_check(&true_hides, &events),
            unproven()
        );
        let missing_index = make_step(
            IndexValue::None,
            params_of(vec![("at_index", EventField::Int(2))]),
        );
        assert_eq!(
            proven_unique_parent_restore_check(&missing_index, &events),
            proved
        );
        let high = make_step(
            IndexValue::None,
            params_of(vec![("at_index", EventField::Int(9))]),
        );
        assert_eq!(
            proven_unique_parent_restore_check(&high, &events),
            unproven()
        );
        assert_seam(&from_at, &events, affected_region_proven_unique_parent_restore);
        assert_seam(&true_hides, &events, affected_region_proven_unique_parent_restore);
    }

    #[test]
    fn parent_restore_exact_match_prefix_and_override() {
        let pair = vec![
            note("evt-parent", None),
            note("evt-child", Some("evt-parent")),
        ];
        let before = snapshot(&pair);
        assert_eq!(
            proven_unique_parent_restore_check(&target_step(1), &pair),
            proven(&[0, 1], &["evt-child", "evt-parent"], &[])
        );
        let same = vec![note("evt-self", Some("evt-self"))];
        assert_eq!(
            proven_unique_parent_restore_check(&target_step(0), &same),
            proven(&[0], &["evt-self"], &[])
        );
        let overridden = vec![
            note("evt-parent", None),
            note("evt-other", None),
            note("evt-child", Some("evt-other")),
        ];
        let param_parent = make_step(
            IndexValue::Int(2),
            params_of(vec![("parent_id", text("evt-parent"))]),
        );
        assert_eq!(
            proven_unique_parent_restore_check(&param_parent, &overridden),
            proven(&[0, 2], &["evt-child", "evt-parent"], &[])
        );
        let prefixed = vec![
            note("evt-parent-full", None),
            note("evt-child", Some("evt-par")),
        ];
        assert_eq!(
            proven_unique_parent_restore_check(&target_step(1), &prefixed),
            proven(
                &[0, 1],
                &["evt-child", "evt-par", "evt-parent-full"],
                &[]
            )
        );
        let exact_wins = vec![
            note("evt-par", None),
            note("evt-parent-extra", None),
            note("evt-child", Some("evt-par")),
        ];
        assert_eq!(
            proven_unique_parent_restore_check(&target_step(2), &exact_wins),
            proven(&[0, 2], &["evt-child", "evt-par"], &[])
        );
        let two_exact = vec![
            note("evt-par", None),
            note("evt-par", None),
            note("evt-child", Some("evt-par")),
        ];
        assert_eq!(
            proven_unique_parent_restore_check(&target_step(2), &two_exact),
            unproven()
        );
        let two_prefix = vec![
            note("evt-parent-a", None),
            note("evt-parent-b", None),
            note("evt-child", Some("evt-par")),
        ];
        assert_eq!(
            proven_unique_parent_restore_check(&target_step(2), &two_prefix),
            unproven()
        );
        let nameless_child = vec![
            note("evt-parent", None),
            ev(vec![
                ("kind", text("note")),
                ("id", text("")),
                ("parent_id", text("evt-parent")),
            ]),
        ];
        assert_eq!(
            proven_unique_parent_restore_check(&target_step(1), &nameless_child),
            proven(&[0, 1], &["evt-parent"], &[])
        );
        let numeric = vec![
            ev(vec![("kind", text("note")), ("id", EventField::Int(7))]),
            note("evt-child", None),
        ];
        let int_parent = make_step(
            IndexValue::Int(1),
            params_of(vec![("parent_id", EventField::Int(7))]),
        );
        assert_eq!(
            proven_unique_parent_restore_check(&int_parent, &numeric),
            proven(&[0, 1], &["7", "evt-child"], &[])
        );
        let true_parent = make_step(
            IndexValue::Int(1),
            params_of(vec![("parent_id", EventField::Bool(true))]),
        );
        let true_ids = vec![note("True", None), note("evt-child", None)];
        assert_eq!(
            proven_unique_parent_restore_check(&true_parent, &true_ids),
            proven(&[0, 1], &["True", "evt-child"], &[])
        );
        let false_falls = make_step(
            IndexValue::Int(1),
            params_of(vec![("parent_id", EventField::Bool(false))]),
        );
        assert_eq!(
            proven_unique_parent_restore_check(&false_falls, &pair),
            proven(&[0, 1], &["evt-child", "evt-parent"], &[])
        );
        let prefix_key = make_step(
            IndexValue::Int(1),
            params_of(vec![
                ("parent_id", EventField::Bool(false)),
                ("parent_fingerprint_prefix", text("evt-parent")),
            ]),
        );
        let bare_child = vec![note("evt-parent", None), note("evt-child", None)];
        assert_eq!(
            proven_unique_parent_restore_check(&prefix_key, &bare_child),
            proven(&[0, 1], &["evt-child", "evt-parent"], &[])
        );
        let ignored_prefix = make_step(
            IndexValue::Int(1),
            params_of(vec![
                ("parent_id", text("evt-parent")),
                ("parent_fingerprint_prefix", text("evt-missing")),
            ]),
        );
        assert_eq!(
            proven_unique_parent_restore_check(&ignored_prefix, &pair),
            proven(&[0, 1], &["evt-child", "evt-parent"], &[])
        );
        assert_seam(&target_step(1), &pair, affected_region_proven_unique_parent_restore);
        assert_seam(&param_parent, &overridden, affected_region_proven_unique_parent_restore);
        assert_eq!(before, snapshot(&pair));

        let parent = session("evt-parent", None, "message");
        let child = session("evt-child", Some("evt-parent"), "message");
        let sessions = vec![
            EventValue::from_session(parent),
            EventValue::from_session(child),
        ];
        assert_eq!(
            proven_unique_parent_restore_check(&target_step(1), &sessions),
            proven(&[0, 1], &["evt-child", "evt-parent"], &[])
        );
        assert_seam(
            &target_step(1),
            &sessions,
            affected_region_proven_unique_parent_restore,
        );
    }

    #[test]
    fn parent_restore_errors_stop_and_the_seam_hides_them() {
        let events = vec![
            ev(vec![("id", EventField::Float(1.5))]),
            note("evt-parent", None),
            note("evt-child", Some("evt-parent")),
        ];
        assert_eq!(
            proven_unique_parent_restore_check(&target_step(2), &events),
            stopped(EventError::PythonFloatStr)
        );
        let float_param = make_step(
            IndexValue::Int(1),
            params_of(vec![("parent_id", EventField::Float(1.5))]),
        );
        let pair = vec![
            note("evt-parent", None),
            note("evt-child", Some("evt-parent")),
        ];
        assert_eq!(
            proven_unique_parent_restore_check(&float_param, &pair),
            stopped(EventError::PythonFloatStr)
        );
        let list_param = make_step(
            IndexValue::Int(1),
            params_of(vec![("parent_id", EventField::List(vec![text("evt-parent")]))]),
        );
        assert_eq!(
            proven_unique_parent_restore_check(&list_param, &pair),
            stopped(EventError::PythonStr)
        );
        let empty_list = make_step(
            IndexValue::Int(1),
            params_of(vec![("parent_id", EventField::List(Vec::new()))]),
        );
        assert_eq!(
            proven_unique_parent_restore_check(&empty_list, &pair),
            proven(&[0, 1], &["evt-child", "evt-parent"], &[])
        );
        assert_seam(&float_param, &pair, affected_region_proven_unique_parent_restore);
        assert_seam(&list_param, &pair, affected_region_proven_unique_parent_restore);
        assert_seam(&target_step(2), &events, affected_region_proven_unique_parent_restore);
    }

    fn reunion() -> Vec<EventValue> {
        vec![
            row("tool_call", "evt-call", Some("corr-synthetic"), None),
            row("message", "evt-mid", None, None),
            row("compaction_boundary", "evt-boundary", None, None),
            row("tool_result", "evt-result", Some("corr-synthetic"), None),
            row("message", "evt-tail", None, None),
        ]
    }

    fn corr_step(corr: &str) -> RecipeStep {
        make_step(
            IndexValue::None,
            params_of(vec![("correlation_id", text(corr))]),
        )
    }

    #[test]
    fn reunion_region_correlation_bool_and_truthiness() {
        let events = reunion();
        let before = snapshot(&events);
        assert_eq!(
            compaction_projection_reunion_check(&none_step(), &[]),
            unproven()
        );
        let float_corr = make_step(
            IndexValue::None,
            params_of(vec![("correlation_id", EventField::Float(1.5))]),
        );
        assert_eq!(
            compaction_projection_reunion_check(&float_corr, &[]),
            unproven()
        );
        assert_eq!(
            compaction_projection_reunion_check(&none_step(), &events),
            unproven()
        );
        let bool_target = make_step(IndexValue::Bool(true), ParamMap::NotMapping);
        assert_eq!(
            compaction_projection_reunion_check(&bool_target, &events),
            unproven()
        );
        let false_target = make_step(IndexValue::Bool(false), ParamMap::NotMapping);
        assert_eq!(
            compaction_projection_reunion_check(&false_target, &events),
            unproven()
        );
        assert_eq!(
            compaction_projection_reunion_check(&target_step(0), &events),
            proven(
                &[0, 1, 2, 3],
                &["evt-boundary", "evt-call", "evt-mid", "evt-result"],
                &[(0, 3)]
            )
        );
        let falsy = make_step(
            IndexValue::Int(0),
            params_of(vec![("correlation_id", EventField::Int(0))]),
        );
        assert_eq!(
            compaction_projection_reunion_check(&falsy, &events),
            compaction_projection_reunion_check(&target_step(0), &events)
        );
        let rendered_true = make_step(
            IndexValue::Int(0),
            params_of(vec![("correlation_id", EventField::Bool(true))]),
        );
        assert_eq!(
            compaction_projection_reunion_check(&rendered_true, &events),
            unproven()
        );
        let true_pair = vec![
            row("tool_call", "evt-call", Some("True"), None),
            row("compaction_boundary", "evt-boundary", None, None),
            row("tool_result", "evt-result", Some("True"), None),
        ];
        assert_eq!(
            compaction_projection_reunion_check(&rendered_true, &true_pair),
            proven(
                &[0, 1, 2],
                &["evt-boundary", "evt-call", "evt-result"],
                &[(0, 2)]
            )
        );
        assert_seam(&bool_target, &events, affected_region_compaction_projection_reunion);
        assert_seam(&falsy, &events, affected_region_compaction_projection_reunion);
        assert_eq!(before, snapshot(&events));
    }

    #[test]
    fn reunion_region_span_cardinality_and_empty_id() {
        let events = reunion();
        let step = corr_step("corr-synthetic");
        assert_eq!(
            compaction_projection_reunion_check(&step, &events),
            proven(
                &[0, 1, 2, 3],
                &["evt-boundary", "evt-call", "evt-mid", "evt-result"],
                &[(0, 3)]
            )
        );
        let empty_mid = vec![
            row("tool_call", "evt-call", Some("corr-synthetic"), None),
            row("message", "", None, None),
            row("compaction_boundary", "evt-boundary", None, None),
            row("tool_result", "evt-result", Some("corr-synthetic"), None),
        ];
        assert_eq!(
            compaction_projection_reunion_check(&step, &empty_mid),
            proven(
                &[0, 1, 2, 3],
                &["", "evt-boundary", "evt-call", "evt-result"],
                &[(0, 3)]
            )
        );
        let missing_mid = vec![
            row("tool_call", "evt-call", Some("corr-synthetic"), None),
            ev(vec![("kind", text("message"))]),
            row("compaction_boundary", "evt-boundary", None, None),
            row("tool_result", "evt-result", Some("corr-synthetic"), None),
        ];
        assert_eq!(
            compaction_projection_reunion_check(&step, &missing_mid),
            proven(
                &[0, 1, 2, 3],
                &["evt-boundary", "evt-call", "evt-result"],
                &[(0, 3)]
            )
        );
        let reversed = vec![
            row("tool_result", "evt-result", Some("corr-synthetic"), None),
            row("compaction_boundary", "evt-boundary", None, None),
            row("tool_use", "evt-call", Some("corr-synthetic"), None),
        ];
        assert_eq!(
            compaction_projection_reunion_check(&step, &reversed),
            proven(
                &[0, 1, 2],
                &["evt-boundary", "evt-call", "evt-result"],
                &[(0, 2)]
            )
        );
        let adjacent = vec![
            row("tool_call", "evt-call", Some("corr-synthetic"), None),
            row("tool_result", "evt-result", Some("corr-synthetic"), None),
        ];
        assert_eq!(
            compaction_projection_reunion_check(&step, &adjacent),
            unproven()
        );
        let two_bounds = vec![
            row("tool_call", "evt-call", Some("corr-synthetic"), None),
            row("compaction_boundary", "evt-a", None, None),
            row("compaction_boundary", "evt-b", None, None),
            row("tool_result", "evt-result", Some("corr-synthetic"), None),
        ];
        assert_eq!(
            compaction_projection_reunion_check(&step, &two_bounds),
            unproven()
        );
        let two_calls = vec![
            row("tool_call", "evt-call", Some("corr-synthetic"), None),
            row("tool_use", "evt-use", Some("corr-synthetic"), None),
            row("compaction_boundary", "evt-boundary", None, None),
            row("tool_result", "evt-result", Some("corr-synthetic"), None),
        ];
        assert_eq!(
            compaction_projection_reunion_check(&step, &two_calls),
            unproven()
        );
        assert_seam(&step, &events, affected_region_compaction_projection_reunion);
        assert_seam(&step, &adjacent, affected_region_compaction_projection_reunion);
    }

    #[test]
    fn reunion_region_short_circuit_session_and_errors() {
        let step = corr_step("corr-synthetic");
        let float_between = vec![
            row("tool_call", "evt-call", Some("corr-synthetic"), None),
            ev(vec![
                ("kind", text("message")),
                ("id", text("evt-mid")),
                ("correlation_id", EventField::Float(1.5)),
            ]),
            row("compaction_boundary", "evt-boundary", None, None),
            row("tool_result", "evt-result", Some("corr-synthetic"), None),
        ];
        assert_eq!(
            compaction_projection_reunion_check(&step, &float_between),
            proven(
                &[0, 1, 2, 3],
                &["evt-boundary", "evt-call", "evt-mid", "evt-result"],
                &[(0, 3)]
            )
        );
        let float_call = vec![
            ev(vec![
                ("kind", text("tool_call")),
                ("id", text("evt-call")),
                ("correlation_id", EventField::Float(1.5)),
            ]),
            row("compaction_boundary", "evt-boundary", None, None),
            row("tool_result", "evt-result", Some("corr-synthetic"), None),
        ];
        assert_eq!(
            compaction_projection_reunion_check(&step, &float_call),
            stopped(EventError::PythonFloatStr)
        );
        let float_param = make_step(
            IndexValue::None,
            params_of(vec![("correlation_id", EventField::Float(1.5))]),
        );
        assert_eq!(
            compaction_projection_reunion_check(&float_param, &reunion()),
            stopped(EventError::PythonFloatStr)
        );
        assert_seam(&float_param, &reunion(), affected_region_compaction_projection_reunion);
        assert_seam(&step, &float_between, affected_region_compaction_projection_reunion);

        let mut call = session("evt-call", None, "tool_call");
        call.correlation_id = Some("corr-synthetic".to_owned());
        let boundary = session("evt-boundary", Some("evt-call"), "compaction_boundary");
        let mut result = session("evt-result", Some("evt-call"), "tool_result");
        result.correlation_id = Some("corr-synthetic".to_owned());
        let sessions = vec![
            EventValue::from_session(call),
            EventValue::from_session(boundary),
            EventValue::from_session(result),
        ];
        assert_eq!(
            compaction_projection_reunion_check(&step, &sessions),
            proven(
                &[0, 1, 2],
                &["evt-boundary", "evt-call", "evt-result"],
                &[(0, 2)]
            )
        );
        assert_seam(&step, &sessions, affected_region_compaction_projection_reunion);
    }

    #[test]
    fn removal_region_target_bool_is_not_an_int() {
        let events = vec![
            tool_result("evt-keep", "hash-a"),
            tool_result("evt-differ", "hash-b"),
            tool_result("evt-later", "hash-a"),
        ];
        let before = snapshot(&events);
        let scanned = || proven(&[0, 2], &["evt-keep", "evt-later"], &[]);
        assert_eq!(
            duplicate_projection_removal_check(&none_step(), &[]),
            unproven()
        );
        let float_corr = make_step(
            IndexValue::None,
            params_of(vec![("correlation_id", EventField::Float(1.5))]),
        );
        assert_eq!(
            duplicate_projection_removal_check(&float_corr, &[]),
            unproven()
        );
        assert_eq!(
            duplicate_projection_removal_check(&corr_step("corr-synthetic"), &events),
            scanned()
        );
        assert_eq!(
            duplicate_projection_removal_check(
                &make_step(IndexValue::Bool(true), ParamMap::NotMapping),
                &events
            ),
            unproven()
        );
        assert_eq!(
            duplicate_projection_removal_check(&target_step(0), &events),
            scanned()
        );
        assert_eq!(
            duplicate_projection_removal_check(
                &make_step(IndexValue::Other, ParamMap::NotMapping),
                &events
            ),
            unproven()
        );
        let with_corr = params_of(vec![("correlation_id", text("corr-synthetic"))]);
        assert_eq!(
            duplicate_projection_removal_check(
                &make_step(IndexValue::Bool(true), with_corr.clone()),
                &events
            ),
            scanned()
        );
        assert_eq!(
            duplicate_projection_removal_check(
                &make_step(IndexValue::Int(1), with_corr.clone()),
                &events
            ),
            unproven()
        );
        assert_eq!(
            duplicate_projection_removal_check(
                &make_step(IndexValue::Int(2), with_corr.clone()),
                &events
            ),
            scanned()
        );
        assert_eq!(
            duplicate_projection_removal_check(&make_step(IndexValue::Int(-1), with_corr), &events),
            scanned()
        );
        let one = vec![tool_result("evt-keep", "hash-a")];
        assert_eq!(
            duplicate_projection_removal_check(&corr_step("corr-synthetic"), &one),
            unproven()
        );
        let differ = vec![
            tool_result("evt-keep", "hash-a"),
            tool_result("evt-other", "hash-b"),
        ];
        assert_eq!(
            duplicate_projection_removal_check(&corr_step("corr-synthetic"), &differ),
            unproven()
        );
        assert_seam(&corr_step("corr-synthetic"), &events, affected_region_duplicate_projection_removal);
        assert_seam(
            &make_step(IndexValue::Int(1), params_of(vec![("correlation_id", text("corr-synthetic"))])),
            &events,
            affected_region_duplicate_projection_removal,
        );
        assert_eq!(before, snapshot(&events));
    }

    #[test]
    fn removal_region_calls_children_order_and_errors() {
        let events = vec![
            row("tool_call", "evt-call", Some("corr-synthetic"), None),
            row("tool_use", "evt-use", Some("corr-synthetic"), None),
            tool_result("evt-keep", "hash-a"),
            row("message", "evt-child", None, Some("evt-drop")),
            row("message", "evt-other", None, Some("evt-keep")),
            tool_result("evt-drop", "hash-a"),
            row("message", "evt-tail", None, None),
        ];
        let step = corr_step("corr-synthetic");
        assert_eq!(
            duplicate_projection_removal_check(&step, &events),
            proven(
                &[0, 1, 2, 3, 5],
                &[
                    "evt-call",
                    "evt-child",
                    "evt-drop",
                    "evt-keep",
                    "evt-use",
                ],
                &[]
            )
        );
        let bare = vec![
            tool_result("evt-keep", "hash-a"),
            ev(vec![
                ("kind", text("tool_result")),
                ("id", text("")),
                ("correlation_id", text("corr-synthetic")),
                ("content_hash", text("hash-a")),
            ]),
            row("message", "evt-child", None, Some("")),
        ];
        assert_eq!(
            duplicate_projection_removal_check(&step, &bare),
            proven(&[0, 1], &["evt-keep"], &[])
        );
        let float_id_message = vec![
            tool_result("evt-keep", "hash-a"),
            ev(vec![
                ("kind", text("message")),
                ("id", EventField::Float(1.5)),
            ]),
            tool_result("evt-drop", "hash-a"),
        ];
        assert_eq!(
            duplicate_projection_removal_check(&step, &float_id_message),
            proven(&[0, 2], &["evt-drop", "evt-keep"], &[])
        );
        let float_parent = vec![
            tool_result("evt-keep", "hash-a"),
            ev(vec![
                ("kind", text("message")),
                ("id", text("evt-child")),
                ("parent_id", EventField::Float(1.5)),
            ]),
            tool_result("evt-drop", "hash-a"),
        ];
        assert_eq!(
            duplicate_projection_removal_check(&step, &float_parent),
            stopped(EventError::PythonFloatStr)
        );
        let float_call = vec![
            ev(vec![
                ("kind", text("tool_call")),
                ("id", EventField::Float(1.5)),
                ("correlation_id", text("corr-synthetic")),
            ]),
            tool_result("evt-keep", "hash-a"),
            tool_result("evt-drop", "hash-a"),
        ];
        assert_eq!(
            duplicate_projection_removal_check(&step, &float_call),
            stopped(EventError::PythonFloatStr)
        );
        let blocked = vec![
            tool_result("evt-keep", "hash-a"),
            ev(vec![
                ("kind", text("tool_result")),
                ("id", text("evt-bad")),
                ("correlation_id", text("corr-synthetic")),
            ]),
            tool_result("evt-later", "hash-a"),
        ];
        assert_eq!(
            duplicate_projection_removal_check(&step, &blocked),
            stopped(EventError::DeterminismCanonicalJsonBytes)
        );
        let aimed = make_step(
            IndexValue::Int(2),
            params_of(vec![("correlation_id", text("corr-synthetic"))]),
        );
        assert_eq!(
            duplicate_projection_removal_check(&aimed, &blocked),
            proven(&[0, 2], &["evt-keep", "evt-later"], &[])
        );
        let aimed_bad = make_step(
            IndexValue::Int(1),
            params_of(vec![("correlation_id", text("corr-synthetic"))]),
        );
        assert_eq!(
            duplicate_projection_removal_check(&aimed_bad, &blocked),
            stopped(EventError::DeterminismCanonicalJsonBytes)
        );
        let float_kind = vec![
            ev(vec![("kind", EventField::Float(1.5))]),
            tool_result("evt-keep", "hash-a"),
            tool_result("evt-drop", "hash-a"),
        ];
        assert_eq!(
            duplicate_projection_removal_check(&step, &float_kind),
            stopped(EventError::PythonFloatStr)
        );
        assert_seam(&step, &events, affected_region_duplicate_projection_removal);
        assert_seam(&step, &blocked, affected_region_duplicate_projection_removal);
        assert_seam(&aimed, &blocked, affected_region_duplicate_projection_removal);

        let mut call = session("evt-call", None, "tool_call");
        call.correlation_id = Some("corr-synthetic".to_owned());
        let mut keep = session("evt-keep", Some("evt-call"), "tool_result");
        keep.correlation_id = Some("corr-synthetic".to_owned());
        keep.content_hash = Some("hash-a".to_owned());
        let mut dropped = session("evt-drop", Some("evt-call"), "tool_result");
        dropped.correlation_id = Some("corr-synthetic".to_owned());
        dropped.content_hash = Some("hash-a".to_owned());
        let sessions = vec![
            EventValue::from_session(call),
            EventValue::from_session(keep),
            EventValue::from_session(dropped),
        ];
        assert_eq!(
            duplicate_projection_removal_check(&step, &sessions),
            proven(&[0, 1, 2], &["evt-call", "evt-drop", "evt-keep"], &[])
        );
        assert_seam(&step, &sessions, affected_region_duplicate_projection_removal);
    }
}

// Port of `src/sesslint/repair/recipes_conservative.py` lines 781-1045
// @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//
// `apply_identical_duplicate_drop` and `apply_seq_renumber` return a
// [`copy_events_as_dicts`](model::events::copy_events_as_dicts) list when the
// pin returns one. A fingerprint error is that error. It is not a successful
// drop. [`EventField::Bool`] is not an int.
//
// The two region functions run the pin's pure checks. Every return in the pin
// constructs `sesslint.policy.abstention.AffectedRegion`. This crate cannot
// construct that type and does not invent one. Display is
// [`AFFECTED_REGION_UNAVAILABLE`]. This is not `true`. `sesslint.checks` is
// not called.
//
// `register_all` registers the recipes already defined in this module through
// [`get_recipe`](crate::registry::get_recipe) and
// [`register_recipe`](crate::registry::register_recipe). The planner keeps its
// current seam.

use crate::registry::{get_recipe, register_recipe, CallableId, Recipe, RecipeSpec, RegistryError};
use model::codes::{SL003, SL004, SL005, SL104, SL108};

pub use crate::recipes_sl002::affected_region_torn_terminal_record_discard;

/// Python `__all__`, in that order. Not sorted.
pub const ALL: [&str; 29] = [
    "CONSERVATIVE_RECIPES",
    "PreconditionFailed",
    "RECIPES",
    "RECIPE_COMPACTION_PROJECTION_REUNION",
    "RECIPE_DUPLICATE_PROJECTION_REMOVAL",
    "RECIPE_IDENTICAL_DUPLICATE_DROP",
    "RECIPE_SEQ_RENUMBER",
    "RECIPE_IDENTICAL_DUPLICATE_COLLAPSE",
    "RECIPE_PROVEN_UNIQUE_PARENT_RESTORE",
    "RECIPE_TERMINAL_SUFFIX_DISCARD",
    "affected_region_compaction_projection_reunion",
    "affected_region_duplicate_projection_removal",
    "affected_region_identical_duplicate_drop",
    "affected_region_identical_duplicate_collapse",
    "affected_region_proven_unique_parent_restore",
    "affected_region_torn_terminal_record_discard",
    "apply_compaction_projection_reunion",
    "apply_duplicate_projection_removal",
    "apply_identical_duplicate_collapse",
    "apply_identical_duplicate_drop",
    "apply_seq_renumber",
    "apply_proven_unique_parent_restore",
    "apply_terminal_suffix_discard",
    "compaction_projection_reunion",
    "duplicate_projection_removal",
    "identical_duplicate_collapse",
    "proven_unique_parent_restore",
    "register_all",
    "terminal_suffix_discard",
];

const DROP_VARIANT: &str =
    "identical-duplicate-drop: finding variant is not identical-duplicate";
const DROP_INDEXES_MISSING: &str = "identical-duplicate-drop: record_indexes missing";
const DROP_INDEXES_FEW: &str =
    "identical-duplicate-drop: fewer than 2 valid occurrence indexes";
const DROP_INDEXES_BOUNDS: &str = "identical-duplicate-drop: occurrence index out of bounds";

const EMPTY_NAMES: [&str; 0] = [];
const TERMINAL_HANDLES: [&str; 1] = [SL005];
const TERMINAL_PRECONDITIONS: [&str; 1] = ["no_prior_safe_tool_after_cut"];
const COLLAPSE_HANDLES: [&str; 1] = [SL003];
const COLLAPSE_PRECONDITIONS: [&str; 2] = ["no_sl203", "adjacent_identical_duplicate"];
const RESTORE_HANDLES: [&str; 1] = [SL004];
const RESTORE_PRECONDITIONS: [&str; 2] = ["no_sl203", "unique_parent_candidate"];
const REUNION_HANDLES: [&str; 1] = [SL108];
const REUNION_PRECONDITIONS: [&str; 2] = ["no_sl203", "single_boundary_split"];
const REMOVAL_HANDLES: [&str; 1] = [SL104];
const REMOVAL_PRECONDITIONS: [&str; 2] = ["no_sl203", "duplicate_projection_identical"];
const DROP_HANDLES: [&str; 1] = [SL003];
const DROP_PRECONDITIONS: [&str; 2] = ["no_sl203", "sl003_identical_duplicate"];

/// Drop later occurrences of one identical event id.
///
/// Python: `apply_identical_duplicate_drop`. `params` that are not a mapping
/// are read as `{}`. `variant` must be `identical-duplicate`.
/// `record_indexes` must be a list. A string is not that list.
/// [`EventField::Bool`] is not an int, so it is not an occurrence index.
/// The kept index is the earliest remaining int. Boundary kind is refused
/// before [`event_id`](model::events::event_id) and before
/// [`event_content_fingerprint`](model::events::event_content_fingerprint).
/// A fingerprint error is returned and the events are not dropped.
///
/// The successful value is a
/// [`copy_events_as_dicts`](model::events::copy_events_as_dicts) list with the
/// later occurrence indexes removed. The input slice is not mutated.
///
/// # Errors
///
/// Returns [`ConservativeError::Precondition`] for a bad variant, a missing
/// index list, fewer than two valid indexes, an out-of-range index, a
/// boundary kind, a kind mismatch, content drift, or event-id drift. Returns
/// [`ConservativeError::Event`] when kind, id, fingerprint, or the copy fails.
/// This function does not panic.
pub fn apply_identical_duplicate_drop(
    events: &[EventValue],
    step: &RecipeStep,
) -> Result<Vec<EventMapping>, ConservativeError> {
    let mapping = identical_drop_params(step)?;
    let raw = raw_record_indexes(mapping)?;
    let idxs = strict_indexes(raw)?;
    let positions = require_in_bounds(&idxs, events.len())?;
    let Some(&keep_at) = positions.first() else {
        return Err(precondition(DROP_INDEXES_BOUNDS).into());
    };
    let Some(kept) = events.get(keep_at) else {
        return Err(precondition(DROP_INDEXES_BOUNDS).into());
    };
    let kept_kind = event_kind(kept)?;
    if let Some(kind) = kept_kind.as_deref() {
        if boundary_kind(Some(kind)) {
            return Err(precondition(format!(
                "identical-duplicate-drop: cannot drop boundary kind '{kind}'"
            ))
            .into());
        }
    }
    let kept_id = event_id(kept)?;
    let kept_fp = event_content_fingerprint(kept)?;
    let dropped_ids = reject_later_occurrences(
        events,
        &idxs,
        &positions,
        &kept_kind,
        &kept_id,
        &kept_fp,
    )?;
    let mut out = copy_events_as_dicts(events)?;
    let mut drop_positions: Vec<usize> = positions.iter().skip(1).copied().collect();
    drop_positions.reverse();
    for position in drop_positions {
        if position >= out.len() {
            return Err(precondition(DROP_INDEXES_BOUNDS).into());
        }
        out.remove(position);
    }
    let drop_ids = relink_id_set(&dropped_ids, &kept_id);
    if let Some(kept_text) = id_text(&kept_id).filter(|_| !drop_ids.is_empty()) {
        relink_parents(&mut out, kept_text, &drop_ids);
    }
    Ok(out)
}

/// Run the identical-duplicate-drop checks, then stop.
///
/// Python: `affected_region_identical_duplicate_drop`. Argument order is
/// `step`, then `events`. A non-mapping `params`, a non-list
/// `record_indexes`, fewer than two ints, or an out-of-range int is unproven.
/// [`EventField::Bool`] is not an int. Duplicate ints are one index. Variant,
/// kind, and fingerprint are not read. A truthy dropped id that differs from
/// the kept id pulls in children by
/// [`event_parent_id`](model::events::event_parent_id). An event-helper error
/// stops that walk.
///
/// Every return in the pin constructs
/// `sesslint.policy.abstention.AffectedRegion`. This crate cannot construct
/// that type and does not invent a region. Each of those returns is
/// [`AffectedRegionUnavailable`]. Display is [`AFFECTED_REGION_UNAVAILABLE`].
/// This is not `true`.
///
/// # Errors
///
/// Always returns [`AffectedRegionUnavailable`] after the checks that apply.
/// This function does not panic.
pub fn affected_region_identical_duplicate_drop(
    step: &RecipeStep,
    events: &[EventValue],
) -> Result<Infallible, AffectedRegionUnavailable> {
    Err(refuse_check(identical_duplicate_drop_check(step, events)))
}

/// Renumber `seq` to `0..n-1` without reordering events.
///
/// Python: `apply_seq_renumber`. `step` is ignored. The result is a
/// [`copy_events_as_dicts`](model::events::copy_events_as_dicts) list. An
/// existing `seq` is replaced in place. A missing `seq` is appended. A copy
/// error is returned and is not a renumbered list. The input slice is not
/// mutated.
///
/// # Errors
///
/// Returns [`ConservativeError::Event`] when the copy fails. This function
/// does not panic.
pub fn apply_seq_renumber(
    events: &[EventValue],
    step: &RecipeStep,
) -> Result<Vec<EventMapping>, ConservativeError> {
    let _ignored = step;
    let mut out = copy_events_as_dicts(events)?;
    for (index, event) in out.iter_mut().enumerate() {
        set_seq(event, index);
    }
    Ok(out)
}

/// Run the seq-renumber check, then stop.
///
/// Python: `affected_region_seq_renumber`. `step` and `events` are discarded.
/// The pin returns an empty `AffectedRegion`, including when an event id
/// cannot be read. Nothing in the events is inspected.
///
/// Every return in the pin constructs
/// `sesslint.policy.abstention.AffectedRegion`. This crate cannot construct
/// that type and does not invent a region. The return is
/// [`AffectedRegionUnavailable`]. Display is [`AFFECTED_REGION_UNAVAILABLE`].
/// This is not `true`.
///
/// # Errors
///
/// Always returns [`AffectedRegionUnavailable`] after the check. This function
/// does not panic.
pub fn affected_region_seq_renumber(
    step: &RecipeStep,
    events: &[EventValue],
) -> Result<Infallible, AffectedRegionUnavailable> {
    Err(refuse_check(seq_renumber_check(step, events)))
}

pub fn recipe_terminal_suffix_discard() -> Result<Recipe, RegistryError> {
    Recipe::try_new(RecipeSpec {
        name: "terminal-suffix-discard",
        handles: &TERMINAL_HANDLES,
        preconditions: &TERMINAL_PRECONDITIONS,
        lossy: true,
        salvage_only: true,
        apply: Some(CallableId::from_fn(apply_terminal_suffix_discard)),
        min_policy: "salvage",
        version: "1.0.0",
        affected_region: None,
        excludes_execution_dependence: false,
    })
}

/// Python constant `RECIPE_TERMINAL_SUFFIX_DISCARD`.
pub use recipe_terminal_suffix_discard as RECIPE_TERMINAL_SUFFIX_DISCARD;

pub fn recipe_identical_duplicate_collapse() -> Result<Recipe, RegistryError> {
    Recipe::try_new(RecipeSpec {
        name: "identical-duplicate-collapse",
        handles: &COLLAPSE_HANDLES,
        preconditions: &COLLAPSE_PRECONDITIONS,
        lossy: false,
        salvage_only: false,
        apply: Some(CallableId::from_fn(apply_identical_duplicate_collapse)),
        min_policy: "conservative",
        version: "1.0.0",
        affected_region: Some(CallableId::from_fn(
            affected_region_identical_duplicate_collapse,
        )),
        excludes_execution_dependence: false,
    })
}

/// Python constant `RECIPE_IDENTICAL_DUPLICATE_COLLAPSE`.
pub use recipe_identical_duplicate_collapse as RECIPE_IDENTICAL_DUPLICATE_COLLAPSE;

pub fn recipe_proven_unique_parent_restore() -> Result<Recipe, RegistryError> {
    Recipe::try_new(RecipeSpec {
        name: "proven-unique-parent-restore",
        handles: &RESTORE_HANDLES,
        preconditions: &RESTORE_PRECONDITIONS,
        lossy: false,
        salvage_only: false,
        apply: Some(CallableId::from_fn(apply_proven_unique_parent_restore)),
        min_policy: "conservative",
        version: "1.0.0",
        affected_region: Some(CallableId::from_fn(
            affected_region_proven_unique_parent_restore,
        )),
        excludes_execution_dependence: false,
    })
}

/// Python constant `RECIPE_PROVEN_UNIQUE_PARENT_RESTORE`.
pub use recipe_proven_unique_parent_restore as RECIPE_PROVEN_UNIQUE_PARENT_RESTORE;

pub fn recipe_compaction_projection_reunion() -> Result<Recipe, RegistryError> {
    Recipe::try_new(RecipeSpec {
        name: "compaction-projection-reunion",
        handles: &REUNION_HANDLES,
        preconditions: &REUNION_PRECONDITIONS,
        lossy: false,
        salvage_only: false,
        apply: Some(CallableId::from_fn(apply_compaction_projection_reunion)),
        min_policy: "conservative",
        version: "1.0.0",
        affected_region: Some(CallableId::from_fn(
            affected_region_compaction_projection_reunion,
        )),
        excludes_execution_dependence: false,
    })
}

/// Python constant `RECIPE_COMPACTION_PROJECTION_REUNION`.
pub use recipe_compaction_projection_reunion as RECIPE_COMPACTION_PROJECTION_REUNION;

pub fn recipe_duplicate_projection_removal() -> Result<Recipe, RegistryError> {
    Recipe::try_new(RecipeSpec {
        name: "duplicate-projection-removal",
        handles: &REMOVAL_HANDLES,
        preconditions: &REMOVAL_PRECONDITIONS,
        lossy: false,
        salvage_only: false,
        apply: Some(CallableId::from_fn(apply_duplicate_projection_removal)),
        min_policy: "conservative",
        version: "1.0.0",
        affected_region: Some(CallableId::from_fn(
            affected_region_duplicate_projection_removal,
        )),
        excludes_execution_dependence: false,
    })
}

/// Python constant `RECIPE_DUPLICATE_PROJECTION_REMOVAL`.
pub use recipe_duplicate_projection_removal as RECIPE_DUPLICATE_PROJECTION_REMOVAL;

pub fn recipe_identical_duplicate_drop() -> Result<Recipe, RegistryError> {
    Recipe::try_new(RecipeSpec {
        name: "identical-duplicate-drop",
        handles: &DROP_HANDLES,
        preconditions: &DROP_PRECONDITIONS,
        lossy: false,
        salvage_only: false,
        apply: Some(CallableId::from_fn(apply_identical_duplicate_drop)),
        min_policy: "conservative",
        version: "1.0.0",
        affected_region: Some(CallableId::from_fn(
            affected_region_identical_duplicate_drop,
        )),
        excludes_execution_dependence: false,
    })
}

/// Python constant `RECIPE_IDENTICAL_DUPLICATE_DROP`.
pub use recipe_identical_duplicate_drop as RECIPE_IDENTICAL_DUPLICATE_DROP;

pub fn recipe_seq_renumber() -> Result<Recipe, RegistryError> {
    Recipe::try_new(RecipeSpec {
        name: "seq-renumber",
        handles: &EMPTY_NAMES,
        preconditions: &EMPTY_NAMES,
        lossy: false,
        salvage_only: false,
        apply: Some(CallableId::from_fn(apply_seq_renumber)),
        min_policy: "conservative",
        version: "1.0.0",
        affected_region: Some(CallableId::from_fn(affected_region_seq_renumber)),
        excludes_execution_dependence: true,
    })
}

/// Python constant `RECIPE_SEQ_RENUMBER`.
pub use recipe_seq_renumber as RECIPE_SEQ_RENUMBER;

pub fn conservative_recipes() -> Result<Vec<Recipe>, RegistryError> {
    Ok(vec![
        recipe_terminal_suffix_discard()?,
        recipe_identical_duplicate_collapse()?,
        recipe_proven_unique_parent_restore()?,
        recipe_compaction_projection_reunion()?,
        recipe_duplicate_projection_removal()?,
        recipe_identical_duplicate_drop()?,
        recipe_seq_renumber()?,
    ])
}

/// Python constant `RECIPES`.
pub use conservative_recipes as RECIPES;

/// Python constant `CONSERVATIVE_RECIPES`.
pub use conservative_recipes as CONSERVATIVE_RECIPES;

/// Register recipes from this module that are not already present.
///
/// Python: `register_all`. [`get_recipe`](crate::registry::get_recipe) runs
/// first for each recipe in [`RECIPES`]. An absent name is inserted through
/// [`register_recipe`](crate::registry::register_recipe). `apply` and
/// `affected_region` are not called. This does not build a second registry.
/// The planner's `register_all` seam is unchanged.
///
/// # Errors
///
/// Returns [`RegistryError`] when construction or registration fails. A name
/// that appears between the check and the insert is the duplicate-name
/// `ValueError`. This function does not panic.
pub fn register_all() -> Result<(), RegistryError> {
    for recipe in conservative_recipes()? {
        if get_recipe(recipe.name()).is_none() {
            register_recipe(&recipe)?;
        }
    }
    Ok(())
}

fn identical_drop_params(step: &RecipeStep) -> Result<&EventMapping, PreconditionFailed> {
    let ParamMap::Mapping(mapping) = &step.params else {
        return Err(precondition(DROP_VARIANT));
    };
    match mapping.get("variant") {
        Some(EventField::Str(variant)) if variant == "identical-duplicate" => Ok(mapping),
        _ => Err(precondition(DROP_VARIANT)),
    }
}

fn raw_record_indexes(mapping: &EventMapping) -> Result<&[EventField], PreconditionFailed> {
    match mapping.get("record_indexes") {
        Some(EventField::List(items)) => Ok(items),
        _ => Err(precondition(DROP_INDEXES_MISSING)),
    }
}

/// [`EventField::Bool`] and [`EventField::Float`] are not ints.
fn unique_ints(raw: &[EventField]) -> Vec<i64> {
    let mut values = BTreeSet::new();
    for item in raw {
        if let EventField::Int(value) = item {
            values.insert(*value);
        }
    }
    values.into_iter().collect()
}

fn strict_indexes(raw: &[EventField]) -> Result<Vec<i64>, PreconditionFailed> {
    let idxs = unique_ints(raw);
    if idxs.len() < 2 || idxs.len() != raw.len() {
        return Err(precondition(DROP_INDEXES_FEW));
    }
    Ok(idxs)
}

fn bounds_ok(idxs: &[i64], len: usize) -> bool {
    match (idxs.first(), idxs.last()) {
        (Some(&first), Some(&last)) => first >= 0 && index_below_len(last, len),
        _ => false,
    }
}

fn index_below_len(index: i64, len: usize) -> bool {
    match usize::try_from(index) {
        Ok(position) => position < len,
        Err(_) => false,
    }
}

fn positions_of(idxs: &[i64]) -> Option<Vec<usize>> {
    let mut positions = Vec::with_capacity(idxs.len());
    for index in idxs {
        positions.push(usize::try_from(*index).ok()?);
    }
    Some(positions)
}

fn require_in_bounds(idxs: &[i64], len: usize) -> Result<Vec<usize>, PreconditionFailed> {
    if !bounds_ok(idxs, len) {
        return Err(precondition(DROP_INDEXES_BOUNDS));
    }
    positions_of(idxs).ok_or_else(|| precondition(DROP_INDEXES_BOUNDS))
}

fn reject_later_occurrences(
    events: &[EventValue],
    idxs: &[i64],
    positions: &[usize],
    kept_kind: &Option<String>,
    kept_id: &Option<String>,
    kept_fp: &str,
) -> Result<Vec<Option<String>>, ConservativeError> {
    let mut dropped_ids = Vec::new();
    for (&index, &position) in idxs.iter().zip(positions.iter()).skip(1) {
        let Some(event) = events.get(position) else {
            return Err(precondition(DROP_INDEXES_BOUNDS).into());
        };
        let kind = event_kind(event)?;
        if kind.as_deref() != kept_kind.as_deref() {
            let found = kind_label(&kind);
            let expected = kind_label(kept_kind);
            return Err(precondition(format!(
                "identical-duplicate-drop: kind mismatch at occurrence {index} ('{found}' != '{expected}')"
            ))
            .into());
        }
        let fingerprint = event_content_fingerprint(event)?;
        if fingerprint != kept_fp {
            return Err(precondition(format!(
                "identical-duplicate-drop: content drift at occurrence {index}"
            ))
            .into());
        }
        let dropped_id = event_id(event)?;
        if both_truthy_differ(kept_id, &dropped_id) {
            return Err(precondition(format!(
                "identical-duplicate-drop: event id drift at occurrence {index}"
            ))
            .into());
        }
        dropped_ids.push(dropped_id);
    }
    Ok(dropped_ids)
}

fn both_truthy_differ(left: &Option<String>, right: &Option<String>) -> bool {
    match (id_text(left), id_text(right)) {
        (Some(kept), Some(dropped)) => kept != dropped,
        _ => false,
    }
}

fn id_text(id: &Option<String>) -> Option<&str> {
    id.as_deref().filter(|text| !text.is_empty())
}

fn relink_id_set(dropped_ids: &[Option<String>], kept_id: &Option<String>) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for id in dropped_ids {
        if let Some(text) = id_text(id) {
            if Some(text) != id_text(kept_id) {
                set.insert(text.to_owned());
            }
        }
    }
    set
}

fn relink_parents(events: &mut [EventMapping], kept_id: &str, drop_ids: &BTreeSet<String>) {
    for event in events {
        let parent = match event.get("parent_id") {
            Some(EventField::Str(parent)) => parent.clone(),
            _ => continue,
        };
        if drop_ids.contains(&parent) {
            replace_parent(event, kept_id);
        }
    }
}

fn set_seq(event: &mut EventMapping, index: usize) {
    let seq = EventField::Int(index as i64);
    let mut entries = event.entries().to_vec();
    if let Some((_, value)) = entries.iter_mut().rev().find(|(key, _)| key == "seq") {
        *value = seq;
    } else {
        entries.push(("seq".to_owned(), seq));
    }
    *event = EventMapping::new(entries);
}

fn identical_duplicate_drop_check(
    step: &RecipeStep,
    events: &[EventValue],
) -> Result<CheckSpan, CheckFailure> {
    let ParamMap::Mapping(mapping) = &step.params else {
        return Err(CheckFailure::Unproven);
    };
    let Some(EventField::List(raw)) = mapping.get("record_indexes") else {
        return Err(CheckFailure::Unproven);
    };
    let idxs = unique_ints(raw);
    if idxs.len() < 2 || !bounds_ok(&idxs, events.len()) {
        return Err(CheckFailure::Unproven);
    }
    let Some(positions) = positions_of(&idxs) else {
        return Err(CheckFailure::Unproven);
    };
    let Some(&keep_at) = positions.first() else {
        return Err(CheckFailure::Unproven);
    };
    let Some(&end) = positions.last() else {
        return Err(CheckFailure::Unproven);
    };
    let Some(kept) = events.get(keep_at) else {
        return Err(CheckFailure::Unproven);
    };
    let kept_key = nonempty_id(event_id(kept).map_err(CheckFailure::Exception)?);
    let mut indices: BTreeSet<usize> = positions.iter().copied().collect();
    let mut ids = BTreeSet::new();
    if let Some(id) = kept_key.clone() {
        ids.insert(id);
    }
    let mut dropped_ids = BTreeSet::new();
    for &position in positions.iter().skip(1) {
        let Some(event) = events.get(position) else {
            return Err(CheckFailure::Unproven);
        };
        let Some(id) = nonempty_id(event_id(event).map_err(CheckFailure::Exception)?) else {
            continue;
        };
        if kept_key.as_deref() != Some(id.as_str()) {
            dropped_ids.insert(id.clone());
        }
        ids.insert(id);
    }
    if !dropped_ids.is_empty() {
        add_relinked_children(events, &dropped_ids, &mut indices, &mut ids)
            .map_err(CheckFailure::Exception)?;
    }
    Ok(CheckSpan {
        indices,
        ids,
        ranges: vec![(keep_at, end)],
    })
}

fn add_relinked_children(
    events: &[EventValue],
    dropped_ids: &BTreeSet<String>,
    indices: &mut BTreeSet<usize>,
    ids: &mut BTreeSet<String>,
) -> Result<(), EventError> {
    for (index, event) in events.iter().enumerate() {
        let Some(parent) = event_parent_id(event)? else {
            continue;
        };
        if !dropped_ids.contains(&parent) {
            continue;
        }
        indices.insert(index);
        if let Some(child_id) = nonempty_id(event_id(event)?) {
            ids.insert(child_id);
        }
    }
    Ok(())
}

fn seq_renumber_check(step: &RecipeStep, events: &[EventValue]) -> Result<CheckSpan, CheckFailure> {
    let _ignored = (step, events);
    Ok(CheckSpan {
        indices: BTreeSet::new(),
        ids: BTreeSet::new(),
        ranges: Vec::new(),
    })
}

#[cfg(test)]
mod tests_recipes_04 {
    use std::collections::BTreeSet;
    use std::error::Error;

    use model::canonical::{
        SessionEvent, NORMALIZE_CANONICAL_UNAVAILABLE, PAYLOAD_CONTENT_HASH_UNAVAILABLE,
    };
    use model::codes::{SL003, SL004, SL005, SL104, SL108};
    use model::events::{
        EventError, EventField, EventMapping, EventValue, DETERMINISM_CANONICAL_JSON_BYTES_UNAVAILABLE,
        PYTHON_FLOAT_STR_UNREPRESENTABLE, PYTHON_STR_HASH_UNREPRESENTABLE,
    };

    use super::{
        affected_region_compaction_projection_reunion, affected_region_duplicate_projection_removal,
        affected_region_identical_duplicate_collapse, affected_region_identical_duplicate_drop,
        affected_region_proven_unique_parent_restore, affected_region_seq_renumber,
        apply_compaction_projection_reunion, apply_duplicate_projection_removal,
        apply_identical_duplicate_collapse, apply_identical_duplicate_drop,
        apply_proven_unique_parent_restore, apply_seq_renumber, apply_terminal_suffix_discard,
        identical_duplicate_drop_check, seq_renumber_check, AffectedRegionUnavailable, CheckFailure,
        CheckSpan, ConservativeError, IndexValue, ParamMap, RecipeStep, ALL,
        AFFECTED_REGION_UNAVAILABLE, CONSERVATIVE_RECIPES, RECIPES,
    };
    use crate::registry::CallableId;

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

    fn ints(values: &[i64]) -> Vec<EventField> {
        values.iter().copied().map(EventField::Int).collect()
    }

    fn drop_step(target: IndexValue, indexes: Vec<EventField>) -> RecipeStep {
        make_step(
            target,
            params_of(vec![
                ("variant", text("identical-duplicate")),
                ("record_indexes", EventField::List(indexes)),
            ]),
        )
    }

    fn hashed(kind: &str, id: EventField, hash: &str) -> EventValue {
        ev(vec![
            ("kind", text(kind)),
            ("id", id),
            ("content_hash", text(hash)),
        ])
    }

    fn note(id: &str, hash: &str) -> EventValue {
        hashed("note", text(id), hash)
    }

    fn with_parent(id: &str, hash: &str, parent: EventField) -> EventValue {
        ev(vec![
            ("kind", text("message")),
            ("id", text(id)),
            ("content_hash", text(hash)),
            ("parent_id", parent),
        ])
    }

    fn snapshot(events: &[EventValue]) -> Vec<EventMapping> {
        events
            .iter()
            .map(|event| match event {
                EventValue::Mapping(mapping) => mapping.clone(),
                EventValue::Session(_) | EventValue::Other => EventMapping::new(Vec::new()),
            })
            .collect()
    }

    fn mapping_at(events: &[EventValue], index: usize) -> EventMapping {
        match &events[index] {
            EventValue::Mapping(mapping) => mapping.clone(),
            EventValue::Session(_) | EventValue::Other => EventMapping::new(Vec::new()),
        }
    }

    fn proven(
        indices: &[usize],
        ids: &[&str],
        ranges: &[(usize, usize)],
    ) -> Result<CheckSpan, CheckFailure> {
        Ok(CheckSpan {
            indices: indices.iter().copied().collect(),
            ids: ids.iter().map(|id| (*id).to_owned()).collect(),
            ranges: ranges.to_vec(),
        })
    }

    fn unproven() -> Result<CheckSpan, CheckFailure> {
        Err(CheckFailure::Unproven)
    }

    fn assert_seam(error: &AffectedRegionUnavailable) {
        let text = error.to_string();
        assert_eq!(
            text,
            "sesslint.policy.abstention.AffectedRegion is not available"
        );
        assert_eq!(text, AFFECTED_REGION_UNAVAILABLE);
        assert_eq!(error.message(), text);
        assert_eq!(*error, AffectedRegionUnavailable);
        assert!(Error::source(error).is_none());
        assert_ne!(text, "true");
        assert!(!text.contains("true"));
        assert!(!text.contains("unproven"));
        assert!(!text.contains("evt-"));
        assert!(!text.contains("representable"));
        assert!(!text.contains("float"));
    }

    fn assert_precondition(events: &[EventValue], step: &RecipeStep, expected: &str) {
        let before = snapshot(events);
        let error = apply_identical_duplicate_drop(events, step).expect_err("precondition");
        assert_eq!(error.to_string(), expected);
        assert!(matches!(error, ConservativeError::Precondition(_)));
        assert_ne!(error.to_string(), "true");
        assert_eq!(snapshot(events), before);
    }

    fn assert_event_error(events: &[EventValue], step: &RecipeStep, expected: &str) {
        let before = snapshot(events);
        let error = apply_identical_duplicate_drop(events, step).expect_err("event");
        assert_eq!(error.to_string(), expected);
        assert!(matches!(error, ConservativeError::Event(_)));
        assert!(!error.to_string().contains("content drift"));
        assert_ne!(error.to_string(), "true");
        assert_eq!(snapshot(events), before);
    }

    #[test]
    fn drop_variant_and_index_shape_use_the_pin_messages() {
        let events = vec![note("evt-a", "hash-a"), note("evt-a", "hash-a")];
        assert_precondition(
            &events,
            &make_step(IndexValue::None, ParamMap::NotMapping),
            "identical-duplicate-drop: finding variant is not identical-duplicate",
        );
        assert_precondition(
            &events,
            &make_step(
                IndexValue::Bool(true),
                params_of(vec![("record_indexes", EventField::List(ints(&[0, 1])))]),
            ),
            "identical-duplicate-drop: finding variant is not identical-duplicate",
        );
        assert_precondition(
            &events,
            &make_step(
                IndexValue::None,
                params_of(vec![
                    ("variant", text("other")),
                    ("record_indexes", EventField::List(ints(&[0, 1]))),
                ]),
            ),
            "identical-duplicate-drop: finding variant is not identical-duplicate",
        );
        assert_precondition(
            &events,
            &make_step(
                IndexValue::None,
                params_of(vec![("variant", text("identical-duplicate"))]),
            ),
            "identical-duplicate-drop: record_indexes missing",
        );
        assert_precondition(
            &events,
            &make_step(
                IndexValue::None,
                params_of(vec![
                    ("variant", text("identical-duplicate")),
                    ("record_indexes", text("01")),
                ]),
            ),
            "identical-duplicate-drop: record_indexes missing",
        );
        assert_precondition(
            &events,
            &drop_step(IndexValue::None, vec![EventField::Bool(false), EventField::Bool(true)]),
            "identical-duplicate-drop: fewer than 2 valid occurrence indexes",
        );
        assert_precondition(
            &events,
            &drop_step(
                IndexValue::None,
                vec![EventField::Int(0), EventField::Bool(true), EventField::Int(1)],
            ),
            "identical-duplicate-drop: fewer than 2 valid occurrence indexes",
        );
        assert_precondition(
            &events,
            &drop_step(IndexValue::None, ints(&[0, 0])),
            "identical-duplicate-drop: fewer than 2 valid occurrence indexes",
        );
        assert_precondition(
            &events,
            &drop_step(IndexValue::None, ints(&[0, 1, 1])),
            "identical-duplicate-drop: fewer than 2 valid occurrence indexes",
        );
        assert_precondition(
            &events,
            &drop_step(IndexValue::None, ints(&[-1, 0])),
            "identical-duplicate-drop: occurrence index out of bounds",
        );
        assert_precondition(
            &[note("evt-only", "hash-a")],
            &drop_step(IndexValue::None, ints(&[0, 1])),
            "identical-duplicate-drop: occurrence index out of bounds",
        );
    }

    #[test]
    fn drop_boundary_and_fingerprint_errors_are_not_a_drop() {
        let pair = drop_step(IndexValue::Bool(true), ints(&[0, 1]));
        let checkpoints = vec![
            hashed("checkpoint", text("evt-a"), "hash-a"),
            ev(vec![
                ("kind", text("checkpoint")),
                ("id", EventField::Float(1.5)),
            ]),
        ];
        assert_precondition(
            &checkpoints,
            &pair,
            "identical-duplicate-drop: cannot drop boundary kind 'checkpoint'",
        );
        let boundaries = vec![
            hashed("compaction_boundary", text("evt-a"), "hash-a"),
            hashed("compaction_boundary", text("evt-a"), "hash-a"),
        ];
        assert_precondition(
            &boundaries,
            &pair,
            "identical-duplicate-drop: cannot drop boundary kind 'compaction_boundary'",
        );
        let kept_checkpoint = vec![
            hashed("checkpoint", text("evt-a"), "hash-a"),
            note("evt-b", "hash-a"),
        ];
        assert_precondition(
            &kept_checkpoint,
            &pair,
            "identical-duplicate-drop: cannot drop boundary kind 'checkpoint'",
        );
        let dropped_checkpoint = vec![
            note("evt-a", "hash-a"),
            hashed("checkpoint", text("evt-b"), "hash-a"),
        ];
        assert_precondition(
            &dropped_checkpoint,
            &pair,
            "identical-duplicate-drop: kind mismatch at occurrence 1 ('checkpoint' != 'note')",
        );
        let hashless = vec![
            ev(vec![("kind", text("note")), ("id", text("evt-a"))]),
            ev(vec![("kind", text("note")), ("id", text("evt-a"))]),
        ];
        assert_event_error(
            &hashless,
            &pair,
            DETERMINISM_CANONICAL_JSON_BYTES_UNAVAILABLE,
        );
        let float_id = vec![
            ev(vec![
                ("kind", text("note")),
                ("id", EventField::Float(1.5)),
                ("content_hash", text("hash-a")),
            ]),
            note("evt-b", "hash-a"),
        ];
        assert_event_error(&float_id, &pair, PYTHON_FLOAT_STR_UNREPRESENTABLE);
        let second_hashless = vec![
            note("evt-a", "hash-a"),
            ev(vec![("kind", text("note")), ("id", text("evt-b"))]),
        ];
        assert_event_error(
            &second_hashless,
            &pair,
            DETERMINISM_CANONICAL_JSON_BYTES_UNAVAILABLE,
        );
        assert_event_error(
            &[EventValue::Other, EventValue::Other],
            &pair,
            PYTHON_STR_HASH_UNREPRESENTABLE,
        );
        let mut first = SessionEvent::new(
            "evt-a",
            None,
            4,
            "2026-01-01T00:00:00Z",
            "user",
            "note",
        );
        let second = first.clone();
        let sessions = vec![
            EventValue::from_session(first.clone()),
            EventValue::from_session(second),
        ];
        assert_event_error(&sessions, &pair, PAYLOAD_CONTENT_HASH_UNAVAILABLE);
        first.content_hash = Some("hash-a".to_owned());
        let mut other = first.clone();
        other.id = "evt-b".to_owned();
        other.content_hash = Some("hash-b".to_owned());
        let drifted = vec![
            EventValue::from_session(first.clone()),
            EventValue::from_session(other),
        ];
        assert_precondition(
            &drifted,
            &pair,
            "identical-duplicate-drop: content drift at occurrence 1",
        );
        let mut same = first.clone();
        same.id = "evt-a".to_owned();
        let copied = vec![
            EventValue::from_session(first),
            EventValue::from_session(same),
        ];
        let error = apply_identical_duplicate_drop(&copied, &pair).expect_err("copy");
        assert_eq!(error.to_string(), NORMALIZE_CANONICAL_UNAVAILABLE);
        assert!(matches!(error, ConservativeError::Event(_)));
    }

    #[test]
    fn drop_copies_kept_events_and_does_not_relink_without_a_kept_id() {
        let events = vec![
            note("evt-a", "hash-a"),
            ev(vec![
                ("kind", text("checkpoint")),
                ("id", text("evt-mid")),
                ("content_hash", text("hash-mid")),
            ]),
            note("evt-a", "hash-a"),
            with_parent("evt-child", "hash-c", text("evt-a")),
        ];
        let before = snapshot(&events);
        let step = drop_step(IndexValue::Bool(false), ints(&[2, 0]));
        let mut output = apply_identical_duplicate_drop(&events, &step).expect("drop");
        assert_eq!(
            output,
            vec![
                mapping_at(&events, 0),
                mapping_at(&events, 1),
                mapping_at(&events, 3),
            ]
        );
        assert_eq!(output[2].get("parent_id"), Some(&text("evt-a")));
        output[0].push("marker", EventField::Int(1));
        assert_eq!(snapshot(&events), before);
        assert!(before[0].get("marker").is_none());

        let mismatch = vec![note("evt-a", "hash-a"), note("evt-b", "hash-b")];
        assert_precondition(
            &mismatch,
            &drop_step(IndexValue::None, ints(&[0, 1])),
            "identical-duplicate-drop: content drift at occurrence 1",
        );
        let drifted_ids = vec![note("evt-a", "hash-a"), note("evt-b", "hash-a")];
        assert_precondition(
            &drifted_ids,
            &drop_step(IndexValue::None, ints(&[0, 1])),
            "identical-duplicate-drop: event id drift at occurrence 1",
        );
        let later = vec![
            note("evt-a", "hash-a"),
            note("evt-mid", "hash-m"),
            note("evt-b", "hash-a"),
        ];
        assert_precondition(
            &later,
            &drop_step(IndexValue::None, ints(&[0, 2])),
            "identical-duplicate-drop: event id drift at occurrence 2",
        );

        let nameless = vec![
            hashed("note", text(""), "hash-a"),
            hashed("note", text("evt-b"), "hash-a"),
            with_parent("evt-child", "hash-c", text("evt-b")),
        ];
        let output = apply_identical_duplicate_drop(
            &nameless,
            &drop_step(IndexValue::None, ints(&[0, 1])),
        )
        .expect("empty kept id");
        assert_eq!(output.len(), 2);
        assert_eq!(output[0].get("id"), Some(&text("")));
        assert_eq!(output[1].get("parent_id"), Some(&text("evt-b")));

        let missing_dropped_id = vec![
            note("evt-a", "hash-a"),
            ev(vec![
                ("kind", text("note")),
                ("content_hash", text("hash-a")),
            ]),
        ];
        let output = apply_identical_duplicate_drop(
            &missing_dropped_id,
            &drop_step(IndexValue::Int(0), ints(&[0, 1])),
        )
        .expect("missing dropped id");
        assert_eq!(output, vec![mapping_at(&missing_dropped_id, 0)]);
    }

    #[test]
    fn drop_region_runs_the_checks_and_stops_at_affected_region() {
        let events = vec![
            note("evt-keep", "hash-a"),
            ev(vec![("kind", text("checkpoint")), ("id", text("evt-mid"))]),
            note("evt-keep", "hash-b"),
            with_parent("evt-child", "hash-c", text("evt-keep")),
        ];
        let before = snapshot(&events);
        let step = drop_step(IndexValue::Bool(true), ints(&[2, 0, 0]));
        assert_eq!(
            identical_duplicate_drop_check(&step, &events),
            proven(&[0, 2], &["evt-keep"], &[(0, 2)])
        );
        let error = affected_region_identical_duplicate_drop(&step, &events).expect_err("seam");
        assert_seam(&error);
        assert_eq!(snapshot(&events), before);

        let wrong_variant = make_step(
            IndexValue::Other,
            params_of(vec![
                ("variant", text("other")),
                ("record_indexes", EventField::List(ints(&[0, 2]))),
            ]),
        );
        assert_eq!(
            identical_duplicate_drop_check(&wrong_variant, &events),
            proven(&[0, 2], &["evt-keep"], &[(0, 2)])
        );
        assert_seam(
            &affected_region_identical_duplicate_drop(&wrong_variant, &events).expect_err("seam"),
        );
        assert_eq!(
            identical_duplicate_drop_check(&make_step(IndexValue::None, ParamMap::NotMapping), &events),
            unproven()
        );
        assert_eq!(
            identical_duplicate_drop_check(
                &make_step(
                    IndexValue::None,
                    params_of(vec![("record_indexes", text("01"))])
                ),
                &events
            ),
            unproven()
        );
        assert_eq!(
            identical_duplicate_drop_check(
                &make_step(
                    IndexValue::None,
                    params_of(vec![(
                        "record_indexes",
                        EventField::List(vec![EventField::Bool(false), EventField::Bool(true)])
                    )])
                ),
                &events
            ),
            unproven()
        );
        assert_eq!(
            identical_duplicate_drop_check(&drop_step(IndexValue::None, ints(&[-1, 0])), &events),
            unproven()
        );
        assert_eq!(
            identical_duplicate_drop_check(&drop_step(IndexValue::None, ints(&[0, 9])), &events),
            unproven()
        );
        assert_seam(
            &affected_region_identical_duplicate_drop(
                &drop_step(IndexValue::None, ints(&[0, 9])),
                &events,
            )
            .expect_err("bounds seam"),
        );
    }

    #[test]
    fn drop_region_children_bool_indexes_and_errors_stay_on_the_seam() {
        let events = vec![
            hashed("note", EventField::Int(7), "hash-a"),
            ev(vec![
                ("kind", text("message")),
                ("id", EventField::Float(1.5)),
            ]),
            hashed("note", EventField::Int(8), "hash-a"),
            with_parent("evt-child", "hash-c", EventField::Int(8)),
        ];
        let bool_indexes = make_step(
            IndexValue::Bool(true),
            params_of(vec![(
                "record_indexes",
                EventField::List(vec![
                    EventField::Int(2),
                    EventField::Bool(true),
                    EventField::Int(0),
                ]),
            )]),
        );
        assert_eq!(
            identical_duplicate_drop_check(&bool_indexes, &events),
            proven(&[0, 2, 3], &["7", "8", "evt-child"], &[(0, 2)])
        );
        let with_float_parent = vec![
            hashed("note", EventField::Int(7), "hash-a"),
            hashed("note", EventField::Int(8), "hash-a"),
            ev(vec![
                ("kind", text("message")),
                ("id", text("evt-other")),
                ("parent_id", EventField::Float(1.5)),
            ]),
        ];
        let aimed = make_step(
            IndexValue::None,
            params_of(vec![(
                "record_indexes",
                EventField::List(vec![EventField::Int(0), EventField::Int(1)]),
            )]),
        );
        assert_eq!(
            identical_duplicate_drop_check(&aimed, &with_float_parent),
            Err(CheckFailure::Exception(EventError::PythonFloatStr))
        );
        assert_eq!(
            identical_duplicate_drop_check(&aimed, &events),
            Err(CheckFailure::Exception(EventError::PythonFloatStr))
        );
        assert_seam(&affected_region_identical_duplicate_drop(&aimed, &events).expect_err("seam"));
        assert_seam(
            &affected_region_identical_duplicate_drop(&bool_indexes, &events).expect_err("seam"),
        );

        let same = vec![
            note("evt-keep", "hash-a"),
            note("evt-keep", "hash-a"),
            ev(vec![("id", EventField::Float(1.5))]),
        ];
        assert_eq!(
            identical_duplicate_drop_check(&drop_step(IndexValue::None, ints(&[0, 1])), &same),
            proven(&[0, 1], &["evt-keep"], &[(0, 1)])
        );
        let empty_kept = vec![
            hashed("note", text(""), "hash-a"),
            note("evt-b", "hash-a"),
            with_parent("evt-child", "hash-c", text("evt-b")),
        ];
        assert_eq!(
            identical_duplicate_drop_check(
                &drop_step(IndexValue::None, ints(&[0, 1])),
                &empty_kept
            ),
            proven(&[0, 1, 2], &["evt-b", "evt-child"], &[(0, 1)])
        );
        let blank_dropped = vec![
            note("evt-a", "hash-a"),
            hashed("note", text(""), "hash-a"),
        ];
        assert_eq!(
            identical_duplicate_drop_check(
                &drop_step(IndexValue::None, ints(&[0, 1])),
                &blank_dropped
            ),
            proven(&[0, 1], &["evt-a"], &[(0, 1)])
        );

        let mut call = SessionEvent::new(
            "evt-keep",
            None,
            0,
            "2026-01-01T00:00:00Z",
            "user",
            "note",
        );
        let mut child = SessionEvent::new(
            "evt-child",
            Some("evt-drop".to_owned()),
            1,
            "2026-01-01T00:00:00Z",
            "user",
            "message",
        );
        let mut dropped = SessionEvent::new(
            "evt-drop",
            None,
            2,
            "2026-01-01T00:00:00Z",
            "user",
            "note",
        );
        call.content_hash = None;
        child.content_hash = None;
        dropped.content_hash = None;
        let sessions = vec![
            EventValue::from_session(call),
            EventValue::from_session(child),
            EventValue::from_session(dropped),
        ];
        let session_step = drop_step(IndexValue::None, ints(&[0, 2]));
        assert_eq!(
            identical_duplicate_drop_check(&session_step, &sessions),
            proven(&[0, 1, 2], &["evt-child", "evt-drop", "evt-keep"], &[(0, 2)])
        );
        assert_seam(
            &affected_region_identical_duplicate_drop(&session_step, &sessions).expect_err("seam"),
        );
        assert_event_error(&sessions, &session_step, PAYLOAD_CONTENT_HASH_UNAVAILABLE);
    }

    #[test]
    fn seq_renumber_copies_ordinals_and_ignores_the_step() {
        let events = vec![
            ev(vec![
                ("kind", text("note")),
                ("seq", EventField::Bool(true)),
                ("id", text("evt-a")),
            ]),
            ev(vec![
                ("kind", text("note")),
                ("id", text("evt-b")),
                (
                    "payload",
                    EventField::Mapping(bare(vec![("text", text("synthetic"))])),
                ),
            ]),
        ];
        let before = snapshot(&events);
        let step = make_step(
            IndexValue::Bool(true),
            params_of(vec![("record_indexes", EventField::List(ints(&[0, 1])))]),
        );
        let mut output = apply_seq_renumber(&events, &step).expect("renumber");
        assert_eq!(
            output[0],
            bare(vec![
                ("kind", text("note")),
                ("seq", EventField::Int(0)),
                ("id", text("evt-a")),
            ])
        );
        assert_eq!(output[1].get("seq"), Some(&EventField::Int(1)));
        assert_eq!(output[1].get("id"), Some(&text("evt-b")));
        assert!(matches!(output[1].get("payload"), Some(EventField::Mapping(_))));
        output[0].push("marker", EventField::Int(1));
        assert_eq!(snapshot(&events), before);
        assert_eq!(apply_seq_renumber(&[], &step).expect("empty"), Vec::new());

        let session = EventValue::from_session(SessionEvent::new(
            "evt-session",
            None,
            9,
            "2026-01-01T00:00:00Z",
            "user",
            "note",
        ));
        let error = apply_seq_renumber(std::slice::from_ref(&session), &step).expect_err("copy");
        assert_eq!(error.to_string(), NORMALIZE_CANONICAL_UNAVAILABLE);
        assert!(matches!(error, ConservativeError::Event(_)));
        match &session {
            EventValue::Session(event) => assert_eq!(event.seq, 9),
            EventValue::Mapping(_) | EventValue::Other => panic!("session"),
        }
    }

    #[test]
    fn seq_region_discards_inputs_and_stops_at_affected_region() {
        let events = vec![ev(vec![("id", EventField::Float(1.5))])];
        let step = make_step(IndexValue::Bool(true), ParamMap::NotMapping);
        let before = snapshot(&events);
        assert_eq!(
            seq_renumber_check(&step, &events),
            Ok(CheckSpan {
                indices: BTreeSet::new(),
                ids: BTreeSet::new(),
                ranges: Vec::new(),
            })
        );
        assert_eq!(
            seq_renumber_check(&step, &[]),
            seq_renumber_check(&make_step(IndexValue::Int(3), ParamMap::NotMapping), &events)
        );
        let error = affected_region_seq_renumber(&step, &events).expect_err("seam");
        assert_seam(&error);
        assert_ne!(error.to_string(), "true");
        assert_eq!(snapshot(&events), before);
    }

    #[test]
    fn recipes_match_the_pin_and_all_keeps_pin_order() {
        let recipes = RECIPES().expect("recipes");
        let alias = CONSERVATIVE_RECIPES().expect("alias");
        assert_eq!(recipes, alias);
        assert_eq!(
            recipes
                .iter()
                .map(|recipe| recipe.name().to_owned())
                .collect::<Vec<_>>(),
            vec![
                "terminal-suffix-discard",
                "identical-duplicate-collapse",
                "proven-unique-parent-restore",
                "compaction-projection-reunion",
                "duplicate-projection-removal",
                "identical-duplicate-drop",
                "seq-renumber",
            ]
        );
        assert_recipe(
            &recipes[0],
            "terminal-suffix-discard",
            &[SL005],
            &["no_prior_safe_tool_after_cut"],
            true,
            "salvage",
            false,
            Some(CallableId::from_fn(apply_terminal_suffix_discard)),
            None,
        );
        assert_recipe(
            &recipes[1],
            "identical-duplicate-collapse",
            &[SL003],
            &["no_sl203", "adjacent_identical_duplicate"],
            false,
            "conservative",
            false,
            Some(CallableId::from_fn(apply_identical_duplicate_collapse)),
            Some(CallableId::from_fn(
                affected_region_identical_duplicate_collapse,
            )),
        );
        assert_recipe(
            &recipes[2],
            "proven-unique-parent-restore",
            &[SL004],
            &["no_sl203", "unique_parent_candidate"],
            false,
            "conservative",
            false,
            Some(CallableId::from_fn(apply_proven_unique_parent_restore)),
            Some(CallableId::from_fn(
                affected_region_proven_unique_parent_restore,
            )),
        );
        assert_recipe(
            &recipes[3],
            "compaction-projection-reunion",
            &[SL108],
            &["no_sl203", "single_boundary_split"],
            false,
            "conservative",
            false,
            Some(CallableId::from_fn(apply_compaction_projection_reunion)),
            Some(CallableId::from_fn(
                affected_region_compaction_projection_reunion,
            )),
        );
        assert_recipe(
            &recipes[4],
            "duplicate-projection-removal",
            &[SL104],
            &["no_sl203", "duplicate_projection_identical"],
            false,
            "conservative",
            false,
            Some(CallableId::from_fn(apply_duplicate_projection_removal)),
            Some(CallableId::from_fn(
                affected_region_duplicate_projection_removal,
            )),
        );
        assert_recipe(
            &recipes[5],
            "identical-duplicate-drop",
            &[SL003],
            &["no_sl203", "sl003_identical_duplicate"],
            false,
            "conservative",
            false,
            Some(CallableId::from_fn(apply_identical_duplicate_drop)),
            Some(CallableId::from_fn(affected_region_identical_duplicate_drop)),
        );
        assert_recipe(
            &recipes[6],
            "seq-renumber",
            &[],
            &[],
            false,
            "conservative",
            true,
            Some(CallableId::from_fn(apply_seq_renumber)),
            Some(CallableId::from_fn(affected_region_seq_renumber)),
        );
        assert_ne!(recipes[5].apply(), recipes[5].affected_region());
        assert_ne!(recipes[6].apply(), recipes[6].affected_region());
        assert_eq!(
            super::RECIPE_SEQ_RENUMBER().expect("alias"),
            super::recipe_seq_renumber().expect("fn")
        );
        assert_eq!(
            ALL,
            [
                "CONSERVATIVE_RECIPES",
                "PreconditionFailed",
                "RECIPES",
                "RECIPE_COMPACTION_PROJECTION_REUNION",
                "RECIPE_DUPLICATE_PROJECTION_REMOVAL",
                "RECIPE_IDENTICAL_DUPLICATE_DROP",
                "RECIPE_SEQ_RENUMBER",
                "RECIPE_IDENTICAL_DUPLICATE_COLLAPSE",
                "RECIPE_PROVEN_UNIQUE_PARENT_RESTORE",
                "RECIPE_TERMINAL_SUFFIX_DISCARD",
                "affected_region_compaction_projection_reunion",
                "affected_region_duplicate_projection_removal",
                "affected_region_identical_duplicate_drop",
                "affected_region_identical_duplicate_collapse",
                "affected_region_proven_unique_parent_restore",
                "affected_region_torn_terminal_record_discard",
                "apply_compaction_projection_reunion",
                "apply_duplicate_projection_removal",
                "apply_identical_duplicate_collapse",
                "apply_identical_duplicate_drop",
                "apply_seq_renumber",
                "apply_proven_unique_parent_restore",
                "apply_terminal_suffix_discard",
                "compaction_projection_reunion",
                "duplicate_projection_removal",
                "identical_duplicate_collapse",
                "proven_unique_parent_restore",
                "register_all",
                "terminal_suffix_discard",
            ]
        );
        assert!(!ALL.contains(&"affected_region_seq_renumber"));
        assert!(!ALL.contains(&"serde_json"));
        assert_eq!(
            CallableId::from_fn(super::affected_region_torn_terminal_record_discard),
            CallableId::from_fn(
                crate::recipes_sl002::affected_region_torn_terminal_record_discard
            )
        );
        assert_eq!(
            crate::planner::RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE,
            "sesslint.repair.recipes_conservative.register_all is not available"
        );
    }

    #[test]
    fn register_all_registers_defined_recipes_once() {
        if std::env::var_os("SESSLINT_CARD_RECIPES_04_REGISTER").is_some() {
            register_defined_recipes();
            return;
        }
        let exe = std::env::current_exe().expect("test executable");
        let output = std::process::Command::new(exe)
            .args([
                "--exact",
                "recipes_conservative::tests_recipes_04::register_all_registers_defined_recipes_once",
                "--test-threads=1",
            ])
            .env("SESSLINT_CARD_RECIPES_04_REGISTER", "1")
            .output()
            .expect("spawn registry child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "register_all child failed\n{stdout}\n{stderr}"
        );
        assert!(
            stdout.contains("ok. 1 passed"),
            "register_all child did not run\n{stdout}\n{stderr}"
        );
    }

    fn register_defined_recipes() {
        use crate::registry::{clear_registry, get_recipe, list_recipes, register_recipe};

        clear_registry();
        super::register_all().expect("register");
        let names: Vec<String> = list_recipes().iter().map(|recipe| recipe.name().to_owned()).collect();
        assert_eq!(
            names,
            vec![
                "terminal-suffix-discard",
                "identical-duplicate-collapse",
                "proven-unique-parent-restore",
                "compaction-projection-reunion",
                "duplicate-projection-removal",
                "identical-duplicate-drop",
                "seq-renumber",
            ]
        );
        let built = RECIPES().expect("built");
        for recipe in &built {
            assert_eq!(get_recipe(recipe.name()).as_ref(), Some(recipe));
        }
        super::register_all().expect("second");
        assert_eq!(list_recipes().len(), built.len());
        clear_registry();
        register_recipe(&super::recipe_seq_renumber().expect("seq")).expect("seed");
        super::register_all().expect("rest");
        let names: Vec<String> = list_recipes().iter().map(|recipe| recipe.name().to_owned()).collect();
        assert_eq!(
            names,
            vec![
                "seq-renumber",
                "terminal-suffix-discard",
                "identical-duplicate-collapse",
                "proven-unique-parent-restore",
                "compaction-projection-reunion",
                "duplicate-projection-removal",
                "identical-duplicate-drop",
            ]
        );
        assert_eq!(
            get_recipe("identical-duplicate-drop").expect("drop").apply(),
            Some(CallableId::from_fn(apply_identical_duplicate_drop))
        );
        assert!(get_recipe("seq-renumber")
            .expect("seq")
            .excludes_execution_dependence());
        clear_registry();
    }

    #[allow(clippy::too_many_arguments)]
    fn assert_recipe(
        recipe: &crate::registry::Recipe,
        name: &str,
        handles: &[&str],
        preconditions: &[&str],
        lossy: bool,
        policy: &str,
        excludes: bool,
        apply: Option<CallableId>,
        region: Option<CallableId>,
    ) {
        assert_eq!(recipe.name(), name);
        assert_eq!(
            recipe
                .handles()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            handles
        );
        assert_eq!(
            recipe
                .preconditions()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            preconditions
        );
        assert_eq!(recipe.lossy(), lossy);
        assert_eq!(recipe.salvage_only(), lossy);
        assert_eq!(recipe.min_policy(), policy);
        assert_eq!(recipe.version(), "1.0.0");
        assert_eq!(recipe.excludes_execution_dependence(), excludes);
        assert_eq!(recipe.apply(), apply);
        assert_eq!(recipe.affected_region(), region);
    }
}
