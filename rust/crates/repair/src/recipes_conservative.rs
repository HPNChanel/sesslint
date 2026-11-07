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
