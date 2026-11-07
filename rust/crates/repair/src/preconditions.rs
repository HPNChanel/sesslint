//! Precondition engine for deterministic repair planning (TASK-018).
//!
//! Port of `src/sesslint/repair/preconditions.py`
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! Pure functions: no I/O, no disk access, no mutation of inputs.
//! Fail closed. This crate does not depend on `checks`, so two calls stay
//! unavailable:
//! [`MUST_ABSTAIN_UNAVAILABLE`] and
//! [`FIND_QUALIFYING_PARENT_CANDIDATES_UNAVAILABLE`].
//! Logic before each call still runs. A true result that needs the call is
//! not returned.
//!
//! Event fingerprints that need canonical JSON or payload hashing propagate
//! the event error. This module does not hash and does not iterate a `HashMap`.
//!
//! [`register_precondition`] updates the module registry the way
//! `PRECONDITION_FUNCS` does. That table is not an input.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt;
use std::sync::{Mutex, OnceLock};

use model::canonical::{MapLookup, Payload, SessionEvent};
use model::events::{
    event_content_fingerprint, event_corr_id, event_id, event_kind, event_parent_id, EventError,
    EventField, EventMapping, EventValue,
};
use model::finding::{DictValue, Finding};

/// `sesslint.policy.abstention.must_abstain` is not available in this crate.
pub const MUST_ABSTAIN_UNAVAILABLE: &str =
    "sesslint.policy.abstention.must_abstain is not available";

/// `sesslint.checks.graph.find_qualifying_parent_candidates` is not available.
pub const FIND_QUALIFYING_PARENT_CANDIDATES_UNAVAILABLE: &str =
    "sesslint.checks.graph.find_qualifying_parent_candidates is not available";

/// Python `_TOOL_KINDS`. Membership only. A `frozenset` has no iteration contract.
const TOOL_KINDS: [&str; 3] = ["tool_call", "tool_use", "tool_result"];

const BOUNDARY_KINDS: [&str; 2] = ["checkpoint", "compaction_boundary"];

/// Failure from a precondition predicate.
///
/// [`Display`](fmt::Display) is the message only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreconditionError {
    /// An `_event_*` helper failed. Display is that error's display.
    Event(EventError),
    /// A Python call this crate does not have. Display is `module.function is not available`.
    Unavailable(&'static str),
    /// Python `ValueError`. Display is the message only.
    Value(String),
}

impl fmt::Display for PreconditionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Event(error) => error.fmt(formatter),
            Self::Unavailable(message) => formatter.write_str(message),
            Self::Value(message) => formatter.write_str(message),
        }
    }
}

impl Error for PreconditionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Event(error) => Some(error),
            Self::Unavailable(_) | Self::Value(_) => None,
        }
    }
}

/// Evaluation context passed to recipe precondition predicates.
///
/// Python: `PreconditionContext` (`frozen=True`, `slots=True`).
/// `finding` defaults to absent, `policy` to `"conservative"`, and
/// `acknowledge_side_effects` to false. Fields are borrowed. Predicates do
/// not write them.
#[derive(Debug, Clone, Copy)]
pub struct PreconditionContext<'a> {
    pub findings: &'a [Finding],
    pub events: &'a [EventValue],
    pub profile: &'a str,
    pub source_hash: &'a str,
    pub finding: Option<&'a Finding>,
    pub policy: &'a str,
    pub acknowledge_side_effects: bool,
}

impl<'a> PreconditionContext<'a> {
    /// Build a context with the Python defaults for the optional fields.
    pub fn new(
        findings: &'a [Finding],
        events: &'a [EventValue],
        profile: &'a str,
        source_hash: &'a str,
    ) -> Self {
        Self {
            findings,
            events,
            profile,
            source_hash,
            finding: None,
            policy: "conservative",
            acknowledge_side_effects: false,
        }
    }
}

/// Precondition: session contains no SL203 findings.
pub fn no_sl203(ctx: &PreconditionContext<'_>) -> bool {
    !ctx.findings.iter().any(|finding| finding.code() == "SL203")
}

/// Precondition: every tool event has `side_effects == "none"`.
///
/// A missing side effect is not `"none"`. Non-tool events are ignored.
/// Kind and side-effect values are not stringified: only a string kind in
/// [`TOOL_KINDS`] is a tool, and only the string `"none"` passes.
pub fn side_effects_known(ctx: &PreconditionContext<'_>) -> bool {
    ctx.events.iter().all(tool_side_effect_is_none)
}

/// Precondition: target finding repairability is `safe-auto` or `deterministic`.
///
/// A [`Finding`] stores `Repairability`. Its value is `as_str()`.
/// `Repairability.DETERMINISTIC.value` is `"deterministic"`.
pub fn repairability_is_safe_auto(ctx: &PreconditionContext<'_>) -> bool {
    match ctx.finding {
        Some(finding) => matches!(
            finding.repairability().as_str(),
            "safe-auto" | "deterministic"
        ),
        None => false,
    }
}

/// Precondition: target finding repairability is `salvage` or `lossy-explicit`.
///
/// `Repairability.LOSSY_EXPLICIT.value` is `"lossy-explicit"`.
pub fn repairability_is_salvage(ctx: &PreconditionContext<'_>) -> bool {
    match ctx.finding {
        Some(finding) => matches!(
            finding.repairability().as_str(),
            "salvage" | "lossy-explicit"
        ),
        None => false,
    }
}

/// Precondition: `source_hash` is non-empty and its Python `len` is 64.
///
/// The length is Unicode scalar values. The predicate does not check hex.
pub fn source_hash_pinned(ctx: &PreconditionContext<'_>) -> bool {
    !ctx.source_hash.is_empty() && ctx.source_hash.chars().count() == 64
}

/// Precondition: a cut index exists and the discarded suffix has no checkpoint.
///
/// The trigger check runs first. Python then calls `must_abstain` and returns
/// false when a reason starts with `side-effect-`. That function is not
/// available. The pure checks after it still run and can prove the predicate
/// false. When they would allow it, this returns [`MUST_ABSTAIN_UNAVAILABLE`]
/// instead of true.
///
/// # Errors
///
/// Returns [`PreconditionError::Event`] when a suffix `_event_kind` fails.
/// Returns [`PreconditionError::Unavailable`] when only `must_abstain` is left.
pub fn no_prior_safe_tool_after_cut(
    ctx: &PreconditionContext<'_>,
) -> Result<bool, PreconditionError> {
    if !has_cut_trigger(ctx) || !side_effects_known(ctx) {
        return Ok(false);
    }
    let Some(cut) = resolve_cut(ctx) else {
        return Ok(false);
    };
    let Some(start) = suffix_start(cut, ctx.events.len()) else {
        return Ok(false);
    };
    if suffix_has_checkpoint(ctx.events, start)? {
        return Ok(false);
    }
    Err(PreconditionError::Unavailable(MUST_ABSTAIN_UNAVAILABLE))
}

/// Precondition: one adjacent pair shares kind, is not a boundary, and matches fingerprints.
///
/// A `record_indexes` list must be exactly one adjacent pair. That path also
/// requires equal event ids. The index path and the full scan do not.
///
/// # Errors
///
/// Returns [`PreconditionError::Event`] from `_event_kind`, `_event_id`, or
/// `_event_content_fingerprint`. Later calls are skipped when `and` would skip them.
pub fn adjacent_identical_duplicate(
    ctx: &PreconditionContext<'_>,
) -> Result<bool, PreconditionError> {
    if let Some(finding) = ctx.finding {
        if let Some(evidence) = evidence_map(finding) {
            if let Some(matched) = listed_duplicate(ctx, &evidence)? {
                return Ok(matched);
            }
            if evidence.is_truthy() {
                if let Some(index) = fallback_index(&evidence) {
                    return indexed_duplicate(ctx.events, index);
                }
            }
        }
    }
    scan_duplicates(ctx.events)
}

/// Precondition: exactly one qualifying parent.
///
/// Index and parent resolution run first. The qualifying-parent walk is
/// [`FIND_QUALIFYING_PARENT_CANDIDATES_UNAVAILABLE`]. This does not return true.
///
/// # Errors
///
/// Returns [`PreconditionError::Event`] from `_event_id` or `_event_parent_id`
/// when that call runs. Returns [`PreconditionError::Unavailable`] when the
/// graph walk would run.
pub fn unique_parent_candidate(ctx: &PreconditionContext<'_>) -> Result<bool, PreconditionError> {
    let Some(finding) = ctx.finding else {
        return Ok(false);
    };
    let evidence = evidence_map(finding);
    let Some(target) = resolve_target_index(ctx, finding, evidence.as_ref())? else {
        return Ok(false);
    };
    if !parent_is_present(ctx, evidence.as_ref(), target)? {
        return Ok(false);
    }
    Err(PreconditionError::Unavailable(
        FIND_QUALIFYING_PARENT_CANDIDATES_UNAVAILABLE,
    ))
}

/// Precondition: one tool call and one tool result have exactly one compaction boundary between them.
///
/// # Errors
///
/// Returns [`PreconditionError::Event`] from `_event_kind` or `_event_corr_id`.
/// A non-matching kind does not read the correlation id.
pub fn single_boundary_split(ctx: &PreconditionContext<'_>) -> Result<bool, PreconditionError> {
    let Some(corr) = correlation_key(ctx, false)? else {
        return Ok(false);
    };
    let (calls, results) = split_corr_indexes(ctx.events, &corr)?;
    let (Some(call), Some(result)) = (only_index(&calls), only_index(&results)) else {
        return Ok(false);
    };
    let start = call.min(result);
    let end = call.max(result);
    let mut boundaries = 0usize;
    for index in (start + 1)..end {
        let Some(event) = ctx.events.get(index) else {
            return Ok(false);
        };
        if map_event(event_kind(event))?.as_deref() == Some("compaction_boundary") {
            boundaries += 1;
        }
    }
    Ok(boundaries == 1)
}

/// Precondition: at least two `tool_result` events for one correlation id share a fingerprint.
///
/// # Errors
///
/// Returns [`PreconditionError::Event`] from kind, correlation, or fingerprint
/// helpers. Fingerprints run only after two results are collected. `any` stops
/// on the first equal fingerprint.
pub fn duplicate_projection_identical(
    ctx: &PreconditionContext<'_>,
) -> Result<bool, PreconditionError> {
    let Some(corr) = correlation_key(ctx, true)? else {
        return Ok(false);
    };
    let mut results = Vec::new();
    for event in ctx.events {
        if map_event(event_kind(event))?.as_deref() != Some("tool_result") {
            continue;
        }
        let event_corr = map_event(event_corr_id(event))?;
        if corr_matches(event_corr.as_deref(), &corr) {
            results.push(event);
        }
    }
    let Some((first, rest)) = results.split_first() else {
        return Ok(false);
    };
    if rest.is_empty() {
        return Ok(false);
    }
    let first_fingerprint = map_event(event_content_fingerprint(first))?;
    for event in rest {
        let fingerprint = map_event(event_content_fingerprint(event))?;
        if fingerprint == first_fingerprint {
            return Ok(true);
        }
    }
    Ok(false)
}

fn map_event<T>(result: Result<T, EventError>) -> Result<T, PreconditionError> {
    result.map_err(PreconditionError::Event)
}

fn is_tool_kind(kind: &str) -> bool {
    TOOL_KINDS.contains(&kind)
}

fn is_boundary(kind: Option<&str>) -> bool {
    matches!(kind, Some(text) if BOUNDARY_KINDS.contains(&text))
}

fn is_call_kind(kind: Option<&str>) -> bool {
    matches!(kind, Some("tool_call" | "tool_use"))
}

fn tool_side_effect_is_none(event: &EventValue) -> bool {
    match event {
        EventValue::Session(event) => !is_tool_kind(&event.kind) || session_side_is_none(event),
        EventValue::Mapping(mapping) => {
            !mapping_kind_is_tool(mapping) || mapping_side_is_none(mapping)
        }
        EventValue::Other => true,
    }
}

fn session_side_is_none(event: &SessionEvent) -> bool {
    match event.side_effects.as_deref() {
        Some("none") => true,
        Some(_) => false,
        None => payload_side_is_none(&event.payload),
    }
}

fn payload_side_is_none(payload: &Payload) -> bool {
    match payload.map_string("side_effects") {
        MapLookup::Present(value) => value.as_str() == Some("none"),
        MapLookup::Absent | MapLookup::NotAMap | MapLookup::Borrowed => false,
    }
}

fn mapping_kind_is_tool(mapping: &EventMapping) -> bool {
    match mapping.get("kind") {
        Some(EventField::Str(kind)) => is_tool_kind(kind),
        _ => false,
    }
}

fn mapping_side_is_none(mapping: &EventMapping) -> bool {
    match side_label(mapping.get("side_effects")) {
        SideLabel::None => true,
        SideLabel::Other => false,
        SideLabel::Missing => match mapping.get("payload") {
            Some(EventField::Mapping(payload)) => {
                matches!(side_label(payload.get("side_effects")), SideLabel::None)
            }
            _ => false,
        },
    }
}

enum SideLabel {
    None,
    Other,
    Missing,
}

fn side_label(field: Option<&EventField>) -> SideLabel {
    match field {
        Some(EventField::Str(text)) if text == "none" => SideLabel::None,
        None | Some(EventField::Null) => SideLabel::Missing,
        Some(_) => SideLabel::Other,
    }
}

fn has_cut_trigger(ctx: &PreconditionContext<'_>) -> bool {
    ctx.findings.iter().any(|finding| {
        finding.code() == "SL203"
            || (finding.code() == "SL005" && finding.severity().as_str() == "fatal")
    })
}

fn resolve_cut(ctx: &PreconditionContext<'_>) -> Option<i64> {
    if let Some(finding) = ctx.finding {
        if let Some(evidence) = evidence_map(finding) {
            if evidence.is_truthy() {
                if let Some(cut) = primary_cut(&evidence) {
                    return Some(cut);
                }
            }
        }
    }
    let mut cuts = Vec::new();
    for finding in ctx.findings {
        if finding.code() != "SL203" && finding.code() != "SL005" {
            continue;
        }
        let Some(evidence) = evidence_map(finding) else {
            continue;
        };
        if !evidence.is_truthy() {
            continue;
        }
        if let Some(cut) = candidate_cut(&evidence) {
            cuts.push(cut);
        }
    }
    minimum_i64(&cuts)
}

fn primary_cut(evidence: &EvidenceMap) -> Option<i64> {
    as_int(first_not_none(&[
        evidence.get("first_unsafe_index"),
        evidence.get("at_index"),
        evidence.get("index"),
        evidence.get("entry_index"),
    ]))
}

fn candidate_cut(evidence: &EvidenceMap) -> Option<i64> {
    as_int(python_or(&[
        evidence.get("first_unsafe_index"),
        evidence.get("at_index"),
        evidence.get("index"),
        evidence.get("entry_index"),
    ]))
}

fn minimum_i64(values: &[i64]) -> Option<i64> {
    let mut values = values.iter().copied();
    let mut best = values.next()?;
    for value in values {
        if value < best {
            best = value;
        }
    }
    Some(best)
}

fn suffix_start(cut: i64, len: usize) -> Option<usize> {
    if cut <= 0 {
        None
    } else {
        index_in_range(cut, len)
    }
}

fn suffix_has_checkpoint(events: &[EventValue], start: usize) -> Result<bool, PreconditionError> {
    for event in events.iter().skip(start) {
        if map_event(event_kind(event))?.as_deref() == Some("checkpoint") {
            return Ok(true);
        }
    }
    Ok(false)
}

fn listed_duplicate(
    ctx: &PreconditionContext<'_>,
    evidence: &EvidenceMap,
) -> Result<Option<bool>, PreconditionError> {
    let pair = match evidence.get("record_indexes") {
        None | Some(DictValue::None) => return Ok(None),
        Some(listed) => sequence_pair(listed),
    };
    if key_truthy(evidence, "truncated") || count_rejects_pair(evidence) {
        return Ok(Some(false));
    }
    let Some((first, second)) = pair else {
        return Ok(Some(false));
    };
    let Some((left, right)) = adjacent_positions(first, second, ctx.events.len()) else {
        return Ok(Some(false));
    };
    let (Some(left_event), Some(right_event)) = (ctx.events.get(left), ctx.events.get(right))
    else {
        return Ok(Some(false));
    };
    Ok(Some(same_adjacent(left_event, right_event, true)?))
}

fn fallback_index(evidence: &EvidenceMap) -> Option<i64> {
    if let Some(index) = first_int_key(evidence, &["at_index", "index", "first_index"]) {
        return Some(index);
    }
    let listed = evidence.get("record_indexes")?;
    if matches!(listed, DictValue::Str(_) | DictValue::Bytes(_)) {
        return None;
    }
    first_sequence_int(listed)
}

fn indexed_duplicate(events: &[EventValue], index: i64) -> Result<bool, PreconditionError> {
    if let Some(anchor) = forward_anchor(index, events.len()) {
        if pair_matches(events, anchor, anchor + 1, false)? {
            return Ok(true);
        }
    }
    if let Some(anchor) = backward_anchor(index, events.len()) {
        if pair_matches(events, anchor - 1, anchor, false)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn scan_duplicates(events: &[EventValue]) -> Result<bool, PreconditionError> {
    if events.len() < 2 {
        return Ok(false);
    }
    for index in 0..events.len() - 1 {
        if pair_matches(events, index, index + 1, false)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn pair_matches(
    events: &[EventValue],
    left: usize,
    right: usize,
    require_same_id: bool,
) -> Result<bool, PreconditionError> {
    let (Some(left_event), Some(right_event)) = (events.get(left), events.get(right)) else {
        return Ok(false);
    };
    same_adjacent(left_event, right_event, require_same_id)
}

fn same_adjacent(
    left: &EventValue,
    right: &EventValue,
    require_same_id: bool,
) -> Result<bool, PreconditionError> {
    let left_kind = map_event(event_kind(left))?;
    let right_kind = map_event(event_kind(right))?;
    if left_kind != right_kind || is_boundary(left_kind.as_deref()) {
        return Ok(false);
    }
    if require_same_id {
        let left_id = map_event(event_id(left))?;
        let right_id = map_event(event_id(right))?;
        if left_id != right_id {
            return Ok(false);
        }
    }
    let left_fingerprint = map_event(event_content_fingerprint(left))?;
    let right_fingerprint = map_event(event_content_fingerprint(right))?;
    Ok(left_fingerprint == right_fingerprint)
}

fn resolve_target_index(
    ctx: &PreconditionContext<'_>,
    finding: &Finding,
    evidence: Option<&EvidenceMap>,
) -> Result<Option<usize>, PreconditionError> {
    if let Some(evidence) = evidence {
        if let Some(index) = explicit_target(evidence, ctx.events.len()) {
            return Ok(Some(index));
        }
    }
    find_id_index(ctx.events, &id_needle(finding, evidence))
}

fn explicit_target(evidence: &EvidenceMap, len: usize) -> Option<usize> {
    let raw = first_not_none(&[evidence.get("index"), evidence.get("at_index")]);
    index_in_range(as_int(raw)?, len)
}

fn id_needle(finding: &Finding, evidence: Option<&EvidenceMap>) -> IdNeedle {
    if let Some(record_id) = finding.source().record_id() {
        if !record_id.is_empty() {
            return IdNeedle::Text(record_id.to_owned());
        }
    }
    match evidence.and_then(|map| map.get("id")) {
        None | Some(DictValue::None) => IdNeedle::Missing,
        Some(DictValue::Str(text)) => IdNeedle::Text(text.clone()),
        Some(_) => IdNeedle::Unequal,
    }
}

fn find_id_index(
    events: &[EventValue],
    needle: &IdNeedle,
) -> Result<Option<usize>, PreconditionError> {
    for (index, event) in events.iter().enumerate() {
        let id = map_event(event_id(event))?;
        if needle_matches(id.as_deref(), needle) {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

fn needle_matches(id: Option<&str>, needle: &IdNeedle) -> bool {
    match (id, needle) {
        (None, IdNeedle::Missing) => true,
        (Some(left), IdNeedle::Text(right)) => left == right,
        _ => false,
    }
}

fn parent_is_present(
    ctx: &PreconditionContext<'_>,
    evidence: Option<&EvidenceMap>,
    index: usize,
) -> Result<bool, PreconditionError> {
    if key_truthy_opt(evidence, "parent_id") {
        return Ok(true);
    }
    let Some(event) = ctx.events.get(index) else {
        return Ok(false);
    };
    let parent = map_event(event_parent_id(event))?;
    if parent.as_deref().is_some_and(|text| !text.is_empty()) {
        return Ok(true);
    }
    Ok(key_truthy_opt(evidence, "parent_fingerprint_prefix"))
}

fn correlation_key(
    ctx: &PreconditionContext<'_>,
    allow_index_fallback: bool,
) -> Result<Option<CorrKey>, PreconditionError> {
    let Some(finding) = ctx.finding else {
        return Ok(None);
    };
    let Some(evidence) = evidence_map(finding) else {
        return Ok(None);
    };
    if let Some(corr) = corr_key(evidence.get("correlation_id")) {
        return Ok(Some(corr));
    }
    if !allow_index_fallback {
        return Ok(None);
    }
    corr_from_indexes(ctx.events, &evidence)
}

fn corr_from_indexes(
    events: &[EventValue],
    evidence: &EvidenceMap,
) -> Result<Option<CorrKey>, PreconditionError> {
    let Some(index) = as_int(python_or(&[
        evidence.get("at_index"),
        evidence.get("index"),
        evidence.get("result_index"),
    ])) else {
        return Ok(None);
    };
    let Some(position) = index_in_range(index, events.len()) else {
        return Ok(None);
    };
    let Some(event) = events.get(position) else {
        return Ok(None);
    };
    let corr = map_event(event_corr_id(event))?;
    Ok(match corr {
        Some(text) if !text.is_empty() => Some(CorrKey::Text(text)),
        _ => None,
    })
}

fn split_corr_indexes(
    events: &[EventValue],
    corr: &CorrKey,
) -> Result<(Vec<usize>, Vec<usize>), PreconditionError> {
    let mut calls = Vec::new();
    let mut results = Vec::new();
    for (index, event) in events.iter().enumerate() {
        let kind = map_event(event_kind(event))?;
        let bucket = if is_call_kind(kind.as_deref()) {
            Some(&mut calls)
        } else if kind.as_deref() == Some("tool_result") {
            Some(&mut results)
        } else {
            None
        };
        let Some(bucket) = bucket else {
            continue;
        };
        let event_corr = map_event(event_corr_id(event))?;
        if corr_matches(event_corr.as_deref(), corr) {
            bucket.push(index);
        }
    }
    Ok((calls, results))
}

fn only_index(indexes: &[usize]) -> Option<usize> {
    if indexes.len() == 1 {
        indexes.first().copied()
    } else {
        None
    }
}

fn corr_key(value: Option<&DictValue>) -> Option<CorrKey> {
    let value = value?;
    if !py_truthy(value) {
        return None;
    }
    match value {
        DictValue::Str(text) => Some(CorrKey::Text(text.clone())),
        _ => Some(CorrKey::NonText),
    }
}

fn corr_matches(event_corr: Option<&str>, key: &CorrKey) -> bool {
    match key {
        CorrKey::Text(text) => event_corr == Some(text.as_str()),
        CorrKey::NonText => false,
    }
}

enum CorrKey {
    Text(String),
    NonText,
}

enum IdNeedle {
    Missing,
    Text(String),
    Unequal,
}

struct EvidenceMap {
    entries: Vec<(String, DictValue)>,
}

impl EvidenceMap {
    fn get(&self, key: &str) -> Option<&DictValue> {
        self.entries
            .iter()
            .rev()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }

    fn is_truthy(&self) -> bool {
        !self.entries.is_empty()
    }
}

fn evidence_map(finding: &Finding) -> Option<EvidenceMap> {
    let mut found = None;
    for (key, value) in finding.to_dict() {
        if key == "evidence" {
            found = Some(value);
        }
    }
    match found {
        Some(DictValue::Map(entries)) => Some(EvidenceMap { entries }),
        _ => None,
    }
}

fn py_truthy(value: &DictValue) -> bool {
    match value {
        DictValue::None => false,
        DictValue::Bool(flag) => *flag,
        DictValue::Int(number) => *number != 0,
        DictValue::Str(text) => !text.is_empty(),
        DictValue::Bytes(bytes) => !bytes.is_empty(),
        DictValue::List(items)
        | DictValue::Tuple(items)
        | DictValue::Set(items)
        | DictValue::FrozenSet(items) => !items.is_empty(),
        DictValue::Map(entries) => !entries.is_empty(),
    }
}

fn first_not_none<'a>(values: &[Option<&'a DictValue>]) -> Option<&'a DictValue> {
    values
        .iter()
        .copied()
        .flatten()
        .find(|value| !matches!(value, DictValue::None))
}

fn python_or<'a>(values: &[Option<&'a DictValue>]) -> Option<&'a DictValue> {
    let mut fallback = None;
    for value in values {
        match *value {
            Some(item) if py_truthy(item) => return Some(item),
            item => fallback = item,
        }
    }
    fallback
}

fn as_int(value: Option<&DictValue>) -> Option<i64> {
    match value {
        Some(DictValue::Int(number)) => Some(*number),
        _ => None,
    }
}

fn index_in_range(index: i64, len: usize) -> Option<usize> {
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

fn forward_anchor(index: i64, len: usize) -> Option<usize> {
    let index = index_in_range(index, len)?;
    if index.checked_add(1).is_some_and(|next| next < len) {
        Some(index)
    } else {
        None
    }
}

fn backward_anchor(index: i64, len: usize) -> Option<usize> {
    let index = index_in_range(index, len)?;
    if index > 0 {
        Some(index)
    } else {
        None
    }
}

fn adjacent_positions(first: i64, second: i64, len: usize) -> Option<(usize, usize)> {
    if first < 0 {
        return None;
    }
    let next = first.checked_add(1)?;
    if second != next {
        return None;
    }
    let start = usize::try_from(first).ok()?;
    let end = usize::try_from(second).ok()?;
    if end < len {
        Some((start, end))
    } else {
        None
    }
}

fn key_truthy(evidence: &EvidenceMap, key: &str) -> bool {
    evidence.get(key).is_some_and(py_truthy)
}

fn key_truthy_opt(evidence: Option<&EvidenceMap>, key: &str) -> bool {
    evidence.is_some_and(|map| key_truthy(map, key))
}

fn count_rejects_pair(evidence: &EvidenceMap) -> bool {
    match evidence.get("count") {
        None | Some(DictValue::Int(2)) => false,
        Some(_) => true,
    }
}

fn sequence_pair(value: &DictValue) -> Option<(i64, i64)> {
    let items = match value {
        DictValue::List(items) | DictValue::Tuple(items) => items.as_slice(),
        _ => return None,
    };
    if items.len() != 2 {
        return None;
    }
    match (items.first(), items.get(1)) {
        (Some(DictValue::Int(first)), Some(DictValue::Int(second))) => Some((*first, *second)),
        _ => None,
    }
}

fn first_int_key(evidence: &EvidenceMap, keys: &[&str]) -> Option<i64> {
    for key in keys {
        if let Some(number) = as_int(evidence.get(key)) {
            return Some(number);
        }
    }
    None
}

fn first_sequence_int(value: &DictValue) -> Option<i64> {
    let items = match value {
        DictValue::List(items) | DictValue::Tuple(items) => items.as_slice(),
        _ => return None,
    };
    for item in items {
        if let DictValue::Int(number) = item {
            return Some(*number);
        }
    }
    None
}

/// Precondition: SL003 evidence is the identical-duplicate class with in-range indexes.
///
/// A truncated list, a `count` other than the index length, a non-sequence,
/// a bool index, or an out-of-range index is false. This does not compare
/// event bytes.
pub fn sl003_identical_duplicate(ctx: &PreconditionContext<'_>) -> bool {
    let Some(finding) = ctx.finding else {
        return false;
    };
    let Some(evidence) = evidence_map(finding) else {
        return false;
    };
    if !matches!(
        evidence.get("variant"),
        Some(DictValue::Str(variant)) if variant == "identical-duplicate"
    ) || key_truthy(&evidence, "truncated")
    {
        return false;
    }
    let Some(items) = evidence.get("record_indexes").and_then(sequence_items) else {
        return false;
    };
    if items.len() < 2 {
        return false;
    }
    let mut indexes = Vec::with_capacity(items.len());
    for item in items {
        let Some(index) = as_int(Some(item)) else {
            return false;
        };
        indexes.push(index);
    }
    if !count_matches_len(&evidence, indexes.len()) {
        return false;
    }
    let len = ctx.events.len();
    indexes
        .iter()
        .all(|index| index_in_range(*index, len).is_some())
}

/// Precondition: planner policy is the string `salvage`.
pub fn salvage_policy(ctx: &PreconditionContext<'_>) -> bool {
    ctx.policy == "salvage"
}

/// Precondition: the operator set `acknowledge_side_effects`.
pub fn acknowledge_side_effects(ctx: &PreconditionContext<'_>) -> bool {
    ctx.acknowledge_side_effects
}

/// Indexes in the undirected parent component of `seed_idx`.
///
/// The order is breadth-first insertion order. That is the order
/// [`branch_has_no_checkpoint`] scans. A Python `set` has that iteration
/// order when it is only grown. An out-of-range seed is still returned after
/// every id and parent read. Those reads run first and can fail.
///
/// # Errors
///
/// Returns [`PreconditionError::Event`] from `_event_id` or `_event_parent_id`.
/// Id reads finish before parent reads.
pub fn _find_component_indices(
    events: &[EventValue],
    seed_idx: i64,
) -> Result<Vec<i64>, PreconditionError> {
    let mut id_to_index = BTreeMap::new();
    for (index, event) in events.iter().enumerate() {
        if let Some(id) = map_event(event_id(event))? {
            id_to_index.insert(id, index);
        }
    }
    let mut adjacent = vec![Vec::new(); events.len()];
    for (index, event) in events.iter().enumerate() {
        let Some(parent) = map_event(event_parent_id(event))? else {
            continue;
        };
        let Some(&parent_index) = id_to_index.get(&parent) else {
            continue;
        };
        push_unique(&mut adjacent[index], parent_index);
        push_unique(&mut adjacent[parent_index], index);
    }

    let mut visited = Vec::new();
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(seed_idx);
    seen.insert(seed_idx);
    visited.push(seed_idx);
    while let Some(current) = queue.pop_front() {
        let Some(position) = usize_from_i64(current) else {
            continue;
        };
        let Some(neighbors) = adjacent.get(position) else {
            continue;
        };
        for &neighbor in neighbors {
            let Some(neighbor) = i64::try_from(neighbor).ok() else {
                continue;
            };
            if seen.insert(neighbor) {
                visited.push(neighbor);
                queue.push_back(neighbor);
            }
        }
    }
    Ok(visited)
}

/// Precondition: the target event's parent component contains no checkpoint.
///
/// Evidence indexes are resolved before `record_id`. A missing seed scans
/// every event. `_event_kind` stops on the first checkpoint. Component
/// construction still reads every id and parent before that scan.
///
/// # Errors
///
/// Returns [`PreconditionError::Event`] from `_event_id`, `_event_parent_id`,
/// or `_event_kind` when that call runs.
pub fn branch_has_no_checkpoint(ctx: &PreconditionContext<'_>) -> Result<bool, PreconditionError> {
    let Some(seed) = resolve_branch_seed(ctx)? else {
        return no_checkpoint(ctx.events);
    };
    let component = _find_component_indices(ctx.events, seed)?;
    for index in component {
        let Some(position) = usize_from_i64(index) else {
            return Ok(false);
        };
        let Some(event) = ctx.events.get(position) else {
            return Ok(false);
        };
        if map_event(event_kind(event))?.as_deref() == Some("checkpoint") {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Indexes dropped for one torn compaction boundary.
///
/// The result is a set. Iteration is ascending index. Membership matches the
/// pin. The boundary is always included. Equal orphan sides keep the trailing
/// side. Event reads run before the "no split" error, in index order, and
/// kind is read before the correlation id.
///
/// # Errors
///
/// Returns [`PreconditionError::Value`] for an empty session, a bad index, a
/// non-boundary, or a boundary with no split or orphan. Returns
/// [`PreconditionError::Event`] from `_event_kind` or `_event_corr_id`.
pub fn _find_torn_compaction_dropped_indices(
    events: &[EventValue],
    boundary_idx: i64,
) -> Result<BTreeSet<usize>, PreconditionError> {
    if events.is_empty() {
        return Err(value_error(
            "Cannot project across compaction in empty session",
        ));
    }
    let Some(boundary) = usize_from_i64(boundary_idx).filter(|index| *index < events.len()) else {
        return Err(value_error(format!(
            "Invalid compaction boundary index {boundary_idx}"
        )));
    };
    let Some(boundary_event) = events.get(boundary) else {
        return Err(value_error(format!(
            "Invalid compaction boundary index {boundary_idx}"
        )));
    };
    if map_event(event_kind(boundary_event))?.as_deref() != Some("compaction_boundary") {
        return Err(value_error(format!(
            "Event at index {boundary_idx} is not a compaction_boundary"
        )));
    }

    let mut calls_before = CorrLists::new();
    let mut results_before = CorrLists::new();
    for (index, event) in events.iter().enumerate().take(boundary) {
        classify_tool(event, index, &mut calls_before, &mut results_before)?;
    }
    let mut calls_after = CorrLists::new();
    let mut results_after = CorrLists::new();
    for (index, event) in events.iter().enumerate().skip(boundary + 1) {
        classify_tool(event, index, &mut calls_after, &mut results_after)?;
    }

    let mut orphans_before = BTreeSet::new();
    let mut orphans_after = BTreeSet::new();
    for corr in corr_keys([&calls_before, &results_before, &calls_after, &results_after]) {
        let calls_before = calls_before.indexes(&corr);
        let results_before = results_before.indexes(&corr);
        let calls_after = calls_after.indexes(&corr);
        let results_after = results_after.indexes(&corr);
        if !calls_before.is_empty() && !results_after.is_empty() {
            orphans_before.extend(calls_before.iter().copied());
            orphans_after.extend(results_after.iter().copied());
        } else if !calls_after.is_empty() && !results_before.is_empty() {
            orphans_before.extend(results_before.iter().copied());
            orphans_after.extend(calls_after.iter().copied());
        } else if !calls_before.is_empty()
            && results_before.is_empty()
            && calls_after.is_empty()
            && results_after.is_empty()
        {
            orphans_before.extend(calls_before.iter().copied());
        } else if !results_after.is_empty()
            && calls_after.is_empty()
            && calls_before.is_empty()
            && results_before.is_empty()
        {
            orphans_after.extend(results_after.iter().copied());
        }
    }
    if orphans_before.is_empty() && orphans_after.is_empty() {
        return Err(value_error(format!(
            "Compaction boundary at index {boundary_idx} has no split pairs or orphaned halves"
        )));
    }
    let minority = if orphans_before.len() < orphans_after.len() {
        &orphans_before
    } else {
        &orphans_after
    };
    let mut dropped = BTreeSet::new();
    dropped.insert(boundary);
    dropped.extend(minority.iter().copied());
    Ok(dropped)
}

/// Precondition: an SL108 finding exists and some boundary has a split or orphan.
///
/// The code check runs before any event read. `ValueError` from one boundary
/// is skipped. Any other error from that boundary is returned.
///
/// # Errors
///
/// Returns [`PreconditionError::Event`] from `_event_kind` while collecting
/// boundaries, or from [`_find_torn_compaction_dropped_indices`] when the
/// error is not a `ValueError`.
pub fn sl108_present(ctx: &PreconditionContext<'_>) -> Result<bool, PreconditionError> {
    if !ctx.findings.iter().any(|finding| finding.code() == "SL108") {
        return Ok(false);
    }
    let mut boundaries = Vec::new();
    for (index, event) in ctx.events.iter().enumerate() {
        if map_event(event_kind(event))?.as_deref() == Some("compaction_boundary") {
            let Some(index) = i64::try_from(index).ok() else {
                return Ok(false);
            };
            boundaries.push(index);
        }
    }
    if boundaries.is_empty() {
        return Ok(false);
    }
    for boundary in boundaries {
        match _find_torn_compaction_dropped_indices(ctx.events, boundary) {
            Ok(_) => return Ok(true),
            Err(PreconditionError::Value(_)) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

/// SL002 whose evidence map has `unterminated is True`.
fn _is_unterminated_torn_append(finding: &Finding) -> bool {
    if finding.code() != "SL002" {
        return false;
    }
    let Some(evidence) = evidence_map(finding) else {
        return false;
    };
    matches!(evidence.get("unterminated"), Some(DictValue::Bool(true)))
}

/// Precondition: the target SL002 finding, or any finding, is an unterminated append.
///
/// A set `finding` is the only record consulted. Integer `1` is not `True`.
pub fn torn_terminal_record(ctx: &PreconditionContext<'_>) -> bool {
    if let Some(finding) = ctx.finding {
        return _is_unterminated_torn_append(finding);
    }
    ctx.findings.iter().any(_is_unterminated_torn_append)
}

/// `PRECONDITION_FUNCS` key order. The Python literal is this order.
#[cfg(test)]
const BUILTIN_PRECONDITION_NAMES: &[&str] = &[
    "acknowledge_side_effects",
    "adjacent_identical_duplicate",
    "branch_has_no_checkpoint",
    "duplicate_projection_identical",
    "no_prior_safe_tool_after_cut",
    "no_sl203",
    "repairability_is_safe_auto",
    "repairability_is_salvage",
    "salvage_policy",
    "side_effects_known",
    "single_boundary_split",
    "sl003_identical_duplicate",
    "sl108_present",
    "source_hash_pinned",
    "torn_terminal_record",
    "unique_parent_candidate",
];

#[derive(Clone, Copy)]
enum Predicate {
    Bool(fn(&PreconditionContext<'_>) -> bool),
    Fallible(fn(&PreconditionContext<'_>) -> Result<bool, PreconditionError>),
}

impl Predicate {
    fn call(self, ctx: &PreconditionContext<'_>) -> Result<bool, PreconditionError> {
        match self {
            Self::Bool(func) => Ok(func(ctx)),
            Self::Fallible(func) => func(ctx),
        }
    }
}

struct Slot {
    name: String,
    predicate: Predicate,
}

/// Keys of `PRECONDITION_FUNCS` in insertion order.
pub fn precondition_func_names() -> Vec<String> {
    with_registry(|registry| registry.iter().map(|slot| slot.name.clone()).collect())
}

/// Register a precondition. An empty name is a `ValueError`.
///
/// An existing name is replaced in place. A new name is appended.
///
/// # Errors
///
/// Returns [`PreconditionError::Value`] when `name` is empty.
pub fn register_precondition(
    name: &str,
    func: fn(&PreconditionContext<'_>) -> bool,
) -> Result<(), PreconditionError> {
    with_registry(|registry| register_slot(registry, name, func))
}

/// Evaluate precondition names in order.
///
/// `(true, None)` when every name passes. `(false, name)` on the first
/// false result. Later names are not called. An unknown name, or a
/// predicate error, is returned and does not become true.
///
/// # Errors
///
/// Returns [`PreconditionError::Value`] for an unknown name. Returns the
/// predicate error unchanged, including [`MUST_ABSTAIN_UNAVAILABLE`] and
/// [`FIND_QUALIFYING_PARENT_CANDIDATES_UNAVAILABLE`].
pub fn check_preconditions<'a>(
    names: &[&'a str],
    ctx: &PreconditionContext<'_>,
) -> Result<(bool, Option<&'a str>), PreconditionError> {
    for name in names {
        let predicate = with_registry(|registry| {
            registry
                .iter()
                .find(|slot| slot.name == *name)
                .map(|slot| slot.predicate)
        });
        let Some(predicate) = predicate else {
            return Err(value_error(format!("Unknown precondition: {name}")));
        };
        if !predicate.call(ctx)? {
            return Ok((false, Some(*name)));
        }
    }
    Ok((true, None))
}

fn value_error(message: impl Into<String>) -> PreconditionError {
    PreconditionError::Value(message.into())
}

fn sequence_items(value: &DictValue) -> Option<&[DictValue]> {
    match value {
        DictValue::List(items) | DictValue::Tuple(items) => Some(items.as_slice()),
        _ => None,
    }
}

fn count_matches_len(evidence: &EvidenceMap, len: usize) -> bool {
    match evidence.get("count") {
        None => true,
        Some(value) => py_equals_len(value, len),
    }
}

fn py_equals_len(value: &DictValue, len: usize) -> bool {
    let Ok(len) = i64::try_from(len) else {
        return false;
    };
    match value {
        DictValue::Int(number) => *number == len,
        DictValue::Bool(flag) => i64::from(*flag) == len,
        _ => false,
    }
}

fn push_unique(neighbors: &mut Vec<usize>, index: usize) {
    if !neighbors.contains(&index) {
        neighbors.push(index);
    }
}

fn usize_from_i64(index: i64) -> Option<usize> {
    usize::try_from(index).ok()
}

fn resolve_branch_seed(ctx: &PreconditionContext<'_>) -> Result<Option<i64>, PreconditionError> {
    let Some(finding) = ctx.finding else {
        return Ok(None);
    };
    if let Some(evidence) = evidence_map(finding).filter(EvidenceMap::is_truthy) {
        if let Some(seed) = evidence_seed(&evidence, ctx.events.len()) {
            return Ok(Some(seed));
        }
    }
    if let Some(record_id) = finding.source().record_id().filter(|text| !text.is_empty()) {
        return record_id_seed(ctx.events, record_id);
    }
    Ok(None)
}

fn evidence_seed(evidence: &EvidenceMap, len: usize) -> Option<i64> {
    for key in ["at_index", "index", "first_index", "entry_index"] {
        if let Some(index) = as_int(evidence.get(key)) {
            if index_in_range(index, len).is_some() {
                return Some(index);
            }
        }
    }
    let items = sequence_items(evidence.get("record_indexes")?)?;
    for item in items {
        if let Some(index) = as_int(Some(item)) {
            if index_in_range(index, len).is_some() {
                return Some(index);
            }
        }
    }
    None
}

fn record_id_seed(
    events: &[EventValue],
    record_id: &str,
) -> Result<Option<i64>, PreconditionError> {
    for (index, event) in events.iter().enumerate() {
        if map_event(event_id(event))?.as_deref() == Some(record_id) {
            return Ok(i64::try_from(index).ok());
        }
    }
    Ok(None)
}

fn no_checkpoint(events: &[EventValue]) -> Result<bool, PreconditionError> {
    for event in events {
        if map_event(event_kind(event))?.as_deref() == Some("checkpoint") {
            return Ok(false);
        }
    }
    Ok(true)
}

struct CorrLists {
    entries: Vec<(String, Vec<usize>)>,
}

impl CorrLists {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn push(&mut self, key: String, index: usize) {
        if let Some((_, indexes)) = self.entries.iter_mut().find(|(name, _)| name == &key) {
            indexes.push(index);
            return;
        }
        self.entries.push((key, vec![index]));
    }

    fn indexes(&self, key: &str) -> &[usize] {
        self.entries
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, indexes)| indexes.as_slice())
            .unwrap_or(&[])
    }
}

fn classify_tool(
    event: &EventValue,
    index: usize,
    calls: &mut CorrLists,
    results: &mut CorrLists,
) -> Result<(), PreconditionError> {
    let kind = map_event(event_kind(event))?;
    let Some(corr) = map_event(event_corr_id(event))?.filter(|text| !text.is_empty()) else {
        return Ok(());
    };
    match kind.as_deref() {
        Some("tool_call" | "tool_use") => calls.push(corr, index),
        Some("tool_result") => results.push(corr, index),
        _ => {}
    }
    Ok(())
}

fn corr_keys(groups: [&CorrLists; 4]) -> Vec<String> {
    let mut seen = Vec::new();
    for group in groups {
        for (key, _) in &group.entries {
            if !seen.iter().any(|seen_key: &String| seen_key == key) {
                seen.push(key.clone());
            }
        }
    }
    seen
}

fn bool_slot(name: &str, func: fn(&PreconditionContext<'_>) -> bool) -> Slot {
    Slot {
        name: name.to_owned(),
        predicate: Predicate::Bool(func),
    }
}

fn fallible_slot(
    name: &str,
    func: fn(&PreconditionContext<'_>) -> Result<bool, PreconditionError>,
) -> Slot {
    Slot {
        name: name.to_owned(),
        predicate: Predicate::Fallible(func),
    }
}

fn builtin_predicates() -> Vec<Slot> {
    vec![
        bool_slot("acknowledge_side_effects", acknowledge_side_effects),
        fallible_slot("adjacent_identical_duplicate", adjacent_identical_duplicate),
        fallible_slot("branch_has_no_checkpoint", branch_has_no_checkpoint),
        fallible_slot(
            "duplicate_projection_identical",
            duplicate_projection_identical,
        ),
        fallible_slot("no_prior_safe_tool_after_cut", no_prior_safe_tool_after_cut),
        bool_slot("no_sl203", no_sl203),
        bool_slot("repairability_is_safe_auto", repairability_is_safe_auto),
        bool_slot("repairability_is_salvage", repairability_is_salvage),
        bool_slot("salvage_policy", salvage_policy),
        bool_slot("side_effects_known", side_effects_known),
        fallible_slot("single_boundary_split", single_boundary_split),
        bool_slot("sl003_identical_duplicate", sl003_identical_duplicate),
        fallible_slot("sl108_present", sl108_present),
        bool_slot("source_hash_pinned", source_hash_pinned),
        bool_slot("torn_terminal_record", torn_terminal_record),
        fallible_slot("unique_parent_candidate", unique_parent_candidate),
    ]
}

fn register_slot(
    registry: &mut Vec<Slot>,
    name: &str,
    func: fn(&PreconditionContext<'_>) -> bool,
) -> Result<(), PreconditionError> {
    if name.is_empty() {
        return Err(value_error("Precondition name must be a non-empty string"));
    }
    if let Some(slot) = registry.iter_mut().find(|slot| slot.name == name) {
        slot.predicate = Predicate::Bool(func);
    } else {
        registry.push(bool_slot(name, func));
    }
    Ok(())
}

fn registry() -> &'static Mutex<Vec<Slot>> {
    static REGISTRY: OnceLock<Mutex<Vec<Slot>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(builtin_predicates()))
}

fn with_registry<T>(body: impl FnOnce(&mut Vec<Slot>) -> T) -> T {
    let mut guard = registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    body(&mut guard)
}

#[cfg(test)]
mod tests {
    use model::canonical::{Payload, SessionEvent};
    use model::codes::{Repairability, Severity};
    use std::collections::BTreeSet;

    use model::events::{
        EventError, EventField, EventMapping, EventValue, PYTHON_FLOAT_STR_UNREPRESENTABLE,
        PYTHON_STR_UNREPRESENTABLE,
    };
    use model::finding::{Finding, FindingInput, PyValue, SourceRef, SCHEMA_VERSION};

    use super::{
        _find_component_indices, _find_torn_compaction_dropped_indices,
        _is_unterminated_torn_append, acknowledge_side_effects, adjacent_identical_duplicate,
        branch_has_no_checkpoint, check_preconditions, duplicate_projection_identical,
        no_prior_safe_tool_after_cut, no_sl203, precondition_func_names, register_precondition,
        repairability_is_safe_auto, repairability_is_salvage, salvage_policy, side_effects_known,
        single_boundary_split, sl003_identical_duplicate, sl108_present, source_hash_pinned,
        torn_terminal_record, unique_parent_candidate, PreconditionContext, PreconditionError,
        FIND_QUALIFYING_PARENT_CANDIDATES_UNAVAILABLE, MUST_ABSTAIN_UNAVAILABLE,
    };

    fn context<'a>(
        findings: &'a [Finding],
        events: &'a [EventValue],
        source_hash: &'a str,
    ) -> PreconditionContext<'a> {
        PreconditionContext::new(findings, events, "neutral", source_hash)
    }

    fn finding(
        code: &str,
        severity: Severity,
        repairability: Repairability,
        record_id: Option<&str>,
        evidence: PyValue,
    ) -> Finding {
        let source = SourceRef::try_new("<canonical>", None, record_id).expect("source");
        Finding::try_new(FindingInput {
            code: PyValue::string(code),
            severity: PyValue::severity(severity),
            repairability: PyValue::repairability(repairability),
            message: PyValue::string("synthetic precondition marker"),
            source: PyValue::source(source),
            related_ids: PyValue::tuple(Vec::new()),
            fingerprint: PyValue::string("0123456789abcdef"),
            schema_version: PyValue::string(SCHEMA_VERSION),
            message_template: PyValue::None,
            evidence,
        })
        .expect("finding")
    }

    fn ev_map(entries: Vec<(&str, PyValue)>) -> PyValue {
        PyValue::map(
            entries
                .into_iter()
                .map(|(key, value)| (PyValue::string(key), value))
                .collect(),
        )
    }

    fn ints(values: &[i64]) -> PyValue {
        PyValue::list(values.iter().copied().map(PyValue::int).collect())
    }

    fn mapped(entries: Vec<(&str, EventField)>) -> EventValue {
        EventValue::Mapping(EventMapping::new(
            entries
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        ))
    }

    fn hashed(id: &str, kind: &str, hash: &str) -> EventValue {
        mapped(vec![
            ("id", EventField::Str(id.to_owned())),
            ("kind", EventField::Str(kind.to_owned())),
            ("content_hash", EventField::Str(hash.to_owned())),
        ])
    }

    fn tool(kind: &str, side_effects: Option<&str>, corr: Option<&str>) -> EventValue {
        let mut entries = vec![("kind", EventField::Str(kind.to_owned()))];
        if let Some(side_effects) = side_effects {
            entries.push(("side_effects", EventField::Str(side_effects.to_owned())));
        }
        if let Some(corr) = corr {
            entries.push(("correlation_id", EventField::Str(corr.to_owned())));
        }
        entries.push(("content_hash", EventField::Str("abc".to_owned())));
        mapped(entries)
    }

    fn session_tool(
        kind: &str,
        side_effects: Option<&str>,
        payload_side: Option<&str>,
    ) -> EventValue {
        let mut event = SessionEvent::new(
            "evt-synthetic",
            None,
            0,
            "2024-02-29T00:00:00Z",
            "assistant",
            kind,
        );
        event.side_effects = side_effects.map(str::to_owned);
        if let Some(payload_side) = payload_side {
            event.payload = Payload::map(vec![(
                Payload::string("side_effects"),
                Payload::string(payload_side),
            )]);
        }
        event.content_hash = Some("abc".to_owned());
        EventValue::from_session(event)
    }

    fn sl203(evidence: PyValue) -> Finding {
        finding(
            "SL203",
            Severity::Error,
            Repairability::Deterministic,
            None,
            evidence,
        )
    }

    #[test]
    fn defaults_and_simple_predicates() {
        let ctx = context(&[], &[], "");
        assert_eq!(ctx.policy, "conservative");
        assert!(!ctx.acknowledge_side_effects);
        assert!(ctx.finding.is_none());
        assert!(no_sl203(&ctx));
        assert!(side_effects_known(&ctx));
        assert!(!repairability_is_safe_auto(&ctx));
        assert!(!repairability_is_salvage(&ctx));
        assert!(!source_hash_pinned(&ctx));
        assert!(!source_hash_pinned(&context(&[], &[], &"a".repeat(63))));
        assert!(source_hash_pinned(&context(&[], &[], &"g".repeat(64))));
        assert!(source_hash_pinned(&context(&[], &[], &"é".repeat(64))));
        assert!(!source_hash_pinned(&context(&[], &[], &"é".repeat(32))));

        let other = finding(
            "SL005",
            Severity::Warning,
            Repairability::Manual,
            None,
            PyValue::None,
        );
        let fatal = finding(
            "SL203",
            Severity::Fatal,
            Repairability::Deterministic,
            None,
            PyValue::None,
        );
        assert!(no_sl203(&context(std::slice::from_ref(&other), &[], "")));
        assert!(!no_sl203(&context(std::slice::from_ref(&fatal), &[], "")));

        let pinned = "a".repeat(64);
        let mut safe = context(&[], &[], &pinned);
        safe.finding = Some(&fatal);
        assert!(repairability_is_safe_auto(&safe));
        assert!(!repairability_is_salvage(&safe));
        safe.finding = Some(&other);
        assert!(!repairability_is_safe_auto(&safe));
        assert!(!repairability_is_salvage(&safe));
        let salvage = finding(
            "SL005",
            Severity::Warning,
            Repairability::LossyExplicit,
            None,
            PyValue::None,
        );
        safe.finding = Some(&salvage);
        assert!(repairability_is_salvage(&safe));
        assert!(!repairability_is_safe_auto(&safe));
    }

    #[test]
    fn side_effects_accept_only_the_string_none_on_tools() {
        let clean = [
            mapped(vec![("kind", EventField::Str("message".to_owned()))]),
            tool("tool_call", Some("none"), None),
            tool("tool_use", Some("none"), None),
            tool("tool_result", Some("none"), None),
            session_tool("tool_call", Some("none"), Some("possible")),
            session_tool("tool_result", None, Some("none")),
            mapped(vec![
                ("kind", EventField::Str("tool_call".to_owned())),
                (
                    "payload",
                    EventField::Mapping(EventMapping::new(vec![(
                        "side_effects".to_owned(),
                        EventField::Str("none".to_owned()),
                    )])),
                ),
            ]),
            mapped(vec![("kind", EventField::Int(1))]),
            EventValue::Other,
        ];
        assert!(side_effects_known(&context(&[], &clean, "")));

        let blocked = [
            tool("tool_call", Some("possible"), None),
            tool("tool_call", None, None),
            session_tool("tool_use", None, Some("possible")),
            session_tool("tool_call", None, None),
            session_tool("tool_call", Some("possible"), Some("none")),
            mapped(vec![
                ("kind", EventField::Str("tool_result".to_owned())),
                ("side_effects", EventField::Str("possible".to_owned())),
                (
                    "payload",
                    EventField::Mapping(EventMapping::new(vec![(
                        "side_effects".to_owned(),
                        EventField::Str("none".to_owned()),
                    )])),
                ),
            ]),
            mapped(vec![
                ("kind", EventField::Str("tool_call".to_owned())),
                ("side_effects", EventField::Int(0)),
            ]),
        ];
        for event in &blocked {
            assert!(!side_effects_known(&context(
                &[],
                std::slice::from_ref(event),
                ""
            )));
        }
    }

    #[test]
    fn cut_predicate_proves_false_before_the_abstain_seam() {
        let message = hashed("evt-a", "message", "abc");
        let events = [
            message.clone(),
            hashed("evt-b", "checkpoint", "abc"),
            hashed("evt-c", "message", "abc"),
        ];
        let warning = finding(
            "SL005",
            Severity::Warning,
            Repairability::Deterministic,
            None,
            ev_map(vec![("index", PyValue::int(1))]),
        );
        let mut ctx = context(std::slice::from_ref(&warning), &events, "hash");
        ctx.finding = Some(&warning);
        assert!(!no_prior_safe_tool_after_cut(&ctx).unwrap());

        let fatal = finding(
            "SL005",
            Severity::Fatal,
            Repairability::Deterministic,
            None,
            ev_map(vec![("first_unsafe_index", PyValue::int(0))]),
        );
        let later = sl203(ev_map(vec![("index", PyValue::int(1))]));
        let findings = [fatal.clone(), later];
        let mut ctx = context(&findings, &events, "hash");
        ctx.finding = Some(&fatal);
        assert!(!no_prior_safe_tool_after_cut(&ctx).unwrap());

        let zero = sl203(ev_map(vec![("entry_index", PyValue::int(0))]));
        let four = sl203(ev_map(vec![("index", PyValue::int(1))]));
        let findings = [zero, four];
        assert!(!no_prior_safe_tool_after_cut(&context(&findings, &events, "hash")).unwrap());

        let trigger = sl203(PyValue::None);
        let tool_event = tool("tool_call", Some("possible"), None);
        let dirty = [tool_event, message.clone()];
        let mut ctx = context(std::slice::from_ref(&trigger), &dirty, "hash");
        ctx.finding = Some(&trigger);
        assert!(!no_prior_safe_tool_after_cut(&ctx).unwrap());

        let cut = sl203(ev_map(vec![("at_index", PyValue::int(1))]));
        let mut ctx = context(std::slice::from_ref(&cut), &events, "hash");
        ctx.finding = Some(&cut);
        assert!(!no_prior_safe_tool_after_cut(&ctx).unwrap());
    }

    #[test]
    fn clean_cut_returns_must_abstain_unavailable() {
        let events = [
            hashed("evt-a", "message", "abc"),
            hashed("evt-b", "message", "abc"),
        ];
        let low = sl203(ev_map(vec![("index", PyValue::int(2))]));
        let high = sl203(ev_map(vec![("at_index", PyValue::int(1))]));
        let findings = [low, high];
        let error = no_prior_safe_tool_after_cut(&context(&findings, &events, "hash")).unwrap_err();
        assert_eq!(error.to_string(), MUST_ABSTAIN_UNAVAILABLE);
        assert_eq!(
            error.to_string(),
            "sesslint.policy.abstention.must_abstain is not available"
        );
        assert!(std::error::Error::source(&error).is_none());

        let kept_zero = sl203(ev_map(vec![
            ("first_unsafe_index", PyValue::None),
            ("at_index", PyValue::int(0)),
            ("index", PyValue::int(1)),
        ]));
        let mut ctx = context(std::slice::from_ref(&kept_zero), &events, "hash");
        ctx.finding = Some(&kept_zero);
        assert!(!no_prior_safe_tool_after_cut(&ctx).unwrap());

        let skipped_none = sl203(ev_map(vec![
            ("first_unsafe_index", PyValue::None),
            ("at_index", PyValue::int(1)),
        ]));
        let mut ctx = context(std::slice::from_ref(&skipped_none), &events, "hash");
        ctx.finding = Some(&skipped_none);
        assert_eq!(
            no_prior_safe_tool_after_cut(&ctx).unwrap_err(),
            PreconditionError::Unavailable(MUST_ABSTAIN_UNAVAILABLE)
        );
    }

    #[test]
    fn adjacent_duplicates_follow_record_indexes_then_the_index_then_the_scan() {
        let same = [
            hashed("evt-a", "message", "abc"),
            hashed("evt-a", "message", "abc"),
            hashed("evt-b", "message", "abd"),
        ];
        assert!(adjacent_identical_duplicate(&context(&[], &same, "")).unwrap());
        let different = [
            hashed("evt-a", "message", "abc"),
            hashed("evt-a", "message", "abd"),
        ];
        assert!(!adjacent_identical_duplicate(&context(&[], &different, "")).unwrap());
        let boundary = [
            hashed("evt-a", "checkpoint", "abc"),
            hashed("evt-a", "checkpoint", "abc"),
        ];
        assert!(!adjacent_identical_duplicate(&context(&[], &boundary, "")).unwrap());
        let compaction = [
            hashed("evt-a", "compaction_boundary", "abc"),
            hashed("evt-a", "compaction_boundary", "abc"),
        ];
        assert!(!adjacent_identical_duplicate(&context(&[], &compaction, "")).unwrap());

        let listed = sl203(ev_map(vec![
            ("record_indexes", ints(&[0, 1])),
            ("count", PyValue::int(2)),
        ]));
        let mut ctx = context(std::slice::from_ref(&listed), &same, "");
        ctx.finding = Some(&listed);
        assert!(adjacent_identical_duplicate(&ctx).unwrap());

        let different_ids = [
            hashed("evt-a", "message", "abc"),
            hashed("evt-b", "message", "abc"),
        ];
        let mut ctx = context(std::slice::from_ref(&listed), &different_ids, "");
        ctx.finding = Some(&listed);
        assert!(!adjacent_identical_duplicate(&ctx).unwrap());

        let gaps = [
            sl203(ev_map(vec![("record_indexes", ints(&[0, 2]))])),
            sl203(ev_map(vec![("record_indexes", ints(&[0, 1, 2]))])),
            sl203(ev_map(vec![
                ("record_indexes", ints(&[0, 1])),
                ("truncated", PyValue::bool_value(true)),
            ])),
            sl203(ev_map(vec![
                ("record_indexes", ints(&[0, 1])),
                ("count", PyValue::int(3)),
            ])),
            sl203(ev_map(vec![
                ("record_indexes", ints(&[0, 1])),
                ("count", PyValue::None),
            ])),
            sl203(ev_map(vec![(
                "record_indexes",
                PyValue::list(vec![PyValue::int(0), PyValue::bool_value(true)]),
            )])),
            sl203(ev_map(vec![("record_indexes", PyValue::string("01"))])),
            sl203(ev_map(vec![(
                "record_indexes",
                PyValue::tuple(vec![PyValue::int(-1), PyValue::int(0)]),
            )])),
        ];
        for finding in &gaps {
            let mut ctx = context(std::slice::from_ref(finding), &same, "");
            ctx.finding = Some(finding);
            assert!(!adjacent_identical_duplicate(&ctx).unwrap());
        }

        let tuple_pair = sl203(ev_map(vec![(
            "record_indexes",
            PyValue::tuple(vec![PyValue::int(0), PyValue::int(1)]),
        )]));
        let mut ctx = context(std::slice::from_ref(&tuple_pair), &different_ids, "");
        ctx.finding = Some(&tuple_pair);
        assert!(!adjacent_identical_duplicate(&ctx).unwrap());
        let mut ctx = context(std::slice::from_ref(&tuple_pair), &same, "");
        ctx.finding = Some(&tuple_pair);
        assert!(adjacent_identical_duplicate(&ctx).unwrap());
    }

    #[test]
    fn index_path_does_not_require_equal_ids_and_does_not_fall_through() {
        let events = [
            hashed("evt-a", "message", "abc"),
            hashed("evt-b", "message", "abc"),
            hashed("evt-c", "message", "zzz"),
        ];
        let at_zero = sl203(ev_map(vec![("at_index", PyValue::int(0))]));
        let mut ctx = context(std::slice::from_ref(&at_zero), &events, "");
        ctx.finding = Some(&at_zero);
        assert!(adjacent_identical_duplicate(&ctx).unwrap());

        let out = sl203(ev_map(vec![("at_index", PyValue::int(9))]));
        let mut ctx = context(std::slice::from_ref(&out), &events, "");
        ctx.finding = Some(&out);
        assert!(!adjacent_identical_duplicate(&ctx).unwrap());

        let bool_then_index = sl203(ev_map(vec![
            ("at_index", PyValue::bool_value(true)),
            ("index", PyValue::int(0)),
        ]));
        let mut ctx = context(std::slice::from_ref(&bool_then_index), &events, "");
        ctx.finding = Some(&bool_then_index);
        assert!(adjacent_identical_duplicate(&ctx).unwrap());

        let last = sl203(ev_map(vec![("first_index", PyValue::int(1))]));
        let mut ctx = context(std::slice::from_ref(&last), &events, "");
        ctx.finding = Some(&last);
        assert!(adjacent_identical_duplicate(&ctx).unwrap());
    }

    #[test]
    fn duplicate_scan_propagates_fingerprint_seams_and_stops_on_a_match() {
        let missing = [
            hashed("evt-a", "message", "abc"),
            mapped(vec![
                ("id", EventField::Str("evt-a".to_owned())),
                ("kind", EventField::Str("message".to_owned())),
            ]),
        ];
        let error = adjacent_identical_duplicate(&context(&[], &missing, "")).unwrap_err();
        assert_eq!(
            error.to_string(),
            "sesslint.determinism.canonical_json_bytes is not available"
        );
        assert!(std::error::Error::source(&error).is_some());

        let session = session_tool("message", Some("none"), None);
        let mut bare = SessionEvent::new(
            "evt-synthetic",
            None,
            0,
            "2024-02-29T00:00:00Z",
            "assistant",
            "message",
        );
        bare.content_hash = Some(String::new());
        let events = [session, EventValue::from_session(bare)];
        let error = adjacent_identical_duplicate(&context(&[], &events, "")).unwrap_err();
        assert_eq!(
            error.to_string(),
            "sesslint._canonical_codec.payload_content_hash is not available"
        );

        let float_kind = mapped(vec![("kind", EventField::Float(1.0))]);
        let events = [hashed("evt-a", "message", "abc"), float_kind];
        let error = adjacent_identical_duplicate(&context(&[], &events, "")).unwrap_err();
        assert_eq!(error.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        assert_eq!(error, PreconditionError::Event(EventError::PythonFloatStr));
    }

    #[test]
    fn unique_parent_stops_at_the_graph_seam_after_pure_resolution() {
        assert!(!unique_parent_candidate(&context(&[], &[], "")).unwrap());
        let orphan = hashed("evt-a", "message", "abc");
        let child = sl203(ev_map(vec![("index", PyValue::int(0))]));
        let mut ctx = context(
            std::slice::from_ref(&child),
            std::slice::from_ref(&orphan),
            "",
        );
        ctx.finding = Some(&child);
        assert!(!unique_parent_candidate(&ctx).unwrap());

        let with_parent = mapped(vec![
            ("id", EventField::Str("evt-a".to_owned())),
            ("kind", EventField::Str("message".to_owned())),
            ("parent_id", EventField::Str("parent-synthetic".to_owned())),
            ("content_hash", EventField::Str("abc".to_owned())),
        ]);
        let mut ctx = context(
            std::slice::from_ref(&child),
            std::slice::from_ref(&with_parent),
            "",
        );
        ctx.finding = Some(&child);
        let error = unique_parent_candidate(&ctx).unwrap_err();
        assert_eq!(
            error.to_string(),
            FIND_QUALIFYING_PARENT_CANDIDATES_UNAVAILABLE
        );
        assert_eq!(
            error.to_string(),
            "sesslint.checks.graph.find_qualifying_parent_candidates is not available"
        );

        let evidence_parent = sl203(ev_map(vec![
            ("index", PyValue::int(0)),
            ("parent_id", PyValue::string("parent-synthetic")),
        ]));
        let float_parent = mapped(vec![
            ("id", EventField::Str("evt-a".to_owned())),
            ("kind", EventField::Str("message".to_owned())),
            ("parent_id", EventField::Float(1.0)),
        ]);
        let mut ctx = context(
            std::slice::from_ref(&evidence_parent),
            std::slice::from_ref(&float_parent),
            "",
        );
        ctx.finding = Some(&evidence_parent);
        assert_eq!(
            unique_parent_candidate(&ctx).unwrap_err().to_string(),
            FIND_QUALIFYING_PARENT_CANDIDATES_UNAVAILABLE
        );

        let by_record = finding(
            "SL203",
            Severity::Error,
            Repairability::Deterministic,
            Some("evt-b"),
            ev_map(vec![("index", PyValue::int(9))]),
        );
        let events = [
            hashed("evt-a", "message", "abc"),
            mapped(vec![
                ("id", EventField::Str("evt-b".to_owned())),
                ("kind", EventField::Str("message".to_owned())),
                (
                    "parent_fingerprint_prefix",
                    EventField::Str("parent-synthetic".to_owned()),
                ),
            ]),
        ];
        let mut ctx = context(std::slice::from_ref(&by_record), &events, "");
        ctx.finding = Some(&by_record);
        assert!(!unique_parent_candidate(&ctx).unwrap());

        let prefix = sl203(ev_map(vec![
            ("index", PyValue::int(1)),
            (
                "parent_fingerprint_prefix",
                PyValue::string("parent-synthetic"),
            ),
        ]));
        let mut ctx = context(std::slice::from_ref(&prefix), &events, "");
        ctx.finding = Some(&prefix);
        assert_eq!(
            unique_parent_candidate(&ctx).unwrap_err().to_string(),
            FIND_QUALIFYING_PARENT_CANDIDATES_UNAVAILABLE
        );
    }

    #[test]
    fn in_range_index_beats_record_id_and_duplicate_keys_use_the_last() {
        let events = [
            mapped(vec![
                ("id", EventField::Str("evt-a".to_owned())),
                ("kind", EventField::Str("message".to_owned())),
                ("parent_id", EventField::Str("parent-synthetic".to_owned())),
            ]),
            hashed("evt-b", "message", "abc"),
        ];
        let finding = finding(
            "SL203",
            Severity::Error,
            Repairability::Deterministic,
            Some("evt-a"),
            ev_map(vec![("index", PyValue::int(1))]),
        );
        let mut ctx = context(std::slice::from_ref(&finding), &events, "");
        ctx.finding = Some(&finding);
        assert!(!unique_parent_candidate(&ctx).unwrap());

        let duplicated = sl203(ev_map(vec![
            ("index", PyValue::int(9)),
            ("index", PyValue::int(0)),
        ]));
        let mut ctx = context(std::slice::from_ref(&duplicated), &events, "");
        ctx.finding = Some(&duplicated);
        assert_eq!(
            unique_parent_candidate(&ctx).unwrap_err().to_string(),
            FIND_QUALIFYING_PARENT_CANDIDATES_UNAVAILABLE
        );

        let missing_id = sl203(PyValue::None);
        let nameless = [mapped(vec![(
            "kind",
            EventField::Str("message".to_owned()),
        )])];
        let mut ctx = context(std::slice::from_ref(&missing_id), &nameless, "");
        ctx.finding = Some(&missing_id);
        assert!(!unique_parent_candidate(&ctx).unwrap());
    }

    #[test]
    fn single_boundary_counts_one_boundary_strictly_between_the_pair() {
        assert!(!single_boundary_split(&context(&[], &[], "")).unwrap());
        let events = [
            tool("tool_call", Some("none"), Some("corr-synthetic")),
            hashed("evt-b", "compaction_boundary", "abc"),
            tool("tool_result", Some("none"), Some("corr-synthetic")),
        ];
        let finding = sl203(ev_map(vec![(
            "correlation_id",
            PyValue::string("corr-synthetic"),
        )]));
        let mut ctx = context(std::slice::from_ref(&finding), &events, "");
        ctx.finding = Some(&finding);
        assert!(single_boundary_split(&ctx).unwrap());

        let adjacent = [
            tool("tool_use", Some("none"), Some("corr-synthetic")),
            tool("tool_result", Some("none"), Some("corr-synthetic")),
        ];
        let mut ctx = context(std::slice::from_ref(&finding), &adjacent, "");
        ctx.finding = Some(&finding);
        assert!(!single_boundary_split(&ctx).unwrap());

        let two = [
            tool("tool_call", Some("none"), Some("corr-synthetic")),
            hashed("evt-b", "compaction_boundary", "abc"),
            hashed("evt-c", "compaction_boundary", "abc"),
            tool("tool_result", Some("none"), Some("corr-synthetic")),
        ];
        let mut ctx = context(std::slice::from_ref(&finding), &two, "");
        ctx.finding = Some(&finding);
        assert!(!single_boundary_split(&ctx).unwrap());

        let reversed = [
            tool("tool_result", Some("none"), Some("corr-synthetic")),
            hashed("evt-b", "compaction_boundary", "abc"),
            tool("tool_call", Some("none"), Some("corr-synthetic")),
        ];
        let mut ctx = context(std::slice::from_ref(&finding), &reversed, "");
        ctx.finding = Some(&finding);
        assert!(single_boundary_split(&ctx).unwrap());

        let empty = sl203(ev_map(vec![("correlation_id", PyValue::string(""))]));
        let mut ctx = context(std::slice::from_ref(&empty), &events, "");
        ctx.finding = Some(&empty);
        assert!(!single_boundary_split(&ctx).unwrap());

        let calls = [
            tool("tool_call", Some("none"), Some("corr-synthetic")),
            tool("tool_call", Some("none"), Some("corr-synthetic")),
            hashed("evt-b", "compaction_boundary", "abc"),
            tool("tool_result", Some("none"), Some("corr-synthetic")),
        ];
        let mut ctx = context(std::slice::from_ref(&finding), &calls, "");
        ctx.finding = Some(&finding);
        assert!(!single_boundary_split(&ctx).unwrap());
    }

    #[test]
    fn duplicate_projection_uses_truthy_or_and_short_circuits_fingerprints() {
        assert!(!duplicate_projection_identical(&context(&[], &[], "")).unwrap());
        let events = [
            tool("tool_result", Some("none"), Some("corr-a")),
            tool("tool_result", Some("none"), Some("corr-b")),
            tool("tool_result", Some("none"), Some("corr-b")),
        ];
        let zero = sl203(ev_map(vec![
            ("at_index", PyValue::int(0)),
            ("index", PyValue::int(1)),
        ]));
        let mut ctx = context(std::slice::from_ref(&zero), &events, "");
        ctx.finding = Some(&zero);
        assert!(duplicate_projection_identical(&ctx).unwrap());

        let direct = sl203(ev_map(vec![("correlation_id", PyValue::string("corr-a"))]));
        let mut ctx = context(std::slice::from_ref(&direct), &events, "");
        ctx.finding = Some(&direct);
        assert!(!duplicate_projection_identical(&ctx).unwrap());

        let bool_index = sl203(ev_map(vec![
            ("at_index", PyValue::bool_value(true)),
            ("index", PyValue::int(1)),
        ]));
        let mut ctx = context(std::slice::from_ref(&bool_index), &events, "");
        ctx.finding = Some(&bool_index);
        assert!(!duplicate_projection_identical(&ctx).unwrap());

        let mismatched = [
            tool("tool_result", Some("none"), Some("corr-b")),
            mapped(vec![
                ("kind", EventField::Str("tool_result".to_owned())),
                ("correlation_id", EventField::Str("corr-b".to_owned())),
                ("content_hash", EventField::Str("abd".to_owned())),
            ]),
        ];
        let by_corr = sl203(ev_map(vec![("correlation_id", PyValue::string("corr-b"))]));
        let mut ctx = context(std::slice::from_ref(&by_corr), &mismatched, "");
        ctx.finding = Some(&by_corr);
        assert!(!duplicate_projection_identical(&ctx).unwrap());

        let early_match = [
            tool("tool_result", Some("none"), Some("corr-b")),
            tool("tool_result", Some("none"), Some("corr-b")),
            mapped(vec![
                ("kind", EventField::Str("tool_result".to_owned())),
                ("correlation_id", EventField::Str("corr-b".to_owned())),
                ("content_hash", EventField::Float(1.0)),
            ]),
        ];
        let mut ctx = context(std::slice::from_ref(&by_corr), &early_match, "");
        ctx.finding = Some(&by_corr);
        assert!(duplicate_projection_identical(&ctx).unwrap());

        let late_error = [
            tool("tool_result", Some("none"), Some("corr-b")),
            mapped(vec![
                ("kind", EventField::Str("tool_result".to_owned())),
                ("correlation_id", EventField::Str("corr-b".to_owned())),
                ("content_hash", EventField::Str("abd".to_owned())),
            ]),
            mapped(vec![
                ("kind", EventField::Str("tool_result".to_owned())),
                ("correlation_id", EventField::Str("corr-b".to_owned())),
                ("content_hash", EventField::Float(1.0)),
            ]),
        ];
        let mut ctx = context(std::slice::from_ref(&by_corr), &late_error, "");
        ctx.finding = Some(&by_corr);
        assert_eq!(
            duplicate_projection_identical(&ctx)
                .unwrap_err()
                .to_string(),
            "sesslint.determinism.canonical_json_bytes is not available"
        );
    }

    fn coded(code: &str, record_id: Option<&str>, evidence: PyValue) -> Finding {
        finding(
            code,
            Severity::Error,
            Repairability::Deterministic,
            record_id,
            evidence,
        )
    }

    fn node(id: &str, parent: Option<&str>, kind: &str) -> EventValue {
        let mut entries = vec![
            ("id", EventField::Str(id.to_owned())),
            ("kind", EventField::Str(kind.to_owned())),
        ];
        if let Some(parent) = parent {
            entries.push(("parent_id", EventField::Str(parent.to_owned())));
        }
        mapped(entries)
    }

    fn indexes_of(values: &[i64]) -> PyValue {
        ints(values)
    }

    #[test]
    fn sl003_rejects_a_list_that_would_leave_copies_behind() {
        let events = [
            hashed("evt-a", "message", "abc"),
            hashed("evt-b", "message", "abd"),
            hashed("evt-c", "message", "abc"),
        ];
        assert!(!sl003_identical_duplicate(&context(&[], &events, "")));
        let absent = coded("SL003", None, PyValue::None);
        let mut ctx = context(std::slice::from_ref(&absent), &events, "");
        ctx.finding = Some(&absent);
        assert!(!sl003_identical_duplicate(&ctx));

        let rejected = [
            ev_map(vec![("variant", PyValue::string("conflicting-duplicate"))]),
            ev_map(vec![
                ("variant", PyValue::string("identical-duplicate")),
                ("truncated", PyValue::bool_value(true)),
                ("record_indexes", indexes_of(&[0, 2])),
            ]),
            ev_map(vec![
                ("variant", PyValue::string("identical-duplicate")),
                ("truncated", PyValue::string("x")),
                ("record_indexes", indexes_of(&[0, 2])),
            ]),
            ev_map(vec![
                ("variant", PyValue::string("identical-duplicate")),
                ("record_indexes", PyValue::string("01")),
            ]),
            ev_map(vec![
                ("variant", PyValue::string("identical-duplicate")),
                ("record_indexes", PyValue::bytes(b"01")),
            ]),
            ev_map(vec![
                ("variant", PyValue::string("identical-duplicate")),
                (
                    "record_indexes",
                    PyValue::set(vec![PyValue::int(0), PyValue::int(2)]),
                ),
            ]),
            ev_map(vec![
                ("variant", PyValue::string("identical-duplicate")),
                ("record_indexes", indexes_of(&[0])),
            ]),
            ev_map(vec![
                ("variant", PyValue::string("identical-duplicate")),
                (
                    "record_indexes",
                    PyValue::list(vec![PyValue::int(0), PyValue::bool_value(true)]),
                ),
            ]),
            ev_map(vec![
                ("variant", PyValue::string("identical-duplicate")),
                ("record_indexes", indexes_of(&[0, 2])),
                ("count", PyValue::int(3)),
            ]),
            ev_map(vec![
                ("variant", PyValue::string("identical-duplicate")),
                ("record_indexes", indexes_of(&[0, 2])),
                ("count", PyValue::None),
            ]),
            ev_map(vec![
                ("variant", PyValue::string("identical-duplicate")),
                ("record_indexes", indexes_of(&[0, 2])),
                ("count", PyValue::bool_value(true)),
            ]),
            ev_map(vec![
                ("variant", PyValue::string("identical-duplicate")),
                ("record_indexes", indexes_of(&[0, 3])),
            ]),
            ev_map(vec![
                ("variant", PyValue::string("identical-duplicate")),
                ("record_indexes", indexes_of(&[-1, 0])),
            ]),
        ];
        for evidence in &rejected {
            let finding = coded("SL003", None, evidence.clone());
            let mut ctx = context(std::slice::from_ref(&finding), &events, "");
            ctx.finding = Some(&finding);
            assert!(!sl003_identical_duplicate(&ctx));
        }
    }

    #[test]
    fn sl003_accepts_in_range_indexes_without_comparing_events() {
        let events = [
            hashed("evt-a", "message", "abc"),
            hashed("evt-b", "message", "abd"),
            hashed("evt-c", "checkpoint", "abe"),
        ];
        let listed = coded(
            "SL003",
            None,
            ev_map(vec![
                ("variant", PyValue::string("other")),
                ("variant", PyValue::string("identical-duplicate")),
                ("truncated", PyValue::bool_value(false)),
                ("truncated", PyValue::list(Vec::new())),
                ("record_indexes", indexes_of(&[0, 0])),
            ]),
        );
        let mut ctx = context(std::slice::from_ref(&listed), &events, "");
        ctx.finding = Some(&listed);
        assert!(sl003_identical_duplicate(&ctx));

        let tuple = coded(
            "SL003",
            None,
            ev_map(vec![
                ("variant", PyValue::string("identical-duplicate")),
                ("truncated", PyValue::int(0)),
                ("truncated", PyValue::string("")),
                (
                    "record_indexes",
                    PyValue::tuple(vec![PyValue::int(0), PyValue::int(2)]),
                ),
            ]),
        );
        let mut ctx = context(std::slice::from_ref(&tuple), &events, "");
        ctx.finding = Some(&tuple);
        assert!(sl003_identical_duplicate(&ctx));

        let counted = coded(
            "SL003",
            None,
            ev_map(vec![
                ("variant", PyValue::string("identical-duplicate")),
                ("record_indexes", indexes_of(&[0, 2])),
                ("count", PyValue::int(2)),
            ]),
        );
        let mut ctx = context(std::slice::from_ref(&counted), &[], "");
        ctx.finding = Some(&counted);
        assert!(!sl003_identical_duplicate(&ctx));
    }

    #[test]
    fn salvage_and_acknowledge_match_the_operator_flags() {
        let mut ctx = context(&[], &[], "");
        assert!(!salvage_policy(&ctx));
        assert!(!acknowledge_side_effects(&ctx));
        ctx.policy = "Salvage";
        assert!(!salvage_policy(&ctx));
        ctx.policy = "salvage";
        assert!(salvage_policy(&ctx));
        ctx.acknowledge_side_effects = true;
        assert!(acknowledge_side_effects(&ctx));
    }

    #[test]
    fn component_order_is_breadth_first_and_last_id_wins() {
        let events = [
            node("evt-a", None, "message"),
            node("evt-b", Some("evt-a"), "message"),
            node("evt-c", Some("evt-b"), "message"),
        ];
        assert_eq!(_find_component_indices(&events, 2).unwrap(), vec![2, 1, 0]);
        assert_eq!(_find_component_indices(&events, 0).unwrap(), vec![0, 1, 2]);

        let duplicated = [
            node("evt-a", None, "message"),
            node("evt-b", Some("evt-a"), "message"),
            node("evt-a", None, "message"),
        ];
        assert_eq!(_find_component_indices(&duplicated, 1).unwrap(), vec![1, 2]);
        assert_eq!(_find_component_indices(&duplicated, 0).unwrap(), vec![0]);

        let numeric = [
            mapped(vec![
                ("id", EventField::Int(7)),
                ("kind", EventField::Str("message".to_owned())),
            ]),
            node("evt-b", Some("7"), "message"),
        ];
        assert_eq!(_find_component_indices(&numeric, 1).unwrap(), vec![1, 0]);
        let unmatched = [node("evt-b", Some("07"), "message")];
        assert_eq!(_find_component_indices(&unmatched, 0).unwrap(), vec![0]);

        let cycle = [
            node("evt-a", Some("evt-b"), "message"),
            node("evt-b", Some("evt-a"), "checkpoint"),
        ];
        assert_eq!(_find_component_indices(&cycle, 0).unwrap(), vec![0, 1]);
        assert_eq!(_find_component_indices(&[], 5).unwrap(), vec![5]);
        assert_eq!(_find_component_indices(&events, -1).unwrap(), vec![-1]);
    }

    #[test]
    fn component_reads_every_id_before_an_out_of_range_seed_returns() {
        let broken = [mapped(vec![(
            "id",
            EventField::List(vec![EventField::Str("evt-a".to_owned())]),
        )])];
        let error = _find_component_indices(&broken, 5).unwrap_err();
        assert_eq!(error.to_string(), PYTHON_STR_UNREPRESENTABLE);
        assert!(std::error::Error::source(&error).is_some());

        let parent_float = [mapped(vec![
            ("id", EventField::Str("evt-a".to_owned())),
            ("parent_id", EventField::Float(1.0)),
        ])];
        assert_eq!(
            _find_component_indices(&parent_float, 0)
                .unwrap_err()
                .to_string(),
            PYTHON_FLOAT_STR_UNREPRESENTABLE
        );
    }

    #[test]
    fn branch_seed_prefers_an_in_range_index_over_record_id() {
        let events = [
            node("evt-a", None, "message"),
            node("evt-b", None, "checkpoint"),
        ];
        let at_zero = coded(
            "SL005",
            Some("evt-b"),
            ev_map(vec![
                ("at_index", PyValue::bool_value(true)),
                ("at_index", PyValue::int(0)),
                ("entry_index", PyValue::int(1)),
            ]),
        );
        let mut ctx = context(std::slice::from_ref(&at_zero), &events, "");
        ctx.finding = Some(&at_zero);
        assert!(branch_has_no_checkpoint(&ctx).unwrap());

        let by_record = coded("SL005", Some("evt-b"), PyValue::None);
        let mut ctx = context(std::slice::from_ref(&by_record), &events, "");
        ctx.finding = Some(&by_record);
        assert!(!branch_has_no_checkpoint(&ctx).unwrap());

        let from_list = coded(
            "SL005",
            Some("evt-a"),
            ev_map(vec![(
                "record_indexes",
                PyValue::list(vec![
                    PyValue::int(9),
                    PyValue::bool_value(true),
                    PyValue::int(1),
                ]),
            )]),
        );
        let mut ctx = context(std::slice::from_ref(&from_list), &events, "");
        ctx.finding = Some(&from_list);
        assert!(!branch_has_no_checkpoint(&ctx).unwrap());

        assert!(branch_has_no_checkpoint(&context(&[], &[], "")).unwrap());
        assert!(!branch_has_no_checkpoint(&context(&[], &events, "")).unwrap());
        let child = [
            node("evt-a", None, "checkpoint"),
            node("evt-b", Some("evt-a"), "message"),
        ];
        let seed = coded("SL005", None, ev_map(vec![("index", PyValue::int(1))]));
        let mut ctx = context(std::slice::from_ref(&seed), &child, "");
        ctx.finding = Some(&seed);
        assert!(!branch_has_no_checkpoint(&ctx).unwrap());
        let isolated = coded(
            "SL005",
            None,
            ev_map(vec![("first_index", PyValue::int(1))]),
        );
        let apart = [
            node("evt-a", None, "checkpoint"),
            node("evt-b", None, "message"),
        ];
        let mut ctx = context(std::slice::from_ref(&isolated), &apart, "");
        ctx.finding = Some(&isolated);
        assert!(branch_has_no_checkpoint(&ctx).unwrap());
    }

    #[test]
    fn branch_short_circuits_in_visit_order_and_propagates_field_errors() {
        let checkpoint_first = [
            node("evt-a", None, "checkpoint"),
            mapped(vec![("kind", EventField::Float(1.0))]),
        ];
        assert!(!branch_has_no_checkpoint(&context(&[], &checkpoint_first, "")).unwrap());

        let float_first = [
            mapped(vec![("kind", EventField::Float(1.0))]),
            node("evt-b", None, "checkpoint"),
        ];
        assert_eq!(
            branch_has_no_checkpoint(&context(&[], &float_first, ""))
                .unwrap_err()
                .to_string(),
            PYTHON_FLOAT_STR_UNREPRESENTABLE
        );

        let events = [
            node("evt-a", None, "checkpoint"),
            node("evt-b", Some("evt-a"), "message"),
            mapped(vec![
                ("id", EventField::Str("evt-c".to_owned())),
                ("kind", EventField::Float(1.0)),
                ("parent_id", EventField::Str("evt-b".to_owned())),
            ]),
        ];
        let seed = coded("SL005", None, ev_map(vec![("at_index", PyValue::int(1))]));
        let mut ctx = context(std::slice::from_ref(&seed), &events, "");
        ctx.finding = Some(&seed);
        assert!(!branch_has_no_checkpoint(&ctx).unwrap());

        let error_first = [
            node("evt-a", None, "checkpoint"),
            node("evt-b", Some("evt-a"), "message"),
            mapped(vec![
                ("id", EventField::Str("evt-c".to_owned())),
                ("kind", EventField::Float(1.0)),
                ("parent_id", EventField::Str("evt-b".to_owned())),
            ]),
        ];
        let seed = coded("SL005", None, ev_map(vec![("at_index", PyValue::int(2))]));
        let mut ctx = context(std::slice::from_ref(&seed), &error_first, "");
        ctx.finding = Some(&seed);
        assert_eq!(
            branch_has_no_checkpoint(&ctx).unwrap_err().to_string(),
            PYTHON_FLOAT_STR_UNREPRESENTABLE
        );

        let early_bad_id = [
            mapped(vec![("id", EventField::Float(1.0))]),
            node("evt-b", None, "checkpoint"),
        ];
        let by_record = coded("SL005", Some("evt-b"), PyValue::None);
        let mut ctx = context(std::slice::from_ref(&by_record), &early_bad_id, "");
        ctx.finding = Some(&by_record);
        assert_eq!(
            branch_has_no_checkpoint(&ctx).unwrap_err().to_string(),
            PYTHON_FLOAT_STR_UNREPRESENTABLE
        );

        let bad_id = [mapped(vec![(
            "id",
            EventField::List(vec![EventField::Str("evt-a".to_owned())]),
        )])];
        let seed = coded("SL005", None, ev_map(vec![("index", PyValue::int(0))]));
        let mut ctx = context(std::slice::from_ref(&seed), &bad_id, "");
        ctx.finding = Some(&seed);
        assert_eq!(
            branch_has_no_checkpoint(&ctx).unwrap_err().to_string(),
            PYTHON_STR_UNREPRESENTABLE
        );
    }

    fn expect_dropped(events: &[EventValue], boundary: i64, indexes: &[usize]) {
        assert_eq!(
            _find_torn_compaction_dropped_indices(events, boundary).unwrap(),
            indexes.iter().copied().collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn torn_projection_keeps_the_smaller_side_and_breaks_ties_toward_the_suffix() {
        let split = [
            tool("tool_call", Some("none"), Some("corr-synthetic")),
            hashed("evt-b", "compaction_boundary", "abc"),
            tool("tool_result", Some("none"), Some("corr-synthetic")),
        ];
        expect_dropped(&split, 1, &[1, 2]);

        let minority_calls = [
            tool("tool_call", Some("none"), Some("corr-synthetic")),
            hashed("evt-b", "compaction_boundary", "abc"),
            tool("tool_result", Some("none"), Some("corr-synthetic")),
            tool("tool_result", Some("none"), Some("corr-synthetic")),
        ];
        expect_dropped(&minority_calls, 1, &[1, 0]);

        let minority_results = [
            tool("tool_call", Some("none"), Some("corr-synthetic")),
            tool("tool_use", Some("none"), Some("corr-synthetic")),
            hashed("evt-b", "compaction_boundary", "abc"),
            tool("tool_result", Some("none"), Some("corr-synthetic")),
        ];
        expect_dropped(&minority_results, 2, &[2, 3]);

        let reversed = [
            tool("tool_result", Some("none"), Some("corr-synthetic")),
            hashed("evt-b", "compaction_boundary", "abc"),
            tool("tool_use", Some("none"), Some("corr-synthetic")),
        ];
        expect_dropped(&reversed, 1, &[1, 2]);

        let only_call = [
            tool("tool_call", Some("none"), Some("corr-synthetic")),
            hashed("evt-b", "compaction_boundary", "abc"),
            hashed("evt-c", "message", "abc"),
        ];
        expect_dropped(&only_call, 1, &[1]);
        let only_result = [
            hashed("evt-b", "compaction_boundary", "abc"),
            tool("tool_result", Some("none"), Some("corr-synthetic")),
        ];
        expect_dropped(&only_result, 0, &[0]);

        let complete_before = [
            tool("tool_call", Some("none"), Some("corr-synthetic")),
            tool("tool_result", Some("none"), Some("corr-synthetic")),
            hashed("evt-b", "compaction_boundary", "abc"),
        ];
        let error = _find_torn_compaction_dropped_indices(&complete_before, 2).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Compaction boundary at index 2 has no split pairs or orphaned halves"
        );
        assert!(std::error::Error::source(&error).is_none());

        let both_sides = [
            tool("tool_call", Some("none"), Some("corr-a")),
            tool("tool_result", Some("none"), Some("corr-a")),
            hashed("evt-b", "compaction_boundary", "abc"),
            tool("tool_call", Some("none"), Some("corr-a")),
            tool("tool_result", Some("none"), Some("corr-a")),
        ];
        expect_dropped(&both_sides, 2, &[2, 4]);
    }

    #[test]
    fn torn_projection_errors_follow_the_pin_order() {
        let error = _find_torn_compaction_dropped_indices(&[], 0).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Cannot project across compaction in empty session"
        );
        assert_eq!(error, PreconditionError::Value(error.to_string()));

        let events = [hashed("evt-a", "message", "abc")];
        assert_eq!(
            _find_torn_compaction_dropped_indices(&events, -1)
                .unwrap_err()
                .to_string(),
            "Invalid compaction boundary index -1"
        );
        assert_eq!(
            _find_torn_compaction_dropped_indices(&events, 1)
                .unwrap_err()
                .to_string(),
            "Invalid compaction boundary index 1"
        );
        assert_eq!(
            _find_torn_compaction_dropped_indices(&events, 0)
                .unwrap_err()
                .to_string(),
            "Event at index 0 is not a compaction_boundary"
        );

        let float_kind = [mapped(vec![("kind", EventField::Float(1.0))])];
        assert_eq!(
            _find_torn_compaction_dropped_indices(&float_kind, 0)
                .unwrap_err()
                .to_string(),
            PYTHON_FLOAT_STR_UNREPRESENTABLE
        );

        let kind_before_corr = [
            mapped(vec![
                (
                    "kind",
                    EventField::List(vec![EventField::Str("message".to_owned())]),
                ),
                ("correlation_id", EventField::Float(1.0)),
            ]),
            hashed("evt-b", "compaction_boundary", "abc"),
        ];
        assert_eq!(
            _find_torn_compaction_dropped_indices(&kind_before_corr, 1)
                .unwrap_err()
                .to_string(),
            PYTHON_STR_UNREPRESENTABLE
        );

        let corr_on_message = [
            hashed("evt-b", "compaction_boundary", "abc"),
            mapped(vec![
                ("kind", EventField::Str("message".to_owned())),
                ("correlation_id", EventField::Float(1.0)),
            ]),
        ];
        assert_eq!(
            _find_torn_compaction_dropped_indices(&corr_on_message, 0)
                .unwrap_err()
                .to_string(),
            PYTHON_FLOAT_STR_UNREPRESENTABLE
        );

        let empty_corr = [
            tool("tool_call", Some("none"), Some("")),
            hashed("evt-b", "compaction_boundary", "abc"),
            tool("tool_result", Some("none"), Some("")),
        ];
        assert_eq!(
            _find_torn_compaction_dropped_indices(&empty_corr, 1)
                .unwrap_err()
                .to_string(),
            "Compaction boundary at index 1 has no split pairs or orphaned halves"
        );
    }

    #[test]
    fn sl108_scans_only_after_the_code_and_skips_value_errors() {
        let split = [
            hashed("evt-a", "compaction_boundary", "abc"),
            tool("tool_call", Some("none"), Some("corr-synthetic")),
            hashed("evt-b", "compaction_boundary", "abc"),
            tool("tool_result", Some("none"), Some("corr-synthetic")),
        ];
        assert!(!sl108_present(&context(&[], &split, "")).unwrap());
        let float_kind = [mapped(vec![("kind", EventField::Float(1.0))])];
        assert!(!sl108_present(&context(&[], &float_kind, "")).unwrap());

        let sl108 = coded("SL108", None, PyValue::None);
        assert!(!sl108_present(&context(std::slice::from_ref(&sl108), &[], "")).unwrap());
        let message = [hashed("evt-a", "message", "abc")];
        assert!(!sl108_present(&context(std::slice::from_ref(&sl108), &message, "")).unwrap());
        assert!(sl108_present(&context(std::slice::from_ref(&sl108), &split, "")).unwrap());

        let bare = [hashed("evt-a", "compaction_boundary", "abc")];
        assert!(!sl108_present(&context(std::slice::from_ref(&sl108), &bare, "")).unwrap());

        let float_after_code = [mapped(vec![("kind", EventField::Float(1.0))])];
        assert_eq!(
            sl108_present(&context(
                std::slice::from_ref(&sl108),
                &float_after_code,
                ""
            ))
            .unwrap_err()
            .to_string(),
            PYTHON_FLOAT_STR_UNREPRESENTABLE
        );

        let corr_error = [
            hashed("evt-a", "compaction_boundary", "abc"),
            mapped(vec![
                ("kind", EventField::Str("message".to_owned())),
                ("correlation_id", EventField::Float(1.0)),
            ]),
            hashed("evt-b", "compaction_boundary", "abc"),
            tool("tool_call", Some("none"), Some("corr-synthetic")),
            tool("tool_result", Some("none"), Some("corr-synthetic")),
        ];
        assert_eq!(
            sl108_present(&context(std::slice::from_ref(&sl108), &corr_error, ""))
                .unwrap_err()
                .to_string(),
            PYTHON_FLOAT_STR_UNREPRESENTABLE
        );
    }

    #[test]
    fn torn_terminal_record_requires_boolean_true_on_sl002() {
        let matched = coded(
            "SL002",
            None,
            ev_map(vec![("unterminated", PyValue::bool_value(true))]),
        );
        assert!(_is_unterminated_torn_append(&matched));
        assert!(torn_terminal_record(&context(
            std::slice::from_ref(&matched),
            &[],
            ""
        )));

        let rejected = [
            coded(
                "SL002",
                None,
                ev_map(vec![("unterminated", PyValue::bool_value(false))]),
            ),
            coded(
                "SL002",
                None,
                ev_map(vec![("unterminated", PyValue::int(1))]),
            ),
            coded("SL002", None, ev_map(vec![("count", PyValue::int(1))])),
            coded(
                "SL003",
                None,
                ev_map(vec![("unterminated", PyValue::bool_value(true))]),
            ),
            coded("SL002", None, PyValue::None),
        ];
        for finding in &rejected {
            assert!(!_is_unterminated_torn_append(finding));
            let mut ctx = context(std::slice::from_ref(&matched), &[], "");
            ctx.finding = Some(finding);
            assert!(!torn_terminal_record(&ctx));
        }
        assert!(!torn_terminal_record(&context(&[], &[], "")));
        let mut ctx = context(std::slice::from_ref(&matched), &[], "");
        ctx.finding = Some(&matched);
        assert!(torn_terminal_record(&ctx));
    }

    fn profile_is_strict(ctx: &PreconditionContext<'_>) -> bool {
        ctx.profile == "strict"
    }

    fn always_true(_ctx: &PreconditionContext<'_>) -> bool {
        true
    }

    fn always_false(_ctx: &PreconditionContext<'_>) -> bool {
        false
    }

    #[test]
    fn registry_keeps_dict_order_and_stops_on_the_first_false_name() {
        let fresh: Vec<_> = super::builtin_predicates()
            .into_iter()
            .map(|slot| slot.name)
            .collect();
        assert_eq!(
            fresh.iter().map(String::as_str).collect::<Vec<_>>(),
            super::BUILTIN_PRECONDITION_NAMES
        );
        let names = precondition_func_names();
        assert!(names.len() >= super::BUILTIN_PRECONDITION_NAMES.len());
        assert_eq!(
            names
                .iter()
                .take(super::BUILTIN_PRECONDITION_NAMES.len())
                .map(String::as_str)
                .collect::<Vec<_>>(),
            super::BUILTIN_PRECONDITION_NAMES
        );

        let mut local = super::builtin_predicates();
        assert!(super::register_slot(&mut local, "", always_true).is_err());
        assert_eq!(local.len(), super::BUILTIN_PRECONDITION_NAMES.len());
        super::register_slot(&mut local, " ", always_true).unwrap();
        super::register_slot(&mut local, "zz_local_flag", always_true).unwrap();
        super::register_slot(&mut local, "zz_local_flag", always_false).unwrap();
        let local_names: Vec<_> = local.iter().map(|slot| slot.name.clone()).collect();
        assert_eq!(
            local_names
                .iter()
                .filter(|name| name.as_str() == "zz_local_flag")
                .count(),
            1
        );
        assert_eq!(
            local_names.last().map(String::as_str),
            Some("zz_local_flag")
        );
        let ctx = context(&[], &[], "");
        let predicate = local
            .iter()
            .find(|slot| slot.name == "zz_local_flag")
            .expect("slot")
            .predicate;
        assert!(!predicate.call(&ctx).unwrap());

        let error = register_precondition("", always_true).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Precondition name must be a non-empty string"
        );
        assert!(std::error::Error::source(&error).is_none());

        let pinned = "a".repeat(64);
        let mut ctx = context(&[], &[], &pinned);
        ctx.policy = "salvage";
        ctx.acknowledge_side_effects = true;
        let names = [
            "no_sl203",
            "salvage_policy",
            "acknowledge_side_effects",
            "source_hash_pinned",
        ];
        assert_eq!(check_preconditions(&names, &ctx).unwrap(), (true, None));
        assert_eq!(check_preconditions(&[], &ctx).unwrap(), (true, None));

        ctx.acknowledge_side_effects = false;
        let names = ["acknowledge_side_effects", "missing_precondition"];
        assert_eq!(
            check_preconditions(&names, &ctx).unwrap(),
            (false, Some("acknowledge_side_effects"))
        );
        let names = ["missing_precondition"];
        let error = check_preconditions(&names, &ctx).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Unknown precondition: missing_precondition"
        );
        assert_eq!(
            error,
            PreconditionError::Value("Unknown precondition: missing_precondition".to_owned())
        );

        register_precondition("zz_card_preconditions_02_strict", profile_is_strict).unwrap();
        let names = ["zz_card_preconditions_02_strict"];
        assert_eq!(
            check_preconditions(&names, &ctx).unwrap(),
            (false, Some("zz_card_preconditions_02_strict"))
        );
        ctx.profile = "strict";
        assert_eq!(check_preconditions(&names, &ctx).unwrap(), (true, None));
        register_precondition("zz_card_preconditions_02_strict", always_false).unwrap();
        assert_eq!(
            check_preconditions(&names, &ctx).unwrap(),
            (false, Some("zz_card_preconditions_02_strict"))
        );
        assert_eq!(
            precondition_func_names()
                .iter()
                .filter(|name| name.as_str() == "zz_card_preconditions_02_strict")
                .count(),
            1
        );

        let listed = coded(
            "SL003",
            None,
            ev_map(vec![
                ("variant", PyValue::string("identical-duplicate")),
                ("record_indexes", indexes_of(&[0, 1])),
            ]),
        );
        let events = [
            hashed("evt-a", "message", "abc"),
            hashed("evt-b", "message", "abd"),
        ];
        let mut ctx = context(std::slice::from_ref(&listed), &events, "");
        ctx.finding = Some(&listed);
        assert_eq!(
            check_preconditions(&["sl003_identical_duplicate"], &ctx).unwrap(),
            (true, None)
        );
        let rejected = coded("SL003", None, PyValue::None);
        ctx.finding = Some(&rejected);
        assert_eq!(
            check_preconditions(&["sl003_identical_duplicate"], &ctx).unwrap(),
            (false, Some("sl003_identical_duplicate"))
        );
    }

    #[test]
    fn check_preconditions_propagates_seams_without_turning_them_true() {
        let events = [
            hashed("evt-a", "message", "abc"),
            hashed("evt-b", "message", "abc"),
        ];
        let trigger = sl203(ev_map(vec![("index", PyValue::int(1))]));
        let error = check_preconditions(
            &["no_prior_safe_tool_after_cut"],
            &context(std::slice::from_ref(&trigger), &events, "hash"),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), MUST_ABSTAIN_UNAVAILABLE);
        assert_eq!(
            error.to_string(),
            "sesslint.policy.abstention.must_abstain is not available"
        );

        let warning = finding(
            "SL005",
            Severity::Warning,
            Repairability::Deterministic,
            None,
            ev_map(vec![("index", PyValue::int(1))]),
        );
        assert_eq!(
            check_preconditions(
                &["no_prior_safe_tool_after_cut", "missing_precondition"],
                &context(std::slice::from_ref(&warning), &events, "hash"),
            )
            .unwrap(),
            (false, Some("no_prior_safe_tool_after_cut"))
        );

        let child = coded("SL203", None, ev_map(vec![("index", PyValue::int(0))]));
        let with_parent = [mapped(vec![
            ("id", EventField::Str("evt-a".to_owned())),
            ("kind", EventField::Str("message".to_owned())),
            ("parent_id", EventField::Str("parent-synthetic".to_owned())),
        ])];
        let mut ctx = context(std::slice::from_ref(&child), &with_parent, "");
        ctx.finding = Some(&child);
        let error = check_preconditions(&["unique_parent_candidate"], &ctx).unwrap_err();
        assert_eq!(
            error.to_string(),
            FIND_QUALIFYING_PARENT_CANDIDATES_UNAVAILABLE
        );
        assert_eq!(
            error.to_string(),
            "sesslint.checks.graph.find_qualifying_parent_candidates is not available"
        );

        let orphan = [hashed("evt-a", "message", "abc")];
        let mut ctx = context(std::slice::from_ref(&child), &orphan, "");
        ctx.finding = Some(&child);
        assert_eq!(
            check_preconditions(&["unique_parent_candidate"], &ctx).unwrap(),
            (false, Some("unique_parent_candidate"))
        );

        let fatal = sl203(PyValue::None);
        let mut ctx = context(std::slice::from_ref(&fatal), &with_parent, "");
        ctx.finding = Some(&child);
        assert_eq!(
            check_preconditions(&["no_sl203", "unique_parent_candidate"], &ctx).unwrap(),
            (false, Some("no_sl203"))
        );

        let float_kind = [mapped(vec![("kind", EventField::Float(1.0))])];
        assert_eq!(
            check_preconditions(
                &["branch_has_no_checkpoint"],
                &context(&[], &float_kind, "")
            )
            .unwrap_err()
            .to_string(),
            PYTHON_FLOAT_STR_UNREPRESENTABLE
        );
    }
}
