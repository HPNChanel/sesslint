//! Precondition engine for deterministic repair planning (TASK-018).
//!
//! Port of `src/sesslint/repair/preconditions.py` lines 1–317
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! `sl003_identical_duplicate` starts at line 320 and is not ported.
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

use std::error::Error;
use std::fmt;

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
}

impl fmt::Display for PreconditionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Event(error) => error.fmt(formatter),
            Self::Unavailable(message) => formatter.write_str(message),
        }
    }
}

impl Error for PreconditionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Event(error) => Some(error),
            Self::Unavailable(_) => None,
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

#[cfg(test)]
mod tests {
    use model::canonical::{Payload, SessionEvent};
    use model::codes::{Repairability, Severity};
    use model::events::{
        EventError, EventField, EventMapping, EventValue, PYTHON_FLOAT_STR_UNREPRESENTABLE,
    };
    use model::finding::{Finding, FindingInput, PyValue, SourceRef, SCHEMA_VERSION};

    use super::{
        adjacent_identical_duplicate, duplicate_projection_identical, no_prior_safe_tool_after_cut,
        no_sl203, repairability_is_safe_auto, repairability_is_salvage, side_effects_known,
        single_boundary_split, source_hash_pinned, unique_parent_candidate, PreconditionContext,
        PreconditionError, FIND_QUALIFYING_PARENT_CANDIDATES_UNAVAILABLE, MUST_ABSTAIN_UNAVAILABLE,
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
}
