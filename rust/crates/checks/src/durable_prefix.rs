//! SL206 durable-prefix boundary detector (detector-depth T-03).
//!
//! Port of `src/sesslint/checks/durable_prefix.py` lines 1–228
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! [`check_durable_prefix`] calls [`make_finding`] with the fingerprint
//! omitted. That returns the codec error and does not produce a digest.
//! This module does not call [`crate::graph::cap_graph_findings`].
//!
//! Codex-rollout-scoped check: the paginated resume path expects a contiguous
//! durable record sequence up to the inherited-prefix ordinal. The adapter
//! normalizes per-record durability into `extra_fields["codex"]` —
//! `{durable, ordinal, envelope_type, ...}` — and this check proves three
//! on-disk violations, at most one finding per kind per file:
//!
//! - `trailing-non-durable` — the file declares an inherited-prefix
//!   ordinal (`subagent_history_start_ordinal`) *past* the last durable
//!   ordinal: the resume path expects durable coverage through the claimed
//!   ordinal and finds a non-durable record there instead
//!   (openai/codex#40747: "expected inherited prefix through ordinal 828,
//!   found final durable ordinal 827"). Files without the claim keep
//!   ordinary non-durable tails clean — a bare non-durable tail proves
//!   nothing on its own.
//! - `durable-gap` — an ordinal strictly inside the durable range has no
//!   record at all: a durable hole inside the prefix. Ordinals held by
//!   non-durable records are legitimate interleave, not holes.
//! - `missing-required-field` — `reasoning` response_items lacking
//!   `encrypted_content` while sibling reasoning items carry it: the
//!   resume projection may silently drop required state (openai/codex#19661
//!   class). Uniform absence cannot prove the field is required — silent.
//!
//! [`durable_prefix_records`] reports at most one record per kind, in
//! emission order. It does not hash. [`check_durable_prefix`] calls
//! [`make_finding`] only when that list is non-empty, and propagates the
//! codec error from the first finding.
//!
//! Evidence is structural only: ordinals, counts, and envelope type names
//! (schema vocabulary), never payload content.
//!
//! # Recorded gaps
//!
//! * Python `int` is unbounded. Gap spans, ordinal walks, and counts use
//!   `i64` checked arithmetic. Overflow is [`PYTHON_INT_UNBOUNDED`], not a
//!   wrap and not a panic. A span whose length does not fit in `i64`,
//!   including a walk that would pass `i64::MAX`, is refused.
//! * [`MapLookup::Borrowed`] is a failed borrow, not a missing key
//!   ([`BORROWED_LOOKUP`]). [`MapLookup::NotAMap`] and
//!   [`MapLookup::Absent`] skip that level and the event is not a marker.
//! * [`crate::graph::event_get`] does not return `extra_fields` for a
//!   [`model::canonical::SessionEvent`]. This module reads
//!   [`model::canonical::SessionEvent::extra_fields`] directly. For
//!   [`EventValue::Mapping`], it reads the `extra_fields` field and uses
//!   [`model::events::EventMapping::to_payload`] when that field is a mapping.
//! * A bool is not an int. A float, a string, and a missing value do not
//!   qualify as an ordinal.

use std::collections::HashSet;
use std::error::Error;
use std::fmt;

use model::canonical::{MapLookup, Payload};
use model::codes::{Repairability, Severity, SL206};
use model::errors::FindingError;
use model::events::{EventField, EventValue};
use model::finding::{make_finding, Finding, MakeFindingInput, PyValue, SourceLine, SourceRef};

use crate::context::CheckContext;
use crate::graph::{event_get, resolve_source_coords, safe_id, GraphError};

/// Python: `_MSG_TRAILING`.
pub const MSG_TRAILING: &str =
    "Non-durable tail record past the durable prefix on line {line} for record {record_id}";

/// Python: `_MSG_GAP`.
pub const MSG_GAP: &str = "Durable-prefix ordinal hole on line {line} for record {record_id}";

/// Python: `_MSG_FIELD`.
pub const MSG_FIELD: &str =
    "Reasoning item missing a resume-required field on line {line} for record {record_id}";

/// Python `int` is unbounded; an `i64` overflow is not a wrap.
pub const PYTHON_INT_UNBOUNDED: &str =
    "Python ints are unbounded; an i64 overflow is not a wrap and not a panic";

/// [`MapLookup::Borrowed`] is not a missing key.
pub const BORROWED_LOOKUP: &str = "A borrowed map lookup is not a missing key";

const DIVERGENCE_TRAILING: &str = "trailing-non-durable";
const DIVERGENCE_GAP: &str = "durable-gap";
const DIVERGENCE_FIELD: &str = "missing-required-field";
const FIELD_ENCRYPTED_CONTENT: &str = "encrypted_content";
const ITEM_FAMILY_REASONING: &str = "reasoning";

/// Failure from this slice. [`Display`] is the message only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurablePrefixError {
    BorrowedLookup,
    PythonIntUnbounded,
    Finding(FindingError),
    Graph(GraphError),
}

impl DurablePrefixError {
    pub fn message(&self) -> &str {
        match self {
            Self::BorrowedLookup => BORROWED_LOOKUP,
            Self::PythonIntUnbounded => PYTHON_INT_UNBOUNDED,
            Self::Finding(error) => error.message(),
            Self::Graph(error) => error.message(),
        }
    }
}

impl fmt::Display for DurablePrefixError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for DurablePrefixError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Finding(error) => Some(error),
            Self::Graph(error) => Some(error),
            Self::BorrowedLookup | Self::PythonIntUnbounded => None,
        }
    }
}

impl From<FindingError> for DurablePrefixError {
    fn from(error: FindingError) -> Self {
        Self::Finding(error)
    }
}

impl From<GraphError> for DurablePrefixError {
    fn from(error: GraphError) -> Self {
        match error {
            GraphError::Finding(error) => Self::Finding(error),
            other => Self::Graph(other),
        }
    }
}

/// One divergence kind with its anchor. Does not call [`make_finding`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurablePrefixRecord {
    pub divergence: &'static str,
    pub event_index: usize,
    pub expected_durable_ordinal: Option<i64>,
    pub last_durable_ordinal: Option<i64>,
    pub inherited_prefix_ordinal: Option<i64>,
    pub tail_ordinal: Option<i64>,
    pub tail_envelope_family: Option<String>,
    pub missing_ordinal: Option<i64>,
    pub missing_count: Option<i64>,
    pub present_count: Option<i64>,
    pub first_missing_ordinal: Option<i64>,
}

struct Marked {
    index: usize,
    marker: Payload,
}

/// Extra-fields payload for one event. [`event_get`] is not used here.
fn extra_fields_payload(ev: &EventValue) -> Option<Payload> {
    match ev {
        EventValue::Session(event) => Some(event.extra_fields.clone()),
        EventValue::Mapping(mapping) => match mapping.get("extra_fields") {
            Some(EventField::Mapping(inner)) => Some(inner.to_payload()),
            Some(_) | None => None,
        },
        EventValue::Other => None,
    }
}

/// [`MapLookup::Borrowed`] is an error. [`MapLookup::NotAMap`] and
/// [`MapLookup::Absent`] skip that level.
fn map_field(payload: &Payload, key: &str) -> Result<Option<Payload>, DurablePrefixError> {
    match payload.map_string(key) {
        MapLookup::Borrowed => Err(DurablePrefixError::BorrowedLookup),
        MapLookup::NotAMap | MapLookup::Absent => Ok(None),
        MapLookup::Present(value) => Ok(Some(value)),
    }
}

/// Python: `_codex_marker`.
fn codex_marker(ev: &EventValue) -> Result<Option<Payload>, DurablePrefixError> {
    let Some(extra) = extra_fields_payload(ev) else {
        return Ok(None);
    };
    match map_field(&extra, "codex")? {
        Some(value) if value.is_map() => Ok(Some(value)),
        Some(_) | None => Ok(None),
    }
}

fn marker_int(marker: &Payload, key: &str) -> Result<Option<i64>, DurablePrefixError> {
    Ok(map_field(marker, key)?.and_then(|value| value.as_int()))
}

fn marker_bool_true(marker: &Payload, key: &str) -> Result<bool, DurablePrefixError> {
    Ok(map_field(marker, key)?.and_then(|value| value.as_bool()) == Some(true))
}

fn envelope_family(marker: &Payload) -> Result<Option<String>, DurablePrefixError> {
    match map_field(marker, "envelope_type")? {
        Some(value) => match value.as_str() {
            Some(text) => {
                let stripped = text.trim();
                if stripped.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(stripped.to_owned()))
                }
            }
            None => Ok(None),
        },
        None => Ok(None),
    }
}

/// Python: `_rec_id`.
fn rec_id(ev: &EventValue) -> Option<String> {
    match event_get(ev, "id") {
        Some(EventField::Str(text)) => {
            let stripped = text.trim();
            if stripped.is_empty() {
                None
            } else {
                Some(safe_id(stripped))
            }
        }
        _ => None,
    }
}

fn optional_int(value: Option<i64>) -> PyValue {
    match value {
        Some(number) => PyValue::int(number),
        None => PyValue::None,
    }
}

fn first_durable_gap(
    envelope_ordinals: &HashSet<i64>,
    min_durable: i64,
    max_durable: i64,
) -> Result<Option<i64>, DurablePrefixError> {
    if max_durable.checked_sub(min_durable).is_none() {
        return Err(DurablePrefixError::PythonIntUnbounded);
    }
    let mut n = min_durable;
    while n < max_durable {
        if !envelope_ordinals.contains(&n) {
            return Ok(Some(n));
        }
        n = n
            .checked_add(1)
            .ok_or(DurablePrefixError::PythonIntUnbounded)?;
    }
    Ok(None)
}

fn trailing_record(
    marked: &[Marked],
    claim: i64,
    last_durable: i64,
) -> Result<DurablePrefixRecord, DurablePrefixError> {
    let mut tail_index = None;
    let mut tail_marker = None;
    let mut tail_ord: i64 = -1;
    let mut claim_index = None;
    let mut claim_marker = None;
    for item in marked {
        let Some(ordinal) = marker_int(&item.marker, "ordinal")? else {
            continue;
        };
        if ordinal >= tail_ord {
            tail_index = Some(item.index);
            tail_marker = Some(&item.marker);
            tail_ord = ordinal;
        }
        if ordinal == claim {
            claim_index = Some(item.index);
            claim_marker = Some(&item.marker);
        }
    }
    let (event_index, anchor_marker) = if let Some(index) = claim_index {
        (index, claim_marker)
    } else if let Some(index) = tail_index {
        (index, tail_marker)
    } else if let Some(last) = marked.last() {
        (last.index, None)
    } else {
        (0, None)
    };
    let tail_envelope_family = match anchor_marker {
        Some(marker) => envelope_family(marker)?,
        None => None,
    };
    let tail_ordinal = if tail_ord >= 0 { Some(tail_ord) } else { None };
    Ok(DurablePrefixRecord {
        divergence: DIVERGENCE_TRAILING,
        event_index,
        expected_durable_ordinal: Some(claim),
        last_durable_ordinal: Some(last_durable),
        inherited_prefix_ordinal: Some(claim),
        tail_ordinal,
        tail_envelope_family,
        missing_ordinal: None,
        missing_count: None,
        present_count: None,
        first_missing_ordinal: None,
    })
}

fn gap_record(
    marked: &[Marked],
    hole: i64,
    last_durable: i64,
) -> Result<DurablePrefixRecord, DurablePrefixError> {
    let mut gap_anchor = None;
    for item in marked {
        let Some(ordinal) = marker_int(&item.marker, "ordinal")? else {
            continue;
        };
        if ordinal > hole {
            gap_anchor = Some(item.index);
            break;
        }
    }
    let event_index = match gap_anchor {
        Some(index) => index,
        None => match marked.last() {
            Some(item) => item.index,
            None => 0,
        },
    };
    Ok(DurablePrefixRecord {
        divergence: DIVERGENCE_GAP,
        event_index,
        expected_durable_ordinal: Some(hole),
        last_durable_ordinal: Some(last_durable),
        inherited_prefix_ordinal: None,
        tail_ordinal: None,
        tail_envelope_family: None,
        missing_ordinal: Some(hole),
        missing_count: None,
        present_count: None,
        first_missing_ordinal: None,
    })
}

/// At most one record per divergence kind, in emission order. Does not call
/// [`make_finding`].
pub fn durable_prefix_records(
    events: &[EventValue],
) -> Result<Vec<DurablePrefixRecord>, DurablePrefixError> {
    let mut marked = Vec::new();
    for (index, ev) in events.iter().enumerate() {
        if let Some(marker) = codex_marker(ev)? {
            marked.push(Marked { index, marker });
        }
    }
    if marked.is_empty() {
        return Ok(Vec::new());
    }

    let mut envelope_ordinals = HashSet::new();
    let mut min_durable: Option<i64> = None;
    let mut max_durable: Option<i64> = None;
    let mut inherited_prefix_ordinal = None;
    for item in &marked {
        if let Some(ordinal) = marker_int(&item.marker, "ordinal")? {
            envelope_ordinals.insert(ordinal);
            if marker_bool_true(&item.marker, "durable")? {
                min_durable = Some(match min_durable {
                    Some(current) => current.min(ordinal),
                    None => ordinal,
                });
                max_durable = Some(match max_durable {
                    Some(current) => current.max(ordinal),
                    None => ordinal,
                });
            }
        }
        if inherited_prefix_ordinal.is_none() {
            inherited_prefix_ordinal = marker_int(&item.marker, "subagent_history_start_ordinal")?;
        }
    }

    let mut records = Vec::new();

    if let (Some(last_durable), Some(claim)) = (max_durable, inherited_prefix_ordinal) {
        if claim > last_durable {
            records.push(trailing_record(&marked, claim, last_durable)?);
        }
    }

    if let (Some(min_d), Some(max_d)) = (min_durable, max_durable) {
        if let Some(hole) = first_durable_gap(&envelope_ordinals, min_d, max_d)? {
            records.push(gap_record(&marked, hole, max_d)?);
        }
    }

    let mut reasoning_missing: Vec<(usize, Option<i64>)> = Vec::new();
    let mut reasoning_present: i64 = 0;
    for item in &marked {
        match map_field(&item.marker, "item_type")? {
            Some(value) if value.as_str() == Some(ITEM_FAMILY_REASONING) => {}
            _ => continue,
        }
        if let Some(value) = map_field(&item.marker, "has_encrypted_content")? {
            match value.as_bool() {
                Some(true) => {
                    reasoning_present = reasoning_present
                        .checked_add(1)
                        .ok_or(DurablePrefixError::PythonIntUnbounded)?;
                }
                Some(false) => {
                    let ordinal = marker_int(&item.marker, "ordinal")?;
                    reasoning_missing.push((item.index, ordinal));
                }
                None => {}
            }
        }
    }
    if !reasoning_missing.is_empty() && reasoning_present > 0 {
        let missing_count = i64::try_from(reasoning_missing.len())
            .map_err(|_| DurablePrefixError::PythonIntUnbounded)?;
        if let Some(&(event_index, first_missing_ordinal)) = reasoning_missing.first() {
            records.push(DurablePrefixRecord {
                divergence: DIVERGENCE_FIELD,
                event_index,
                expected_durable_ordinal: None,
                last_durable_ordinal: None,
                inherited_prefix_ordinal: None,
                tail_ordinal: None,
                tail_envelope_family: None,
                missing_ordinal: None,
                missing_count: Some(missing_count),
                present_count: Some(reasoning_present),
                first_missing_ordinal,
            });
        }
    }

    Ok(records)
}

fn message_template(divergence: &str) -> &'static str {
    match divergence {
        DIVERGENCE_TRAILING => MSG_TRAILING,
        DIVERGENCE_GAP => MSG_GAP,
        DIVERGENCE_FIELD => MSG_FIELD,
        _ => MSG_TRAILING,
    }
}

fn record_evidence(record: &DurablePrefixRecord) -> PyValue {
    match record.divergence {
        DIVERGENCE_TRAILING => {
            let mut entries = vec![
                (
                    PyValue::string("divergence"),
                    PyValue::string(record.divergence),
                ),
                (
                    PyValue::string("expected_durable_ordinal"),
                    optional_int(record.expected_durable_ordinal),
                ),
                (
                    PyValue::string("last_durable_ordinal"),
                    optional_int(record.last_durable_ordinal),
                ),
                (
                    PyValue::string("inherited_prefix_ordinal"),
                    optional_int(record.inherited_prefix_ordinal),
                ),
            ];
            if let Some(tail_ordinal) = record.tail_ordinal {
                entries.push((PyValue::string("tail_ordinal"), PyValue::int(tail_ordinal)));
            }
            if let Some(family) = record.tail_envelope_family.as_deref() {
                entries.push((
                    PyValue::string("tail_envelope_family"),
                    PyValue::string(family),
                ));
            }
            PyValue::map(entries)
        }
        DIVERGENCE_GAP => PyValue::map(vec![
            (
                PyValue::string("divergence"),
                PyValue::string(record.divergence),
            ),
            (
                PyValue::string("missing_ordinal"),
                optional_int(record.missing_ordinal),
            ),
            (
                PyValue::string("expected_durable_ordinal"),
                optional_int(record.expected_durable_ordinal),
            ),
            (
                PyValue::string("last_durable_ordinal"),
                optional_int(record.last_durable_ordinal),
            ),
        ]),
        DIVERGENCE_FIELD => PyValue::map(vec![
            (
                PyValue::string("divergence"),
                PyValue::string(record.divergence),
            ),
            (
                PyValue::string("field"),
                PyValue::string(FIELD_ENCRYPTED_CONTENT),
            ),
            (
                PyValue::string("item_family"),
                PyValue::string(ITEM_FAMILY_REASONING),
            ),
            (
                PyValue::string("missing_count"),
                optional_int(record.missing_count),
            ),
            (
                PyValue::string("present_count"),
                optional_int(record.present_count),
            ),
            (
                PyValue::string("first_missing_ordinal"),
                optional_int(record.first_missing_ordinal),
            ),
        ]),
        _ => PyValue::map(Vec::new()),
    }
}

/// Python: `check_durable_prefix`.
///
/// No markers, and no divergence, return an empty list and do not call
/// [`make_finding`]. A divergence calls [`make_finding`] with the
/// fingerprint omitted; that codec error is propagated from the first
/// finding. The list is not capped.
pub fn check_durable_prefix(
    events: &[EventValue],
    source_path: Option<&str>,
    context: Option<&CheckContext>,
) -> Result<Vec<Finding>, DurablePrefixError> {
    let records = durable_prefix_records(events)?;
    if records.is_empty() {
        return Ok(Vec::new());
    }

    let source_path = source_path.unwrap_or("<canonical>");
    let owned_ctx;
    let ctx = match context {
        Some(value) => value,
        None => {
            owned_ctx = CheckContext::default();
            &owned_ctx
        }
    };

    let mut findings = Vec::new();
    for record in records {
        let Some(ev) = events.get(record.event_index) else {
            continue;
        };
        let (resolved_path, line_num) = resolve_source_coords(ev, source_path)?;
        let clean_rec_id = rec_id(ev);
        let source = SourceRef::try_new(
            &resolved_path,
            line_num.map(SourceLine::Int),
            clean_rec_id.as_deref(),
        )?;
        findings.push(make_finding(&MakeFindingInput {
            code: PyValue::string(SL206),
            severity: PyValue::severity(Severity::Warning),
            repairability: PyValue::repairability(Repairability::Manual),
            message_template: PyValue::string(message_template(record.divergence)),
            template_args: PyValue::None,
            source: PyValue::source(source),
            related_ids: PyValue::tuple(Vec::new()),
            evidence: record_evidence(&record),
            fingerprint: PyValue::None,
            adapter_id: Some(ctx.adapter_id().to_owned()),
            adapter_version: Some(ctx.adapter_version().to_owned()),
            profile_id: Some(ctx.profile_id().to_owned()),
            profile_version: Some(ctx.profile_version().to_owned()),
            ordinal: None,
            context: None,
        })?);
    }
    Ok(findings)
}

/// Python `__all__`, in that order.
pub const ALL: [&str; 1] = ["check_durable_prefix"];

#[cfg(test)]
mod tests {
    use super::{
        check_durable_prefix, durable_prefix_records, DurablePrefixError, ALL, MSG_FIELD, MSG_GAP,
        MSG_TRAILING,
    };
    use model::canonical::{Payload, SessionEvent};
    use model::events::EventValue;
    use model::finding::FINGERPRINT_CODEC_UNAVAILABLE;

    fn session_event(id: &str, extra: Payload) -> EventValue {
        let mut event =
            SessionEvent::new(id, None, 0, "2024-02-29T00:00:00Z", "assistant", "message");
        event.extra_fields = extra;
        EventValue::from_session(event)
    }

    fn pair(key: &str, value: Payload) -> (Payload, Payload) {
        (Payload::string(key), value)
    }

    fn codex_extra(entries: Vec<(Payload, Payload)>) -> Payload {
        Payload::map(vec![(Payload::string("codex"), Payload::map(entries))])
    }

    fn marked(id: &str, entries: Vec<(Payload, Payload)>) -> EventValue {
        session_event(id, codex_extra(entries))
    }

    fn is_lower_hex16(text: &str) -> bool {
        text.len() == 16 && text.chars().all(|ch| matches!(ch, '0'..='9' | 'a'..='f'))
    }

    fn assert_codec_unavailable(err: DurablePrefixError) {
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(err.message(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!is_lower_hex16(&err.to_string()));
    }

    #[test]
    fn all_is_check_durable_prefix() {
        assert_eq!(ALL, ["check_durable_prefix"]);
        assert_eq!(
            MSG_TRAILING,
            "Non-durable tail record past the durable prefix on line {line} for record {record_id}"
        );
        assert_eq!(
            MSG_GAP,
            "Durable-prefix ordinal hole on line {line} for record {record_id}"
        );
        assert_eq!(
            MSG_FIELD,
            "Reasoning item missing a resume-required field on line {line} for record {record_id}"
        );
    }

    #[test]
    fn no_codex_marker_is_silent() {
        let events = vec![
            session_event("evt-a-synthetic", Payload::map(Vec::new())),
            session_event("evt-b-synthetic", Payload::map(Vec::new())),
        ];
        let records = durable_prefix_records(&events).unwrap();
        assert!(records.is_empty());
        let findings = check_durable_prefix(&events, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn non_durable_tail_without_claim_is_silent() {
        let events = vec![
            marked(
                "evt-durable-synthetic",
                vec![
                    pair("ordinal", Payload::int(0)),
                    pair("durable", Payload::bool_value(true)),
                ],
            ),
            marked(
                "evt-tail-synthetic",
                vec![
                    pair("ordinal", Payload::int(1)),
                    pair("durable", Payload::bool_value(false)),
                    pair("envelope_type", Payload::string("event_msg")),
                ],
            ),
        ];
        let records = durable_prefix_records(&events).unwrap();
        assert!(records.is_empty());
        let findings = check_durable_prefix(&events, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn claim_past_last_durable_is_trailing_and_codec_error() {
        let events = vec![
            marked(
                "evt-durable-synthetic",
                vec![
                    pair("ordinal", Payload::int(0)),
                    pair("durable", Payload::bool_value(true)),
                    pair("subagent_history_start_ordinal", Payload::int(2)),
                ],
            ),
            marked(
                "evt-tail-synthetic",
                vec![
                    pair("ordinal", Payload::int(1)),
                    pair("durable", Payload::bool_value(false)),
                    pair("envelope_type", Payload::string("event_msg")),
                ],
            ),
        ];
        let records = durable_prefix_records(&events).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].divergence, "trailing-non-durable");
        assert_eq!(records[0].expected_durable_ordinal, Some(2));
        assert_eq!(records[0].last_durable_ordinal, Some(0));
        assert_eq!(records[0].inherited_prefix_ordinal, Some(2));
        let err = check_durable_prefix(&events, None, None).unwrap_err();
        assert_codec_unavailable(err);
    }

    #[test]
    fn durable_ordinals_0_and_2_with_no_record_at_1_is_gap() {
        let events = vec![
            marked(
                "evt-zero-synthetic",
                vec![
                    pair("ordinal", Payload::int(0)),
                    pair("durable", Payload::bool_value(true)),
                ],
            ),
            marked(
                "evt-two-synthetic",
                vec![
                    pair("ordinal", Payload::int(2)),
                    pair("durable", Payload::bool_value(true)),
                ],
            ),
        ];
        let records = durable_prefix_records(&events).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].divergence, "durable-gap");
        assert_eq!(records[0].missing_ordinal, Some(1));
        assert_eq!(records[0].expected_durable_ordinal, Some(1));
        assert_eq!(records[0].last_durable_ordinal, Some(2));
        let err = check_durable_prefix(&events, None, None).unwrap_err();
        assert_codec_unavailable(err);
    }

    #[test]
    fn non_durable_record_at_1_between_durable_0_and_2_is_not_a_gap() {
        let events = vec![
            marked(
                "evt-zero-synthetic",
                vec![
                    pair("ordinal", Payload::int(0)),
                    pair("durable", Payload::bool_value(true)),
                ],
            ),
            marked(
                "evt-one-synthetic",
                vec![
                    pair("ordinal", Payload::int(1)),
                    pair("durable", Payload::bool_value(false)),
                ],
            ),
            marked(
                "evt-two-synthetic",
                vec![
                    pair("ordinal", Payload::int(2)),
                    pair("durable", Payload::bool_value(true)),
                ],
            ),
        ];
        let records = durable_prefix_records(&events).unwrap();
        assert!(records.is_empty());
        let findings = check_durable_prefix(&events, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn reasoning_items_all_missing_encrypted_content_are_silent() {
        let events = vec![
            marked(
                "evt-r1-synthetic",
                vec![
                    pair("item_type", Payload::string("reasoning")),
                    pair("has_encrypted_content", Payload::bool_value(false)),
                    pair("ordinal", Payload::int(1)),
                ],
            ),
            marked(
                "evt-r2-synthetic",
                vec![
                    pair("item_type", Payload::string("reasoning")),
                    pair("has_encrypted_content", Payload::bool_value(false)),
                    pair("ordinal", Payload::int(2)),
                ],
            ),
        ];
        let records = durable_prefix_records(&events).unwrap();
        assert!(records.is_empty());
        let findings = check_durable_prefix(&events, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn mixed_reasoning_encrypted_content_is_missing_required_field() {
        let events = vec![
            marked(
                "evt-present-synthetic",
                vec![
                    pair("item_type", Payload::string("reasoning")),
                    pair("has_encrypted_content", Payload::bool_value(true)),
                    pair("ordinal", Payload::int(1)),
                ],
            ),
            marked(
                "evt-missing-synthetic",
                vec![
                    pair("item_type", Payload::string("reasoning")),
                    pair("has_encrypted_content", Payload::bool_value(false)),
                    pair("ordinal", Payload::int(2)),
                ],
            ),
        ];
        let records = durable_prefix_records(&events).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].divergence, "missing-required-field");
        assert_eq!(records[0].missing_count, Some(1));
        assert_eq!(records[0].present_count, Some(1));
        assert_eq!(records[0].first_missing_ordinal, Some(2));
        let err = check_durable_prefix(&events, None, None).unwrap_err();
        assert_codec_unavailable(err);
    }

    #[test]
    fn bool_ordinal_is_ignored() {
        let events = vec![marked(
            "evt-bool-synthetic",
            vec![
                pair("ordinal", Payload::bool_value(true)),
                pair("durable", Payload::bool_value(true)),
            ],
        )];
        let records = durable_prefix_records(&events).unwrap();
        assert!(records.is_empty());
        let findings = check_durable_prefix(&events, None, None).unwrap();
        assert!(findings.is_empty());
    }
}
